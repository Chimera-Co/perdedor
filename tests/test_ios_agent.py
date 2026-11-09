"""Device-shell and CoreSimulator transcripts; no hardware needed."""

import json
import plistlib
from pathlib import Path

import pytest
from perdedor_common.catalog import load_catalog
from perdedor_common.models import Platform
from perdedor_common.registry import RunContext
from perdedor_common.validation import validate_report
from perdedor_ios.checks import behavioural, design
from perdedor_ios.checks.platform_extra import active_tunnels
from perdedor_ios.device import IosTarget, SimulatorTransport, ios_ssh
from perdedor_ios.runner import all_checks, run_scan
from perdedor_macos.checkkit import Skip
from perdedor_macos.transport import CommandResult, FakeTransport, LocalTransport

FIXTURES = Path(__file__).parent / "fixtures" / "ios"
UDID = "12345678-1234-1234-1234-123456789ABC"


@pytest.mark.parametrize("name", ["rootless", "corellium", "simulator"])
def test_ios_command_transcripts(name):
    fake = FakeTransport.from_fixture(FIXTURES / (name + ".json"))
    report = run_scan(IosTarget(fake), network=False).to_dict()
    validate_report(report)
    findings = {f["id"]: f for f in report["findings"]}
    if name == "rootless":
        detected = [
            "design.jb_rootless_prefix",
            "design.jb_rootless_bootstrap",
            "design.hook_ellekit",
            "design.jb_package_managers",
            "design.injected_images",
            "design.jb_url_schemes",
        ]
        clean = [
            "env.hw_machine",
            "env.hw_model",
            "env.hv_vmm_present",
            "env.virtual_vendor",
            "env.simulator_environment",
            "env.telephony_daemon",
            "env.radio_daemons",
            "env.baseband_registry",
            "design.traced_processes",
            "design.proxy_settings",
            "design.mitm_certificates",
            "design.lockdown_mode",
            "behavioural.installed_apps",
            "behavioural.contacts",
            "behavioural.messages",
            "behavioural.photos",
        ]
    elif name == "corellium":
        detected = [
            "env.virtual_vendor",
            "env.hv_vmm_present",
            "env.telephony_daemon",
            "env.baseband_registry",
            "design.frida_files",
            "design.frida_processes",
            "design.traced_processes",
            "design.jb_rootfs_writable",
            "design.listening_ports",
            "behavioural.installed_apps",
        ]
        clean = ["env.hw_machine", "env.hw_model", "design.proxy_settings", "env.simulator_environment"]
    else:
        detected = [
            "env.hw_machine",
            "env.hw_model",
            "env.simulator_environment",
            "env.simulator_device_type",
            "env.dyld_sim",
            "env.os_version_mismatch",
            "behavioural.installed_apps",
        ]
        clean = ["design.proxy_settings", "design.traced_processes"]
        assert findings["ios.design.jb_shell_binaries"]["status"] == "skipped"
        assert findings["ios.design.jb_rootfs_writable"]["status"] == "skipped"
    for suffix in detected:
        assert findings["ios." + suffix]["status"] == "detected", (name, suffix, findings["ios." + suffix])
    for suffix in clean:
        assert findings["ios." + suffix]["status"] == "clean", (name, suffix, findings["ios." + suffix])
    assert not any(key.startswith("curl_") for key, _ in fake.calls)
    for key, command in fake.calls:
        if key.startswith("count:"):
            assert "SELECT count(*)" in command and "-readonly" in command
    assert "photo0.HEIC" not in json.dumps(report)


def test_ios_ids_and_catalog_match():
    catalog = load_catalog(cache=False)
    checks = all_checks()
    assert len(checks) >= 60
    assert len({s.id for s in checks}) == len(checks)
    for s in checks:
        e = catalog.check(s.id)
        assert e["technique"] == s.technique
        assert e["severity"] == s.func.metadata.severity.value
        assert e["cost"] == s.cost
        assert e["network"] == s.network
    assert len(run_scan(IosTarget(FakeTransport(unreachable=True)), network=False).findings) > 60
    assert all(
        f.status.value == "error"
        for f in run_scan(IosTarget(FakeTransport(unreachable=True)), network=False).findings
    )


def test_private_store_denial_never_means_empty():
    ctx = RunContext(platform=Platform.IOS)
    target = IosTarget(FakeTransport())
    result = behavioural.store_probe(behavioural.PERSONAL_STORES["messages"])(target, ctx)
    assert isinstance(result, Skip)
    assert isinstance(design.probe_mitm_certs(target, ctx), Skip)
    assert isinstance(design.probe_injected_images(target, ctx), Skip)


def test_personal_counts_only_and_empty_vs_nonempty():
    path = behavioural.PERSONAL_STORES["messages"][0]
    ctx = RunContext(platform=Platform.IOS)
    for count in (0, 200):
        fake = FakeTransport(commands={"count:" + path + ":message": str(count)})
        result = behavioural.store_probe([path])(IosTarget(fake), ctx)
        assert result.detected == (count == 0)
        assert result.evidence == {"records": count}
        assert "SELECT count(*)" in fake.calls[0][1]
        assert "SELECT *" not in fake.calls[0][1]
        assert "mode=ro&immutable=1" in fake.calls[0][1]


def test_url_schemes_are_declarations_not_arbitrary_strings():
    text = plistlib.dumps(
        {"CFBundleName": "sileo", "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example", "zbra"]}]}
    ).decode()
    assert design.declared_url_schemes(text) == {"example", "zbra"}
    assert design.declared_url_schemes("cydia sileo filza") == set()
    assert design.declared_url_schemes('CFBundleURLSchemes = ("sileo", example);') == {"sileo", "example"}


def test_proxy_disabled_keys_are_clean():
    ctx = RunContext(platform=Platform.IOS)
    path = design.SC_PREFERENCES
    for enabled in (0, 1):
        fake = FakeTransport(
            commands={
                "plist:"
                + path: plistlib.dumps(
                    {"Services": {"example": {"HTTPEnable": enabled, "HTTPProxy": "redacted.invalid"}}}
                ).decode()
            }
        )
        assert design.probe_proxy(IosTarget(fake), ctx).detected == bool(enabled)


def test_tunnel_parser_requires_up_and_address():
    text = (
        "utun0: flags=8051<UP,POINTOPOINT,RUNNING> mtu 1400\n inet6 fe80::1\n"
        "utun1: flags=8050<POINTOPOINT,RUNNING> mtu 1400\n inet6 fe80::2\n"
        "en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n inet 10.0.0.1\n"
    )
    assert active_tunnels(text) == ["utun0"]


def resolved_simulator(monkeypatch, tmp_path, state="Booted", duplicate=False):
    data = tmp_path / "device" / "data"
    runtime = tmp_path / "RuntimeRoot"
    data.mkdir(parents=True)
    runtime.mkdir()
    record = {"udid": UDID, "state": state, "isAvailable": True, "dataPath": str(data)}
    entries = [record, {**record, "udid": "87654321-1234-1234-1234-123456789ABC"}] if duplicate else [record]
    responses = {
        "xcrun simctl list devices --json": json.dumps({"devices": {"runtime-id": entries}}),
        "xcrun simctl list runtimes --json": json.dumps(
            {"runtimes": [{"identifier": "runtime-id", "runtimeRoot": str(runtime)}]}
        ),
    }
    calls = []

    def execute(self, command, timeout):
        calls.append(command)
        return CommandResult(0, responses.get(command, ""))

    monkeypatch.setattr(LocalTransport, "_exec", execute)
    return SimulatorTransport("booted"), data, runtime, calls


def test_simulator_resolves_booted_paths_and_spawns_without_shell(monkeypatch, tmp_path):
    transport, data, runtime, calls = resolved_simulator(monkeypatch, tmp_path)
    assert transport.resolve()
    assert transport.device_path("/var/mobile/Library/SMS/sms.db") == str(data / "Library/SMS/sms.db")
    assert transport.device_path("/var/containers/Bundle/Application") == str(
        data / "Containers/Bundle/Application"
    )
    assert transport.device_path("/System/Library/test") == str(runtime / "System/Library/test")
    transport.run("sysctl hw.machine 2>/dev/null", key="sysctl")
    assert calls[-1] == "xcrun simctl spawn " + UDID + " sysctl hw.machine"
    assert transport.run("date +%s; sleep 3; date +%s", key="sleep_window").returncode == 127
    with pytest.raises(ValueError):
        transport.device_path("/var/mobile/../../etc/passwd")
    (data / "escape").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        transport.device_path("/var/mobile/escape/hostfile")


@pytest.mark.parametrize("state,duplicate", [("Shutdown", False), ("Booted", True)])
def test_simulator_never_uses_host_fallback(monkeypatch, tmp_path, state, duplicate):
    transport, _, _, calls = resolved_simulator(monkeypatch, tmp_path, state, duplicate)
    assert not transport.resolve()
    assert transport.run("sysctl hw.machine", key="sysctl") is None
    with pytest.raises(ValueError):
        transport.device_path("/etc/passwd")
    assert not any(c.startswith("sysctl") for c in calls)


def test_ios_ssh_rootless_path_and_udid_validation():
    transport = ios_ssh("root@example.invalid", port=2222)
    assert "/var/jb/usr/bin" in transport.argv("sysctl hw.machine")[-1]
    for udid in ("booted;id", "--help", "../../host"):
        with pytest.raises(ValueError):
            SimulatorTransport(udid)


def test_ios_cli_list(capsys):
    from perdedor_ios.__main__ import main

    assert main(["--list-checks", "--only", "class:emulator"]) == 0
    assert "ios.env.simulator_environment" in capsys.readouterr().out
