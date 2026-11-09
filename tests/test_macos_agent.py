"""Deterministic command-transcript and transport regressions, runnable on Linux."""

import json
import shlex
import sys
import time
from pathlib import Path

import pytest
from perdedor_common.catalog import load_catalog
from perdedor_common.models import Platform
from perdedor_common.registry import RunContext, select
from perdedor_common.validation import validate_report
from perdedor_macos import parsing
from perdedor_macos.checkkit import Fail, Skip
from perdedor_macos.checks import behavioural, design, timing
from perdedor_macos.runner import all_checks, run_scan
from perdedor_macos.target import Target
from perdedor_macos.transport import CommandResult, FakeTransport, LocalTransport, SshTransport, _subprocess

FIXTURES = Path(__file__).parent / "fixtures" / "macos"


def scan(name, **kw):
    fake = FakeTransport.from_fixture(FIXTURES / (name + ".json"))
    report = run_scan(Target(fake), network=False, **kw).to_dict()
    validate_report(report)
    return {f["id"]: f for f in report["findings"]}, fake


@pytest.mark.parametrize("name", ["apple_silicon", "virtualmac", "vmware", "parallels", "utm"])
def test_hardware_transcripts(name):
    findings, fake = scan(name)
    if name == "apple_silicon":
        clean = [
            "env.hw_model",
            "env.memsize",
            "env.cpu_count",
            "env.hv_vmm_present",
            "env.board_id",
            "design.sip_status",
            "design.gatekeeper",
            "design.mac_oui",
            "design.traced_processes",
            "design.cis_locale",
            "design.default_locale",
            "behavioural.safari_history",
            "behavioural.documents_files",
            "timing.uptime",
        ]
        detected = []
    else:
        clean = ["design.traced_processes", "design.processes_debuggers", "design.proxy_settings"]
        detected = [
            "env.hv_vmm_present",
            "env.memsize",
            "env.cpu_count",
            "env.platform_serial",
            "env.storage_identity",
            "design.sip_status",
            "design.default_subnets",
            "timing.uptime",
        ]
        if name != "utm":
            detected.append("env.hw_model")
        if name in ("vmware", "parallels", "utm"):
            detected += ["design.mac_oui", "env.guest_tools_processes"]
        if name != "utm":
            detected.append(
                "env.kext_"
                + {"virtualmac": "apple_virtualization", "vmware": "vmware", "parallels": "parallels"}[name]
            )
    for suffix in clean:
        assert findings["macos." + suffix]["status"] == "clean", (name, suffix, findings["macos." + suffix])
    for suffix in detected:
        assert findings["macos." + suffix]["status"] == "detected", (
            name,
            suffix,
            findings["macos." + suffix],
        )
    assert not any(key.startswith("curl_") for key, _ in fake.calls)
    assert not any("Traceback" in (f.get("error_detail") or "") for f in findings.values())


def test_registration_catalog_and_selection_agree():
    checks = all_checks()
    assert len(checks) >= 80
    assert len({s.id for s in checks}) == len(checks)
    catalog = load_catalog(cache=False)
    for spec in checks:
        entry = catalog.check(spec.id)
        assert entry["technique"] == spec.technique
        assert entry["severity"] == spec.func.metadata.severity.value
        assert entry["cost"] == spec.cost
        assert entry["network"] == spec.network
        assert entry["fix"]["how"] and entry["fix"]["chimera"] and entry["references"]
    assert all(s.check_class == "cpu" for s in select(checks, only=["class:cpu"]))
    assert not any(s.network for s in select(checks, profile="deep", network=False))
    assert not any(s.cost == "slow" for s in select(checks, profile="standard"))


def test_equivalent_names_match_pinned_inventories():
    root = Path(__file__).resolve().parents[1]
    upstreams = json.loads((root / "catalog/upstreams.json").read_text())["upstreams"]
    keys = {u["id"]: u.get("equivalents_key") for u in upstreams}
    valid = {}
    for path in (root / "catalog/inventory").glob("*.json"):
        inventory = json.loads(path.read_text())
        key = keys.get(inventory["source_id"])
        if key:
            valid.setdefault(key, set()).update(t["name"] for t in inventory["techniques"])
    for entry in load_catalog(cache=False).checks.values():
        if entry["platform"] not in ("macos", "ios"):
            continue
        for key, names in entry["equivalents"].items():
            assert key in valid
            assert set(names) <= valid[key], (entry["id"], key, set(names) - valid[key])
        if "freerasp" in entry["equivalents"]:
            names = entry["equivalents"]["freerasp"]
            assert any(name.startswith("on") for name in names)
            assert any(not name.startswith("on") for name in names)


def test_failed_transport_never_clean():
    report = run_scan(Target(FakeTransport(unreachable=True)), network=False).to_dict()
    assert report["findings"]
    assert {f["status"] for f in report["findings"]} == {"error"}


def test_missing_commands_and_denied_directories_remain_unknown():
    target = Target(
        FakeTransport(
            commands={"echo": "perdedor-ok", "home": "/Users/example"},
            fs={
                "/Users/example/Library/Safari": {"kind": "dir", "denied": True},
                "/Library/LaunchDaemons": {"kind": "dir", "denied": True},
            },
        )
    )
    report = run_scan(
        target,
        only=[
            "macos.behavioural.safari_history",
            "macos.behavioural.launch_agents",
            "macos.design.sip_status",
            "macos.design.software_update_disabled",
        ],
        network=False,
    )
    assert all(f.status.value in ("error", "skipped") for f in report.findings)


@pytest.mark.parametrize("value", ["nan", "inf", "0", "-5", "10000"])
def test_bad_waits_are_bounded(value):
    target = Target(FakeTransport())
    ctx = RunContext(
        platform=Platform.MACOS, params={"timing.sleep_seconds": value, "human.window_seconds": value}
    )
    assert isinstance(timing.probe_sleep_acceleration(target, ctx), Fail)
    assert isinstance(behavioural.probe_input_activity(target, ctx), Fail)
    assert not target.transport.calls


def test_sleep_and_human_activity_positive_and_negative(monkeypatch):
    ctx = RunContext(platform=Platform.MACOS)
    for stamps, elapsed, detected in [
        ("100\n103", 3.2, False),
        ("100\n106", 3.2, True),
        ("100\n100", 0.1, True),
    ]:
        ticks = iter([10, 10 + elapsed])
        monkeypatch.setattr(timing.time, "monotonic", lambda ticks=ticks: next(ticks))
        verdict = timing.probe_sleep_acceleration(
            Target(FakeTransport(commands={"sleep_window": stamps})), ctx
        )
        assert verdict.detected == detected
    monkeypatch.setattr(behavioural.time, "sleep", lambda _: None)
    for seconds, detected in [([100, 130], True), ([100, 1], False)]:
        values = iter(seconds)
        monkeypatch.setattr(behavioural, "_hid_idle_seconds", lambda _, values=values: next(values))
        assert behavioural.probe_input_activity(Target(FakeTransport()), ctx).detected == detected


def test_safe_network_probe_names_and_unknown_errors():
    fake = FakeTransport(
        commands={"curl_dns": "200 10.0.0.1 rc=0", "curl_http": "000 rc=28", "curl_metadata": "000 rc=7"}
    )
    target = Target(fake)
    ctx = RunContext(platform=Platform.MACOS)
    assert design.probe_dns_sinkhole(target, ctx).detected
    assert isinstance(design.probe_simulated_internet(target, ctx), Skip)
    assert isinstance(design.probe_cloud_metadata(target, ctx), Skip)
    for _, command in fake.calls:
        assert ".invalid/" in command or "169.254.169.254" in command
        assert "curl -q" in command and " -L " not in command and "--noproxy" in command


def test_ps_spaces_flags_and_registry_parsers():
    ps = parsing.parse_ps("90 1 4800 /Applications/Little Snitch.app/Contents/MacOS/Little Snitch\n")
    assert ps[0].executable == "Little Snitch"
    assert parsing.traced(ps) == ps
    assert parsing.matching_processes(ps, ["Little Snitch"])
    assert not parsing.traced(parsing.parse_ps("90 1 4000 /usr/bin/lldb\n"))
    assert parsing.parse_launchctl_list("PID Status Label\n- 0 com.apple.motiontrackingd") == [
        "com.apple.motiontrackingd"
    ]
    assert parsing.ioreg_string("<4d61632d41424300>") == "Mac-ABC"
    assert parsing.parse_listen_ports("tcp4 0 0 *.27042 *.* LISTEN\n") == {27042}
    assert parsing.parse_boottime("{ sec = 123, usec = 0 }") == 123


def test_ssh_command_quoting_and_destination_validation():
    command = "printf '%s' '$(touch /tmp/unwanted); text'"
    transport = SshTransport("research@example.invalid", identity="/tmp/key file", port=2222)
    argv = transport.argv(command)
    assert argv[-2] == "research@example.invalid" and argv[-3] == "--"
    assert shlex.split(argv[-1]) == ["sh", "-c", command]
    assert argv[argv.index("-i") + 1] == "/tmp/key file"
    for host in ["-oProxyCommand=bad", "user@host;touch /tmp/x", "host$(id)"]:
        with pytest.raises(ValueError):
            SshTransport(host)
    with pytest.raises(ValueError):
        SshTransport("host", port=0)


def test_local_command_timeout_output_cap_and_linux_guard(monkeypatch):
    assert _subprocess([sys.executable, "-c", "import time; time.sleep(1)"], 0.03) is None
    monkeypatch.setattr("perdedor_macos.transport.MAX_OUTPUT_BYTES", 10)
    assert _subprocess([sys.executable, "-c", "print('x'*100)"], 2).returncode == 75
    if sys.platform != "darwin":
        assert not Target(LocalTransport()).reachable()


def test_transport_permission_errors_not_empty_clean(monkeypatch):
    transport = LocalTransport()
    monkeypatch.setattr(transport, "_exec", lambda *_: CommandResult(77, "", "Operation not permitted"))
    assert transport.exists(["/example/hidden"]) is None
    assert transport.stat(["/example/hidden"]) is None
    assert transport.listdir("/example") is None
    monkeypatch.setattr(transport, "_exec", lambda *_: CommandResult(0, "ls: Operation not permitted\n"))
    assert transport.listdir("/example").entries is None


def test_command_cache_and_deadline(monkeypatch):
    fake = FakeTransport(commands={"echo": "perdedor-ok", "sysctl": "hw.memsize: 1000\n"})
    target = Target(fake)
    assert target.sysctl() == target.sysctl()
    assert [key for key, _ in fake.calls].count("sysctl") == 1
    target.deadline = time.monotonic() - 1
    assert target.run("new", "never executed") is None
    assert not any(key == "new" for key, _ in fake.calls)


def test_cli_list_and_fake_scan(monkeypatch, capsys):
    from perdedor_macos import __main__ as cli

    assert cli.main(["--list-checks", "--only", "class:cpu"]) == 0
    assert "cpu" in capsys.readouterr().out
    monkeypatch.setattr(
        cli, "make_transport", lambda _: FakeTransport.from_fixture(FIXTURES / "apple_silicon.json")
    )
    assert cli.main(["--local", "--only", "macos.env.hw_model", "--no-network"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["platform"] == "macos" and report["findings"][0]["status"] == "clean"


@pytest.mark.parametrize("family,expected", [("MacBook Air", "detected"), ("Mac mini", "clean")])
def test_unified_mac_identifiers_use_hardware_family(family, expected):
    fake = FakeTransport(
        commands={
            "echo": "perdedor-ok",
            "sysctl": "hw.model: Mac14,2\n",
            "system_profiler_SPHardwareDataType": json.dumps(
                {"SPHardwareDataType": [{"machine_name": family}]}
            ),
            "system_profiler_SPCameraDataType": json.dumps({"SPCameraDataType": []}),
            "ioreg_battery": "",
        }
    )
    report = run_scan(Target(fake), only=["macos.env.battery", "macos.env.camera"], network=False)
    assert [finding.status.value for finding in report.findings] == [expected, expected]
