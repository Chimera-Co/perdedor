"""Replay adb output and test transport boundaries without a device or network."""

from __future__ import annotations

import json
import re
import shlex
import struct
from collections import Counter
from pathlib import Path

import pytest
from perdedor_android import adb
from perdedor_android.checks import native
from perdedor_android.checks._parsers import parse_parcel_string, parse_sensors
from perdedor_android.runner import all_checks, run_scan
from perdedor_common.catalog import load_catalog
from perdedor_common.models import Platform
from perdedor_common.registry import RunContext, run_checks, select

FIXTURES = Path(__file__).parent / "fixtures/android"


class FakeAdb:
    def __init__(self, profile="phone", *, reachable=True):
        fixture = json.loads((FIXTURES / f"{profile}.json").read_text())
        self.commands = fixture["commands"]
        self.paths = set(fixture["paths"])
        self.denied = set()
        self.calls = []
        self.connected = reachable
        self.push_ok = True

    def reachable(self):
        return self.connected

    def shell(self, command, timeout=8):
        self.calls.append((command, timeout))
        if command.startswith(adb.EXISTS_SCRIPT_PREFIX):
            paths = shlex.split(command.split("; do", 1)[0])[3:]
            return adb.ShellResult(
                0, "\n".join(f"{'?' if p in self.denied else int(p in self.paths)} {p}" for p in paths)
            )
        value = self.commands.get(command)
        if isinstance(value, adb.ShellResult):
            return value
        return adb.ShellResult(0, value) if value is not None else adb.ShellResult(1, "", "unavailable")

    def push(self, local, remote, timeout=15):
        self.calls.append(("push " + remote, timeout))
        return self.push_ok


def scan(fake, *only, params=None):
    return run_scan(
        "fixture-device",
        profile="deep",
        only=only,
        network=False,
        transport=fake,
        params={"native.binary": "/missing/perdedor", **(params or {})},
    )


def by_id(report):
    return {f.id.removeprefix("android."): f for f in report.findings}


@pytest.mark.parametrize(
    "profile,expected",
    [
        (
            "avd",
            (
                "env.qemu_kernel_flag",
                "env.product_model",
                "design.sensor_vendors",
                "design.avd_default_subnet",
            ),
        ),
        ("genymotion", ("env.vendor_genymotion", "env.hardware_prop")),
        (
            "bluestacks_nox",
            ("env.vendor_nox", "env.vendor_bluestacks", "design.frida_processes", "design.root_managers"),
        ),
        ("android_x86", ("env.vendor_android_x86", "env.cpu_abi", "design.adb_root", "design.selinux")),
        ("phone", ()),
    ],
)
def test_profiles(profile, expected):
    fake = FakeAdb(profile)
    report = scan(fake)
    findings = by_id(report)
    assert len(findings) == len([s for s in all_checks() if not s.network])
    for id in expected:
        assert findings[id].status.value == "detected", (id, findings[id])
    assert all("raised before" not in f.description for f in findings.values())
    if profile == "phone":
        for id in (
            "env.qemu_kernel_flag",
            "env.build_fingerprint",
            "env.cpu_abi",
            "design.operator_identity",
            "design.sensor_vendors",
            "design.selinux",
            "design.verified_boot",
            "design.screen_lock",
        ):
            assert findings[id].status.value == "clean", id
    assert Counter(cmd for cmd, _ in fake.calls)["getprop"] == 1
    assert all(timeout <= 100 for _, timeout in fake.calls)
    assert not any(cmd.startswith(("ping ", "printf 'GET")) for cmd, _ in fake.calls)
    report.to_dict()


def test_unreachable_never_clean():
    report = scan(FakeAdb(reachable=False))
    assert all(f.status.value == "error" for f in report.findings)


@pytest.mark.parametrize("value,status", [("", "clean"), ("1", "detected"), ("0", "clean")])
def test_qemu_kernel_flag(value, status):
    fake = FakeAdb()
    fake.commands["getprop"] += f"[ro.kernel.qemu]: [{value}]\n"
    finding = scan(fake, "android.env.qemu_kernel_flag").findings[0]
    assert finding.status.value == status


@pytest.mark.parametrize("text", ["", "garbage", "SecurityException: denied"])
def test_content_unreadable_is_unknown(text):
    fake = FakeAdb()
    fake.commands["content query --uri content://sms --projection _id"] = text
    finding = scan(fake, "android.behavioural.sms").findings[0]
    assert finding.status.value in ("skipped", "error")


def test_permission_error_on_stderr_is_not_empty_success():
    fake = FakeAdb()
    fake.commands["pm list packages"] = adb.ShellResult(0, "", "Permission Denial")
    assert scan(fake, "android.design.root_managers").findings[0].status.value == "error"


def test_inaccessible_paths_do_not_mean_clean():
    fake = FakeAdb()
    fake.denied.update(
        adb_path
        for adb_path in __import__("perdedor_android.signatures", fromlist=["SU_PATHS"]).su_candidates("su")
    )
    assert scan(fake, "android.design.su_paths").findings[0].status.value == "error"


def test_partition_build_dates_can_differ():
    fake = FakeAdb()
    fake.commands[
        "getprop"
    ] += "[ro.vendor.build.fingerprint]: [google/shiba/shiba:14/OLDER/100:user/release-keys]\n"
    assert scan(fake, "android.env.fingerprint_consistency").findings[0].status.value == "clean"


def test_identifier_evidence_has_no_subscriber_content():
    fake = FakeAdb()
    private_number = "234150999123456"
    raw = private_number.encode("utf-16-le") + b"\0\0"
    raw += b"\0" * (-len(raw) % 4)
    words = [0, len(private_number)] + list(struct.unpack("<" + "I" * (len(raw) // 4), raw))
    parcel = "\n".join(
        f"0x{i:08x}: " + " ".join(f"{w:08x}" for w in words[i : i + 4]) + " " for i in range(0, len(words), 4)
    )
    assert parse_parcel_string(parcel) == private_number
    fake.commands["service call iphonesubinfo 1 s16 com.android.shell"] = parcel
    finding = scan(fake, "android.design.telephony_identifiers").findings[0]
    assert finding.status.value == "clean"  # IMSIs are not IMEIs and do not require Luhn.
    assert private_number not in json.dumps(finding.to_dict())


def test_selection_and_catalog_complete():
    specs = all_checks()
    assert len(specs) > 150
    ids = [id for s in specs for id in s.ids]
    assert len(ids) == len(set(ids))
    catalog = load_catalog(cache=False)
    for s in specs:
        entry = catalog.check(s.id)
        assert entry["technique"] == s.technique
        assert entry["cost"] == s.cost
        assert entry["references"]
        assert entry["fix"]["how"] and entry["fix"]["chimera"]
    assert all("native" in s.tags for s in select(specs, only=["tag:native"]))
    assert all(not s.network for s in select(specs, network=False))
    assert all(s.check_class == "integrity" for s in select(specs, only=["class:integrity"]))


def static_binary(tmp_path):
    file = tmp_path / "probe"
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", header, 18, 62)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 1)
    file.write_bytes(header + bytes(56))
    return file


@pytest.mark.parametrize("failure", ["none", "push", "execute", "json", "cleanup"])
def test_native_lifecycle(tmp_path, failure):
    fake = FakeAdb("avd")
    directory = "/data/local/tmp/perdedor.ABC123xy"
    fake.commands["mktemp -d /data/local/tmp/perdedor.XXXXXXXX"] = directory + "\n"
    fake.commands[f"chmod 700 {directory}/probe"] = ""
    command = f"timeout 60 {directory}/probe --only class:cpu,class:timing --no-network"
    fake.commands[command] = json.dumps(
        {
            "platform": "linux",
            "findings": [
                {"id": "linux." + rel, "technique": tech, "status": "detected", "evidence": {"bit31": 1}}
                for rel, (tech, _) in native.NATIVE_CHECKS.items()
            ],
        }
    )
    cleanup = f"rm -f {directory}/probe && rmdir {directory}"
    fake.commands[cleanup] = ""
    if failure == "push":
        fake.push_ok = False
    if failure == "execute":
        fake.commands[command] = adb.ShellResult(124, "")
    if failure == "json":
        fake.commands[command] = "{}"
    if failure == "cleanup":
        fake.commands[cleanup] = adb.ShellResult(1, "")
    results = scan(fake, "tag:native", params={"native.binary": str(static_binary(tmp_path))})
    assert len(results.findings) == 2
    assert all(f.status.value == ("detected" if failure == "none" else "error") for f in results.findings)
    assert Counter(c for c, _ in fake.calls)[cleanup] == 1
    assert Counter(c for c, _ in fake.calls)[command] <= 1


def test_native_skips_arm_without_upload(tmp_path):
    fake = FakeAdb()
    result = scan(fake, "tag:native", params={"native.binary": str(static_binary(tmp_path))})
    assert all(f.status.value == "skipped" for f in result.findings)
    assert not any(c.startswith("push") for c, _ in fake.calls)


def test_native_registry_matches_current_source():
    root = Path(__file__).resolve().parents[1]
    registered = {}
    pattern = re.compile(r'PERDEDOR_REGISTER\(\w+, "((?:cpu|timing)\.[^"]+)", "[^"]+", false, "([^"]+)"\);')
    for folder in ("common", "linux"):
        for path in (root / "native/src" / folder).glob("*.cpp"):
            for technique, rel in pattern.findall(path.read_text()):
                registered[rel] = technique
    assert registered == {rel: tech for rel, (tech, _) in native.NATIVE_CHECKS.items()}


def test_adb_command_is_single_quoted_remote_argument(monkeypatch):
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return type("Result", (), {"returncode": 0, "stdout": "ok\r\n", "stderr": ""})()

    monkeypatch.setattr(adb.subprocess, "run", run)
    result = adb.AdbTransport("serial with spaces").shell("getprop")
    assert calls[0][0] == ["adb", "-s", "serial with spaces", "shell", "getprop"]
    assert result.stdout == "ok\n"
    assert calls[0][1]["timeout"] > 0


def test_parsers():
    assert adb.parse_getprop("[a]: [b]\n[m]: [first\nsecond]\n") == {"a": "b", "m": "first\nsecond"}
    assert adb.parse_proc_net_tcp("header\n0: 00000000:69A2 00000000:0000 0A\n") == [("00000000", 27042)]
    assert len(parse_sensors(FakeAdb().commands["dumpsys sensorservice"])) == 6


def test_registered_functions_accept_context():
    fake = FakeAdb()
    ctx = RunContext(platform=Platform.ANDROID, target=fake)
    findings = run_checks(select(all_checks(), only=["android.env.qemu_kernel_flag"]), ctx)
    assert findings[0].status.value == "clean"
