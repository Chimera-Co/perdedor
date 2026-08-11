from __future__ import annotations

from hydra_android import adb
from hydra_android.checks import design, environment


def test_qemu_kernel_flag_reports_error_when_device_unreachable(monkeypatch) -> None:
    """Regression test: an unreachable device and a genuinely-unset property
    both make getprop() return None, but they are not the same finding --
    conflating them previously made an unreachable device silently report
    'clean' for this check instead of 'error', which would make an
    all-errored scan look partially successful."""
    monkeypatch.setattr(adb, "device_reachable", lambda serial: False)
    finding = environment.check_qemu_kernel_flag(serial=None)
    assert finding.status.value == "error"
    assert finding.evidence is None


def test_qemu_kernel_flag_clean_when_reachable_but_property_unset(monkeypatch) -> None:
    monkeypatch.setattr(adb, "device_reachable", lambda serial: True)
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: None)
    finding = environment.check_qemu_kernel_flag(serial=None)
    assert finding.status.value == "clean"


def test_qemu_kernel_flag_detects_when_set_to_one(monkeypatch) -> None:
    monkeypatch.setattr(adb, "device_reachable", lambda serial: True)
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: "1")
    finding = environment.check_qemu_kernel_flag(serial=None)
    assert finding.status.value == "detected"
    assert finding.severity.value == "critical"


def test_build_fingerprint_detects_goldfish_signature(monkeypatch) -> None:
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: "generic/sdk_gphone_x86/generic:14/goldfish")
    finding = environment.check_build_fingerprint(serial=None)
    assert finding.status.value == "detected"


def test_build_fingerprint_clean_for_real_looking_fingerprint(monkeypatch) -> None:
    monkeypatch.setattr(
        adb,
        "getprop",
        lambda serial, prop: "OnePlus/OnePlus9/OnePlus9:14/AP2A.240905.003/release-keys",
    )
    finding = environment.check_build_fingerprint(serial=None)
    assert finding.status.value == "clean"


def test_build_fingerprint_errors_when_adb_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: None)
    finding = environment.check_build_fingerprint(serial=None)
    assert finding.status.value == "error"


def test_cpu_abi_detects_x86(monkeypatch) -> None:
    """No Pafish/al-khaser/VMAware equivalent exists for this check -- it's
    HYDRA-original. An x86/x86_64 ABI means any ARM-only payload needs a
    translation layer (libhoudini) to run at all, which is itself a tell."""
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: "x86_64")
    finding = environment.check_cpu_abi(serial=None)
    assert finding.status.value == "detected"


def test_cpu_abi_clean_for_arm(monkeypatch) -> None:
    monkeypatch.setattr(adb, "getprop", lambda serial, prop: "arm64-v8a")
    finding = environment.check_cpu_abi(serial=None)
    assert finding.status.value == "clean"


def test_avd_default_subnet_detects_stock_nat_range(monkeypatch) -> None:
    monkeypatch.setattr(
        adb, "shell", lambda serial, cmd: "inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0"
    )
    finding = design.check_avd_default_subnet(serial=None)
    assert finding.status.value == "detected"


def test_avd_default_subnet_clean_for_other_range(monkeypatch) -> None:
    monkeypatch.setattr(
        adb, "shell", lambda serial, cmd: "inet 192.168.1.42/24 brd 192.168.1.255 scope global wlan0"
    )
    finding = design.check_avd_default_subnet(serial=None)
    assert finding.status.value == "clean"
