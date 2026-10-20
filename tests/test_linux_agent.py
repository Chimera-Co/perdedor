from __future__ import annotations

from perdedor_linux import signatures
from perdedor_linux.checks import design, environment
from perdedor_linux.cpu import CpuidResult
from perdedor_linux.utils import any_signature_in


def test_cpuid_vendor_string_decode_order_is_ebx_ecx_edx() -> None:
    """Regression test for a real bug caught during development: the
    hypervisor signature leaf (0x40000000) packs its 12-char string into
    EBX,ECX,EDX (per the QEMU/KVM convention) -- NOT EBX,EDX,ECX, which is
    leaf 0's vendor-string order. Getting this backwards silently decodes
    to garbage instead of 'KVMKVMKVM\\0\\0\\0', which would make the
    hypervisor-vendor check always report clean on a real KVM/QEMU guest."""
    signature = b"KVMKVMKVM\0\0\0"
    ebx = int.from_bytes(signature[0:4], "little")
    ecx = int.from_bytes(signature[4:8], "little")
    edx = int.from_bytes(signature[8:12], "little")

    result = CpuidResult(eax=0x40000000, ebx=ebx, ecx=ecx, edx=edx)

    assert result.vendor_string == "KVMKVMKVM\0\0\0"
    assert result.vendor_string in signatures.CPUID_HYPERVISOR_VENDORS


def test_any_signature_in_matches_known_vm_vendor_case_insensitively() -> None:
    assert any_signature_in("QEMU Standard PC", signatures.DMI_VENDOR_SIGNATURES) == "qemu"
    assert any_signature_in("innotek GmbH", signatures.DMI_VENDOR_SIGNATURES) == "innotek"
    assert any_signature_in("Dell Inc.", signatures.DMI_VENDOR_SIGNATURES) is None
    assert any_signature_in(None, signatures.DMI_VENDOR_SIGNATURES) is None


def test_suspicious_hostname_check_flags_sandbox_token(monkeypatch) -> None:
    monkeypatch.setattr(design.socket, "gethostname", lambda: "malware-sandbox-01")
    monkeypatch.setenv("USER", "analyst")
    finding = design.check_suspicious_hostname_or_user()
    assert finding.status.value == "detected"
    assert "hostname" in str(finding.evidence)


def test_suspicious_hostname_check_clean_for_ordinary_name(monkeypatch) -> None:
    monkeypatch.setattr(design.socket, "gethostname", lambda: "DESKTOP-2IC3SIJ")
    monkeypatch.setenv("USER", "arjun.mehta")
    finding = design.check_suspicious_hostname_or_user()
    assert finding.status.value == "clean"


def test_exact_sandbox_username_matches_short_name_exactly(monkeypatch) -> None:
    """Regression test for the exact-match/substring distinction: al-khaser
    blacklists short usernames like 'test' as an exact match rather than a
    substring, because substring matching against 'test' would false-positive
    on plenty of ordinary real names (e.g. 'testarossa')."""
    monkeypatch.setenv("USER", "test")
    finding = design.check_exact_sandbox_username()
    assert finding.status.value == "detected"


def test_exact_sandbox_username_does_not_substring_match(monkeypatch) -> None:
    monkeypatch.setenv("USER", "testarossa")
    finding = design.check_exact_sandbox_username()
    assert finding.status.value == "clean"


def test_cpu_brand_string_detects_qemu_signature(monkeypatch) -> None:
    monkeypatch.setattr(environment.cpu, "brand_string", lambda: "QEMU Virtual CPU version 2.5+")
    finding = environment.check_cpu_brand_string()
    assert finding.status.value == "detected"
    assert finding.severity.value == "high"


def test_cpu_brand_string_clean_for_real_cpu_name(monkeypatch) -> None:
    monkeypatch.setattr(environment.cpu, "brand_string", lambda: "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz")
    finding = environment.check_cpu_brand_string()
    assert finding.status.value == "clean"


def test_cpu_brand_string_skipped_when_cpuid_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(environment.cpu, "brand_string", lambda: None)
    finding = environment.check_cpu_brand_string()
    assert finding.status.value == "skipped"


def test_supplied_cpuid_helper_is_used_without_building(tmp_path, monkeypatch):
    import subprocess

    from perdedor_linux import cpu

    helper = tmp_path / "helper"
    subprocess.run(
        ["cc", "-O2", "-o", str(helper), str(cpu._NATIVE_DIR / "cpuid_rdtsc.c")], check=True, capture_output=True
    )
    monkeypatch.setattr(cpu, "_BINARY", tmp_path / "never-built")
    monkeypatch.setenv("PERDEDOR_CPUID_HELPER", str(helper))
    assert cpu._ensure_built() == helper
    assert not (tmp_path / "never-built").exists()
    monkeypatch.setenv("PERDEDOR_CPUID_HELPER", str(tmp_path / "missing"))
    assert cpu._ensure_built() is None
