"""Category 1 (Ch.3.2.1, extended by Ch.3.3 to Android): build-fingerprint
and device-node signatures unique to emulated/virtualised Android guests."""

from __future__ import annotations

from hydra_common import FindingFactory
from hydra_common.models import Category, Finding, Platform, Severity

from .. import adb, signatures

_PLATFORM = Platform.ANDROID
_CATEGORY = Category.ENVIRONMENT_ARTIFACT
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)
_ADB_UNREACHABLE = "adb command failed or no device reachable at the given serial"


def _prop_check(
    serial: str | None,
    check_id: str,
    name: str,
    prop: str,
    signature_list: tuple[str, ...],
    severity: Severity,
) -> Finding:
    description = f"getprop {prop}, checked against known emulator signatures."
    value = adb.getprop(serial, prop)
    if value is None:
        return _f.error(check_id, name, description, severity, _ADB_UNREACHABLE)
    lowered = value.lower()
    hit = next((s for s in signature_list if s in lowered), None)
    return _f.bool_check(
        check_id,
        name,
        description,
        severity,
        is_detected=bool(hit),
        evidence=f"{prop}={value!r}" + (f" (matched {hit!r})" if hit else ""),
        remediation=f"Override {prop} to a value consistent with a real, shipped device profile.",
    )


def check_build_fingerprint(serial: str | None = None) -> Finding:
    return _prop_check(
        serial,
        "android.env.build_fingerprint",
        "Build fingerprint",
        "ro.build.fingerprint",
        signatures.BUILD_PROP_EMULATOR_SIGNATURES,
        Severity.CRITICAL,
    )


def check_hardware_prop(serial: str | None = None) -> Finding:
    return _prop_check(
        serial,
        "android.env.hardware_prop",
        "Hardware property",
        "ro.hardware",
        signatures.BUILD_PROP_EMULATOR_SIGNATURES,
        Severity.CRITICAL,
    )


def check_boot_hardware(serial: str | None = None) -> Finding:
    return _prop_check(
        serial,
        "android.env.boot_hardware",
        "Boot hardware property (incl. Cuttlefish)",
        "ro.boot.hardware",
        signatures.BUILD_PROP_EMULATOR_SIGNATURES,
        Severity.CRITICAL,
    )


def check_product_model(serial: str | None = None) -> Finding:
    return _prop_check(
        serial,
        "android.env.product_model",
        "Product model",
        "ro.product.model",
        signatures.BUILD_PROP_EMULATOR_SIGNATURES,
        Severity.HIGH,
    )


def check_manufacturer(serial: str | None = None) -> Finding:
    return _prop_check(
        serial,
        "android.env.manufacturer",
        "Product manufacturer/brand",
        "ro.product.manufacturer",
        signatures.MANUFACTURER_SIGNATURES,
        Severity.HIGH,
    )


def check_gralloc_egl(serial: str | None = None) -> Finding:
    check_id, name = "android.env.gralloc_egl", "Graphics HAL (gralloc/EGL) implementation"
    description = "ro.hardware.gralloc / ro.hardware.egl -- emulators report 'goldfish'/'ranchu'/'emulation' or 'swiftshader'/'mesa'; real devices report a real GPU vendor's HAL name."
    if not adb.device_reachable(serial):
        return _f.error(check_id, name, description, Severity.HIGH, _ADB_UNREACHABLE)
    gralloc = adb.getprop(serial, "ro.hardware.gralloc") or ""
    egl = adb.getprop(serial, "ro.hardware.egl") or ""
    combined = f"{gralloc} {egl}".lower()
    hit = next((s for s in signatures.BUILD_PROP_EMULATOR_SIGNATURES if s in combined), None)
    hit = hit or next((s for s in ("swiftshader", "mesa") if s in combined), None)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=bool(hit),
        evidence=f"gralloc={gralloc!r} egl={egl!r}",
        remediation="Override the graphics HAL properties to a real-GPU-vendor identity, or accept this as a documented residual gap (software rendering is hard to fully hide).",
    )


def check_qemu_properties_present(serial: str | None = None) -> Finding:
    check_id, name = "android.env.qemu_properties_present", "Any 'qemu.*' system property present"
    description = "Dumps all system properties and checks for any 'qemu.' prefix (e.g. qemu.hw.mainkeys, qemu.sf.fake_camera) -- these are emulator-only properties with no real-device equivalent."
    output = adb.shell(serial, "getprop")
    if output is None:
        return _f.error(check_id, name, description, Severity.HIGH, _ADB_UNREACHABLE)
    qemu_props = [line for line in output.splitlines() if line.strip().startswith("[qemu.")]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=bool(qemu_props),
        evidence=qemu_props[:10] or None,
        remediation="Strip all 'qemu.*' properties from the build's default.prop / boot config.",
    )


def check_qemu_kernel_flag(serial: str | None = None) -> Finding:
    check_id, name = "android.env.qemu_kernel_flag", "ro.kernel.qemu flag"
    description = "ro.kernel.qemu is set to 1 by the goldfish/ranchu kernel; absent on real hardware."
    # getprop() collapses "device unreachable" and "property genuinely unset"
    # to the same None -- those are not the same finding (one means no data
    # was collected at all), so the device must be checked reachable
    # explicitly before treating an empty value as a real "clean" result.
    if not adb.device_reachable(serial):
        return _f.error(check_id, name, description, Severity.CRITICAL, _ADB_UNREACHABLE)
    value = adb.getprop(serial, "ro.kernel.qemu")
    if value is None:
        # Reachable device, property just isn't set -- the normal state on
        # real hardware.
        return _f.clean(check_id, name, description, Severity.CRITICAL, "ro.kernel.qemu unset")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.CRITICAL,
        is_detected=value.strip() == "1",
        evidence=f"ro.kernel.qemu={value!r}",
        remediation="Clear ro.kernel.qemu in the build's default.prop / boot config.",
    )


def check_qemu_device_nodes(serial: str | None = None) -> Finding:
    check_id, name = "android.env.qemu_device_nodes", "goldfish/ranchu device nodes"
    description = "Checks for /dev/qemu_pipe, /dev/goldfish_pipe and similar nodes that only exist under an emulated kernel."
    if not adb.device_reachable(serial):
        return _f.error(check_id, name, description, Severity.CRITICAL, _ADB_UNREACHABLE)
    found = [path for path in signatures.QEMU_DEVICE_NODES if adb.file_exists(serial, path)]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.CRITICAL,
        is_detected=bool(found),
        evidence=found or None,
        remediation="No clean fix from userspace -- these nodes are created by the goldfish/ranchu kernel driver itself.",
    )


def check_libhoudini_present(serial: str | None = None) -> Finding:
    check_id, name = "android.env.libhoudini_present", "libhoudini ARM-translation shim"
    description = (
        "Presence of libhoudini means this is an x86 hypervisor translating ARM code, not a genuine ARM "
        "execution path -- CHIMERA's own reason for choosing full-system ARM (TCG) emulation (Ch.7.2)."
    )
    if not adb.device_reachable(serial):
        return _f.error(check_id, name, description, Severity.CRITICAL, _ADB_UNREACHABLE)
    found = [path for path in signatures.LIBHOUDINI_PATHS if adb.file_exists(serial, path)]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.CRITICAL,
        is_detected=bool(found),
        evidence=found or None,
        remediation="Use full-system ARM (qemu-system-aarch64, TCG) instead of an x86 Android VM with a translation layer.",
    )


def check_cpu_abi(serial: str | None = None) -> Finding:
    check_id, name = "android.env.cpu_abi", "CPU ABI (x86 translation-layer requirement)"
    description = (
        "ro.product.cpu.abi -- an x86/x86_64 ABI means any ARM-only native payload requires libhoudini or "
        "an equivalent translation layer to run at all, which is itself a detectable tell (complements the "
        "direct libhoudini file-presence check)."
    )
    value = adb.getprop(serial, "ro.product.cpu.abi")
    if value is None:
        return _f.error(check_id, name, description, Severity.HIGH, _ADB_UNREACHABLE)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=value.strip().lower() in signatures.X86_CPU_ABIS,
        evidence=f"ro.product.cpu.abi={value!r}",
        remediation="Use full-system ARM (qemu-system-aarch64, TCG) so the reported ABI is genuinely ARM, not x86 running a translation layer.",
    )


def run_all(serial: str | None = None) -> list[Finding]:
    return [
        check_build_fingerprint(serial),
        check_hardware_prop(serial),
        check_boot_hardware(serial),
        check_product_model(serial),
        check_manufacturer(serial),
        check_gralloc_egl(serial),
        check_qemu_properties_present(serial),
        check_qemu_kernel_flag(serial),
        check_qemu_device_nodes(serial),
        check_libhoudini_present(serial),
        check_cpu_abi(serial),
    ]
