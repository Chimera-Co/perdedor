"""v1 environment checks: build identity, emulator properties, goldfish device
nodes and ARM-on-x86 translation. Ids are frozen; newer checks of the same
classes live in emulator_props.py, emulator_files.py and kernel_cpu.py."""

from __future__ import annotations

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, Verdict, existing, props, substr_hits

REG = Checks()


def _prop_signature(dev: Device, prop: str, tokens: tuple[str, ...]) -> Verdict:
    value = props(dev).get(prop, "")
    hits = substr_hits(value, tokens)
    return Verdict(bool(hits), {"property": prop, "value": value, "matched": hits or None})


@REG.check(
    "android.env.build_fingerprint",
    "emulator.android_build_identity",
    name="Build fingerprint",
    description="ro.build.fingerprint checked against emulator build names (generic, sdk_gphone, goldfish, "
    "ranchu, vbox86, cutf_cvm...). Shipped devices carry the vendor's product fingerprint.",
    severity=Severity.CRITICAL,
    remediation="Build or patch the image with a real device fingerprint (vendor/product/device:version/id/"
    "incremental:user/release-keys) and keep the partition fingerprints consistent with it.",
)
def check_build_fingerprint(dev: Device, ctx: RunContext) -> Verdict:
    return _prop_signature(dev, "ro.build.fingerprint", sig.BUILD_PROP_EMULATOR_SIGNATURES)


@REG.check(
    "android.env.hardware_prop",
    "emulator.android_properties",
    name="Hardware property (ro.hardware)",
    description="ro.hardware names the board HAL; emulators report goldfish, ranchu, vbox86, cutf_cvm or "
    "android_x86.",
    severity=Severity.CRITICAL,
    remediation="Set androidboot.hardware / ro.hardware to the real SoC name of the profile you imitate "
    "(e.g. qcom, exynos9820, tensor) and rename the matching init.<hw>.rc files.",
)
def check_hardware_prop(dev: Device, ctx: RunContext) -> Verdict:
    return _prop_signature(dev, "ro.hardware", sig.BUILD_PROP_EMULATOR_SIGNATURES)


@REG.check(
    "android.env.boot_hardware",
    "emulator.android_properties",
    name="Boot hardware property (incl. Cuttlefish)",
    description="ro.boot.hardware comes from the kernel command line (androidboot.hardware=) and names "
    "the virtual board on goldfish/ranchu/Cuttlefish/Android-x86.",
    severity=Severity.CRITICAL,
    remediation="Change androidboot.hardware on the kernel command line (bootloader/GRUB config) to a real "
    "SoC name.",
)
def check_boot_hardware(dev: Device, ctx: RunContext) -> Verdict:
    return _prop_signature(dev, "ro.boot.hardware", sig.BUILD_PROP_EMULATOR_SIGNATURES)


@REG.check(
    "android.env.product_model",
    "emulator.android_build_identity",
    name="Product model",
    description="ro.product.model checked against emulator build names (sdk_gphone, google_sdk, generic...).",
    severity=Severity.HIGH,
    remediation="Override ro.product.model (and every partition copy: ro.product.system/vendor/odm.model) "
    "with a shipped device model.",
)
def check_product_model(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.product.model", "")
    hits = substr_hits(value, sig.BUILD_PROP_EMULATOR_SIGNATURES + sig.MODEL_SUBSTRINGS)
    if value.strip().lower() == "sdk":
        hits.append("sdk")
    return Verdict(bool(hits), {"property": "ro.product.model", "value": value, "matched": hits or None})


@REG.check(
    "android.env.manufacturer",
    "emulator.android_build_identity",
    name="Product manufacturer",
    description="ro.product.manufacturer is 'Genymotion' on Genymotion and 'unknown' on many emulator images.",
    severity=Severity.HIGH,
    remediation="Set ro.product.manufacturer (all partitions) to the vendor of the imitated device.",
)
def check_manufacturer(dev: Device, ctx: RunContext) -> Verdict:
    return _prop_signature(dev, "ro.product.manufacturer", sig.MANUFACTURER_SIGNATURES)


@REG.check(
    "android.env.gralloc_egl",
    "emulator.android_properties",
    name="Graphics HAL (gralloc/EGL) implementation",
    description="ro.hardware.gralloc / ro.hardware.egl report goldfish, ranchu, emulation, swiftshader or "
    "mesa under emulation; real devices name their GPU vendor's HAL (adreno, mali, img).",
    severity=Severity.HIGH,
    remediation="Use a GPU-vendor HAL name, or accept software rendering as a residual tell and document it.",
)
def check_gralloc_egl(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    gralloc, egl = values.get("ro.hardware.gralloc", ""), values.get("ro.hardware.egl", "")
    hits = substr_hits(f"{gralloc} {egl}", sig.BUILD_PROP_EMULATOR_SIGNATURES + sig.HAL_SIGNATURES)
    return Verdict(bool(hits), {"gralloc": gralloc, "egl": egl, "matched": hits or None})


@REG.check(
    "android.env.qemu_properties_present",
    "emulator.android_properties",
    name="Any 'qemu.*' system property present",
    description="qemu.* properties (qemu.hw.mainkeys, qemu.sf.fake_camera, qemu.sf.lcd_density...) are set "
    "only by the emulator's qemu-props service (anti-emulator known_props).",
    severity=Severity.HIGH,
    remediation="Remove the qemu-props service and every qemu.* property from the image.",
)
def check_qemu_properties_present(dev: Device, ctx: RunContext) -> Verdict:
    found = sorted(k for k in props(dev) if k.startswith("qemu."))
    return Verdict(bool(found), found[:20] or None)


@REG.check(
    "android.env.qemu_kernel_flag",
    "emulator.android_properties",
    name="ro.kernel.qemu flag",
    description="ro.kernel.qemu=1 is set by the goldfish/ranchu kernel command line; absent on real hardware.",
    severity=Severity.CRITICAL,
    remediation="Remove qemu=1 from the kernel command line and clear ro.kernel.qemu.",
)
def check_qemu_kernel_flag(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.kernel.qemu", "")
    return Verdict(value.strip() == "1", f"ro.kernel.qemu={value!r}" if value else "ro.kernel.qemu unset")


@REG.check(
    "android.env.qemu_device_nodes",
    "emulator.android_files",
    name="goldfish/ranchu device nodes",
    description="/dev/qemu_pipe, /dev/goldfish_pipe, /dev/goldfish_audio and /dev/socket/qemud exist only "
    "under the emulator kernel (anti-emulator hasPipes).",
    severity=Severity.CRITICAL,
    remediation="No user-space fix: these nodes come from goldfish kernel drivers. Use a kernel without them "
    "or a real device.",
)
def check_qemu_device_nodes(dev: Device, ctx: RunContext) -> Verdict:
    found = existing(dev, sig.QEMU_DEVICE_NODES)
    return Verdict(bool(found), found or None)


@REG.check(
    "android.env.libhoudini_present",
    "emulator.binary_translation",
    name="libhoudini ARM-translation shim",
    description="libhoudini.so translates ARM code on x86 Android (BlueStacks, Nox, Android-x86, Genymotion "
    "ARM translation); its presence means the 'phone' is an x86 machine.",
    severity=Severity.CRITICAL,
    remediation="Run ARM samples on ARM: a real phone, an ARM host, or full-system ARM emulation without a "
    "translation layer.",
)
def check_libhoudini_present(dev: Device, ctx: RunContext) -> Verdict:
    found = existing(dev, sig.LIBHOUDINI_PATHS)
    return Verdict(bool(found), found or None)


@REG.check(
    "android.env.cpu_abi",
    "emulator.binary_translation",
    name="CPU ABI (x86 translation-layer requirement)",
    description="ro.product.cpu.abi=x86/x86_64 means ARM-only native code needs a translator; almost every "
    "consumer phone is ARM.",
    severity=Severity.HIGH,
    remediation="Use an ARM target so the primary ABI is arm64-v8a.",
)
def check_cpu_abi(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.product.cpu.abi", "")
    return Verdict(value.strip().lower() in sig.X86_CPU_ABIS, f"ro.product.cpu.abi={value!r}")


CHECKS = REG.specs
