"""System properties of emulated Android builds (beyond the v1 set).

Property names and values follow anti-emulator (FindEmulator.known_props,
hasEmulatorBuild), framgia EmulatorDetector (PROPERTIES, checkBasic),
reveny/Android-Emulator-Detection (checkHardwareProps, checkArmTranslation),
CalebFenton/AndroidEmulatorDetect and the AOSP goldfish/Cuttlefish device
trees. See signatures.py for every list.
"""

from __future__ import annotations

import re

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, Skip, Verdict, existing, props, substr_hits, token_re

REG = Checks()

# anti-emulator / framgia hasQEmuProps: a QEMU environment is declared when
# at least MIN_PROPERTIES_THRESHOLD (0x5) of the 15 known properties match.
QEMU_PROPS_THRESHOLD = 0x5
KNOWN_QEMU_PROPS: tuple[tuple[str, str | None], ...] = (
    ("init.svc.qemud", None),
    ("init.svc.qemu-props", None),
    ("qemu.hw.mainkeys", None),
    ("qemu.sf.fake_camera", None),
    ("qemu.sf.lcd_density", None),
    ("ro.bootloader", "unknown"),
    ("ro.bootmode", "unknown"),
    ("ro.hardware", "goldfish"),
    ("ro.kernel.android.qemud", None),
    ("ro.kernel.qemu.gles", None),
    ("ro.kernel.qemu", "1"),
    ("ro.product.device", "generic"),
    ("ro.product.model", "sdk"),
    ("ro.product.name", "sdk"),
    ("ro.serialno", None),
)


def _exact(dev: Device, prop: str) -> Verdict:
    value = props(dev).get(prop, "")
    bad = {v.lower() for v in sig.EXACT_PROP_VALUES[prop]}
    return Verdict(value.strip().lower() in bad, {"property": prop, "value": value})


@REG.check(
    "android.env.qemu_props_threshold",
    "emulator.android_properties",
    name="anti-emulator QEMU property score",
    description="Counts the 15 properties of anti-emulator hasQEmuProps / framgia checkQEmuProps; five or "
    "more matches is that library's QEMU verdict.",
    severity=Severity.HIGH,
    remediation="Remove the qemu-props service, qemu.* and ro.kernel.qemu* properties and give the image a "
    "real bootloader, product and model identity.",
)
def check_qemu_props_threshold(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    matched = []
    for name, seek in KNOWN_QEMU_PROPS:
        value = values.get(name)
        # The upstream libraries count a property whose value is merely non-null
        # (Utilities.getProp returns "" for unset properties on modern Android,
        # so only non-empty values are counted here).
        if (seek is None and value) or (seek is not None and value and seek in value):
            matched.append(name)
    threshold = ctx.param("android.qemu_props_threshold", QEMU_PROPS_THRESHOLD)
    return Verdict(
        len(matched) >= threshold,
        {"matched": matched},
        measurement={"matched": len(matched), "threshold": threshold, "of": len(KNOWN_QEMU_PROPS)},
    )


@REG.check(
    "android.env.boot_qemu",
    "emulator.android_properties",
    name="ro.boot.qemu flag",
    description="ro.boot.qemu=1 comes from androidboot.qemu=1 on the emulator kernel command line (Android "
    "10+ goldfish/ranchu images).",
    severity=Severity.CRITICAL,
    remediation="Remove androidboot.qemu from the kernel command line.",
)
def check_boot_qemu(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.boot.qemu", "")
    return Verdict(value.strip() == "1", f"ro.boot.qemu={value!r}" if value else "ro.boot.qemu unset")


@REG.check(
    "android.env.qemu_boot_props_present",
    "emulator.android_properties",
    name="ro.kernel.qemu.* / ro.boot.qemu.* properties",
    description="Emulator boot properties such as ro.kernel.qemu.gles, ro.kernel.android.qemud, "
    "ro.boot.qemu.avd_name and ro.boot.qemu.gltransport (the last one leaks the AVD name).",
    severity=Severity.CRITICAL,
    remediation="Strip every ro.kernel.qemu*, ro.kernel.android.qemud and ro.boot.qemu.* property from the "
    "kernel command line and default properties.",
)
def check_qemu_boot_props(dev: Device, ctx: RunContext) -> Verdict:
    found = {
        k: v
        for k, v in props(dev).items()
        if k.startswith(("ro.kernel.qemu.", "ro.boot.qemu.", "ro.kernel.android.qemud", "ro.qemu."))
    }
    return Verdict(bool(found), dict(sorted(found.items())[:20]) or None)


@REG.check(
    "android.env.qemu_init_services",
    "emulator.android_properties",
    name="Emulator init services",
    description="init.svc.<name> properties of emulator daemons: qemud, qemu-props (anti-emulator), "
    "goldfish-logcat, ranchu-setup, qemu-adb-setup (AOSP goldfish), genyd, noxd, bstsvcmgr, ldinit.",
    severity=Severity.CRITICAL,
    remediation="Remove the emulator daemons from the init scripts or rename them; their init.svc.* "
    "properties are world-readable.",
)
def check_qemu_init_services(dev: Device, ctx: RunContext) -> Verdict:
    found = {
        k: v
        for k, v in props(dev).items()
        if k.startswith("init.svc.") and any(t in k[len("init.svc.") :] for t in sig.INIT_SERVICE_TOKENS)
    }
    return Verdict(bool(found), dict(sorted(found.items())) or None)


@REG.check(
    "android.env.bootloader_prop",
    "emulator.android_properties",
    name="Bootloader version (ro.bootloader)",
    description="ro.bootloader is 'unknown' on emulator images (anti-emulator known_props) and 'nox' on Nox "
    "(reveny); phones report the vendor bootloader version.",
    severity=Severity.MEDIUM,
    remediation="Set ro.bootloader/ro.boot.bootloader to a vendor bootloader version string.",
)
def check_bootloader_prop(dev: Device, ctx: RunContext) -> Verdict:
    return _exact(dev, "ro.bootloader")


@REG.check(
    "android.env.bootmode_prop",
    "emulator.android_properties",
    name="Boot mode (ro.bootmode)",
    description="ro.bootmode='unknown' is one of anti-emulator's known QEMU properties; phones report "
    "normal/charger/recovery or leave it unset.",
    severity=Severity.LOW,
    remediation="Set androidboot.mode/ro.bootmode as the imitated device's bootloader does.",
)
def check_bootmode_prop(dev: Device, ctx: RunContext) -> Verdict:
    return _exact(dev, "ro.bootmode")


@REG.check(
    "android.env.board_platform",
    "emulator.android_properties",
    name="Board and platform (ro.product.board, ro.board.platform)",
    description="ro.product.board / ro.board.platform name the SoC on phones (msmnails, kalama, exynos, mt6789) "
    "and goldfish/ranchu/android_x86 on emulators; anti-emulator flags Build.BOARD=='unknown'.",
    severity=Severity.HIGH,
    remediation="Set the board/platform properties to the imitated SoC.",
)
def check_board_platform(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    hits = {}
    for prop in ("ro.product.board", "ro.board.platform"):
        value = values.get(prop, "")
        if value.strip().lower() in {v.lower() for v in sig.EXACT_PROP_VALUES[prop]} or substr_hits(
            value, ("goldfish", "ranchu", "android_x86", "vbox86")
        ):
            hits[prop] = value
    return Verdict(
        bool(hits),
        {p: values.get(p, "") for p in ("ro.product.board", "ro.board.platform")} | {"matched": hits},
    )


@REG.check(
    "android.env.product_device",
    "emulator.android_build_identity",
    name="Product device (ro.product.device)",
    description="ro.product.device equals generic/generic_x86_64/emu64x/vbox86p/vsoc_x86_64 on emulator and "
    "virtual-device builds (anti-emulator, framgia, reveny deviceInfo).",
    severity=Severity.HIGH,
    remediation="Set ro.product.device (all partitions) to the imitated device codename.",
)
def check_product_device(dev: Device, ctx: RunContext) -> Verdict:
    return _exact(dev, "ro.product.device")


@REG.check(
    "android.env.product_name",
    "emulator.android_build_identity",
    name="Product name (ro.product.name)",
    description="ro.product.name equals sdk/google_sdk/sdk_gphone64_x86_64/vbox86p/aosp_cf_* on emulator "
    "builds (framgia checkBasic, reveny products).",
    severity=Severity.HIGH,
    remediation="Set ro.product.name (all partitions) to the imitated product name.",
)
def check_product_name(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    value = values.get("ro.product.name", "")
    bad = value.strip().lower() in {v.lower() for v in sig.EXACT_PROP_VALUES["ro.product.name"]}
    hits = substr_hits(value, ("sdk_gphone", "sdk_phone", "google_sdk", "vbox86"))
    return Verdict(bad or bool(hits), {"property": "ro.product.name", "value": value})


@REG.check(
    "android.env.build_product",
    "emulator.android_build_identity",
    name="Build product (ro.build.product)",
    description="ro.build.product is reveny checkHardwareProps' 'product' and equals sdk/vbox86p/nox/andy/"
    "emu64x on emulators.",
    severity=Severity.HIGH,
    remediation="Set ro.build.product to the imitated device codename.",
)
def check_build_product(dev: Device, ctx: RunContext) -> Verdict:
    return _exact(dev, "ro.build.product")


@REG.check(
    "android.env.product_brand",
    "emulator.android_build_identity",
    name="Product brand (ro.product.brand)",
    description="Build.BRAND 'generic' (framgia checkBasic: BRAND and DEVICE start with 'generic', "
    "CalebFenton) or 'Android' on AOSP emulator images.",
    severity=Severity.MEDIUM,
    remediation="Set ro.product.brand (all partitions) to the imitated vendor brand.",
)
def check_product_brand(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    brand = values.get("ro.product.brand", "")
    device = values.get("ro.product.device", "")
    bad = brand.strip() in sig.EXACT_PROP_VALUES["ro.product.brand"] or (
        brand.startswith("generic") and device.startswith("generic")
    )
    return Verdict(bad, {"ro.product.brand": brand, "ro.product.device": device})


@REG.check(
    "android.env.build_flavor",
    "emulator.android_build_identity",
    name="Build flavor / description",
    description="ro.build.flavor and ro.build.description carry the lunch target (sdk_gphone64_x86_64-"
    "userdebug, aosp_cf_x86_64_phone-userdebug, vbox86p-userdebug).",
    severity=Severity.HIGH,
    remediation="Rebuild with the target name of a shipped product or override ro.build.flavor/"
    "ro.build.description consistently with the fingerprint.",
)
def check_build_flavor(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    fields = {
        p: values.get(p, "") for p in ("ro.build.flavor", "ro.build.description", "ro.build.display.id")
    }
    hits = {p: v for p, v in fields.items() if substr_hits(v, sig.FLAVOR_SUBSTRINGS)}
    return Verdict(bool(hits), {"values": fields, "matched": hits or None})


@REG.check(
    "android.env.build_type",
    "emulator.android_build_identity",
    name="Build type (ro.build.type)",
    description="Production devices ship 'user' builds; emulator and lab images are 'userdebug' or 'eng' "
    "(CalebFenton isNotUserBuild).",
    severity=Severity.MEDIUM,
    remediation="Use a 'user' build, or override ro.build.type and the fingerprint's build type together.",
)
def check_build_type(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.build.type", "")
    return Verdict(value.strip() not in ("user", ""), f"ro.build.type={value!r}")


@REG.check(
    "android.env.build_id",
    "emulator.android_build_identity",
    name="Build id of the original SDK emulator (FRF91)",
    description="ro.build.id FRF91 is the build id of the Android 2.2 SDK emulator image that "
    "CalebFenton/AndroidEmulatorDetect tests; still copied into cheap clones.",
    severity=Severity.LOW,
    remediation="Use a real build id (e.g. AP2A.240905.003) consistent with the fingerprint.",
)
def check_build_id(dev: Device, ctx: RunContext) -> Verdict:
    value = props(dev).get("ro.build.id", "")
    return Verdict("FRF91" in value, f"ro.build.id={value!r}")


@REG.check(
    "android.env.serialno",
    "emulator.android_properties",
    name="Serial number (ro.serialno / ro.boot.serialno)",
    description="AVD serials start with EMULATOR, Cuttlefish uses CUTTLEFISHCVD<nn>, Nox serials contain "
    "'nox' (framgia); empty or placeholder serials (unknown, 0123456789ABCDEF) are typical of VM images.",
    severity=Severity.MEDIUM,
    remediation="Provide a vendor-format serial number through androidboot.serialno.",
)
def check_serialno(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    serial = values.get("ro.serialno") or values.get("ro.boot.serialno") or ""
    low = serial.strip().lower()
    bad = (
        not low or low in sig.SERIAL_PLACEHOLDERS or any(low.startswith(p) for p in sig.SERIAL_PREFIXES)
    ) or "nox" in low
    return Verdict(bad, {"serial": serial or None})


@REG.check(
    "android.env.hardware_hal_props",
    "emulator.android_properties",
    name="Other HAL properties (ro.hardware.*)",
    description="ro.hardware.audio.primary, .vulkan, .power, .camera, .sensors and friends name goldfish/"
    "ranchu/android_x86 HALs on emulators.",
    severity=Severity.HIGH,
    remediation="Rename or replace the emulator HALs; the property names are visible to every app.",
)
def check_hardware_hal_props(dev: Device, ctx: RunContext) -> Verdict:
    pattern = token_re(sig.BUILD_PROP_EMULATOR_SIGNATURES + sig.HAL_SIGNATURES)
    found = {
        k: v
        for k, v in props(dev).items()
        if k.startswith(("ro.hardware.", "ro.boot.hardware."))
        and k not in ("ro.hardware.gralloc", "ro.hardware.egl")
        and pattern.search(v)
    }
    return Verdict(bool(found), dict(sorted(found.items())) or None)


@REG.check(
    "android.env.partition_identity",
    "emulator.android_build_identity",
    name="Partition build identity (system/vendor/odm product props)",
    description="Android 10+ keeps ro.product.<partition>.* and ro.<partition>.build.fingerprint copies; "
    "spoofers usually change only ro.product.model, so emulator names survive in the partition copies.",
    severity=Severity.HIGH,
    remediation="Change every partition copy of the product properties and fingerprints, not just the "
    "top-level ones.",
)
def check_partition_identity(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    pattern = token_re(
        sig.BUILD_PROP_EMULATOR_SIGNATURES + ("sdk", "emu64x", "emu64a", "vsoc_x86_64", "vsoc_arm64")
    )
    keys = [
        k
        for k in values
        if re.match(
            r"^ro\.(product\.(system|vendor|odm|product|system_ext|bootimage|vendor_dlkm)\.|"
            r"(system|vendor|odm|product|system_ext|bootimage)\.build\.fingerprint)",
            k,
        )
    ]
    hits = {k: values[k] for k in sorted(keys) if pattern.search(values[k])}
    return Verdict(bool(hits), hits or {"checked": len(keys)})


@REG.check(
    "android.env.fingerprint_consistency",
    "emulator.android_build_identity",
    name="Fingerprint consistency across partitions",
    description="Partition fingerprints with different brand/product/device fields can expose inconsistent identity; "
    "build ids and security patch dates may legitimately differ after an OTA.",
    severity=Severity.LOW,
    remediation="Keep the brand/product/device identity consistent with the selected stock firmware.",
)
def check_fingerprint_consistency(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    keys = ("ro.build.fingerprint", "ro.system.build.fingerprint", "ro.vendor.build.fingerprint")
    identities = {k: values[k].split(":", 1)[0] for k in keys if values.get(k) and ":" in values[k]}
    if len(identities) < 2:
        raise Skip("fewer than two comparable partition identities")
    return Verdict(len(set(identities.values())) > 1, identities, confidence=0.4)


@REG.check(
    "android.env.native_bridge",
    "emulator.binary_translation",
    name="Native bridge (ro.dalvik.vm.native.bridge)",
    description="A native bridge (libhoudini.so, libndk_translation.so) runs ARM libraries on x86 "
    "(reveny checkArmTranslation). Magisk Zygisk (v24-26) also used this property to load libzygisk.so; that "
    "case is reported here as root evidence rather than translation.",
    severity=Severity.HIGH,
    remediation="Run ARM code on an ARM CPU so no native bridge is configured.",
)
def check_native_bridge(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    bridge = values.get("ro.dalvik.vm.native.bridge", "")
    enabled = values.get("ro.enable.native.bridge.exec", "")
    zygisk = "zygisk" in bridge.lower()
    translating = (bridge not in ("", "0") and not zygisk) or enabled == "1"
    return Verdict(
        translating,
        {
            "ro.dalvik.vm.native.bridge": bridge or None,
            "ro.enable.native.bridge.exec": enabled or None,
            "zygisk": zygisk,
        },
    )


@REG.check(
    "android.env.isa_translation",
    "emulator.binary_translation",
    name="ARM ISA mapped to x86 (ro.dalvik.vm.isa.*)",
    description="ro.dalvik.vm.isa.arm=x86 / ro.dalvik.vm.isa.arm64=x86_64 tells ART to run ARM apps on the "
    "x86 ISA through a translator (reveny checkArmTranslation).",
    severity=Severity.HIGH,
    remediation="Use an ARM device or ARM emulation without an ISA mapping.",
)
def check_isa_translation(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    arm, arm64 = values.get("ro.dalvik.vm.isa.arm", ""), values.get("ro.dalvik.vm.isa.arm64", "")
    return Verdict(
        arm.startswith("x86") or arm64.startswith("x86"),
        {"ro.dalvik.vm.isa.arm": arm or None, "ro.dalvik.vm.isa.arm64": arm64 or None},
    )


@REG.check(
    "android.env.abi_list",
    "emulator.binary_translation",
    name="ABI list (ro.product.cpu.abilist)",
    description="An ABI list containing x86 (reveny checkCPUArchitecture), especially x86 next to ARM ABIs, "
    "shows an x86 CPU that advertises translated ARM support.",
    severity=Severity.HIGH,
    remediation="Use an ARM target; ARM phones list only arm64-v8a/armeabi-v7a/armeabi.",
)
def check_abi_list(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    abilist = values.get("ro.product.cpu.abilist", "") or values.get("ro.system.product.cpu.abilist", "")
    abis = [a.strip() for a in abilist.split(",") if a.strip()]
    x86 = [a for a in abis if a.startswith("x86")]
    arm = [a for a in abis if a.startswith("arm")]
    return Verdict(bool(x86), {"abilist": abis, "x86": x86, "translated_arm": bool(x86 and arm)})


@REG.check(
    "android.env.ndk_translation",
    "emulator.binary_translation",
    name="libndk_translation (Google ARM translator)",
    description="libndk_translation.so and the /system/bin/arm*/linker* it uses are Google's ARM-on-x86 "
    "translator in AVD x86 images, ChromeOS ARC and Windows Subsystem for Android.",
    severity=Severity.CRITICAL,
    remediation="Run ARM samples on ARM hardware or ARM system emulation.",
)
def check_ndk_translation(dev: Device, ctx: RunContext) -> Verdict:
    found = existing(dev, sig.NDK_TRANSLATION_PATHS)
    return Verdict(bool(found), found or None)


@REG.check(
    "android.env.build_characteristics_tablet_default",
    "emulator.android_build_identity",
    name="Generic build characteristics (default/tablet without a phone radio)",
    description="ro.build.characteristics 'default' or 'tablet' combined with an x86 ABI is the AOSP default "
    "of Android-x86/Bliss/PrimeOS images; phone builds declare 'nosdcard' or vendor values.",
    severity=Severity.LOW,
    remediation="Set ro.build.characteristics to the imitated device's value.",
)
def check_build_characteristics_default(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    chars = values.get("ro.build.characteristics", "")
    abi = values.get("ro.product.cpu.abi", "")
    return Verdict(
        chars.strip() in ("default", "tablet") and abi.startswith("x86"),
        {"ro.build.characteristics": chars or None, "ro.product.cpu.abi": abi or None},
    )


@REG.check(
    "android.env.hardware_identity_list",
    "emulator.android_properties",
    name="Emulator names anywhere in identity properties",
    description="Scans 23 identity properties (product, build, hardware, board, bootloader, serial and their "
    "partition copies) for emulator words, so a single overridden property cannot hide the rest.",
    severity=Severity.HIGH,
    remediation="Make every identity property tell the same real-device story.",
)
def check_identity_list(dev: Device, ctx: RunContext) -> Verdict:
    values = props(dev)
    pattern = token_re(
        sig.BUILD_PROP_EMULATOR_SIGNATURES + ("emu64x", "emu64a", "vsoc_x86_64", "vbox86p", "sdk_x86")
    )
    hits = {p: values[p] for p in sig.IDENTITY_PROPS if values.get(p) and pattern.search(values[p])}
    return Verdict(bool(hits), hits or None, measurement={"properties_matched": len(hits)})


CHECKS = REG.specs
