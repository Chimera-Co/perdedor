"""Emulator files, init scripts and vendor-emulator markers.

Paths come from anti-emulator (known_files, known_pipes, known_geny_files),
framgia EmulatorDetector (GENY/ANDY/NOX/X86 files), reveny
Android-Emulator-Detection (EmulatorData.hpp), CalebFenton
AndroidEmulatorDetect (hasQemuFile) and the AOSP goldfish/Cuttlefish trees.
A path the shell user cannot see counts as absent; apps see the same view or
less, so this is what a sample sees.
"""

from __future__ import annotations

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, Verdict, existing, packages, props, token_re

REG = Checks()


@REG.check(
    "android.env.qemu_files",
    "emulator.android_files",
    name="QEMU emulator files",
    description="/system/lib/libc_malloc_debug_qemu.so, /sys/qemu_trace, /system/bin/qemu-props "
    "(anti-emulator hasQEmuFiles), /system/bin/qemud (CalebFenton hasQemuFile) and goldfish sync/address-space "
    "nodes.",
    severity=Severity.CRITICAL,
    remediation="Remove the emulator daemons and debug libraries from the image; kernel-created goldfish nodes "
    "need a kernel without goldfish drivers.",
)
def check_qemu_files(dev: Device, ctx: RunContext) -> Verdict:
    found = existing(dev, sig.QEMU_FILES)
    return Verdict(bool(found), found or None)


@REG.check(
    "android.env.goldfish_init_files",
    "emulator.android_files",
    name="goldfish/ranchu init and fstab files",
    description="init.goldfish.rc / init.ranchu.rc / fstab.ranchu / ueventd.ranchu.rc in the root or vendor "
    "partition name the emulator board.",
    severity=Severity.CRITICAL,
    remediation="Rename the board files together with ro.hardware, or use a non-goldfish board definition.",
)
def check_goldfish_init_files(dev: Device, ctx: RunContext) -> Verdict:
    found = existing(dev, sig.GOLDFISH_INIT_FILES)
    return Verdict(bool(found), found or None)


@REG.check(
    "android.env.x86_vm_init_files",
    "emulator.android_files",
    name="x86 VM init files (framgia X86_FILES)",
    description="ueventd.android_x86.rc, x86.prop, init.vbox86.rc, fstab.vbox86, init.ttVM_x86.rc... - "
    "framgia checks these together with the QEMU property score.",
    severity=Severity.HIGH,
    remediation="Rename the board init files and the matching ro.hardware value.",
)
def check_x86_vm_init_files(dev: Device, ctx: RunContext) -> Verdict:
    found = existing(dev, sig.X86_VM_INIT_FILES)
    return Verdict(bool(found), found or None)


def _vendor_check(key: str):
    vendor = sig.VENDOR_EMULATORS[key]
    tokens = token_re(vendor["tokens"])

    def fn(dev: Device, ctx: RunContext) -> Verdict:
        values = props(dev)
        hits: dict[str, object] = {}
        prefixes = tuple(vendor["prop_prefixes"])
        if prefixes:
            keys = sorted(k for k in values if k.startswith(prefixes))
            if keys:
                hits["properties"] = keys[:10]
        identity = {p: values[p] for p in sig.IDENTITY_PROPS if values.get(p) and tokens.search(values[p])}
        if identity:
            hits["identity"] = identity
        if vendor["files"]:
            files = existing(dev, vendor["files"])
            if files:
                hits["files"] = files
        if vendor["packages"]:
            installed = set(packages(dev))
            pk = [p for p in vendor["packages"] if p in installed]
            if pk:
                hits["packages"] = pk
        return Verdict(bool(hits), hits or None, measurement={"signal_groups": len(hits)})

    fn.__name__ = f"check_vendor_{key}"
    return fn


for _key, _vendor in sig.VENDOR_EMULATORS.items():
    REG.check(
        f"android.env.vendor_{_key}",
        "emulator.android_vendor_emulators",
        name=f"{_vendor['title']} markers",
        description=f"{_vendor['title']}: vendor properties, identity strings, files and packages "
        f"({_vendor['sources']}).",
        severity=Severity.CRITICAL,
        remediation=f"Do not analyse on {_vendor['title']}; if it must be used, remove its daemons, kernel "
        "modules, packages and properties from the image.",
    )(_vendor_check(_key))


CHECKS = REG.specs
