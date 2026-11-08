"""Kernel, CPU and virtual-hardware tells readable from the adb shell:
/proc/cpuinfo, /proc/version, /proc/tty/drivers, /proc/cmdline, mounts,
kernel modules, PCI vendor ids, DMI strings, block devices, the Xen/hypervisor
sysfs interfaces and the GPU renderer.

anti-emulator and framgia read the first 1024 bytes of /proc/tty/drivers and
/proc/cpuinfo for 'goldfish' (hasQEmuDrivers / checkQEmuDrivers); reveny
checkCPUInfo looks for the 'hypervisor' flag and host CPU vendors; reveny
checkMounts looks for vboxsf.
"""

from __future__ import annotations

import re

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, ProbeError, Skip, Verdict, existing, need, substr_hits

REG = Checks()


def _read_required(dev: Device, path: str) -> str:
    text = dev.read(path)
    if text is None:
        raise Skip(f"{path} is not readable by the adb shell user on this build")
    return text


@REG.check(
    "android.env.cpuinfo_emulator_strings",
    "cpu.brand_string",
    name="/proc/cpuinfo emulator strings",
    description="/proc/cpuinfo 'Hardware: Goldfish' (CalebFenton hasQemuCpuInfo, anti-emulator "
    "hasQEmuDrivers) or a QEMU/KVM virtual CPU model name.",
    severity=Severity.CRITICAL,
    remediation="Use a kernel/CPU model that reports a real SoC; on x86 hosts pass the host CPU model through.",
)
def check_cpuinfo_strings(dev: Device, ctx: RunContext) -> Verdict:
    text = _read_required(dev, "/proc/cpuinfo")
    hits = substr_hits(text, sig.CPUINFO_EMULATOR_TOKENS)
    hardware = re.findall(r"^Hardware\s*:\s*(.+)$", text, re.MULTILINE)
    models = sorted(set(re.findall(r"^model name\s*:\s*(.+)$", text, re.MULTILINE)))
    return Verdict(
        bool(hits), {"matched": hits or None, "hardware": hardware[:1] or None, "model_names": models[:3]}
    )


@REG.check(
    "android.env.cpuinfo_hypervisor_flag",
    "cpu.hypervisor_bit",
    name="/proc/cpuinfo 'hypervisor' flag",
    description="On x86 Android the kernel exports CPUID.1:ECX[31] as the 'hypervisor' cpu flag (reveny "
    "checkCPUInfo).",
    severity=Severity.CRITICAL,
    remediation="Hide the hypervisor CPUID bit from the guest (Xen + DRAKVUF: cpuidmon -s; KVM: -cpu "
    "host,-hypervisor).",
)
def check_cpuinfo_hypervisor(dev: Device, ctx: RunContext) -> Verdict:
    text = _read_required(dev, "/proc/cpuinfo")
    flags = re.findall(r"^flags\s*:\s*(.+)$", text, re.MULTILINE)
    if not flags:
        raise Skip("no x86 'flags' line in /proc/cpuinfo (ARM CPU)")
    present = any("hypervisor" in line.split() for line in flags)
    return Verdict(present, {"hypervisor_flag": present})


@REG.check(
    "android.env.cpuinfo_x86_vendor",
    "emulator.binary_translation",
    name="Host-class x86 CPU in /proc/cpuinfo",
    description="reveny checkCPUInfo flags Intel/AMD in /proc/cpuinfo: phones use ARM SoCs, so an Intel or "
    "AMD desktop/server CPU means an x86 emulator or VM.",
    severity=Severity.HIGH,
    remediation="Analyse ARM samples on ARM hardware.",
)
def check_cpuinfo_x86_vendor(dev: Device, ctx: RunContext) -> Verdict:
    text = _read_required(dev, "/proc/cpuinfo")
    vendors = sorted(set(re.findall(r"^vendor_id\s*:\s*(\S+)", text, re.MULTILINE)))
    models = sorted(set(re.findall(r"^model name\s*:\s*(.+)$", text, re.MULTILINE)))
    x86 = bool(vendors) or bool(re.search(r"\b(Intel|AMD)\b", " ".join(models)))
    return Verdict(x86, {"vendor_id": vendors or None, "model_names": models[:3] or None})


@REG.check(
    "android.env.kernel_version",
    "artifacts.kernel_messages",
    name="Kernel version string (/proc/version)",
    description="/proc/version names goldfish, ranchu, qemu, android-x86, vbox, genymotion or cuttlefish "
    "kernels.",
    severity=Severity.HIGH,
    remediation="Build the guest kernel with a neutral version string (CONFIG_LOCALVERSION, build user/host).",
)
def check_kernel_version(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.read("/proc/version") or dev.sh("uname -a")
    text = need(text, "/proc/version")
    hits = substr_hits(text, sig.KERNEL_VERSION_TOKENS)
    return Verdict(bool(hits), {"version": text.strip()[:200], "matched": hits or None})


@REG.check(
    "android.env.tty_drivers",
    "emulator.android_files",
    name="goldfish TTY driver (/proc/tty/drivers)",
    description="anti-emulator hasQEmuDrivers / framgia checkQEmuDrivers: 'goldfish' in /proc/tty/drivers.",
    severity=Severity.CRITICAL,
    remediation="Use a kernel without the goldfish TTY driver.",
)
def check_tty_drivers(dev: Device, ctx: RunContext) -> Verdict:
    text = _read_required(dev, "/proc/tty/drivers")
    hits = substr_hits(text, sig.TTY_DRIVER_TOKENS)
    return Verdict(bool(hits), hits or None)


@REG.check(
    "android.env.kernel_cmdline",
    "emulator.android_properties",
    name="Kernel command line",
    description="/proc/cmdline contains androidboot.hardware=ranchu/goldfish/cutf_cvm, qemu=1, "
    "androidboot.qemu=1 or console=ttyGF on emulators. Often not readable by shell on Android 9+ (skipped).",
    severity=Severity.CRITICAL,
    remediation="Change the boot loader's kernel command line.",
)
def check_kernel_cmdline(dev: Device, ctx: RunContext) -> Verdict:
    text = _read_required(dev, "/proc/cmdline")
    hits = [t for t in sig.CMDLINE_TOKENS if t in text]
    return Verdict(bool(hits), {"matched": hits or None, "length": len(text)})


@REG.check(
    "android.env.vm_mounts",
    "emulator.android_files",
    name="Host-shared file systems in mounts",
    description="vboxsf (reveny checkMounts), 9p/virtiofs, BlueStacks' BstSharedFolder or /mnt/windows in "
    "/proc/mounts.",
    severity=Severity.HIGH,
    remediation="Do not mount host shares into the analysis guest.",
)
def check_vm_mounts(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.mounts(), "/proc/mounts")
    lines = [line for line in text.splitlines() if any(t in line.split()[:3] for t in sig.VM_MOUNT_TOKENS)]
    lines += [line for line in text.splitlines() if "BstSharedFolder" in line or "/mnt/windows" in line]
    lines = list(dict.fromkeys(lines))
    return Verdict(bool(lines), lines[:10] or None)


@REG.check(
    "android.env.vm_kernel_modules",
    "emulator.android_files",
    name="Virtual-hardware kernel modules",
    description="/proc/modules or /sys/module entries for goldfish, VirtualBox (vboxguest, vboxsf, "
    "vboxpcismv), virtio, Xen front-ends, BlueStacks (bstsensor, bstpgaipc), MuMu (nemusf), MEmu.",
    severity=Severity.HIGH,
    remediation="Build the guest kernel without hypervisor guest drivers, or rename them (residual: virtio "
    "is needed for paravirtual I/O).",
)
def check_vm_kernel_modules(dev: Device, ctx: RunContext) -> Verdict:
    modules = dev.read("/proc/modules") or ""
    sysmod = dev.listdir("/sys/module") or []
    if not modules and not sysmod:
        raise Skip("/proc/modules and /sys/module are not readable by the shell user")
    names = {line.split()[0] for line in modules.splitlines() if line.strip()} | set(sysmod)
    found = sorted(n for n in names if any(n == m or n.startswith(m) for m in sig.VM_KERNEL_MODULES))
    return Verdict(bool(found), found or None, measurement={"modules_seen": len(names)})


@REG.check(
    "android.env.pci_vendor_ids",
    "hardware.pci_vendor_ids",
    name="Virtual PCI devices",
    description="PCI vendor ids in /sys/bus/pci/devices/*/vendor: 0x1af4 virtio, 0x1b36/0x1234 QEMU, 0x80ee "
    "VirtualBox, 0x5853 Xen platform device, 0x15ad VMware. Phones have no PCI bus or only the SoC's PCIe root.",
    severity=Severity.CRITICAL,
    remediation="Present real-looking PCI ids where the hypervisor allows it (Xen: xen_platform_pci=0 removes "
    "the 5853 device but also the PV drivers); otherwise accept as residual.",
)
def check_pci_vendor_ids(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.sh("cat /sys/bus/pci/devices/*/vendor 2>/dev/null", any_rc=True)
    if text is None:
        raise ProbeError("could not read /sys/bus/pci/devices")
    ids = [line.strip().lower() for line in text.splitlines() if line.strip()]
    if not ids:
        raise Skip("no PCI bus visible (normal on ARM phones)")
    hits = sorted({sig.VIRTUAL_PCI_VENDORS[i] for i in ids if i in sig.VIRTUAL_PCI_VENDORS})
    return Verdict(bool(hits), {"virtual": hits or None, "pci_devices": len(ids)})


@REG.check(
    "android.env.dmi_identity",
    "firmware.smbios_strings",
    name="DMI/SMBIOS identity",
    description="/sys/class/dmi/id/{sys_vendor,product_name,bios_vendor} on x86 Android name the hypervisor "
    "(Xen 'HVM domU', QEMU, VirtualBox, VMware).",
    severity=Severity.CRITICAL,
    remediation="Present host-derived SMBIOS strings to the guest (CHIMERA: hvmloader firmware_override and "
    "SMBIOS OEM strings, as for the Windows image).",
)
def check_dmi_identity(dev: Device, ctx: RunContext) -> Verdict:
    values = {}
    for path in sig.DMI_FILES:
        text = dev.read(path)
        if text:
            values[path.rsplit("/", 1)[1]] = text.strip()
    if not values:
        raise Skip("no readable DMI table (ARM device, or SELinux denies sysfs DMI reads)")
    hits = {k: v for k, v in values.items() if substr_hits(v, sig.DMI_HYPERVISOR_TOKENS)}
    return Verdict(bool(hits), {"dmi": values, "matched": hits or None})


@REG.check(
    "android.env.hypervisor_sysfs",
    "artifacts.hypervisor_interfaces",
    name="Hypervisor interfaces (/sys/hypervisor, /proc/xen)",
    description="/sys/hypervisor/type ('xen') and /proc/xen exist when the kernel runs as a Xen guest.",
    severity=Severity.CRITICAL,
    remediation="Build the guest kernel without CONFIG_XEN guest support or run the guest as plain HVM "
    "without PV interfaces.",
)
def check_hypervisor_sysfs(dev: Device, ctx: RunContext) -> Verdict:
    present = existing(dev, ("/sys/hypervisor/type", "/proc/xen"))
    kind = dev.read("/sys/hypervisor/type")
    return Verdict(bool(present), {"present": present or None, "type": kind.strip() if kind else None})


@REG.check(
    "android.env.virtual_block_devices",
    "hardware.disk_identity",
    name="Virtual block devices",
    description="virtio (vd*) or Xen (xvd*) block devices in /sys/block, or disk models QEMU HARDDISK / VBOX "
    "HARDDISK. Phones use mmcblk* (eMMC) or sd* (UFS) with vendor models.",
    severity=Severity.HIGH,
    remediation="Emulate an eMMC/UFS-style disk with a vendor model where the hypervisor allows it; "
    "otherwise residual.",
)
def check_virtual_block_devices(dev: Device, ctx: RunContext) -> Verdict:
    names = dev.listdir("/sys/block")
    if names is None:
        raise ProbeError("could not list /sys/block")
    virtual = [n for n in names if n.startswith(sig.VIRTUAL_BLOCK_PREFIXES)]
    models_text = dev.sh("cat /sys/block/*/device/model 2>/dev/null", any_rc=True) or ""
    models = sorted({m.strip() for m in models_text.splitlines() if m.strip()})
    bad_models = [m for m in models if substr_hits(m, sig.VIRTUAL_DISK_TOKENS)]
    return Verdict(
        bool(virtual or bad_models), {"virtual_devices": virtual or None, "models": models[:6] or None}
    )


@REG.check(
    "android.env.gpu_renderer",
    "hardware.gpu_identity",
    name="GPU renderer (SurfaceFlinger GLES)",
    description="dumpsys SurfaceFlinger prints the GLES vendor/renderer: 'Android Emulator OpenGL ES "
    "Translator', SwiftShader, llvmpipe, virgl, VMware SVGA, or a desktop GPU name, where phones report "
    "Adreno, Mali, PowerVR or Xclipse.",
    severity=Severity.HIGH,
    remediation="Use GPU passthrough with a mobile GPU, or accept software rendering as a residual tell.",
    cost="medium",
)
def check_gpu_renderer(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.dumpsys("SurfaceFlinger"), "dumpsys SurfaceFlinger")
    gles = re.findall(r"^GLES:\s*(.+)$", text, re.MULTILINE)
    if not gles:
        raise Skip("SurfaceFlinger did not print a GLES line")
    hits = substr_hits(gles[0], sig.GL_RENDERER_SIGNATURES)
    return Verdict(bool(hits), {"gles": gles[0][:200], "matched": hits or None})


CHECKS = REG.specs
