"""Category 1 (Ch.3.2.1): hardware/firmware/driver signatures.

Covers Pafish's QEMU/VirtualBox/VMware artifact checks, al-khaser's
"Generic sandbox/VM" + per-hypervisor sections, and VMAware's CPUID/DMI/PCI/
MAC technique classes -- see docs/CHECK_COVERAGE.md for the full mapping.
"""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path

from hydra_common import FindingFactory
from hydra_common.models import Category, Finding, Platform, Severity

from .. import cpu, signatures, utils

_PLATFORM = Platform.LINUX
_CATEGORY = Category.ENVIRONMENT_ARTIFACT
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)

_LOW_CORE_COUNT_THRESHOLD = 2
_LOW_RAM_KB_THRESHOLD = 4 * 1024 * 1024  # 4 GiB
_SMALL_DISK_BYTES_THRESHOLD = 60 * 1024 * 1024 * 1024  # 60 GiB


def _dmi_checks() -> list[Finding]:
    findings = []
    for dmi_file in signatures.DMI_FIELDS:
        check_id = f"linux.env.dmi_{dmi_file}"
        name = f"DMI '{dmi_file}'"
        description = f"/sys/class/dmi/id/{dmi_file}, checked against known hypervisor vendor names."
        value = utils.read_text(f"/sys/class/dmi/id/{dmi_file}")
        if value is None:
            findings.append(
                _f.error(
                    check_id,
                    name,
                    description,
                    Severity.MEDIUM,
                    f"could not read /sys/class/dmi/id/{dmi_file} (permissions or not present)",
                )
            )
            continue
        match = utils.any_signature_in(value, signatures.DMI_VENDOR_SIGNATURES)
        findings.append(
            _f.bool_check(
                check_id,
                name,
                description,
                Severity.HIGH,
                is_detected=bool(match),
                evidence=value,
                remediation=f"Override {dmi_file} via libvirt <sysinfo> to a real vendor identity.",
            )
        )
    return findings


def check_cpuid_hypervisor_bit() -> Finding:
    check_id, name = "linux.env.cpuid_hypervisor_bit", "CPUID hypervisor-present bit"
    description = (
        "CPUID leaf 1, ECX bit 31 -- set by every mainstream hypervisor to advertise itself to the guest."
    )
    result = cpu.cpuid(1)
    if result is None:
        return _f.skipped(
            check_id,
            name,
            description,
            Severity.HIGH,
            "CPUID unavailable (non-x86 host or native helper failed to build)",
        )
    present = bool(result.ecx & (1 << 31))
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.CRITICAL,
        is_detected=present,
        evidence=f"ecx=0x{result.ecx:08x} bit31={'1' if present else '0'}",
        remediation="Set <kvm><hidden state='on'/></kvm> in the libvirt domain XML.",
    )


def check_cpuid_hypervisor_vendor() -> Finding:
    check_id, name = "linux.env.cpuid_hypervisor_vendor", "CPUID hypervisor vendor string"
    description = "CPUID leaf 0x40000000 -- the hypervisor vendor ID string (e.g. 'KVMKVMKVM')."
    result = cpu.cpuid(0x40000000)
    if result is None:
        return _f.skipped(
            check_id,
            name,
            description,
            Severity.CRITICAL,
            "CPUID unavailable (non-x86 host or native helper failed to build)",
        )
    vendor = result.vendor_string
    known = signatures.CPUID_HYPERVISOR_VENDORS.get(vendor)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.CRITICAL,
        is_detected=bool(known),
        evidence=f"{vendor!r}" + (f" ({known})" if known else ""),
        remediation="A patched QEMU build (e.g. the zhaodice/qemu-anti-detection patch set) is required to change this string; libvirt alone cannot.",
    )


def check_cpu_brand_string() -> Finding:
    check_id, name = "linux.env.cpu_brand_string", "CPU brand string (Pafish-class)"
    description = "CPUID leaves 0x80000002-4 -- Pafish's classic check for 'QEMU Virtual CPU'/'Common KVM processor'/Hyper-V's 'Virtual CPU'."
    brand = cpu.brand_string()
    if brand is None:
        return _f.skipped(
            check_id,
            name,
            description,
            Severity.HIGH,
            "CPUID unavailable (non-x86 host or native helper failed to build)",
        )
    match = utils.any_signature_in(brand, signatures.CPU_BRAND_STRING_SIGNATURES)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=bool(match),
        evidence=brand,
        remediation="Use CPU host-passthrough with a real-CPU model string, or patch the brand string via a custom QEMU build.",
    )


def check_pci_virtio_devices() -> Finding:
    check_id, name = "linux.env.pci_virtio_devices", "PCI vendor ID enumeration"
    description = (
        "Scans /sys/bus/pci/devices/*/vendor for known virtio/QEMU/VMware/VirtualBox/Xen PCI vendor IDs."
    )
    pci_root = Path("/sys/bus/pci/devices")
    if not pci_root.is_dir():
        return _f.skipped(check_id, name, description, Severity.HIGH, "/sys/bus/pci/devices not present")
    hits: list[str] = []
    for device_dir in pci_root.iterdir():
        vendor = utils.read_text(str(device_dir / "vendor"))
        if vendor and vendor.lower() in signatures.PCI_VIRT_VENDOR_IDS:
            hits.append(f"{device_dir.name}: {vendor} ({signatures.PCI_VIRT_VENDOR_IDS[vendor.lower()]})")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=bool(hits),
        evidence=hits or None,
        remediation="Remove virtio devices from the domain XML; use e1000e NIC and SATA/ICH9 controllers instead.",
    )


def check_guest_kernel_modules() -> Finding:
    check_id, name = "linux.env.guest_kernel_modules", "Loaded guest-integration kernel modules"
    description = (
        "Reads /proc/modules for virtio/VirtualBox/VMware/Xen/Hyper-V paravirtualised driver modules."
    )
    modules = utils.read_text("/proc/modules")
    if modules is None:
        return _f.error(check_id, name, description, Severity.MEDIUM, "could not read /proc/modules")
    loaded = {line.split()[0] for line in modules.splitlines() if line.strip()}
    hits = {
        module: vendor
        for module in loaded
        for prefix, vendor in signatures.GUEST_KERNEL_MODULES.items()
        if module.startswith(prefix)
    }
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(hits),
        evidence=hits or None,
        remediation="Blacklist/unload paravirtualised guest driver modules on the golden image before freezing it.",
    )


def check_guest_agent_binaries() -> Finding:
    check_id, name = "linux.env.guest_agent_binaries", "Guest-integration agent binaries on disk"
    description = (
        "Checks for qemu-ga/VBoxService/vmtoolsd binaries, whose presence alone identifies a VM guest."
    )
    found = [path for path in signatures.GUEST_AGENT_PATHS if Path(path).exists()]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(found),
        evidence=found or None,
        remediation="Uninstall guest-integration packages (qemu-guest-agent, virtualbox-guest-utils, open-vm-tools) from the golden image.",
    )


def check_scsi_device_vendor() -> Finding:
    check_id, name = "linux.env.scsi_device_vendor", "SCSI device vendor string"
    description = (
        "/proc/scsi/scsi Vendor: field -- Pafish's 'QEMU SCSI key' check, generalised to the /proc source."
    )
    text = utils.read_text("/proc/scsi/scsi")
    if text is None:
        return _f.skipped(
            check_id, name, description, Severity.MEDIUM, "/proc/scsi/scsi not present or empty"
        )
    match = utils.any_signature_in(text, signatures.BLOCK_DEVICE_VENDOR_SIGNATURES)
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(match),
        evidence=match,
        remediation="Use a custom disk model/vendor string (<qemu:override> disk model property) instead of the QEMU default.",
    )


def check_block_device_vendor() -> Finding:
    check_id, name = "linux.env.block_device_vendor", "Block device vendor/model strings"
    description = "/sys/block/*/device/{vendor,model}, checked against known virtual-disk vendor strings."
    block_root = Path("/sys/block")
    if not block_root.is_dir():
        return _f.skipped(check_id, name, description, Severity.MEDIUM, "/sys/block not present")
    hits: list[str] = []
    for device_dir in block_root.iterdir():
        for field in ("vendor", "model"):
            value = utils.read_text(str(device_dir / "device" / field))
            if value and utils.any_signature_in(value, signatures.BLOCK_DEVICE_VENDOR_SIGNATURES):
                hits.append(f"{device_dir.name}.{field}={value}")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(hits),
        evidence=hits or None,
        remediation="Use a custom disk model/vendor string instead of the hypervisor default.",
    )


def check_systemd_detect_virt() -> Finding:
    check_id, name = "linux.env.systemd_detect_virt", "systemd-detect-virt"
    description = (
        "Cross-checks against systemd's own virtualization detector -- an independent authoritative source "
        "that Pafish/al-khaser/VMAware (Windows-only) have no equivalent of."
    )
    output = utils.run(["systemd-detect-virt"])
    if output is None:
        return _f.skipped(
            check_id, name, description, Severity.HIGH, "systemd-detect-virt not installed or unavailable"
        )
    virt_type = output.strip()
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=virt_type != "none",
        evidence=virt_type,
        remediation=f"systemd itself identifies this as {virt_type!r}; see the corresponding CPUID/DMI findings for the specific spoofing gap.",
    )


def check_low_core_count() -> Finding:
    check_id, name = "linux.env.low_core_count", "Logical CPU count"
    description = f"A sandbox is commonly provisioned with very few vCPUs (<= {_LOW_CORE_COUNT_THRESHOLD})."
    count = os.cpu_count()
    if count is None:
        return _f.error(check_id, name, description, Severity.LOW, "os.cpu_count() returned None")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=count <= _LOW_CORE_COUNT_THRESHOLD,
        evidence=f"{count} logical CPUs",
        remediation="Provision the sandbox with a realistic core count (4+) for the spoofed hardware identity.",
    )


def check_low_ram() -> Finding:
    check_id, name = "linux.env.low_ram", "Total RAM"
    description = f"A sandbox is commonly provisioned with very little RAM (<= {_LOW_RAM_KB_THRESHOLD // (1024 * 1024)} GiB)."
    meminfo = utils.read_text("/proc/meminfo")
    if meminfo is None:
        return _f.error(check_id, name, description, Severity.LOW, "could not read /proc/meminfo")
    for line in meminfo.splitlines():
        if line.startswith("MemTotal:"):
            kb = int(line.split()[1])
            return _f.bool_check(
                check_id,
                name,
                description,
                Severity.LOW,
                is_detected=kb <= _LOW_RAM_KB_THRESHOLD,
                evidence=f"{kb // 1024} MiB",
                remediation="Provision the sandbox with realistic RAM (8GB+) for the spoofed hardware identity.",
            )
    return _f.error(check_id, name, description, Severity.LOW, "MemTotal not found in /proc/meminfo")


def check_small_disk() -> Finding:
    check_id, name = "linux.env.small_disk", "Primary disk size"
    description = f"A sandbox is commonly provisioned with a small disk (<= {_SMALL_DISK_BYTES_THRESHOLD // (1024**3)} GiB)."
    block_root = Path("/sys/block")
    if not block_root.is_dir():
        return _f.skipped(check_id, name, description, Severity.LOW, "/sys/block not present")
    sizes = {}
    for device_dir in block_root.iterdir():
        if device_dir.name.startswith(("loop", "ram", "sr")):
            continue
        size_sectors = utils.read_text(str(device_dir / "size"))
        if size_sectors and size_sectors.isdigit():
            sizes[device_dir.name] = int(size_sectors) * 512
    if not sizes:
        return _f.skipped(check_id, name, description, Severity.LOW, "no eligible block devices found")
    largest_name = max(sizes, key=lambda k: sizes[k])
    largest_bytes = sizes[largest_name]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=largest_bytes <= _SMALL_DISK_BYTES_THRESHOLD,
        evidence=f"{largest_name}: {largest_bytes // (1024**3)} GiB",
        remediation="Provision the sandbox with a realistic disk size (120GB+) for the spoofed hardware identity.",
    )


def check_container_or_wsl() -> Finding:
    check_id, name = "linux.env.container_or_wsl", "Container/WSL execution environment"
    description = "Checks for /.dockerenv, cgroup container markers, and WSL's kernel version string."
    hits: list[str] = []
    if Path("/.dockerenv").exists():
        hits.append("/.dockerenv present")
    cgroup = utils.read_text("/proc/1/cgroup")
    if cgroup and utils.any_signature_in(cgroup, ("docker", "lxc", "kubepods")):
        hits.append("container marker in /proc/1/cgroup")
    version = utils.read_text("/proc/version")
    if version and utils.any_signature_in(version, ("microsoft", "wsl")):
        hits.append(f"/proc/version={version}")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(hits),
        evidence=hits or None,
        remediation="Detonate inside a real VM guest, not a container or WSL -- neither provides the isolation CHIMERA's threat model assumes.",
    )


def check_cloud_metadata_reachable() -> Finding:
    check_id, name = "linux.env.cloud_metadata_reachable", "Cloud instance-metadata endpoint"
    description = (
        f"Attempts a short-timeout request to {signatures.CLOUD_METADATA_URL} -- reachability alone identifies "
        "a cloud VM. Not checked by Pafish/al-khaser/VMAware, which predate cloud-native detonation infrastructure."
    )
    try:
        # Fixed link-local IP, not user input -- deliberate urlopen target.
        urllib.request.urlopen(signatures.CLOUD_METADATA_URL, timeout=1.0)
        reachable = True
    except Exception:  # noqa: BLE001 - any failure (timeout, refused, DNS, etc.) just means "not reachable"
        reachable = False
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=reachable,
        evidence="metadata endpoint responded" if reachable else "unreachable",
        remediation="Ensure the sandbox network has no route to the cloud metadata service (169.254.169.254) if cloud infrastructure is being used for hosting only, not as the detonation identity.",
    )


def check_sandbox_framework_paths() -> Finding:
    check_id, name = "linux.env.sandbox_framework_paths", "Known analysis-framework marker paths"
    description = "Checks for Cuckoo/INetSim installation directories left on the host."
    found = [path for path in signatures.SANDBOX_FRAMEWORK_PATHS if Path(path).exists()]
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.MEDIUM,
        is_detected=bool(found),
        evidence=found or None,
        remediation="These paths belong on the host/service VM, not inside the detonation guest -- remove them from the golden image.",
    )


def run_all() -> list[Finding]:
    return [
        *_dmi_checks(),
        check_cpuid_hypervisor_bit(),
        check_cpuid_hypervisor_vendor(),
        check_cpu_brand_string(),
        check_pci_virtio_devices(),
        check_guest_kernel_modules(),
        check_guest_agent_binaries(),
        check_scsi_device_vendor(),
        check_block_device_vendor(),
        check_systemd_detect_virt(),
        check_low_core_count(),
        check_low_ram(),
        check_small_disk(),
        check_container_or_wsl(),
        check_cloud_metadata_reachable(),
        check_sandbox_framework_paths(),
    ]
