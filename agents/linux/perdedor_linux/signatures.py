"""Known hypervisor/VM identity signatures shared across Linux checks.

Sourced from the same public technique classes CHIMERA verifies against
(VMAware, Pafish, al-khaser) and documented in the CHIMERA KVM hardening
report's own Section 3.2.1 (environment artifacts). See docs/CHECK_COVERAGE.md
for the full mapping of which upstream tool each signature list traces back to.
"""

from __future__ import annotations

# Case-insensitive substrings that identify a hypervisor/emulator when found
# in DMI strings (sys_vendor, product_name, bios_vendor, board_vendor, ...).
DMI_VENDOR_SIGNATURES: tuple[str, ...] = (
    "qemu",
    "bochs",
    "kvm",
    "virtualbox",
    "vbox",
    "innotek",
    "vmware",
    "xen",
    "microsoft corporation",  # Hyper-V reports this as system-manufacturer
    "parallels",
    "bhyve",
    "amazon ec2",  # Nitro-based instances expose this in product_name
    "google compute engine",
    "ovmf",  # generic upstream OVMF firmware string, not vendor-specific but still a tell
    "seabios",
)

# /sys/class/dmi/id/<file> entries to scan with DMI_VENDOR_SIGNATURES. Pafish
# and al-khaser only ever check a couple of these via the Windows registry
# equivalent; the full DMI table has several more fields worth checking.
DMI_FIELDS: tuple[str, ...] = (
    "sys_vendor",
    "product_name",
    "product_family",
    "product_sku",
    "product_version",
    "bios_vendor",
    "bios_version",
    "board_vendor",
    "board_name",
    "chassis_vendor",
    "chassis_asset_tag",
)

# CPUID leaf 0x40000000 EBX:ECX:EDX vendor strings for common hypervisors.
CPUID_HYPERVISOR_VENDORS: dict[str, str] = {
    "KVMKVMKVM\0\0\0": "KVM",
    "TCGTCGTCGTCG": "QEMU TCG (software emulation)",
    "VMwareVMware": "VMware",
    "XenVMMXenVMM": "Xen",
    "Microsoft Hv": "Hyper-V",
    "prl hyperv  ": "Parallels",
    "VBoxVBoxVBox": "VirtualBox (minimal vendor id)",
    "bhyve bhyve ": "bhyve",
}

# CPUID leaf 0x80000002-4 processor brand string signatures (Pafish's classic
# "QEMU Virtual CPU" check, plus the KVM/Hyper-V/Xen equivalents).
CPU_BRAND_STRING_SIGNATURES: tuple[str, ...] = (
    "qemu virtual cpu",
    "common kvm processor",
    "virtual cpu",  # Hyper-V, e.g. "Virtual CPU @ 2.6GHz"
)

# PCI vendor IDs for paravirtualised device families.
PCI_VIRT_VENDOR_IDS: dict[str, str] = {
    "0x1af4": "Red Hat / virtio",
    "0x1b36": "QEMU (red hat virtual PCI device)",
    "0x15ad": "VMware",
    "0x80ee": "VirtualBox (Oracle/innotek)",
    "0x5853": "Xen",
}

# Kernel module name substrings that only load inside a specific hypervisor's guest.
GUEST_KERNEL_MODULES: dict[str, str] = {
    "virtio": "virtio (generic paravirtualised device driver)",
    "vboxguest": "VirtualBox Guest Additions",
    "vboxsf": "VirtualBox shared folders",
    "vboxvideo": "VirtualBox video driver",
    "vmwgfx": "VMware SVGA graphics driver",
    "vmw_balloon": "VMware balloon driver",
    "vmw_vmci": "VMware VMCI",
    "vmw_vsock": "VMware VSOCK",
    "xen_": "Xen paravirtualised driver family",
    "hv_": "Hyper-V paravirtualised driver family",
    "hyperv_": "Hyper-V paravirtualised driver family",
}

# Disk/SCSI device vendor/model strings (/proc/scsi/scsi, /sys/block/*/device/*).
BLOCK_DEVICE_VENDOR_SIGNATURES: tuple[str, ...] = (
    "qemu",
    "vbox",
    "vmware",
    "virtual disk",
    "msft virtual disk",  # Hyper-V
)

# NIC MAC address OUI prefixes (first 3 octets) assigned to virtual NIC vendors.
MAC_OUI_SIGNATURES: dict[str, str] = {
    "52:54:00": "QEMU/KVM (libvirt default OUI)",
    "08:00:27": "VirtualBox (Oracle/innotek default OUI)",
    "0a:00:27": "VirtualBox (host-only adapter)",
    "00:0c:29": "VMware (auto-generated OUI)",
    "00:50:56": "VMware (manually-assigned OUI)",
    "00:1c:14": "VMware (older OUI block)",
    "00:05:69": "VMware (very old OUI block)",
    "00:16:3e": "Xen (default OUI)",
    "00:03:ff": "Microsoft Hyper-V/Virtual PC",
    "00:15:5d": "Microsoft Hyper-V",
}

# Process names for common malware-analysis tooling; their mere presence is
# itself a "design-specific" tell that this is not an ordinary end-user box.
# Extends al-khaser's "Analysis Tools" section to Linux-native equivalents.
ANALYSIS_TOOL_PROCESS_NAMES: tuple[str, ...] = (
    "strace",
    "ltrace",
    "gdb",
    "edb",  # Evan's Debugger, the common Linux GUI debugger
    "wireshark",
    "tshark",
    "tcpdump",
    "mitmproxy",
    "mitmdump",
    "mitmweb",
    "burpsuite",
    "zaproxy",
    "fakenet",
    "inetsim",
    "volatility",
    "vol.py",
    "vol3",
    "ida64",
    "ida",
    "ghidra",
    "radare2",
    "r2",
    "x64dbg",
    "binwalk",
    "sysdig",
    "bpftrace",
)

# Hostnames/usernames that betray a purpose-built analysis box rather than
# an ordinary machine (the "design-specific" category, Ch.3.2.4). Substring
# match -- see SANDBOX_USERNAME_EXACT below for al-khaser's exact-match list.
SUSPICIOUS_NAME_TOKENS: tuple[str, ...] = (
    "sandbox",
    "malware",
    "sample",
    "analysis",
    "cuckoo",
    "detonat",
    "honeypot",
    "virus",
)

# al-khaser checks these as exact (not substring) username/hostname matches --
# kept as a separate list because some are short enough (e.g. "test") that a
# substring match would false-positive constantly on real names.
SANDBOX_USERNAME_EXACT: tuple[str, ...] = (
    "sandbox",
    "malware",
    "maltest",
    "currentuser",
    "sample",
    "virus",
    "test",
    "test user",
    "vmuser",
    "john doe",
)

# Guest-integration agent binaries whose mere presence identifies the host as
# a VM even after firmware/CPUID spoofing (CHIMERA KVM report Section 7.7 --
# "ghost device cleanup" documents exactly this class of residual tell).
GUEST_AGENT_PATHS: tuple[str, ...] = (
    "/usr/bin/qemu-ga",
    "/usr/sbin/VBoxService",
    "/usr/bin/VBoxClient",
    "/usr/bin/vmtoolsd",
    "/usr/bin/vmware-toolbox-cmd",
    "/usr/bin/open-vm-tools",
)

# Marker paths/config left behind by other public sandboxes (Cuckoo, INetSim,
# etc.) -- the same "design-specific" idea as GUEST_AGENT_PATHS but aimed at
# analysis frameworks rather than hypervisor guest tools.
SANDBOX_FRAMEWORK_PATHS: tuple[str, ...] = (
    "/etc/cuckoo",
    "/opt/cuckoo",
    "/etc/inetsim",
    "/opt/inetsim",
)

# Well-known cloud-provider instance-metadata endpoints. Reachability alone
# (regardless of response content) is a strong "this is a cloud VM" signal
# that none of Pafish/al-khaser/VMAware check, since all three predate/ignore
# cloud-native detonation infrastructure.
CLOUD_METADATA_URL = "http://169.254.169.254/latest/meta-data/"
