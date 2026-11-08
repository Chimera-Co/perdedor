// Devices and resource sizing on Linux: PCI, USB, input, disks, NICs, GPU,
// monitors, sound, sensors, power, CPU clock/cache, cores, RAM, disk, screen.
//
// Sources: VMAware v2.8.2 (DEVICES pci_devices table, QEMU_USB, HWMON,
// TEMPERATURE, DISK serial patterns, THREAD_COUNT), Pafish/al-khaser device
// and resource checks (Windows equivalents), QEMU hw/display/edid-generate.c.
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <set>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

// Thresholds kept from the v1 Linux agent (agents/linux/perdedor_linux/checks/environment.py), which follow
// al-khaser NumberOfProcessors (< 2 cores), memory_space (< 1 GB) and disk_size_* (< 80 GB) on Windows,
// raised to what current consumer machines ship with.
constexpr long long kLowCoreCount = 2;
constexpr long long kLowRamKiB = 4LL * 1024 * 1024;
constexpr long long kSmallDiskBytes = 60LL * 1024 * 1024 * 1024;
// Pafish/al-khaser have no screen threshold on Linux; 1024x768 is the default VGA mode of QEMU std-vga,
// bochs-drm and the Xen stdvga device, and below every shipping laptop panel.
constexpr long long kLowScreenPixels = 1024LL * 768;
constexpr long long kSectorBytes = 512;
// DSP0134 3.4 table 17 portable chassis types: 8 Portable, 9 Laptop, 10 Notebook, 14 Sub Notebook,
// 30 Tablet, 31 Convertible, 32 Detachable.
const std::vector<long long> kPortableChassis = {8, 9, 10, 14, 30, 31, 32};
// Same table, mains-powered chassis that normally expose no power_supply device at all: 3 Desktop, 4 Low
// Profile Desktop, 5 Pizza Box, 6 Mini Tower, 7 Tower, 13 All in One, 15 Space-saving, 16 Lunch Box,
// 17 Main Server Chassis, 23 Rack Mount, 24 Sealed-case PC, 35 Mini PC, 36 Stick PC.
const std::vector<long long> kMainsChassis = {3, 4, 5, 6, 7, 13, 15, 16, 17, 23, 24, 35, 36};

const std::map<std::string, std::string>& pci_vendors() {
    // v1 PCI_VIRT_VENDOR_IDS plus Parallels (0x1ab8) and Microsoft Hyper-V (0x1414).
    static const std::map<std::string, std::string> m = {{"0x1af4", "Red Hat / virtio"},
        {"0x1b36", "QEMU (Red Hat virtual PCI)"}, {"0x15ad", "VMware"}, {"0x80ee", "VirtualBox"},
        {"0x5853", "Xen"}, {"0x1ab8", "Parallels"}, {"0x1414", "Microsoft Hyper-V"}};
    return m;
}

std::vector<Finding> pci_virtio(Context& ctx) {
    const char* id = "env.pci_virtio_devices";
    const char* name = "PCI vendor ID enumeration";
    const char* desc = "Scans /sys/bus/pci/devices/*/vendor for virtio/QEMU/VMware/VirtualBox/Xen/Parallels/Hyper-V "
                       "PCI vendor IDs.";
    Root root(ctx);
    auto l = root.list("/sys/bus/pci/devices");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/bus/pci/devices")};
    Evidence e;
    e.partial = l.truncated;
    for (const auto& d : l.names) {
        bool ok;
        std::string v = lower(read_value(root, "/sys/bus/pci/devices/" + d + "/vendor", ok));
        if (!ok) { ++e.unavailable; continue; }
        ++e.observed;
        auto it = pci_vendors().find(v);
        if (it != pci_vendors().end()) e.add(d + " " + v + " (" + it->second + ")");
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::High, "no PCI devices (no PCI bus or container)")};
    return {e.finding(id, name, desc, Severity::High,
                      "Use emulated real-vendor devices instead of paravirtual ones (Xen: disable the platform "
                      "PCI device with xen_platform_pci=0, use e1000e/ahci).")};
}

std::vector<Finding> pci_device_ids(Context& ctx) {
    const char* id = "env.pci_device_ids";
    const char* name = "Virtual PCI device ids";
    const char* desc = "vendor:device pairs from VMAware DEVICES (virtio, QEMU, VMware, VirtualBox, Parallels, Xen "
                       "platform device 5853:0001, virtual GPUs).";
    // VMAware v2.8.2 pci_devices() id32 table.
    static const std::set<unsigned> ids = {0x1af40022, 0x1af41000, 0x1af41001, 0x1af41002, 0x1af41003, 0x1af41004,
        0x1af41005, 0x1af41009, 0x1af41041, 0x1af41042, 0x1af41043, 0x1af41044, 0x1af41045, 0x1af41048, 0x1af41049,
        0x1af41050, 0x1af41052, 0x1af41053, 0x1af4105a, 0x1af41100, 0x1af41110, 0x1af41b36, 0x15ad0710, 0x15ad0720,
        0x15ad0770, 0x15ad0774, 0x15ad0778, 0x15ad0779, 0x15ad0790, 0x15ad07a0, 0x15ad07b0, 0x15ad07c0, 0x15ad07e0,
        0x15ad07f0, 0x15ad0801, 0x15ad0820, 0x15ad1977, 0xfffe0710, 0x0e0f0001, 0x0e0f0002, 0x0e0f0003, 0x0e0f0004,
        0x0e0f0005, 0x0e0f0006, 0x0e0f000a, 0x0e0f8001, 0x0e0f8002, 0x0e0f8003, 0x0e0ff80a, 0x1b360001, 0x1b360002,
        0x1b360003, 0x1b360004, 0x1b360005, 0x1b360008, 0x1b360009, 0x1b36000b, 0x1b36000c, 0x1b36000d, 0x1b360010,
        0x1b360011, 0x1b360013, 0x1b360100, 0x06270001, 0x1d1d1f1f, 0x80865845, 0x1d6b0200, 0x10de0fe7, 0x10de0ff7,
        0x10de118d, 0x10de11b0, 0x1ec6020f, 0x80ee0021, 0x80ee0022, 0x80eebeef, 0x80eecafe, 0x1ab84000, 0x1ab84005,
        0x1ab84006, 0x5853c000, 0xfffd0101, 0x5853c147, 0x5853c110, 0x5853c200, 0x58530001, 0x29556e61};
    Root root(ctx);
    auto l = root.list("/sys/bus/pci/devices");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/bus/pci/devices")};
    Evidence e;
    e.partial = l.truncated;
    for (const auto& d : l.names) {
        bool a, b;
        std::string v = read_value(root, "/sys/bus/pci/devices/" + d + "/vendor", a);
        std::string dv = read_value(root, "/sys/bus/pci/devices/" + d + "/device", b);
        long long vi, di;
        if (!a || !b || !number(v, vi, 16) || !number(dv, di, 16)) { ++e.unavailable; continue; }
        ++e.observed;
        unsigned key = (static_cast<unsigned>(vi) << 16) | static_cast<unsigned>(di & 0xffff);
        if (ids.count(key)) e.add(d + " " + v.substr(2) + ":" + dv.substr(2));
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::High, "no PCI devices")};
    return {e.finding(id, name, desc, Severity::High, "Remove or replace paravirtual and emulator-specific PCI devices.")};
}

std::vector<Finding> pci_subsystem(Context& ctx) {
    const char* id = "env.pci_subsystem_ids";
    const char* name = "Virtual PCI subsystem ids";
    const char* desc = "Emulated 'real' devices (Intel e1000, ICH9, piix) keep the hypervisor's subsystem vendor: "
                       "QEMU uses 1af4:1100 (VMAware DEVICES 32-bit id table), VMware 15ad, VirtualBox 80ee.";
    Root root(ctx);
    auto l = root.list("/sys/bus/pci/devices");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/bus/pci/devices")};
    Evidence e;
    for (const auto& d : l.names) {
        bool a, b;
        std::string sv = lower(read_value(root, "/sys/bus/pci/devices/" + d + "/subsystem_vendor", a));
        std::string sd = lower(read_value(root, "/sys/bus/pci/devices/" + d + "/subsystem_device", b));
        if (!a) { ++e.unavailable; continue; }
        ++e.observed;
        auto it = pci_vendors().find(sv);
        if (it != pci_vendors().end()) e.add(d + " subsystem " + sv + ":" + (b ? sd : "?") + " (" + it->second + ")");
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::High, "no PCI devices")};
    return {e.finding(id, name, desc, Severity::High,
                      "Override subsystem vendor/device ids of emulated devices with the host's values.")};
}

std::vector<Finding> usb_devices(Context& ctx) {
    const char* id = "env.usb_devices";
    const char* name = "Virtual USB devices";
    const char* desc = "USB devices with QEMU (0627), VirtualBox (80ee) or VMware (0e0f) vendor ids or names "
                       "such as 'QEMU USB Tablet'.";
    static const std::map<std::string, std::string> vendors = {
        {"0627", "QEMU"}, {"80ee", "VirtualBox"}, {"0e0f", "VMware"}};
    static const std::vector<std::string> names = {"QEMU", "VirtualBox", "VMware", "Virtual USB", "Xen"};
    Root root(ctx);
    auto l = root.list("/sys/bus/usb/devices");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/bus/usb/devices")};
    Evidence e;
    for (const auto& d : l.names) {
        bool ok;
        std::string base = "/sys/bus/usb/devices/" + d + "/";
        std::string v = lower(read_value(root, base + "idVendor", ok));
        if (!ok) continue;  // interfaces have no idVendor
        ++e.observed;
        auto it = vendors.find(v);
        bool a, b;
        std::string man = read_value(root, base + "manufacturer", a), prod = read_value(root, base + "product", b);
        if (it != vendors.end()) e.add(d + " " + v + " (" + it->second + ") " + prod.substr(0, 40));
        else if (!match(man + " " + prod, names).empty()) e.add(d + " " + (man + " " + prod).substr(0, 60));
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no USB devices")};
    return {e.finding(id, name, desc, Severity::Medium,
                      "Do not attach emulated tablets; pass through or emulate a vendor HID (Xen: drop "
                      "usbdevice=['tablet'] and inject input with hidsim instead).")};
}

std::vector<Finding> qemu_usb_debugfs(Context& ctx) {
    const char* id = "env.qemu_usb_debugfs";
    const char* name = "QEMU in USB debugfs";
    const char* desc = "/sys/kernel/debug/usb/devices lists 'QEMU' devices (VMAware QEMU_USB; debugfs needs root).";
    Root root(ctx);
    auto r = root.read("/sys/kernel/debug/usb/devices");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Medium, r.err, "/sys/kernel/debug/usb/devices")};
    Evidence e;
    e.scan(r, {"QEMU", "VirtualBox", "VMware"}, "usb/devices");
    return {e.finding(id, name, desc, Severity::Medium, "Do not attach QEMU-branded USB devices.")};
}

std::vector<Finding> input_devices(Context& ctx) {
    const char* id = "env.input_devices";
    const char* name = "Virtual input devices";
    const char* desc = "/proc/bus/input/devices names of hypervisor pointing devices and keyboards.";
    static const std::vector<std::string> sigs = {"QEMU", "VirtualBox", "VMware", "Xen Virtual", "virtio",
        "Microsoft Vmbus", "Hyper-V", "Parallels", "spice vdagent", "BOCHS"};
    Root root(ctx);
    auto r = root.read("/proc/bus/input/devices");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Medium, r.err, "/proc/bus/input/devices")};
    Evidence e;
    for (const auto& line : lines(r.value)) {
        if (line.rfind("N: Name=", 0) != 0) continue;
        ++e.observed;
        if (!match(line, sigs).empty()) e.add(trim(line.substr(8)));
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no input devices registered")};
    return {e.finding(id, name, desc, Severity::Medium,
                      "Remove paravirtual keyboards/tablets (Xen: vkb/vfb devices, usbdevice tablet).")};
}

const std::vector<std::string>& disk_sigs() {
    // v1 BLOCK_DEVICE_VENDOR_SIGNATURES.
    static const std::vector<std::string> s = {"qemu", "vbox", "vmware", "virtual disk", "msft virtual disk"};
    return s;
}

std::vector<Finding> scsi_vendor(Context& ctx) {
    Root root(ctx);
    const char* id = "env.scsi_device_vendor";
    const char* name = "SCSI device vendor string";
    const char* desc = "/proc/scsi/scsi Vendor/Model fields -- Pafish's 'QEMU SCSI key' check, read from /proc.";
    auto r = root.read("/proc/scsi/scsi");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Medium, r.err, "/proc/scsi/scsi")};
    Evidence e;
    e.scan(r, disk_sigs(), "/proc/scsi/scsi");
    return {e.finding(id, name, desc, Severity::Medium, "Give virtual disks a real vendor/model string.")};
}

std::vector<Finding> block_vendor(Context& ctx) {
    const char* id = "env.block_device_vendor";
    const char* name = "Block device vendor/model strings";
    const char* desc = "/sys/block/*/device/{vendor,model}, checked against known virtual-disk vendor strings.";
    Root root(ctx);
    auto l = root.list("/sys/block");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/block")};
    Evidence e;
    for (const auto& d : l.names)
        for (const char* f : {"vendor", "model"}) {
            auto r = root.read("/sys/block/" + d + "/device/" + f);
            if (!r.ok) continue;
            ++e.observed;
            if (!match(r.value, disk_sigs()).empty()) e.add(d + "." + f + "=" + trim(r.value));
        }
    if (!e.observed) {
        // virtio-blk and xen-blkfront disks have no vendor/model attributes; that is a clean read.
        return {clean(id, name, desc, Severity::Medium, "no vendor/model attributes")};
    }
    return {e.finding(id, name, desc, Severity::Medium, "Give virtual disks a real vendor/model string.")};
}

std::vector<Finding> disk_by_id(Context& ctx) {
    const char* id = "env.disk_by_id";
    const char* name = "Disk ids in /dev/disk/by-id";
    const char* desc = "udev names disks by bus, model and serial: ata-QEMU_HARDDISK_QM00001, "
                       "ata-VBOX_HARDDISK_VB..., scsi-0QEMU_QEMU_HARDDISK, virtio-..., xen ids.";
    static const std::vector<std::string> sigs = {"qemu", "vbox", "vmware", "virtio", "xen", "msft_virtual",
        "virtual_disk"};
    Root root(ctx);
    auto l = root.list("/dev/disk/by-id");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/dev/disk/by-id")};
    Evidence e;
    e.observed = l.names.size();
    for (const auto& n : l.names)
        if (!match(n, sigs).empty()) e.add(n);
    return {e.finding(id, name, desc, Severity::Medium, "Give virtual disks a real model and serial (QEMU: "
                                                          "-device ide-hd,model=...,serial=...).")};
}

bool qemu_serial(const std::string& s) {
    // VMAware DISK is_qemu_serial: "QM" followed by "0000".
    return s.size() >= 6 && std::tolower(static_cast<unsigned char>(s[0])) == 'q' &&
           std::tolower(static_cast<unsigned char>(s[1])) == 'm' && s.compare(2, 4, "0000") == 0;
}
bool vbox_serial(const std::string& s) {
    // VMAware DISK is_vbox_serial: VB12345678-12345678.
    return s.size() == 19 && std::tolower(static_cast<unsigned char>(s[0])) == 'v' &&
           std::tolower(static_cast<unsigned char>(s[1])) == 'b' && s[10] == '-' && hex_string(s.substr(2, 8)) &&
           hex_string(s.substr(11, 8));
}

std::vector<Finding> disk_serial(Context& ctx) {
    const char* id = "env.disk_serial_pattern";
    const char* name = "Hypervisor disk serial pattern";
    const char* desc = "Disk serials in the QEMU (QM0000x) or VirtualBox (VBxxxxxxxx-xxxxxxxx) default formats "
                       "(VMAware DISK), from /sys/block/*/serial, device/serial and by-id names.";
    Root root(ctx);
    auto l = root.list("/sys/block");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/block")};
    Evidence e;
    std::vector<std::string> serials;
    for (const auto& d : l.names)
        for (const char* f : {"serial", "device/serial"}) {
            bool ok;
            std::string s = read_value(root, "/sys/block/" + d + "/" + f, ok);
            if (ok && !s.empty()) serials.push_back(s);
        }
    auto ids = root.list("/dev/disk/by-id");
    for (const auto& n : ids.names) {
        auto us = n.rfind('_');
        if (us != std::string::npos) serials.push_back(n.substr(us + 1));
    }
    for (const auto& s : serials) {
        ++e.observed;
        if (qemu_serial(s)) e.add("QEMU serial " + s.substr(0, 24));
        if (vbox_serial(s)) e.add("VirtualBox serial " + s);
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::High, "no disk serials exposed")};
    return {e.finding(id, name, desc, Severity::High, "Set disk serials in the host vendor's format.")};
}

std::vector<Finding> virtual_disk_driver(Context& ctx) {
    const char* id = "env.virtual_disk_driver";
    const char* name = "Paravirtual disk driver";
    const char* desc = "Block devices named vd* (virtio-blk), xvd* (xen-blkfront) or driven by virtio_blk, "
                       "xen_blkfront, vmw_pvscsi, hv_storvsc, virtio_scsi.";
    static const std::vector<std::string> drivers = {"virtio_blk", "vbd", "xen_blkfront", "vmw_pvscsi", "hv_storvsc",
        "virtio_scsi"};
    Root root(ctx);
    auto l = root.list("/sys/block");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/block")};
    Evidence e;
    for (const auto& d : l.names) {
        if (d.rfind("loop", 0) == 0 || d.rfind("ram", 0) == 0 || d.rfind("zram", 0) == 0) continue;
        ++e.observed;
        if (d.rfind("vd", 0) == 0) e.add(d + " (virtio-blk name)");
        if (d.rfind("xvd", 0) == 0) e.add(d + " (xen-blkfront name)");
        auto drv = root.link("/sys/block/" + d + "/device/driver");
        if (drv.ok) {
            std::string b = basename(drv.value);
            for (const auto& x : drivers)
                if (b == x) e.add(d + " driver " + b);
        }
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::High, "no disks")};
    return {e.finding(id, name, desc, Severity::High, "Attach system disks through an emulated AHCI/NVMe controller.")};
}

std::vector<Finding> nic_driver(Context& ctx) {
    const char* id = "env.nic_driver";
    const char* name = "Virtual network adapter driver";
    const char* desc = "Drivers of /sys/class/net adapters: virtio_net, xen-netfront (vif), vmxnet3, hv_netvsc, "
                       "or an emulated e1000/rtl8139/pcnet carrying a hypervisor PCI subsystem vendor.";
    static const std::vector<std::string> pv = {"virtio_net", "vif", "xen-netfront", "vmxnet3", "vmxnet", "hv_netvsc",
        "netvsc"};
    static const std::vector<std::string> emulated = {"e1000", "e1000e", "8139cp", "8139too", "pcnet32", "ne2k-pci"};
    Root root(ctx);
    auto l = root.list("/sys/class/net");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/class/net")};
    Evidence e;
    for (const auto& n : l.names) {
        if (n == "lo") continue;
        auto drv = root.link("/sys/class/net/" + n + "/device/driver");
        if (!drv.ok) continue;  // software interfaces (bridges, veth, tun)
        ++e.observed;
        std::string b = basename(drv.value);
        if (std::find(pv.begin(), pv.end(), b) != pv.end()) e.add(n + " driver " + b);
        if (std::find(emulated.begin(), emulated.end(), b) != emulated.end()) {
            bool ok;
            std::string sv = lower(read_value(root, "/sys/class/net/" + n + "/device/subsystem_vendor", ok));
            if (ok && pci_vendors().count(sv)) e.add(n + " emulated " + b + " subsystem " + sv);
        }
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no hardware network adapters")};
    return {e.finding(id, name, desc, Severity::Medium,
                      "Use an emulated NIC with the host's subsystem ids (Xen: model=e1000 and type=ioemu; no "
                      "PV vif frontend in the guest).")};
}

std::vector<Finding> gpu_driver(Context& ctx) {
    const char* id = "env.gpu_driver";
    const char* name = "Virtual display adapter";
    const char* desc = "DRM/framebuffer drivers of virtual GPUs: bochs-drm, qxl, virtio_gpu, vmwgfx, cirrus, "
                       "vboxvideo, hyperv_drm, xen-fbfront.";
    static const std::vector<std::string> sigs = {"bochs", "qxl", "virtio_gpu", "virtio-gpu", "vmwgfx", "cirrus",
        "vboxvideo", "vboxdrm", "hyperv_drm", "hyperv_fb", "xen-fbfront", "xenfb", "simpledrm"};
    Root root(ctx);
    auto l = root.list("/sys/class/drm");
    auto fb = root.read("/sys/class/graphics/fb0/name");
    if (!l.ok && !fb.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/class/drm")};
    Evidence e;
    for (const auto& n : l.names) {
        if (n.find('-') != std::string::npos || n.rfind("card", 0) != 0) continue;  // connectors
        ++e.observed;
        auto drv = root.link("/sys/class/drm/" + n + "/device/driver");
        std::string b = drv.ok ? basename(drv.value) : "";
        auto ue = root.read("/sys/class/drm/" + n + "/device/uevent");
        if (ue.ok) {
            auto f = fields(ue.value, '=');
            if (f.count("DRIVER")) b = f["DRIVER"];
        }
        if (!b.empty() && b != "simpledrm" && !match(b, sigs).empty()) e.add(n + " driver " + b);
    }
    if (fb.ok) {
        ++e.observed;
        std::string v = trim(fb.value);
        if (!match(v, sigs).empty() && lower(v).find("simpledrm") == std::string::npos) e.add("fb0 " + v);
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no display adapter")};
    return {e.finding(id, name, desc, Severity::Medium, "Pass through a GPU or emulate a vendor adapter.")};
}

std::vector<Finding> no_display(Context& ctx) {
    const char* id = "env.no_display_adapter";
    const char* name = "No display adapter";
    const char* desc = "No DRM card and no framebuffer: a headless machine, unlike a desktop or laptop.";
    Root root(ctx);
    auto l = root.list("/sys/class/drm");
    if (!l.ok && l.err != ENOENT) return {unreadable(id, name, desc, Severity::Low, l.err, "/sys/class/drm")};
    if (!root.exists("/sys/class")) return {skipped(id, name, desc, Severity::Low, "no sysfs")};
    bool card = false;
    for (const auto& n : l.names)
        if (n.rfind("card", 0) == 0) card = true;
    bool fb = root.exists("/sys/class/graphics/fb0");
    Json ev = Json::object();
    ev.set("drm_card", card);
    ev.set("framebuffer", fb);
    return {bool_check(id, name, desc, Severity::Low, !card && !fb, ev, "Give the guest a display adapter.")};
}

std::vector<Finding> monitor_edid(Context& ctx) {
    const char* id = "env.monitor_edid";
    const char* name = "Monitor EDID";
    const char* desc = "Connected DRM connectors without an EDID, or with QEMU's generated EDID (manufacturer RHT, "
                       "qemu hw/display/edid-generate.c).";
    Root root(ctx);
    auto l = root.list("/sys/class/drm");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Low, l.err, "/sys/class/drm")};
    Evidence e;
    for (const auto& n : l.names) {
        if (n.find('-') == std::string::npos) continue;
        bool ok;
        if (read_value(root, "/sys/class/drm/" + n + "/status", ok) != "connected") continue;
        ++e.observed;
        auto edid = root.read("/sys/class/drm/" + n + "/edid");
        if (!edid.ok || edid.value.size() < 10) { e.add(n + ": no EDID"); continue; }
        // EDID 1.4 bytes 8-9: big-endian PNP manufacturer id, 5 bits per letter.
        unsigned m = (static_cast<uint8_t>(edid.value[8]) << 8) | static_cast<uint8_t>(edid.value[9]);
        std::string pnp = {static_cast<char>('@' + ((m >> 10) & 0x1f)), static_cast<char>('@' + ((m >> 5) & 0x1f)),
                           static_cast<char>('@' + (m & 0x1f))};
        if (pnp == "RHT") e.add(n + ": QEMU EDID (RHT)");
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Low, "no connected display connector")};
    return {e.finding(id, name, desc, Severity::Low, "Provide a real monitor EDID to the virtual display.")};
}

std::vector<Finding> sound_cards(Context& ctx) {
    const char* id = "env.sound_cards";
    const char* name = "Sound hardware";
    const char* desc = "/proc/asound/cards is empty or lists chips only emulators offer today (Intel 82801AA "
                       "AC'97, Ensoniq ES1370/ES1371, virtio-snd).";
    static const std::vector<std::string> sigs = {"82801AA", "ES1370", "ES1371", "virtio", "VirtualBox", "VMware"};
    Root root(ctx);
    auto r = root.read("/proc/asound/cards");
    if (!r.ok && r.err == ENOENT && root.exists("/proc/version"))
        return {detected(id, name, desc, Severity::Low, "no ALSA (/proc/asound absent)",
                         "Give the guest an HD Audio device.")};
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "/proc/asound/cards")};
    std::string v = trim(r.value);
    if (v.empty() || v.find("no soundcards") != std::string::npos)
        return {detected(id, name, desc, Severity::Low, "no sound cards", "Give the guest an HD Audio device.")};
    Evidence e;
    e.scan(r, sigs, "cards");
    return {e.finding(id, name, desc, Severity::Low, "Emulate Intel HD Audio rather than AC'97/ES1370.")};
}

std::vector<Finding> hwmon(Context& ctx) {
    const char* id = "env.hwmon_absent";
    const char* name = "No hardware monitoring sensors";
    const char* desc = "/sys/class/hwmon is missing or empty: VMs expose no voltage/fan/temperature chips "
                       "(VMAware HWMON).";
    Root root(ctx);
    if (!root.exists("/sys/class")) return {skipped(id, name, desc, Severity::Medium, "no sysfs")};
    auto l = root.list("/sys/class/hwmon");
    if (!l.ok && l.err != ENOENT) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/class/hwmon")};
    std::vector<std::string> chips;
    for (const auto& n : l.names) {
        bool ok;
        std::string nm = read_value(root, "/sys/class/hwmon/" + n + "/name", ok);
        chips.push_back(ok ? nm : n);
    }
    Json ev = Json::object();
    ev.set("chips", Json(chips));
    return {bool_check(id, name, desc, Severity::Medium, chips.empty(), ev,
                       "Not fixable by configuration alone; a sensor-emulating device model is needed.")};
}

std::vector<Finding> thermal(Context& ctx) {
    const char* id = "env.thermal_zones";
    const char* name = "No thermal zones or cooling devices";
    const char* desc = "No /sys/class/thermal/thermal_zone0 and no cooling_device0 (VMAware TEMPERATURE; "
                       "al-khaser current_temperature_acpi_wmi and cpu_fan_wmi on Windows).";
    Root root(ctx);
    if (!root.exists("/sys/class")) return {skipped(id, name, desc, Severity::Medium, "no sysfs")};
    bool zone = root.exists("/sys/class/thermal/thermal_zone0"), cool = root.exists("/sys/class/thermal/cooling_device0");
    Json ev = Json::object();
    ev.set("thermal_zone0", zone);
    ev.set("cooling_device0", cool);
    return {bool_check(id, name, desc, Severity::Medium, !zone && !cool, ev,
                       "Expose ACPI thermal zones (_TZ) in the guest DSDT.")};
}

long long chassis_type(const Root& root) {
    bool ok;
    long long t = -1;
    std::string v = read_value(root, "/sys/class/dmi/id/chassis_type", ok);
    if (!ok || !number(v, t)) return -1;
    return t;
}

std::vector<Finding> power_supply(Context& ctx) {
    const char* id = "env.power_supply";
    const char* name = "Battery and AC adapter";
    const char* desc = "No /sys/class/power_supply entries at all, or a portable chassis type without a battery "
                       "(al-khaser power_capabilities, VMAware POWER_CAPABILITIES on Windows).";
    Root root(ctx);
    if (!root.exists("/sys/class")) return {skipped(id, name, desc, Severity::Low, "no sysfs")};
    auto l = root.list("/sys/class/power_supply");
    if (!l.ok && l.err != ENOENT)
        return {unreadable(id, name, desc, Severity::Low, l.err, "/sys/class/power_supply")};
    bool battery = false;
    for (const auto& n : l.names) {
        bool ok;
        if (read_value(root, "/sys/class/power_supply/" + n + "/type", ok) == "Battery") battery = true;
    }
    long long ct = chassis_type(root);
    bool portable = std::find(kPortableChassis.begin(), kPortableChassis.end(), ct) != kPortableChassis.end();
    bool mains = std::find(kMainsChassis.begin(), kMainsChassis.end(), ct) != kMainsChassis.end();
    Json ev = Json::object();
    ev.set("supplies", Json(l.names));
    ev.set("battery", battery);
    ev.set("chassis_type", ct);
    // A desktop or server without any supply is normal; a portable without a battery, or a machine of
    // unknown/"Other" chassis with no supply at all (the VM default), is not.
    bool hit = portable ? !battery : (l.names.empty() && !mains);
    auto f = bool_check(id, name, desc, Severity::Low, hit, ev,
                        "Expose an ACPI battery/AC adapter consistent with the chassis type (Xen: acpi_s3/battery "
                        "emulation or a laptop identity with a battery device).");
    f.confidence = portable ? 0.8 : 0.4;
    return {f};
}

std::vector<Finding> cpu_frequency(Context& ctx) {
    const char* id = "env.cpu_frequency_scaling";
    const char* name = "No CPU frequency scaling";
    const char* desc = "No cpufreq interface and every core at exactly the same 'cpu MHz': virtual CPUs run at a "
                       "fixed nominal clock (al-khaser/VMAware CLOCK-class checks).";
    Root root(ctx);
    auto r = root.read("/proc/cpuinfo");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "/proc/cpuinfo")};
    std::set<std::string> mhz;
    for (const auto& line : lines(r.value))
        if (line.rfind("cpu MHz", 0) == 0) {
            auto c = line.find(':');
            if (c != std::string::npos) mhz.insert(trim(line.substr(c + 1)));
        }
    bool cpufreq = root.exists("/sys/devices/system/cpu/cpu0/cpufreq") || root.exists("/sys/devices/system/cpu/cpufreq/policy0");
    if (mhz.empty() && cpufreq) return {clean(id, name, desc, Severity::Low, "cpufreq present")};
    if (mhz.empty()) return {skipped(id, name, desc, Severity::Low, "no clock information (non-x86 cpuinfo)")};
    Json ev = Json::object();
    ev.set("cpufreq", cpufreq);
    ev.set("distinct_mhz", static_cast<long long>(mhz.size()));
    ev.set("mhz", *mhz.begin());
    auto f = bool_check(id, name, desc, Severity::Low, !cpufreq && mhz.size() == 1, ev,
                        "Expose CPU performance states (Xen: cpufreq=dom0-kernel is host-side only; accept or pass "
                        "_PSS through ACPI).");
    f.confidence = 0.5;
    return {f};
}

std::vector<Finding> cpu_cache(Context& ctx) {
    const char* id = "env.cpu_cache_topology";
    const char* name = "CPU cache hierarchy";
    const char* desc = "No L2/L3 cache in /sys/devices/system/cpu/cpu0/cache (al-khaser cachememory_wmi on "
                       "Windows): emulated CPUs often report none.";
    Root root(ctx);
    auto l = root.list("/sys/devices/system/cpu/cpu0/cache");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Low, l.err, "/sys/devices/system/cpu/cpu0/cache")};
    std::vector<std::string> levels;
    for (const auto& n : l.names) {
        if (n.rfind("index", 0) != 0) continue;
        bool a, b;
        std::string lvl = read_value(root, "/sys/devices/system/cpu/cpu0/cache/" + n + "/level", a);
        std::string sz = read_value(root, "/sys/devices/system/cpu/cpu0/cache/" + n + "/size", b);
        if (a) levels.push_back("L" + lvl + (b ? " " + sz : ""));
    }
    bool l2 = false;
    for (const auto& s : levels)
        if (s.rfind("L2", 0) == 0 || s.rfind("L3", 0) == 0) l2 = true;
    Json ev = Json::object();
    ev.set("caches", Json(levels));
    return {bool_check(id, name, desc, Severity::Low, !l2, ev, "Pass the host cache topology to the guest CPU model.")};
}

std::vector<Finding> cpuinfo_model(Context& ctx) {
    const char* id = "env.cpuinfo_virtual_model";
    const char* name = "Virtual CPU model in /proc/cpuinfo";
    const char* desc = "/proc/cpuinfo model/vendor naming a virtual or emulated CPU (QEMU Virtual CPU, Common KVM "
                       "processor, User Mode Linux -- VMAware UML_CPU, virt-what PowerVM Lx86).";
    static const std::vector<std::string> sigs = {"QEMU Virtual CPU", "Common KVM processor", "Common 32-bit KVM",
        "User Mode Linux", "PowerVM Lx86", "Virtual CPU", "Bochs"};
    Root root(ctx);
    auto r = root.read("/proc/cpuinfo");
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/proc/cpuinfo")};
    Evidence e;
    ++e.observed;
    for (const auto& line : lines(r.value)) {
        if (line.rfind("model name", 0) != 0 && line.rfind("vendor_id", 0) != 0 && line.rfind("cpu", 0) != 0) continue;
        std::string hit = match(line, sigs);
        if (!hit.empty()) e.add(trim(line).substr(0, 80));
        auto c = line.find(':');
        if (line.rfind("vendor_id", 0) == 0 && c != std::string::npos && trim(line.substr(c + 1)) == "UML")
            e.add("vendor_id UML");
    }
    return {e.finding(id, name, desc, Severity::High, "Use CPU passthrough with the host model name.")};
}

std::vector<Finding> cpuinfo_flag(Context& ctx) {
    const char* id = "env.cpuinfo_hypervisor_flag";
    const char* name = "'hypervisor' flag in /proc/cpuinfo";
    const char* desc = "The kernel lists the CPUID hypervisor bit as the 'hypervisor' flag; shell malware greps "
                       "/proc/cpuinfo for it rather than executing CPUID.";
    Root root(ctx);
    auto r = root.read("/proc/cpuinfo");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Critical, r.err, "/proc/cpuinfo")};
    bool seen = false, flag = false;
    for (const auto& line : lines(r.value))
        if (line.rfind("flags", 0) == 0) {
            seen = true;
            if (has_word(line, "hypervisor")) flag = true;
        }
    if (!seen) return {skipped(id, name, desc, Severity::Critical, "no x86 flags line")};
    return {bool_check(id, name, desc, Severity::Critical, flag, flag ? "flags contain 'hypervisor'" : "no flag",
                       "Clear CPUID.1:ECX[31] (Xen + DRAKVUF: cpuidmon -s also hides it from the guest kernel).")};
}

std::vector<Finding> cores(Context& ctx) {
    const char* id = "env.low_core_count";
    const char* name = "Logical CPU count";
    const char* desc = "A sandbox is commonly provisioned with very few vCPUs (<= 2; VMAware THREAD_COUNT, "
                       "al-khaser NumberOfProcessors).";
    Root root(ctx);
    long long limit = ctx.param_int("resources.min_cores", kLowCoreCount);
    bool ok;
    std::string online = read_value(root, "/sys/devices/system/cpu/online", ok);
    long long count = 0;
    if (ok) {
        for (const auto& part : split(online, ',')) {
            auto dash = part.find('-');
            long long a, b;
            if (dash == std::string::npos) { if (number(part, a)) ++count; }
            else if (number(part.substr(0, dash), a) && number(part.substr(dash + 1), b) && b >= a) count += b - a + 1;
        }
    }
    if (!count) {
        auto r = root.read("/proc/cpuinfo");
        if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "/proc/cpuinfo")};
        for (const auto& line : lines(r.value))
            if (line.rfind("processor", 0) == 0) ++count;
    }
    if (!count) return {error(id, name, desc, Severity::Low, "could not count CPUs")};
    return {measured(id, name, desc, static_cast<double>(count), static_cast<double>(limit), count <= limit, "cpus",
                     "Give the guest at least 4 vCPUs (xl.cfg vcpus=).", Severity::Low, 0.5)};
}

std::vector<Finding> ram(Context& ctx) {
    const char* id = "env.low_ram";
    const char* name = "Total RAM";
    const char* desc = "A sandbox is commonly provisioned with little RAM (<= 4 GiB; al-khaser memory_space).";
    Root root(ctx);
    auto r = root.read("/proc/meminfo");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "/proc/meminfo")};
    auto f = fields(r.value);
    long long kib;
    if (!f.count("MemTotal") || !number(split(f["MemTotal"], ' ')[0], kib))
        return {error(id, name, desc, Severity::Low, "MemTotal not found in /proc/meminfo")};
    long long limit = ctx.param_int("resources.min_ram_kib", kLowRamKiB);
    return {measured(id, name, desc, static_cast<double>(kib / 1024), static_cast<double>(limit / 1024), kib <= limit,
                     "MiB", "Give the guest at least 8 GiB (xl.cfg memory=).", Severity::Low, 0.5)};
}

std::vector<Finding> disk(Context& ctx) {
    const char* id = "env.small_disk";
    const char* name = "Primary disk size";
    const char* desc = "A sandbox is commonly provisioned with a small disk (<= 60 GiB; al-khaser disk_size_*).";
    Root root(ctx);
    auto l = root.list("/sys/block");
    long long best = 0;
    std::string best_name;
    if (l.ok)
        for (const auto& d : l.names) {
            if (d.rfind("loop", 0) == 0 || d.rfind("ram", 0) == 0 || d.rfind("sr", 0) == 0 || d.rfind("zram", 0) == 0)
                continue;
            bool ok;
            long long sectors;
            if (number(read_value(root, "/sys/block/" + d + "/size", ok), sectors) && sectors * kSectorBytes > best) {
                best = sectors * kSectorBytes;
                best_name = d;
            }
        }
    if (!best && !root.fixture()) {
        struct statvfs vfs {};
        if (statvfs("/", &vfs) == 0) {
            best = static_cast<long long>(vfs.f_blocks) * static_cast<long long>(vfs.f_frsize);
            best_name = "/ (filesystem)";
        }
    }
    if (!best) return {skipped(id, name, desc, Severity::Low, "no eligible block devices found")};
    long long limit = ctx.param_int("resources.min_disk_bytes", kSmallDiskBytes);
    auto f = measured(id, name, desc, static_cast<double>(best >> 30), static_cast<double>(limit >> 30), best <= limit,
                      "GiB", "Give the guest a disk of 256 GB or more (sparse images cost nothing).", Severity::Low, 0.5);
    f.evidence.set("device", best_name);
    return {f};
}

std::vector<Finding> screen(Context& ctx) {
    const char* id = "env.screen_resolution";
    const char* name = "Screen resolution";
    const char* desc = "Current mode of connected DRM connectors or the framebuffer: 1024x768 and below are "
                       "emulator defaults.";
    Root root(ctx);
    long long best = 0;
    std::string mode;
    auto l = root.list("/sys/class/drm");
    for (const auto& n : l.names) {
        if (n.find('-') == std::string::npos) continue;
        bool ok;
        if (read_value(root, "/sys/class/drm/" + n + "/status", ok) != "connected") continue;
        auto modes = root.read("/sys/class/drm/" + n + "/modes");
        if (!modes.ok) continue;
        std::string first = trim(lines(modes.value)[0]);
        auto x = first.find('x');
        long long w, h;
        if (x != std::string::npos && number(first.substr(0, x), w) &&
            number(first.substr(x + 1, first.find_first_not_of("0123456789", x + 1) - x - 1), h) && w * h > best) {
            best = w * h;
            mode = first;
        }
    }
    if (!best) {
        bool ok;
        std::string vs = read_value(root, "/sys/class/graphics/fb0/virtual_size", ok);
        auto comma = vs.find(',');
        long long w, h;
        if (ok && comma != std::string::npos && number(vs.substr(0, comma), w) && number(vs.substr(comma + 1), h)) {
            best = w * h;
            mode = vs;
        }
    }
    if (!best) return {skipped(id, name, desc, Severity::Low, "no display mode readable (headless or no DRM)")};
    auto f = measured(id, name, desc, static_cast<double>(best), static_cast<double>(kLowScreenPixels),
                      best <= kLowScreenPixels, "pixels", "Configure a 1920x1080 or larger virtual display.",
                      Severity::Low, 0.5);
    f.evidence.set("mode", mode);
    return {f};
}

}  // namespace

PERDEDOR_REGISTER(pci_virtio, "hardware.pci_vendor_ids", "fast", false, "env.pci_virtio_devices");
PERDEDOR_REGISTER(pci_device_ids, "hardware.pci_vendor_ids", "fast", false, "env.pci_device_ids");
PERDEDOR_REGISTER(pci_subsystem, "hardware.pci_vendor_ids", "fast", false, "env.pci_subsystem_ids");
PERDEDOR_REGISTER(usb_devices, "hardware.usb_devices", "fast", false, "env.usb_devices");
PERDEDOR_REGISTER(qemu_usb_debugfs, "hardware.usb_devices", "fast", false, "env.qemu_usb_debugfs");
PERDEDOR_REGISTER(input_devices, "hardware.input_devices", "fast", false, "env.input_devices");
PERDEDOR_REGISTER(scsi_vendor, "hardware.disk_identity", "fast", false, "env.scsi_device_vendor");
PERDEDOR_REGISTER(block_vendor, "hardware.disk_identity", "fast", false, "env.block_device_vendor");
PERDEDOR_REGISTER(disk_by_id, "hardware.disk_identity", "fast", false, "env.disk_by_id");
PERDEDOR_REGISTER(disk_serial, "hardware.disk_identity", "fast", false, "env.disk_serial_pattern");
PERDEDOR_REGISTER(virtual_disk_driver, "hardware.disk_identity", "fast", false, "env.virtual_disk_driver");
PERDEDOR_REGISTER(nic_driver, "hardware.nic_identity", "fast", false, "env.nic_driver");
PERDEDOR_REGISTER(gpu_driver, "hardware.gpu_identity", "fast", false, "env.gpu_driver");
PERDEDOR_REGISTER(no_display, "hardware.gpu_identity", "fast", false, "env.no_display_adapter");
PERDEDOR_REGISTER(monitor_edid, "hardware.monitor_edid", "fast", false, "env.monitor_edid");
PERDEDOR_REGISTER(sound_cards, "hardware.audio_devices", "fast", false, "env.sound_cards");
PERDEDOR_REGISTER(hwmon, "hardware.thermal_sensors", "fast", false, "env.hwmon_absent");
PERDEDOR_REGISTER(thermal, "hardware.thermal_sensors", "fast", false, "env.thermal_zones");
PERDEDOR_REGISTER(power_supply, "hardware.battery_power", "fast", false, "env.power_supply");
PERDEDOR_REGISTER(cpu_frequency, "hardware.cpu_cache_clock", "fast", false, "env.cpu_frequency_scaling");
PERDEDOR_REGISTER(cpu_cache, "hardware.cpu_cache_clock", "fast", false, "env.cpu_cache_topology");
PERDEDOR_REGISTER(cpuinfo_model, "cpu.brand_string", "fast", false, "env.cpuinfo_virtual_model");
PERDEDOR_REGISTER(cpuinfo_flag, "cpu.hypervisor_bit", "fast", false, "env.cpuinfo_hypervisor_flag");
PERDEDOR_REGISTER(cores, "resources.cpu_count", "fast", false, "env.low_core_count");
PERDEDOR_REGISTER(ram, "resources.memory_size", "fast", false, "env.low_ram");
PERDEDOR_REGISTER(disk, "resources.disk_size", "fast", false, "env.small_disk");
PERDEDOR_REGISTER(screen, "resources.screen", "fast", false, "env.screen_resolution");

}  // namespace perdedor
