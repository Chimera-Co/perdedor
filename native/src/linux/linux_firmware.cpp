// Firmware identity on Linux: SMBIOS/DMI strings and serials, raw SMBIOS
// structures, ACPI tables and devices, BIOS metadata and boot mode.
//
// Sources: VMAware v2.8.2 (DMI_SCAN, CVENDOR, CTYPE, QEMU_VIRTUAL_DMI,
// SMBIOS_VM_BIT, DMIDECODE, FIRMWARE), systemd src/basic/virt.c
// (detect_vm_dmi_vendor, detect_vm_smbios), Xen 4.19 hvmloader smbios.c,
// SeaBIOS src/fw/biostables.c, VirtualBox DevFwCommon.cpp.
#include <cerrno>
#include <cstring>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

const char* kDmi = "/sys/class/dmi/id/";

// DSP0134 3.4 section 7.1.2.2: BIOS Characteristics Extension Byte 2, bit 4 =
// "Virtual machine"; it lives at offset 0x13 of the type 0 structure.
constexpr size_t kSmbiosExt2Offset = 0x13;
constexpr unsigned kSmbiosVmBit = 1u << 4;
// DSP0134 3.4 table 17 (System Enclosure or Chassis Types): 1 = Other. QEMU
// and several hypervisors report it; VMAware CTYPE flags exactly this value.
constexpr long long kChassisOther = 1;
// ACPI 6.5 section 5.2.6: every system description table starts with a
// 36-byte header; OEMID at offset 10 (6 bytes), OEM table id at 16 (8 bytes),
// creator id at 28 (4 bytes).
constexpr size_t kAcpiHeader = 36;

const std::vector<std::string>& dmi_vm_strings() {
    // systemd v257 dmi_vendor_table plus VMAware v2.8.2 DMI_SCAN vm_table.
    static const std::vector<std::string> s = {"KVM", "OpenStack", "KubeVirt", "Alibaba Cloud ECS", "Amazon EC2",
        "QEMU", "VMware", "VMW", "innotek GmbH", "VirtualBox", "Oracle Corporation", "Xen", "Bochs", "Parallels",
        "BHYVE", "Hyper-V", "Apple Virtualization", "Google Compute Engine", "HVM domU", "Virtual Machine",
        "Standard PC (i440FX", "Standard PC (Q35", "Nutanix", "oVirt", "RHEV Hypervisor"};
    return s;
}

std::vector<Finding> dmi_fields(Context& ctx) {
    Root root(ctx);
    static const std::vector<std::string> fields = {"sys_vendor", "product_name", "product_family", "product_sku",
        "product_version", "bios_vendor", "bios_version", "board_vendor", "board_name", "chassis_vendor",
        "chassis_asset_tag", "board_version", "chassis_version", "board_asset_tag"};
    std::vector<Finding> out;
    for (const auto& f : fields) {
        std::string id = "env.dmi_" + f, name = "DMI '" + f + "'";
        std::string desc = "/sys/class/dmi/id/" + f + ", checked against known hypervisor vendor names.";
        auto r = root.read(kDmi + f);
        if (!r.ok) { out.push_back(unreadable(id, name, desc, Severity::High, r.err, kDmi + f)); continue; }
        std::string value = trim(r.value);
        std::string hit = match(value, vm_signatures());
        Json ev = Json::object();
        ev.set("value", value.substr(0, 120));
        if (!hit.empty()) ev.set("match", hit);
        out.push_back(bool_check(id, name, desc, Severity::High, !hit.empty(), ev,
                                 "Present a real vendor identity in SMBIOS (Xen: hvmloader smbios_firmware / "
                                 "firmware_override with host-derived tables)."));
    }
    return out;
}

std::vector<Finding> dmi_modalias(Context& ctx) {
    const char* id = "env.dmi_modalias";
    const char* name = "DMI modalias names a hypervisor";
    const char* desc = "The DMI modalias concatenates every SMBIOS identity string; VMAware QEMU_VIRTUAL_DMI reads it.";
    Root root(ctx);
    auto r = root.read("/sys/devices/virtual/dmi/id/modalias");
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/sys/devices/virtual/dmi/id/modalias")};
    std::string hit = match(r.value, dmi_vm_strings());
    Json ev = Json::object();
    ev.set("modalias", trim(r.value).substr(0, 200));
    if (!hit.empty()) ev.set("match", hit);
    return {bool_check(id, name, desc, Severity::High, !hit.empty(), ev,
                       "Replace the SMBIOS type 0/1/2/3 strings with a real machine's identity.")};
}

std::vector<Finding> dmi_chassis_type(Context& ctx) {
    const char* id = "env.dmi_chassis_type";
    const char* name = "SMBIOS chassis type 'Other'";
    const char* desc = "Chassis type 1 (Other) is what QEMU and other hypervisors report (VMAware CTYPE).";
    Root root(ctx);
    auto r = root.read(std::string(kDmi) + "chassis_type");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "chassis_type")};
    long long t = 0;
    if (!number(r.value, t)) return {error(id, name, desc, Severity::Low, "unparsable chassis_type")};
    Json ev = Json::object();
    ev.set("chassis_type", t);
    return {bool_check(id, name, desc, Severity::Low, t == kChassisOther, ev,
                       "Report a real chassis type (3 Desktop, 10 Notebook) in SMBIOS type 3.")};
}

bool placeholder_serial(const std::string& v) {
    // Values firmware writes when the OEM left a field unset (seen in dmidecode output of
    // virtual and white-box machines); not hypervisor-specific, so medium confidence.
    static const std::vector<std::string> p = {"", "0", "None", "Not Specified", "Default string",
        "To be filled by O.E.M.", "System Serial Number", "Chassis Serial Number", "0123456789", "Not Applicable"};
    for (const auto& x : p)
        if (lower(trim(v)) == lower(x)) return true;
    return false;
}

std::vector<Finding> dmi_serials(Context& ctx) {
    const char* id = "env.dmi_serials_uuid";
    const char* name = "SMBIOS serial numbers and system UUID";
    const char* desc = "Serials and the UUID of a VM are empty, placeholders or hypervisor-patterned "
                       "(VMware-..., VirtualBox '0', Xen hvmloader serial = UUID, EC2 UUID prefix ec2).";
    Root root(ctx);
    std::map<std::string, std::string> v;
    int denied = 0, missing = 0;
    for (const char* f : {"product_serial", "product_uuid", "board_serial", "chassis_serial"}) {
        auto r = root.read(std::string(kDmi) + f);
        if (r.ok) v[f] = trim(r.value);
        else if (r.err == EACCES || r.err == EPERM) ++denied;
        else ++missing;
    }
    if (v.empty()) {
        if (denied) return {skipped(id, name, desc, Severity::Medium, "serial/uuid files need root (mode 0400)")};
        return {skipped(id, name, desc, Severity::Medium, "no DMI serial/uuid files")};
    }
    Evidence e;
    for (const auto& kv : v) {
        ++e.observed;
        std::string l = lower(kv.second);
        if (l.rfind("vmware-", 0) == 0) e.add(kv.first + ": VMware-pattern serial");
        if (l.rfind("virtualbox-", 0) == 0) e.add(kv.first + ": VirtualBox-pattern serial");
        if (l.rfind("qm0", 0) == 0) e.add(kv.first + ": QEMU-pattern serial");
        if (placeholder_serial(kv.second)) e.add(kv.first + ": placeholder '" + kv.second + "'");
        if (kv.first == "product_uuid") {
            // AWS: "If the UUID starts with ec2 it is an EC2 instance" (identify_ec2_instances).
            if (l.rfind("ec2", 0) == 0) e.add("product_uuid: EC2 prefix");
            if (l == "00000000-0000-0000-0000-000000000000" || l == "ffffffff-ffff-ffff-ffff-ffffffffffff")
                e.add("product_uuid: all-zero/all-one");
        }
    }
    // Xen hvmloader smbios_type_1_init: serial defaults to the domain UUID string.
    if (v.count("product_serial") && v.count("product_uuid") && !v["product_uuid"].empty() &&
        lower(v["product_serial"]) == lower(v["product_uuid"]))
        e.add("product_serial equals product_uuid (Xen hvmloader default)");
    e.partial = denied > 0;
    auto f = e.finding(id, name, desc, Severity::Medium,
                       "Set realistic, vendor-formatted serials and a random UUID (Xen: xenstore "
                       "bios-strings/system-serial-number or a host-derived SMBIOS table).",
                       0.7);
    if (f.status == Status::Skipped && !e.hits.size() && denied)
        f.error_detail = "some serial files need root; readable ones show no pattern";
    return {f};
}

// Walk raw SMBIOS structures: formatted area then the string set ending in two NULs.
struct Smbios {
    uint8_t type;
    std::string formatted;
    std::vector<std::string> strings;
};
std::vector<Smbios> parse_smbios(const std::string& t) {
    std::vector<Smbios> out;
    size_t p = 0;
    while (p + 4 <= t.size()) {
        uint8_t type = static_cast<uint8_t>(t[p]), len = static_cast<uint8_t>(t[p + 1]);
        if (len < 4 || p + len > t.size()) break;
        Smbios s{type, t.substr(p, len), {}};
        size_t q = p + len;
        while (q < t.size()) {
            size_t end = t.find('\0', q);
            if (end == std::string::npos) { q = t.size(); break; }
            if (end == q) { ++q; break; }
            s.strings.push_back(t.substr(q, end - q));
            q = end + 1;
        }
        if (s.strings.empty() && q < t.size() && t[q] == '\0') ++q;
        out.push_back(s);
        if (type == 127) break;  // end-of-table
        p = q;
    }
    return out;
}

std::vector<Finding> smbios_raw(Context& ctx) {
    const char* id = "env.smbios_raw_strings";
    const char* name = "Raw SMBIOS table strings";
    const char* desc = "Every string of every SMBIOS structure in /sys/firmware/dmi/tables/DMI (what dmidecode "
                       "prints; VMAware DMIDECODE), searched for hypervisor names.";
    Root root(ctx);
    auto r = root.read("/sys/firmware/dmi/tables/DMI", kTableLimit);
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/sys/firmware/dmi/tables/DMI")};
    auto structs = parse_smbios(r.value);
    if (structs.empty()) return {error(id, name, desc, Severity::High, "no SMBIOS structures parsed")};
    Evidence e;
    e.observed = structs.size();
    e.partial = r.truncated;
    for (const auto& s : structs)
        for (const auto& str : s.strings) {
            std::string hit = match(str, dmi_vm_strings());
            if (!hit.empty()) e.add("type " + std::to_string(s.type) + ": " + str.substr(0, 60));
        }
    Finding f = e.finding(id, name, desc, Severity::High,
                          "Use host-derived SMBIOS tables for every structure type, not only types 0-3.");
    return {f};
}

std::vector<Finding> smbios_vm_bit(Context& ctx) {
    const char* id = "env.smbios_vm_bit";
    const char* name = "SMBIOS 'virtual machine' BIOS characteristic";
    const char* desc = "SMBIOS type 0 extension byte 2 bit 4 says the system is a VM (systemd detect_vm_smbios, "
                       "VMAware SMBIOS_VM_BIT).";
    Root root(ctx);
    auto r = root.read("/sys/firmware/dmi/entries/0-0/raw");
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/sys/firmware/dmi/entries/0-0/raw")};
    if (r.value.size() <= kSmbiosExt2Offset || static_cast<uint8_t>(r.value[1]) <= kSmbiosExt2Offset)
        return {skipped(id, name, desc, Severity::High, "type 0 structure has no extension byte 2")};
    uint8_t b = static_cast<uint8_t>(r.value[kSmbiosExt2Offset]);
    char ev[48];
    std::snprintf(ev, sizeof ev, "ext_byte2=0x%02x", b);
    return {bool_check(id, name, desc, Severity::High, (b & kSmbiosVmBit) != 0, ev,
                       "Clear bit 4 of BIOS characteristics extension byte 2 in the SMBIOS type 0 table.")};
}

std::vector<Finding> bios_signature(Context& ctx) {
    const char* id = "env.bios_signature";
    const char* name = "BIOS vendor, version and date";
    const char* desc = "bios_vendor/bios_version/bios_date typical of SeaBIOS, OVMF, Xen hvmloader or the "
                       "VirtualBox BIOS.";
    Root root(ctx);
    bool okv, okr, okd;
    std::string vendor = read_value(root, std::string(kDmi) + "bios_vendor", okv);
    std::string version = read_value(root, std::string(kDmi) + "bios_version", okr);
    std::string date = read_value(root, std::string(kDmi) + "bios_date", okd);
    if (!okv && !okr && !okd) return {skipped(id, name, desc, Severity::Medium, "no DMI BIOS fields")};
    std::vector<std::string> hits;
    std::string lv = lower(vendor), lr = lower(version);
    if (lv == "seabios" || lr.find("seabios") != std::string::npos) hits.push_back("SeaBIOS vendor");
    if (lr.rfind("rel-1.", 0) == 0 || lr.find("qemu.org") != std::string::npos) hits.push_back("SeaBIOS build tag");
    if (lv == "xen") hits.push_back("Xen hvmloader BIOS vendor");
    if (lv.find("innotek") != std::string::npos || lr == "virtualbox") hits.push_back("VirtualBox BIOS");
    if (lv == "edk ii" || lr.find("edk ii") != std::string::npos || lv.find("ovmf") != std::string::npos)
        hits.push_back("EDK II/OVMF reference firmware");
    if (lv.find("bochs") != std::string::npos) hits.push_back("Bochs BIOS");
    // SeaBIOS src/fw/biostables.c: #define BIOS_DATE "04/01/2014" (used by QEMU's SeaBIOS builds).
    if (date == "04/01/2014") hits.push_back("SeaBIOS default date 04/01/2014");
    // VirtualBox DevFwCommon.cpp: g_pszDefDmiBIOSReleaseDate = "12/01/2006".
    if (date == "12/01/2006") hits.push_back("VirtualBox default date 12/01/2006");
    Json ev = Json::object();
    ev.set("vendor", vendor.substr(0, 60));
    ev.set("version", version.substr(0, 60));
    ev.set("date", date.substr(0, 20));
    ev.set("matches", Json(hits));
    return {bool_check(id, name, desc, Severity::High, !hits.empty(), ev,
                       "Present the host's BIOS vendor/version/date in SMBIOS type 0.")};
}

std::vector<Finding> acpi_table_names(Context& ctx) {
    const char* id = "env.acpi_table_names";
    const char* name = "ACPI table set";
    const char* desc = "Names in /sys/firmware/acpi/tables (readable without root): WAET (Windows ACPI Emulated "
                       "devices Table, a VMAware FIRMWARE target) is written by hypervisors, not by PC firmware.";
    Root root(ctx);
    auto l = root.list("/sys/firmware/acpi/tables");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/firmware/acpi/tables")};
    std::vector<std::string> tables, hits;
    for (const auto& n : l.names) {
        auto st = root.stat("/sys/firmware/acpi/tables/" + n, false);
        if (st.ok && S_ISREG(st.st.st_mode)) tables.push_back(n);
        if (n == "WAET") hits.push_back("WAET");
    }
    Json ev = Json::object();
    ev.set("tables", Json(tables));
    ev.set("count", static_cast<long long>(tables.size()));
    ev.set("matches", Json(hits));
    return {bool_check(id, name, desc, Severity::Medium, !hits.empty(), ev,
                       "Drop emulator-only ACPI tables (WAET) or pass through the host's table set.")};
}

std::vector<Finding> acpi_table_oem(Context& ctx) {
    const char* id = "env.acpi_table_oem";
    const char* name = "ACPI table OEM ids and AML strings";
    const char* desc = "OEM id, OEM table id and creator id of every ACPI table, plus QEMU-only AML strings "
                       "(VMAware FIRMWARE targets). Table files are mode 0400.";
    // VMAware v2.8.2 firmware() targets, plus the QEMU AML resource strings it searches for.
    static const std::vector<std::string> sigs = {"Parallels Software", "Parallels(R)", "innotek", "VirtualBox",
        "VBOX", "VMware", "VMWARE", "VMW0003", "QEMU", "pc-q35", "Q35 +", "FWCF", "BOCHS", "BXPC", "Xen",
        "S3 Corp.", "VS2005R2", "SMI resources", "SMI interface", "CPU Hotplug resources", "PCI Hotplug resources"};
    Root root(ctx);
    auto l = root.list("/sys/firmware/acpi/tables");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/firmware/acpi/tables")};
    Evidence e;
    int denied = 0;
    for (const auto& n : l.names) {
        std::string path = "/sys/firmware/acpi/tables/" + n;
        auto st = root.stat(path, false);
        if (!st.ok || !S_ISREG(st.st.st_mode)) continue;
        auto r = root.read(path, kTableLimit);
        if (!r.ok) { if (r.err == EACCES || r.err == EPERM) ++denied; else ++e.unavailable; continue; }
        ++e.observed;
        e.partial |= r.truncated;
        if (r.value.size() >= kAcpiHeader) {
            std::string oem = trim(r.value.substr(10, 6)), table = trim(r.value.substr(16, 8)),
                        creator = trim(r.value.substr(28, 4));
            for (const auto& s : sigs)
                if (oem.find(s) != std::string::npos || table.find(s) != std::string::npos ||
                    creator.find(s) != std::string::npos)
                    e.add(n + ": oem=" + oem + " table=" + table + " creator=" + creator);
        }
        for (const auto& s : sigs)
            if (r.value.find(s) != std::string::npos) { e.add(n + ": contains '" + s + "'"); break; }
    }
    if (!e.observed && denied) return {skipped(id, name, desc, Severity::High, "ACPI table files need root")};
    return {e.finding(id, name, desc, Severity::High,
                      "Present host-derived ACPI tables (Xen: hvmloader acpi_firmware / firmware_override) and "
                      "patch OEM ids in generated tables.")};
}

std::vector<Finding> acpi_device_ids(Context& ctx) {
    const char* id = "env.acpi_device_ids";
    const char* name = "Hypervisor ACPI device ids";
    const char* desc = "ACPI namespace devices in /sys/bus/acpi/devices: QEMU fw_cfg (QEMU0002), VM generation "
                       "id (QEMUVGID), Hyper-V VMBus (VMBUS, MSFT1000), VMware (VMW*) or VirtualBox (VBOX*).";
    static const std::vector<std::string> prefixes = {"QEMU", "VMBUS", "MSFT1000", "VMW", "VBOX", "BOCHS", "XEN"};
    Root root(ctx);
    auto l = root.list("/sys/bus/acpi/devices");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/bus/acpi/devices")};
    Evidence e;
    e.observed = l.names.size();
    e.partial = l.truncated;
    for (const auto& n : l.names)
        for (const auto& p : prefixes)
            if (n.rfind(p, 0) == 0) e.add(n);
    auto f = e.finding(id, name, desc, Severity::High,
                       "Remove paravirtual ACPI devices from the DSDT/SSDT presented to the guest.");
    return {f};
}

std::vector<Finding> legacy_bios_boot(Context& ctx) {
    const char* id = "env.legacy_bios_boot";
    const char* name = "Legacy BIOS boot";
    const char* desc = "No /sys/firmware/efi: the system booted through a legacy BIOS (SeaBIOS, ROMBIOS), "
                       "which PCs sold since 2020 no longer ship.";
    Root root(ctx);
    auto fw = root.stat("/sys/firmware");
    if (!fw.ok) return {unreadable(id, name, desc, Severity::Low, fw.err, "/sys/firmware")};
    bool efi = root.exists("/sys/firmware/efi");
    Json ev = Json::object();
    ev.set("efi", efi);
    return {bool_check(id, name, desc, Severity::Low, !efi, ev,
                       "Boot the guest with UEFI firmware (Xen: bios='ovmf' in xl.cfg).")};
}

std::vector<Finding> secure_boot(Context& ctx) {
    const char* id = "env.secure_boot_disabled";
    const char* name = "UEFI Secure Boot disabled";
    const char* desc = "The SecureBoot EFI variable is 0. Consumer PCs ship with Secure Boot on.";
    Root root(ctx);
    if (!root.exists("/sys/firmware/efi")) return {skipped(id, name, desc, Severity::Low, "not booted via UEFI")};
    // UEFI 2.10 section 3.3: SecureBoot, EFI_GLOBAL_VARIABLE GUID; efivarfs prefixes 4 attribute bytes.
    auto r = root.read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "SecureBoot efivar")};
    if (r.value.size() < 5) return {error(id, name, desc, Severity::Low, "short SecureBoot variable")};
    bool on = r.value[4] == 1;
    Json ev = Json::object();
    ev.set("secure_boot", on);
    return {bool_check(id, name, desc, Severity::Low, !on, ev, "Enrol keys and enable Secure Boot in the guest firmware.")};
}

std::vector<Finding> tpm_absent(Context& ctx) {
    const char* id = "env.tpm_absent";
    const char* name = "No TPM";
    const char* desc = "No TPM device in /sys/class/tpm. PCs certified for Windows 11 have TPM 2.0; VMs have none "
                       "unless a vTPM is configured (VMAware TPM is the Windows equivalent).";
    Root root(ctx);
    auto l = root.list("/sys/class/tpm");
    if (!l.ok && l.err != ENOENT) return {unreadable(id, name, desc, Severity::Low, l.err, "/sys/class/tpm")};
    if (!root.exists("/sys/class")) return {skipped(id, name, desc, Severity::Low, "no sysfs")};
    Json ev = Json::object();
    ev.set("devices", Json(l.names));
    return {bool_check(id, name, desc, Severity::Low, l.names.empty(), ev,
                       "Attach a virtual TPM 2.0 (swtpm) to the guest.")};
}

std::vector<Finding> memory_modules(Context& ctx) {
    const char* id = "env.memory_modules";
    const char* name = "SMBIOS memory devices";
    const char* desc = "SMBIOS type 17 memory devices: VMs report none, or modules with a hypervisor or empty "
                       "manufacturer and no part number (al-khaser memorydevice_wmi on Windows).";
    Root root(ctx);
    auto l = root.list("/sys/firmware/dmi/entries");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/firmware/dmi/entries")};
    Evidence e;
    int denied = 0, modules = 0;
    for (const auto& n : l.names) {
        if (n.rfind("17-", 0) != 0) continue;
        auto r = root.read("/sys/firmware/dmi/entries/" + n + "/raw");
        if (!r.ok) { if (r.err == EACCES || r.err == EPERM) ++denied; else ++e.unavailable; continue; }
        ++e.observed;
        auto s = parse_smbios(r.value);
        if (s.empty() || s[0].formatted.size() < 0x1b) continue;
        const std::string& fm = s[0].formatted;
        // DSP0134 7.18: size at 0x0C (word), manufacturer string index at 0x17, part number at 0x1A.
        unsigned size = static_cast<uint8_t>(fm[0x0c]) | (static_cast<uint8_t>(fm[0x0d]) << 8);
        if (size == 0) continue;  // empty slot
        ++modules;
        auto str = [&](size_t off) -> std::string {
            unsigned idx = static_cast<uint8_t>(fm[off]);
            return idx && idx <= s[0].strings.size() ? trim(s[0].strings[idx - 1]) : "";
        };
        std::string man = str(0x17), part = fm.size() > 0x1a ? str(0x1a) : "";
        if (!match(man, dmi_vm_strings()).empty()) e.add(n + ": manufacturer " + man);
        else if (placeholder_serial(man) && placeholder_serial(part)) e.add(n + ": no manufacturer/part number");
    }
    if (!e.observed) {
        if (denied) return {skipped(id, name, desc, Severity::Medium, "type 17 entries need root")};
        return {detected(id, name, desc, Severity::Medium, "no SMBIOS type 17 structures",
                         "Provide SMBIOS type 17 entries copied from the host.")};
    }
    if (!modules) e.add("no populated memory device");
    return {e.finding(id, name, desc, Severity::Medium, "Provide SMBIOS type 17 entries copied from the host.")};
}

std::vector<Finding> device_tree(Context& ctx) {
    const char* id = "env.device_tree_hypervisor";
    const char* name = "Device tree hypervisor node";
    const char* desc = "On device-tree platforms (ARM, POWER, RISC-V): /proc/device-tree/hypervisor/compatible, "
                       "fw-cfg nodes and the 'linux,dummy-virt'/'qemu,pseries' machine (systemd "
                       "detect_vm_device_tree).";
    Root root(ctx);
    auto l = root.list("/proc/device-tree");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/proc/device-tree")};
    Evidence e;
    e.observed = 1;
    bool ok;
    std::string hv = read_value(root, "/proc/device-tree/hypervisor/compatible", ok);
    if (ok) e.add("hypervisor/compatible=" + hv.substr(0, 60));
    for (const auto& n : l.names)
        if (n.find("fw-cfg") != std::string::npos) e.add(n);
    std::string compat = read_value(root, "/proc/device-tree/compatible", ok);
    if (ok && (compat.find("linux,dummy-virt") != std::string::npos ||
               compat.find("qemu,pseries") != std::string::npos))
        e.add("compatible=" + compat.substr(0, 60));
    return {e.finding(id, name, desc, Severity::High, "Use a machine model that mirrors real hardware's device tree.")};
}

}  // namespace

PERDEDOR_REGISTER(dmi_fields, "firmware.smbios_strings", "fast", false, "env.dmi_sys_vendor", "env.dmi_product_name",
                  "env.dmi_product_family", "env.dmi_product_sku", "env.dmi_product_version", "env.dmi_bios_vendor",
                  "env.dmi_bios_version", "env.dmi_board_vendor", "env.dmi_board_name", "env.dmi_chassis_vendor",
                  "env.dmi_chassis_asset_tag", "env.dmi_board_version", "env.dmi_chassis_version",
                  "env.dmi_board_asset_tag");
PERDEDOR_REGISTER(dmi_modalias, "firmware.smbios_strings", "fast", false, "env.dmi_modalias");
PERDEDOR_REGISTER(dmi_chassis_type, "firmware.smbios_strings", "fast", false, "env.dmi_chassis_type");
PERDEDOR_REGISTER(dmi_serials, "firmware.smbios_serials_uuid", "fast", false, "env.dmi_serials_uuid");
PERDEDOR_REGISTER(smbios_raw, "firmware.smbios_raw_table", "fast", false, "env.smbios_raw_strings");
PERDEDOR_REGISTER(smbios_vm_bit, "firmware.bios_metadata", "fast", false, "env.smbios_vm_bit");
PERDEDOR_REGISTER(bios_signature, "firmware.bios_metadata", "fast", false, "env.bios_signature");
PERDEDOR_REGISTER(acpi_table_names, "firmware.acpi_tables", "fast", false, "env.acpi_table_names");
PERDEDOR_REGISTER(acpi_table_oem, "firmware.acpi_tables", "fast", false, "env.acpi_table_oem");
PERDEDOR_REGISTER(acpi_device_ids, "firmware.acpi_tables", "fast", false, "env.acpi_device_ids");
PERDEDOR_REGISTER(legacy_bios_boot, "firmware.boot_mode", "fast", false, "env.legacy_bios_boot");
PERDEDOR_REGISTER(secure_boot, "firmware.boot_mode", "fast", false, "env.secure_boot_disabled");
PERDEDOR_REGISTER(tpm_absent, "firmware.boot_mode", "fast", false, "env.tpm_absent");
PERDEDOR_REGISTER(memory_modules, "hardware.memory_modules", "fast", false, "env.memory_modules");
PERDEDOR_REGISTER(device_tree, "artifacts.hypervisor_interfaces", "fast", false, "env.device_tree_hypervisor");

}  // namespace perdedor
