// Windows system checks that complete the InviZzzible, al-khaser, VMAware and Check Point
// Evasions coverage: vendor-specific firmware scans, disk/display identities, sandbox
// product IDs, named objects, Sandboxie registry virtualisation and UI heuristics.
#include "system_checks.hpp"
#include <winternl.h>
#include <winioctl.h>
#include <algorithm>
#include <cstring>
namespace perdedor {
namespace {
using namespace winsys;
constexpr DWORD kRsmb = 0x52534d42, kFirm = 0x4649524d, kAcpi = 0x41435049;
// Highest \\.\PhysicalDriveN probed for storage descriptors (bounded enumeration).
constexpr unsigned kMaxPhysicalDrives = 16;

// ---- firmware: vendor strings in the raw FIRM / RSMB tables (InviZzzible "firmware" type)
std::vector<Finding> firmware_tokens(const char *id, const char *name, DWORD provider,
                                     const std::vector<std::string> &tokens) {
    std::vector<std::string> blobs;
    if (provider == kFirm) {
        auto ids = win::firmware_ids(kFirm);
        if (!ids.ok())
            return {fail(id, name, ids.error)};
        if (ids.absent || ids.value.empty())
            return {absent(id, name, "FIRM provider absent (expected on UEFI and most x64 systems)")};
        for (auto t : ids.value) {
            auto v = win::firmware(kFirm, t);
            if (!v.ok())
                return {fail(id, name, v.error)};
            blobs.emplace_back(v.value.begin(), v.value.end());
        }
    } else {
        auto v = win::firmware(kRsmb, 0);
        if (!v.ok())
            return {fail(id, name, v.error)};
        if (v.absent)
            return {absent(id, name, "RSMB firmware provider unavailable")};
        blobs.emplace_back(v.value.begin(), v.value.end());
    }
    std::vector<std::string> hits;
    for (const auto &b : blobs) {
        auto s = winlogic::match(b, tokens);
        if (!s.empty() && std::find(hits.begin(), hits.end(), s) == hits.end())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, blobs.size()), Severity::High, 0.9,
                   "Replace the hypervisor's default firmware strings with host-derived identity.")};
}
std::vector<Finding> vbox_firm(Context &) {
    return firmware_tokens("env.vbox_firmwareraw_table", "vbox: FirmwareRaw Table", kFirm,
                           {"VirtualBox", "Oracle", "innotek"});
}
std::vector<Finding> vbox_rsmb(Context &) {
    return firmware_tokens("env.vbox_firmwaresmbios_table", "vbox: FirmwareSMBIOS Table", kRsmb,
                           {"VirtualBox", "Oracle", "innotek"});
}
std::vector<Finding> vmware_firm(Context &) {
    return firmware_tokens("env.vmware_firmwareraw_table", "vmware: FirmwareRaw Table", kFirm, {"VMware"});
}
std::vector<Finding> vmware_rsmb(Context &) {
    return firmware_tokens("env.vmware_firmwaresmbios_table", "vmware: FirmwareSMBIOS Table", kRsmb, {"VMware"});
}
std::vector<Finding> parallels_firm(Context &) {
    return firmware_tokens("env.parallels_firmwareraw_table", "parallels: FirmwareRaw Table", kFirm,
                           {"Parallels(R)"});
}
std::vector<Finding> parallels_rsmb(Context &) {
    return firmware_tokens("env.parallels_firmwaresmbios_table", "parallels: FirmwareSMBIOS Table", kRsmb,
                           {"Parallels Software International"});
}
std::vector<Finding> virtualpc_firm(Context &) {
    return firmware_tokens("env.virtualpc_firmwareraw_table", "virtualpc: FirmwareRaw Table", kFirm,
                           {"S3 Corp."});
}
std::vector<Finding> virtualpc_rsmb(Context &) {
    return firmware_tokens("env.virtualpc_firmwaresmbios_table", "virtualpc: FirmwareSMBIOS Table", kRsmb,
                           {"VS2005R2"});
}
std::vector<Finding> xen_rsmb(Context &) {
    // Xen hvmloader's SMBIOS defaults (tools/firmware/hvmloader/smbios.c): "Xen", "HVM domU".
    return firmware_tokens("env.xen_firmwaresmbios_table", "xen: FirmwareSMBIOS Table", kRsmb,
                           {"Xen", "HVM domU"});
}
std::vector<Finding> qemu_rsmb(Context &) {
    return firmware_tokens("env.qemu_firmwaresmbios_table", "qemu: FirmwareSMBIOS Table", kRsmb,
                           {"QEMU", "SeaBIOS", "BOCHS", "BXPC"});
}

// ACPI table inventory: WAET (Windows ACPI Emulated Devices Table) is a Microsoft table for
// virtual platforms (spec linked from QEMU hw/i386/acpi-build.c build_waet()); Xen builds it
// in tools/libacpi/build.c construct_waet(). Physical firmware has no reason to publish it.
std::vector<Finding> acpi_waet(Context &) {
    const char *id = "env.acpi_waet_table", *name = "ACPI WAET emulated-devices table";
    auto ids = win::firmware_ids(kAcpi);
    if (!ids.ok())
        return {fail(id, name, ids.error)};
    if (ids.absent)
        return {absent(id, name, "ACPI firmware provider unavailable")};
    bool waet = false;
    Json list = Json::array();
    for (DWORD t : ids.value) {
        char sig[5]{};
        std::memcpy(sig, &t, 4); // table IDs are little-endian signatures
        if (list.size() < 64)
            list.push(std::string(sig));
        waet |= std::memcmp(sig, "WAET", 4) == 0;
    }
    return {result(id, name, waet, Ev().set("tables", list), Severity::High, 0.9,
                   "Do not publish a WAET table on analysis guests.")};
}

// ---- storage identity: STORAGE_DEVICE_DESCRIPTOR on every \\.\PhysicalDriveN
struct Disk {
    unsigned index = 0;
    std::string vendor, product, revision, serial;
};
win::Result<std::vector<Disk>> disks() {
    static volatile LONG outstanding = 0;
    return win::bounded<std::vector<Disk>>(
        [] {
            win::Result<std::vector<Disk>> r;
            for (unsigned i = 0; i < kMaxPhysicalDrives; ++i) {
                auto path = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
                // Zero access: IOCTL_STORAGE_QUERY_PROPERTY needs no read rights.
                win::Handle h(CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                          OPEN_EXISTING, 0, nullptr));
                if (!h)
                    continue;
                STORAGE_PROPERTY_QUERY q{};
                q.PropertyId = StorageDeviceProperty;
                q.QueryType = PropertyStandardQuery;
                std::vector<BYTE> b(4096);
                DWORD got = 0;
                if (!DeviceIoControl(h.get(), IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, b.data(),
                                     static_cast<DWORD>(b.size()), &got, nullptr) ||
                    got < sizeof(STORAGE_DEVICE_DESCRIPTOR))
                    continue;
                b.resize(got);
                STORAGE_DEVICE_DESCRIPTOR d{};
                std::memcpy(&d, b.data(), sizeof d);
                auto text = [&](DWORD offset) {
                    if (!offset || offset >= b.size())
                        return std::string();
                    auto begin = b.begin() + offset, end = std::find(begin, b.end(), 0);
                    return winlogic::trim(std::string(begin, end));
                };
                r.value.push_back({i, text(d.VendorIdOffset), text(d.ProductIdOffset),
                                   text(d.ProductRevisionOffset), text(d.SerialNumberOffset)});
            }
            return r;
        },
        winlogic::kWmiMs, outstanding);
}
std::vector<Finding> disk_name(const char *id, const char *name, const std::vector<std::string> &tokens) {
    auto d = disks();
    if (!d.ok())
        return {fail(id, name, d.error)};
    if (d.value.empty())
        return {absent(id, name, "no physical drive answered IOCTL_STORAGE_QUERY_PROPERTY")};
    std::vector<std::string> hits;
    for (const auto &x : d.value) {
        auto s = winlogic::match(x.vendor + " " + x.product, tokens);
        if (!s.empty())
            hits.push_back("PhysicalDrive" + std::to_string(x.index) + ": " + s);
    }
    return {result(id, name, !hits.empty(), matched(hits, d.value.size()), Severity::High, 0.9,
                   "Give virtual disks a plausible vendor/model (QEMU/Xen: -device ...,model=/vendor=; "
                   "VirtualBox: VBoxManage setextradata ...ModelNumber).")};
}
std::vector<Finding> qemu_disk(Context &) {
    return disk_name("env.qemu_qemu_disk_name", "qemu: QEMU Disk Name", {"QEMU"});
}
std::vector<Finding> vbox_disk(Context &) {
    return disk_name("env.vbox_vbox_disk_name", "vbox: VBox Disk Name", {"VBOX"});
}
std::vector<Finding> vmware_disk(Context &) {
    return disk_name("env.vmware_vmware_disk_name", "vmware: VMware Disk Name", {"VMware"});
}
std::vector<Finding> virtualpc_disk(Context &) {
    return disk_name("env.virtualpc_virtualpc_disk_name", "virtualpc: VirtualPC Disk Name", {"VIRTUAL HD"});
}
std::vector<Finding> xen_disk(Context &) {
    // Xen PV storage drivers report vendor "XENSRC"/product "PVDISK" (to be confirmed per driver
    // release, docs/notes/windows.md); QEMU-emulated IDE under Xen reports "QEMU HARDDISK".
    return disk_name("env.xen_xen_disk_name", "xen: Xen Disk Name", {"XENSRC", "PVDISK", "Xen"});
}
std::vector<Finding> drive_model(const char *id, const char *name, const char *token) {
    auto rows = win::wmi(L"ROOT\\CIMV2", L"SELECT Model FROM Win32_DiskDrive", {L"Model"});
    if (!rows.ok())
        return {fail(id, name, rows.error)};
    if (rows.absent || rows.value.empty())
        return {absent(id, name, "no Win32_DiskDrive instances")};
    std::vector<std::string> hits;
    for (const auto &row : rows.value)
        if (winlogic::contains(win::field(row, "Model"), token))
            hits.push_back(token);
    return {result(id, name, !hits.empty(), matched(hits, rows.value.size()), Severity::High, 0.9)};
}
std::vector<Finding> vbox_model(Context &) {
    return drive_model("env.vbox_vbox_drive_model", "vbox: VBox Drive Model", "VBox");
}
std::vector<Finding> vmware_model(Context &) {
    return drive_model("env.vmware_vmware_drive_model", "vmware: VMware Drive Model", "VMware");
}

// ---- display adapters (EnumDisplayDevices + the adapter's driver key)
struct Adapter {
    std::string description, device_id, drivers;
};
win::Result<std::vector<Adapter>> display_adapters() {
    win::Result<std::vector<Adapter>> r;
    for (DWORD i = 0; i < 64; ++i) {
        DISPLAY_DEVICEW d{};
        d.cb = sizeof d;
        if (!EnumDisplayDevicesW(nullptr, i, &d, 0))
            break;
        Adapter a{win::narrow(d.DeviceString), win::narrow(d.DeviceID), {}};
        // DeviceKey is \Registry\Machine\System\CurrentControlSet\Control\Video\{GUID}\NNNN.
        std::wstring key = d.DeviceKey;
        const std::wstring prefix = L"\\Registry\\Machine\\";
        if (winlogic::lower(win::narrow(key)).rfind(winlogic::lower(win::narrow(prefix)), 0) == 0) {
            auto v = win::registry_string(HKEY_LOCAL_MACHINE, key.substr(prefix.size()), L"InstalledDisplayDrivers");
            if (v.ok() && !v.absent)
                a.drivers = v.value;
        }
        if (std::find_if(r.value.begin(), r.value.end(), [&](const Adapter &x) {
                return x.device_id == a.device_id && x.description == a.description;
            }) == r.value.end())
            r.value.push_back(a);
    }
    return r;
}
std::vector<Finding> display_check(const char *id, const char *name, int field,
                                   const std::vector<std::string> &tokens) {
    auto v = display_adapters();
    if (v.value.empty())
        return {absent(id, name, "no display adapters enumerated")};
    std::vector<std::string> hits;
    for (const auto &a : v.value) {
        const std::string &text = field == 0 ? a.description : field == 1 ? a.device_id : a.drivers;
        auto s = winlogic::match(text, tokens);
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, v.value.size()), Severity::High, 0.85,
                   "Expose a display adapter with a physical vendor/device identity or pass through a GPU.")};
}
std::vector<Finding> vmw_display_vendor(Context &) {
    return display_check("env.vmware_vmware_physical_display_adapter_vendorid",
                         "vmware: VMware Physical Display Adapter VendorId", 1, {"VEN_15AD"});
}
std::vector<Finding> vmw_display_device(Context &) {
    return display_check("env.vmware_vmware_physical_display_adapter_deviceid",
                         "vmware: VMware Physical Display Adapter DeviceId", 1, {"VEN_15AD&DEV_0405"});
}
std::vector<Finding> vmw_display_driver(Context &) {
    return display_check("env.vmware_vmware_physical_display_adapter_driver",
                         "vmware: VMware Physical Display Adapter Driver", 2,
                         {"vm3dum.dll", "vm3dum64_loader.dll", "vm3dum"});
}
std::vector<Finding> vmw_display_description(Context &) {
    return display_check("env.vmware_vmware_physical_display_adapter_description",
                         "vmware: VMware Physical Display Adapter Description", 0, {"VMware SVGA 3D"});
}
std::vector<Finding> display_pci(Context &) {
    // Bochs/QEMU stdvga 1234:1111 (also Xen's emulated VGA), QXL/virtio-gpu, VirtualBox, VMware,
    // Hyper-V synthetic video and Cirrus 5446 as emulated by QEMU. PCI vendor IDs: pcisig/pci.ids.
    return display_check("env.display_adapter_pci_ids", "Virtual display adapter PCI identity", 1,
                         {"VEN_1234&DEV_1111", "VEN_1B36", "VEN_1AF4", "VEN_80EE", "VEN_15AD", "VEN_1414",
                          "VEN_1013&DEV_00B8", "VMBUS"});
}

// ---- registry: sandbox Windows product IDs (VMAware GAMARUE, InviZzzible joebox)
std::vector<Finding> product_ids(Context &) {
    const char *id = "env.sandbox_product_ids", *name = "Known sandbox Windows product IDs";
    // JoeBox, CWSandbox and Anubis images (VMAware gamarue()).
    const std::vector<std::string> known = {"55274-640-2673064-23950", "76487-644-3177037-23510",
                                            "76487-337-8429955-22614"};
    std::vector<std::string> hits;
    unsigned read = 0;
    for (const wchar_t *key : {L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                               L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion"}) {
        auto v = win::registry_string(HKEY_LOCAL_MACHINE, key, L"ProductId");
        if (!v.ok())
            return {fail(id, name, v.error)};
        if (v.absent)
            continue;
        ++read;
        auto s = winlogic::match(v.value, known, true);
        if (!s.empty())
            hits.push_back(s);
    }
    if (!read)
        return {absent(id, name, "ProductId not present")};
    return {result(id, name, !hits.empty(), matched(hits, read), Severity::High, 0.95,
                   "Install the guest from fresh media so it receives a unique product ID.")};
}

// ---- named objects
std::vector<Finding> object_exists(const char *id, const char *name, const char *kind,
                                   const std::vector<std::wstring> &paths, Severity sev = Severity::High) {
    std::vector<std::string> hits;
    for (const auto &p : paths) {
        auto v = win::named_object(p, kind);
        if (!v.ok())
            return {fail(id, name, v.error)};
        if (v.value)
            hits.push_back(win::narrow(p));
    }
    return {result(id, name, !hits.empty(), matched(hits, paths.size()), sev, 0.85)};
}
std::vector<Finding> deepfreeze_mutex(Context &) {
    // Check Point Evasions, "Check for specific global mutexes": DeepFreeze -> Frz_State.
    return object_exists("env.deepfreeze_mutex", "Deep Freeze mutex", "mutex",
                         {L"Frz_State", L"Global\\Frz_State"}, Severity::Medium);
}
std::vector<Finding> npf_device(Context &) {
    // InviZzzible generic DeviceNPF_NDIS: WinPcap's NDIS WAN device.
    return object_exists("env.generic_devicenpf_ndis", "generic: DeviceNPF_NDIS", "device",
                         {L"\\\\.\\NPF_NdisWanIp"}, Severity::Medium);
}
std::vector<Finding> vbox_handles(Context &) {
    // VMAware device_handles() targets (\??\ names are the same objects as \\.\).
    return object_exists("env.vbox_device_handles", "VirtualBox device and pipe handles", "device",
                         {L"\\\\.\\VBoxMiniRdrDN", L"\\\\.\\pipe\\VBoxMiniRdDN", L"\\\\.\\VBoxTrayIPC",
                          L"\\\\.\\pipe\\VBoxTrayIPC"});
}
std::vector<Finding> cuckoo_dir(Context &) {
    const char *id = "env.cuckoo_directory", *name = "Cuckoo analyzer directory";
    // VMAware cuckoo(): \??\C:\Cuckoo.
    auto v = win::file_size(L"C:\\Cuckoo");
    if (!v.ok())
        return {fail(id, name, v.error)};
    return {result(id, name, !v.absent, Ev().set("present", !v.absent), Severity::High, 0.9)};
}

// ---- Sandboxie registry virtualisation (VMAware virtual_registry, Check Point global objects #6)
std::vector<Finding> sandboxie_registry(Context &) {
    const char *id = "env.sandboxie_virtual_registry", *name = "Sandboxie virtualised registry hive";
    using OpenKey = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using QueryObject = NTSTATUS(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto open = win::proc<OpenKey>(ntdll, "NtOpenKey");
    auto query = win::proc<QueryObject>(ntdll, "NtQueryObject");
    if (!open || !query)
        return {absent(id, name, "NtOpenKey/NtQueryObject unavailable")};
    wchar_t text[] = L"\\REGISTRY\\USER";
    UNICODE_STRING us{};
    us.Buffer = text;
    us.Length = sizeof(text) - sizeof(wchar_t);
    us.MaximumLength = sizeof text;
    OBJECT_ATTRIBUTES a{};
    a.Length = sizeof a;
    a.ObjectName = &us;
    a.Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE raw = nullptr;
    NTSTATUS s = open(&raw, KEY_READ, &a);
    if (s < 0)
        return {fail(id, name, "NtOpenKey status " + std::to_string(s))};
    win::Handle key(raw);
    constexpr ULONG kObjectNameInformation = 1;
    std::vector<BYTE> b(4096);
    ULONG got = 0;
    s = query(key.get(), kObjectNameInformation, b.data(), static_cast<ULONG>(b.size()), &got);
    if (s < 0)
        return {fail(id, name, "NtQueryObject status " + std::to_string(s))};
    UNICODE_STRING resolved{};
    std::memcpy(&resolved, b.data(), sizeof resolved);
    auto begin = reinterpret_cast<uintptr_t>(b.data()), ptr = reinterpret_cast<uintptr_t>(resolved.Buffer);
    if (resolved.Length % 2 || ptr < begin || ptr > begin + b.size() || resolved.Length > begin + b.size() - ptr)
        return {fail(id, name, "unexpected object name layout")};
    auto actual = win::narrow(std::wstring(resolved.Buffer, resolved.Length / 2));
    bool redirected = winlogic::lower(actual) != "\\registry\\user";
    return {result(id, name, redirected,
                   Ev().set("redirected", redirected).set("sandbox_path", winlogic::contains(actual, "\\sandbox\\")),
                   Severity::High, 0.95, "Do not run samples inside Sandboxie on an analysis host.")};
}

// ---- identity lists from InviZzzible misc.conf and al-khaser other_known_sandbox_environment_checks
win::Result<std::string> user_name() {
    wchar_t v[257];
    DWORD n = 257;
    if (!GetUserNameW(v, &n))
        return {{}, win::last_error_message()};
    return {win::narrow(v)};
}
win::Result<std::string> computer(COMPUTER_NAME_FORMAT format) {
    wchar_t v[256];
    DWORD n = 256;
    if (!GetComputerNameExW(format, v, &n))
        return {{}, win::last_error_message()};
    return {win::narrow(std::wstring(v, n))};
}
std::vector<Finding> list_match(const char *id, const char *name, const win::Result<std::string> &value,
                                const std::vector<std::string> &names) {
    if (!value.ok())
        return {fail(id, name, value.error)};
    auto s = winlogic::match(value.value, names, true);
    return {result(id, name, !s.empty(), Ev().set("matched", s), Severity::Medium, 0.5)};
}
std::vector<Finding> misc_users(Context &) {
    return list_match("env.misc_sandbox_user_names", "misc: Sandbox User Names", user_name(),
                      {"Wilbert", "admin", "John Doe", "John"});
}
std::vector<Finding> misc_computers(Context &) {
    return list_match("env.misc_sandbox_computer_names", "misc: Sandbox Computer Names",
                      computer(ComputerNameNetBIOS), {"TEQUILABOOMBOOM", "KLONE_X64-PC"});
}
std::vector<Finding> misc_hosts(Context &) {
    return list_match("env.misc_sandbox_host_names", "misc: Sandbox Host Names", computer(ComputerNameDnsHostname),
                      {"SystemIT"});
}
std::vector<Finding> user_host_pairs(Context &) {
    const char *id = "design.known_sandbox_user_host_pairs", *name = "Known sandbox user and host combinations";
    auto u = user_name();
    auto h = computer(ComputerNameNetBIOS);
    if (!u.ok() || !h.ok())
        return {fail(id, name, !u.ok() ? u.error : h.error)};
    auto user = winlogic::lower(u.value), host = winlogic::lower(h.value);
    // al-khaser other_known_sandbox_environment_checks.
    bool wilber = user == "wilber" && (host.rfind("sc", 0) == 0 || host.rfind("sw", 0) == 0);
    bool admin = user == "admin" && host == "systemit";
    return {result(id, name, wilber || admin, Ev().set("wilber_sc_sw", wilber).set("admin_systemit", admin),
                   Severity::High, 0.9)};
}

// ---- own process path (InviZzzible generic "Sandbox-like named file")
std::vector<Finding> sandbox_named_file(Context &) {
    const char *id = "env.generic_sandbox_like_named_file", *name = "generic: Sandbox-like named file";
    std::vector<wchar_t> path(32768);
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!n || n >= path.size())
        return {fail(id, name, "GetModuleFileNameW failed or truncated")};
    auto text = winlogic::lower(win::narrow(std::wstring(path.data(), n)));
    std::string hit = text == "c:\\self.exe" ? "c:\\self.exe" : "";
    if (hit.empty())
        hit = winlogic::match(text, {"self.", "sample", "sandbox", "virus", "malware"});
    return {result(id, name, !hit.empty(), Ev().set("matched", hit), Severity::Medium, 0.6)};
}

// ---- processes
std::vector<Finding> process_names(const char *id, const char *name, const std::vector<std::string> &names,
                                   Severity sev = Severity::Medium) {
    auto p = win::processes();
    if (!p.ok())
        return {fail(id, name, p.error)};
    std::vector<std::string> hits;
    for (const auto &x : p.value) {
        auto s = winlogic::match(x.name, names, true);
        if (!s.empty() && std::find(hits.begin(), hits.end(), s) == hits.end())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, p.value.size()), sev, 0.7)};
}
std::vector<Finding> av_tools(Context &) {
    return process_names("env.generic_av_and_research_tools_processes", "generic: AV and Research tools Processes",
                         {"avgsvc.exe", "avgui.exe", "avastsvc.exe", "avastui.exe", "procmon.exe", "procmon64.exe",
                          "procexp.exe", "procexp64.exe", "ollydbg.exe", "windbg.exe", "avp.exe", "bdagent.exe",
                          "bdwtxag.exe", "dwengine.exe"});
}
std::vector<Finding> looking_glass(Context &) {
    return process_names("env.looking_glass_processes", "Looking Glass / virtual display driver processes",
                         {"looking-glass-host.exe", "VDDSysTray.exe"});
}
std::vector<Finding> qemu_processes(Context &) {
    return process_names("env.qemu_guest_processes", "QEMU guest agent and SPICE processes",
                         {"qemu-ga.exe", "vdagent.exe", "vdservice.exe"}, Severity::High);
}
std::vector<Finding> long_process_name(Context &) {
    const char *id = "env.generic_existence_of_a_process_with_long_name",
               *name = "generic: Existence of a process with long name";
    // InviZzzible: some sandboxes rename the sample to its SHA-256 (64 hex characters).
    constexpr size_t kLongName = 64;
    auto p = win::processes();
    if (!p.ok())
        return {fail(id, name, p.error)};
    unsigned longest = 0, hits = 0;
    for (const auto &x : p.value) {
        auto stem = x.name.substr(0, x.name.find_last_of('.'));
        longest = std::max<unsigned>(longest, static_cast<unsigned>(stem.size()));
        hits += stem.size() >= kLongName;
    }
    return {result(id, name, hits > 0, Ev().set("matching_processes", hits).set("longest", longest),
                   Severity::Low, 0.5)};
}

// ---- UI: total top-level windows (Check Point ui-artifacts #2: fewer than 10)
std::vector<Finding> top_level_windows(Context &ctx) {
    const char *id = "design.top_level_window_count", *name = "Top-level window count";
    constexpr long long kMinTopLevelWindows = 10; // Check Point Evasions UI artifacts sample threshold
    auto v = win::windows();
    if (!v.ok())
        return {fail(id, name, v.error)};
    auto minimum = ctx.param_int("ui.min_top_level_windows", kMinTopLevelWindows);
    return {result(id, name, static_cast<long long>(v.value.size()) < minimum,
                   counts(v.value.size()).set("minimum", minimum))};
}

// ---- Office macro security (Check Point registry #3, VBAWarnings)
std::vector<Finding> vba_warnings(Context &) {
    const char *id = "design.office_vba_warnings", *name = "Office macros enabled without prompt";
    // VBAWarnings 1 = "Enable all macros". Office 2007 (12.0) to Microsoft 365 (16.0).
    std::vector<std::string> hits;
    unsigned seen = 0;
    for (const wchar_t *version : {L"12.0", L"14.0", L"15.0", L"16.0"})
        for (const wchar_t *app : {L"Word", L"Excel", L"PowerPoint"})
            for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
                std::wstring base = root == HKEY_CURRENT_USER ? L"Software\\Microsoft\\Office\\"
                                                              : L"SOFTWARE\\Policies\\Microsoft\\Office\\";
                auto v = win::registry_number(root, base + version + L"\\" + app + L"\\Security", L"VBAWarnings");
                if (!v.ok() || v.absent)
                    continue;
                ++seen;
                if (v.value == 1)
                    hits.push_back(win::narrow(std::wstring(app) + L" " + version));
            }
    if (!seen)
        return {absent(id, name, "no Office VBAWarnings setting configured")};
    return {result(id, name, !hits.empty(), matched(hits, seen), Severity::Low, 0.5)};
}
} // namespace
PERDEDOR_REGISTER(vbox_firm, "firmware.bios_metadata", "fast", false, "env.vbox_firmwareraw_table");
PERDEDOR_REGISTER(vbox_rsmb, "firmware.smbios_raw_table", "fast", false, "env.vbox_firmwaresmbios_table");
PERDEDOR_REGISTER(vmware_firm, "firmware.bios_metadata", "fast", false, "env.vmware_firmwareraw_table");
PERDEDOR_REGISTER(vmware_rsmb, "firmware.smbios_raw_table", "fast", false, "env.vmware_firmwaresmbios_table");
PERDEDOR_REGISTER(parallels_firm, "firmware.bios_metadata", "fast", false, "env.parallels_firmwareraw_table");
PERDEDOR_REGISTER(parallels_rsmb, "firmware.smbios_raw_table", "fast", false, "env.parallels_firmwaresmbios_table");
PERDEDOR_REGISTER(virtualpc_firm, "firmware.bios_metadata", "fast", false, "env.virtualpc_firmwareraw_table");
PERDEDOR_REGISTER(virtualpc_rsmb, "firmware.smbios_raw_table", "fast", false, "env.virtualpc_firmwaresmbios_table");
PERDEDOR_REGISTER(xen_rsmb, "firmware.smbios_raw_table", "fast", false, "env.xen_firmwaresmbios_table");
PERDEDOR_REGISTER(qemu_rsmb, "firmware.smbios_raw_table", "fast", false, "env.qemu_firmwaresmbios_table");
PERDEDOR_REGISTER(acpi_waet, "firmware.acpi_tables", "fast", false, "env.acpi_waet_table");
PERDEDOR_REGISTER(qemu_disk, "hardware.disk_identity", "fast", false, "env.qemu_qemu_disk_name");
PERDEDOR_REGISTER(vbox_disk, "hardware.disk_identity", "fast", false, "env.vbox_vbox_disk_name");
PERDEDOR_REGISTER(vmware_disk, "hardware.disk_identity", "fast", false, "env.vmware_vmware_disk_name");
PERDEDOR_REGISTER(virtualpc_disk, "hardware.disk_identity", "fast", false, "env.virtualpc_virtualpc_disk_name");
PERDEDOR_REGISTER(xen_disk, "hardware.disk_identity", "fast", false, "env.xen_xen_disk_name");
PERDEDOR_REGISTER(vbox_model, "hardware.disk_identity", "medium", false, "env.vbox_vbox_drive_model");
PERDEDOR_REGISTER(vmware_model, "hardware.disk_identity", "medium", false, "env.vmware_vmware_drive_model");
PERDEDOR_REGISTER(vmw_display_vendor, "hardware.gpu_identity", "fast", false,
                  "env.vmware_vmware_physical_display_adapter_vendorid");
PERDEDOR_REGISTER(vmw_display_device, "hardware.gpu_identity", "fast", false,
                  "env.vmware_vmware_physical_display_adapter_deviceid");
PERDEDOR_REGISTER(vmw_display_driver, "hardware.gpu_identity", "fast", false,
                  "env.vmware_vmware_physical_display_adapter_driver");
PERDEDOR_REGISTER(vmw_display_description, "hardware.gpu_identity", "fast", false,
                  "env.vmware_vmware_physical_display_adapter_description");
PERDEDOR_REGISTER(display_pci, "hardware.gpu_identity", "fast", false, "env.display_adapter_pci_ids");
PERDEDOR_REGISTER(product_ids, "artifacts.registry", "fast", false, "env.sandbox_product_ids");
PERDEDOR_REGISTER(deepfreeze_mutex, "container.app_sandbox", "fast", false, "env.deepfreeze_mutex");
PERDEDOR_REGISTER(npf_device, "analysis_tools.drivers_services", "fast", false, "env.generic_devicenpf_ndis");
PERDEDOR_REGISTER(vbox_handles, "artifacts.named_objects", "fast", false, "env.vbox_device_handles");
PERDEDOR_REGISTER(cuckoo_dir, "artifacts.files", "fast", false, "env.cuckoo_directory");
PERDEDOR_REGISTER(sandboxie_registry, "container.app_sandbox", "fast", false, "env.sandboxie_virtual_registry");
PERDEDOR_REGISTER(misc_users, "identity.username", "fast", false, "env.misc_sandbox_user_names");
PERDEDOR_REGISTER(misc_computers, "identity.hostname", "fast", false, "env.misc_sandbox_computer_names");
PERDEDOR_REGISTER(misc_hosts, "identity.hostname", "fast", false, "env.misc_sandbox_host_names");
PERDEDOR_REGISTER(user_host_pairs, "identity.username", "fast", false, "design.known_sandbox_user_host_pairs");
PERDEDOR_REGISTER(sandbox_named_file, "identity.sample_path", "fast", false, "env.generic_sandbox_like_named_file");
PERDEDOR_REGISTER(av_tools, "analysis_tools.processes", "fast", false, "env.generic_av_and_research_tools_processes");
PERDEDOR_REGISTER(looking_glass, "guest_tools.processes", "fast", false, "env.looking_glass_processes");
PERDEDOR_REGISTER(qemu_processes, "guest_tools.processes", "fast", false, "env.qemu_guest_processes");
PERDEDOR_REGISTER(long_process_name, "identity.sample_path", "fast", false,
                  "env.generic_existence_of_a_process_with_long_name");
PERDEDOR_REGISTER(top_level_windows, "human.foreground_activity", "fast", false, "design.top_level_window_count");
PERDEDOR_REGISTER(vba_warnings, "os_config.script_policies", "fast", false, "design.office_vba_warnings");
} // namespace perdedor
