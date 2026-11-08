#include "system_checks.hpp"
#include <powrprof.h>
#include <winioctl.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <set>
namespace perdedor {
namespace {
using namespace winsys;
// Provider signatures are big-endian four-character constants; ACPI table IDs
// returned by EnumSystemFirmwareTables are little-endian. Do not interchange them.
constexpr DWORD kRsmb = 0x52534d42, kAcpi = 0x41435049, kFirm = 0x4649524d;
std::vector<Finding> smbios_check(const char *id, const char *name, int kind) {
    auto bytes = win::firmware(kRsmb, 0);
    if (!bytes.ok())
        return {fail(id, name, bytes.error)};
    if (bytes.absent)
        return {absent(id, name, "RSMB firmware provider unavailable")};
    auto r = winlogic::smbios(bytes.value);
    if (!r.valid)
        return {fail(id, name, r.error)};
    bool hit = false;
    Ev ev = matched(r.hits, r.types.size());
    Ev types;
    for (auto p : r.types)
        types.set(std::to_string(p.first), p.second);
    ev.set("structure_types", types);
    switch (kind) {
    case 0:
        hit = !r.hits.empty();
        break;
    case 1:
        hit = r.vm_bit;
        ev.set("vm_bit", hit);
        break;
    case 2:
        hit = r.uuid_default;
        ev.set("default_uuid", hit);
        break;
    case 17:
        if (!r.memory_devices)
            return {absent(id, name, "no populated type 17 memory devices")};
        hit = r.memory_without_speed > 0;
        ev.set("populated_devices", r.memory_devices).set("without_speed", r.memory_without_speed);
        break;
    default:
        hit = r.types.count(static_cast<unsigned>(kind)) == 0;
        break;
    }
    return {result(id, name, hit, ev, kind == 0 ? Severity::High : Severity::Low, kind == 0 ? 0.9 : 0.3,
                   "Keep SMBIOS structure contents, device inventory and host-derived identity coherent in "
                   "the firmware image.")};
}
std::vector<Finding> acpi_check(const char *id, const char *name, int kind) {
    auto ids = win::firmware_ids(kAcpi);
    if (!ids.ok())
        return {fail(id, name, ids.error)};
    if (ids.absent)
        return {absent(id, name, "ACPI firmware provider unavailable")};
    std::vector<std::string> hits;
    Json headers = Json::array();
    size_t examined = 0;
    if (kind == 1)
        return {result(id, name, ids.value.size() < winlogic::kMinAcpiTables, counts(ids.value.size()))};
    for (DWORD table : ids.value) {
        auto b = win::firmware(kAcpi, table);
        if (!b.ok() || b.absent)
            return {fail(id, name, b.error.empty() ? "enumerated ACPI table could not be fetched" : b.error)};
        auto t = winlogic::acpi(b.value);
        // FACS has a different header and no checksum; its bytes are not a DESCRIPTION_HEADER.
        if (b.value.size() >= 4 && std::memcmp(b.value.data(), "FACS", 4) == 0)
            continue;
        if (!t.valid)
            return {fail(id, name, t.error)};
        if (kind == 2 && t.signature != "DSDT")
            continue;
        if (kind == 3 && t.signature != "FACP")
            continue;
        ++examined;
        if (!t.hit.empty())
            hits.push_back(t.signature + ": " + t.hit);
        if (headers.size() < 16)
            headers.push(Ev()
                             .set("signature", t.signature)
                             .set("oem", t.oem)
                             .set("table_id", t.table)
                             .set("creator", t.creator));
    }
    if (!examined)
        return {absent(id, name, "selected ACPI table not exposed by firmware API")};
    auto ev = matched(hits, examined);
    ev.set("headers", headers);
    return {result(
        id, name, !hits.empty(), ev, Severity::High, 0.9,
        "Correct OEM IDs, creator IDs and AML strings in the ACPI firmware, including secondary tables.")};
}
std::vector<Finding> legacy_firmware(Context &) {
    const char *id = "env.firm_bios_strings", *name = "Legacy FIRM firmware strings";
    auto ids = win::firmware_ids(kFirm);
    if (!ids.ok())
        return {fail(id, name, ids.error)};
    if (ids.absent)
        return {absent(id, name, "FIRM provider absent (expected on UEFI and many x64 systems)")};
    std::vector<std::string> hits;
    for (auto x : ids.value) {
        auto v = win::firmware(kFirm, x);
        if (!v.ok())
            return {fail(id, name, v.error)};
        auto s = winlogic::match(std::string(v.value.begin(), v.value.end()), winlogic::vendors());
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, ids.value.size()), Severity::High, 0.85)};
}
std::vector<Finding> smbios_vendor(Context &) {
    const char *id = "env.smbios_vendor", *name = "SMBIOS computer and BIOS vendor strings";
    auto cs = win::wmi(L"ROOT\\CIMV2", L"SELECT Manufacturer,Model FROM Win32_ComputerSystem",
                       {L"Manufacturer", L"Model"});
    auto bios = win::wmi(L"ROOT\\CIMV2", L"SELECT Manufacturer,Version,SerialNumber FROM Win32_BIOS",
                         {L"Manufacturer", L"Version", L"SerialNumber"});
    if (!cs.ok() || !bios.ok())
        return {fail(id, name, !cs.ok() ? cs.error : bios.error, Severity::High)};
    if (cs.value.empty() || bios.value.empty())
        return {absent(id, name, "computer or BIOS instance unavailable", Severity::High)};
    std::vector<std::string> hits;
    for (const auto *rows : {&cs.value, &bios.value})
        for (const auto &row : *rows)
            for (const auto &v : row) {
                auto s = winlogic::match(v.second, winlogic::vendors());
                if (!s.empty())
                    hits.push_back(v.first + ": " + s);
            }
    return {result(id, name, !hits.empty(), matched(hits, cs.value.size() + bios.value.size()),
                   Severity::High, 0.75)};
}
std::vector<Finding> pnp(Context &, bool ghosts) {
    const char *id = ghosts ? "env.ghost_devices" : "env.pnp_virtual_devices",
               *name = ghosts ? "Non-present virtual devices" : "PnP virtual device identifiers";
    auto d = win::devices();
    if (!d.ok())
        return {fail(id, name, d.error, Severity::High)};
    std::vector<std::string> hits;
    size_t examined = 0;
    for (const auto &v : d.value) {
        if (ghosts && v.present)
            continue;
        ++examined;
        auto sig = winlogic::match(v.id + " " + v.hardware, winlogic::pci_vendors());
        if (sig.empty())
            sig = winlogic::match(v.name, winlogic::vendors());
        if (!sig.empty())
            hits.push_back(sig);
    }
    return {result(id, name, !hits.empty(), matched(hits, examined), Severity::High, 0.85)};
}
std::vector<Finding> low_core(Context &) {
    SYSTEM_INFO s{};
    GetNativeSystemInfo(&s);
    return {result("env.low_core_count", "Logical processor count",
                   s.dwNumberOfProcessors < winlogic::kMinCpus, counts(s.dwNumberOfProcessors),
                   Severity::Medium)};
}
std::vector<Finding> peb_cores(Context &) {
    const char *id = "env.peb_processor_count", *name = "PEB NumberOfProcessors";
    // PEB offsets for x86/x64 Windows 7+: phnt ntpebteb.h. ReadProcessMemory
    // makes a failed/changed layout an error instead of dereferencing it.
    // https://github.com/winsiderss/phnt/blob/master/ntpebteb.h
    using Query = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto fn = win::proc<Query>(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION p{};
    if (!fn)
        return {absent(id, name, "NtQueryInformationProcess unavailable")};
    auto status = fn(GetCurrentProcess(), ProcessBasicInformation, &p, sizeof p, nullptr);
    if (status < 0)
        return {fail(id, name, "ProcessBasicInformation status " + std::to_string(status))};
#ifdef _WIN64
    constexpr size_t offset = 0xb8;
#else
    constexpr size_t offset = 0x64;
#endif
    ULONG count = 0;
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const BYTE *>(p.PebBaseAddress) + offset,
                           &count, sizeof count, &got) ||
        got != sizeof count)
        return {fail(id, name, win::last_error_message())};
    if (!count)
        return {fail(id, name, "PEB processor count is zero; unsupported layout or invalid value")};
    return {result(id, name, count < winlogic::kMinCpus, counts(count), Severity::Medium)};
}
std::vector<Finding> low_ram(Context &) {
    MEMORYSTATUSEX m{};
    m.dwLength = sizeof m;
    if (!GlobalMemoryStatusEx(&m))
        return {fail("env.low_ram", "Physical RAM", win::last_error_message(), Severity::Medium)};
    return {result("env.low_ram", "Physical RAM", m.ullTotalPhys < winlogic::kMinRam,
                   Ev().set("bytes", m.ullTotalPhys), Severity::Medium)};
}
std::vector<Finding> installed_ram(Context &) {
    ULONGLONG kib = 0;
    if (!GetPhysicallyInstalledSystemMemory(&kib))
        return {fail("env.installed_ram", "Firmware physical memory", win::last_error_message())};
    return {result("env.installed_ram", "Firmware physical memory", kib < winlogic::kMinRam / 1024,
                   Ev().set("kib", kib))};
}
std::vector<Finding> disk_free(Context &) {
    wchar_t path[MAX_PATH];
    UINT n = GetWindowsDirectoryW(path, MAX_PATH);
    if (!n || n >= MAX_PATH)
        return {fail("env.small_disk", "System volume size", win::last_error_message())};
    wchar_t root[MAX_PATH];
    if (!GetVolumePathNameW(path, root, MAX_PATH))
        return {fail("env.small_disk", "System volume size", win::last_error_message())};
    ULARGE_INTEGER total{};
    if (!GetDiskFreeSpaceExW(root, nullptr, &total, nullptr))
        return {fail("env.small_disk", "System volume size", win::last_error_message())};
    return {result("env.small_disk", "System volume size", total.QuadPart < winlogic::kMinDisk,
                   Ev().set("bytes", total.QuadPart), Severity::Medium)};
}
win::Result<std::vector<BYTE>> disk_ioctl(DWORD code, bool access) {
    static volatile LONG stalled = 0;
    return win::bounded<std::vector<BYTE>>(
        [code, access] {
            win::Result<std::vector<BYTE>> r;
            win::Handle h(CreateFileW(L"\\\\.\\PhysicalDrive0", access ? GENERIC_READ : 0,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                      nullptr));
            if (!h) {
                DWORD e = GetLastError();
                r.code = static_cast<long>(e);
                r.error = win::last_error_message(e);
                return r;
            }
            STORAGE_PROPERTY_QUERY q{};
            q.PropertyId = StorageDeviceProperty;
            q.QueryType = PropertyStandardQuery;
            r.value.resize(65536);
            DWORD got = 0;
            BOOL ok = DeviceIoControl(h.get(), code, code == IOCTL_STORAGE_QUERY_PROPERTY ? &q : nullptr,
                                      code == IOCTL_STORAGE_QUERY_PROPERTY ? sizeof q : 0, r.value.data(),
                                      static_cast<DWORD>(r.value.size()), &got, nullptr);
            if (!ok) {
                DWORD e = GetLastError();
                r.code = static_cast<long>(e);
                r.error = win::last_error_message(e);
                return r;
            }
            r.value.resize(got);
            return r;
        },
        winlogic::kIoMs, stalled);
}
std::vector<Finding> disk_ioctl_probe(Context &, bool identity) {
    const char *id = identity ? "env.disk_identity_ioctl" : "env.disk_length_ioctl",
               *name = identity ? "Storage descriptor identity" : "Physical disk length";
    auto b = disk_ioctl(identity ? IOCTL_STORAGE_QUERY_PROPERTY : IOCTL_DISK_GET_LENGTH_INFO, !identity);
    if (!b.ok() && b.code == ERROR_ACCESS_DENIED)
        return {absent(id, name, "raw disk handle requires administrator rights")};
    if (!b.ok() && (b.code == ERROR_NOT_SUPPORTED || b.code == ERROR_INVALID_FUNCTION))
        return {absent(id, name, "storage stack does not implement this IOCTL")};
    if (!b.ok())
        return {fail(id, name, b.error)};
    if (!identity) {
        if (b.value.size() < sizeof(GET_LENGTH_INFORMATION))
            return {fail(id, name, "short disk length response")};
        GET_LENGTH_INFORMATION length{};
        std::memcpy(&length, b.value.data(), sizeof length);
        if (length.Length.QuadPart <= 0)
            return {fail(id, name, "invalid disk length")};
        return {result(id, name, uint64_t(length.Length.QuadPart) < winlogic::kMinDisk,
                       Ev().set("bytes", length.Length.QuadPart))};
    }
    if (b.value.size() < sizeof(STORAGE_DEVICE_DESCRIPTOR))
        return {fail(id, name, "short storage descriptor")};
    STORAGE_DEVICE_DESCRIPTOR d{};
    std::memcpy(&d, b.value.data(), sizeof d);
    std::vector<std::string> hits;
    for (DWORD offset :
         {d.VendorIdOffset, d.ProductIdOffset, d.ProductRevisionOffset, d.SerialNumberOffset}) {
        if (!offset)
            continue;
        if (offset >= b.value.size())
            return {fail(id, name, "storage descriptor string offset out of bounds")};
        auto begin = b.value.begin() + offset, end = std::find(begin, b.value.end(), 0);
        if (end == b.value.end())
            return {fail(id, name, "unterminated storage descriptor string")};
        auto s = winlogic::match(std::string(begin, end), winlogic::vendors());
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, 4), Severity::High, 0.85)};
}
std::vector<Finding> display(Context &, bool count) {
    const char *id = count ? "env.monitor_count" : "env.screen_resolution",
               *name = count ? "Display monitor count" : "Primary screen resolution";
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN),
        n = GetSystemMetrics(SM_CMONITORS);
    if (!w || !h || !n)
        return {absent(id, name, "no interactive display available")};
    // Check Point "Check if the quantity of monitors is small": a single head is normal on
    // laptops, so the monitor count is informational and low-confidence by design.
    auto f = result(id, name,
                    count ? n < 2 : (w < int(winlogic::kMinScreenWidth) || h < int(winlogic::kMinScreenHeight)),
                    Ev().set("width", w).set("height", h).set("monitors", n),
                    count ? Severity::Info : Severity::Low, count ? 0.1 : 0.35);
    return {f};
}
std::vector<Finding> power(Context &, bool thermal) {
    const char *id = thermal ? "env.power_thermal_control" : "env.power_capabilities",
               *name = thermal ? "Power thermal control" : "System sleep capabilities";
    SYSTEM_POWER_CAPABILITIES p{};
    if (!GetPwrCapabilities(&p))
        return {fail(id, name, win::last_error_message())};
    auto ev = Ev()
                  .set("s1", bool(p.SystemS1))
                  .set("s2", bool(p.SystemS2))
                  .set("s3", bool(p.SystemS3))
                  .set("s4", bool(p.SystemS4))
                  .set("thermal_control", bool(p.ThermalControl))
                  .set("battery", bool(p.SystemBatteriesPresent));
    return {result(id, name,
                   thermal ? !p.ThermalControl : (!p.SystemS1 && !p.SystemS2 && !p.SystemS3 && !p.SystemS4),
                   ev)};
}
std::vector<Finding> edid(Context &) {
    const char *id = "env.monitor_edid_registry", *name = "Monitor EDID inventory";
    auto models = win::registry_names(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY");
    if (!models.ok())
        return {fail(id, name, models.error)};
    if (models.absent)
        return {absent(id, name, "no DISPLAY registry inventory")};
    unsigned found = 0, missing = 0, defaults = 0, invalid = 0;
    std::set<std::string> makers;
    for (const auto &m : models.value) {
        auto base = L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\" + m;
        auto instances = win::registry_names(HKEY_LOCAL_MACHINE, base);
        if (!instances.ok())
            return {fail(id, name, instances.error)};
        for (const auto &i : instances.value) {
            DWORD type = 0;
            auto v = win::registry_value(HKEY_LOCAL_MACHINE, base + L"\\" + i + L"\\Device Parameters",
                                         L"EDID", type);
            if (!v.ok())
                return {fail(id, name, v.error)};
            if (v.absent) {
                ++missing;
                continue;
            }
            auto parsed = winlogic::edid(v.value);
            if (!parsed.valid) {
                ++invalid; // a corrupt EDID is itself a display-emulation tell, not a probe failure
                continue;
            }
            ++found;
            defaults += parsed.serial_missing;
            makers.insert(parsed.manufacturer);
        }
    }
    if (!found && !missing && !invalid)
        return {absent(id, name, "no monitor instances")};
    Json a = Json::array();
    for (const auto &m : makers)
        a.push(m);
    bool virtual_maker = false;
    for (const auto &m : makers)
        virtual_maker |= !winlogic::match(m, winlogic::monitor_vendors(), true).empty();
    return {result(id, name, missing > 0 || defaults > 0 || invalid > 0 || virtual_maker,
                   Ev()
                       .set("edids", found)
                       .set("invalid", invalid)
                       .set("missing", missing)
                       .set("zero_serials", defaults)
                       .set("manufacturers", a))};
}
std::vector<Finding> boot_mode(Context &) {
    const char *id = "env.firmware_boot_mode", *name = "Firmware boot mode";
    using Fn = BOOL(WINAPI *)(DWORD *);
    auto fn = win::proc<Fn>(GetModuleHandleW(L"kernel32.dll"), "GetFirmwareType");
    if (!fn)
        return {absent(id, name, "GetFirmwareType requires Windows 8 or later")};
    DWORD type = 0;
    if (!fn(&type))
        return {fail(id, name, win::last_error_message())};
    return {result(id, name, type == 1, Ev().set("firmware_type", type))};
}
std::vector<Finding> secure_boot(Context &) {
    const char *id = "env.secure_boot", *name = "Secure Boot configuration";
    auto v =
        win::registry_number(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                             L"UEFISecureBootEnabled");
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {absent(id, name, "Secure Boot state not exposed")};
    return {result(id, name, v.value == 0, Ev().set("enabled", v.value != 0))};
}
std::vector<Finding> native_vhd(Context &) {
    const char *id = "env.native_vhd_boot", *name = "Native VHD boot";
    using Fn = BOOL(WINAPI *)(BOOL *);
    auto fn = win::proc<Fn>(GetModuleHandleW(L"kernel32.dll"), "IsNativeVhdBoot");
    if (!fn)
        return {absent(id, name, "IsNativeVhdBoot unavailable")};
    BOOL value = FALSE;
    if (!fn(&value))
        return {fail(id, name, win::last_error_message())};
    return {result(id, name, value != FALSE, Ev().set("vhd", bool(value)))};
}

std::vector<Finding> inv_smbios_firmware_table_raw(Context &ctx) {
    return smbios_check("env.smbios_firmware_table_raw", "Smbios firmware table raw", 0);
}

std::vector<Finding> inv_smbios_vm_bit(Context &ctx) {
    return smbios_check("env.smbios_vm_bit", "Smbios vm bit", 1);
}

std::vector<Finding> inv_smbios_raw_uuid(Context &ctx) {
    return smbios_check("env.smbios_raw_uuid", "Smbios raw uuid", 2);
}

std::vector<Finding> inv_smbios_memory_speed(Context &ctx) {
    return smbios_check("env.smbios_memory_speed", "Smbios memory speed", 17);
}

std::vector<Finding> inv_smbios_slots(Context &ctx) {
    return smbios_check("env.smbios_slots", "Smbios slots", 9);
}

std::vector<Finding> inv_smbios_cooling(Context &ctx) {
    return smbios_check("env.smbios_cooling", "Smbios cooling", 27);
}

std::vector<Finding> inv_smbios_temperature(Context &ctx) {
    return smbios_check("env.smbios_temperature", "Smbios temperature", 28);
}

std::vector<Finding> inv_acpi_oem_strings(Context &ctx) {
    return acpi_check("env.acpi_oem_strings", "Acpi oem strings", 0);
}

std::vector<Finding> inv_acpi_table_count(Context &ctx) {
    return acpi_check("env.acpi_table_count", "Acpi table count", 1);
}

std::vector<Finding> inv_acpi_dsdt_strings(Context &ctx) {
    return acpi_check("env.acpi_dsdt_strings", "Acpi dsdt strings", 2);
}

std::vector<Finding> inv_acpi_fadt_strings(Context &ctx) {
    return acpi_check("env.acpi_fadt_strings", "Acpi fadt strings", 3);
}

std::vector<Finding> pnp_all(Context &ctx) { return pnp(ctx, false); }

std::vector<Finding> pnp_ghost(Context &ctx) { return pnp(ctx, true); }

std::vector<Finding> io_identity(Context &ctx) { return disk_ioctl_probe(ctx, true); }

std::vector<Finding> io_length(Context &ctx) { return disk_ioctl_probe(ctx, false); }

std::vector<Finding> inv_screen(Context &ctx) { return display(ctx, false); }

std::vector<Finding> inv_monitors(Context &ctx) { return display(ctx, true); }

std::vector<Finding> inv_power(Context &ctx) { return power(ctx, false); }

std::vector<Finding> inv_thermal(Context &ctx) { return power(ctx, true); }
} // namespace
PERDEDOR_REGISTER(inv_smbios_firmware_table_raw, "firmware.smbios_raw_table", "fast", false,
                  "env.smbios_firmware_table_raw");
PERDEDOR_REGISTER(inv_smbios_vm_bit, "firmware.smbios_raw_table", "fast", false, "env.smbios_vm_bit");
PERDEDOR_REGISTER(inv_smbios_raw_uuid, "firmware.smbios_serials_uuid", "fast", false, "env.smbios_raw_uuid");
PERDEDOR_REGISTER(inv_smbios_memory_speed, "hardware.memory_modules", "fast", false,
                  "env.smbios_memory_speed");
PERDEDOR_REGISTER(inv_smbios_slots, "hardware.port_connectors", "fast", false, "env.smbios_slots");
PERDEDOR_REGISTER(inv_smbios_cooling, "hardware.thermal_sensors", "fast", false, "env.smbios_cooling");
PERDEDOR_REGISTER(inv_smbios_temperature, "hardware.thermal_sensors", "fast", false,
                  "env.smbios_temperature");
PERDEDOR_REGISTER(inv_acpi_oem_strings, "firmware.acpi_tables", "fast", false, "env.acpi_oem_strings");
PERDEDOR_REGISTER(inv_acpi_table_count, "firmware.acpi_tables", "fast", false, "env.acpi_table_count");
PERDEDOR_REGISTER(inv_acpi_dsdt_strings, "firmware.acpi_tables", "fast", false, "env.acpi_dsdt_strings");
PERDEDOR_REGISTER(inv_acpi_fadt_strings, "firmware.acpi_tables", "fast", false, "env.acpi_fadt_strings");
PERDEDOR_REGISTER(legacy_firmware, "firmware.bios_metadata", "fast", false, "env.firm_bios_strings");
PERDEDOR_REGISTER(smbios_vendor, "firmware.smbios_strings", "medium", false, "env.smbios_vendor");
PERDEDOR_REGISTER(low_core, "resources.cpu_count", "fast", false, "env.low_core_count");
PERDEDOR_REGISTER(peb_cores, "resources.cpu_count", "fast", false, "env.peb_processor_count");
PERDEDOR_REGISTER(low_ram, "resources.memory_size", "fast", false, "env.low_ram");
PERDEDOR_REGISTER(installed_ram, "resources.memory_size", "fast", false, "env.installed_ram");
PERDEDOR_REGISTER(disk_free, "resources.disk_size", "fast", false, "env.small_disk");
PERDEDOR_REGISTER(edid, "hardware.monitor_edid", "medium", false, "env.monitor_edid_registry");
PERDEDOR_REGISTER(boot_mode, "firmware.boot_mode", "fast", false, "env.firmware_boot_mode");
PERDEDOR_REGISTER(secure_boot, "firmware.boot_mode", "fast", false, "env.secure_boot");
PERDEDOR_REGISTER(native_vhd, "container.virtualisation_report", "fast", false, "env.native_vhd_boot");
PERDEDOR_REGISTER(pnp_all, "hardware.pci_vendor_ids", "medium", false, "env.pnp_virtual_devices");
PERDEDOR_REGISTER(pnp_ghost, "hardware.ghost_devices", "medium", false, "env.ghost_devices");
PERDEDOR_REGISTER(io_identity, "hardware.disk_identity", "medium", false, "env.disk_identity_ioctl");
PERDEDOR_REGISTER(io_length, "resources.disk_size", "medium", false, "env.disk_length_ioctl");
PERDEDOR_REGISTER(inv_screen, "resources.screen", "fast", false, "env.screen_resolution");
PERDEDOR_REGISTER(inv_monitors, "resources.screen", "fast", false, "env.monitor_count");
PERDEDOR_REGISTER(inv_power, "hardware.battery_power", "fast", false, "env.power_capabilities");
PERDEDOR_REGISTER(inv_thermal, "hardware.battery_power", "fast", false, "env.power_thermal_control");
} // namespace perdedor
