#include "system_checks.hpp"
#include <algorithm>
namespace perdedor {
namespace {
using namespace winsys;
enum class WmiRule {
    Signature,
    Serial,
    Uuid,
    Zero,
    Missing,
    True,
    Small,
    Chassis,
    Date,
    Ascii,
    Activation,
    Age,
    Null,
    Mac
};
std::vector<Finding> wmi_check(Context &ctx, const char *id, const char *name, const wchar_t *space,
                               const wchar_t *query, const std::vector<std::wstring> &props, WmiRule rule,
                               uint64_t limit = 0, DWORD budget_ms = winlogic::kWmiMs) {
    auto rows = win::wmi(space, query, props, budget_ms);
    if (!rows.ok() && win::access_denied(rows.code))
        return {absent(id, name, rows.error)};
    if (!rows.ok())
        return {fail(id, name, rows.error)};
    if (rows.absent) {
        // A sensor/inventory provider that answers "not supported" has nothing to report:
        // the same outcome al-khaser treats as a VM (for example MSAcpi_ThermalZoneTemperature).
        if (rule == WmiRule::Missing && rows.code == win::kWbemNotSupported)
            return {result(id, name, true,
                           Ev().set("instances", 0).set("provider", "WBEM_E_NOT_SUPPORTED"))};
        return {absent(id, name, "WMI namespace or class not present on this system")};
    }
    // An empty successful inventory is evidence of missing peripherals, not a COM failure.
    if (rows.value.empty() && rule != WmiRule::Missing)
        return {absent(id, name, "provider returned no instances")};
    bool hit = rule == WmiRule::Missing && rows.value.empty();
    size_t populated = 0, missing = 0;
    uint64_t minimum = UINT64_MAX;
    std::vector<std::string> hits;
    for (const auto &row : rows.value)
        for (const auto &p : props) {
            auto key = win::narrow(p), v = win::field(row, key);
            if (v.empty()) {
                ++missing;
                if (rule == WmiRule::Null)
                    hit = true;
                continue;
            }
            ++populated;
            std::string sig;
            uint64_t n = 0;
            bool bad = false;
            switch (rule) {
            case WmiRule::Signature:
                sig = winlogic::match(v, winlogic::vendors());
                bad = !sig.empty();
                break;
            case WmiRule::Ascii: {
                std::string decoded;
                size_t start = 0;
                do {
                    auto end = v.find(',', start);
                    if (!winlogic::integer(v.substr(start, end - start), n))
                        break;
                    if (n > 0 && n < 128)
                        decoded += static_cast<char>(n);
                    if (end == std::string::npos)
                        break;
                    start = end + 1;
                } while (start < v.size());
                sig = winlogic::match(decoded, winlogic::vendors());
                if (sig.empty())
                    sig = winlogic::match(decoded, winlogic::monitor_vendors(), true);
                bad = !sig.empty();
                break;
            }
            case WmiRule::Serial:
                bad = winlogic::default_serial(v) || !winlogic::match(v, winlogic::vendors()).empty();
                break;
            case WmiRule::Uuid:
                // VMware derives SMBIOS UUIDs from "564D..." ("VM"); only the prefix is a tell.
                bad = winlogic::default_uuid(v) || winlogic::lower(winlogic::trim(v)).rfind("564d", 0) == 0;
                break;
            case WmiRule::Zero:
                bad = winlogic::integer(v, n) && n == 0;
                break;
            case WmiRule::True:
                bad = v == "1";
                break;
            case WmiRule::Small: {
                uint64_t threshold = static_cast<uint64_t>(std::max<long long>(
                    0, ctx.param_int(std::string(id) + ".min", static_cast<long long>(limit))));
                if (winlogic::integer(v, n)) {
                    minimum = std::min(minimum, n);
                    bad = n < threshold;
                }
                break;
            }
            case WmiRule::Chassis:
                bad = v == "1" || v == "2";
                break; // SMBIOS Other/Unknown
            case WmiRule::Date:
                bad = winlogic::bios_date(v);
                break;
            case WmiRule::Activation:
                bad = v != "1";
                break;
            case WmiRule::Age: {
                int64_t d = winlogic::date_days(v);
                if (d >= 0) {
                    n = uint64_t(std::max<int64_t>(0, win::now_days() - d));
                    minimum = std::min(minimum, n);
                }
                break;
            }
            case WmiRule::Mac: {
                // "08:00:27:12:34:56" -> OUI lookup shared with the adapter checks.
                std::vector<uint8_t> b;
                for (size_t i = 0; i + 1 < v.size() && b.size() < 3; i += 3) {
                    uint64_t hi = 0;
                    auto hex = [](char c) { return c >= '0' && c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
                    hi = uint64_t(hex(v[i]) * 16 + hex(v[i + 1]));
                    b.push_back(static_cast<uint8_t>(hi));
                }
                sig = winlogic::oui(b);
                bad = !sig.empty();
                break;
            }
            case WmiRule::Missing:
            case WmiRule::Null:
                break;
            }
            if (bad) {
                hit = true;
                std::string label = key + (sig.empty() ? ": atypical" : ": " + sig);
                if (std::find(hits.begin(), hits.end(), label) == hits.end())
                    hits.push_back(label);
            }
        }
    if (rule == WmiRule::Serial && missing)
        hit = true;
    if (rule == WmiRule::Age) {
        if (minimum == UINT64_MAX)
            return {absent(id, name, "provider supplied no parseable dates")};
        hit = minimum > limit;
    }
    if (!populated && !rows.value.empty() && rule != WmiRule::Serial && rule != WmiRule::Missing &&
        rule != WmiRule::Null)
        return {absent(id, name, "requested properties unavailable or null")};
    auto ev = matched(hits, rows.value.size());
    ev.set("missing_properties", static_cast<unsigned long long>(missing));
    if (minimum != UINT64_MAX)
        ev.set("minimum", minimum);
    return {result(id, name, hit, ev)};
}

std::vector<Finding> wmi_env_bios_manufacturer(Context &ctx) {
    return wmi_check(ctx, "env.bios_manufacturer", "Bios manufacturer", L"ROOT\\CIMV2",
                     L"SELECT Manufacturer FROM Win32_BIOS", {L"Manufacturer"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_bios_version(Context &ctx) {
    return wmi_check(ctx, "env.bios_version", "Bios version", L"ROOT\\CIMV2",
                     L"SELECT SMBIOSBIOSVersion,Version FROM Win32_BIOS", {L"SMBIOSBIOSVersion", L"Version"},
                     WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_bios_serial(Context &ctx) {
    return wmi_check(ctx, "env.bios_serial", "Bios serial", L"ROOT\\CIMV2",
                     L"SELECT SerialNumber FROM Win32_BIOS", {L"SerialNumber"}, WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_computer_manufacturer(Context &ctx) {
    return wmi_check(ctx, "env.computer_manufacturer", "Computer manufacturer", L"ROOT\\CIMV2",
                     L"SELECT Manufacturer FROM Win32_ComputerSystem", {L"Manufacturer"}, WmiRule::Signature,
                     0);
}

std::vector<Finding> wmi_env_computer_model(Context &ctx) {
    return wmi_check(ctx, "env.computer_model", "Computer model", L"ROOT\\CIMV2",
                     L"SELECT Model FROM Win32_ComputerSystem", {L"Model"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_baseboard_manufacturer(Context &ctx) {
    return wmi_check(ctx, "env.baseboard_manufacturer", "Baseboard manufacturer", L"ROOT\\CIMV2",
                     L"SELECT Manufacturer FROM Win32_BaseBoard", {L"Manufacturer"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_baseboard_product(Context &ctx) {
    return wmi_check(ctx, "env.baseboard_product", "Baseboard product", L"ROOT\\CIMV2",
                     L"SELECT Product FROM Win32_BaseBoard", {L"Product"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_baseboard_version(Context &ctx) {
    return wmi_check(ctx, "env.baseboard_version", "Baseboard version", L"ROOT\\CIMV2",
                     L"SELECT Version FROM Win32_BaseBoard", {L"Version"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_baseboard_serial(Context &ctx) {
    return wmi_check(ctx, "env.baseboard_serial", "Baseboard serial", L"ROOT\\CIMV2",
                     L"SELECT SerialNumber FROM Win32_BaseBoard", {L"SerialNumber"}, WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_enclosure_manufacturer(Context &ctx) {
    return wmi_check(ctx, "env.enclosure_manufacturer", "Enclosure manufacturer", L"ROOT\\CIMV2",
                     L"SELECT Manufacturer,Model FROM Win32_SystemEnclosure", {L"Manufacturer", L"Model"},
                     WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_enclosure_serial(Context &ctx) {
    return wmi_check(ctx, "env.enclosure_serial", "Enclosure serial", L"ROOT\\CIMV2",
                     L"SELECT SerialNumber,SMBIOSAssetTag FROM Win32_SystemEnclosure",
                     {L"SerialNumber", L"SMBIOSAssetTag"}, WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_chassis_type(Context &ctx) {
    return wmi_check(ctx, "env.chassis_type", "Chassis type", L"ROOT\\CIMV2",
                     L"SELECT ChassisTypes FROM Win32_SystemEnclosure", {L"ChassisTypes"}, WmiRule::Chassis,
                     0);
}

std::vector<Finding> wmi_env_system_product_vendor(Context &ctx) {
    return wmi_check(ctx, "env.system_product_vendor", "System product vendor", L"ROOT\\CIMV2",
                     L"SELECT Vendor FROM Win32_ComputerSystemProduct", {L"Vendor"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_system_product_name(Context &ctx) {
    return wmi_check(ctx, "env.system_product_name", "System product name", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_ComputerSystemProduct", {L"Name"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_system_product_version(Context &ctx) {
    return wmi_check(ctx, "env.system_product_version", "System product version", L"ROOT\\CIMV2",
                     L"SELECT Version FROM Win32_ComputerSystemProduct", {L"Version"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_system_product_uuid(Context &ctx) {
    return wmi_check(ctx, "env.system_product_uuid", "System product uuid", L"ROOT\\CIMV2",
                     L"SELECT UUID FROM Win32_ComputerSystemProduct", {L"UUID"}, WmiRule::Uuid, 0);
}

std::vector<Finding> wmi_env_system_product_serial(Context &ctx) {
    return wmi_check(ctx, "env.system_product_serial", "System product serial", L"ROOT\\CIMV2",
                     L"SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct", {L"IdentifyingNumber"},
                     WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_hypervisor_present(Context &ctx) {
    return wmi_check(ctx, "env.hypervisor_present", "Hypervisor present", L"ROOT\\CIMV2",
                     L"SELECT HypervisorPresent FROM Win32_ComputerSystem", {L"HypervisorPresent"},
                     WmiRule::True, 0);
}

std::vector<Finding> wmi_env_tpm_manufacturer(Context &ctx) {
    return wmi_check(ctx, "env.tpm_manufacturer", "Tpm manufacturer", L"ROOT\\CIMV2\\Security\\MicrosoftTpm",
                     L"SELECT ManufacturerIdTxt,ManufacturerVersion FROM Win32_Tpm",
                     {L"ManufacturerIdTxt", L"ManufacturerVersion"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_tpm_presence(Context &ctx) {
    return wmi_check(ctx, "env.tpm_presence", "Tpm presence", L"ROOT\\CIMV2\\Security\\MicrosoftTpm",
                     L"SELECT SpecVersion FROM Win32_Tpm", {L"SpecVersion"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_disk_model_wmi(Context &ctx) {
    return wmi_check(ctx, "env.disk_model_wmi", "Disk model wmi", L"ROOT\\CIMV2",
                     L"SELECT Model FROM Win32_DiskDrive", {L"Model"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_disk_manufacturer_wmi(Context &ctx) {
    return wmi_check(ctx, "env.disk_manufacturer_wmi", "Disk manufacturer wmi", L"ROOT\\CIMV2",
                     L"SELECT Manufacturer FROM Win32_DiskDrive", {L"Manufacturer"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_disk_serial_wmi(Context &ctx) {
    return wmi_check(ctx, "env.disk_serial_wmi", "Disk serial wmi", L"ROOT\\CIMV2",
                     L"SELECT SerialNumber FROM Win32_DiskDrive", {L"SerialNumber"}, WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_storage_physicaldisk(Context &ctx) {
    return wmi_check(ctx, "env.storage_physicaldisk", "Storage physicaldisk",
                     L"ROOT\\Microsoft\\Windows\\Storage",
                     L"SELECT FriendlyName,Manufacturer,Model FROM MSFT_PhysicalDisk",
                     {L"FriendlyName", L"Manufacturer", L"Model"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_cdrom_identity(Context &ctx) {
    return wmi_check(ctx, "env.cdrom_identity", "Cdrom identity", L"ROOT\\CIMV2",
                     L"SELECT Name,Manufacturer FROM Win32_CDROMDrive", {L"Name", L"Manufacturer"},
                     WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_nic_identity(Context &ctx) {
    return wmi_check(ctx, "env.nic_identity", "Nic identity", L"ROOT\\CIMV2",
                     L"SELECT Name,Manufacturer,Description FROM Win32_NetworkAdapter",
                     {L"Name", L"Manufacturer", L"Description"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_gpu_identity(Context &ctx) {
    return wmi_check(ctx, "env.gpu_identity", "Gpu identity", L"ROOT\\CIMV2",
                     L"SELECT Name,AdapterCompatibility FROM Win32_VideoController",
                     {L"Name", L"AdapterCompatibility"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_gpu_driver(Context &ctx) {
    return wmi_check(ctx, "env.gpu_driver", "Gpu driver", L"ROOT\\CIMV2",
                     L"SELECT InstalledDisplayDrivers FROM Win32_VideoController",
                     {L"InstalledDisplayDrivers"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_gpu_vram(Context &ctx) {
    return wmi_check(ctx, "env.gpu_vram", "Gpu vram", L"ROOT\\CIMV2",
                     L"SELECT AdapterRAM FROM Win32_VideoController", {L"AdapterRAM"}, WmiRule::Zero, 0);
}

std::vector<Finding> wmi_env_monitor_wmi(Context &ctx) {
    return wmi_check(ctx, "env.monitor_wmi", "Monitor wmi", L"ROOT\\WMI",
                     L"SELECT ManufacturerName,UserFriendlyName FROM WmiMonitorID",
                     {L"ManufacturerName", L"UserFriendlyName"}, WmiRule::Ascii, 0);
}

std::vector<Finding> wmi_env_audio_devices(Context &ctx) {
    return wmi_check(ctx, "env.audio_devices", "Audio devices", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_SoundDevice", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_audio_identity(Context &ctx) {
    return wmi_check(ctx, "env.audio_identity", "Audio identity", L"ROOT\\CIMV2",
                     L"SELECT Name,Manufacturer FROM Win32_SoundDevice", {L"Name", L"Manufacturer"},
                     WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_usb_controllers(Context &ctx) {
    return wmi_check(ctx, "env.usb_controllers", "Usb controllers", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_USBController", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_usb_identity(Context &ctx) {
    return wmi_check(ctx, "env.usb_identity", "Usb identity", L"ROOT\\CIMV2",
                     L"SELECT Name,DeviceID FROM Win32_USBHub", {L"Name", L"DeviceID"}, WmiRule::Signature,
                     0);
}

std::vector<Finding> wmi_env_pointing_devices(Context &ctx) {
    return wmi_check(ctx, "env.pointing_devices", "Pointing devices", L"ROOT\\CIMV2",
                     L"SELECT Name,Description,Manufacturer FROM Win32_PointingDevice",
                     {L"Name", L"Description", L"Manufacturer"}, WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_keyboards(Context &ctx) {
    return wmi_check(ctx, "env.keyboards", "Keyboards", L"ROOT\\CIMV2",
                     L"SELECT Name,Description FROM Win32_Keyboard", {L"Name", L"Description"},
                     WmiRule::Signature, 0);
}

std::vector<Finding> wmi_env_thermal_zones(Context &ctx) {
    return wmi_check(ctx, "env.thermal_zones", "Thermal zones", L"ROOT\\WMI",
                     L"SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature", {L"CurrentTemperature"},
                     WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_cpu_fans(Context &ctx) {
    return wmi_check(ctx, "env.cpu_fans", "Cpu fans", L"ROOT\\CIMV2", L"SELECT Name FROM Win32_Fan",
                     {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_temperature_probes(Context &ctx) {
    return wmi_check(ctx, "env.temperature_probes", "Temperature probes", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_TemperatureProbe", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_voltage_probes(Context &ctx) {
    return wmi_check(ctx, "env.voltage_probes", "Voltage probes", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_VoltageProbe", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_numeric_sensors(Context &ctx) {
    return wmi_check(ctx, "env.numeric_sensors", "Numeric sensors", L"ROOT\\CIMV2",
                     L"SELECT Name FROM CIM_NumericSensor", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_sensors(Context &ctx) {
    return wmi_check(ctx, "env.sensors", "Sensors", L"ROOT\\CIMV2", L"SELECT Name FROM CIM_Sensor", {L"Name"},
                     WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_battery_presence(Context &ctx) {
    return wmi_check(ctx, "env.battery_presence", "Battery presence", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_Battery", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_memory_manufacturer(Context &ctx) {
    return wmi_check(ctx, "env.memory_manufacturer", "Memory manufacturer", L"ROOT\\CIMV2",
                     L"SELECT Manufacturer FROM Win32_PhysicalMemory", {L"Manufacturer"}, WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_memory_serial(Context &ctx) {
    return wmi_check(ctx, "env.memory_serial", "Memory serial", L"ROOT\\CIMV2",
                     L"SELECT SerialNumber FROM Win32_PhysicalMemory", {L"SerialNumber"}, WmiRule::Serial, 0);
}

std::vector<Finding> wmi_env_memory_speed(Context &ctx) {
    return wmi_check(ctx, "env.memory_speed", "Memory speed", L"ROOT\\CIMV2",
                     L"SELECT Speed FROM Win32_PhysicalMemory", {L"Speed"}, WmiRule::Zero, 0);
}

std::vector<Finding> wmi_env_memory_arrays(Context &ctx) {
    return wmi_check(ctx, "env.memory_arrays", "Memory arrays", L"ROOT\\CIMV2",
                     L"SELECT MemoryDevices FROM Win32_PhysicalMemoryArray", {L"MemoryDevices"},
                     WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_processor_clock(Context &ctx) {
    return wmi_check(ctx, "env.processor_clock", "Processor clock", L"ROOT\\CIMV2",
                     L"SELECT MaxClockSpeed,CurrentClockSpeed FROM Win32_Processor",
                     {L"MaxClockSpeed", L"CurrentClockSpeed"}, WmiRule::Zero, 0);
}

std::vector<Finding> wmi_env_processor_caches(Context &ctx) {
    return wmi_check(ctx, "env.processor_caches", "Processor caches", L"ROOT\\CIMV2",
                     L"SELECT L2CacheSize,L3CacheSize FROM Win32_Processor", {L"L2CacheSize", L"L3CacheSize"},
                     WmiRule::Zero, 0);
}

std::vector<Finding> wmi_env_cache_memory(Context &ctx) {
    return wmi_check(ctx, "env.cache_memory", "Cache memory", L"ROOT\\CIMV2",
                     L"SELECT InstalledSize FROM Win32_CacheMemory", {L"InstalledSize"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_port_connectors(Context &ctx) {
    return wmi_check(ctx, "env.port_connectors", "Port connectors", L"ROOT\\CIMV2",
                     L"SELECT Tag FROM Win32_PortConnector", {L"Tag"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_system_slots(Context &ctx) {
    return wmi_check(ctx, "env.system_slots", "System slots", L"ROOT\\CIMV2",
                     L"SELECT SlotDesignation FROM Win32_SystemSlot", {L"SlotDesignation"}, WmiRule::Missing,
                     0);
}

std::vector<Finding> wmi_env_cpu_count_wmi(Context &ctx) {
    return wmi_check(ctx, "env.cpu_count_wmi", "Cpu count wmi", L"ROOT\\CIMV2",
                     L"SELECT NumberOfLogicalProcessors FROM Win32_ComputerSystem",
                     {L"NumberOfLogicalProcessors"}, WmiRule::Small, winlogic::kMinCpus);
}

std::vector<Finding> wmi_env_disk_size_wmi(Context &ctx) {
    return wmi_check(ctx, "env.disk_size_wmi", "Disk size wmi", L"ROOT\\CIMV2",
                     L"SELECT Size FROM Win32_DiskDrive", {L"Size"}, WmiRule::Small, winlogic::kMinDisk);
}

std::vector<Finding> wmi_behavioural_hotfix_history(Context &ctx) {
    return wmi_check(ctx, "behavioural.hotfix_history", "Hotfix history", L"ROOT\\CIMV2",
                     L"SELECT HotFixID FROM Win32_QuickFixEngineering", {L"HotFixID"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_behavioural_printer_history(Context &ctx) {
    return wmi_check(ctx, "behavioural.printer_history", "Printer history", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_Printer", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_design_antivirus_presence(Context &ctx) {
    return wmi_check(ctx, "design.antivirus_presence", "Antivirus presence", L"ROOT\\SecurityCenter2",
                     L"SELECT displayName FROM AntiVirusProduct", {L"displayName"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_design_defender_service_state(Context &ctx) {
    return wmi_check(ctx, "design.defender_service_state", "Defender service state",
                     L"ROOT\\Microsoft\\Windows\\Defender",
                     L"SELECT AntivirusEnabled,RealTimeProtectionEnabled FROM MSFT_MpComputerStatus",
                     {L"AntivirusEnabled", L"RealTimeProtectionEnabled"}, WmiRule::Zero, 0);
}

std::vector<Finding> wmi_design_windows_activation(Context &ctx) {
    return wmi_check(
        ctx, "design.windows_activation", "Windows activation", L"ROOT\\CIMV2",
        L"SELECT LicenseStatus FROM SoftwareLicensingProduct WHERE "
        L"ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL",
        {L"LicenseStatus"}, WmiRule::Activation, 0, winlogic::kWmiSlowMs);
}

std::vector<Finding> wmi_design_last_update_age(Context &ctx) {
    return wmi_check(ctx, "design.last_update_age", "Last update age", L"ROOT\\CIMV2",
                     L"SELECT InstalledOn FROM Win32_QuickFixEngineering", {L"InstalledOn"}, WmiRule::Age,
                     winlogic::kStaleUpdateDays);
}

std::vector<Finding> wmi_env_memory_devices(Context &ctx) {
    return wmi_check(ctx, "env.memory_devices", "Memory devices", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_MemoryDevice", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_smbios_memory_wmi(Context &ctx) {
    return wmi_check(ctx, "env.smbios_memory_wmi", "Smbios memory wmi", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_SMBIOSMemory", {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_cim_memory(Context &ctx) {
    return wmi_check(ctx, "env.cim_memory", "Cim memory", L"ROOT\\CIMV2", L"SELECT Name FROM CIM_Memory",
                     {L"Name"}, WmiRule::Missing, 0);
}

std::vector<Finding> wmi_env_physical_connectors(Context &ctx) {
    return wmi_check(ctx, "env.physical_connectors", "Physical connectors", L"ROOT\\CIMV2",
                     L"SELECT Name FROM CIM_PhysicalConnector", {L"Name"}, WmiRule::Missing, 0);
}
std::vector<Finding> wmi_env_perf_thermal(Context &ctx) {
    return wmi_check(ctx, "env.perfctrs_thermal_zone", "Thermal zone performance counters", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation", {L"Name"},
                     WmiRule::Missing, 0);
}
std::vector<Finding> wmi_env_cim_slots(Context &ctx) {
    return wmi_check(ctx, "env.cim_slots", "CIM slots", L"ROOT\\CIMV2", L"SELECT Name FROM CIM_Slot", {L"Name"},
                     WmiRule::Missing, 0);
}
std::vector<Finding> wmi_env_cim_temperature(Context &ctx) {
    return wmi_check(ctx, "env.cim_temperature_sensors", "CIM temperature sensors", L"ROOT\\CIMV2",
                     L"SELECT Name FROM CIM_TemperatureSensor", {L"Name"}, WmiRule::Missing, 0);
}
std::vector<Finding> wmi_env_cim_voltage(Context &ctx) {
    return wmi_check(ctx, "env.cim_voltage_sensors", "CIM voltage sensors", L"ROOT\\CIMV2",
                     L"SELECT Name FROM CIM_VoltageSensor", {L"Name"}, WmiRule::Missing, 0);
}
std::vector<Finding> wmi_env_processor_id(Context &ctx) {
    return wmi_check(ctx, "env.processor_id_wmi", "Processor ID", L"ROOT\\CIMV2",
                     L"SELECT ProcessorId FROM Win32_Processor", {L"ProcessorId"}, WmiRule::Null, 0);
}
std::vector<Finding> wmi_env_video_caption(Context &ctx) {
    return wmi_check(ctx, "env.video_controller_caption", "Video controller caption", L"ROOT\\CIMV2",
                     L"SELECT Caption FROM Win32_VideoController", {L"Caption"}, WmiRule::Signature, 0);
}
std::vector<Finding> wmi_env_pnp_names(Context &ctx) {
    return wmi_check(ctx, "env.pnp_entity_names", "PnP entity names", L"ROOT\\CIMV2",
                     L"SELECT Name FROM Win32_PnPEntity", {L"Name"}, WmiRule::Signature, 0);
}
std::vector<Finding> wmi_env_bus(Context &ctx) {
    return wmi_check(ctx, "env.bus_count_wmi", "System bus inventory", L"ROOT\\CIMV2",
                     L"SELECT DeviceID FROM Win32_Bus", {L"DeviceID"}, WmiRule::Missing, 0);
}
std::vector<Finding> wmi_env_vbox_mac(Context &ctx) {
    return wmi_check(ctx, "env.adapter_mac_wmi", "Network adapter MAC (WMI)", L"ROOT\\CIMV2",
                     L"SELECT MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE",
                     {L"MACAddress"}, WmiRule::Mac, 0);
}
} // namespace
PERDEDOR_REGISTER(wmi_env_perf_thermal, "hardware.thermal_sensors", "medium", false, "env.perfctrs_thermal_zone");
PERDEDOR_REGISTER(wmi_env_cim_slots, "hardware.port_connectors", "medium", false, "env.cim_slots");
PERDEDOR_REGISTER(wmi_env_cim_temperature, "hardware.thermal_sensors", "medium", false,
                  "env.cim_temperature_sensors");
PERDEDOR_REGISTER(wmi_env_cim_voltage, "hardware.thermal_sensors", "medium", false, "env.cim_voltage_sensors");
PERDEDOR_REGISTER(wmi_env_processor_id, "hardware.cpu_cache_clock", "medium", false, "env.processor_id_wmi");
PERDEDOR_REGISTER(wmi_env_video_caption, "hardware.gpu_identity", "medium", false, "env.video_controller_caption");
PERDEDOR_REGISTER(wmi_env_pnp_names, "hardware.pci_vendor_ids", "medium", false, "env.pnp_entity_names");
PERDEDOR_REGISTER(wmi_env_bus, "hardware.port_connectors", "medium", false, "env.bus_count_wmi");
PERDEDOR_REGISTER(wmi_env_vbox_mac, "network.mac_oui", "medium", false, "env.adapter_mac_wmi");
PERDEDOR_REGISTER(wmi_env_bios_manufacturer, "firmware.smbios_strings", "medium", false,
                  "env.bios_manufacturer");
PERDEDOR_REGISTER(wmi_env_bios_version, "firmware.bios_metadata", "medium", false, "env.bios_version");
PERDEDOR_REGISTER(wmi_env_bios_serial, "firmware.smbios_serials_uuid", "medium", false, "env.bios_serial");
PERDEDOR_REGISTER(wmi_env_computer_manufacturer, "firmware.smbios_strings", "medium", false,
                  "env.computer_manufacturer");
PERDEDOR_REGISTER(wmi_env_computer_model, "firmware.smbios_strings", "medium", false, "env.computer_model");
PERDEDOR_REGISTER(wmi_env_baseboard_manufacturer, "firmware.smbios_strings", "medium", false,
                  "env.baseboard_manufacturer");
PERDEDOR_REGISTER(wmi_env_baseboard_product, "firmware.smbios_strings", "medium", false,
                  "env.baseboard_product");
PERDEDOR_REGISTER(wmi_env_baseboard_version, "firmware.smbios_strings", "medium", false,
                  "env.baseboard_version");
PERDEDOR_REGISTER(wmi_env_baseboard_serial, "firmware.smbios_serials_uuid", "medium", false,
                  "env.baseboard_serial");
PERDEDOR_REGISTER(wmi_env_enclosure_manufacturer, "firmware.smbios_strings", "medium", false,
                  "env.enclosure_manufacturer");
PERDEDOR_REGISTER(wmi_env_enclosure_serial, "firmware.smbios_serials_uuid", "medium", false,
                  "env.enclosure_serial");
PERDEDOR_REGISTER(wmi_env_chassis_type, "firmware.smbios_strings", "medium", false, "env.chassis_type");
PERDEDOR_REGISTER(wmi_env_system_product_vendor, "firmware.smbios_strings", "medium", false,
                  "env.system_product_vendor");
PERDEDOR_REGISTER(wmi_env_system_product_name, "firmware.smbios_strings", "medium", false,
                  "env.system_product_name");
PERDEDOR_REGISTER(wmi_env_system_product_version, "firmware.smbios_strings", "medium", false,
                  "env.system_product_version");
PERDEDOR_REGISTER(wmi_env_system_product_uuid, "firmware.smbios_serials_uuid", "medium", false,
                  "env.system_product_uuid");
PERDEDOR_REGISTER(wmi_env_system_product_serial, "firmware.smbios_serials_uuid", "medium", false,
                  "env.system_product_serial");
PERDEDOR_REGISTER(wmi_env_hypervisor_present, "container.virtualisation_report", "medium", false,
                  "env.hypervisor_present");
PERDEDOR_REGISTER(wmi_env_tpm_manufacturer, "firmware.boot_mode", "medium", false, "env.tpm_manufacturer");
PERDEDOR_REGISTER(wmi_env_tpm_presence, "firmware.boot_mode", "medium", false, "env.tpm_presence");
PERDEDOR_REGISTER(wmi_env_disk_model_wmi, "hardware.disk_identity", "medium", false, "env.disk_model_wmi");
PERDEDOR_REGISTER(wmi_env_disk_manufacturer_wmi, "hardware.disk_identity", "medium", false,
                  "env.disk_manufacturer_wmi");
PERDEDOR_REGISTER(wmi_env_disk_serial_wmi, "hardware.disk_identity", "medium", false, "env.disk_serial_wmi");
PERDEDOR_REGISTER(wmi_env_storage_physicaldisk, "hardware.disk_identity", "medium", false,
                  "env.storage_physicaldisk");
PERDEDOR_REGISTER(wmi_env_cdrom_identity, "hardware.disk_identity", "medium", false, "env.cdrom_identity");
PERDEDOR_REGISTER(wmi_env_nic_identity, "hardware.nic_identity", "medium", false, "env.nic_identity");
PERDEDOR_REGISTER(wmi_env_gpu_identity, "hardware.gpu_identity", "medium", false, "env.gpu_identity");
PERDEDOR_REGISTER(wmi_env_gpu_driver, "hardware.gpu_identity", "medium", false, "env.gpu_driver");
PERDEDOR_REGISTER(wmi_env_gpu_vram, "hardware.gpu_identity", "medium", false, "env.gpu_vram");
PERDEDOR_REGISTER(wmi_env_monitor_wmi, "hardware.monitor_edid", "medium", false, "env.monitor_wmi");
PERDEDOR_REGISTER(wmi_env_audio_devices, "hardware.audio_devices", "medium", false, "env.audio_devices");
PERDEDOR_REGISTER(wmi_env_audio_identity, "hardware.audio_devices", "medium", false, "env.audio_identity");
PERDEDOR_REGISTER(wmi_env_usb_controllers, "hardware.usb_devices", "medium", false, "env.usb_controllers");
PERDEDOR_REGISTER(wmi_env_usb_identity, "hardware.usb_devices", "medium", false, "env.usb_identity");
PERDEDOR_REGISTER(wmi_env_pointing_devices, "hardware.input_devices", "medium", false,
                  "env.pointing_devices");
PERDEDOR_REGISTER(wmi_env_keyboards, "hardware.input_devices", "medium", false, "env.keyboards");
PERDEDOR_REGISTER(wmi_env_thermal_zones, "hardware.thermal_sensors", "medium", false, "env.thermal_zones");
PERDEDOR_REGISTER(wmi_env_cpu_fans, "hardware.thermal_sensors", "medium", false, "env.cpu_fans");
PERDEDOR_REGISTER(wmi_env_temperature_probes, "hardware.thermal_sensors", "medium", false,
                  "env.temperature_probes");
PERDEDOR_REGISTER(wmi_env_voltage_probes, "hardware.thermal_sensors", "medium", false, "env.voltage_probes");
PERDEDOR_REGISTER(wmi_env_numeric_sensors, "hardware.thermal_sensors", "medium", false,
                  "env.numeric_sensors");
PERDEDOR_REGISTER(wmi_env_sensors, "hardware.thermal_sensors", "medium", false, "env.sensors");
PERDEDOR_REGISTER(wmi_env_battery_presence, "hardware.battery_power", "medium", false,
                  "env.battery_presence");
PERDEDOR_REGISTER(wmi_env_memory_manufacturer, "hardware.memory_modules", "medium", false,
                  "env.memory_manufacturer");
PERDEDOR_REGISTER(wmi_env_memory_serial, "hardware.memory_modules", "medium", false, "env.memory_serial");
PERDEDOR_REGISTER(wmi_env_memory_speed, "hardware.memory_modules", "medium", false, "env.memory_speed");
PERDEDOR_REGISTER(wmi_env_memory_arrays, "hardware.memory_modules", "medium", false, "env.memory_arrays");
PERDEDOR_REGISTER(wmi_env_processor_clock, "hardware.cpu_cache_clock", "medium", false,
                  "env.processor_clock");
PERDEDOR_REGISTER(wmi_env_processor_caches, "hardware.cpu_cache_clock", "medium", false,
                  "env.processor_caches");
PERDEDOR_REGISTER(wmi_env_cache_memory, "hardware.cpu_cache_clock", "medium", false, "env.cache_memory");
PERDEDOR_REGISTER(wmi_env_port_connectors, "hardware.port_connectors", "medium", false,
                  "env.port_connectors");
PERDEDOR_REGISTER(wmi_env_system_slots, "hardware.port_connectors", "medium", false, "env.system_slots");
PERDEDOR_REGISTER(wmi_env_cpu_count_wmi, "resources.cpu_count", "medium", false, "env.cpu_count_wmi");
PERDEDOR_REGISTER(wmi_env_disk_size_wmi, "resources.disk_size", "medium", false, "env.disk_size_wmi");
PERDEDOR_REGISTER(wmi_behavioural_hotfix_history, "wear_and_tear.system_age", "medium", false,
                  "behavioural.hotfix_history");
PERDEDOR_REGISTER(wmi_behavioural_printer_history, "wear_and_tear.peripherals_history", "medium", false,
                  "behavioural.printer_history");
PERDEDOR_REGISTER(wmi_design_antivirus_presence, "os_config.security_software", "medium", false,
                  "design.antivirus_presence");
PERDEDOR_REGISTER(wmi_design_defender_service_state, "os_config.security_software", "medium", false,
                  "design.defender_service_state");
PERDEDOR_REGISTER(wmi_design_windows_activation, "os_config.activation_updates", "medium", false,
                  "design.windows_activation");
PERDEDOR_REGISTER(wmi_design_last_update_age, "os_config.activation_updates", "medium", false,
                  "design.last_update_age");
PERDEDOR_REGISTER(wmi_env_memory_devices, "hardware.memory_modules", "medium", false, "env.memory_devices");
PERDEDOR_REGISTER(wmi_env_smbios_memory_wmi, "hardware.memory_modules", "medium", false,
                  "env.smbios_memory_wmi");
PERDEDOR_REGISTER(wmi_env_cim_memory, "hardware.memory_modules", "medium", false, "env.cim_memory");
PERDEDOR_REGISTER(wmi_env_physical_connectors, "hardware.port_connectors", "medium", false,
                  "env.physical_connectors");
} // namespace perdedor
