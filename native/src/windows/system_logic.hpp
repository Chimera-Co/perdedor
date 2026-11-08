// Pure Windows evidence interpretation. No Win32 headers; exercised by host fixtures.
#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace perdedor {
namespace winlogic {
// Compatibility defaults from the v1 Windows probes (not hardware requirements):
// https://github.com/Chimera-Co/perdedor/tree/main/agents/windows/probes
constexpr unsigned kMinCpus = 2;
constexpr uint64_t kGiB = 1024ULL * 1024 * 1024;
constexpr uint64_t kMinRam = 4 * kGiB;
constexpr uint64_t kMinDisk = 60 * kGiB;
constexpr unsigned kMinPrograms = 20, kMinFonts = 100, kMinProcesses = 40;
constexpr unsigned kMinAgedFiles = 5, kAgedDays = 7, kHistoryBytes = 20 * 1024;
// Conservative, tunable presence/age heuristics, rationale: docs/notes/windows.md.
// These are policy defaults, not statistically validated VM classifiers.
constexpr unsigned kMinTraceCount = 1, kMinVisibleWindows = 2, kMinAcpiTables = 4;
constexpr unsigned kYoungDays = 7, kStaleUpdateDays = 180, kIdleSeconds = 600;
constexpr unsigned kMinScreenWidth = 1024, kMinScreenHeight = 768;
constexpr unsigned kWaitSeconds = 30, kMaxWaitSeconds = 90, kSampleMs = 100;
constexpr unsigned kMinMotionSegments = 5;
constexpr double kStraightCosine = 0.999, kTeleportScreenFraction = 0.75, kLowEntropy = 1.0;
// Resource caps keep enumeration finite (DESIGN-V2.md safety contract).
constexpr size_t kMaxBlob = 16 * 1024 * 1024, kMaxRows = 4096, kMaxEntries = 10000;
constexpr unsigned kQueryMs = 3000, kScanMs = 2000, kIoMs = 1500;
// WMI budget covers a cold winmgmt start plus enumeration and stays inside the 45 s
// medium watchdog; SoftwareLicensingProduct is documented as slow and gets the long budget.
constexpr unsigned kWmiMs = 8000, kWmiSlowMs = 25000;
// SetupAPI enumeration of all device instances including non-present ones; large
// desktops carry a few thousand instances (each needs several property reads).
constexpr unsigned kDeviceScanMs = 8000;
// Recursive user-folder and registry scans stop here; counts are then lower bounds.
constexpr unsigned kTreeScanMs = 4000;

std::string lower(std::string s);
std::string trim(std::string s);
bool contains(const std::string &text, const std::string &token);
std::string match(const std::string &text, const std::vector<std::string> &signatures, bool exact = false);
const std::vector<std::string> &vendors();
const std::vector<std::string> &pci_vendors();
const std::vector<std::string> &usernames();
const std::vector<std::string> &hostnames();
const std::vector<std::string> &name_tokens();
const std::vector<std::string> &analysis_processes();
const std::vector<std::string> &guest_processes();
const std::vector<std::string> &guest_services();
const std::vector<std::string> &modules();
// EDID three-letter manufacturer codes of virtual displays.
const std::vector<std::string> &monitor_vendors();
std::string oui(const std::vector<uint8_t> &address);
// IPv4 address in network display order (10.0.2.1 == 0x0a000201).
std::string subnet(uint32_t address);
bool default_serial(const std::string &s);
bool default_uuid(const std::string &s);
bool hash_name(const std::string &path);
bool known_filename(const std::string &path);
bool suspicious_path(const std::string &path);
bool bios_date(const std::string &date);
// UTC civil-day number, or -1 for missing/invalid/ambiguous dates.
int64_t date_days(const std::string &date);
bool integer(const std::string &s, uint64_t &out);
uint16_t u16(const std::vector<uint8_t> &b, size_t at);
uint32_t u32(const std::vector<uint8_t> &b, size_t at);
struct Smbios {
    bool valid = false, vm_bit = false, uuid_default = false;
    unsigned memory_devices = 0, memory_without_speed = 0;
    std::map<unsigned, unsigned> types;
    std::vector<std::string> hits;
    std::string error;
};
Smbios smbios(const std::vector<uint8_t> &raw);
struct Acpi {
    bool valid = false;
    std::string signature, oem, table, creator, hit, error;
};
Acpi acpi(const std::vector<uint8_t> &bytes);
struct Edid {
    bool valid = false, serial_missing = false;
    std::string manufacturer, error;
    unsigned year = 0;
};
Edid edid(const std::vector<uint8_t> &bytes);
struct Point {
    int x = 0, y = 0;
};
struct Motion {
    size_t moves = 0, unique = 0, straight = 0, teleports = 0;
    double entropy = 0;
};
Motion motion(const std::vector<Point> &points, double screen_diagonal);
} // namespace winlogic
} // namespace perdedor
