#include "system_logic.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <set>

namespace perdedor {
namespace winlogic {
std::string lower(std::string s) {
    for (auto &c : s)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    return s;
}
std::string trim(std::string s) {
    auto blank = [](unsigned char c) { return c == 0 || c == ' ' || c == '\r' || c == '\n' || c == '\t'; };
    while (!s.empty() && blank(s.back()))
        s.pop_back();
    size_t n = 0;
    while (n < s.size() && blank(s[n]))
        ++n;
    return s.substr(n);
}
bool contains(const std::string &text, const std::string &token) {
    return !token.empty() && lower(text).find(lower(token)) != std::string::npos;
}
std::string match(const std::string &text, const std::vector<std::string> &signatures, bool exact) {
    const auto t = lower(trim(text));
    for (const auto &s : signatures)
        if (exact ? t == lower(s) : contains(t, s))
            return s;
    return {};
}
const std::vector<std::string> &vendors() {
    // v1 DmiVendorSignatures, al-khaser AntiVM, ACPI OEM signatures.
    static const std::vector<std::string> v = {"qemu",
                                               "bochs",
                                               "kvm",
                                               "virtualbox",
                                               "vbox",
                                               "innotek",
                                               "vmware",
                                               "xen",
                                               "microsoft corporation",
                                               "parallels",
                                               "bhyve",
                                               "amazon ec2",
                                               "google compute engine",
                                               "hvm dom",
                                               "hvmloader",
                                               "seabios",
                                               "ovmf",
                                               "msftvm",
                                               "vrtual",
                                               "bxpc",
                                               "virtual machine",
                                               "virtual hd",
                                               "virtual disk",
                                               "red hat",
                                               "virtio",
                                               "prl_",
                                               "hyper-v"};
    return v;
}
const std::vector<std::string> &pci_vendors() {
    static const std::vector<std::string> v = {
        "ven_1af4",          "ven_1b36", "ven_15ad", "ven_80ee", "ven_5853", "ven_1414",
        "ven_1234&dev_1111", "ven_1ab8", "ven_fffe", "vmbus\\",  "xen\\"};
    return v;
}
const std::vector<std::string> &name_tokens() {
    static const std::vector<std::string> v = {"sandbox", "malware", "sample",   "analysis",
                                               "cuckoo",  "detonat", "honeypot", "virus"};
    return v;
}
const std::vector<std::string> &usernames() {
    // Exact matching preserves the v1 set and al-khaser AntiVM/Generic.cpp known_usernames.
    static const std::vector<std::string> v = {
        "sandbox",   "malware", "maltest",  "currentuser",  "sample",  "virus",    "test",
        "test user", "vmuser",  "john doe", "emily",        "hapubws", "hong lee", "it-admin",
        "johnson",   "miller",  "milozs",   "peter wilson", "timmy",   "user",     "sand box"};
    return v;
}
const std::vector<std::string> &hostnames() {
    static const std::vector<std::string> v = {"sandbox",    "7silvia",    "hanspeter-pc", "john-pc",
                                               "mueller-pc", "win7-traps", "fortinet",     "tequilaboomboom"};
    return v;
}
std::string oui(const std::vector<uint8_t> &b) {
    // v1 MacOuiSignatures and al-khaser AntiVM/{Parallels,Generic}.cpp.
    if (b.size() < 3)
        return {};
    static const std::map<uint32_t, std::string> v = {
        {0x525400, "QEMU/KVM"}, {0x080027, "VirtualBox"}, {0x0a0027, "VirtualBox host-only"},
        {0x000c29, "VMware"},   {0x005056, "VMware"},     {0x001c14, "VMware"},
        {0x000569, "VMware"},   {0x00163e, "Xen"},        {0x0003ff, "Virtual PC"},
        {0x00155d, "Hyper-V"},  {0x001c42, "Parallels"},  {0x0a0020, "Hybrid Analysis"}};
    const auto it = v.find((uint32_t(b[0]) << 16) | (uint32_t(b[1]) << 8) | b[2]);
    return it == v.end() ? "" : it->second;
}
std::string subnet(uint32_t address) {
    // QEMU user networking, VirtualBox host-only, libvirt default NAT networks:
    // https://www.qemu.org/docs/master/system/devices/net.html
    // https://www.virtualbox.org/manual/ch06.html
    // https://libvirt.org/formatnetwork.html
    switch (address & 0xffffff00U) {
    case 0x0a000200U:
        return "10.0.2.0/24 (QEMU/VirtualBox NAT)";
    case 0xc0a83800U:
        return "192.168.56.0/24 (VirtualBox host-only)";
    case 0xc0a87a00U:
        return "192.168.122.0/24 (libvirt NAT)";
    default:
        return {};
    }
}
bool default_serial(const std::string &s) {
    const auto t = lower(trim(s));
    static const std::vector<std::string> defaults = {"0",
                                                      "none",
                                                      "unknown",
                                                      "default string",
                                                      "not specified",
                                                      "to be filled by o.e.m.",
                                                      "system serial number",
                                                      "123456789",
                                                      "0123456789",
                                                      "not applicable"};
    return t.empty() || !match(t, defaults, true).empty() ||
           std::all_of(t.begin(), t.end(), [](char c) { return c == '0' || c == ' '; });
}
bool default_uuid(const std::string &s) {
    auto t = lower(trim(s));
    t.erase(std::remove(t.begin(), t.end(), '-'), t.end());
    return t.empty() || t == std::string(32, '0') || t == std::string(32, 'f') ||
           t == "03000200040005000006000700080009";
}
static std::string basename(const std::string &s) { return lower(s.substr(s.find_last_of("/\\") + 1)); }
bool hash_name(const std::string &path) {
    auto s = basename(path);
    s = s.substr(0, s.find_last_of('.'));
    // MD5/SHA1/SHA256 lengths used in al-khaser known_file_names.
    return (s.size() == 32 || s.size() == 40 || s.size() == 64) &&
           std::all_of(s.begin(), s.end(),
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool known_filename(const std::string &path) {
    return !match(basename(path),
                  {"sample.exe", "bot.exe", "sandbox.exe", "malware.exe", "test.exe", "klavme.exe",
                   "myapp.exe", "testapp.exe"},
                  true)
                .empty();
}
bool suspicious_path(const std::string &path) {
    return !match(path, {"\\sample", "\\analysis", "\\malware", "\\sandbox", "\\cuckoo"}).empty();
}
bool bios_date(const std::string &date) { return trim(date) == "06/23/99" || trim(date) == "06/23/1999"; }
bool integer(const std::string &s, uint64_t &out) {
    auto t = trim(s);
    if (t.empty())
        return false;
    uint64_t n = 0;
    for (char c : t) {
        if (c < '0' || c > '9' || n > (std::numeric_limits<uint64_t>::max() - unsigned(c - '0')) / 10)
            return false;
        n = n * 10 + unsigned(c - '0');
    }
    out = n;
    return true;
}
int64_t date_days(const std::string &s) {
    unsigned y = 0, m = 0, d = 0;
    uint64_t n = 0;
    auto number = [&](size_t a, size_t b) { return a + b <= s.size() && integer(s.substr(a, b), n); };
    if (s.size() >= 8 && number(0, 8)) {
        y = unsigned(n / 10000);
        m = unsigned(n / 100 % 100);
        d = unsigned(n % 100);
    } else if (s.size() >= 10 && s[4] == '-' && s[7] == '-' && number(0, 4)) {
        y = unsigned(n);
        if (!number(5, 2))
            return -1;
        m = unsigned(n);
        if (!number(8, 2))
            return -1;
        d = unsigned(n);
    } else {
        auto a = s.find('/'), b = s.find('/', a == std::string::npos ? a : a + 1);
        if (a == std::string::npos || b == std::string::npos || !number(0, a))
            return -1;
        m = unsigned(n);
        if (!number(a + 1, b - a - 1))
            return -1;
        d = unsigned(n);
        if (s.size() - b - 1 != 4 || !number(b + 1, 4))
            return -1;
        y = unsigned(n);
    }
    if (y < 1970 || y > 9999 || m < 1 || m > 12 || d < 1)
        return -1;
    const unsigned lengths[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    unsigned days = lengths[m - 1] + (m == 2 && y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    if (d > days)
        return -1;
    // Gregorian civil date to Unix days; no local-time or CRT timezone dependency.
    int yy = int(y) - (m <= 2), era = yy / 400;
    unsigned yo = unsigned(yy - era * 400), mp = m > 2 ? m - 3 : m + 9;
    return int64_t(era) * 146097 + yo * 365 + yo / 4 - yo / 100 + (153 * mp + 2) / 5 + d - 1 - 719468;
}
uint16_t u16(const std::vector<uint8_t> &b, size_t a) {
    return a < b.size() && b.size() - a >= 2 ? uint16_t(b[a] | (uint16_t(b[a + 1]) << 8)) : 0;
}
uint32_t u32(const std::vector<uint8_t> &b, size_t a) {
    return a < b.size() && b.size() - a >= 4 ? uint32_t(b[a]) | (uint32_t(b[a + 1]) << 8) |
                                                   (uint32_t(b[a + 2]) << 16) | (uint32_t(b[a + 3]) << 24)
                                             : 0;
}
Smbios smbios(const std::vector<uint8_t> &b) {
    Smbios r;
    // RawSMBIOSData envelope:
    // https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable Structure
    // layouts: https://www.dmtf.org/standards/smbios
    if (b.size() < 8 || u32(b, 4) > b.size() - 8) {
        r.error = "truncated RawSMBIOSData";
        return r;
    }
    const size_t end = 8 + u32(b, 4);
    size_t p = 8;
    while (p < end) {
        if (end - p < 4 || b[p + 1] < 4 || b[p + 1] > end - p) {
            r.error = "invalid SMBIOS structure length";
            return r;
        }
        unsigned type = b[p], len = b[p + 1];
        size_t q = p + len;
        while (q + 1 < end && (b[q] != 0 || b[q + 1] != 0))
            ++q;
        if (q + 1 >= end) {
            r.error = "unterminated SMBIOS string set";
            return r;
        }
        ++r.types[type];
        const std::string strings(reinterpret_cast<const char *>(b.data() + p + len), q - (p + len));
        for (const auto &v : vendors())
            if (contains(strings, v) && std::find(r.hits.begin(), r.hits.end(), v) == r.hits.end())
                r.hits.push_back(v);
        if (type == 0 && len > 19)
            r.vm_bit = (b[p + 19] & 0x10) != 0;
        if (type == 1 && len >= 24) {
            bool zero = true, ff = true;
            for (size_t i = p + 8; i < p + 24; ++i) {
                zero &= b[i] == 0;
                ff &= b[i] == 255;
            }
            r.uuid_default |= zero || ff;
        }
        // Type 17 Size==0 means an empty slot, not a populated DIMM with missing speed.
        if (type == 17 && len >= 14 && u16(b, p + 12) != 0) {
            ++r.memory_devices;
            if (len < 23 || u16(b, p + 21) == 0)
                ++r.memory_without_speed;
        }
        p = q + 2;
        if (type == 127)
            break;
    }
    if (r.types.empty()) {
        r.error = "empty SMBIOS table";
        return r;
    }
    r.valid = true;
    return r;
}
Acpi acpi(const std::vector<uint8_t> &b) {
    Acpi r;
    // ACPI DESCRIPTION_HEADER and checksum:
    // https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html
    if (b.size() < 36 || u32(b, 4) < 36 || u32(b, 4) > b.size()) {
        r.error = "truncated ACPI header/table";
        return r;
    }
    unsigned sum = 0;
    for (size_t i = 0; i < u32(b, 4); ++i)
        sum += b[i];
    if ((sum & 255) != 0) {
        r.error = "invalid ACPI checksum";
        return r;
    }
    auto str = [&](size_t a, size_t n) {
        return trim(std::string(reinterpret_cast<const char *>(b.data() + a), n));
    };
    r.signature = str(0, 4);
    r.oem = str(10, 6);
    r.table = str(16, 8);
    r.creator = str(28, 4);
    r.hit = match(str(0, u32(b, 4)), vendors());
    r.valid = true;
    return r;
}
Edid edid(const std::vector<uint8_t> &b) {
    Edid r;
    // EDID base block: https://glenwing.github.io/docs/VESA-EEDID-A2.pdf
    const uint8_t header[] = {0, 255, 255, 255, 255, 255, 255, 0};
    if (b.size() < 128 || !std::equal(std::begin(header), std::end(header), b.begin())) {
        r.error = "invalid EDID header";
        return r;
    }
    unsigned sum = 0;
    for (size_t i = 0; i < 128; ++i)
        sum += b[i];
    if (sum & 255) {
        r.error = "invalid EDID checksum";
        return r;
    }
    unsigned m = unsigned(b[8]) * 256 + b[9];
    for (int shift : {10, 5, 0}) {
        unsigned ch = (m >> shift) & 31;
        if (!ch || ch > 26) {
            r.error = "invalid EDID manufacturer";
            return r;
        }
        r.manufacturer += char('A' + ch - 1);
    }
    r.serial_missing = u32(b, 12) == 0;
    r.year = 1990 + b[17];
    r.valid = true;
    return r;
}
Motion motion(const std::vector<Point> &points, double diagonal) {
    Motion r;
    std::set<std::pair<int, int>> unique;
    std::array<unsigned, 8> bins{};
    double px = 0, py = 0;
    bool prev = false;
    constexpr double pi = 3.14159265358979323846;
    for (size_t i = 0; i < points.size(); ++i) {
        unique.emplace(points[i].x, points[i].y);
        if (!i)
            continue;
        double x = double(points[i].x) - points[i - 1].x, y = double(points[i].y) - points[i - 1].y;
        double length = std::hypot(x, y);
        if (!length)
            continue;
        ++r.moves;
        if (diagonal > 0 && length > diagonal * kTeleportScreenFraction)
            ++r.teleports;
        if (prev && (x * px + y * py) / (length * std::hypot(px, py)) > kStraightCosine)
            ++r.straight;
        unsigned bin = unsigned((std::atan2(y, x) + pi) / (2 * pi) * 8) % 8;
        ++bins[bin];
        px = x;
        py = y;
        prev = true;
    }
    r.unique = unique.size();
    for (auto n : bins)
        if (n && r.moves) {
            double p = double(n) / r.moves;
            r.entropy -= p * std::log2(p);
        }
    return r;
}
} // namespace winlogic
} // namespace perdedor
