// Host tests for the pure Windows evidence logic (src/windows/system_logic.*). The blobs are
// synthetic but follow the published layouts: RawSMBIOSData + DSP0134 structures, the ACPI
// DESCRIPTION_HEADER with a valid checksum, and the VESA EDID base block.
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "../src/windows/system_logic.hpp"

using namespace perdedor::winlogic;
using Bytes = std::vector<uint8_t>;

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond);          \
            ++failures;                                                                            \
        }                                                                                          \
    } while (0)

// One SMBIOS structure: formatted area (type, length, handle, fields) plus its string set.
static void structure(Bytes &out, uint8_t type, Bytes fields, const std::vector<std::string> &strings) {
    uint8_t len = uint8_t(4 + fields.size());
    out.insert(out.end(), {type, len, uint8_t(out.size()), 0});
    out.insert(out.end(), fields.begin(), fields.end());
    for (const auto &s : strings) {
        out.insert(out.end(), s.begin(), s.end());
        out.push_back(0);
    }
    if (strings.empty())
        out.push_back(0);
    out.push_back(0);
}

struct Identity {
    std::string bios_vendor, bios_version, maker, product;
    bool vm_bit;
    uint8_t uuid_fill;  // 0x00 / 0xff are the "unset" patterns, anything else is a set UUID
    bool dimm_speed;
};

static Bytes raw_smbios(const Identity &id) {
    Bytes t;
    // Type 0 BIOS: vendor(1) version(2) start segment, date(3), ROM size, characteristics (8 bytes),
    // extension byte 1 at offset 18, extension byte 2 at offset 19 (bit 4 = virtual machine).
    Bytes bios = {1, 2, 0x00, 0xe8, 3, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, uint8_t(id.vm_bit ? 0x10 : 0x00)};
    structure(t, 0, bios, {id.bios_vendor, id.bios_version, "04/01/2014"});
    // Type 1 System: manufacturer(1) product(2) version(3) serial(4) UUID[16] wake-up type.
    Bytes sys = {1, 2, 3, 4};
    for (int i = 0; i < 16; ++i)
        sys.push_back(id.uuid_fill == 0x5a ? uint8_t(0x10 + i) : id.uuid_fill);
    sys.push_back(6);
    structure(t, 1, sys, {id.maker, id.product, "1.0", "SN123"});
    // Type 17 Memory Device: Size at offset 12 (MB), Speed at offset 21.
    Bytes mem(19, 0);
    mem[8] = 0x00;
    mem[9] = 0x20;  // 8192 MB at offsets 12..13 (fields start at offset 4)
    mem[17] = id.dimm_speed ? 0x40 : 0x00;
    mem[18] = id.dimm_speed ? 0x0c : 0x00;  // 3136 MT/s
    structure(t, 17, mem, {});
    structure(t, 127, {}, {});
    Bytes raw = {0, 3, 4, 0};
    uint32_t n = uint32_t(t.size());
    raw.insert(raw.end(), {uint8_t(n), uint8_t(n >> 8), uint8_t(n >> 16), uint8_t(n >> 24)});
    raw.insert(raw.end(), t.begin(), t.end());
    return raw;
}

static Bytes acpi_table(const std::string &sig, const std::string &oem, const std::string &table,
                        const std::string &creator, const std::string &body = "") {
    Bytes b(36, ' ');
    auto put = [&](size_t at, const std::string &s, size_t n) {
        for (size_t i = 0; i < n; ++i)
            b[at + i] = i < s.size() ? uint8_t(s[i]) : uint8_t(' ');
    };
    put(0, sig, 4);
    b[8] = 1;
    b[9] = 0;
    put(10, oem, 6);
    put(16, table, 8);
    for (int i = 24; i < 28; ++i)
        b[i] = 1;
    put(28, creator, 4);
    for (int i = 32; i < 36; ++i)
        b[i] = 1;
    b.insert(b.end(), body.begin(), body.end());
    uint32_t len = uint32_t(b.size());
    b[4] = uint8_t(len);
    b[5] = uint8_t(len >> 8);
    b[6] = uint8_t(len >> 16);
    b[7] = uint8_t(len >> 24);
    unsigned sum = 0;
    for (auto v : b)
        sum += v;
    b[9] = uint8_t(256 - (sum & 255));
    return b;
}

static Bytes edid_block(const char maker[3], uint32_t serial, uint8_t year_offset) {
    Bytes b(128, 0);
    const uint8_t header[] = {0, 255, 255, 255, 255, 255, 255, 0};
    std::copy(std::begin(header), std::end(header), b.begin());
    unsigned m = (unsigned(maker[0] - 'A' + 1) << 10) | (unsigned(maker[1] - 'A' + 1) << 5) |
                 unsigned(maker[2] - 'A' + 1);
    b[8] = uint8_t(m >> 8);
    b[9] = uint8_t(m);
    b[12] = uint8_t(serial);
    b[13] = uint8_t(serial >> 8);
    b[14] = uint8_t(serial >> 16);
    b[15] = uint8_t(serial >> 24);
    b[17] = year_offset;
    unsigned sum = 0;
    for (int i = 0; i < 127; ++i)
        sum += b[i];
    b[127] = uint8_t(256 - (sum & 255));
    return b;
}

static void test_smbios() {
    struct Case {
        Identity id;
        bool hit, vm_bit, uuid_default, speedless;
    } cases[] = {
        {{"SeaBIOS", "rel-1.16.2", "QEMU", "Standard PC (Q35 + ICH9, 2009)", false, 0x00, false}, true, false, true, true},
        {{"innotek GmbH", "VirtualBox", "innotek GmbH", "VirtualBox", false, 0x5a, false}, true, false, false, true},
        {{"VMware, Inc.", "VMW71.00V", "VMware, Inc.", "VMware7,1", true, 0x5a, true}, true, true, false, false},
        {{"Xen", "4.19.1", "Xen", "HVM domU", false, 0x5a, false}, true, false, false, true},
        {{"Dell Inc.", "1.21.0", "Dell Inc.", "OptiPlex 7090", false, 0x5a, true}, false, false, false, false},
    };
    for (const auto &c : cases) {
        auto r = smbios(raw_smbios(c.id));
        CHECK(r.valid);
        CHECK(r.hits.empty() != c.hit);
        CHECK(r.vm_bit == c.vm_bit);
        CHECK(r.uuid_default == c.uuid_default);
        CHECK(r.memory_devices == 1);
        CHECK((r.memory_without_speed == 1) == c.speedless);
        CHECK(r.types.count(0) == 1 && r.types.count(1) == 1 && r.types.count(17) == 1);
    }
    CHECK(!smbios({}).valid);
    auto bad = raw_smbios(cases[4].id);
    bad.resize(bad.size() - 3);  // cut the terminator: length field now overstates the data
    CHECK(!smbios(bad).valid);
}

static void test_acpi() {
    auto qemu = acpi(acpi_table("FACP", "BOCHS", "BXPC", "BXPC"));
    CHECK(qemu.valid && qemu.oem == "BOCHS" && !qemu.hit.empty());
    auto vbox = acpi(acpi_table("DSDT", "VBOX", "VBOXBIOS", "INTL", "VBOX__ VirtualBox"));
    CHECK(vbox.valid && !vbox.hit.empty());
    auto vmware = acpi(acpi_table("APIC", "VMWARE", "EFIAPIC", "VMW"));
    CHECK(vmware.valid && !vmware.hit.empty());
    auto xen = acpi(acpi_table("FACP", "Xen", "HVM", "HVML"));
    CHECK(xen.valid && !xen.hit.empty());
    auto dell = acpi(acpi_table("FACP", "DELL", "CBX3", "AMI"));
    CHECK(dell.valid && dell.hit.empty() && dell.signature == "FACP" && dell.table == "CBX3");
    auto broken = acpi_table("FACP", "DELL", "CBX3", "AMI");
    broken[9] ^= 1;
    CHECK(!acpi(broken).valid);
    CHECK(!acpi(Bytes(10, 0)).valid);
}

static void test_edid() {
    auto real = edid(edid_block("DEL", 0x4c4e3033, 31));
    CHECK(real.valid && real.manufacturer == "DEL" && !real.serial_missing && real.year == 2021);
    auto virt = edid(edid_block("RHT", 0, 24));  // QEMU/Red Hat virtual display, no serial
    CHECK(virt.valid && virt.manufacturer == "RHT" && virt.serial_missing);
    auto bad = edid_block("DEL", 1, 30);
    bad[127] ^= 1;
    CHECK(!edid(bad).valid);
    CHECK(!edid(Bytes(128, 0)).valid);
}

static void test_identity_rules() {
    CHECK(oui({0x52, 0x54, 0x00, 1, 2, 3}) == "QEMU/KVM");
    CHECK(oui({0x00, 0x16, 0x3e, 1, 2, 3}) == "Xen");
    CHECK(oui({0x08, 0x00, 0x27, 1, 2, 3}) == "VirtualBox");
    CHECK(oui({0x00, 0x50, 0x56, 1, 2, 3}) == "VMware");
    CHECK(oui({0x3c, 0xa8, 0x2a, 1, 2, 3}).empty());  // a physical vendor's OUI
    CHECK(oui({0x52, 0x54}).empty());
    CHECK(!subnet(0x0a00020fU).empty());
    CHECK(!subnet(0xc0a8380aU).empty());
    CHECK(!subnet(0xc0a87a64U).empty());
    CHECK(subnet(0xc0a8010aU).empty());  // 192.168.1.10, an ordinary home LAN
    CHECK(default_serial("To Be Filled By O.E.M."));
    CHECK(default_serial("0000000000"));
    CHECK(default_serial(""));
    CHECK(!default_serial("7XK2LN3"));
    CHECK(default_uuid("00000000-0000-0000-0000-000000000000"));
    CHECK(default_uuid("03000200-0400-0500-0006-000700080009"));
    CHECK(!default_uuid("4c4c4544-0058-4b10-8032-b7c04f4c4e33"));
    CHECK(hash_name("C:\\Users\\a\\Desktop\\d41d8cd98f00b204e9800998ecf8427e.exe"));
    CHECK(hash_name("/tmp/da39a3ee5e6b4b0d3255bfef95601890afd80709.bin"));
    CHECK(!hash_name("C:\\Users\\a\\Downloads\\invoice_march.exe"));
    CHECK(known_filename("C:\\sample.exe") && !known_filename("C:\\Users\\a\\setup.exe"));
    CHECK(suspicious_path("C:\\analysis\\x.exe") && !suspicious_path("C:\\Users\\a\\Downloads\\x.exe"));
    CHECK(bios_date("06/23/99") && !bios_date("03/14/2023"));
    CHECK(date_days("1970-01-01") == 0);
    CHECK(date_days("20240229") == 19782);
    CHECK(date_days("03/01/2024") == 19783);
    CHECK(date_days("2023-02-29") == -1);
    CHECK(date_days("13/01/2024") == -1);
    CHECK(match("Hardware: VBOX HARDDISK", vendors()) == "vbox");
    CHECK(match("Dell Inc.", vendors()).empty());
}

static void test_motion() {
    std::vector<Point> line;
    for (int i = 0; i < 50; ++i)
        line.push_back({i * 10, i * 10});
    auto l = motion(line, 2203);  // 1920x1080 diagonal
    CHECK(l.moves == 49 && l.straight == 48 && l.teleports == 0 && l.entropy < kLowEntropy);
    std::vector<Point> human;
    for (int i = 0; i < 60; ++i)
        human.push_back({int(400 + 200 * std::cos(i / 7.0)), int(300 + 150 * std::sin(i / 5.0))});
    auto h = motion(human, 2203);
    CHECK(h.moves > 50 && h.straight < h.moves / 2 && h.entropy > kLowEntropy);
    auto jump = motion({{0, 0}, {1900, 1060}, {0, 0}}, 2203);
    CHECK(jump.teleports == 2);
}

int main() {
    test_smbios();
    test_acpi();
    test_edid();
    test_identity_rules();
    test_motion();
    if (failures) {
        std::fprintf(stderr, "windows logic: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("windows logic: SMBIOS, ACPI, EDID, identity and motion fixtures passed");
    return 0;
}
