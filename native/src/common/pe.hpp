#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace perdedor::lowlevel {
// Bounds-checked subset of PE/COFF. No mapped address is dereferenced here.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
class PeImage {
  public:
    struct Section { std::string name; uint32_t rva, virtual_size, raw, raw_size, flags; };
    struct Export { std::string name; uint32_t rva, ordinal; bool forwarded; };
    explicit PeImage(const std::vector<unsigned char>& bytes, bool mapped = false) : bytes_(bytes), mapped_(mapped) { parse(); }
    bool valid() const { return valid_; }
    bool x64() const { return x64_; }
    uint32_t timestamp() const { return timestamp_; }
    uint32_t image_size() const { return image_size_; }
    const std::vector<Section>& sections() const { return sections_; }
    uint32_t directory(unsigned i) const { return i < 16 ? directories_[i][0] : 0; }
    uint32_t directory_size(unsigned i) const { return i < 16 ? directories_[i][1] : 0; }
    const unsigned char* at(uint32_t rva, size_t count) const {
        if (!valid_ || rva >= image_size_ || count > image_size_ - rva) return nullptr;
        if (mapped_ || rva < headers_) return raw(rva, count);
        for (const auto& s : sections_) {
            if (rva >= s.rva && static_cast<uint64_t>(rva) + count <= static_cast<uint64_t>(s.rva) + s.raw_size)
                return raw(static_cast<uint64_t>(s.raw) + rva - s.rva, count);
        }
        return nullptr;
    }
    uint32_t u32(uint32_t rva) const { const auto* p = at(rva, 4); return p ? read32(p) : 0; }
    uint64_t pointer(uint32_t rva) const {
        const auto* p = at(rva, x64_ ? 8 : 4); if (!p) return 0;
        return read32(p) | (x64_ ? static_cast<uint64_t>(read32(p + 4)) << 32 : 0);
    }
    std::string string(uint32_t rva, size_t limit = 512) const {
        std::string out;
        for (size_t i = 0; i < limit; ++i) {
            if (rva > UINT32_MAX - i) return {};
            const auto* p = at(rva + static_cast<uint32_t>(i), 1); if (!p) return {};
            if (!*p) return out;
            out += static_cast<char>(*p);
        }
        return {};  // Unterminated strings are never accepted.
    }
    std::vector<Export> exports(bool* complete = nullptr) const {
        if (complete) *complete = true;
        std::vector<Export> out; const uint32_t dir = directory(0), len = directory_size(0);
        if (!dir && !len) return out;
        const auto* p = at(dir, 40);
        if (!p) { if (complete) *complete = false; return out; }
        const uint32_t base = read32(p + 16), functions = read32(p + 20), names = read32(p + 24);
        const uint32_t addresses = read32(p + 28), name_table = read32(p + 32), ordinals = read32(p + 36);
        constexpr uint32_t kMaxExports = 65536;  // Parser resource cap, not a detector threshold.
        if (names > kMaxExports || functions > kMaxExports || !at(addresses, functions * 4ull) || !at(name_table, names * 4ull) || !at(ordinals, names * 2ull)) {
            if (complete) *complete = false;
            return out;
        }
        for (uint32_t i = 0; i < names; ++i) {
            const auto* op = at(ordinals + i * 2, 2); const unsigned ordinal = op[0] | unsigned(op[1]) << 8;
            if (ordinal >= functions) { if (complete) *complete = false; continue; }
            const auto name = string(u32(name_table + i * 4)); const auto rva = u32(addresses + ordinal * 4);
            if (name.empty()) { if (complete) *complete = false; continue; }
            out.push_back({name, rva, base + ordinal, rva >= dir && uint64_t(rva) < uint64_t(dir) + len});
        }
        return out;
    }
    bool relocation_mask(uint32_t start, size_t length, std::vector<bool>& mask) const {
        mask.assign(length, false); const uint32_t directory_rva = directory(5), size = directory_size(5);
        if (!directory_rva && !size) return true;
        if (!at(directory_rva, size)) return false;
        uint32_t offset = 0;
        while (offset < size) {
            if (size - offset < 8) return false;
            const uint32_t block = directory_rva + offset, page = u32(block), block_size = u32(block + 4);
            if (block_size < 8 || block_size > size - offset || block_size % 2) return false;
            for (uint32_t i = 8; i < block_size; i += 2) {
                const auto* e = at(block + i, 2); const unsigned word = e[0] | unsigned(e[1]) << 8;
                const unsigned type = word >> 12; if (!type) continue;
                const unsigned width = type == 10 ? 8 : (type == 3 ? 4 : 0);
                if (!width) return false;  // Do not report loader relocation differences as hooks.
                const uint64_t address = uint64_t(page) + (word & 4095);
                for (unsigned j = 0; j < width; ++j) if (address + j >= start && address + j - start < length) mask[address + j - start] = true;
            }
            offset += block_size;
        }
        return true;
    }
  private:
    const std::vector<unsigned char>& bytes_;
    bool mapped_ = false, valid_ = false, x64_ = false;
    uint32_t image_size_ = 0, headers_ = 0, timestamp_ = 0;
    uint32_t directories_[16][2]{};
    std::vector<Section> sections_;
    static uint32_t read32(const unsigned char* p) { return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }
    const unsigned char* raw(uint64_t offset, size_t count) const { return offset <= bytes_.size() && count <= bytes_.size() - offset ? bytes_.data() + offset : nullptr; }
    void parse() {
        const auto* dos = raw(0, 64); if (!dos || dos[0] != 'M' || dos[1] != 'Z') return;
        const uint32_t nt = read32(dos + 60); const auto* coff = raw(nt, 24);
        if (!coff || read32(coff) != 0x4550) return;
        const unsigned count = coff[6] | unsigned(coff[7]) << 8, opt_size = coff[20] | unsigned(coff[21]) << 8;
        const auto* opt = raw(uint64_t(nt) + 24, opt_size); if (!opt || opt_size < 96) return;
        const unsigned magic = opt[0] | unsigned(opt[1]) << 8; if (magic != 0x10b && magic != 0x20b) return;
        x64_ = magic == 0x20b; const unsigned dir_offset = x64_ ? 112 : 96;
        if (opt_size < dir_offset) return;
        image_size_ = read32(opt + 56); headers_ = read32(opt + 60); timestamp_ = read32(coff + 8);
        const unsigned dirs = std::min(16u, read32(opt + dir_offset - 4));
        if (dir_offset + dirs * 8 > opt_size || !image_size_ || headers_ > image_size_) return;
        for (unsigned i = 0; i < dirs; ++i) { directories_[i][0] = read32(opt + dir_offset + i * 8); directories_[i][1] = read32(opt + dir_offset + i * 8 + 4); }
        constexpr unsigned kMaxSections = 96;  // Windows loader PE section limit.
        if (count > kMaxSections) return;
        for (unsigned i = 0; i < count; ++i) {
            const auto* s = raw(uint64_t(nt) + 24 + opt_size + i * 40ull, 40); if (!s) return;
            size_t name_size = 0; while (name_size < 8 && s[name_size]) ++name_size;
            Section section{std::string(reinterpret_cast<const char*>(s), name_size), read32(s + 12), read32(s + 8), read32(s + 20), read32(s + 16), read32(s + 36)};
            if (section.rva > image_size_ || section.virtual_size > image_size_ - section.rva) return;
            sections_.push_back(section);
        }
        valid_ = true;
    }
};
}  // namespace perdedor::lowlevel
