// CPUID / RDTSC primitives for both targets (GCC/Clang/MinGW builtins).
#pragma once
#include <cstdint>
#include <string>
#include "guard.hpp"

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#define PERDEDOR_X86 1
#include <cpuid.h>
#include <x86intrin.h>
#else
#define PERDEDOR_X86 0
#endif

namespace perdedor {
namespace x86 {

struct Regs {
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
};

inline Regs cpuid(uint32_t leaf, uint32_t subleaf = 0) {
    Regs r;
#if PERDEDOR_X86
    __cpuid_count(leaf, subleaf, r.eax, r.ebx, r.ecx, r.edx);
#else
    (void)leaf; (void)subleaf;
#endif
    return r;
}

// CPUID with a volatile asm statement and a memory clobber, for timing loops:
// the compiler can neither drop nor move it (the reason the CHIMERA cpuid-timing
// harness hand-codes it too).
inline void cpuid_serialize(uint32_t leaf) {
#if PERDEDOR_X86
    uint32_t a = leaf, b = 0, c = 0, d = 0;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) : : "memory");
#else
    (void)leaf;
#endif
}

inline bool available() {
    if (!PERDEDOR_X86) return false;
    // Linux ARCH_SET_CPUID can disable CPUID for a thread. Check before using
    // string/topology helpers, whose C++ ownership must not cross a longjmp.
    Regs regs;
    return !guard::run([](void* out) { *static_cast<Regs*>(out) = cpuid(0); }, &regs).faulted;
}

inline uint64_t rdtsc() {
#if PERDEDOR_X86
    return __rdtsc();
#else
    return 0;
#endif
}

// Vendor string of a hypervisor leaf: EBX, ECX, EDX (KVM/Xen/Hyper-V/VMware convention).
inline std::string hv_vendor(const Regs& r) {
    char s[13] = {0};
    for (int i = 0; i < 4; ++i) {
        s[i] = static_cast<char>((r.ebx >> (8 * i)) & 0xff);
        s[4 + i] = static_cast<char>((r.ecx >> (8 * i)) & 0xff);
        s[8 + i] = static_cast<char>((r.edx >> (8 * i)) & 0xff);
    }
    std::string out;
    for (char c : s)
        if (c >= 0x20 && c < 0x7f) out += c;
    return out;
}

// Leaf 0 vendor: EBX, EDX, ECX.
inline std::string cpu_vendor() {
    Regs r = cpuid(0);
    char s[13] = {0};
    for (int i = 0; i < 4; ++i) {
        s[i] = static_cast<char>((r.ebx >> (8 * i)) & 0xff);
        s[4 + i] = static_cast<char>((r.edx >> (8 * i)) & 0xff);
        s[8 + i] = static_cast<char>((r.ecx >> (8 * i)) & 0xff);
    }
    return std::string(s);
}

// Brand string exactly as the 48 bytes of leaves 0x80000002..4 hold it (up to
// the first NUL), without trimming: Bochs quirks live in the padding.
inline std::string raw_brand_string() {
    if (cpuid(0x80000000).eax < 0x80000004) return {};
    std::string out;
    for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
        Regs r = cpuid(leaf);
        for (uint32_t v : {r.eax, r.ebx, r.ecx, r.edx})
            for (int i = 0; i < 4; ++i) {
                char c = static_cast<char>((v >> (8 * i)) & 0xff);
                if (!c) return out;
                out += c;
            }
    }
    return out;
}

inline std::string brand_string() {
    if (cpuid(0x80000000).eax < 0x80000004) return {};
    std::string out;
    for (uint32_t leaf = 0x80000002; leaf <= 0x80000004; ++leaf) {
        Regs r = cpuid(leaf);
        for (uint32_t v : {r.eax, r.ebx, r.ecx, r.edx})
            for (int i = 0; i < 4; ++i) {
                char c = static_cast<char>((v >> (8 * i)) & 0xff);
                if (c) out += c;
            }
    }
    size_t a = out.find_first_not_of(' '), b = out.find_last_not_of(' ');
    return a == std::string::npos ? std::string() : out.substr(a, b - a + 1);
}

}  // namespace x86
}  // namespace perdedor
