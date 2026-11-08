#include "lowlevel.hpp"
#include <array>
#include <cstring>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace perdedor {
namespace {
using namespace lowlevel;
// Xen public arch-x86/cpuid.h: scan 0x100-aligned relocated ranges.
constexpr uint32_t kHvFirst = 0x40000000u, kHvLast = 0x4001ff00u, kHvStride = 0x100u;
constexpr unsigned kMaxTopologyLevels = 32;  // CPUID subleaf safety cap; Intel SDM CPUID.
struct HvRange { uint32_t base; x86::Regs regs; };
std::vector<HvRange> ranges() {
    std::vector<HvRange> found;
    for (uint32_t leaf = kHvFirst; leaf <= kHvLast; leaf += kHvStride) {
        const auto r = x86::cpuid(leaf);
        // Invalid basic leaves may alias the maximum basic leaf on bare metal.
        if (r.eax >= leaf && r.eax < leaf + kHvStride && (r.ebx || r.ecx || r.edx)) found.push_back({leaf, r});
    }
    return found;
}
Json regs_json(const x86::Regs& r) { return numbers({{"eax", r.eax}, {"ebx", r.ebx}, {"ecx", r.ecx}, {"edx", r.edx}}); }
std::vector<Finding> brand(Context&) {
    if (!x86::available()) return {skipped("env.cpu_brand_string", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    const auto s = x86::brand_string();
    if (s.empty()) return {skipped("env.cpu_brand_string", "CPU brand", "Extended CPUID brand string.", Severity::High, "Brand leaves unavailable")};
    const auto text = lower(s);
    std::vector<std::string> matches;
    for (const auto* token : {"qemu", "virtual", "vmware", "kvm", "xen", "bochs", "bhyve", "tcg"})
        if (text.find(token) != std::string::npos) matches.emplace_back(token);
    Json ev = Json::object(); ev.set("brand", s); ev.set("matches", Json(matches));
    return {measured("env.cpu_brand_string", "CPU brand", "CPUID brand identifies a virtual or emulated processor.", Severity::High,
                     !matches.empty(), ev, numbers({{"matches", static_cast<double>(matches.size())}}))};
}
std::vector<Finding> leaf_ranges(Context&) {
    if (!x86::available()) return {skipped("env.cpuid_hypervisor_leaf_range", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    Json ev = Json::array();
    for (const auto& r : ranges()) {
        Json row = regs_json(r.regs); row.set("base", hex(r.base)); row.set("vendor", x86::hv_vendor(r.regs)); ev.push(row);
    }
    return {measured("env.cpuid_hypervisor_leaf_range", "Relocated hypervisor leaves", "Scans all 512 aligned bases, including Xen behind Viridian and KVM behind Hyper-V.", Severity::High,
                     ev.size() != 0, ev, numbers({{"bases_scanned", 512}, {"ranges", static_cast<double>(ev.size())}}), 0.95)};
}
std::vector<Finding> enlightenments(Context&) {
    if (!x86::available()) return {skipped("env.cpuid_enlightenments", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    Json ev = Json::array();
    // TLFS interface signature is Hv#1; SimpleVisor uses Shv\0 (upstream CPUID_SIGNATURE).
    constexpr uint32_t kHyperVInterface = 0x31237648, kSimpleVisorInterface = 0x00766853;
    for (uint32_t base = kHvFirst; base <= kHvLast; base += kHvStride) {
        const auto interface = x86::cpuid(base + 1);
        if (interface.eax != kHyperVInterface && interface.eax != kSimpleVisorInterface) continue;
        Json row = Json::object(); row.set("base", hex(base)); row.set("interface", hex(interface.eax));
        const auto limit = x86::cpuid(base).eax;
        for (uint32_t i = 2; i <= 6 && base + i <= limit && limit < base + kHvStride; ++i)
            row.set(hex(base + i), regs_json(x86::cpuid(base + i)));
        ev.push(row);
    }
    return {measured("env.cpuid_enlightenments", "Hyper-V/Viridian interfaces", "Checks interface signatures and records feature, recommendation and limit leaves.", Severity::High,
                     ev.size() != 0, ev, numbers({{"interfaces", static_cast<double>(ev.size())}}), 0.95)};
}
std::vector<Finding> vendor_brand(Context&) {
    if (!x86::available()) return {skipped("env.cpu_vendor_brand_consistency", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    const auto vendor = x86::cpu_vendor(), text = x86::brand_string();
    if (text.empty()) return {skipped("env.cpu_vendor_brand_consistency", "CPU vendor/brand", "Leaf 0 versus extended brand.", Severity::Medium, "No brand leaves")};
    const bool mismatch = (text.find("Intel") != std::string::npos && vendor != "GenuineIntel") ||
                          (text.find("AMD") != std::string::npos && vendor != "AuthenticAMD");
    const char* bochs = bochs_brand_quirk(x86::raw_brand_string());
    // Pafish bochs_cpu_amd2 queries the K8 "easter egg" leaf 0x8FFFFFFF; current
    // AMD parts also return zeros there, so it is recorded, never used alone.
    const bool amd = vendor == "AuthenticAMD";
    const uint32_t egg = amd ? x86::cpuid(0x8fffffffu).ecx : 0;
    Json ev = Json::object(); ev.set("vendor", vendor); ev.set("brand", text);
    if (bochs) ev.set("bochs_quirk", bochs);
    if (amd) ev.set("amd_easter_egg_ecx", hex(egg));
    return {measured("env.cpu_vendor_brand_consistency", "CPU vendor/brand", "Vendor and brand disagree on Intel versus AMD, or the raw brand string is one only Bochs reports.", Severity::Medium,
                     mismatch || bochs, ev, numbers({{"mismatches", mismatch ? 1.0 : 0.0}, {"bochs_quirk", bochs != nullptr}}), bochs ? 0.95 : 0.75)};
}
std::vector<Finding> feature_consistency(Context&) {
    if (!x86::available()) return {skipped("env.cpu_feature_consistency", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    const auto r = x86::cpuid(1), ext = x86::cpuid(0x80000000);
    const auto amd = ext.eax >= 0x80000001 ? x86::cpuid(0x80000001) : x86::Regs{};
    const bool hypervisor = r.ecx & (1u << 31), xsave = r.ecx & (1u << 26), osxsave = r.ecx & (1u << 27);
    const bool vmx = r.ecx & (1u << 5), svm = amd.ecx & (1u << 2);
    const bool invariant = ext.eax >= 0x80000007 && (x86::cpuid(0x80000007).edx & (1u << 8));
    const bool x2apic = r.ecx & (1u << 21), deadline = r.ecx & (1u << 24);
    std::vector<std::string> issues, cautions;
    const auto hv = ranges();
    if (!hypervisor && !hv.empty()) issues.emplace_back("hypervisor bit clear but a hypervisor range is advertised");
    if (osxsave && !xsave) issues.emplace_back("OSXSAVE without XSAVE");
    if ((r.ecx & (1u << 28)) && !xsave) issues.emplace_back("AVX without XSAVE");
    const auto vendor = x86::cpu_vendor();
    if ((vendor == "GenuineIntel" && svm) || (vendor == "AuthenticAMD" && vmx)) issues.emplace_back("virtualization feature belongs to the other vendor");
    // Model-scoped expectations; absence alone is configurable CPUID policy.
    const auto b = x86::brand_string();
    if (b.find("i7-7700") != std::string::npos || b.find("E5-2670 v3") != std::string::npos) {
        if (!invariant) cautions.emplace_back("listed modern Intel model lacks invariant TSC");
        if (!x2apic) cautions.emplace_back("listed modern Intel model lacks x2APIC");
        if (!deadline) cautions.emplace_back("listed modern Intel model lacks TSC deadline");
        if (!vmx) cautions.emplace_back("listed Intel model hides VMX (firmware/policy can do this)");
    }
    if (b.find("Ryzen 5 3600") != std::string::npos && !svm) cautions.emplace_back("listed AMD model hides SVM (firmware/policy can do this)");
    Json ev = Json::object(); ev.set("contradictions", Json(issues)); ev.set("model_cautions", Json(cautions));
    auto m = numbers({{"leaf1_ecx", r.ecx}, {"extended_ecx", amd.ecx}, {"vmx", vmx}, {"svm", svm},
                      {"xsave", xsave}, {"osxsave", osxsave}, {"x2apic", x2apic}, {"tsc_deadline", deadline},
                      {"invariant_tsc", invariant}, {"contradictions", static_cast<double>(issues.size())},
                      {"model_cautions", static_cast<double>(cautions.size())}});
    return {measured("env.cpu_feature_consistency", "CPU feature consistency", "Architectural contradictions plus model-specific missing features; firmware policy can hide virtualization features.", Severity::Medium,
                     !issues.empty() || !cautions.empty(), ev, m, issues.empty() ? 0.3 : 0.8)};
}
struct Topology { unsigned logical = 0, smt = 0; Json levels = Json::array(); };
Topology topology(uint32_t leaf) {
    Topology t;
    for (unsigned i = 0; i < kMaxTopologyLevels; ++i) {
        const auto r = x86::cpuid(leaf, i);
        const unsigned type = (r.ecx >> 8) & 255, count = r.ebx & 65535;
        if (!type || !count) break;
        t.levels.push(regs_json(r)); t.logical = std::max(t.logical, count);
        if (type == 1) t.smt = count;
    }
    return t;
}
std::vector<Finding> topology_consistency(Context&) {
    if (!x86::available()) return {skipped("env.cpu_topology_consistency", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    const auto max = x86::cpuid(0).eax;
    const auto b = max >= 0xb ? topology(0xb) : Topology{};
    const auto f = max >= 0x1f ? topology(0x1f) : Topology{};
    const unsigned os = os_processors(), package = f.logical ? f.logical : b.logical, smt = f.smt ? f.smt : b.smt;
    const auto cache = max >= 4 ? x86::cpuid(4) : x86::Regs{};
    const unsigned cores = (cache.eax & 31) ? ((cache.eax >> 26) & 63) + 1 : 0;
    std::vector<std::string> issues, cautions;
    if (b.logical && f.logical && b.logical != f.logical) issues.emplace_back("leaf B and 1F package counts disagree");
    if (smt && package && package % smt) issues.emplace_back("package thread count is not a multiple of SMT width");
    if (cores && package && cores > package) issues.emplace_back("leaf 4 cores exceed topology logical processors");
    if (os && package && os % package) cautions.emplace_back("OS online count is not a whole number of packages (offline CPUs/cpusets can explain)");
    // Exact tokens with delimiter prevent matching i7-7700 against i7-7700HQ.
    // Cores/threads from the vendors' specification pages (Intel ARK,
    // https://ark.intel.com; AMD, https://www.amd.com/en/products/specifications).
    // VMAware THREAD_COUNT / CPU_HEURISTIC compare similar tables.
    struct Model { const char* token; unsigned cores, threads; };
    constexpr Model models[] = {
        {"i5-8250U", 4, 8},      {"i7-7700", 4, 8},       {"i7-8700", 6, 12},       {"i7-10700", 8, 16},
        {"i9-9900K", 8, 16},     {"i7-12700", 12, 20},    {"i7-13700HX", 16, 24},   {"i9-13900K", 24, 32},
        {"E5-2670 v3", 12, 24},  {"E5-2680 v4", 14, 28},  {"Gold 6130", 16, 32},    {"Ryzen 5 3600", 6, 12},
        {"Ryzen 7 5800X", 8, 16}, {"Ryzen 9 5900X", 12, 24}, {"EPYC 7742", 64, 128}};
    unsigned expected = 0;
    const auto brand = x86::brand_string();
    for (const auto& model : models) {
        const auto at = brand.find(model.token);
        if (at == std::string::npos) continue;
        const size_t end = at + std::strlen(model.token);
        if (end != brand.size() && brand[end] != ' ' && brand[end] != '@') continue;
        expected = model.threads;
        if (os > model.threads) issues.emplace_back("more online threads than the listed model has");
        if (package && package != model.threads && package != model.cores)
            cautions.emplace_back("package differs from listed model with SMT enabled or disabled");
        if (os > 1 && os % 2) cautions.emplace_back("odd online thread count for listed even-core model");
    }
    Json ev = Json::object(); ev.set("brand", brand); ev.set("leaf_b", b.levels); ev.set("leaf_1f", f.levels); ev.set("contradictions", Json(issues)); ev.set("cautions", Json(cautions));
    return {measured("env.cpu_topology_consistency", "CPU topology consistency", "Compares CPUID topology/cache counts with OS online CPUs and a small sourced model table. Affinity, hotplug, SMT and multiple sockets affect interpretation.", Severity::Medium,
                     !issues.empty() || !cautions.empty(), ev,
                     numbers({{"os_online_threads", os}, {"package_threads", package}, {"smt_width", smt},
                              {"leaf4_max_cores", cores}, {"model_threads", expected}, {"contradictions", static_cast<double>(issues.size())}}),
                     issues.empty() ? 0.3 : 0.7)};
}
std::vector<Finding> caches(Context&) {
    if (!x86::available()) return {skipped("env.cpu_cache_descriptors", "CPUID probe", "CPU enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    const auto max = x86::cpuid(0).eax, ext = x86::cpuid(0x80000000).eax;
    const uint32_t leaf = x86::cpu_vendor() == "AuthenticAMD" && ext >= 0x8000001d ? 0x8000001d : (max >= 4 ? 4 : 0);
    unsigned count = 0, descriptors = 0; uint64_t bytes = 0;
    if (leaf) for (unsigned i = 0; i < kMaxTopologyLevels; ++i) {
        const auto r = x86::cpuid(leaf, i); if (!(r.eax & 31)) break;
        ++count; bytes += static_cast<uint64_t>((r.ebx & 4095) + 1) * (((r.ebx >> 12) & 1023) + 1) *
                          (((r.ebx >> 22) & 1023) + 1) * (static_cast<uint64_t>(r.ecx) + 1);
    }
    if (max >= 2) {
        auto r = x86::cpuid(2); const uint32_t vals[] = {r.eax & ~255u, r.ebx, r.ecx, r.edx};
        for (uint32_t v : vals) if (!(v & 0x80000000u)) for (unsigned i = 0; i < 4; ++i) if ((v >> (i * 8)) & 255) ++descriptors;
    }
    const bool legacy_amd = ext >= 0x80000006 && ((x86::cpuid(0x80000006).ecx >> 16) != 0);
    if (!leaf && max < 2 && !legacy_amd) return {skipped("env.cpu_cache_descriptors", "CPU caches", "Cache descriptor visibility.", Severity::Low, "No supported cache enumeration leaves")};
    return {measured("env.cpu_cache_descriptors", "CPU caches", "No deterministic, legacy descriptor or AMD L2 cache information is exposed.", Severity::Low,
                     !count && !descriptors && !legacy_amd, "Legacy leaf 2 includes TLB descriptors; absence is conservative.",
                     numbers({{"deterministic_caches", count}, {"legacy_descriptor_bytes", descriptors}, {"amd_legacy_l2", legacy_amd}, {"total_cache_bytes", static_cast<double>(bytes)}}), 0.4)};
}
#pragma pack(push, 1)
struct TableRegister { uint16_t limit = 0; uintptr_t base = 0; };
#pragma pack(pop)
void sidt_probe(void* p) { asm volatile("sidt %0" : "=m"(*static_cast<TableRegister*>(p))); }
void sgdt_probe(void* p) { asm volatile("sgdt %0" : "=m"(*static_cast<TableRegister*>(p))); }
void sldt_probe(void* p) { asm volatile("sldt %0" : "=m"(*static_cast<uint16_t*>(p))); }
void str_probe(void* p) { asm volatile("str %0" : "=m"(*static_cast<uint16_t*>(p))); }
void smsw_probe(void* p) { asm volatile("smsw %0" : "=m"(*static_cast<uint16_t*>(p))); }
std::vector<Finding> descriptors(Context&) {
    TableRegister idt{}, gdt{}; uint16_t ldt = 0, tr = 0, msw = 0;
    const auto a = guard::run(sidt_probe, &idt), b = guard::run(sgdt_probe, &gdt), c = guard::run(sldt_probe, &ldt),
               d = guard::run(str_probe, &tr), e = guard::run(smsw_probe, &msw);
    const unsigned completed = !a.faulted + !b.faulted + !c.faulted + !d.faulted + !e.faulted;
    Json ev = Json::object(); ev.set("idt_base", hex(idt.base)); ev.set("gdt_base", hex(gdt.base)); ev.set("note", "UMIP may fault or the OS may emulate these instructions; descriptor placement is not decisive on modern OSes.");
    auto m = numbers({{"sidt_fault", a.code}, {"sgdt_fault", b.code}, {"sldt_fault", c.code}, {"str_fault", d.code},
                      {"smsw_fault", e.code}, {"idt_limit", idt.limit}, {"gdt_limit", gdt.limit}, {"ldt_selector", ldt}, {"tr_selector", tr}, {"machine_status", msw}, {"completed", completed}});
    if (!completed) { auto f = skipped("env.cpu_descriptor_tables", "Descriptor tables", "Guarded SIDT/SGDT/SLDT/STR/SMSW.", Severity::Low, "All instructions blocked, possibly UMIP"); f.evidence = ev; f.measurement = m; return {f}; }
    // al-khaser AntiVM/Generic.cpp idt_trick / gdt_trick ((base >> 24) == 0xff)
    // and str_trick (STR bytes 00 40, from Scoopy). These describe 32-bit
    // Windows XP-era guests; they are evaluated only for a native 32-bit process
    // (a WOW64 process sees truncated 64-bit kernel addresses).
    constexpr uint32_t kHistoricalHighByte = 0xff;
    constexpr uint16_t kVmwareTaskRegister = 0x4000;
    bool native32 = sizeof(uintptr_t) == 4;
#ifdef _WIN32
    BOOL wow64 = FALSE;
    if (native32 && IsWow64Process(GetCurrentProcess(), &wow64) && wow64) native32 = false;
#endif
    std::vector<std::string> hits;
    if (native32 && !a.faulted && ((idt.base >> 24) & 255) == kHistoricalHighByte) hits.emplace_back("idt_trick");
    if (native32 && !b.faulted && ((gdt.base >> 24) & 255) == kHistoricalHighByte) hits.emplace_back("gdt_trick");
    if (native32 && !d.faulted && tr == kVmwareTaskRegister) hits.emplace_back("str_trick");
    ev.set("legacy_rules_evaluated", native32); ev.set("legacy_hits", Json(hits));
    return {measured("env.cpu_descriptor_tables", "Descriptor tables", "Guarded SIDT/SGDT/SLDT/STR/SMSW (Red Pill / No Pill / Scoopy). Historical rules apply to native 32-bit guests only; very low discrimination on modern 64-bit systems.", Severity::Low, !hits.empty(), ev, m, 0.15)};
}
struct Port { uint32_t command = 0, a = 0, b = 0, c = 0, d = 0; };
void vmware_port(void* p) {
    auto& r = *static_cast<Port*>(p);
    uint32_t a = 0x564d5868, b = ~0x564d5868u, c = r.command, d = 0x5658;
    asm volatile("inl %%dx,%%eax" : "+a"(a), "+b"(b), "+c"(c), "+d"(d) : : "memory");
    r.a = a; r.b = b; r.c = c; r.d = d;
}
std::vector<Finding> backdoor(Context&) {
    Port version{0x0a}, memory{0x14}; const auto a = guard::run(vmware_port, &version), b = guard::run(vmware_port, &memory);
    if (a.code == guard::kUnavailable || b.code == guard::kUnavailable) return {fault_skip("env.vmware_backdoor", "VMware backdoor", Severity::High, a)};
    const bool match = !a.faulted && version.b == 0x564d5868 && version.a != 0xffffffff;
    Json ev = Json::object(); ev.set("version_eax", hex(version.a)); ev.set("version_ebx", hex(version.b)); ev.set("memory_eax", hex(memory.a));
    return {measured("env.vmware_backdoor", "VMware backdoor", "Read-only get-version and memory-size I/O commands at port 0x5658; expected privilege faults are negative results.", Severity::High, match, ev,
                     numbers({{"version_fault", a.code}, {"memory_fault", b.code}, {"version", version.a}, {"memory_reply", memory.a}}), 0.98)};
}
void virtualpc_probe(void* p) {
    uint32_t a = 1, b = 0, c = 0, d = 0;
    asm volatile(".byte 0x0f,0x3f,0x07,0x0b" : "+a"(a), "+b"(b), "+c"(c), "+d"(d) : : "cc", "memory");
    *static_cast<uint32_t*>(p) = b;
}
std::vector<Finding> virtualpc(Context&) {
    uint32_t reply = ~0u; const auto r = guard::run(virtualpc_probe, &reply);
    if (r.code == guard::kUnavailable) return {fault_skip("env.virtualpc_opcode", "VirtualPC opcode", Severity::High, r)};
    return {measured("env.virtualpc_opcode", "VirtualPC opcode", "Guarded 0F 3F 07 0B signature; unsupported instructions should fault.", Severity::High,
                     !r.faulted && reply == 0, "VirtualPC version-query sequence.", numbers({{"fault_code", r.code}, {"ebx", reply}}), 0.9)};
}
// Call number chosen outside every documented range (Xen < 64, KVM < 32,
// Hyper-V call codes are 16-bit with this one unassigned) so no hypercall can run.
constexpr uintptr_t kInvalidHypercall = 0x0badc0de;
void vmcall_probe(void* p) {
    uintptr_t a = kInvalidHypercall, b = 0, c = 0, d = 0;
    asm volatile(".byte 0x0f,0x01,0xc1" : "+a"(a), "+b"(b), "+c"(c), "+d"(d) : : "cc", "memory");
    *static_cast<uintptr_t*>(p) = a;
}
void vmmcall_probe(void* p) {
    uintptr_t a = kInvalidHypercall, b = 0, c = 0, d = 0;
    asm volatile(".byte 0x0f,0x01,0xd9" : "+a"(a), "+b"(b), "+c"(c), "+d"(d) : : "cc", "memory");
    *static_cast<uintptr_t*>(p) = a;
}
std::vector<Finding> hypercalls(Context&) {
    uintptr_t a = kInvalidHypercall, b = kInvalidHypercall; const auto x = guard::run(vmcall_probe, &a), y = guard::run(vmmcall_probe, &b);
    if (x.code == guard::kUnavailable || y.code == guard::kUnavailable) return {fault_skip("env.hypercall_behavior", "Hypercall behaviour", Severity::Medium, x)};
    Json ev = Json::object(); ev.set("vmcall_return", hex(a)); ev.set("vmmcall_return", hex(b)); ev.set("call_number", hex(kInvalidHypercall));
    ev.set("note", "Bare metal raises #UD for both. Xen and KVM answer a CPL3 hypercall with -EPERM in RAX instead of a fault (xen/arch/x86/hvm/hypercall.c, arch/x86/kvm/x86.c).");
    return {measured("env.hypercall_behavior", "Hypercall behaviour", "Executes CPL3 VMCALL and VMMCALL with an invalid call number under the fault guard; returning instead of raising #UD means a hypervisor intercepted the instruction.", Severity::Medium,
                     !x.faulted || !y.faulted, ev, numbers({{"vmcall_fault", x.code}, {"vmmcall_fault", y.code}, {"vmcall_returned", !x.faulted}, {"vmmcall_returned", !y.faulted},
                             {"vmcall_rax_changed", !x.faulted && a != kInvalidHypercall}, {"vmmcall_rax_changed", !y.faulted && b != kInvalidHypercall}}), 0.7)};
}
struct Quirks { uint32_t bsf = 0x12345678, bsr = 0x12345678, shifted = 0x1234; unsigned char zf_bsf = 0, zf_bsr = 0; };
void quirks_probe(void* p) {
    auto& q = *static_cast<Quirks*>(p); uint32_t zero = 0, source = 0xabcd;
    asm volatile("bsfl %2,%0; setz %1" : "+r"(q.bsf), "=qm"(q.zf_bsf) : "r"(zero) : "cc");
    asm volatile("bsrl %2,%0; setz %1" : "+r"(q.bsr), "=qm"(q.zf_bsr) : "r"(zero) : "cc");
    asm volatile("shldw $17,%w1,%w0" : "+r"(q.shifted) : "r"(source) : "cc");
}
std::vector<Finding> quirks(Context&) {
    Quirks q; const auto r = guard::run(quirks_probe, &q);
    if (r.faulted) return {fault_skip("env.cpu_emulation_quirks", "Instruction semantics", Severity::Low, r)};
    // Intel SDM BSF/BSR define ZF for source zero but leave destination undefined;
    // SHLD count > operand width is undefined. Never classify those values alone.
    return {measured("env.cpu_emulation_quirks", "Instruction semantics", "Records undefined BSF/BSR destinations and 16-bit SHLD count 17; only a violation of defined zero-flag semantics is detected.", Severity::Low,
                     !q.zf_bsf || !q.zf_bsr, "Undefined results are observations, not portable emulator signatures.",
                     numbers({{"bsf_destination", q.bsf}, {"bsr_destination", q.bsr}, {"shld_destination", q.shifted & 65535}, {"bsf_zf", q.zf_bsf}, {"bsr_zf", q.zf_bsr}}), 0.4)};
}
}  // namespace
PERDEDOR_REGISTER(brand, "cpu.brand_string", "fast", false, "env.cpu_brand_string");
PERDEDOR_REGISTER(leaf_ranges, "cpu.hypervisor_leaf_range", "fast", false, "env.cpuid_hypervisor_leaf_range");
PERDEDOR_REGISTER(enlightenments, "cpu.hypervisor_leaf_range", "fast", false, "env.cpuid_enlightenments");
PERDEDOR_REGISTER(vendor_brand, "cpu.feature_consistency", "fast", false, "env.cpu_vendor_brand_consistency");
PERDEDOR_REGISTER(feature_consistency, "cpu.feature_consistency", "fast", false, "env.cpu_feature_consistency");
PERDEDOR_REGISTER(topology_consistency, "cpu.topology_consistency", "fast", false, "env.cpu_topology_consistency");
PERDEDOR_REGISTER(caches, "cpu.feature_consistency", "fast", false, "env.cpu_cache_descriptors");
PERDEDOR_REGISTER(descriptors, "cpu.descriptor_tables", "fast", false, "env.cpu_descriptor_tables");
PERDEDOR_REGISTER(backdoor, "cpu.vmware_backdoor", "fast", false, "env.vmware_backdoor");
PERDEDOR_REGISTER(virtualpc, "cpu.undefined_instruction_behaviour", "fast", false, "env.virtualpc_opcode");
PERDEDOR_REGISTER(hypercalls, "cpu.undefined_instruction_behaviour", "fast", false, "env.hypercall_behavior");
PERDEDOR_REGISTER(quirks, "cpu.emulation_quirks", "fast", false, "env.cpu_emulation_quirks");
}  // namespace perdedor
