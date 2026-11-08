// Software-breakpoint self-check, compiled into both builds: a debugger that
// sets an INT3 (0xCC) or INT 3 (CD 03) breakpoint on the agent's own code
// changes its bytes. al-khaser SoftwareBreakpoints scans a function for 0xCC the
// same way. Only bytes up to the first RET of a tiny, known function are read,
// so compiler padding after the function is never mistaken for a breakpoint.
#include "lowlevel.hpp"

namespace perdedor {
namespace {
using namespace lowlevel;
__attribute__((noinline)) unsigned breakpoint_sentinel(unsigned value) {
    asm volatile("" : "+r"(value));
    return value ^ 0x5a5au;
}
constexpr unsigned kScanBytes = 32;  // Upper bound on the sentinel's compiled size (a few instructions).
struct Scan { unsigned char bytes[kScanBytes]{}; unsigned scanned = 0, int3 = 0, first_cc = 0xffu; };
void scan_probe(void* p) {
    auto& s = *static_cast<Scan*>(p);
    const auto* code = reinterpret_cast<const volatile unsigned char*>(&breakpoint_sentinel);
    for (unsigned i = 0; i < kScanBytes; ++i) {
        s.bytes[i] = code[i];
        s.scanned = i + 1;
        if (s.bytes[i] == 0xcc || (i && s.bytes[i - 1] == 0xcd && s.bytes[i] == 0x03)) {
            ++s.int3;
            if (s.first_cc == 0xffu) s.first_cc = i;
        }
        if (s.bytes[i] == 0xc3) break;  // End of the function (no immediates contain C3 here).
    }
}
std::vector<Finding> software_breakpoint(Context&) {
    const char* id = "design.software_breakpoint_entry";
    const char* name = "Own function breakpoint";
    Scan scan;
    const auto r = guard::run(scan_probe, &scan);
    if (r.faulted) return {fault_skip(id, name, Severity::High, r)};
    if (scan.scanned == 0 || scan.bytes[scan.scanned - 1] != 0xc3) {
        auto f = skipped(id, name, "Own code bytes checked for INT3 encodings.", Severity::High,
                         "Sentinel function end not found within the scan window");
        f.measurement = numbers({{"scanned_bytes", scan.scanned}});
        return {f};
    }
    volatile unsigned keep = breakpoint_sentinel(1);  // Keeps the function referenced and callable.
    (void)keep;
    return {measured(id, name,
                     "Reads the code of a small compiled function (entry to RET) for INT3 encodings without executing "
                     "patched bytes.",
                     Severity::High, scan.int3 != 0,
                     "Hidden hypervisor (EPT/altp2m) breakpoints such as DRAKVUF's read as the original bytes, so a "
                     "clean result says nothing about hypervisor-level tracing.",
                     numbers({{"scanned_bytes", scan.scanned}, {"int3_encodings", scan.int3},
                              {"first_int3_offset", scan.int3 ? static_cast<double>(scan.first_cc) : -1},
                              {"first_byte", scan.bytes[0]}}),
                     0.8)};
}
}  // namespace
PERDEDOR_REGISTER(software_breakpoint, "debugger.exception_tricks", "fast", false, "design.software_breakpoint_entry");
}  // namespace perdedor
