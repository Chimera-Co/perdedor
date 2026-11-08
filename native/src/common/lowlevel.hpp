// Shared helpers for the low-level probes (CPU, timing, debugger, instrumentation):
// robust statistics, bounded operator parameters, finding builders, clocks and
// the bounded byte parsers used by the hook scanners. Everything here is pure or
// read-only; probes that can fault go through guard::run (guard.hpp).
#pragma once
#include "../core/perdedor.hpp"
#include "guard.hpp"
#include "x86.hpp"
#include <algorithm>
#include <cmath>
#include <cctype>
#include <limits>
#include <vector>

namespace perdedor::lowlevel {
struct Statistics {
    size_t count = 0;
    double min = 0, p5 = 0, p25 = 0, median = 0, p75 = 0, p90 = 0, p95 = 0, p99 = 0, max = 0;
    double mean = 0, trimmed_mean = 0, mad = 0;
    Json json() const;
};
// Nearest-rank percentiles; even medians average the middle pair; symmetric 10%
// trim; MAD about the median. Non-finite values are dropped.
// https://www.itl.nist.gov/div898/handbook/eda/section3/eda35h.htm
Statistics statistics(std::vector<double> values);
// Nearest-rank percentile of an ascending, non-empty vector (q in (0,1]).
double nearest_rank(const std::vector<double>& sorted, double q);
double statistical_confidence(const Statistics& stats, double ceiling = 0.8);
long long bounded_int(const Context&, const char*, long long, long long, long long);
double bounded_double(const Context&, const char*, double, double, double);
Json numbers(std::initializer_list<std::pair<const char*, double>> values);
std::string hex(uint64_t value);
std::string lower(std::string text);
// Remediation text emitted with a finding (the catalog entry holds the full fix).
const char* remediation_for(const char* relative_id);
Finding measured(const char* id, const char* name, const char* description, Severity severity,
                 bool detected, Json evidence, Json measurement, double confidence = 0.9);
Finding fault_skip(const char* id, const char* name, Severity severity, guard::Result result);

struct CounterAccess { bool rdtsc = false, rdtscp = false; uint32_t tsc_fault = 0, tscp_fault = 0; };
CounterAccess counter_access();
// LFENCE ordering for statistical probes; the compatibility avg10 uses raw RDTSC.
uint64_t ordered_tsc();
double monotonic_ns();
double wall_ns();
double tick_ns();
void bounded_sleep(unsigned milliseconds);
unsigned os_processors();

// Pins the calling thread to the logical CPU it is running on and restores the
// previous affinity on destruction, so a timing loop is not split across CPUs
// with different TSC offsets (the CHIMERA cpuid-timing harness pins as well).
// Never construct inside a guarded probe.
class CpuPin {
  public:
    CpuPin();
    ~CpuPin();
    CpuPin(const CpuPin&) = delete;
    CpuPin& operator=(const CpuPin&) = delete;
    bool pinned() const { return pinned_; }
    int cpu() const { return cpu_; }

  private:
    bool pinned_ = false;
    int cpu_ = -1;
    unsigned char saved_[128]{};  // Opaque saved affinity (cpu_set_t prefix or DWORD_PTR).
};

// Bounded byte parsers shared by the Windows scanner and host fixture tests.
enum class Prologue { Ordinary, Jump, PushReturn, Breakpoint, ReturnOnly };
Prologue prologue(const unsigned char* bytes, size_t size, bool x64);
bool syscall_stub(const unsigned char* bytes, size_t size, bool x64);
const char* prologue_name(Prologue kind);

// Decoded control transfer at a function entry. `address` is where `bytes` was
// read from. A direct branch yields `target`; an indirect JMP [mem] yields the
// address of the pointer slot in `slot` (the caller reads it).
struct Branch {
    bool decoded = false;
    bool indirect = false;
    uint64_t target = 0;
    uint64_t slot = 0;
};
Branch decode_branch(const unsigned char* bytes, size_t size, uint64_t address, bool x64);

// KUSER_SHARED_DATA.KdDebuggerEnabled (offset 0x2D4): bit 0 = debugger enabled,
// bit 1 = debugger present (al-khaser SharedUserData_KernelDebugger).
struct SharedKd { bool enabled = false, present = false; };
inline SharedKd shared_kd(unsigned char value) { return {(value & 1) != 0, (value & 2) != 0}; }

// Bochs CPUID oversights (Pafish bochs_cpu_amd1 / bochs_cpu_intel1): raw,
// untrimmed brand strings that no real processor reports.
const char* bochs_brand_quirk(const std::string& raw_brand);
}  // namespace perdedor::lowlevel
