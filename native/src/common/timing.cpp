#include "lowlevel.hpp"
#include <array>
#include <cstring>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <sys/select.h>
#include <time.h>
#endif

namespace perdedor {
namespace {
using namespace lowlevel;
// al-khaser TimingAttacks/timing.cpp rdtsc_diff_vmexit and Pafish cpu.c
// cpu_rdtsc_force_vmexit: a ten-round average >= 1000 cycles (or 0) is a VM.
constexpr double kVmExitCycles = 1000;
constexpr unsigned kAlkhaserRounds = 10;
// CHIMERA cpuid-timing harness (scripts/chimera/bench/cpuid-timing, G2 runs of
// 2026-10-29): 2000 warm-up rounds before sampling. Median RDTSC;CPUID;RDTSC was
// 2398-3720 cycles on Xen HVM without an introspection monitor and 92530-94514
// cycles with DRAKVUF cpuidmon -s (CPUID forwarded to a dom0 monitor). A median
// above 20000 cycles therefore separates "CPUID trapped to a monitor" from an
// ordinary in-hypervisor exit with a wide margin on that host.
constexpr unsigned kWarmupRounds = 2000;
constexpr double kIntrospectionTrapCycles = 20000;
// Sampling/bounds are Perdedor policies, documented in docs/notes/lowlevel.md.
constexpr long long kIterations = 100000, kMaxIterations = 1000000, kTrials = 10, kMaxTrials = 1000;
constexpr double kSamplingBudgetNs = 4e9;
constexpr unsigned kBudgetStride = 256;
struct Samples {
    double* base; double* exits; size_t requested, count = 0; unsigned backwards = 0;
};
void sample_cpuid(void* p) {
    auto& s = *static_cast<Samples*>(p); const double deadline = monotonic_ns() + kSamplingBudgetNs;
    for (; s.count < s.requested; ++s.count) {
        if (s.count % kBudgetStride == 0 && monotonic_ns() >= deadline) break;
        asm volatile("" : : : "memory"); const uint64_t a = x86::rdtsc();
        asm volatile("" : : : "memory"); const uint64_t b = x86::rdtsc();
        asm volatile("" : : : "memory"); const uint64_t c = x86::rdtsc();
        x86::cpuid_serialize(0);
        asm volatile("" : : : "memory"); const uint64_t d = x86::rdtsc();
        if (b < a || d < c) { ++s.backwards; s.base[s.count] = s.exits[s.count] = -1; }
        else { s.base[s.count] = static_cast<double>(b - a); s.exits[s.count] = static_cast<double>(d - c); }
    }
}
void warm_up(void*) {
    for (unsigned i = 0; i < kWarmupRounds; ++i) { const uint64_t a = x86::rdtsc(); x86::cpuid_serialize(0); asm volatile("" : : "r"(x86::rdtsc() - a)); }
}
struct AverageTrials { double* out; size_t requested, completed = 0; unsigned backwards = 0; };
void sample_trials(void* p) {
    auto& t = *static_cast<AverageTrials*>(p); const double deadline = monotonic_ns() + kSamplingBudgetNs;
    for (; t.completed < t.requested; ++t.completed) {
        if (monotonic_ns() >= deadline) break;
        uint64_t sum = 0; bool valid = true;
        for (unsigned j = 0; j < kAlkhaserRounds; ++j) {
            const uint64_t a = x86::rdtsc(); x86::cpuid_serialize(0); const uint64_t b = x86::rdtsc();
            if (b < a) valid = false; else sum += b - a;
        }
        if (!valid) { ++t.backwards; t.out[t.completed] = -1; }
        else t.out[t.completed] = static_cast<double>(sum / kAlkhaserRounds);  // Upstream integer division.
    }
}
std::vector<Finding> vmexit(Context& ctx) {
    const char* id = "timing.rdtsc_cpuid_vmexit";
    const auto access = counter_access();
    if (!access.rdtsc) return {fault_skip(id, "RDTSC/CPUID VM-exit cost", Severity::High, {true, access.tsc_fault})};
    const auto n = static_cast<size_t>(bounded_int(ctx, "timing.iterations", kIterations, 100, kMaxIterations));
    const auto trials = static_cast<size_t>(bounded_int(ctx, "timing.trials", kTrials, 1, kMaxTrials));
    const double threshold = bounded_double(ctx, "timing.vmexit_cycles", kVmExitCycles, 1, 1e9);
    const double trap_threshold = bounded_double(ctx, "timing.introspection_cycles", kIntrospectionTrapCycles, 1, 1e10);
    std::vector<double> baseline(n), exits(n), averages(trials);
    CpuPin pin;  // Outside the guarded region: it owns state with a destructor.
    const auto warm = guard::run(warm_up);
    if (warm.faulted) return {fault_skip(id, "RDTSC/CPUID VM-exit cost", Severity::High, warm)};
    Samples samples{baseline.data(), exits.data(), n}; const auto r = guard::run(sample_cpuid, &samples);
    if (r.faulted) return {fault_skip(id, "RDTSC/CPUID VM-exit cost", Severity::High, r)};
    AverageTrials trial{averages.data(), trials}; const auto tr = guard::run(sample_trials, &trial);
    if (tr.faulted) return {fault_skip(id, "RDTSC/CPUID VM-exit cost", Severity::High, tr)};
    baseline.resize(samples.count); exits.resize(samples.count); averages.resize(trial.completed);
    const auto reject = [](std::vector<double>& v) { v.erase(std::remove_if(v.begin(), v.end(), [](double x) { return x < 0; }), v.end()); };
    reject(baseline); reject(exits); reject(averages);
    if (exits.empty() || averages.empty()) return {error(id, "RDTSC/CPUID VM-exit cost", "Cycle-counter statistics.", Severity::High, "No valid counter samples")};
    const auto a = statistics(baseline), b = statistics(exits), c = statistics(averages);
    unsigned hits = 0; for (double v : averages) if (v == 0 || v >= threshold) ++hits;
    Json measurement = Json::object(); measurement.set("rdtsc_rdtsc", a.json()); measurement.set("rdtsc_cpuid_rdtsc", b.json()); measurement.set("alkhaser_style_avg10", c.json()); measurement.set("alkhaser_style_detected", std::to_string(hits) + "/" + std::to_string(averages.size())); measurement.set("alkhaser_detected_trials", hits); measurement.set("alkhaser_trials", static_cast<unsigned>(averages.size())); measurement.set("threshold_cycles", threshold); measurement.set("requested_iterations", static_cast<unsigned>(n)); measurement.set("backwards_samples", samples.backwards + trial.backwards);
    measurement.set("warmup_rounds", kWarmupRounds); measurement.set("pinned_cpu", pin.cpu()); measurement.set("introspection_threshold_cycles", trap_threshold);
    measurement.set("exit_over_floor", a.median > 0 ? b.median / a.median : 0);
    const char* verdict = b.median >= trap_threshold ? "cpuid_trapped_to_monitor" : (b.median >= threshold ? "vm_exit" : (b.median == 0 ? "counter_frozen" : "native_range"));
    measurement.set("classification", verdict);
    Json av = Json::array(); for (double v : averages) av.push(v); measurement.set("alkhaser_trial_averages", av);
    Json ev = Json::object(); ev.set("units", "TSC cycles; raw RDTSC sequence matches al-khaser avg10"); ev.set("classification", verdict); ev.set("caveats", "Scheduling, CPU migration, power management, CPU generation and TSC compensation can alter results; baseline and MAD aid calibration."); ev.set("bounded_early", samples.count < n || trial.completed < trials);
    return {measured(id, "RDTSC/CPUID VM-exit cost", "Robust raw cycle statistics and independent ten-round al-khaser trials.", Severity::High,
                     b.median >= threshold || b.median == 0 || samples.backwards != 0 || trial.backwards != 0, ev, measurement, statistical_confidence(b))};
}
std::vector<Finding> availability(Context&) {
    if (!x86::available()) return {skipped("timing.tsc_instruction_availability", "RDTSC/RDTSCP availability", "Counter feature enumeration.", Severity::Low, "CPUID unavailable or blocked")};
    const auto a = counter_access(); const auto ext = x86::cpuid(0x80000000).eax;
    const bool advertised = ext >= 0x80000001 && (x86::cpuid(0x80000001).edx & (1u << 27));
    return {measured("timing.tsc_instruction_availability", "RDTSC/RDTSCP availability", "Checks advertised counters under the fault guard. An absent optional RDTSCP feature alone is not a detection.", Severity::Low,
                     (advertised && !a.rdtscp) || ((x86::cpuid(1).edx & (1u << 4)) && !a.rdtsc), "User-mode TSC access may be restricted by OS policy.",
                     numbers({{"rdtsc_usable", a.rdtsc}, {"rdtscp_advertised", advertised}, {"rdtscp_usable", a.rdtscp}, {"rdtsc_fault", a.tsc_fault}, {"rdtscp_fault", a.tscp_fault}}), 0.4)};
}
struct LeafSamples { const uint32_t* leaves; size_t leaf_count, iterations; double* values; size_t completed = 0; };
void sample_leaves(void* p) {
    auto& s = *static_cast<LeafSamples*>(p); const double deadline = monotonic_ns() + kSamplingBudgetNs;
    for (; s.completed < s.iterations; ++s.completed) {
        if (s.completed % kBudgetStride == 0 && monotonic_ns() >= deadline) break;
        for (size_t j = 0; j < s.leaf_count; ++j) {
            const uint64_t a = ordered_tsc(); x86::cpuid_serialize(s.leaves[j]); const uint64_t b = ordered_tsc();
            s.values[j * s.iterations + s.completed] = b >= a ? static_cast<double>(b - a) : 0;
        }
    }
}
std::vector<Finding> leaf_timing(Context& ctx) {
    if (!counter_access().rdtsc) return {skipped("timing.cpuid_leaf_timing", "CPUID leaf latency", "Compares serialization cost between leaves.", Severity::Low, "RDTSC unavailable")};
    constexpr double kLeafRatio = 3;  // Research threshold, local policy; no universal hardware boundary.
    const double threshold = bounded_double(ctx, "timing.leaf_ratio", kLeafRatio, 1, 1000);
    const size_t n = static_cast<size_t>(bounded_int(ctx, "timing.leaf_iterations", 2000, 100, 20000));
    constexpr uint32_t leaves[] = {0, 1, 7, 0x40000000, 0x40000100, 0x80000000};
    std::vector<double> values(n * 6); CpuPin pin; LeafSamples s{leaves, 6, n, values.data()}; const auto r = guard::run(sample_leaves, &s);
    if (r.faulted) return {fault_skip("timing.cpuid_leaf_timing", "CPUID leaf latency", Severity::Low, r)};
    if (!s.completed) return {error("timing.cpuid_leaf_timing", "CPUID leaf latency", "Per-leaf sampling.", Severity::Low, "No samples")};
    Json rows = Json::object(); double lo = std::numeric_limits<double>::max(), hi = 0, confidence = 0.5;
    for (size_t j = 0; j < 6; ++j) {
        const auto stat = statistics(std::vector<double>(values.begin() + j * n, values.begin() + j * n + s.completed));
        rows.set(hex(leaves[j]), stat.json()); lo = std::min(lo, stat.median); hi = std::max(hi, stat.median);
        confidence = std::min(confidence, statistical_confidence(stat, 0.5));
    }
    const double ratio = lo > 0 ? hi / lo : 0;
    Json m = numbers({{"max_min_ratio", ratio}, {"threshold_ratio", threshold}}); m.set("cycles_by_leaf", rows);
    return {measured("timing.cpuid_leaf_timing", "CPUID leaf latency", "Research comparison of leaf costs; native CPUID leaves also differ and TCG is not uniquely identified.", Severity::Low,
                     ratio > threshold, "LFENCE-ordered, interleaved leaf samples; unrelated to VMAware CPUID_SIGNATURE content checks.", m, confidence)};
}
// Busy calibration avoids calibrating the TSC against an already-skipped sleep.
struct Calibration { double cycles_per_ns = 0; };
void calibrate(void* p) {
    constexpr double kCalibrationNs = 2e7;  // 20 ms local bounded measurement policy.
    constexpr unsigned kMaxClockPolls = 2000000;  // Hard cap if the monotonic clock is patched/frozen.
    const double start = monotonic_ns(); const uint64_t a = ordered_tsc(); double now = start;
    for (unsigned i = 0; i < kMaxClockPolls && now - start < kCalibrationNs; ++i) now = monotonic_ns();
    const uint64_t b = ordered_tsc();
    if (now > start && b > a) static_cast<Calibration*>(p)->cycles_per_ns = (b - a) / (now - start);
}
std::vector<Finding> stability(Context& ctx) {
    if (!counter_access().rdtsc) return {skipped("timing.tsc_frequency_stability", "TSC stability", "TSC against the monotonic clock.", Severity::Medium, "RDTSC unavailable")};
    constexpr double kDriftFraction = 0.10;  // Research tolerance; Intel invariant TSC guarantees rate, not a detection boundary.
    const double threshold = bounded_double(ctx, "timing.tsc_drift_fraction", kDriftFraction, 0.001, 1);
    const unsigned windows = static_cast<unsigned>(bounded_int(ctx, "timing.tsc_windows", 5, 3, 20));
    std::vector<double> rates;
    for (unsigned i = 0; i < windows; ++i) {
        Calibration c; const auto r = guard::run(calibrate, &c);
        if (r.faulted) return {fault_skip("timing.tsc_frequency_stability", "TSC stability", Severity::Medium, r)};
        if (c.cycles_per_ns > 0) rates.push_back(c.cycles_per_ns * 1000);  // MHz.
    }
    if (rates.size() != windows) return {error("timing.tsc_frequency_stability", "TSC stability", "Repeated clock calibration.", Severity::Medium, "Clock failed to advance")};
    const auto s = statistics(rates); const double drift = (s.max - s.min) / s.median;
    Json m = s.json(); m.set("relative_range", drift); m.set("threshold_fraction", threshold); Json ev = Json::array(); for (double r : rates) ev.push(r);
    return {measured("timing.tsc_frequency_stability", "TSC stability", "Repeated busy-window TSC frequency against the OS monotonic clock. Scheduling and migration can cause drift.", Severity::Medium,
                     drift > threshold, ev, m, statistical_confidence(s, 0.65) * std::sqrt(1000.0 / windows))};
}
struct SleepSample {
    unsigned ms; unsigned method;
    double mono = 0, wall = 0, tick = 0, cycles = 0;
    long result = 0;
#ifdef _WIN32
    HANDLE event = nullptr;
    using Delay = LONG (NTAPI*)(BOOLEAN, LARGE_INTEGER*);
    Delay delay = nullptr;
#endif
};
void sample_sleep(void* p) {
    auto& s = *static_cast<SleepSample*>(p);
    const double m = monotonic_ns(), w = wall_ns(), t = tick_ns(); const uint64_t c = ordered_tsc();
#ifdef _WIN32
    if (s.method == 0) Sleep(s.ms);
    else if (s.method == 1) { s.result = s.event && WaitForSingleObject(s.event, s.ms) == WAIT_TIMEOUT ? 0 : -1; }
    else { LARGE_INTEGER interval{}; interval.QuadPart = -static_cast<LONGLONG>(s.ms) * 10000; s.result = s.delay ? s.delay(FALSE, &interval) : -1; }
#else
    if (s.method == 0) { const timespec ts{static_cast<time_t>(s.ms / 1000), static_cast<long>(s.ms % 1000) * 1000000}; s.result = nanosleep(&ts, nullptr); }
    else { timeval tv{static_cast<time_t>(s.ms / 1000), static_cast<suseconds_t>(s.ms % 1000) * 1000}; s.result = select(0, nullptr, nullptr, nullptr, &tv); }
    if (s.result < 0) s.result = errno;
#endif
    const uint64_t end = ordered_tsc(); s.cycles = end >= c ? static_cast<double>(end - c) : -1;
    s.mono = monotonic_ns() - m; s.wall = wall_ns() - w; s.tick = tick_ns() - t;
}
std::vector<Finding> sleep_check(Context& ctx, bool deep) {
    const char* id = deep ? "timing.sleep_acceleration_long" : "timing.sleep_acceleration";
    if (!counter_access().rdtsc) return {skipped(id, "Independent sleep clocks", "Compares clocks across native waits.", Severity::High, "RDTSC unavailable")};
    constexpr double kClockTolerance = 0.20;  // Local tolerance for timer quantization/scheduling, not a proven signature.
    constexpr double kTickSlackNs = 2e7;  // GetTickCount resolution 10-16 ms (Microsoft docs), rounded up.
    const unsigned ms = static_cast<unsigned>(bounded_int(ctx, deep ? "timing.long_sleep_ms" : "timing.sleep_ms", deep ? 5000 : 200, 50, deep ? 15000 : 500));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", kClockTolerance, 0.01, 0.8);
    Calibration cal; const auto r = guard::run(calibrate, &cal);
    if (r.faulted || cal.cycles_per_ns <= 0) return {fault_skip(id, "Independent sleep clocks", Severity::High, {true, r.code})};
#ifdef _WIN32
    constexpr const char* methods[] = {"Sleep", "WaitForSingleObject", "NtDelayExecution"};
#else
    constexpr const char* methods[] = {"nanosleep", "select"};
#endif
    Json rows = Json::array(); unsigned completed = 0, anomalies = 0;
    for (unsigned method = 0; method < sizeof(methods) / sizeof(*methods); ++method) {
        SleepSample sample{ms, method};
#ifdef _WIN32
        // Own the event outside the recovery boundary so a fault cannot leak it.
        if (method == 1) sample.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (method == 2) {
            const auto raw = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
            static_assert(sizeof(raw) == sizeof(sample.delay));
            std::memcpy(&sample.delay, &raw, sizeof raw);
        }
#endif
        const auto fault = guard::run(sample_sleep, &sample);
#ifdef _WIN32
        if (sample.event) CloseHandle(sample.event);
#endif
        Json row = numbers({{"requested_ms", ms}, {"monotonic_ms", sample.mono / 1e6}, {"wall_ms", sample.wall / 1e6}, {"tick_ms", sample.tick / 1e6},
                            {"tsc_ms", sample.cycles / cal.cycles_per_ns / 1e6}, {"api_status", static_cast<double>(sample.result)}, {"fault", fault.code}});
        row.set("method", methods[method]);
        if (!fault.faulted && sample.result == 0) {
            ++completed; const double expected = ms * 1e6;
            const std::array<double, 4> clocks{sample.mono, sample.wall, sample.tick, sample.cycles / cal.cycles_per_ns};
            const auto mm = std::minmax_element(clocks.begin(), clocks.end());
            const bool bad = *mm.first + kTickSlackNs < expected * (1 - tolerance) ||
                             *mm.second - *mm.first > std::max(expected, *mm.second) * tolerance + kTickSlackNs;
            anomalies += bad; row.set("disagreement", bad);
        }
        rows.push(row);
    }
    Json m = numbers({{"requested_ms", ms}, {"completed_methods", completed}, {"anomalous_methods", anomalies}, {"tolerance_fraction", tolerance}, {"tick_slack_ms", kTickSlackNs / 1e6}, {"calibrated_tsc_mhz", cal.cycles_per_ns * 1000}}); m.set("waits", rows);
    if (!anomalies && completed != sizeof(methods) / sizeof(*methods)) { auto f = skipped(id, "Independent sleep clocks", "Multiple wait APIs and four clock readings.", Severity::High, "One or more waits interrupted, unavailable or faulted"); f.measurement = m; return {f}; }
    return {measured(id, "Independent sleep clocks", "Checks early returns and clock disagreement across waits. Clock sources may share hardware; coherent acceleration can evade this test.", Severity::High,
                     anomalies != 0, "Wall-clock adjustment and scheduler delays can also cause disagreement; incomplete methods are shown individually.", m, 0.75)};
}
std::vector<Finding> sleep_short(Context& ctx) { return sleep_check(ctx, false); }
std::vector<Finding> sleep_long(Context& ctx) { return sleep_check(ctx, true); }
std::vector<Finding> resolution(Context& ctx) {
    constexpr unsigned kResolutionPolls = 10000;
    constexpr double kCoarseResolutionNs = 1e6;  // Research warning at >1 ms; not an OS promise.
    const double limit = bounded_double(ctx, "timing.resolution_ns", kCoarseResolutionNs, 1, 1e9);
    std::vector<double> deltas; deltas.reserve(kResolutionPolls); double last = monotonic_ns(); unsigned backwards = 0;
    for (unsigned i = 0; i < kResolutionPolls; ++i) { const double now = monotonic_ns(); if (now > last) deltas.push_back(now - last); else if (now < last) ++backwards; last = now; }
    if (deltas.empty()) return {error("timing.timer_resolution", "Timer resolution", "Observed monotonic increments.", Severity::Low, "Clock did not advance during bounded sampling")};
    double declared = 0;
#ifdef _WIN32
    LARGE_INTEGER f{}; if (QueryPerformanceFrequency(&f) && f.QuadPart > 0) declared = 1e9 / f.QuadPart;
#else
    timespec res{}; if (clock_getres(CLOCK_MONOTONIC, &res) == 0) declared = res.tv_sec * 1e9 + res.tv_nsec;
#endif
    const auto stats = statistics(deltas); Json m = stats.json(); m.set("declared_ns", declared); m.set("threshold_ns", limit); m.set("backwards", backwards);
    return {measured("timing.timer_resolution", "Timer resolution", "Declared monotonic resolution and observed positive increments; API call overhead is included.", Severity::Low,
                     stats.min > limit || backwards, "Nanosecond units. Coarse clocks are not unique to analysis environments.", m, 0.3)};
}
}  // namespace
PERDEDOR_REGISTER(vmexit, "timing.cpuid_vmexit", "medium", false, "timing.rdtsc_cpuid_vmexit");
PERDEDOR_REGISTER(availability, "timing.tsc_stability", "fast", false, "timing.tsc_instruction_availability");
PERDEDOR_REGISTER(leaf_timing, "timing.cpuid_vmexit", "medium", false, "timing.cpuid_leaf_timing");
PERDEDOR_REGISTER(stability, "timing.tsc_stability", "medium", false, "timing.tsc_frequency_stability");
PERDEDOR_REGISTER(sleep_short, "timing.sleep_acceleration", "medium", false, "timing.sleep_acceleration");
PERDEDOR_REGISTER(sleep_long, "timing.sleep_acceleration", "slow", false, "timing.sleep_acceleration_long");
PERDEDOR_REGISTER(resolution, "timing.tsc_stability", "fast", false, "timing.timer_resolution");
}  // namespace perdedor
