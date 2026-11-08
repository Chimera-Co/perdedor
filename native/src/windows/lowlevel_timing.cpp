#include "lowlevel_support.hpp"
#include <array>
#include <cwchar>

namespace perdedor {
namespace {
using namespace lowlevel;
using namespace win_lowlevel;
std::vector<Finding> uptime(Context& ctx) {
    constexpr double kLowUptimeSeconds = 600;  // Preserved v1 Timing.ps1 policy; Pafish gensandbox_uptime uses 12 minutes.
    const double limit = bounded_double(ctx, "timing.uptime_seconds", kLowUptimeSeconds, 0, 86400);
    const double ticks = GetTickCount64() / 1000.0;
    struct SharedTime { uint32_t low; int32_t high1, high2; } value{};
    bool readable = false; uint64_t interrupt = 0;
    // KUSER_SHARED_DATA.InterruptTime is KSYSTEM_TIME at offset 8; seqlock read
    // repeats until High1Time == High2Time (phnt ntexapi.h).
    for (unsigned i = 0; i < 8; ++i) {
        if (!read_value(uintptr_t{0x7ffe0008}, value)) break;
        if (value.high1 == value.high2) { interrupt = (uint64_t(static_cast<uint32_t>(value.high1)) << 32) | value.low; readable = true; break; }
    }
    Json m = numbers({{"tick_count_seconds", ticks}, {"interrupt_seconds", readable ? interrupt / 1e7 : -1}, {"threshold_seconds", limit}, {"interrupt_readable", readable}});
    return {measured("timing.low_uptime", "System uptime", "GetTickCount64 uptime with independent shared interrupt-time observation; a recent legitimate boot also has low uptime.", Severity::Low,
                     ticks < limit, "Interrupt time is in 100-ns units; low uptime alone has low discrimination.", m, 0.35)};
}
struct LockySamples { double heap[10]{}, close[10]{}; };
void locky_samples(void* p) {
    auto& s = *static_cast<LockySamples*>(p);
    for (unsigned i = 0; i < 10; ++i) {
        const auto a = x86::rdtsc(); GetProcessHeap(); const auto b = x86::rdtsc(); CloseHandle(nullptr); const auto c = x86::rdtsc();
        s.heap[i] = b >= a ? static_cast<double>(b - a) : 0;
        s.close[i] = c >= b ? static_cast<double>(c - b) : 0;
    }
}
std::vector<Finding> locky(Context& ctx) {
    if (!counter_access().rdtsc) return {unavailable("timing.locky_api_ratio", "Locky API ratio", "RDTSC unavailable")};
    constexpr double kLockyRatio = 10;  // al-khaser rdtsc_diff_locky: any ratio >= 10 returns negative.
    const double threshold = bounded_double(ctx, "timing.locky_ratio", kLockyRatio, 1, 10000);
    LockySamples data; const auto r = guard::run(locky_samples, &data);
    if (r.faulted) return {fault_skip("timing.locky_api_ratio", "Locky API ratio", Severity::Medium, r)};
    std::vector<double> heap, close, ratios;
    for (unsigned i = 0; i < 10; ++i) if (data.heap[i] > 0 && data.close[i] > 0) {
        heap.push_back(data.heap[i]); close.push_back(data.close[i]); ratios.push_back(data.close[i] / data.heap[i]);
    }
    if (ratios.size() != 10) return {unavailable("timing.locky_api_ratio", "Locky API ratio", "Zero/backwards TSC deltas")};
    const auto stats = statistics(ratios); Json m = numbers({{"threshold_ratio", threshold}});
    m.set("close_over_heap_ratio", stats.json()); m.set("getprocessheap_cycles", statistics(heap).json()); m.set("closehandle_cycles", statistics(close).json());
    return {measured("timing.locky_api_ratio", "Locky API ratio", "Ten RDTSC ratios around GetProcessHeap versus invalid CloseHandle; consistently small ratios reproduce the historical Locky heuristic.", Severity::Medium,
                     stats.max < threshold, "API implementation, Wine and modern CPU costs affect this historical heuristic.", m, 0.3)};
}
struct QpcSamples { double* values; size_t n, completed = 0; };
void qpc_samples(void* p) {
    auto& s = *static_cast<QpcSamples*>(p); const double deadline = monotonic_ns() + 3e9;
    for (; s.completed < s.n; ++s.completed) {
        if (s.completed % 256 == 0 && monotonic_ns() >= deadline) break;
        LARGE_INTEGER a{}, b{}; QueryPerformanceCounter(&a); x86::cpuid_serialize(0); QueryPerformanceCounter(&b);
        s.values[s.completed] = static_cast<double>(b.QuadPart - a.QuadPart);
    }
}
std::vector<Finding> qpc_jitter(Context& ctx) {
    constexpr double kLegacyQpcTicks = 20000;  // Frozen v1 Timing.ps1 JitterThresholdTicks, QPC ticks not TSC cycles.
    const size_t n = static_cast<size_t>(bounded_int(ctx, "timing.qpc_iterations", 2000, 100, 100000));
    const double threshold = bounded_double(ctx, "timing.qpc_ticks", kLegacyQpcTicks, 1, 1e9);
    LARGE_INTEGER frequency{};
    if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return {unavailable("timing.cpuid_qpc_jitter", "QPC-around-CPUID", "QPC unavailable", Severity::High)};
    std::vector<double> values(n); QpcSamples s{values.data(), n}; const auto r = guard::run(qpc_samples, &s);
    if (r.faulted) return {fault_skip("timing.cpuid_qpc_jitter", "QPC-around-CPUID", Severity::High, r)};
    values.resize(s.completed); if (values.empty()) return {unavailable("timing.cpuid_qpc_jitter", "QPC-around-CPUID", "No samples", Severity::High)};
    const auto stats = statistics(values); Json m = stats.json(); m.set("qpc_frequency", static_cast<double>(frequency.QuadPart)); m.set("threshold_ticks", threshold);
    return {measured("timing.cpuid_qpc_jitter", "QPC-around-CPUID", "Preserves the v1 QPC-tick CPUID measurement and threshold; the RDTSC check separately reports cycle counts.", Severity::High,
                     stats.median > threshold, "QPC ticks, not TSC cycles; the historical threshold is not portable across QPC frequencies.", m, statistical_confidence(stats, 0.6))};
}
// System-call latency side channel (see the Linux twin for the rationale). A
// VMI tracer such as DRAKVUF traps traced kernel functions with hidden
// breakpoints: each traced call costs a VM exit and a dom0 monitor round trip.
// Series, batched to amortise QPC cost: a failing NtOpenKey on a random absent
// key (read access, STATUS_OBJECT_NAME_NOT_FOUND; registry monitors trap this
// family), NtQueryInformationProcess(ProcessBasicInformation) as the cheap
// syscall, and a user-mode arithmetic reference that enters no kernel.
constexpr unsigned kBatch = 8;            // Calls per QPC reading (QPC is 100 ns on Windows 10).
constexpr unsigned kBaselineSteps = 256;  // Dependent multiply-adds per reference call.
constexpr double kLatencyBudgetNs = 3e9;  // Hard sampling budget (cost class "medium").
// Research defaults (local policy, docs/notes/lowlevel.md; calibrate per host): an
// untraced failing NtOpenKey costs about 1-5 us; a trap to a monitor adds >= 10 us.
constexpr double kTracedFloorNs = 15000;
constexpr double kSelectiveRatio = 30;
constexpr LONG kNameNotFound = static_cast<LONG>(0xc0000034u);  // STATUS_OBJECT_NAME_NOT_FOUND
struct NtUnicode { USHORT length, maximum; PWSTR buffer; };
struct NtAttributes { ULONG length; HANDLE root; NtUnicode* name; ULONG attributes; PVOID descriptor, qos; };
using OpenKey = LONG (NTAPI*)(PHANDLE, ACCESS_MASK, NtAttributes*);
using CloseObject = LONG (NTAPI*)(HANDLE);
struct SyscallSamples {
    OpenKey open; CloseObject close; QueryProcess query; NtAttributes* attributes;
    double* target; double* cheap; double* user; size_t n, completed = 0; long unexpected = 0; uint64_t sink = 0;
};
void syscall_samples(void* p) {
    auto& s = *static_cast<SyscallSamples*>(p); alignas(void*) unsigned char info[6 * sizeof(void*)]{};
    const double deadline = monotonic_ns() + kLatencyBudgetNs;
    for (; s.completed < s.n; ++s.completed) {
        if (monotonic_ns() >= deadline) break;
        const double a = monotonic_ns();
        for (unsigned k = 0; k < kBatch; ++k) {
            HANDLE key = nullptr; const LONG status = s.open(&key, KEY_READ, s.attributes);
            if (status >= 0) { s.close(key); ++s.unexpected; } else if (status != kNameNotFound) ++s.unexpected;
        }
        const double b = monotonic_ns();
        for (unsigned k = 0; k < kBatch; ++k) if (s.query(GetCurrentProcess(), 0, info, sizeof info, nullptr) < 0) ++s.unexpected;
        const double c = monotonic_ns();
        uint64_t x = s.completed | 1;
        for (unsigned k = 0; k < kBatch * kBaselineSteps; ++k) { x = x * 6364136223846793005ull + 1442695040888963407ull; asm volatile("" : "+r"(x)); }
        const double d = monotonic_ns();
        s.sink ^= x;
        s.target[s.completed] = (b - a) / kBatch; s.cheap[s.completed] = (c - b) / kBatch; s.user[s.completed] = (d - c) / kBatch;
    }
}
std::vector<Finding> syscall_latency(Context& ctx) {
    const char* id = "timing.syscall_instrumentation_latency";
    const char* name = "Syscall latency side channel";
    const auto open = nt<OpenKey>("NtOpenKey");
    const auto close = nt<CloseObject>("NtClose");
    const auto query = nt<QueryProcess>("NtQueryInformationProcess");
    if (!open || !close || !query) return {unavailable(id, name, "NT registry/process services unavailable")};
    const double ratio_limit = bounded_double(ctx, "instrumentation.latency_ratio", kSelectiveRatio, 1, 10000);
    const double floor = bounded_double(ctx, "instrumentation.min_latency_ns", kTracedFloorNs, 0, 1e9);
    const size_t n = static_cast<size_t>(bounded_int(ctx, "instrumentation.iterations", 2000, 100, 20000));
    wchar_t path[96];
    swprintf(path, sizeof path / sizeof *path, L"\\Registry\\Machine\\SOFTWARE\\Perdedor-absent-%lu-%08llx",
             GetCurrentProcessId(), static_cast<unsigned long long>(monotonic_ns()) & 0xffffffffull);
    NtUnicode unicode{static_cast<USHORT>(wcslen(path) * sizeof(wchar_t)), static_cast<USHORT>(sizeof path), path};
    NtAttributes attributes{sizeof(NtAttributes), nullptr, &unicode, 0x40 /* OBJ_CASE_INSENSITIVE */, nullptr, nullptr};
    std::vector<double> target(n), cheap(n), user(n);
    SyscallSamples data{open, close, query, &attributes, target.data(), cheap.data(), user.data(), n};
    CpuPin pin;
    const auto r = guard::run(syscall_samples, &data);
    if (r.faulted) return {fault_skip(id, name, Severity::Medium, r)};
    if (!data.completed) return {unavailable(id, name, "No samples within the time budget")};
    if (data.unexpected) return {unavailable(id, name, "NtOpenKey/NtQueryInformationProcess returned unexpected status (policy or hooks)")};
    target.resize(data.completed); cheap.resize(data.completed); user.resize(data.completed);
    const auto a = statistics(target), b = statistics(cheap), u = statistics(user);
    if (b.median <= 0) return {unavailable(id, name, "QPC resolution insufficient for the batch size")};
    const double ratio = a.median / b.median;
    Json m = numbers({{"traced_floor_ns", floor}, {"ratio_threshold", ratio_limit}, {"openkey_over_query", ratio},
                      {"openkey_over_user_reference", u.median > 0 ? a.median / u.median : 0}, {"batch", kBatch},
                      {"samples", static_cast<double>(data.completed)}, {"pinned_cpu", pin.cpu()}});
    m.set("failing_ntopenkey_ns", a.json()); m.set("ntqueryinformationprocess_ns", b.json()); m.set("user_reference_ns", u.json());
    const bool absolute = a.median > floor || b.median > floor, selective = ratio > ratio_limit;
    Json ev = Json::object();
    ev.set("signal", absolute ? "per-call latency above the traced floor" : (selective ? "NtOpenKey far slower than the cheap query" : "none"));
    ev.set("caveat", "Heuristic research check: security products, VBS/HVCI and registry filter drivers also add cost. It cannot name a monitor.");
    return {measured(id, name,
                     "Batched latency of a failing NtOpenKey and of NtQueryInformationProcess against a user-mode reference; "
                     "hypervisor-level syscall tracing adds a VM exit and monitor round trip per traced call.",
                     Severity::Medium, absolute || selective, ev, m,
                     std::min(0.6, std::min(statistical_confidence(a, 0.6), statistical_confidence(b, 0.6))))};
}
}  // namespace
PERDEDOR_REGISTER(uptime, "timing.uptime", "fast", false, "timing.low_uptime");
PERDEDOR_REGISTER(locky, "timing.rdtsc_api_ratio", "medium", false, "timing.locky_api_ratio");
PERDEDOR_REGISTER(qpc_jitter, "timing.cpuid_vmexit", "medium", false, "timing.cpuid_qpc_jitter");
PERDEDOR_REGISTER(syscall_latency, "timing.instrumentation_latency", "medium", false, "timing.syscall_instrumentation_latency");
}  // namespace perdedor
