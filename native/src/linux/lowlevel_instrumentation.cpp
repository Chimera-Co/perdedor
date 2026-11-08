#include "../common/lowlevel.hpp"
#include "lowlevel_parsers.hpp"
#include <array>
#include <cstdio>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <set>
#include <sys/syscall.h>
#include <unistd.h>

namespace perdedor {
namespace {
using namespace lowlevel;
// procfs/tracefs reads are bounded and never list unrelated process mappings.
bool read_file(const char* path, std::string& text, size_t cap = 1024 * 1024) {
    const int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    text.clear(); std::array<char, 4096> buffer{}; bool ok = true;
    while (text.size() < cap) {
        const auto n = read(fd, buffer.data(), std::min(buffer.size(), cap - text.size()));
        if (!n) break;
        if (n < 0) { ok = false; break; }
        text.append(buffer.data(), static_cast<size_t>(n));
    }
    close(fd); return ok;
}
std::vector<Finding> preload(Context&) {
    const char* preload = std::getenv("LD_PRELOAD"), *audit = std::getenv("LD_AUDIT");
    const bool env = preload && *preload, auditing = audit && *audit;
    std::string text; errno = 0; const bool readable = read_file("/etc/ld.so.preload", text, 65536); const int err = errno;
    std::istringstream lines(text); std::string line; unsigned entries = 0;
    while (std::getline(lines, line)) { line.resize(line.find('#') == std::string::npos ? line.size() : line.find('#')); std::istringstream tokens(line); std::string token; while (tokens >> token) ++entries; }
    if (!readable && err != ENOENT && !env && !auditing)
        return {skipped("design.preloaded_libraries", "Preloaded libraries", "Loader environment and system preload configuration.", Severity::Medium, "System preload file unreadable: errno " + std::to_string(err))};
    return {measured("design.preloaded_libraries", "Preloaded libraries", "LD_PRELOAD, LD_AUDIT or active entries in ld.so.preload. Legitimate libraries also use these mechanisms.", Severity::Medium,
                     env || auditing || entries, "The static agent ignores LD_PRELOAD; configuration still exposes what dynamically linked samples would see.",
                     numbers({{"ld_preload_present", env}, {"ld_audit_present", auditing}, {"system_preload_entries", entries}, {"system_file_readable", readable}}), 0.6)};
}
std::vector<Finding> mapped_tools(Context&) {
    std::string text;
    if (!read_file("/proc/self/maps", text)) return {skipped("design.instrumentation_mappings", "Instrumentation mappings", "Tool paths mapped in this process.", Severity::High, "Own maps unreadable")};
    std::istringstream lines(text); std::string line; std::set<std::string> matches; unsigned mappings = 0;
    while (std::getline(lines, line)) {
        const auto path = lower(linux_lowlevel::mapped_path(line)); if (path.empty() || path.front() != '/') continue; ++mappings;
        for (const auto* token : {"frida", "dynamorio", "valgrind", "libpin", "/pin-", "librrpreload", "libasan", "libtsan", "libubsan", "libsysdig"})
            if (path.find(token) != std::string::npos) matches.emplace(token);
    }
    return {measured("design.instrumentation_mappings", "Instrumentation mappings", "Own mappings contain recognized instrumentation or sanitizer library names; developer tools can be legitimate.", Severity::High,
                     !matches.empty(), Json(std::vector<std::string>(matches.begin(), matches.end())), numbers({{"file_mappings", mappings}, {"tool_tokens", static_cast<double>(matches.size())}}), 0.8)};
}
std::vector<Finding> status_flags(Context&) {
    std::string text; long seccomp = 0, filters = 0, privileges = 0, tracer = 0;
    if (!read_file("/proc/self/status", text) || !linux_lowlevel::status_number(text, "Seccomp", seccomp))
        return {skipped("design.process_tracing_flags", "Process tracing/restriction flags", "Procfs seccomp and ptrace fields.", Severity::Low, "Seccomp field unavailable")};
    const bool has_filters = linux_lowlevel::status_number(text, "Seccomp_filters", filters);
    const bool has_privileges = linux_lowlevel::status_number(text, "NoNewPrivs", privileges);
    const bool has_tracer = linux_lowlevel::status_number(text, "TracerPid", tracer);
    return {measured("design.process_tracing_flags", "Process tracing/restriction flags", "Seccomp or ptrace is active for this process. Seccomp is a security restriction and does not itself establish tracing.", Severity::Low,
                     seccomp != 0 || (has_tracer && tracer != 0), "Fields reflect this PID namespace and may omit host tracing.",
                     numbers({{"seccomp", static_cast<double>(seccomp)}, {"seccomp_filters", has_filters ? static_cast<double>(filters) : -1},
                              {"no_new_privs", has_privileges ? static_cast<double>(privileges) : -1}, {"tracer_pid", has_tracer ? static_cast<double>(tracer) : -1}}), 0.35)};
}
std::vector<Finding> tracing(Context&) {
    Json rows = Json::array(); unsigned readable = 0, events = 0; std::set<std::string> definitions;
    for (const char* root : {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}) {
        for (const char* file : {"kprobe_events", "uprobe_events"}) {
            std::string text; const std::string path = std::string(root) + "/" + file;
            if (!read_file(path.c_str(), text, 65536)) continue;
            ++readable; std::istringstream lines(text); std::string line; unsigned count = 0;
            while (std::getline(lines, line)) if (!line.empty() && line[0] != '#') { definitions.insert(line); ++count; }
            Json row = numbers({{"definitions", count}}); row.set("source", path); rows.push(row);
        }
    }
    events = static_cast<unsigned>(definitions.size());
    union bpf_attr attr{}; errno = 0;
#ifdef SYS_bpf
    const long rc = syscall(SYS_bpf, BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
    const int bpf_error = errno;
#else
    const long rc = -1; const int bpf_error = ENOSYS;
#endif
    const bool bpf_visible = rc == 0 || bpf_error == ENOENT;
    if (!readable && !bpf_visible) return {skipped("design.visible_kernel_probes", "Visible kernel probes", "Read-only tracefs and BPF enumeration.", Severity::Low, "tracefs unreadable; BPF enumeration denied/unavailable (errno " + std::to_string(bpf_error) + ")")};
    return {measured("design.visible_kernel_probes", "Visible kernel probes", "Visible kprobe/uprobe definitions or a loaded BPF program. Definitions can be disabled; BPF may be networking rather than tracing.", Severity::Low,
                     events != 0 || rc == 0, rows, numbers({{"readable_tracefs_files", readable}, {"unique_probe_definitions", events}, {"bpf_program_visible", rc == 0}, {"bpf_errno", bpf_error}}), 0.3)};
}
std::vector<Finding> perf_policy(Context&) {
    std::string text; if (!read_file("/proc/sys/kernel/perf_event_paranoid", text, 64))
        return {skipped("design.perf_event_policy", "Perf event policy", "Unprivileged profiling policy.", Severity::Info, "perf_event_paranoid unavailable")};
    char* end = nullptr; errno = 0; const long value = std::strtol(text.c_str(), &end, 10);
    if (errno || end == text.c_str()) return {error("design.perf_event_policy", "Perf event policy", "Profiling policy.", Severity::Info, "Invalid integer")};
    // Linux admin-guide/perf-security: >=2 forbids kernel profiling to unprivileged users.
    constexpr long kKernelProfilingRestricted = 2;
    return {measured("design.perf_event_policy", "Perf event policy", "Permissive unprivileged profiling policy is an exposure, not evidence that a profiler is active.", Severity::Info,
                     value < kKernelProfilingRestricted, "Read-only policy observation; root-only tracer inventory is not attempted.", numbers({{"perf_event_paranoid", static_cast<double>(value)}, {"restricted_at", kKernelProfilingRestricted}}), 0.15)};
}
// System-call latency side channel. A VMI tracer such as DRAKVUF traps traced
// kernel functions with hidden breakpoints; each trap is a VM exit plus a round
// trip to the monitor in dom0, which costs tens of microseconds, against well
// under a microsecond for an untraced call. Three batched series are measured:
// a failing path lookup (openat of a random absent name in /, ENOENT, nothing is
// created), the cheapest real syscall (SYS_getpid, not the libc cache) and a
// fixed user-mode arithmetic loop that enters no kernel (CPU-speed reference).
constexpr unsigned kBatch = 8;               // Calls per clock reading: amortises clock_gettime cost.
constexpr unsigned kBaselineSteps = 256;     // Dependent multiply-adds in the user-mode reference.
constexpr double kLatencyBudgetNs = 3e9;     // Hard sampling budget (cost class "medium").
// Research defaults (local policy, see docs/notes/lowlevel.md; calibrate per host):
// an untraced failing openat on current x86_64 kernels costs 0.3-3 us; a trap to a
// monitor adds >= 10 us per call. 15 us leaves room for slow, mitigated kernels.
constexpr double kTracedFloorNs = 15000;
// A selective tracer inflates the traced call but not getpid; a ratio this large
// is not produced by path lookup cost alone (local research default).
constexpr double kSelectiveRatio = 30;
struct Latencies {
    const char* path; double* target; double* cheap; double* user; size_t n, completed = 0; long unexpected = 0;
    uint64_t sink = 0;
};
void latency_samples(void* p) {
    auto& s = *static_cast<Latencies*>(p);
    const double deadline = monotonic_ns() + kLatencyBudgetNs;
    for (; s.completed < s.n; ++s.completed) {
        if (monotonic_ns() >= deadline) break;
        const double a = monotonic_ns();
        for (unsigned k = 0; k < kBatch; ++k) {
            const long fd = syscall(SYS_openat, AT_FDCWD, s.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
            if (fd >= 0) { close(static_cast<int>(fd)); ++s.unexpected; }
            else if (errno != ENOENT) ++s.unexpected;
        }
        const double b = monotonic_ns();
        for (unsigned k = 0; k < kBatch; ++k) s.sink += static_cast<uint64_t>(syscall(SYS_getpid));
        const double c = monotonic_ns();
        uint64_t x = s.completed | 1;
        for (unsigned k = 0; k < kBatch * kBaselineSteps; ++k) { x = x * 6364136223846793005ull + 1442695040888963407ull; asm volatile("" : "+r"(x)); }
        const double d = monotonic_ns();
        s.sink ^= x;
        s.target[s.completed] = (b - a) / kBatch; s.cheap[s.completed] = (c - b) / kBatch; s.user[s.completed] = (d - c) / kBatch;
    }
}
std::vector<Finding> latency(Context& ctx) {
    const char* id = "timing.syscall_instrumentation_latency";
    const char* name = "Syscall latency side channel";
    const size_t n = static_cast<size_t>(bounded_int(ctx, "instrumentation.iterations", 2000, 100, 20000));
    const double ratio_limit = bounded_double(ctx, "instrumentation.latency_ratio", kSelectiveRatio, 1, 10000);
    const double floor = bounded_double(ctx, "instrumentation.min_latency_ns", kTracedFloorNs, 0, 1e9);
    char path[64];
    std::snprintf(path, sizeof path, "/.perdedor-absent-%d-%08llx", static_cast<int>(getpid()),
                  static_cast<unsigned long long>(monotonic_ns()) & 0xffffffffull);
    std::vector<double> target(n), cheap(n), user(n);
    Latencies data{path, target.data(), cheap.data(), user.data(), n};
    CpuPin pin;
    latency_samples(&data);
    target.resize(data.completed); cheap.resize(data.completed); user.resize(data.completed);
    if (!data.completed) return {error(id, name, "Batched failing openat versus getpid.", Severity::Medium, "No samples within the time budget")};
    if (data.unexpected) return {skipped(id, name, "Batched failing openat versus getpid.", Severity::Medium, "openat did not fail with ENOENT (policy, filtering or an existing name)")};
    const auto a = statistics(target), b = statistics(cheap), u = statistics(user);
    if (b.median <= 0) return {error(id, name, "Batched failing openat versus getpid.", Severity::Medium, "Clock resolution insufficient")};
    const double ratio = a.median / b.median;
    Json m = numbers({{"traced_floor_ns", floor}, {"ratio_threshold", ratio_limit}, {"openat_over_getpid", ratio},
                      {"openat_over_user_reference", u.median > 0 ? a.median / u.median : 0}, {"batch", kBatch},
                      {"samples", static_cast<double>(data.completed)}, {"pinned_cpu", pin.cpu()}});
    m.set("failing_openat_ns", a.json()); m.set("getpid_ns", b.json()); m.set("user_reference_ns", u.json());
    const bool absolute = a.median > floor || b.median > floor, selective = ratio > ratio_limit;
    Json ev = Json::object();
    ev.set("signal", absolute ? "per-call latency above the traced floor" : (selective ? "openat far slower than getpid" : "none"));
    ev.set("caveat", "Heuristic research check: audit, LSM hooks, seccomp, KPTI and slow storage stacks also add cost. It cannot name a monitor.");
    return {measured(id, name,
                     "Batched latency of a failing openat and of getpid against a user-mode reference; hypervisor-level "
                     "syscall tracing adds a VM exit and monitor round trip per traced call.",
                     Severity::Medium, absolute || selective, ev, m,
                     std::min(0.6, std::min(statistical_confidence(a, 0.6), statistical_confidence(b, 0.6))))};
}
}  // namespace
PERDEDOR_REGISTER(preload, "instrumentation.injected_libraries", "fast", false, "design.preloaded_libraries");
PERDEDOR_REGISTER(mapped_tools, "instrumentation.hooking_frameworks", "fast", false, "design.instrumentation_mappings");
PERDEDOR_REGISTER(status_flags, "instrumentation.tracing_facilities", "fast", false, "design.process_tracing_flags");
PERDEDOR_REGISTER(tracing, "instrumentation.tracing_facilities", "fast", false, "design.visible_kernel_probes");
PERDEDOR_REGISTER(perf_policy, "instrumentation.tracing_facilities", "fast", false, "design.perf_event_policy");
PERDEDOR_REGISTER(latency, "timing.instrumentation_latency", "medium", false, "timing.syscall_instrumentation_latency");
}  // namespace perdedor
