#include "lowlevel.hpp"
#include <cstdio>
#include <ctime>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <cerrno>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#endif
#include <cstring>
#include <map>
#include <string>

namespace perdedor::lowlevel {
namespace {
double median_of(const std::vector<double>& v) {
    const size_t m = v.size() / 2;
    return v.size() % 2 ? v[m] : v[m - 1] / 2 + v[m] / 2;
}
void read_tsc(void* p) { *static_cast<uint64_t*>(p) = x86::rdtsc(); }
void read_tscp(void* p) {
#if PERDEDOR_X86
    unsigned aux = 0;
    *static_cast<uint64_t*>(p) = __rdtscp(&aux);
#else
    (void)p;
#endif
}
}  // namespace
double nearest_rank(const std::vector<double>& v, double q) {
    const auto rank = static_cast<size_t>(std::ceil(q * static_cast<double>(v.size())));
    return v[std::min(v.size(), std::max<size_t>(rank, 1)) - 1];
}
Statistics statistics(std::vector<double> values) {
    values.erase(std::remove_if(values.begin(), values.end(), [](double x) { return !std::isfinite(x); }), values.end());
    Statistics s;
    if (values.empty()) return s;
    std::sort(values.begin(), values.end());
    s.count = values.size(); s.min = values.front(); s.max = values.back(); s.median = median_of(values);
    // Nearest-rank definition (NIST EDA 1.3.5.6). p5..p99 and mean mirror the
    // CHIMERA cpuid-timing harness output so both reports compare directly.
    s.p5 = nearest_rank(values, 0.05); s.p25 = nearest_rank(values, 0.25); s.p75 = nearest_rank(values, 0.75);
    s.p90 = nearest_rank(values, 0.90); s.p95 = nearest_rank(values, 0.95); s.p99 = nearest_rank(values, 0.99);
    constexpr size_t kTrimDivisor = 10;  // 10% each tail; robust descriptive policy, not a detector.
    const size_t trim = values.size() / kTrimDivisor;
    long double sum = 0, all = 0;
    for (size_t i = 0; i < values.size(); ++i) {
        all += values[i];
        if (i >= trim && i < values.size() - trim) sum += values[i];
    }
    s.mean = static_cast<double>(all / values.size());
    s.trimmed_mean = static_cast<double>(sum / (values.size() - 2 * trim));
    for (auto& v : values) v = std::abs(v - s.median);
    std::sort(values.begin(), values.end());
    s.mad = median_of(values);
    return s;
}
Json Statistics::json() const {
    return numbers({{"samples", static_cast<double>(count)}, {"min", min}, {"p5", p5}, {"p25", p25},
                    {"median", median}, {"p75", p75}, {"p90", p90}, {"p95", p95}, {"p99", p99}, {"max", max},
                    {"mean", mean}, {"trimmed_mean", trimmed_mean}, {"mad", mad}});
}
double statistical_confidence(const Statistics& s, double ceiling) {
    // Descriptive stability, not a calibrated posterior. NIST MAD scale factor.
    constexpr double kMadScale = 1.4826;
    constexpr double kSampleSaturation = 1000;  // Local reporting policy; docs/notes/lowlevel.md.
    if (!s.count || s.median <= 0) return 0;
    return ceiling * std::min(1.0, std::sqrt(s.count / kSampleSaturation)) /
           (1.0 + kMadScale * s.mad / s.median);
}
long long bounded_int(const Context& ctx, const char* key, long long def, long long lo, long long hi) {
    return std::clamp(ctx.param_int(key, def), lo, hi);
}
double bounded_double(const Context& ctx, const char* key, double def, double lo, double hi) {
    const double value = ctx.param_double(key, def);
    return std::isfinite(value) ? std::clamp(value, lo, hi) : def;
}
Json numbers(std::initializer_list<std::pair<const char*, double>> values) {
    Json out = Json::object();
    for (const auto& value : values) out.set(value.first, value.second);
    return out;
}
std::string hex(uint64_t value) { char buf[24]; std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(value)); return buf; }
std::string lower(std::string text) {
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}
Finding measured(const char* id, const char* name, const char* description, Severity severity,
                 bool detected, Json evidence, Json measurement, double confidence) {
    auto f = bool_check(id, name, description, severity, detected, std::move(evidence), remediation_for(id));
    f.measurement = std::move(measurement); f.confidence = confidence;
    return f;
}
Finding fault_skip(const char* id, const char* name, Severity severity, guard::Result result) {
    auto f = skipped(id, name, "Guarded probe unavailable on this target.", severity,
                     "guard/probe fault " + hex(result.code));
    f.measurement = numbers({{"fault_code", result.code}});
    return f;
}
CounterAccess counter_access() {
    CounterAccess a;
    if (!x86::available() || !(x86::cpuid(1).edx & (1u << 4))) return a;
    uint64_t value = 0;
    const auto r = guard::run(read_tsc, &value);
    a.rdtsc = !r.faulted; a.tsc_fault = r.code;
    if (x86::cpuid(0x80000000).eax >= 0x80000001 && (x86::cpuid(0x80000001).edx & (1u << 27))) {
        const auto p = guard::run(read_tscp, &value);
        a.rdtscp = !p.faulted; a.tscp_fault = p.code;
    }
    return a;
}
uint64_t ordered_tsc() {
#if PERDEDOR_X86
    uint32_t lo = 0, hi = 0;
    asm volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi) : : "memory");
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return 0;
#endif
}
double monotonic_ns() {
#ifdef _WIN32
    LARGE_INTEGER counter{}, frequency{};
    if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&counter) || !frequency.QuadPart) return 0;
    return static_cast<double>(counter.QuadPart) * 1e9 / frequency.QuadPart;
#else
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return static_cast<double>(ts.tv_sec) * 1e9 + ts.tv_nsec;
#endif
}
double wall_ns() {
#ifdef _WIN32
    FILETIME time{}; GetSystemTimeAsFileTime(&time);
    return static_cast<double>((static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime) * 100;
#else
    timespec ts{};
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return static_cast<double>(ts.tv_sec) * 1e9 + ts.tv_nsec;
#endif
}
double tick_ns() {
#ifdef _WIN32
    return static_cast<double>(GetTickCount64()) * 1e6;
#else
    timespec ts{};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) return 0;
    return static_cast<double>(ts.tv_sec) * 1e9 + ts.tv_nsec;
#endif
}
void bounded_sleep(unsigned ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    const timespec ts{static_cast<time_t>(ms / 1000), static_cast<long>(ms % 1000) * 1000000};
    nanosleep(&ts, nullptr);  // A signal can shorten calibration; caller checks actual elapsed time.
#endif
}
unsigned os_processors() {
#ifdef _WIN32
    return GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#else
    const long count = sysconf(_SC_NPROCESSORS_ONLN);
    return count > 0 ? static_cast<unsigned>(count) : 0;
#endif
}
Prologue prologue(const unsigned char* b, size_t n, bool x64) {
    // Skip CET ENDBR and the documented x86 hotpatch MOV EDI,EDI / NOP prefix.
    if (n >= 4 && b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && (b[3] == 0xfa || b[3] == 0xfb)) { b += 4; n -= 4; }
    if (!x64 && n >= 2 && b[0] == 0x8b && b[1] == 0xff) { b += 2; n -= 2; }
    if (!n) return Prologue::Ordinary;
    if (b[0] == 0xcc) return Prologue::Breakpoint;
    if (b[0] == 0xc3 || (n >= 3 && b[0] == 0xc2)) return Prologue::ReturnOnly;
    if ((n >= 5 && b[0] == 0xe9) || (n >= 2 && b[0] == 0xeb) ||
        (n >= 6 && b[0] == 0xff && b[1] == 0x25)) return Prologue::Jump;
    if ((n >= 6 && b[0] == 0x68 && b[5] == 0xc3) || (n >= 3 && b[0] == 0x6a && b[2] == 0xc3)) return Prologue::PushReturn;
    if (x64 && n >= 12 && b[0] == 0x48 && b[1] == 0xb8 && b[10] == 0xff && b[11] == 0xe0) return Prologue::Jump;
    if (x64 && n >= 13 && b[0] == 0x49 && b[1] == 0xbb && b[10] == 0x41 && b[11] == 0xff && b[12] == 0xe3) return Prologue::Jump;
    return Prologue::Ordinary;
}
bool syscall_stub(const unsigned char* b, size_t n, bool x64) {
    if (n >= 4 && b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && (b[3] == 0xfa || b[3] == 0xfb)) { b += 4; n -= 4; }
    if (x64) return n >= 8 && b[0] == 0x4c && b[1] == 0x8b && b[2] == 0xd1 && b[3] == 0xb8;
    // NT x86: MOV EAX,ssn followed by the native shared-user gate (MOV EDX,
    // 7FFE0300h), the Windows 7 WOW64 FS:[C0h] gate (MOV ECX,imm or XOR ECX,ECX;
    // LEA EDX,[ESP+4]), the Windows 10 WOW64 MOV EDX,Wow64SystemServiceCall;
    // CALL EDX shape, or the Windows 8+ native CALL to a local KiFastSystemCall.
    if (n < 7 || b[0] != 0xb8) return false;
    return b[5] == 0xba || b[5] == 0xb9 || (b[5] == 0x33 && b[6] == 0xc9) ||
           (b[5] == 0x64 && b[6] == 0xff) || (b[5] == 0x8d && b[6] == 0x54) || b[5] == 0xe8;
}
const char* prologue_name(Prologue p) {
    switch (p) {
        case Prologue::Jump: return "jump";
        case Prologue::PushReturn: return "push-ret";
        case Prologue::Breakpoint: return "int3";
        case Prologue::ReturnOnly: return "return";
        default: return "ordinary";
    }
}
namespace {
uint64_t le(const unsigned char* p, unsigned width) {
    uint64_t v = 0;
    for (unsigned i = 0; i < width; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}
int64_t sext(uint64_t v, unsigned bits) {
    const uint64_t sign = uint64_t{1} << (bits - 1);
    return static_cast<int64_t>((v ^ sign) - sign);
}
}  // namespace
Branch decode_branch(const unsigned char* b, size_t n, uint64_t address, bool x64) {
    Branch out;
    // Same prefixes prologue() skips: CET ENDBR32/64 and the x86 hotpatch MOV EDI,EDI.
    if (n >= 4 && b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && (b[3] == 0xfa || b[3] == 0xfb)) { b += 4; n -= 4; address += 4; }
    if (!x64 && n >= 2 && b[0] == 0x8b && b[1] == 0xff) { b += 2; n -= 2; address += 2; }
    const uint64_t mask = x64 ? ~uint64_t{0} : 0xffffffffu;
    if (n >= 5 && b[0] == 0xe9) { out.decoded = true; out.target = (address + 5 + sext(le(b + 1, 4), 32)) & mask; return out; }
    if (n >= 2 && b[0] == 0xeb) { out.decoded = true; out.target = (address + 2 + sext(b[1], 8)) & mask; return out; }
    // JMP [mem]: x64 encodes RIP-relative disp32 (optionally behind REX.W), x86 an absolute address.
    const unsigned rex = x64 && n >= 7 && b[0] == 0x48 && b[1] == 0xff && b[2] == 0x25 ? 1 : 0;
    if (n >= 6u + rex && b[rex] == 0xff && b[rex + 1] == 0x25) {
        const uint64_t disp = le(b + rex + 2, 4);
        out.decoded = out.indirect = true;
        out.slot = x64 ? (address + 6 + rex + sext(disp, 32)) : disp;
        return out;
    }
    // PUSH imm32; RET (64-bit mode sign-extends the immediate).
    if (n >= 6 && b[0] == 0x68 && b[5] == 0xc3) { out.decoded = true; out.target = static_cast<uint64_t>(sext(le(b + 1, 4), 32)) & mask; return out; }
    // MOV RAX,imm64; JMP RAX and MOV R11,imm64; JMP R11 (common x64 trampolines).
    if (x64 && n >= 12 && b[0] == 0x48 && b[1] == 0xb8 && b[10] == 0xff && b[11] == 0xe0) { out.decoded = true; out.target = le(b + 2, 8); return out; }
    if (x64 && n >= 13 && b[0] == 0x49 && b[1] == 0xbb && b[10] == 0x41 && b[11] == 0xff && b[12] == 0xe3) { out.decoded = true; out.target = le(b + 2, 8); return out; }
    // MOV EAX,imm32; JMP EAX (x86 trampoline).
    if (!x64 && n >= 7 && b[0] == 0xb8 && b[5] == 0xff && b[6] == 0xe0) { out.decoded = true; out.target = le(b + 1, 4); return out; }
    return out;
}
const char* bochs_brand_quirk(const std::string& raw) {
    // Pafish bochs.c: real AMD parts report "Processor" with a capital P, and the
    // padded Pentium 4 name below is not a string any real Intel part returns.
    static const char kAmd[] = "AMD Athlon(tm) processor";
    static const char kIntel[] = "              Intel(R) Pentium(R) 4 CPU        ";
    if (raw.compare(0, sizeof kAmd - 1, kAmd) == 0) return "bochs_cpu_amd1";
    if (raw.compare(0, sizeof kIntel - 1, kIntel) == 0) return "bochs_cpu_intel1";
    return nullptr;
}
CpuPin::CpuPin() {
#ifdef _WIN32
    const DWORD cpu = GetCurrentProcessorNumber();
    if (cpu >= sizeof(DWORD_PTR) * 8) return;
    const DWORD_PTR previous = SetThreadAffinityMask(GetCurrentThread(), DWORD_PTR{1} << cpu);
    if (!previous) return;
    static_assert(sizeof previous <= sizeof saved_, "affinity storage");
    std::memcpy(saved_, &previous, sizeof previous);
    pinned_ = true; cpu_ = static_cast<int>(cpu);
#else
    static_assert(sizeof(cpu_set_t) >= sizeof saved_, "affinity storage");
    cpu_set_t previous;
    if (pthread_getaffinity_np(pthread_self(), sizeof previous, &previous) != 0) return;
    const int cpu = sched_getcpu();
    if (cpu < 0 || cpu >= static_cast<int>(sizeof saved_ * 8)) return;
    cpu_set_t one; CPU_ZERO(&one); CPU_SET(cpu, &one);
    if (pthread_setaffinity_np(pthread_self(), sizeof one, &one) != 0) return;
    std::memcpy(saved_, &previous, sizeof saved_);
    pinned_ = true; cpu_ = cpu;
#endif
}
CpuPin::~CpuPin() {
    if (!pinned_) return;
#ifdef _WIN32
    DWORD_PTR previous = 0; std::memcpy(&previous, saved_, sizeof previous);
    SetThreadAffinityMask(GetCurrentThread(), previous);
#else
    cpu_set_t previous; CPU_ZERO(&previous); std::memcpy(&previous, saved_, sizeof saved_);
    pthread_setaffinity_np(pthread_self(), sizeof previous, &previous);
#endif
}
const char* remediation_for(const char* relative_id) {
    static const std::map<std::string, const char*> table = {
        {"env.cpuid_hypervisor_bit", "Clear CPUID.1:ECX[31] for the guest (Xen + DRAKVUF: cpuidmon -s; KVM: -cpu host,-hypervisor,kvm=off)."},
        {"env.cpuid_hypervisor_vendor", "Mask the 0x40000000 vendor leaf (Xen + DRAKVUF: cpuidmon -s; KVM: kvm=off, hv-vendor-id)."},
        {"env.cpu_brand_string", "Pass the host CPU model through (Xen: default cpuid policy; KVM: -cpu host) instead of a generic virtual CPU model."},
        {"env.cpuid_hypervisor_leaf_range", "Mask every hypervisor leaf base, not only 0x40000000: with Viridian on, Xen moves its leaves to 0x40000100; disable viridian or mask both bases."},
        {"env.cpuid_enlightenments", "Disable Hyper-V/Viridian enlightenments for the analysis guest (Xen: viridian=0; KVM: no hv_* flags) or accept the residual signal."},
        {"env.cpu_vendor_brand_consistency", "Expose a coherent vendor, brand and family/model/stepping triple from one real CPU model."},
        {"env.cpu_feature_consistency", "Use a CPUID policy derived from a real CPU model so feature flags agree with each other and with the brand string."},
        {"env.cpu_topology_consistency", "Give the guest a topology the claimed CPU can have (cores x threads) and keep CPUID topology leaves consistent with the vCPU count."},
        {"env.cpu_cache_descriptors", "Pass through cache leaves 2/4 (AMD 0x8000001D/0x80000006) from the host CPU policy."},
        {"env.cpu_descriptor_tables", "Enable UMIP for the guest where available; historic SIDT/SGDT values are low-discrimination on 64-bit systems."},
        {"env.vmware_backdoor", "Disable the VMware backdoor I/O port (VMware: monitor_control.restrict_backdoor = TRUE)."},
        {"env.virtualpc_opcode", "No change on non-VirtualPC hypervisors: the opcode must raise #UD as on bare metal."},
        {"env.hypercall_behavior", "Make CPL3 VMCALL/VMMCALL raise #UD as on bare metal (Xen returns -EPERM to user mode; this needs a hypervisor patch)."},
        {"env.cpu_emulation_quirks", "Use hardware virtualization instead of a CPU emulator (QEMU TCG, Bochs)."},
        {"timing.rdtsc_cpuid_vmexit", "Exit cost cannot be removed by configuration; it needs hypervisor TSC compensation for CPUID exits. Do not trap CPUID to an introspection monitor when not needed."},
        {"timing.tsc_instruction_availability", "Leave RDTSC/RDTSCP usable from user mode and advertised consistently (no CR4.TSD, RDTSCP passed through)."},
        {"timing.cpuid_leaf_timing", "Same as the VM-exit check: CPUID latency differences across leaves come from exits and monitor traps."},
        {"timing.tsc_frequency_stability", "Use an invariant, stable TSC for the guest (Xen tsc_mode=native or always_emulate consistently; pin vCPUs)."},
        {"timing.sleep_acceleration", "Accelerate sleeps coherently across every clock (TSC, QPC/monotonic, wall clock, tick count) or not at all."},
        {"timing.sleep_acceleration_long", "Accelerate sleeps coherently across every clock (TSC, QPC/monotonic, wall clock, tick count) or not at all."},
        {"timing.timer_resolution", "Expose a high-resolution clock source (TSC-backed QPC / CLOCK_MONOTONIC) to the guest."},
        {"timing.low_uptime", "Boot the analysis snapshot long before detonation or restore a snapshot taken after a realistic uptime."},
        {"timing.locky_api_ratio", "Reduce the cost of trapped calls (CloseHandle) relative to cheap calls, or stop trapping them."},
        {"timing.cpuid_qpc_jitter", "Same as the VM-exit check: reduce or compensate the CPUID exit cost."},
        {"timing.syscall_instrumentation_latency", "Trap fewer system calls (select DRAKVUF plugins / syscall filters) so traced calls are not orders of magnitude slower."},
        {"design.software_breakpoint_entry", "Detach debuggers; use hardware or hidden (EPT/altp2m) breakpoints that leave guest code bytes unchanged."},
        {"design.tracer_pid", "Do not ptrace the sample from inside the guest; trace from the hypervisor instead."},
        {"design.ptrace_traceme_child", "Do not ptrace the sample from inside the guest; relax seccomp/Yama only if the image policy allows."},
        {"design.debugger_parent", "Launch samples from the normal shell (explorer.exe / login shell), not from a debugger or tracer."},
        {"design.debugger_terminal_environment", "Launch samples without debugger-provided LINES/COLUMNS."},
        {"design.preloaded_libraries", "Remove LD_PRELOAD/LD_AUDIT and /etc/ld.so.preload entries from the analysis image."},
        {"design.instrumentation_mappings", "Do not inject instrumentation libraries into the sample; trace from the hypervisor."},
        {"design.process_tracing_flags", "Launch samples without seccomp filters or ptrace attached unless the image policy needs them."},
        {"design.visible_kernel_probes", "Do not leave kprobes/uprobes or tracing BPF programs loaded in the guest; trace from the hypervisor."},
        {"design.perf_event_policy", "Set kernel.perf_event_paranoid to the distribution default (2 or higher)."},
        {"design.debugger_present", "Detach in-guest debuggers and launch the sample normally."},
        {"design.remote_debugger_present", "Detach in-guest debuggers and launch the sample normally."},
        {"design.peb_debug_flags", "Detach debuggers and clear global flags (gflags) that enable debug heaps."},
        {"design.heap_debug_flags", "Detach debuggers and disable Application Verifier / page heap for the sample."},
        {"design.nt_debug_objects", "Detach debuggers; do not create debug objects for the sample."},
        {"design.debug_object_count", "Do not run user-mode debuggers anywhere in the analysis guest."},
        {"design.debug_privilege", "Launch the sample without SeDebugPrivilege enabled in its token."},
        {"design.kernel_debugger", "Disable the kernel debugger in the analysis image (bcdedit /debug off)."},
        {"design.hardware_breakpoints", "Do not set hardware breakpoints from inside the guest; use hypervisor breakpoints."},
        {"design.output_debug_string", "Detach debuggers."},
        {"design.debugger_exception_delivery", "Detach debuggers so INT3/INT 2D/ICEBP/TF/guard-page exceptions reach the process."},
        {"design.invalid_handle_exception", "Detach debuggers and disable Application Verifier handle checks for the sample."},
        {"design.thread_hide_roundtrip", "Remove anti-anti-debug hooks (e.g. ScyllaHide) that fake NtSetInformationThread results."},
        {"design.ntdll_syscall_stubs", "Do not hook ntdll in the guest; observe system calls from the hypervisor."},
        {"design.system_export_prologues", "Do not inline-hook system DLL exports in the guest; observe from the hypervisor."},
        {"design.system_module_text_integrity", "Do not patch system DLL code in the guest; observe from the hypervisor."},
        {"design.import_export_redirection", "Do not redirect IAT/EAT entries in the sample; observe from the hypervisor."},
        {"design.unexpected_loaded_modules", "Remove in-guest monitoring/injection DLLs (sandbox, AV hook DLLs) from the analysis image."},
        {"design.appinit_appcert_libraries", "Clear AppInit_DLLs and AppCertDlls in the analysis image."},
        {"design.process_instrumentation_callback", "Do not install process instrumentation callbacks on the sample."},
        {"design.etw_event_write_hook", "Do not patch EtwEventWrite in the guest."},
    };
    std::string key(relative_id ? relative_id : "");
    const auto it = table.find(key);
    return it == table.end() ? "See the catalog fix for this check." : it->second;
}
}  // namespace perdedor::lowlevel
