#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <winhttp.h>

#include "lowlevel_support.hpp"
#include "winutil.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

namespace perdedor {
namespace {

using namespace lowlevel;
using namespace win_lowlevel;

inline Finding unavailable(const char* id, const char* name, const std::string& why, Severity severity = Severity::Medium) {
    return skipped(id, name, "Native Windows low-level observation.", severity, why);
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

inline HMODULE get_winmm() {
    static HMODULE h = LoadLibraryW(L"winmm.dll");
    return h;
}

using TimeCallbackFn = void (CALLBACK*)(UINT, UINT, DWORD_PTR, DWORD_PTR, DWORD_PTR);
using TimeSetEventFn = UINT (WINAPI*)(UINT, UINT, TimeCallbackFn, DWORD_PTR, UINT);
using TimeKillEventFn = UINT (WINAPI*)(UINT);
using TimeGetTimeFn = DWORD (WINAPI*)(void);
using DelayExecutionFn = LONG (NTAPI*)(BOOLEAN, LARGE_INTEGER*);

VOID CALLBACK timer_queue_routine(PVOID p, BOOLEAN) {
    SetEvent(static_cast<HANDLE>(p));
}

void CALLBACK mm_timer_routine(UINT, UINT, DWORD_PTR dwUser, DWORD_PTR, DWORD_PTR) {
    SetEvent(reinterpret_cast<HANDLE>(dwUser));
}

struct KUserTick {
    uint64_t tick_ms = 0;
    bool valid = false;
};

KUserTick read_kuser_tick() {
    // KUSER_SHARED_DATA.TickCount is KSYSTEM_TIME at offset 0x320;
    // TickCountMultiplier is ULONG at offset 0x0004.
    struct SharedTime { uint32_t low; int32_t high1, high2; } tick{};
    uint32_t mult = 0;
    if (!read_value(uintptr_t{0x7ffe0004}, mult)) return {};
    for (unsigned i = 0; i < 8; ++i) {
        if (!read_value(uintptr_t{0x7ffe0320}, tick)) break;
        if (tick.high1 == tick.high2) {
            uint64_t raw = (uint64_t(static_cast<uint32_t>(tick.high1)) << 32) | tick.low;
            uint64_t ms = (raw * mult) >> 24;
            return {ms, true};
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// 1. win.timing.clock_jitter_vmaware
// ---------------------------------------------------------------------------
struct ClockJitterSamples {
    double ratios[5]{};
    size_t count = 0;
    LARGE_INTEGER freq{};
};

using PreciseTimeFn = VOID(WINAPI*)(LPFILETIME);
// GetSystemTimePreciseAsFileTime (Windows 8+). The coarse GetSystemTimeAsFileTime ticks every 15.6 ms, which
// makes short-window ratios swing on bare metal, so without the precise clock this check is skipped.
PreciseTimeFn precise_time() {
    static PreciseTimeFn fn = reinterpret_cast<PreciseTimeFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetSystemTimePreciseAsFileTime")));
    return fn;
}

void run_clock_jitter(void* p) {
    auto& s = *static_cast<ClockJitterSamples*>(p);
    if (!QueryPerformanceFrequency(&s.freq) || s.freq.QuadPart <= 0) return;
    const PreciseTimeFn now = precise_time();
    if (!now) return;

    for (unsigned i = 0; i < 5; ++i) {
        LARGE_INTEGER q1{}, q2{};
        FILETIME ft1{}, ft2{};
        QueryPerformanceCounter(&q1);
        now(&ft1);

        // 200 ms windows: long enough that scheduling noise stays well under the tolerance
        bounded_sleep(200);

        QueryPerformanceCounter(&q2);
        now(&ft2);

        double qpc_sec = static_cast<double>(q2.QuadPart - q1.QuadPart) / static_cast<double>(s.freq.QuadPart);
        uint64_t t1 = (uint64_t(ft1.dwHighDateTime) << 32) | ft1.dwLowDateTime;
        uint64_t t2 = (uint64_t(ft2.dwHighDateTime) << 32) | ft2.dwLowDateTime;
        double rtc_sec = static_cast<double>(t2 >= t1 ? (t2 - t1) : 0) / 10000000.0;

        if (rtc_sec > 0.05) {
            s.ratios[s.count++] = qpc_sec / rtc_sec;
        }
    }
}

std::vector<Finding> clock_jitter_vmaware(Context& ctx) {
    const char* id = "timing.clock_jitter_vmaware";
    const char* name = "VMAware clock rate and jitter";
    constexpr double kDefaultTolerance = 0.25;
    const double tolerance = bounded_double(ctx, "timing.vmaware_clock_tolerance", kDefaultTolerance, 0.05, 0.80);

    if (!precise_time())
        return {skipped(id, name, "VMAware CLOCK: QPC rate against the precise system clock.", Severity::Medium,
                        "GetSystemTimePreciseAsFileTime unavailable (Windows 7)")};
    ClockJitterSamples samples;
    const auto r = guard::run(run_clock_jitter, &samples);
    if (r.faulted) return {fault_skip(id, name, Severity::Medium, r)};
    if (samples.count < 3 || samples.freq.QuadPart <= 0) {
        return {unavailable(id, name, "QPC or RTC sampling failed / insufficient samples")};
    }

    std::vector<double> vals(samples.ratios, samples.ratios + samples.count);
    const auto stats = statistics(vals);
    const double drift = stats.max - stats.min;
    const bool anomalous = std::abs(stats.median - 1.0) > tolerance || drift > (tolerance * 1.5);

    Json m = stats.json();
    m.set("qpc_frequency", static_cast<double>(samples.freq.QuadPart));
    m.set("drift", drift);
    m.set("tolerance", tolerance);

    Json ev = Json::object();
    ev.set("median_qpc_over_rtc_ratio", stats.median);
    ev.set("drift", drift);
    ev.set("samples", static_cast<double>(samples.count));

    return {measured(id, name,
                     "VMAware CLOCK: Compares high-resolution performance counter advancement against "
                     "hardware RTC / system file time across short sampling windows.",
                     Severity::Medium, anomalous, ev, m, statistical_confidence(stats, 0.70))};
}

// ---------------------------------------------------------------------------
// 2. win.timing.create_timer_queue_timer
// ---------------------------------------------------------------------------
std::vector<Finding> create_timer_queue_timer(Context& ctx) {
    const char* id = "timing.create_timer_queue_timer";
    const char* name = "CreateTimerQueueTimer delay";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.timer_queue_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        Handle hEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!hEvent.valid()) continue;

        HANDLE hTimer = nullptr;
        const double start = monotonic_ns();
        const BOOL ok = CreateTimerQueueTimer(
            &hTimer, nullptr,
            timer_queue_routine,
            hEvent.get(), delay_ms, 0, WT_EXECUTEONLYONCE);

        if (!ok) continue;

        DWORD res = WaitForSingleObject(hEvent.get(), delay_ms * 3 + 150);
        const double elapsed_ms = (monotonic_ns() - start) / 1e6;
        DeleteTimerQueueTimer(nullptr, hTimer, INVALID_HANDLE_VALUE);

        if (res == WAIT_OBJECT_0) {
            trials.push_back(elapsed_ms);
        }
    }

    if (trials.empty()) {
        return {unavailable(id, name, "TimerQueueTimer callbacks failed to fire within timeout")};
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);
    m.set("tolerance", tolerance);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "al-khaser timing_CreateTimerQueueTimer: Delays execution using thread-pool timers "
                     "via CreateTimerQueueTimer to detect premature callback dispatching.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 3. win.timing.create_waitable_timer
// ---------------------------------------------------------------------------
std::vector<Finding> create_waitable_timer(Context& ctx) {
    const char* id = "timing.create_waitable_timer";
    const char* name = "CreateWaitableTimer delay";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.waitable_timer_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        Handle hTimer(CreateWaitableTimerW(nullptr, TRUE, nullptr));
        if (!hTimer.valid()) continue;

        LARGE_INTEGER due;
        due.QuadPart = -10000LL * delay_ms;
        if (!SetWaitableTimer(hTimer.get(), &due, 0, nullptr, nullptr, FALSE)) continue;

        const double start = monotonic_ns();
        DWORD res = WaitForSingleObject(hTimer.get(), delay_ms * 3 + 150);
        const double elapsed_ms = (monotonic_ns() - start) / 1e6;

        if (res == WAIT_OBJECT_0) {
            trials.push_back(elapsed_ms);
        }
    }

    if (trials.empty()) {
        return {unavailable(id, name, "Waitable timer wait failed or timed out")};
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "al-khaser timing_CreateWaitableTimer: Creates a kernel waitable timer object via "
                     "CreateWaitableTimer and tests whether WaitForSingleObject returns prematurely.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 4. win.timing.icmp_send_echo_delay
// ---------------------------------------------------------------------------
std::vector<Finding> icmp_send_echo_delay(Context& ctx) {
    const char* id = "timing.icmp_send_echo_delay";
    const char* name = "IcmpSendEcho timeout delay";
    constexpr unsigned kDefaultTimeoutMs = 100;
    const unsigned timeout_ms = static_cast<unsigned>(bounded_int(ctx, "timing.icmp_timeout_ms", kDefaultTimeoutMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        return {unavailable(id, name, "IcmpCreateFile failed: " + win::last_error_message())};
    }

    std::vector<double> trials;
    char send_buf[] = "PERDEDOR";
    char reply_buf[sizeof(ICMP_ECHO_REPLY) + 32]{};
    // RFC 5737 TEST-NET-1: never routed, so a real stack waits out the timeout. (All of 127/8 is loopback on
    // Windows and answers at once, which is why loopback cannot be used.) Only attempts that end with
    // IP_REQ_TIMED_OUT are measured: an early "timed out" is the skipped wait this check looks for.
    const IPAddr ip = inet_addr("192.0.2.1");

    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        const double start = monotonic_ns();
        const DWORD replies =
            IcmpSendEcho(hIcmp, ip, send_buf, sizeof(send_buf), nullptr, reply_buf, sizeof(reply_buf), timeout_ms);
        const DWORD err = GetLastError();
        const double elapsed_ms = (monotonic_ns() - start) / 1e6;
        if (replies == 0 && err == IP_REQ_TIMED_OUT) trials.push_back(elapsed_ms);
    }
    IcmpCloseHandle(hIcmp);
    if (trials.size() < 2)
        return {skipped(id, name, "IcmpSendEcho timeout to a non-routable address.", Severity::Medium,
                        "the request did not time out (no route, filtered, or answered), so the wait cannot be measured")};

    const auto stats = statistics(trials);
    const double threshold = timeout_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_timeout_ms", timeout_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("configured_timeout_ms", timeout_ms);

    return {measured(id, name,
                     "al-khaser timing_IcmpSendEcho: Sends an ICMP echo request to a non-responsive loopback IP "
                     "with a configured timeout to detect premature return from sleep-skipping sandbox hooks.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 5. win.timing.user32_set_timer
// ---------------------------------------------------------------------------
std::vector<Finding> user32_set_timer(Context& ctx) {
    const char* id = "timing.user32_set_timer";
    const char* name = "SetTimer message dispatch delay";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.settimer_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        UINT_PTR timer_id = SetTimer(nullptr, 0, delay_ms, nullptr);
        if (!timer_id) continue;

        const double start = monotonic_ns();
        MSG msg;
        bool got_timer = false;
        const double deadline = monotonic_ns() + (delay_ms * 3 + 150) * 1e6;

        while (monotonic_ns() < deadline) {
            if (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_TIMER && msg.wParam == timer_id) {
                    got_timer = true;
                    break;
                }
                DispatchMessageW(&msg);
            }
            bounded_sleep(1);
        }

        const double elapsed_ms = (monotonic_ns() - start) / 1e6;
        KillTimer(nullptr, timer_id);

        if (got_timer) {
            trials.push_back(elapsed_ms);
        }
    }

    if (trials.empty()) {
        return {unavailable(id, name, "WM_TIMER message not received within the deadline")};
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "al-khaser timing_SetTimer: Installs a Win32 GUI timer via SetTimer and dispatches "
                     "messages to detect accelerated timer dispatching.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 6. win.timing.wait_for_multiple_objects
// ---------------------------------------------------------------------------
std::vector<Finding> wait_for_multiple_objects(Context& ctx) {
    const char* id = "timing.wait_for_multiple_objects";
    const char* name = "WaitForMultipleObjects timeout delay";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.wfmo_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        Handle ev0(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        Handle ev1(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!ev0.valid() || !ev1.valid()) continue;

        HANDLE handles[2] = {ev0.get(), ev1.get()};
        const double start = monotonic_ns();
        DWORD res = WaitForMultipleObjects(2, handles, FALSE, delay_ms);
        const double elapsed_ms = (monotonic_ns() - start) / 1e6;

        if (res == WAIT_TIMEOUT) {
            trials.push_back(elapsed_ms);
        }
    }

    if (trials.empty()) {
        return {unavailable(id, name, "WaitForMultipleObjects returned unexpected status")};
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "al-khaser timing_WaitForMultipleObjects: Waits on multiple unsignaled events with "
                     "a timeout to detect premature WAIT_TIMEOUT return.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 7. win.timing.sleep_loop
// ---------------------------------------------------------------------------
std::vector<Finding> sleep_loop(Context& ctx) {
    const char* id = "timing.sleep_loop";
    const char* name = "Repeated Sleep loop";
    constexpr unsigned kDefaultLoops = 10;
    constexpr unsigned kDefaultStepMs = 15;
    const unsigned loops = static_cast<unsigned>(bounded_int(ctx, "timing.sleep_loop_count", kDefaultLoops, 2, 50));
    const unsigned step_ms = static_cast<unsigned>(bounded_int(ctx, "timing.sleep_loop_step_ms", kDefaultStepMs, 5, 100));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    const unsigned expected_total_ms = loops * step_ms;

    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        const double start = monotonic_ns();
        for (unsigned i = 0; i < loops; ++i) {
            Sleep(step_ms);
        }
        const double elapsed_ms = (monotonic_ns() - start) / 1e6;
        trials.push_back(elapsed_ms);
    }

    const auto stats = statistics(trials);
    const double threshold = expected_total_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("loops", loops);
    m.set("step_ms", step_ms);
    m.set("expected_total_ms", expected_total_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("expected_ms", expected_total_ms);

    return {measured(id, name,
                     "al-khaser timing_sleep_loop: Performs repeated short Sleep() calls in a loop "
                     "and compares total elapsed clock time against expected cumulative duration.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 8. win.timing.timesetevent_delay
// ---------------------------------------------------------------------------
std::vector<Finding> timesetevent_delay(Context& ctx) {
    const char* id = "timing.timesetevent_delay";
    const char* name = "timeSetEvent multimedia timer delay";
    HMODULE winmm = get_winmm();
    const auto fnSet = symbol<TimeSetEventFn>(winmm, "timeSetEvent");
    const auto fnKill = symbol<TimeKillEventFn>(winmm, "timeKillEvent");
    if (!fnSet || !fnKill) {
        return {unavailable(id, name, "winmm!timeSetEvent / timeKillEvent unavailable")};
    }

    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.timesetevent_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        Handle hEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!hEvent.valid()) continue;

        const double start = monotonic_ns();
        UINT tid = fnSet(
            delay_ms, 1,
            mm_timer_routine,
            reinterpret_cast<DWORD_PTR>(hEvent.get()), 0 /* TIME_ONESHOT */);

        if (!tid) continue;

        DWORD res = WaitForSingleObject(hEvent.get(), delay_ms * 3 + 150);
        const double elapsed_ms = (monotonic_ns() - start) / 1e6;
        fnKill(tid);

        if (res == WAIT_OBJECT_0) {
            trials.push_back(elapsed_ms);
        }
    }

    if (trials.empty()) {
        return {unavailable(id, name, "Multimedia timer callback failed to fire within timeout")};
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "al-khaser timing_timeSetEvent: Schedules a delayed callback using multimedia timer API "
                     "timeSetEvent to detect premature callback triggering.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 9. win.timing.cuckoo_delay_interval
// ---------------------------------------------------------------------------
std::vector<Finding> cuckoo_delay_interval(Context&) {
    const char* id = "timing.cuckoo_delay_interval";
    const char* name = "NtDelayExecution DelayInterval buffer integrity";
    const auto delay_fn = nt<DelayExecutionFn>("NtDelayExecution");
    if (!delay_fn) {
        return {unavailable(id, name, "ntdll!NtDelayExecution unavailable")};
    }

    // Monitor hooks in Cuckoo sometimes alter the DelayInterval buffer in-place
    // or modify surrounding stack memory when rewriting the sleep interval.
    struct BufferCheck {
        LONGLONG guard_before = 0x1122334455667788LL;
        LARGE_INTEGER interval{{static_cast<ULONG>(-200000 & 0xffffffff), -1}}; // 20 ms
        LONGLONG guard_after = static_cast<LONGLONG>(0x99AABBCCDDEEFF00ULL);
    } test;

    const LONGLONG original_val = test.interval.QuadPart;
    const double start = monotonic_ns();
    const LONG status = delay_fn(FALSE, &test.interval);
    const double elapsed_ms = (monotonic_ns() - start) / 1e6;

    const bool modified = (test.interval.QuadPart != original_val) ||
                          (test.guard_before != 0x1122334455667788LL) ||
                          (test.guard_after != static_cast<LONGLONG>(0x99AABBCCDDEEFF00ULL));

    Json m = numbers({
        {"status", static_cast<double>(status)},
        {"original_interval_100ns", static_cast<double>(original_val)},
        {"resulting_interval_100ns", static_cast<double>(test.interval.QuadPart)},
        {"elapsed_ms", elapsed_ms},
        {"in_place_modified", modified ? 1.0 : 0.0}
    });

    Json ev = Json::object();
    ev.set("interval_altered", modified);
    ev.set("status", status);

    return {measured(id, name,
                     "InviZzzible cuckoo/DelayInterval: Verifies whether the DelayInterval memory buffer "
                     "passed to NtDelayExecution is modified in-place by an in-guest monitor hook.",
                     Severity::Medium, modified, ev, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 10. win.timing.cuckoo_infinite_delay
// ---------------------------------------------------------------------------
struct InfiniteWaitParams {
    HANDLE hWakeup = nullptr;
    bool completed = false;
    DWORD wait_result = 0;
    double elapsed_ms = 0;
};

DWORD WINAPI infinite_wait_thread(LPVOID param) {
    auto* p = static_cast<InfiniteWaitParams*>(param);
    const double start = monotonic_ns();
    p->wait_result = WaitForSingleObject(p->hWakeup, INFINITE);
    p->elapsed_ms = (monotonic_ns() - start) / 1e6;
    p->completed = true;
    return 0;
}

std::vector<Finding> cuckoo_infinite_delay(Context&) {
    const char* id = "timing.cuckoo_infinite_delay";
    const char* name = "INFINITE wait skip detection";

    // HARD SAFETY RULE: Never perform an unbounded wait on the main thread.
    // Spawn a worker thread that waits on an unsignaled event with INFINITE.
    // The main thread waits on the worker thread with a bounded timeout (60 ms).
    // If the worker thread returns before the wakeup event is signaled, the
    // sandbox intercepted and skipped the INFINITE wait.
    Handle hWakeup(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!hWakeup.valid()) {
        return {unavailable(id, name, "Failed to create test synchronization event")};
    }

    // Heap-held and intentionally leaked if the worker outlives its 500 ms join: it must never write to a dead
    // stack frame.
    auto* heap = new InfiniteWaitParams{hWakeup.get(), false, 0, 0};
    InfiniteWaitParams& data = *heap;
    Handle hThread(CreateThread(nullptr, 0, infinite_wait_thread, heap, 0, nullptr));
    if (!hThread.valid()) {
        delete heap;
        return {unavailable(id, name, "Failed to spawn worker thread")};
    }

    // Hard time budget: bounded 60 ms wait
    DWORD res = WaitForSingleObject(hThread.get(), 60);
    const bool prematurely_returned = (res == WAIT_OBJECT_0);

    // Clean up worker thread: signal wakeup and wait for exit
    SetEvent(hWakeup.get());
    const bool joined = WaitForSingleObject(hThread.get(), 500) == WAIT_OBJECT_0;
    if (!joined) hWakeup.release();  // the worker may still wait on it; leak the event with the context
    const double worker_elapsed_ms = data.elapsed_ms;
    const DWORD worker_wait_result = data.wait_result;
    if (joined) delete heap;

    Json m = numbers({
        {"bounded_probe_ms", 60.0},
        {"worker_completed_early", prematurely_returned ? 1.0 : 0.0},
        {"worker_elapsed_ms", worker_elapsed_ms},
        {"worker_wait_result", static_cast<double>(worker_wait_result)}
    });

    Json ev = Json::object();
    ev.set("skipped_infinite_wait", prematurely_returned);
    ev.set("probe_budget_ms", 60);

    return {measured(id, name,
                     "InviZzzible cuckoo/InfiniteDelay: Requests an INFINITE wait under a bounded safety "
                     "watchdog to test whether a sleep-skipping sandbox terminates the wait early.",
                     Severity::High, prematurely_returned, ev, m, 0.90)};
}

// ---------------------------------------------------------------------------
// 11. win.timing.cuckoo_socket_timeout
// ---------------------------------------------------------------------------
std::vector<Finding> cuckoo_socket_timeout(Context&) {
    const char* id = "timing.cuckoo_socket_timeout";
    const char* name = "Socket timeout vs sleep delay comparison";

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return {unavailable(id, name, "WSAStartup failed: " + win::last_error_message())};
    }

    constexpr DWORD kDelayMs = 100;
    std::vector<double> sleep_trials, sock_trials;

    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        // 1. Measure standard Sleep()
        const double s_start = monotonic_ns();
        Sleep(kDelayMs);
        sleep_trials.push_back((monotonic_ns() - s_start) / 1e6);

        // 2. Measure blocking socket timeout on unbinded/unconnected loopback UDP socket
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s != INVALID_SOCKET) {
            DWORD timeout = kDelayMs;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

            char buf[16];
            sockaddr_in from{};
            int fromlen = sizeof(from);
            const double sock_start = monotonic_ns();
            recvfrom(s, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &fromlen);
            sock_trials.push_back((monotonic_ns() - sock_start) / 1e6);
            closesocket(s);
        }
    }
    WSACleanup();

    if (sleep_trials.empty() || sock_trials.empty()) {
        return {unavailable(id, name, "Failed to collect socket or sleep timing samples")};
    }

    const auto sleep_stats = statistics(sleep_trials);
    const auto sock_stats = statistics(sock_trials);

    // Detected if Sleep() was accelerated (median < 50% target) while socket timeout
    // ran unaccelerated at true wall-clock speed (>= 75% target).
    const bool selective_acceleration = (sleep_stats.median < (kDelayMs * 0.50)) &&
                                        (sock_stats.median >= (kDelayMs * 0.75));

    Json m = Json::object();
    m.set("sleep_ms", sleep_stats.json());
    m.set("socket_timeout_ms", sock_stats.json());
    m.set("requested_ms", static_cast<double>(kDelayMs));
    m.set("ratio", sleep_stats.median > 0 ? (sock_stats.median / sleep_stats.median) : 0);

    Json ev = Json::object();
    ev.set("selective_sleep_skipping", selective_acceleration);
    ev.set("median_sleep_ms", sleep_stats.median);
    ev.set("median_socket_ms", sock_stats.median);

    return {measured(id, name,
                     "InviZzzible cuckoo/SocketTimeout: Compares blocking socket timeout duration against "
                     "sleep delays to detect selective sleep acceleration.",
                     Severity::Medium, selective_acceleration, ev, m,
                     std::min(statistical_confidence(sleep_stats), statistical_confidence(sock_stats)))};
}

// ---------------------------------------------------------------------------
// 12. win.timing.kuser_tickcount_drift
// ---------------------------------------------------------------------------
std::vector<Finding> kuser_tickcount_drift(Context&) {
    const char* id = "timing.kuser_tickcount_drift";
    const char* name = "KUSER_SHARED_DATA TickCount drift";

    std::vector<double> deltas;
    for (unsigned i = 0; i < 5; ++i) {
        const auto kuser = read_kuser_tick();
        const ULONGLONG api = GetTickCount64();
        if (kuser.valid) {
            deltas.push_back(std::abs(static_cast<double>(api) - static_cast<double>(kuser.tick_ms)));
        }
        bounded_sleep(5);
    }

    if (deltas.empty()) {
        return {unavailable(id, name, "KUSER_SHARED_DATA TickCount unreadable")};
    }

    const auto stats = statistics(deltas);
    // Typical timer tick resolution is 15.6 ms; a drift above 64 ms indicates hooking
    constexpr double kMaxDriftMs = 64.0;
    const bool drifted = stats.median > kMaxDriftMs;

    Json m = stats.json();
    m.set("threshold_drift_ms", kMaxDriftMs);

    Json ev = Json::object();
    ev.set("median_drift_ms", stats.median);
    ev.set("samples", static_cast<double>(deltas.size()));

    return {measured(id, name,
                     "InviZzzible cuckoo/TickCount: Compares GetTickCount API return values with "
                     "KUSER_SHARED_DATA TickCount to detect hooked tick APIs.",
                     Severity::Medium, drifted, ev, m, statistical_confidence(stats, 0.80))};
}

// ---------------------------------------------------------------------------
// 13. win.timing.external_time_tampering
// ---------------------------------------------------------------------------
std::vector<Finding> external_time_tampering(Context& ctx) {
    const char* id = "timing.external_time_tampering";
    const char* name = "External HTTP Date vs system clock";

    if (!ctx.network) {
        return {unavailable(id, name, "Network checks disabled by configuration")};
    }

    // Never a default third-party server: the operator names a host they control (or may contact).
    const std::string host_str = ctx.param("timing.time_server", "");
    if (host_str.empty())
        return {skipped(id, name, "HTTP Date header against the guest clock.", Severity::High,
                        "no time server given (--param timing.time_server=HOST)")};
    const std::wstring host = win::widen(host_str);

    HINTERNET hSession = WinHttpOpen(L"Perdedor/2", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        return {unavailable(id, name, "WinHttpOpen failed: " + win::last_error_message())};
    }

    // Bounded short timeouts (2 seconds)
    WinHttpSetTimeouts(hSession, 2000, 2000, 2000, 2000);
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return {unavailable(id, name, "WinHttpConnect to " + host_str + " failed: " + win::last_error_message())};
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", L"/", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {unavailable(id, name, "WinHttpOpenRequest failed: " + win::last_error_message())};
    }

    DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled));
    // Only the Date header is read. A guest whose clock is far off fails certificate validity checks, which is
    // exactly the case this check measures, so certificate errors are ignored for this one HEAD request.
    DWORD ignore = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &ignore, sizeof(ignore));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD err = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {unavailable(id, name, "WinHttp request to " + host_str + " failed: " + win::last_error_message(err))};
    }

    SYSTEMTIME server_st{};
    DWORD size = sizeof(server_st);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_DATE | WINHTTP_QUERY_FLAG_SYSTEMTIME,
                             WINHTTP_HEADER_NAME_BY_INDEX, &server_st, &size, WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return {unavailable(id, name, "HTTP Date header absent or invalid")};
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    SYSTEMTIME guest_st{};
    GetSystemTime(&guest_st);

    FILETIME server_ft{}, guest_ft{};
    if (!SystemTimeToFileTime(&server_st, &server_ft) || !SystemTimeToFileTime(&guest_st, &guest_ft))
        return {unavailable(id, name, "could not convert the Date header or the guest time")};

    uint64_t t_srv = (uint64_t(server_ft.dwHighDateTime) << 32) | server_ft.dwLowDateTime;
    uint64_t t_gst = (uint64_t(guest_ft.dwHighDateTime) << 32) | guest_ft.dwLowDateTime;
    double delta_sec = std::abs(static_cast<double>(t_srv) - static_cast<double>(t_gst)) / 10000000.0;

    // Tolerance threshold: 3600 seconds (1 hour)
    constexpr double kMaxSkewSec = 3600.0;
    const bool tampered = delta_sec > kMaxSkewSec;

    Json m = numbers({
        {"skew_seconds", delta_sec},
        {"threshold_seconds", kMaxSkewSec}
    });

    Json ev = Json::object();
    ev.set("host", host_str);
    ev.set("skew_seconds", delta_sec);
    ev.set("tampered", tampered);

    return {measured(id, name,
                     "InviZzzible generic/TimeTampering: Fetches HTTP Date headers from external web servers "
                     "and compares them with the guest system clock to detect time tampering.",
                     Severity::High, tampered, ev, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 14. win.timing.get_local_time_delay
// ---------------------------------------------------------------------------
std::vector<Finding> get_local_time_delay(Context& ctx) {
    const char* id = "timing.get_local_time_delay";
    const char* name = "GetLocalTime delay measurement";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.getlocaltime_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        SYSTEMTIME st1{}, st2{};
        FILETIME ft1{}, ft2{};
        GetLocalTime(&st1);
        Sleep(delay_ms);
        GetLocalTime(&st2);

        SystemTimeToFileTime(&st1, &ft1);
        SystemTimeToFileTime(&st2, &ft2);

        uint64_t t1 = (uint64_t(ft1.dwHighDateTime) << 32) | ft1.dwLowDateTime;
        uint64_t t2 = (uint64_t(ft2.dwHighDateTime) << 32) | ft2.dwLowDateTime;
        double elapsed_ms = (t2 >= t1 ? (t2 - t1) : 0) / 10000.0;
        trials.push_back(elapsed_ms);
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "Check Point anti-debug/timing/getlocaltime: Measures time intervals across delays "
                     "using GetLocalTime to detect accelerated clock rates.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 15. win.timing.get_system_time_delay
// ---------------------------------------------------------------------------
std::vector<Finding> get_system_time_delay(Context& ctx) {
    const char* id = "timing.get_system_time_delay";
    const char* name = "GetSystemTime delay measurement";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.getsystemtime_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        SYSTEMTIME st1{}, st2{};
        FILETIME ft1{}, ft2{};
        GetSystemTime(&st1);
        Sleep(delay_ms);
        GetSystemTime(&st2);

        SystemTimeToFileTime(&st1, &ft1);
        SystemTimeToFileTime(&st2, &ft2);

        uint64_t t1 = (uint64_t(ft1.dwHighDateTime) << 32) | ft1.dwLowDateTime;
        uint64_t t2 = (uint64_t(ft2.dwHighDateTime) << 32) | ft2.dwLowDateTime;
        double elapsed_ms = (t2 >= t1 ? (t2 - t1) : 0) / 10000.0;
        trials.push_back(elapsed_ms);
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "Check Point anti-debug/timing/getsystemtime: Measures delays using GetSystemTime "
                     "to detect discrepancies against hardware clock timers.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 16. win.timing.get_tick_count_delay
// ---------------------------------------------------------------------------
std::vector<Finding> get_tick_count_delay(Context& ctx) {
    const char* id = "timing.get_tick_count_delay";
    const char* name = "GetTickCount delay measurement";
    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.gettickcount_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        DWORD t1 = GetTickCount();
        Sleep(delay_ms);
        DWORD t2 = GetTickCount();
        double elapsed_ms = static_cast<double>(t2 >= t1 ? (t2 - t1) : 0);
        trials.push_back(elapsed_ms);
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "Check Point anti-debug/timing/gettickcount: Measures time elapsed across sleep "
                     "using GetTickCount to detect accelerated time.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 17. win.timing.kernel_kuser_tick_timing
// ---------------------------------------------------------------------------
std::vector<Finding> kernel_kuser_tick_timing(Context&) {
    const char* id = "timing.kernel_kuser_tick_timing";
    const char* name = "Direct kernel KUSER_SHARED_DATA tick consistency";

    std::vector<double> deltas;
    for (unsigned i = 0; i < 5; ++i) {
        const auto kuser = read_kuser_tick();
        const ULONGLONG api = GetTickCount64();  // the 32-bit GetTickCount wraps after 49.7 days of uptime
        if (kuser.valid) {
            deltas.push_back(std::abs(static_cast<double>(api) - static_cast<double>(kuser.tick_ms)));
        }
        bounded_sleep(5);
    }

    if (deltas.empty()) {
        return {unavailable(id, name, "KUSER_SHARED_DATA TickCount unreadable")};
    }

    const auto stats = statistics(deltas);
    constexpr double kMaxDiscrepancyMs = 64.0;
    const bool detected = stats.median > kMaxDiscrepancyMs;

    Json m = stats.json();
    m.set("threshold_discrepancy_ms", kMaxDiscrepancyMs);

    Json ev = Json::object();
    ev.set("median_discrepancy_ms", stats.median);
    ev.set("samples", static_cast<double>(deltas.size()));

    return {measured(id, name,
                     "Check Point anti-debug/timing/kernel-timing: Reads kernel timing data directly via "
                     "KUSER_SHARED_DATA to bypass user-mode API timing hooks and verify API consistency.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.80))};
}

// ---------------------------------------------------------------------------
// 18. win.timing.time_get_time_delay
// ---------------------------------------------------------------------------
std::vector<Finding> time_get_time_delay(Context& ctx) {
    const char* id = "timing.time_get_time_delay";
    const char* name = "timeGetTime delay measurement";
    HMODULE winmm = get_winmm();
    const auto fnGetTime = symbol<TimeGetTimeFn>(winmm, "timeGetTime");
    if (!fnGetTime) {
        return {unavailable(id, name, "winmm!timeGetTime unavailable")};
    }

    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.timegettime_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        DWORD t1 = fnGetTime();
        Sleep(delay_ms);
        DWORD t2 = fnGetTime();
        double elapsed_ms = static_cast<double>(t2 >= t1 ? (t2 - t1) : 0);
        trials.push_back(elapsed_ms);
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);

    Json ev = Json::object();
    ev.set("median_elapsed_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "Check Point anti-debug/timing/timegettime: Measures execution delays with "
                     "winmm!timeGetTime to detect virtualization sleep skipping.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

// ---------------------------------------------------------------------------
// 19. win.timing.network_adapter_reset_time
// ---------------------------------------------------------------------------
std::vector<Finding> network_adapter_reset_time(Context& ctx) {
    const char* id = "timing.network_adapter_reset_time";
    const char* name = "Network adapter reset timestamp";

    auto rows = win::wmi(
        L"ROOT\\CIMV2",
        L"SELECT TimeOfLastReset FROM Win32_NetworkAdapter WHERE TimeOfLastReset IS NOT NULL",
        {L"TimeOfLastReset"});

    if (!rows.ok() && win::access_denied(rows.code)) {
        return {unavailable(id, name, "Access denied querying WMI Win32_NetworkAdapter")};
    }
    if (!rows.ok()) {
        return {unavailable(id, name, "WMI query failed: " + rows.error)};
    }
    if (rows.absent || rows.value.empty()) {
        return {skipped(id, name, "Network adapter reset timestamp.", Severity::Medium,
                        "No Win32_NetworkAdapter instances with TimeOfLastReset present")};
    }

    constexpr double kDefaultLowUptimeSeconds = 600.0;
    const double threshold = bounded_double(ctx, "timing.adapter_reset_seconds", kDefaultLowUptimeSeconds, 0, 86400);

    // Current time in UTC Unix seconds
    const double now_sec = wall_ns() / 1e9;
    double min_age_sec = 1e12;
    unsigned valid_adapters = 0;

    for (const auto& row : rows.value) {
        auto val = win::field(row, "TimeOfLastReset");
        if (val.size() < 14) continue;

        int64_t days = winlogic::date_days(val.substr(0, 8));
        if (days < 0) continue;

        // Parse HHMMSS
        uint64_t hh = 0, mm = 0, ss = 0;
        if (winlogic::integer(val.substr(8, 2), hh) &&
            winlogic::integer(val.substr(10, 2), mm) &&
            winlogic::integer(val.substr(12, 2), ss)) {
            int64_t reset_unix = days * 86400 + hh * 3600 + mm * 60 + ss;
            // CIM datetime: yyyymmddHHMMSS.ffffff followed by the offset from UTC in minutes (+UUU / -UUU),
            // so the value is local time. Convert to UTC before comparing with the clock.
            uint64_t offset_min = 0;
            if (val.size() >= 25 && (val[21] == '+' || val[21] == '-') && winlogic::integer(val.substr(22, 3), offset_min))
                reset_unix -= (val[21] == '+' ? 1 : -1) * static_cast<int64_t>(offset_min) * 60;
            double age = now_sec - static_cast<double>(reset_unix);
            if (age >= 0) {
                min_age_sec = std::min(min_age_sec, age);
                ++valid_adapters;
            }
        }
    }

    if (valid_adapters == 0) {
        return {skipped(id, name, "Network adapter reset timestamp.", Severity::Medium,
                        "Could not parse TimeOfLastReset datetime strings")};
    }

    const bool detected = min_age_sec < threshold;

    Json m = numbers({
        {"min_reset_age_seconds", min_age_sec},
        {"threshold_seconds", threshold},
        {"valid_adapters", static_cast<double>(valid_adapters)}
    });

    Json ev = Json::object();
    ev.set("min_reset_age_seconds", min_age_sec);
    ev.set("recent_reset", detected);

    return {measured(id, name,
                     "Check Point evasions/wmi/check-network-adapter-reset-time: Queries WMI "
                     "Win32_NetworkAdapter TimeOfLastReset to detect newly spawned sandbox VMs.",
                     Severity::Medium, detected, ev, m, 0.70)};
}

// ---------------------------------------------------------------------------
// 20. win.timing.dotnet_time_delay
// ---------------------------------------------------------------------------
std::vector<Finding> dotnet_time_delay(Context& ctx) {
    const char* id = "timing.dotnet_time_delay";
    const char* name = ".NET Thread.Sleep and Stopwatch timing";

    constexpr unsigned kRequestedMs = 150;
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.35, 0.05, 0.80);

    // Create stdout pipe for child process
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return {unavailable(id, name, "Failed to create stdout pipe: " + win::last_error_message())};
    }
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = nullptr;

    PROCESS_INFORMATION pi{};
    // Command line executes Stopwatch and Thread.Sleep(150) in managed .NET runtime
    // Absolute System32 path: never resolve powershell.exe through the search path.
    wchar_t sysdir[MAX_PATH]{};
    if (!GetSystemDirectoryW(sysdir, MAX_PATH)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return {unavailable(id, name, "GetSystemDirectory failed")};
    }
    std::wstring cmd = L"\"" + std::wstring(sysdir) + L"\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive -Command "
                       L"\"$s=[System.Diagnostics.Stopwatch]::StartNew(); "
                       L"[System.Threading.Thread]::Sleep(150); "
                       L"$s.Stop(); "
                       L"Write-Host $s.ElapsedMilliseconds\"";

    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(L'\0');

    const double start = monotonic_ns();
    BOOL created = CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                                  CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite); // Close write end in parent so ReadFile finishes on process exit

    if (!created) {
        CloseHandle(hRead);
        return {unavailable(id, name, "PowerShell / .NET runtime execution unavailable")};
    }

    // Bounded hard timeout of 5 seconds
    DWORD wait_res = WaitForSingleObject(pi.hProcess, 5000);
    if (wait_res == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 1000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);
        return {unavailable(id, name, "PowerShell .NET timing probe timed out")};
    }

    char buffer[256]{};
    DWORD bytes_read = 0;
    ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytes_read, nullptr);
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    const double total_proc_ms = (monotonic_ns() - start) / 1e6;

    uint64_t managed_ms = 0;
    std::string out_str(buffer, bytes_read);
    // Trim whitespace
    out_str.erase(std::remove_if(out_str.begin(), out_str.end(), [](unsigned char c) { return std::isspace(c); }), out_str.end());

    if (!winlogic::integer(out_str, managed_ms)) {
        return {unavailable(id, name, "Could not parse .NET Stopwatch output: '" + out_str + "'")};
    }

    const double threshold = kRequestedMs * (1.0 - tolerance);
    const bool detected = managed_ms < threshold;

    Json m = numbers({
        {"requested_ms", static_cast<double>(kRequestedMs)},
        {"managed_elapsed_ms", static_cast<double>(managed_ms)},
        {"total_process_ms", total_proc_ms},
        {"threshold_ms", threshold}
    });

    Json ev = Json::object();
    ev.set("managed_elapsed_ms", static_cast<double>(managed_ms));
    ev.set("requested_ms", kRequestedMs);
    ev.set("premature_return", detected);

    return {measured(id, name,
                     "capa check-for-time-delay-in-dotnet: Measures execution delay in .NET managed code "
                     "using Thread.Sleep and Stopwatch to detect accelerated execution.",
                     Severity::Medium, detected, ev, m, 0.80)};
}

// ---------------------------------------------------------------------------
// 21. win.timing.qpc_time_delay_loop
// ---------------------------------------------------------------------------
std::vector<Finding> qpc_time_delay_loop(Context& ctx) {
    const char* id = "timing.qpc_time_delay_loop";
    const char* name = "QueryPerformanceCounter delay loop";

    LARGE_INTEGER freq{};
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0) {
        return {unavailable(id, name, "QueryPerformanceFrequency unavailable")};
    }

    constexpr unsigned kDefaultDelayMs = 100;
    const unsigned delay_ms = static_cast<unsigned>(bounded_int(ctx, "timing.qpc_loop_ms", kDefaultDelayMs, 20, 1000));
    const double tolerance = bounded_double(ctx, "timing.sleep_tolerance", 0.30, 0.05, 0.80);

    const LONGLONG target_ticks = (static_cast<LONGLONG>(delay_ms) * freq.QuadPart) / 1000;

    std::vector<double> trials;
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        // Reference: GetTickCount64 (the interrupt tick), independent of QPC; its 15.6 ms granularity is well
        // inside the 30 % tolerance on a 100 ms loop. monotonic_ns() is QPC itself and cannot be the reference.
        LARGE_INTEGER start{}, now{};
        QueryPerformanceCounter(&start);
        const ULONGLONG tick_start = GetTickCount64();
        const ULONGLONG tick_deadline = tick_start + delay_ms * 3 + 150;

        do {
            if (GetTickCount64() >= tick_deadline) break;
            YieldProcessor();
            QueryPerformanceCounter(&now);
        } while ((now.QuadPart - start.QuadPart) < target_ticks);

        trials.push_back(static_cast<double>(GetTickCount64() - tick_start));
    }

    const auto stats = statistics(trials);
    const double threshold = delay_ms * (1.0 - tolerance);
    // If the QPC loop terminated because QPC reported target delay elapsed,
    // but the true monotonic clock elapsed significantly less time, QPC was accelerated.
    const bool detected = stats.median < threshold;

    Json m = stats.json();
    m.set("requested_ms", delay_ms);
    m.set("threshold_ms", threshold);
    m.set("qpc_frequency", static_cast<double>(freq.QuadPart));

    Json ev = Json::object();
    ev.set("median_tick_ms", stats.median);
    ev.set("requested_ms", delay_ms);

    return {measured(id, name,
                     "capa check-for-time-delay-via-queryperformancecounter: Executes a delay loop using "
                     "QueryPerformanceCounter against independent monotonic timing to detect accelerated QPC virtual time.",
                     Severity::Medium, detected, ev, m, statistical_confidence(stats, 0.75))};
}

}  // namespace

// Registration of all 21 checks without the "win." prefix
PERDEDOR_REGISTER(clock_jitter_vmaware, "timing.clock_source", "medium", false, "timing.clock_jitter_vmaware");
PERDEDOR_REGISTER(create_timer_queue_timer, "timing.sleep_acceleration", "medium", false, "timing.create_timer_queue_timer");
PERDEDOR_REGISTER(create_waitable_timer, "timing.sleep_acceleration", "medium", false, "timing.create_waitable_timer");
PERDEDOR_REGISTER(icmp_send_echo_delay, "timing.sleep_acceleration", "medium", true, "timing.icmp_send_echo_delay");
PERDEDOR_REGISTER(user32_set_timer, "timing.sleep_acceleration", "medium", false, "timing.user32_set_timer");
PERDEDOR_REGISTER(wait_for_multiple_objects, "timing.sleep_acceleration", "medium", false, "timing.wait_for_multiple_objects");
PERDEDOR_REGISTER(sleep_loop, "timing.sleep_acceleration", "medium", false, "timing.sleep_loop");
PERDEDOR_REGISTER(timesetevent_delay, "timing.sleep_acceleration", "medium", false, "timing.timesetevent_delay");
PERDEDOR_REGISTER(cuckoo_delay_interval, "timing.sleep_acceleration", "fast", false, "timing.cuckoo_delay_interval");
PERDEDOR_REGISTER(cuckoo_infinite_delay, "timing.sleep_acceleration", "fast", false, "timing.cuckoo_infinite_delay");
PERDEDOR_REGISTER(cuckoo_socket_timeout, "timing.sleep_acceleration", "medium", false, "timing.cuckoo_socket_timeout");
PERDEDOR_REGISTER(kuser_tickcount_drift, "timing.uptime", "fast", false, "timing.kuser_tickcount_drift");
PERDEDOR_REGISTER(external_time_tampering, "timing.time_plausibility", "fast", true, "timing.external_time_tampering");
PERDEDOR_REGISTER(get_local_time_delay, "timing.sleep_acceleration", "fast", false, "timing.get_local_time_delay");
PERDEDOR_REGISTER(get_system_time_delay, "timing.sleep_acceleration", "fast", false, "timing.get_system_time_delay");
PERDEDOR_REGISTER(get_tick_count_delay, "timing.sleep_acceleration", "fast", false, "timing.get_tick_count_delay");
PERDEDOR_REGISTER(kernel_kuser_tick_timing, "timing.clock_source", "fast", false, "timing.kernel_kuser_tick_timing");
PERDEDOR_REGISTER(time_get_time_delay, "timing.sleep_acceleration", "fast", false, "timing.time_get_time_delay");
PERDEDOR_REGISTER(network_adapter_reset_time, "timing.uptime", "fast", false, "timing.network_adapter_reset_time");
PERDEDOR_REGISTER(dotnet_time_delay, "timing.sleep_acceleration", "medium", false, "timing.dotnet_time_delay");
PERDEDOR_REGISTER(qpc_time_delay_loop, "timing.sleep_acceleration", "medium", false, "timing.qpc_time_delay_loop");

}  // namespace perdedor
