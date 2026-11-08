#include "lowlevel_support.hpp"
#include <tlhelp32.h>
#include <algorithm>
#include <array>
#include <cstring>

namespace perdedor {
namespace {
using namespace lowlevel;
using namespace win_lowlevel;
std::vector<Finding> api_flags(Context&) {
    const bool local = IsDebuggerPresent() != FALSE; BOOL remote = FALSE; const BOOL ok = CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    auto a = measured("design.debugger_present", "IsDebuggerPresent", "Win32 debugger-present flag for this process.", Severity::High,
                      local, "IsDebuggerPresent", numbers({{"present", local}}), 0.95);
    auto b = ok ? measured("design.remote_debugger_present", "CheckRemoteDebuggerPresent", "Win32 debug port observation for this process.", Severity::High,
                           remote != FALSE, "CheckRemoteDebuggerPresent", numbers({{"present", remote != FALSE}}), 0.95)
                : unavailable("design.remote_debugger_present", "CheckRemoteDebuggerPresent", "API failed", Severity::High);
    return {a, b};
}
std::vector<Finding> peb_flags(Context&) {
    const uintptr_t address = peb(); unsigned char debugged = 0; uint32_t global = 0;
    // Windows 7+ PEB offsets; Check Point Anti-Debug Debug Flags manual checks.
    constexpr unsigned kGlobalOffset = sizeof(void*) == 8 ? 0xbc : 0x68;
    constexpr uint32_t kDebugHeapMask = 0x70;
    if (!read_value(address + 2, debugged) || !read_value(address + kGlobalOffset, global))
        return {unavailable("design.peb_debug_flags", "PEB debugger flags", "PEB could not be read", Severity::High)};
    return {measured("design.peb_debug_flags", "PEB debugger flags", "Direct BeingDebugged and NtGlobalFlag debug-heap bits. GFlags can set heap flags without a debugger.", Severity::High,
                     debugged || (global & kDebugHeapMask), "Reads the PEB matching the process bitness (WOW64 native PEB is not inspected).",
                     numbers({{"being_debugged", debugged}, {"nt_global_flag", global}, {"debug_heap_mask", kDebugHeapMask}}), debugged ? 0.95 : 0.65)};
}
std::vector<Finding> heap_flags(Context&) {
    const uintptr_t heap = reinterpret_cast<uintptr_t>(GetProcessHeap()); uint32_t signature = 0, flags = 0, forced = 0;
    // Segment heap signature from public Windows symbols (_SEGMENT_HEAP).
    constexpr uint32_t kSegmentHeapSignature = 0xddeeddee;
    if (read_value(heap + 0x10, signature) && signature == kSegmentHeapSignature)
        return {unavailable("design.heap_debug_flags", "Heap debug flags", "Segment heap layout; legacy NT heap offsets not applicable")};
    constexpr unsigned kFlagsOffset = sizeof(void*) == 8 ? 0x70 : 0x40;  // al-khaser ProcessHeap_Flags.cpp (Vista+).
    constexpr uint32_t kHeapDebugMask = 0x40000060;  // HEAP_TAIL_CHECKING_ENABLED, FREE_CHECKING_ENABLED, VALIDATE_PARAMETERS_ENABLED.
    constexpr uint32_t kHeapGrowable = 0x2;          // HEAP_GROWABLE: the only Flags bit a normal process heap has.
    if (!read_value(heap + kFlagsOffset, flags) || !read_value(heap + kFlagsOffset + 4, forced))
        return {unavailable("design.heap_debug_flags", "Heap debug flags", "Process heap could not be read")};
    return {measured("design.heap_debug_flags", "Heap debug flags", "NT heap Flags/ForceFlags contain debugging bits. Application Verifier or GFlags may enable them legitimately.", Severity::Medium,
                     (flags & ~kHeapGrowable) || forced, "Classic NT heap only; Vista+ offsets. al-khaser HeapFlags/HeapForceFlags: Flags > HEAP_GROWABLE or ForceFlags != 0.",
                     numbers({{"flags", flags}, {"force_flags", forced}, {"debug_bits_set", (flags & kHeapDebugMask) != 0}, {"debug_mask", kHeapDebugMask}}), 0.7)};
}
std::vector<Finding> debug_objects(Context&) {
    const auto query = nt<QueryProcess>("NtQueryInformationProcess");
    if (!query) return {unavailable("design.nt_debug_objects", "NT debug objects", "NtQueryInformationProcess unavailable", Severity::High)};
    ULONG_PTR port = 0; HANDLE object = nullptr; ULONG flags = 1;
    const LONG p = query(GetCurrentProcess(), 7, &port, sizeof port, nullptr);
    const LONG o = query(GetCurrentProcess(), 30, &object, sizeof object, nullptr);
    const LONG f = query(GetCurrentProcess(), 31, &flags, sizeof flags, nullptr);
    // ProcessDebugObjectHandle with no debug object returns STATUS_PORT_NOT_SET.
    constexpr uint32_t kPortNotSet = 0xc0000353u;
    const bool object_ok = o >= 0 || static_cast<uint32_t>(o) == kPortNotSet;
    const bool found = (p >= 0 && port) || (o >= 0 && object) || (f >= 0 && !flags);
    Handle owned_object(o >= 0 ? object : nullptr);
    Json m = numbers({{"debug_port", port != 0}, {"debug_object", object != nullptr}, {"debug_flags", flags},
                      {"port_status", static_cast<uint32_t>(p)}, {"object_status", static_cast<uint32_t>(o)}, {"flags_status", static_cast<uint32_t>(f)}});
    if (!found && (p < 0 || !object_ok || f < 0)) { auto result = unavailable("design.nt_debug_objects", "NT debug objects", "At least one NT query unavailable/denied", Severity::High); result.measurement = m; return {result}; }
    return {measured("design.nt_debug_objects", "NT debug objects", "ProcessDebugPort, ProcessDebugObjectHandle and inverse ProcessDebugFlags.", Severity::High,
                     found, "Any returned debug-object handle is closed.", m, 0.95)};
}
std::vector<Finding> kernel_debugger(Context&) {
    struct Kernel { unsigned char enabled = 0, absent = 1; } info;
    const auto query = nt<QuerySystem>("NtQuerySystemInformation");
    const LONG status = query ? query(35, &info, sizeof info, nullptr) : static_cast<LONG>(0xc0000002u);
    unsigned char shared = 0; const bool read = read_value(uintptr_t{0x7ffe02d4}, shared);
    Json m = numbers({{"nt_status", static_cast<uint32_t>(status)}, {"enabled", info.enabled}, {"not_present", info.absent}, {"shared_data_bits", shared}, {"shared_data_read", read}});
    if (status < 0 && !read) { auto f = unavailable("design.kernel_debugger", "Kernel debugger", "Neither NT query nor KUSER_SHARED_DATA readable", Severity::High); f.measurement = m; return {f}; }
    const auto kd = shared_kd(shared);
    // al-khaser NtQuerySystemInformation_SystemKernelDebuggerInformation and
    // SharedUserData_KernelDebugger: enabled OR present is a detection.
    const bool from_query = status >= 0 && (info.enabled || !info.absent), from_shared = read && (kd.enabled || kd.present);
    Json ev = Json::object(); ev.set("query", status >= 0 ? (from_query ? "kernel debugger enabled/present" : "none") : "unavailable");
    ev.set("shared_user_data", read ? (kd.present ? "enabled and present" : (kd.enabled ? "enabled" : "none")) : "unreadable");
    return {measured("design.kernel_debugger", "Kernel debugger", "SystemKernelDebuggerInformation and KUSER_SHARED_DATA.KdDebuggerEnabled (bit 0 enabled, bit 1 present). Enabled without present means debugging is configured but nothing is connected.", Severity::High,
                     from_query || from_shared, ev, m, kd.present ? 0.95 : 0.85)};
}
struct ContextRequest { HANDLE thread; CONTEXT context{}; DWORD error = 0; bool success = false; };
DWORD WINAPI get_context_worker(void* p) {
    auto& request = *static_cast<ContextRequest*>(p);
    if (SuspendThread(request.thread) == static_cast<DWORD>(-1)) { request.error = GetLastError(); return 0; }
    request.context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    request.success = GetThreadContext(request.thread, &request.context) != FALSE;
    if (!request.success) request.error = GetLastError();
    if (ResumeThread(request.thread) == static_cast<DWORD>(-1)) { request.success = false; request.error = GetLastError(); }
    return 0;
}
// Debug registers of one thread of this process. The check thread itself is read
// by a helper (GetThreadContext on the running thread is unsupported); other
// threads are suspended only for the GetThreadContext call, with no allocation
// in between, and always resumed.
bool thread_debug_registers(DWORD tid, CONTEXT& out) {
    if (tid == GetCurrentThreadId()) {
        HANDLE duplicate = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &duplicate,
                             THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, 0))
            return false;
        Handle target(duplicate); ContextRequest request{target.get()};
        Handle worker(CreateThread(nullptr, 0, get_context_worker, &request, 0, nullptr));
        if (!worker.valid()) return false;
        WaitForSingleObject(worker.get(), INFINITE);  // Bounded kernel work; the runner watchdog bounds the check.
        if (!request.success) return false;
        out = request.context; return true;
    }
    Handle thread(OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid));
    if (!thread.valid()) return false;
    if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) return false;
    out.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    const bool ok = GetThreadContext(thread.get(), &out) != FALSE;
    ResumeThread(thread.get());
    return ok;
}
std::vector<Finding> hardware_breakpoints(Context&) {
    // al-khaser HardwareBreakpoints reads Dr0-Dr3 of the current thread; every
    // thread of this process is read here because DRx state is per thread.
    std::vector<DWORD> threads;
    {
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (snapshot.valid()) {
            THREADENTRY32 entry{}; entry.dwSize = sizeof entry;
            if (Thread32First(snapshot.get(), &entry)) do {
                if (entry.th32OwnerProcessID == GetCurrentProcessId()) threads.push_back(entry.th32ThreadID);
            } while (Thread32Next(snapshot.get(), &entry));
        }
    }
    if (std::find(threads.begin(), threads.end(), GetCurrentThreadId()) == threads.end()) threads.push_back(GetCurrentThreadId());
    constexpr size_t kMaxThreads = 256;  // Resource cap; the agent runs a few dozen threads at most.
    if (threads.size() > kMaxThreads) threads.resize(kMaxThreads);
    Json rows = Json::array(); unsigned read = 0, armed = 0, addresses = 0;
    for (DWORD tid : threads) {
        CONTEXT c{};
        if (!thread_debug_registers(tid, c)) continue;
        ++read;
        // Intel SDM Vol. 3 17.2.4: DR7 bits 0-7 are the L0/G0..L3/G3 enables.
        const bool enabled = (c.Dr7 & 0xff) != 0, any_address = c.Dr0 || c.Dr1 || c.Dr2 || c.Dr3;
        armed += enabled; addresses += any_address;
        if ((enabled || any_address) && rows.size() < 16) {
            Json row = Json::object(); row.set("tid", static_cast<double>(tid)); row.set("dr0", hex(c.Dr0)); row.set("dr1", hex(c.Dr1));
            row.set("dr2", hex(c.Dr2)); row.set("dr3", hex(c.Dr3)); row.set("dr7", hex(c.Dr7)); rows.push(row);
        }
    }
    if (!read) return {unavailable("design.hardware_breakpoints", "Hardware breakpoints", "No thread context readable", Severity::High)};
    return {measured("design.hardware_breakpoints", "Hardware breakpoints", "Reads Dr0-Dr3 and Dr7 of every thread of this process. al-khaser flags any nonzero Dr0-Dr3; DR7 enables show the breakpoint is armed.", Severity::High,
                     armed != 0 || addresses != 0, rows,
                     numbers({{"threads_listed", static_cast<double>(threads.size())}, {"threads_read", read}, {"threads_armed", armed}, {"threads_with_addresses", addresses}}), 0.9)};
}
void output_probe(void* p) { SetLastError(0x5a17); OutputDebugStringA("Perdedor debugger self-test"); *static_cast<DWORD*>(p) = GetLastError(); }
std::vector<Finding> output_string(Context&) {
    DWORD error_code = 0; const auto r = guard::run(output_probe, &error_code);
    if (r.faulted) return {fault_skip("design.output_debug_string", "OutputDebugString last error", Severity::Low, r)};
    // Historical last-error trick no longer discriminates reliably on Vista+.
    return {measured("design.output_debug_string", "OutputDebugString last error", "Historical last-error observation. Modern Windows normally preserves last error regardless of debugger presence.", Severity::Low,
                     false, "No verdict is inferred solely from preserved last-error on supported Windows versions.", numbers({{"sentinel", 0x5a17}, {"last_error", error_code}, {"changed", error_code != 0x5a17}}), 0.1)};
}
void invalid_handle(void*) { CloseHandle(nullptr); }
void int3_probe(void*) { asm volatile("int3; nop" : : : "memory"); }
void int2d_probe(void*) { asm volatile("xor %%eax,%%eax; int $0x2d; nop; nop" : : : "eax", "cc", "memory"); }
void icebp_probe(void*) { asm volatile(".byte 0xf1; nop" : : : "memory"); }
void trap_probe(void*) {
#if defined(__x86_64__)
    asm volatile("pushfq; orq $0x100,(%%rsp); popfq; nop; pushfq; andq $-257,(%%rsp); popfq" : : : "cc", "memory");
#else
    asm volatile("pushfl; orl $0x100,(%%esp); popfl; nop; pushfl; andl $-257,(%%esp); popfl" : : : "cc", "memory");
#endif
}
// al-khaser MemoryBreakpoints_PageGuard: executing a PAGE_GUARD page raises
// STATUS_GUARD_PAGE_VIOLATION unless a debugger using guard pages consumes it.
void guard_page_probe(void* p) { reinterpret_cast<void (*)()>(p)(); }
std::vector<Finding> exceptions(Context&) {
    // A connected kernel debugger may break on user-mode INT3/INT 2D and stop the
    // guest; those two probes run only when no kernel debugger is enabled.
    unsigned char kd_byte = 0; const bool kd_read = read_value(uintptr_t{0x7ffe02d4}, kd_byte);
    const bool kd_safe = kd_read && !shared_kd(kd_byte).enabled && !shared_kd(kd_byte).present;
    struct Test { const char* name; guard::Probe probe; uint32_t expected; bool needs_no_kd; void* argument; };
    // RET in a PAGE_GUARD page; the page is released after the probe.
    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD old = 0; bool guarded = false;
    if (page) { *static_cast<unsigned char*>(page) = 0xc3; guarded = VirtualProtect(page, 4096, PAGE_EXECUTE_READ | PAGE_GUARD, &old) != FALSE; }
    const Test tests[] = {{"INT3", int3_probe, EXCEPTION_BREAKPOINT, true, nullptr}, {"INT2D", int2d_probe, EXCEPTION_BREAKPOINT, true, nullptr},
                          {"ICEBP", icebp_probe, EXCEPTION_SINGLE_STEP, false, nullptr}, {"trap_flag", trap_probe, EXCEPTION_SINGLE_STEP, false, nullptr},
                          {"PAGE_GUARD", guard_page_probe, EXCEPTION_GUARD_PAGE, false, guarded ? page : nullptr}};
    Json rows = Json::array(); unsigned swallowed = 0, unexpected = 0, ran = 0;
    for (const auto& test : tests) {
        Json row = Json::object(); row.set("probe", test.name);
        if ((test.needs_no_kd && !kd_safe) || (test.probe == guard_page_probe && !test.argument)) {
            row.set("skipped", test.needs_no_kd ? "kernel debugger enabled or state unreadable" : "guard page unavailable"); rows.push(row); continue;
        }
        const auto r = guard::run(test.probe, test.argument); ++ran;
        row.set("faulted", r.faulted); row.set("code", r.code); row.set("expected", test.expected); rows.push(row);
        swallowed += !r.faulted; unexpected += r.faulted && r.code != test.expected;
    }
    if (page) VirtualFree(page, 0, MEM_RELEASE);
    auto f = measured("design.debugger_exception_delivery", "Debugger exception delivery", "Checks whether INT3, INT 2D, ICEBP, trap-flag and guard-page exceptions reach the process handler. A debugger may forward them unchanged.", Severity::Medium,
                      swallowed != 0, rows, numbers({{"probes_run", ran}, {"swallowed", swallowed}, {"unexpected_faults", unexpected}}), 0.65);
    if (unexpected && !swallowed) { f.status = Status::Skipped; f.error_detail = "Unexpected exception code; execution policy may block probes"; }
    const auto close = guard::run(invalid_handle);
    // al-khaser SetHandleInformatiom_ProtectedHandle: closing a handle marked
    // HANDLE_FLAG_PROTECT_FROM_CLOSE raises STATUS_HANDLE_NOT_CLOSABLE only under
    // a debugger. The protection is removed and the handle closed afterwards.
    constexpr uint32_t kNotClosable = 0xc0000235u;
    guard::Result protected_close{};
    bool protected_ran = false;
    HANDLE mutex = CreateMutexW(nullptr, FALSE, nullptr);
    if (mutex && SetHandleInformation(mutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE)) {
        protected_close = guard::run([](void* h) { CloseHandle(static_cast<HANDLE>(h)); }, mutex); protected_ran = true;
        SetHandleInformation(mutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
    }
    if (mutex) CloseHandle(mutex);
    const bool invalid_hit = close.faulted && close.code == EXCEPTION_INVALID_HANDLE;
    const bool protected_hit = protected_ran && protected_close.faulted && protected_close.code == kNotClosable;
    auto g = measured("design.invalid_handle_exception", "Handle-close exceptions", "CloseHandle(NULL) and closing a protected handle raise exceptions only under a debugger (or Application Verifier); no real handle is lost.", Severity::Medium,
                      invalid_hit || protected_hit, "Normal behaviour is FALSE with ERROR_INVALID_HANDLE and no exception.",
                      numbers({{"invalid_faulted", close.faulted}, {"invalid_code", close.code}, {"protected_ran", protected_ran},
                               {"protected_faulted", protected_close.faulted}, {"protected_code", protected_close.code}}), 0.75);
    if (close.faulted && close.code != EXCEPTION_INVALID_HANDLE) g = fault_skip("design.invalid_handle_exception", "Handle-close exceptions", Severity::Medium, close);
    return {f, g};
}
struct HideResult { LONG set = 0, query = 0; alignas(4) unsigned char hidden = 0; };
DWORD WINAPI hide_worker(void* p) {
    auto& r = *static_cast<HideResult*>(p);
    using Set = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    using Query = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto set = nt<Set>("NtSetInformationThread");
    const auto query = nt<Query>("NtQueryInformationThread");
    if (!set || !query) { r.set = static_cast<LONG>(0xc0000002u); return 0; }
    // Only this disposable thread is hidden; never run exception probes on it.
    r.set = set(GetCurrentThread(), 0x11, nullptr, 0);
    r.query = query(GetCurrentThread(), 0x11, &r.hidden, sizeof r.hidden, nullptr);
    return 0;
}
std::vector<Finding> hide_roundtrip(Context&) {
    HideResult result; Handle thread(CreateThread(nullptr, 0, hide_worker, &result, 0, nullptr));
    if (!thread.valid()) return {unavailable("design.thread_hide_roundtrip", "ThreadHideFromDebugger round trip", "Worker unavailable")};
    WaitForSingleObject(thread.get(), INFINITE);
    Json m = numbers({{"set_status", static_cast<uint32_t>(result.set)}, {"query_status", static_cast<uint32_t>(result.query)}, {"hidden", result.hidden}});
    if (result.set < 0 || result.query < 0) { auto f = unavailable("design.thread_hide_roundtrip", "ThreadHideFromDebugger round trip", "Set/query denied or unsupported"); f.measurement = m; return {f}; }
    return {measured("design.thread_hide_roundtrip", "ThreadHideFromDebugger round trip", "A disposable thread sets and queries its hide flag to detect a successful-looking intercepted call.", Severity::Medium,
                     !result.hidden, "No agent runner thread is hidden. The worker exits immediately after the query.", m, 0.65)};
}
// al-khaser NtQueryObject_ObjectAllTypesInformation: the DebugObject type's
// object count is nonzero while any user-mode debugger session exists.
// OBJECT_TYPE_INFORMATION layout from phnt ntobapi.h; each entry is followed by
// its TypeName buffer, then aligned to pointer size.
struct NtUnicodeString { USHORT length, maximum; PWSTR buffer; };
struct ObjectTypeInfo { NtUnicodeString name; ULONG total_objects, total_handles; };
std::vector<Finding> debug_object_count(Context&) {
    const char* id = "design.debug_object_count"; const char* name = "System DebugObject count";
    using QueryObject = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = nt<QueryObject>("NtQueryObject");
    if (!query) return {unavailable(id, name, "NtQueryObject unavailable", Severity::Medium)};
    constexpr ULONG kObjectTypesInformation = 3;
    constexpr ULONG kMaxBuffer = 4 * 1024 * 1024;  // Resource cap; the table is a few tens of KiB.
    std::vector<unsigned char> buffer(64 * 1024); LONG status = 0;
    for (;;) {
        ULONG needed = 0; status = query(nullptr, kObjectTypesInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
        if (status != static_cast<LONG>(0xc0000004u) || buffer.size() >= kMaxBuffer) break;  // STATUS_INFO_LENGTH_MISMATCH
        buffer.resize(std::min<size_t>(kMaxBuffer, std::max<size_t>(buffer.size() * 2, needed + 4096)));
    }
    if (status < 0) { auto f = unavailable(id, name, "ObjectTypesInformation query failed", Severity::Medium); f.measurement = numbers({{"nt_status", static_cast<uint32_t>(status)}}); return {f}; }
    const uintptr_t base = reinterpret_cast<uintptr_t>(buffer.data()), end = base + buffer.size();
    const ULONG types = *reinterpret_cast<const ULONG*>(buffer.data());
    uintptr_t at = base + sizeof(void*);
    bool found = false, malformed = false; ULONG objects = 0, handles = 0, parsed = 0;
    for (ULONG i = 0; i < types && i < 1024; ++i) {
        if (at + sizeof(ObjectTypeInfo) > end) { malformed = true; break; }
        ObjectTypeInfo info; std::memcpy(&info, reinterpret_cast<const void*>(at), sizeof info);
        const uintptr_t text = reinterpret_cast<uintptr_t>(info.name.buffer);
        if (text < at || text > end || info.name.maximum > end - text || info.name.length > info.name.maximum) { malformed = true; break; }
        ++parsed;
        if (info.name.length == 22 && std::memcmp(reinterpret_cast<const void*>(text), L"DebugObject", 22) == 0) {
            found = true; objects = info.total_objects; handles = info.total_handles;
        }
        at = (text + info.name.maximum + sizeof(void*) - 1) & ~(uintptr_t)(sizeof(void*) - 1);
    }
    Json m = numbers({{"types_reported", types}, {"types_parsed", parsed}, {"debug_objects", objects}, {"debug_handles", handles}});
    if (!found) { auto f = unavailable(id, name, malformed ? "Object type table not in the expected layout" : "DebugObject type not listed", Severity::Medium); f.measurement = m; return {f}; }
    return {measured(id, name, "Counts DebugObject instances system-wide via NtQueryObject(ObjectTypesInformation). Any debugger in the guest, not only one attached to this process, raises it.", Severity::Medium,
                     objects != 0 || handles != 0, "System-wide count; reports numbers only.", m, 0.75)};
}
// al-khaser CanOpenCsrss: a process started by a debugger often inherits an
// enabled SeDebugPrivilege, which lets it open csrss.exe. Opened read-only for
// query and closed at once; the privilege state is read from the own token.
std::vector<Finding> debug_privilege(Context&) {
    const char* id = "design.debug_privilege"; const char* name = "SeDebugPrivilege enabled";
    HANDLE raw = nullptr; bool enabled = false, token_read = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
        Handle token(raw); LUID luid{};
        if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
            PRIVILEGE_SET set{}; set.PrivilegeCount = 1; set.Control = PRIVILEGE_SET_ALL_NECESSARY;
            set.Privilege[0].Luid = luid; set.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED; BOOL result = FALSE;
            if (PrivilegeCheck(token.get(), &set, &result)) { token_read = true; enabled = result != FALSE; }
        }
    }
    using CsrPid = DWORD (NTAPI*)();
    const auto csr = nt<CsrPid>("CsrGetProcessId");
    const DWORD pid = csr ? csr() : 0; bool opened = false; DWORD open_error = 0;
    if (pid) {
        Handle process(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        opened = process.valid(); if (!opened) open_error = GetLastError();
    }
    Json m = numbers({{"token_read", token_read}, {"privilege_enabled", enabled}, {"csrss_pid_known", pid != 0}, {"csrss_opened", opened}, {"open_error", open_error}});
    if (!token_read && !pid) { auto f = unavailable(id, name, "Token and csrss both unavailable"); f.measurement = m; return {f}; }
    return {measured(id, name, "Own token has SeDebugPrivilege enabled, or csrss.exe can be opened for query (al-khaser CanOpenCsrss). Elevated administrative tools can also enable it.", Severity::Medium,
                     enabled || opened, "Privilege state only; no other process is read.", m, 0.55)};
}
std::vector<Finding> debugger_parent(Context&) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) return {unavailable("design.debugger_parent", "Debugger parent", "Process snapshot unavailable")};
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof entry; DWORD parent = 0;
    if (Process32FirstW(snapshot.get(), &entry)) do { if (entry.th32ProcessID == GetCurrentProcessId()) { parent = entry.th32ParentProcessID; break; } } while (Process32NextW(snapshot.get(), &entry));
    std::wstring name;
    if (Process32FirstW(snapshot.get(), &entry)) do { if (entry.th32ProcessID == parent) { name = entry.szExeFile; break; } } while (Process32NextW(snapshot.get(), &entry));
    if (name.empty()) return {unavailable("design.debugger_parent", "Debugger parent", "Parent exited or was not observable")};
    std::string ascii; for (wchar_t c : name) ascii += c < 128 ? static_cast<char>(c) : '?'; ascii = lower(ascii);
    bool found = false; for (const char* tool : {"windbg.exe", "windbgx.exe", "cdb.exe", "ntsd.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "gdb.exe", "ida.exe", "ida64.exe"}) if (ascii == tool) found = true;
    return {measured("design.debugger_parent", "Debugger parent", "Immediate parent executable matches a debugger name; an ordinary shell parent is accepted.", Severity::Medium,
                     found, found ? Json(ascii) : Json("No debugger-name match"), numbers({{"matched", found}}), 0.75)};
}
}  // namespace
PERDEDOR_REGISTER(api_flags, "debugger.api_flags", "fast", false, "design.debugger_present", "design.remote_debugger_present");
PERDEDOR_REGISTER(peb_flags, "debugger.api_flags", "fast", false, "design.peb_debug_flags");
PERDEDOR_REGISTER(heap_flags, "debugger.api_flags", "fast", false, "design.heap_debug_flags");
PERDEDOR_REGISTER(debug_objects, "debugger.debug_objects", "fast", false, "design.nt_debug_objects");
PERDEDOR_REGISTER(kernel_debugger, "debugger.kernel_debugger", "fast", false, "design.kernel_debugger");
PERDEDOR_REGISTER(hardware_breakpoints, "debugger.hardware_breakpoints", "medium", false, "design.hardware_breakpoints");
PERDEDOR_REGISTER(output_string, "debugger.exception_tricks", "fast", false, "design.output_debug_string");
PERDEDOR_REGISTER(exceptions, "debugger.exception_tricks", "fast", false, "design.debugger_exception_delivery", "design.invalid_handle_exception");
PERDEDOR_REGISTER(hide_roundtrip, "debugger.debug_objects", "medium", false, "design.thread_hide_roundtrip");
PERDEDOR_REGISTER(debug_object_count, "debugger.debug_objects", "fast", false, "design.debug_object_count");
PERDEDOR_REGISTER(debug_privilege, "debugger.api_flags", "fast", false, "design.debug_privilege");
PERDEDOR_REGISTER(debugger_parent, "debugger.api_flags", "fast", false, "design.debugger_parent");
}  // namespace perdedor
