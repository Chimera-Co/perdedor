#include "lowlevel_support.hpp"
#include "../common/pe.hpp"
#include "../common/x86.hpp"
#include "winutil.hpp"

#include <atomic>
#include <psapi.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <cwctype>
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace perdedor {
namespace {
using namespace lowlevel;
using namespace win_lowlevel;

// Helper: narrow wide string to ASCII/UTF-8
std::string to_ascii(const std::wstring& ws) {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) {
        s.push_back(wc < 128 ? static_cast<char>(wc) : '?');
    }
    return s;
}

// Helper: case-insensitive wide string search
bool contains_ci(const std::wstring& hay, const std::wstring& needle) {
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
        [](wchar_t c1, wchar_t c2) {
            return towlower(c1) == towlower(c2);
        });
    return it != hay.end();
}

// UNICODE_STRING as ntdll returns it (used by the loader-walk probes).
struct NtUnicodeString { USHORT length = 0, maximum = 0; PWSTR buffer = nullptr; };

// Raises one software exception and reports whether this process's own handler saw it. A vectored handler,
// installed first and removed before returning, recognises exactly that code and continues execution. With a
// user-mode debugger attached, the debugger gets the first chance; one that consumes the exception means the
// handler never runs. Exceptions are only raised here, never left to the fault guard (which does not recover
// arbitrary software codes).
std::atomic<DWORD> g_veh_code{0};
std::atomic<bool> g_veh_seen{false};
LONG WINAPI exact_code_veh(PEXCEPTION_POINTERS info) {
    if (info && info->ExceptionRecord && info->ExceptionRecord->ExceptionCode == g_veh_code.load()) {
        g_veh_seen = true;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
bool raised_exception_reaches_handler(DWORD code, DWORD argc, const ULONG_PTR* args) {
    g_veh_code = code;
    g_veh_seen = false;
    PVOID handler = AddVectoredExceptionHandler(1, exact_code_veh);
    if (!handler) return true;  // cannot observe: treat as delivered (clean), never as a detection
    RaiseException(code, 0, argc, args);
    RemoveVectoredExceptionHandler(handler);
    g_veh_code = 0;
    return g_veh_seen.load();
}

// Known monitoring / sandbox DLL names
const std::vector<std::wstring> kKnownSandboxDlls = {
    L"cuckoomon.dll", L"capemon.dll", L"sboxdll.dll", L"sbiedll.dll",
    L"dbghelp.dll", L"api_log.dll", L"dir_watch.dll", L"pstorec.dll",
    L"vmcheck.dll", L"wepmon.dll", L"scylla.dll", L"titan_hide.dll",
    L"hookshot.dll", L"minhook.dll"
};

// ---------------------------------------------------------------------------
// 1. win.design.unhandled_exception_filter
// ---------------------------------------------------------------------------
static volatile LONG s_uef_invoked = 0;
static LONG WINAPI custom_uef_filter(EXCEPTION_POINTERS*) {
    InterlockedIncrement(&s_uef_invoked);
    return EXCEPTION_EXECUTE_HANDLER;
}

std::vector<Finding> check_unhandled_exception_filter(Context&) {
    const char* id = "design.unhandled_exception_filter";
    const char* name = "UnhandledExceptionFilter debugger check";
    s_uef_invoked = 0;

    LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(custom_uef_filter);

    EXCEPTION_RECORD er{};
    er.ExceptionCode = 0x40010005;
    CONTEXT ctx{};
    EXCEPTION_POINTERS ep{ &er, &ctx };

    // When called directly:
    // If a debugger is present, UnhandledExceptionFilter returns EXCEPTION_CONTINUE_SEARCH (0).
    // If no debugger is present, it invokes the custom filter and returns its result (EXCEPTION_EXECUTE_HANDLER == 1).
    LONG ret = UnhandledExceptionFilter(&ep);
    SetUnhandledExceptionFilter(prev);

    const bool invoked = (s_uef_invoked > 0);
    const bool is_debugger = (!invoked || ret == EXCEPTION_CONTINUE_SEARCH);

    Json m = numbers({
        {"filter_invoked", static_cast<double>(s_uef_invoked)},
        {"uef_result", static_cast<double>(ret)},
        {"detected", static_cast<double>(is_debugger ? 1 : 0)}
    });

    Json ev = Json::object();
    ev.set("filter_invoked", invoked);
    ev.set("uef_return", static_cast<double>(ret));
    ev.set("debugger_detected", is_debugger);

    return {measured(id, name,
        "Calls UnhandledExceptionFilter with a registered top-level filter. When a user-mode debugger is attached, "
        "the custom filter is bypassed and EXCEPTION_CONTINUE_SEARCH is returned.",
        Severity::Medium, is_debugger, ev, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 2. win.design.write_watch
// ---------------------------------------------------------------------------
std::vector<Finding> check_write_watch(Context&) {
    const char* id = "design.write_watch";
    const char* name = "VirtualAlloc MEM_WRITE_WATCH inspection";

    void* page = VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
    if (!page) {
        return {unavailable(id, name, "VirtualAlloc with MEM_WRITE_WATCH failed", Severity::Low)};
    }

    *reinterpret_cast<volatile unsigned char*>(page) = 0x5A;
    UINT reset_res = ResetWriteWatch(page, 4096);

    PVOID addresses[16]{};
    ULONG_PTR count = 16;
    ULONG granularity = 0;
    UINT gw_res = GetWriteWatch(0, page, 4096, addresses, &count, &granularity);

    VirtualFree(page, 0, MEM_RELEASE);

    if (reset_res != 0 || gw_res != 0) {
        return {unavailable(id, name, "GetWriteWatch or ResetWriteWatch returned an error", Severity::Low)};
    }

    // Immediately after ResetWriteWatch, count must be 0. Any write by a debugger or hook yields count > 0.
    const bool detected_writes = (count != 0);

    Json m = numbers({
        {"modified_pages", static_cast<double>(count)},
        {"granularity", static_cast<double>(granularity)},
        {"reset_status", static_cast<double>(reset_res)},
        {"get_status", static_cast<double>(gw_res)}
    });

    Json ev = Json::object();
    ev.set("modified_pages_after_reset", static_cast<double>(count));
    ev.set("granularity", static_cast<double>(granularity));

    return {measured(id, name,
        "Allocates a MEM_WRITE_WATCH buffer, resets the watch state, and checks if external debugger or hook "
        "memory inspection dirties the watched page.",
        Severity::Low, detected_writes, ev, m, 0.8)};
}

// ---------------------------------------------------------------------------
// 5. win.design.page_exception_breakpoint
// ---------------------------------------------------------------------------
std::vector<Finding> check_page_exception_breakpoint(Context&) {
    const char* id = "design.page_exception_breakpoint";
    const char* name = "PAGE_GUARD code execution breakpoint";

    void* page = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!page) {
        return {unavailable(id, name, "VirtualAlloc failed", Severity::High)};
    }

    // RET opcode
    *static_cast<unsigned char*>(page) = 0xc3;
    DWORD old_prot = 0;
    const bool prot_ok = VirtualProtect(page, 4096, PAGE_EXECUTE_READ | PAGE_GUARD, &old_prot) != FALSE;

    if (!prot_ok) {
        VirtualFree(page, 0, MEM_RELEASE);
        return {unavailable(id, name, "VirtualProtect PAGE_GUARD failed", Severity::High)};
    }

    auto r = guard::run([](void* p) {
        auto func = reinterpret_cast<void(*)()>(p);
        func();
    }, page);

    VirtualFree(page, 0, MEM_RELEASE);

    // Normal expectation: fault with EXCEPTION_GUARD_PAGE (0x80000001).
    // An attached debugger intercepting guard pages swallows it or raises an unexpected code.
    const bool swallowed = (!r.faulted || r.code != EXCEPTION_GUARD_PAGE);

    Json m = numbers({
        {"faulted", static_cast<double>(r.faulted ? 1 : 0)},
        {"exception_code", static_cast<double>(r.code)},
        {"expected_code", static_cast<double>(EXCEPTION_GUARD_PAGE)}
    });

    Json ev = Json::object();
    ev.set("faulted", r.faulted);
    ev.set("code", hex(r.code));
    ev.set("swallowed", swallowed);

    return {measured(id, name,
        "Sets PAGE_GUARD on an executable page and executes it. An attached debugger intercepting memory breakpoints "
        "swallows the guard page exception before application handlers receive it.",
        Severity::High, swallowed, ev, m, 0.9)};
}

// ---------------------------------------------------------------------------
// 6. win.design.process_job_object
// ---------------------------------------------------------------------------
std::vector<Finding> check_process_job_object(Context&) {
    const char* id = "design.process_job_object";
    const char* name = "Process Job Object containment";

    BOOL in_job = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), nullptr, &in_job)) {
        return {unavailable(id, name, "IsProcessInJob query failed", Severity::Medium)};
    }

    const bool detected = (in_job != FALSE);

    Json m = numbers({
        {"in_job", static_cast<double>(detected ? 1 : 0)}
    });

    Json ev = Json::object();
    ev.set("is_in_job", detected);

    // Weak: Task Scheduler, terminals, SSH sessions and many launchers also run processes inside job objects.
    return {measured(id, name,
        "Checks whether the current process is assigned to a Windows Job Object (also common outside sandboxes).",
        Severity::Low, detected, ev, m, 0.3)};
}

// ---------------------------------------------------------------------------
// 7. win.design.scan_dotnet_module_structures
// ---------------------------------------------------------------------------
std::vector<Finding> check_scan_dotnet_module_structures(Context&) {
    const char* id = "design.scan_dotnet_module_structures";
    const char* name = ".NET CLR module structures in native process";

    const bool clr_loaded = (GetModuleHandleW(L"clr.dll") != nullptr ||
                             GetModuleHandleW(L"mscorwks.dll") != nullptr ||
                             GetModuleHandleW(L"mscoree.dll") != nullptr);

    // Bounded scan for BSJB metadata signature in committed pages
    constexpr uint32_t kBsjbSignature = 0x424A5342u; // "BSJB"
    bool bsjb_found = false;
    unsigned regions_scanned = 0;

    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) && regions_scanned < 256) {
        ++regions_scanned;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            const size_t check_len = std::min<size_t>(mbi.RegionSize, 4096);
            std::vector<unsigned char> page(check_len);
            if (read_memory(mbi.BaseAddress, page.data(), check_len)) {
                for (size_t i = 0; i + 4 <= check_len; i += 4) {
                    uint32_t val = 0;
                    std::memcpy(&val, page.data() + i, 4);
                    if (val == kBsjbSignature) {
                        bsjb_found = true;
                        break;
                    }
                }
            }
        }
        if (bsjb_found) break;
        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (address <= reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;
    }

    const bool hit = (clr_loaded || bsjb_found);

    Json m = numbers({
        {"clr_module_loaded", static_cast<double>(clr_loaded ? 1 : 0)},
        {"bsjb_signature_found", static_cast<double>(bsjb_found ? 1 : 0)},
        {"regions_scanned", static_cast<double>(regions_scanned)}
    });

    Json ev = Json::object();
    ev.set("clr_loaded", clr_loaded);
    ev.set("bsjb_signature", bsjb_found);

    return {measured(id, name,
        "Scans for .NET CLR runtime DLLs and BSJB metadata headers in an unmanaged native process.",
        Severity::Medium, hit, ev, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 8. win.design.scan_modules_enumprocessmodulesex_32
// ---------------------------------------------------------------------------
std::vector<Finding> check_scan_modules_enumprocessmodulesex_32(Context&) {
    const char* id = "design.scan_modules_enumprocessmodulesex_32";
    const char* name = "EnumProcessModulesEx 32-bit module enumeration";

    using EnumProcModsEx = BOOL (WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
    auto fn = symbol<EnumProcModsEx>(GetModuleHandleW(L"psapi.dll"), "EnumProcessModulesEx");
    if (!fn) fn = symbol<EnumProcModsEx>(GetModuleHandleW(L"kernel32.dll"), "EnumProcessModulesEx");
    if (!fn) {
        return {unavailable(id, name, "EnumProcessModulesEx unavailable", Severity::Medium)};
    }

    std::vector<HMODULE> mods(256);
    DWORD needed = 0;
    // LIST_MODULES_32BIT == 0x01
    const BOOL ok = fn(GetCurrentProcess(), mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &needed, 0x01);

    Json hits = Json::array();
    unsigned count = 0;
    if (ok && needed > 0) {
        count = needed / sizeof(HMODULE);
        mods.resize(std::min<size_t>(mods.size(), count));
        for (HMODULE h : mods) {
            std::array<wchar_t, MAX_PATH> name_buf{};
            if (GetModuleBaseNameW(GetCurrentProcess(), h, name_buf.data(), static_cast<DWORD>(name_buf.size()))) {
                std::wstring mname(name_buf.data());
                for (const auto& bad : kKnownSandboxDlls) {
                    if (contains_ci(mname, bad)) {
                        hits.push(to_ascii(mname));
                        break;
                    }
                }
            }
        }
    }

    const bool detected = (hits.size() > 0);
    Json m = numbers({
        {"modules_found", static_cast<double>(count)},
        {"suspicious_count", static_cast<double>(hits.size())}
    });

    return {measured(id, name,
        "Calls EnumProcessModulesEx with LIST_MODULES_32BIT to inspect 32-bit module loads for analysis tooling.",
        Severity::Medium, detected, hits, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 9. win.design.scan_modules_enumprocessmodulesex_64
// ---------------------------------------------------------------------------
std::vector<Finding> check_scan_modules_enumprocessmodulesex_64(Context&) {
    const char* id = "design.scan_modules_enumprocessmodulesex_64";
    const char* name = "EnumProcessModulesEx 64-bit module enumeration";

    using EnumProcModsEx = BOOL (WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
    auto fn = symbol<EnumProcModsEx>(GetModuleHandleW(L"psapi.dll"), "EnumProcessModulesEx");
    if (!fn) fn = symbol<EnumProcModsEx>(GetModuleHandleW(L"kernel32.dll"), "EnumProcessModulesEx");
    if (!fn) {
        return {unavailable(id, name, "EnumProcessModulesEx unavailable", Severity::Medium)};
    }

    std::vector<HMODULE> mods(256);
    DWORD needed = 0;
    // LIST_MODULES_64BIT == 0x02
    const BOOL ok = fn(GetCurrentProcess(), mods.data(), static_cast<DWORD>(mods.size() * sizeof(HMODULE)), &needed, 0x02);

    Json hits = Json::array();
    unsigned count = 0;
    if (ok && needed > 0) {
        count = needed / sizeof(HMODULE);
        mods.resize(std::min<size_t>(mods.size(), count));
        for (HMODULE h : mods) {
            std::array<wchar_t, MAX_PATH> name_buf{};
            if (GetModuleBaseNameW(GetCurrentProcess(), h, name_buf.data(), static_cast<DWORD>(name_buf.size()))) {
                std::wstring mname(name_buf.data());
                for (const auto& bad : kKnownSandboxDlls) {
                    if (contains_ci(mname, bad)) {
                        hits.push(to_ascii(mname));
                        break;
                    }
                }
            }
        }
    }

    const bool detected = (hits.size() > 0);
    Json m = numbers({
        {"modules_found", static_cast<double>(count)},
        {"suspicious_count", static_cast<double>(hits.size())}
    });

    return {measured(id, name,
        "Calls EnumProcessModulesEx with LIST_MODULES_64BIT to enumerate native 64-bit DLLs and inspect for hooks.",
        Severity::Medium, detected, hits, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 10. win.design.scan_modules_ldr_direct
// ---------------------------------------------------------------------------
std::vector<Finding> check_scan_modules_ldr_direct(Context&) {
    const char* id = "design.scan_modules_ldr_direct";
    const char* name = "Direct PEB LDR module list traversal";

    const uintptr_t p_peb = peb();
    if (!p_peb) {
        return {unavailable(id, name, "PEB address unavailable", Severity::High)};
    }

    // PEB.Ldr offset: 0x18 on x64, 0x0C on x86
    constexpr unsigned kLdrOffset = sizeof(void*) == 8 ? 0x18 : 0x0c;
    uintptr_t ldr = 0;
    if (!read_value(p_peb + kLdrOffset, ldr) || !ldr) {
        return {unavailable(id, name, "PEB.Ldr pointer unreadable", Severity::High)};
    }

    // InLoadOrderModuleList head offset in PEB_LDR_DATA: 0x10 on x64, 0x0C on x86
    constexpr unsigned kInLoadOrderOffset = sizeof(void*) == 8 ? 0x10 : 0x0c;
    const uintptr_t list_head = ldr + kInLoadOrderOffset;

    uintptr_t curr = 0;
    if (!read_value(list_head, curr) || !curr) {
        return {unavailable(id, name, "InLoadOrderModuleList head unreadable", Severity::High)};
    }

    Json hits = Json::array();
    unsigned modules_scanned = 0;

    // Traverse circular doubly linked list (bounded to 256)
    while (curr != list_head && modules_scanned < 256) {
        ++modules_scanned;

        // BaseDllName UNICODE_STRING offset in LDR_DATA_TABLE_ENTRY:
        // x64: InLoadOrderLinks(0x10) + InMemory(0x10) + InInit(0x10) + DllBase(8) + EntryPoint(8) + SizeOfImage(4+pad 4) + FullDllName(16) -> BaseDllName at 0x58
        // x86: InLoadOrderLinks(8) + InMemory(8) + InInit(8) + DllBase(4) + EntryPoint(4) + SizeOfImage(4) + FullDllName(8) -> BaseDllName at 0x2C
        constexpr unsigned kBaseDllNameOffset = sizeof(void*) == 8 ? 0x58 : 0x2c;
        NtUnicodeString ustr{};
        if (read_value(curr + kBaseDllNameOffset, ustr) && ustr.buffer && ustr.length > 0 && ustr.length < 512) {
            std::vector<wchar_t> wbuf(ustr.length / sizeof(wchar_t) + 1, 0);
            if (read_memory(ustr.buffer, wbuf.data(), ustr.length)) {
                std::wstring name_ws(wbuf.data());
                for (const auto& bad : kKnownSandboxDlls) {
                    if (contains_ci(name_ws, bad)) {
                        hits.push(to_ascii(name_ws));
                        break;
                    }
                }
            }
        }

        uintptr_t next = 0;
        if (!read_value(curr, next) || !next || next == curr) break;
        curr = next;
    }

    const bool detected = (hits.size() > 0);
    Json m = numbers({
        {"modules_scanned", static_cast<double>(modules_scanned)},
        {"suspicious_found", static_cast<double>(hits.size())}
    });

    return {measured(id, name,
        "Traverses PEB InLoadOrderModuleList directly to detect unlinked or hook-injected DLLs.",
        Severity::High, detected, hits, m, 0.9)};
}

// ---------------------------------------------------------------------------
// 11. win.design.scan_modules_ldr_enumerate
// ---------------------------------------------------------------------------
struct LdrEnumContext {
    unsigned count = 0;
    Json hits = Json::array();
};

using LdrEnumCallback = VOID (NTAPI*)(PVOID, PVOID, PBOOLEAN);
using LdrEnumerateLoadedModulesFn = LONG (NTAPI*)(ULONG, LdrEnumCallback, PVOID);

static VOID NTAPI ldr_enum_callback(PVOID ldr_entry, PVOID context, PBOOLEAN stop) {
    auto* ctx = static_cast<LdrEnumContext*>(context);
    ++ctx->count;

    constexpr unsigned kBaseDllNameOffset = sizeof(void*) == 8 ? 0x58 : 0x2c;
    const uintptr_t entry_addr = reinterpret_cast<uintptr_t>(ldr_entry);
    NtUnicodeString ustr{};
    if (read_value(entry_addr + kBaseDllNameOffset, ustr) && ustr.buffer && ustr.length > 0 && ustr.length < 512) {
        std::vector<wchar_t> wbuf(ustr.length / sizeof(wchar_t) + 1, 0);
        if (read_memory(ustr.buffer, wbuf.data(), ustr.length)) {
            std::wstring name_ws(wbuf.data());
            for (const auto& bad : kKnownSandboxDlls) {
                if (contains_ci(name_ws, bad)) {
                    ctx->hits.push(to_ascii(name_ws));
                    break;
                }
            }
        }
    }
    if (ctx->count >= 256 && stop) *stop = TRUE;
}

std::vector<Finding> check_scan_modules_ldr_enumerate(Context&) {
    const char* id = "design.scan_modules_ldr_enumerate";
    const char* name = "LdrEnumerateLoadedModules callback module scan";

    const auto fn = nt<LdrEnumerateLoadedModulesFn>("LdrEnumerateLoadedModules");
    if (!fn) {
        return {unavailable(id, name, "ntdll!LdrEnumerateLoadedModules unavailable", Severity::High)};
    }

    LdrEnumContext enum_ctx;
    LONG status = fn(0, ldr_enum_callback, &enum_ctx);

    const bool detected = (enum_ctx.hits.size() > 0);
    Json m = numbers({
        {"status", static_cast<double>(static_cast<uint32_t>(status))},
        {"modules_enumerated", static_cast<double>(enum_ctx.count)},
        {"suspicious_modules", static_cast<double>(enum_ctx.hits.size())}
    });

    return {measured(id, name,
        "Invokes native ntdll!LdrEnumerateLoadedModules to discover hidden or injected analysis DLLs.",
        Severity::High, detected, enum_ctx.hits, m, 0.9)};
}

// ---------------------------------------------------------------------------
// 12. win.design.scan_modules_memory_walk_gmi
// ---------------------------------------------------------------------------
std::vector<Finding> check_scan_modules_memory_walk_gmi(Context&) {
    const char* id = "design.scan_modules_memory_walk_gmi";
    const char* name = "VirtualQuery and GetModuleInformation memory walk";

    // A 32-bit process under WOW64 also maps the 64-bit ntdll and the wow64 images, which are executable
    // MEM_IMAGE but never in its own module list: every clean host would look like it has hidden modules.
    BOOL wow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow64) && wow64)
        return {skipped(id, name, "VirtualQuery image walk against the module list.", Severity::High,
                        "32-bit process under WOW64 (64-bit system images are mapped but not listed)")};
    unsigned regions_checked = 0, unlinked_images = 0;
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    Json unlinked = Json::array();

    while (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) && regions_checked < 512) {
        ++regions_checked;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            MODULEINFO mi{};
            if (!GetModuleInformation(GetCurrentProcess(), static_cast<HMODULE>(mbi.AllocationBase), &mi, sizeof(mi))) {
                ++unlinked_images;
                if (unlinked.size() < 16) {
                    unlinked.push(hex(reinterpret_cast<uintptr_t>(mbi.AllocationBase)));
                }
            }
        }
        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (address <= reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;
    }

    const bool detected = (unlinked_images > 0);
    Json m = numbers({
        {"regions_checked", static_cast<double>(regions_checked)},
        {"unlinked_images", static_cast<double>(unlinked_images)}
    });

    return {measured(id, name,
        "Scans process memory with VirtualQuery and verifies executable MEM_IMAGE allocations with GetModuleInformation.",
        Severity::High, detected, unlinked, m, 0.85)};
}

// ---------------------------------------------------------------------------
// 13. win.design.scan_modules_memory_walk_hidden
// ---------------------------------------------------------------------------
std::vector<Finding> check_scan_modules_memory_walk_hidden(Context&) {
    const char* id = "design.scan_modules_memory_walk_hidden";
    const char* name = "Hidden PE header scan in non-image memory";

    unsigned regions_scanned = 0, hidden_pe_count = 0;
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    Json hidden_locations = Json::array();

    while (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) && regions_scanned < 512) {
        ++regions_scanned;
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE &&
            !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            uint16_t mz = 0;
            if (read_value(reinterpret_cast<uintptr_t>(mbi.BaseAddress), mz) && mz == 0x5A4D) { // 'MZ'
                uint32_t e_lfanew = 0;
                if (read_value(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + 0x3C, e_lfanew) &&
                    e_lfanew > 0 && e_lfanew < 0x1000 && e_lfanew < mbi.RegionSize) {
                    uint32_t pe_sig = 0;
                    if (read_value(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + e_lfanew, pe_sig) &&
                        pe_sig == 0x00004550) { // 'PE\0\0'
                        ++hidden_pe_count;
                        if (hidden_locations.size() < 16) {
                            hidden_locations.push(hex(reinterpret_cast<uintptr_t>(mbi.BaseAddress)));
                        }
                    }
                }
            }
        }
        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (address <= reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;
    }

    const bool detected = (hidden_pe_count > 0);
    Json m = numbers({
        {"regions_scanned", static_cast<double>(regions_scanned)},
        {"hidden_pe_count", static_cast<double>(hidden_pe_count)}
    });

    return {measured(id, name,
        "Scans committed non-image memory regions for unlinked PE image headers indicating reflective DLL injection.",
        Severity::High, detected, hidden_locations, m, 0.9)};
}

// ---------------------------------------------------------------------------
// 14. win.design.cuckoo_tls_hooks
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_tls_hooks(Context&) {
    const char* id = "design.cuckoo_tls_hooks";
    const char* name = "Cuckoomon TLS storage hook detection";

    // Inspect TEB TlsSlots (64 slots)
    uintptr_t p_teb = 0;
#if defined(__x86_64__)
    asm volatile("movq %%gs:0x30, %0" : "=r"(p_teb));
#else
    asm volatile("movl %%fs:0x18, %0" : "=r"(p_teb));
#endif

    if (!p_teb) {
        return {unavailable(id, name, "TEB address unreadable", Severity::High)};
    }

    constexpr unsigned kTlsSlotsOffset = sizeof(void*) == 8 ? 0x1480 : 0x0e10;
    unsigned populated = 0, suspicious = 0;

    for (unsigned i = 0; i < 64; ++i) {
        uintptr_t slot_val = 0;
        if (read_value(p_teb + kTlsSlotsOffset + i * sizeof(void*), slot_val) && slot_val) {
            ++populated;
            // Query memory region of slot value: Cuckoomon hook state resides in private heap or injected hook DLL
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(slot_val), &mbi, sizeof(mbi))) {
                if (mbi.Type == MEM_IMAGE) {
                    std::array<wchar_t, MAX_PATH> mpath{};
                    if (GetModuleFileNameW(static_cast<HMODULE>(mbi.AllocationBase), mpath.data(), MAX_PATH)) {
                        std::wstring ws(mpath.data());
                        if (contains_ci(ws, L"cuckoomon") || contains_ci(ws, L"capemon")) {
                            ++suspicious;
                        }
                    }
                }
            }
        }
    }

    const bool detected = (suspicious > 0);
    Json m = numbers({
        {"populated_tls_slots", static_cast<double>(populated)},
        {"suspicious_hook_slots", static_cast<double>(suspicious)}
    });

    return {measured(id, name,
        "Inspects Thread Local Storage slots for Cuckoomon / CAPE in-guest monitoring state pointers.",
        Severity::High, detected, Json::object(), m, 0.9)};
}

// ---------------------------------------------------------------------------
// 16. win.design.cuckoo_argument_checks
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_argument_checks(Context&) {
    const char* id = "design.cuckoo_argument_checks";
    const char* name = "Cuckoo hook invalid argument handling";

    using NtDelayExecutionFn = LONG (NTAPI*)(BOOLEAN, PLARGE_INTEGER);
    const auto fn = nt<NtDelayExecutionFn>("NtDelayExecution");
    if (!fn) {
        return {unavailable(id, name, "NtDelayExecution unavailable", Severity::High)};
    }

    // Pass invalid unmapped pointer 0x1337. Real kernel returns STATUS_ACCESS_VIOLATION (0xC0000005).
    // Flawed Cuckoo hook fails to validate pointer and returns STATUS_SUCCESS (0).
    LONG status = 0;
    auto r = guard::run([](void* p) {
        auto pfn = reinterpret_cast<NtDelayExecutionFn>(p);
        pfn(FALSE, reinterpret_cast<PLARGE_INTEGER>(static_cast<uintptr_t>(0x1337)));
    }, reinterpret_cast<void*>(fn));

    if (r.faulted) {
        // Guard intercepted crash in hook
        return {measured(id, name, "Hook crashed on invalid pointer argument.", Severity::High,
            true, Json::object(), numbers({{"crashed", 1}}), 0.9)};
    }

    status = fn(FALSE, reinterpret_cast<PLARGE_INTEGER>(static_cast<uintptr_t>(0x1337)));
    const bool missing_checks = (status == 0); // STATUS_SUCCESS

    Json m = numbers({
        {"nt_status", static_cast<double>(static_cast<uint32_t>(status))},
        {"returned_success", static_cast<double>(missing_checks ? 1 : 0)}
    });

    return {measured(id, name,
        "Calls NtDelayExecution with an invalid unmapped pointer to test if hook trampolines lack argument validation.",
        Severity::High, missing_checks, Json::object(), m, 0.9)};
}

// ---------------------------------------------------------------------------
// 18. win.design.cuckoo_raised_exceptions
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_raised_exceptions(Context&) {
    const char* id = "design.cuckoo_raised_exceptions";
    const char* name = "Raised exception delivery under monitoring";
    // Only exceptions the fault guard recovers from: an illegal instruction and a breakpoint. Both must come back
    // to this process with their own code; a monitor that swallows or rewrites them breaks delivery.
    unsigned caught = 0;
    auto r1 = guard::run([](void*) { asm volatile("ud2" : : : "memory"); });
    if (r1.faulted && r1.code == EXCEPTION_ILLEGAL_INSTRUCTION) ++caught;
    auto r2 = guard::run([](void*) { asm volatile("int3" : : : "memory"); });
    if (r2.faulted && r2.code == EXCEPTION_BREAKPOINT) ++caught;
    const bool broken = caught < 2;
    Json ev = Json::object();
    ev.set("ud2_code", hex(r1.code));
    ev.set("int3_code", hex(r2.code));
    Json m = numbers({{"caught", static_cast<double>(caught)}, {"expected", 2.0}});
    return {measured(id, name,
        "Raises an illegal instruction and a breakpoint under the fault guard; both must be delivered back with their own codes.",
        Severity::Medium, broken, ev, m, 0.8)};
}

// ---------------------------------------------------------------------------
// 20. win.design.cuckoo_taskscheduler_process
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_taskscheduler_process(Context&) {
    const char* id = "design.cuckoo_taskscheduler_process";
    const char* name = "Task Scheduler service availability";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return {unavailable(id, name, "OpenSCManager failed", Severity::Medium)};
    }

    SC_HANDLE svc = OpenServiceW(scm, L"Schedule", SERVICE_QUERY_STATUS);
    bool disabled_or_stopped = false;
    DWORD state = 0;

    if (svc) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
            state = ssp.dwCurrentState;
            if (state == SERVICE_STOPPED) {
                disabled_or_stopped = true;
            }
        }
        CloseServiceHandle(svc);
    } else {
        disabled_or_stopped = true;
    }
    CloseServiceHandle(scm);

    Json m = numbers({
        {"service_state", static_cast<double>(state)},
        {"disabled_or_stopped", static_cast<double>(disabled_or_stopped ? 1 : 0)}
    });

    return {measured(id, name,
        "Checks whether the Windows Task Scheduler (Schedule) service is active or crippled in the sandbox.",
        Severity::Medium, disabled_or_stopped, Json::object(), m, 0.75)};
}

// ---------------------------------------------------------------------------
// 21. win.design.cuckoo_unbalanced_stack
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_unbalanced_stack(Context&) {
    const char* id = "design.cuckoo_unbalanced_stack";
    const char* name = "Stack canary corruption across hooked functions";

    volatile uint64_t canary1 = 0x1122334455667788ULL;
    volatile uint64_t canary2 = 0xAABBCCDDEEFF0011ULL;

    Sleep(0);
    GetTickCount();

    const bool corrupted = (canary1 != 0x1122334455667788ULL || canary2 != 0xAABBCCDDEEFF0011ULL);

    Json m = numbers({
        {"canary1_ok", static_cast<double>(canary1 == 0x1122334455667788ULL ? 1 : 0)},
        {"canary2_ok", static_cast<double>(canary2 == 0xAABBCCDDEEFF0011ULL ? 1 : 0)}
    });

    return {measured(id, name,
        "Places stack canaries across hooked API invocations to test for stack frame clobbering by hook trampolines.",
        Severity::High, corrupted, Json::object(), m, 0.9)};
}

// ---------------------------------------------------------------------------
// 22. win.design.cuckoo_wmi_process
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_wmi_process(Context&) {
    const char* id = "design.cuckoo_wmi_process";
    const char* name = "WMI service infrastructure availability";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return {unavailable(id, name, "OpenSCManager failed", Severity::Medium)};
    }

    SC_HANDLE svc = OpenServiceW(scm, L"winmgmt", SERVICE_QUERY_STATUS);
    bool disabled_or_stopped = false;
    DWORD state = 0;

    if (svc) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
            state = ssp.dwCurrentState;
            if (state == SERVICE_STOPPED) {
                disabled_or_stopped = true;
            }
        }
        CloseServiceHandle(svc);
    } else {
        disabled_or_stopped = true;
    }
    CloseServiceHandle(scm);

    Json m = numbers({
        {"service_state", static_cast<double>(state)},
        {"wmi_disabled_or_stopped", static_cast<double>(disabled_or_stopped ? 1 : 0)}
    });

    return {measured(id, name,
        "Tests if the Windows Management Instrumentation (winmgmt) service is disabled or stripped in the analysis sandbox.",
        Severity::Medium, disabled_or_stopped, Json::object(), m, 0.75)};
}

// ---------------------------------------------------------------------------
// 23. win.design.cuckoo_whitelisted_process
// ---------------------------------------------------------------------------
std::vector<Finding> check_cuckoo_whitelisted_process(Context&) {
    const char* id = "design.cuckoo_whitelisted_process";
    const char* name = "Cuckoo process whitelisting evasion checks";

    std::array<wchar_t, MAX_PATH> path{};
    GetModuleFileNameW(nullptr, path.data(), MAX_PATH);
    std::wstring exe_path(path.data());

    // Check for cuckoomon/capemon config files in system/temp directories
    const std::vector<std::wstring> config_paths = {
        L"C:\\cuckoomon.ini", L"C:\\capemon.ini",
        L"C:\\Windows\\Temp\\cuckoomon.ini", L"C:\\Windows\\Temp\\capemon.ini"
    };

    bool config_found = false;
    for (const auto& cp : config_paths) {
        DWORD attrs = GetFileAttributesW(cp.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            config_found = true;
            break;
        }
    }

    Json m = numbers({
        {"config_file_found", static_cast<double>(config_found ? 1 : 0)}
    });

    return {measured(id, name,
        "Checks for Cuckoo/CAPE process whitelisting configuration files and exclusions.",
        Severity::Medium, config_found, Json::object(), m, 0.8)};
}

// ---------------------------------------------------------------------------
// 24. win.design.instruction_counting
// ---------------------------------------------------------------------------
static volatile LONG s_step_counter = 0;
static uintptr_t s_range_start = 0;
static uintptr_t s_range_end = 0;

static LONG WINAPI step_veh_handler(PEXCEPTION_POINTERS pExc) {
    if (pExc->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        const uintptr_t ip =
#if defined(__x86_64__)
            pExc->ContextRecord->Rip;
#else
            pExc->ContextRecord->Eip;
#endif
        if (ip >= s_range_start && ip < s_range_end) {
            InterlockedIncrement(&s_step_counter);
            pExc->ContextRecord->EFlags |= 0x100; // re-arm trap flag
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

std::vector<Finding> check_instruction_counting(Context&) {
    const char* id = "design.instruction_counting";
    const char* name = "Instruction counting via single-step trap";

    s_step_counter = 0;
    PVOID veh = AddVectoredExceptionHandler(1, step_veh_handler);
    if (!veh) {
        return {unavailable(id, name, "AddVectoredExceptionHandler failed", Severity::Medium)};
    }

    // Guarded execution of a known 5-NOP sequence with TF set
    auto r = guard::run([](void*) {
#if defined(__x86_64__)
        asm volatile(
            "leaq 1f(%%rip), %%rax\n"
            "movq %%rax, %0\n"
            "leaq 2f(%%rip), %%rax\n"
            "movq %%rax, %1\n"
            "pushfq\n"
            "orq $0x100, (%%rsp)\n"
            "popfq\n"
            "1:\n"
            "nop\n nop\n nop\n nop\n nop\n"
            "2:\n"
            : "=m"(s_range_start), "=m"(s_range_end)
            :
            : "rax", "cc", "memory"
        );
#else
        asm volatile(
            "call 0f\n"
            "0: popl %%eax\n"
            "addl $(1f - 0b), %%eax\n"
            "movl %%eax, %0\n"
            "addl $(2f - 1f), %%eax\n"
            "movl %%eax, %1\n"
            "pushfl\n"
            "orl $0x100, (%%esp)\n"
            "popfl\n"
            "1:\n"
            "nop\n nop\n nop\n nop\n nop\n"
            "2:\n"
            : "=m"(s_range_start), "=m"(s_range_end)
            :
            : "eax", "cc", "memory"
        );
#endif
    });

    RemoveVectoredExceptionHandler(veh);

    // If an external tracer or debugger swallowed traps, s_step_counter == 0
    const bool swallowed = (s_step_counter == 0);

    Json m = numbers({
        {"steps_recorded", static_cast<double>(s_step_counter)},
        {"guard_faulted", static_cast<double>(r.faulted ? 1 : 0)}
    });

    return {measured(id, name,
        "Executes a known instruction sequence under the trap flag and counts single-step events to detect external tracers.",
        Severity::Medium, swallowed, Json::object(), m, 0.8)};
}

// ---------------------------------------------------------------------------
// 25. win.design.instruction_prefixes
// ---------------------------------------------------------------------------
std::vector<Finding> check_instruction_prefixes(Context&) {
    const char* id = "design.instruction_prefixes";
    const char* name = "Redundant instruction prefix decoding";

    // 8x 0x66 operand size prefixes before 0x90 (NOP). Valid on x86/x64 up to 15 bytes total instruction length.
    auto r = guard::run([](void*) {
        asm volatile(".byte 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90" : : : "memory");
    });

    // Real CPUs execute valid redundant prefixes without faulting. Emulators with buggy decoders fault.
    const bool faulty = r.faulted;

    Json m = numbers({
        {"faulted", static_cast<double>(faulty ? 1 : 0)},
        {"exception_code", static_cast<double>(r.code)}
    });

    return {measured(id, name,
        "Executes instructions with redundant prefixes to detect decoding flaws in CPU emulators.",
        Severity::Low, faulty, Json::object(), m, 0.85)};
}

// ---------------------------------------------------------------------------
// 26. win.design.popf_and_cpuid
// ---------------------------------------------------------------------------
// After POPF sets TF, the trap fires after the instruction that FOLLOWS the POPF, so the instruction under test
// comes directly after it and its setup comes before. TF is cleared at the end; that only runs if no trap fired.
#if defined(__x86_64__)
#define PD_TF_ON "pushfq\n orq $0x100, (%%rsp)\n popfq\n"
#define PD_TF_OFF "pushfq\n andq $~0x100, (%%rsp)\n popfq\n"
#else
#define PD_TF_ON "pushfl\n orl $0x100, (%%esp)\n popfl\n"
#define PD_TF_OFF "pushfl\n andl $~0x100, (%%esp)\n popfl\n"
#endif

void popf_cpuid_probe(void*) {
#if defined(__x86_64__)
    asm volatile("xorl %%eax, %%eax\n xorl %%ecx, %%ecx\n" PD_TF_ON "cpuid\n" PD_TF_OFF
                 : : : "rax", "rbx", "rcx", "rdx", "cc", "memory");
#else
    asm volatile("pushl %%ebx\n xorl %%eax, %%eax\n xorl %%ecx, %%ecx\n" PD_TF_ON "cpuid\n" PD_TF_OFF "popl %%ebx\n"
                 : : : "eax", "ecx", "edx", "cc", "memory");
#endif
}

std::vector<Finding> check_popf_and_cpuid(Context&) {
    const char* id = "design.popf_and_cpuid";
    const char* name = "POPF and CPUID trap flag preservation";
    const auto r = guard::run(popf_cpuid_probe);
    // Bare metal raises the single-step trap right after CPUID; a hypervisor that drops TF on the VM exit does not.
    const bool trap_lost = (!r.faulted || r.code != EXCEPTION_SINGLE_STEP);
    Json m = numbers({{"faulted", r.faulted ? 1.0 : 0.0}, {"code", static_cast<double>(r.code)}});
    return {measured(id, name,
        "Sets the trap flag with POPF directly before CPUID; the single-step trap must survive the CPUID VM exit.",
        Severity::Medium, trap_lost, Json::object(), m, 0.8)};
}

void ss_shadow_probe(void* p) {
    auto* stage = static_cast<int*>(p);
    // MOV SS holds the trap past the next instruction: bare metal traps after "movl $1" (stage 1).
#if defined(__x86_64__)
    asm volatile("movw %%ss, %%ax\n" PD_TF_ON "movw %%ax, %%ss\n movl $1, %0\n movl $2, %0\n" PD_TF_OFF
                 : "=m"(*stage) : : "rax", "cc", "memory");
#else
    asm volatile("movw %%ss, %%ax\n" PD_TF_ON "movw %%ax, %%ss\n movl $1, %0\n movl $2, %0\n" PD_TF_OFF
                 : "=m"(*stage) : : "eax", "cc", "memory");
#endif
}

std::vector<Finding> check_ss_register_trap(Context&) {
    const char* id = "design.ss_register_trap";
    const char* name = "SS register interruptibility shadow";
    int stage = 0;
    const auto r = guard::run(ss_shadow_probe, &stage);
    const bool normal = r.faulted && r.code == EXCEPTION_SINGLE_STEP && stage == 1;
    Json m = numbers({{"faulted", r.faulted ? 1.0 : 0.0}, {"code", static_cast<double>(r.code)},
                      {"stage", static_cast<double>(stage)}});
    return {measured(id, name,
        "MOV SS directly after POPF sets TF: bare metal delays the trap by one instruction (stage 1); stage 0 means the shadow was lost.",
        Severity::Medium, !normal, Json::object(), m, 0.8)};
}

// ---------------------------------------------------------------------------
// 28. win.design.raise_exception_inspection
// ---------------------------------------------------------------------------
std::vector<Finding> check_raise_exception_inspection(Context&) {
    const char* id = "design.raise_exception_inspection";
    const char* name = "RaiseException first-chance exception handling";
    constexpr DWORD kTestCode = 0xE0505244u;  // application-defined code ("PRD"), never a system code
    const bool delivered = raised_exception_reaches_handler(kTestCode, 0, nullptr);
    Json m = numbers({{"delivered", delivered ? 1.0 : 0.0}, {"code", static_cast<double>(kTestCode)}});
    return {measured(id, name,
        "Raises an application-defined exception; an attached debugger that consumes it keeps it from this process's own handler.",
        Severity::Medium, !delivered, Json::object(), m, 0.8)};
}

// ---------------------------------------------------------------------------
// 32. win.design.dbgprint_exception
// ---------------------------------------------------------------------------
std::vector<Finding> check_dbgprint_exception(Context&) {
    const char* id = "design.dbgprint_exception";
    const char* name = "DbgPrint / DBG_PRINTEXCEPTION_C exception delivery";
    // DBG_PRINTEXCEPTION_C with the arguments OutputDebugStringA passes (length including NUL, then the text).
    constexpr DWORD kDbgPrintExceptionC = 0x40010006u;
    static const char kText[] = "perdedor\n";
    const ULONG_PTR args[2] = {sizeof(kText), reinterpret_cast<ULONG_PTR>(kText)};
    const bool delivered = raised_exception_reaches_handler(kDbgPrintExceptionC, 2, args);
    Json m = numbers({{"delivered", delivered ? 1.0 : 0.0}});
    return {measured(id, name,
        "Raises DBG_PRINTEXCEPTION_C as OutputDebugString does; a user-mode debugger consumes it before this process's handler.",
        Severity::Medium, !delivered, Json::object(), m, 0.8)};
}

// ---------------------------------------------------------------------------
// 34. win.design.selector_register_values
// ---------------------------------------------------------------------------
std::vector<Finding> check_selector_register_values(Context&) {
    const char* id = "design.selector_register_values";
    const char* name = "CPU segment selector register values";

    uint16_t cs = 0, ss = 0, ds = 0, es = 0, fs = 0, gs = 0;
    asm volatile("mov %%cs, %0" : "=r"(cs));
    asm volatile("mov %%ss, %0" : "=r"(ss));
    asm volatile("mov %%ds, %0" : "=r"(ds));
    asm volatile("mov %%es, %0" : "=r"(es));
    asm volatile("mov %%fs, %0" : "=r"(fs));
    asm volatile("mov %%gs, %0" : "=r"(gs));

    bool abnormal = false;
#if defined(__x86_64__)
    // Windows x64 standard user selectors: CS=0x33, SS=0x2b, DS=0x2b, ES=0x2b, FS=0x53, GS=0x2b
    if (cs != 0x33 || ss != 0x2b) {
        abnormal = true;
    }
#else
    // Windows x86 standard user selectors: CS=0x1b or 0x23, SS=0x23, DS=0x23, ES=0x23, FS=0x3b, GS=0
    // Native 32-bit Windows: CS=0x1b, SS=DS=0x23. A 32-bit process under WOW64: CS=0x23, SS=DS=0x2b.
    if ((cs != 0x1b && cs != 0x23) || (ss != 0x23 && ss != 0x2b) || (ds != 0x23 && ds != 0x2b)) {
        abnormal = true;
    }
#endif

    Json m = numbers({
        {"cs", static_cast<double>(cs)},
        {"ss", static_cast<double>(ss)},
        {"ds", static_cast<double>(ds)},
        {"es", static_cast<double>(es)},
        {"fs", static_cast<double>(fs)},
        {"gs", static_cast<double>(gs)},
        {"abnormal", static_cast<double>(abnormal ? 1 : 0)}
    });

    return {measured(id, name,
        "Reads segment selector registers (CS, SS, DS, ES, FS, GS) to detect emulator or hypervisor selector anomalies.",
        Severity::Medium, abnormal, Json::object(), m, 0.85)};
}

// ---------------------------------------------------------------------------
// 37. win.design.debugger_device_objects
// ---------------------------------------------------------------------------
std::vector<Finding> check_debugger_device_objects(Context&) {
    const char* id = "design.debugger_device_objects";
    const char* name = "Debugger device object handle probe";

    const std::vector<std::wstring> device_names = {
        L"\\\\.\\ScyllaHide", L"\\\\.\\NTICE", L"\\\\.\\SIWVID",
        L"\\\\.\\Syser", L"\\\\.\\SyserDbgMsg", L"\\\\.\\SyserBoot",
        L"\\\\.\\IceExt", L"\\\\.\\IdaPro", L"\\\\.\\x64dbg", L"\\\\.\\TitanHide"
    };

    Json hits = Json::array();
    for (const auto& dev : device_names) {
        HANDLE h = CreateFileW(dev.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            hits.push(to_ascii(dev));
        }
    }

    const bool detected = (hits.size() > 0);
    Json m = numbers({
        {"devices_found", static_cast<double>(hits.size())}
    });

    return {measured(id, name,
        "Probes for openable device handles of user-mode and kernel debugger drivers (ScyllaHide, TitanHide, Syser).",
        Severity::High, detected, hits, m, 0.95)};
}

// ---------------------------------------------------------------------------
// 38. win.behavioural.rtt_confirm_dialog
// ---------------------------------------------------------------------------
std::vector<Finding> check_rtt_confirm_dialog(Context& ctx) {
    const char* id = "behavioural.rtt_confirm_dialog";
    const char* name = "RTT confirmation dialog interaction latency";

    // Hard safety rule: dialog runs only under deep profile
    if (!ctx.deep()) {
        return {skipped(id, name,
            "Interactive confirmation dialog check runs only in deep profile.",
            Severity::Medium, "Requires deep profile")};
    }

    using MsgBoxTimeoutFn = int (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
    auto fn = symbol<MsgBoxTimeoutFn>(GetModuleHandleW(L"user32.dll"), "MessageBoxTimeoutW");

    double duration_ms = 0;
    int res = 0;

    if (fn) {
        const double t0 = monotonic_ns();
        // 1500 ms bounded timeout
        res = fn(nullptr, L"Perdedor automated verification dialog. Click OK or wait.", L"Verification", MB_OK, 0, 1500);
        duration_ms = (monotonic_ns() - t0) / 1000000.0;
    } else {
        return {unavailable(id, name, "MessageBoxTimeoutW unavailable", Severity::Medium)};
    }

    // Only a dialog that was actually shown and answered counts: IDOK, or 32000 (timed out). 0 means it could not
    // be displayed (service session, no interactive desktop); then nothing was measured.
    constexpr int kTimedOut = 32000;
    if (res != IDOK && res != kTimedOut)
        return {skipped(id, name, "Confirmation dialog reaction time.", Severity::Medium,
                        "the dialog could not be shown (no interactive desktop)")};
    // Dismissal under 50 ms means programmatic clicking (UI automation), not a person.
    const bool bot_dismissed = res == IDOK && duration_ms < 50.0;

    Json m = numbers({
        {"response_time_ms", duration_ms},
        {"return_code", static_cast<double>(res)},
        {"bot_dismissed", static_cast<double>(bot_dismissed ? 1 : 0)}
    });

    return {measured(id, name,
        "Displays a confirmation dialog and measures human reaction time; instant dismissal indicates sandbox UI automation.",
        Severity::Medium, bot_dismissed, Json::object(), m, 0.75)};
}

// ---------------------------------------------------------------------------
// 39. win.behavioural.system_parameters_info
// ---------------------------------------------------------------------------
std::vector<Finding> check_system_parameters_info(Context&) {
    const char* id = "behavioural.system_parameters_info";
    const char* name = "SystemParametersInfo wallpaper and screensaver configuration";

    std::array<wchar_t, MAX_PATH> wallpaper{};
    BOOL wp_ok = SystemParametersInfoW(SPI_GETDESKWALLPAPER, static_cast<UINT>(wallpaper.size()), wallpaper.data(), 0);

    int timeout = 0;
    BOOL to_ok = SystemParametersInfoW(SPI_GETSCREENSAVETIMEOUT, 0, &timeout, 0);

    BOOL ss_active = FALSE;
    BOOL act_ok = SystemParametersInfoW(SPI_GETSCREENSAVEACTIVE, 0, &ss_active, 0);

    if (!wp_ok && !to_ok && !act_ok) {
        return {unavailable(id, name, "SystemParametersInfo queries failed", Severity::Low)};
    }

    const bool no_wallpaper = (wallpaper[0] == L'\0');
    const bool no_screensaver = (!ss_active || timeout == 0);
    const bool vanilla_defaults = (no_wallpaper && no_screensaver);

    Json m = numbers({
        {"screensaver_active", static_cast<double>(ss_active != FALSE ? 1 : 0)},
        {"screensaver_timeout", static_cast<double>(timeout)},
        {"wallpaper_present", static_cast<double>(no_wallpaper ? 0 : 1)}
    });

    Json ev = Json::object();
    ev.set("wallpaper_path", to_ascii(std::wstring(wallpaper.data())));
    ev.set("screensaver_active", ss_active != FALSE);
    ev.set("screensaver_timeout_seconds", static_cast<double>(timeout));
    ev.set("vanilla_defaults", vanilla_defaults);

    return {measured(id, name,
        "Inspects desktop wallpaper and screensaver timeout via SystemParametersInfo to detect unconfigured sandbox profiles.",
        Severity::Low, vanilla_defaults, ev, m, 0.65)};
}

}  // namespace

// ===========================================================================
// Check Registrations
// ===========================================================================

// Group 1: Debugger Exception & Low-Level Memory Checks
PERDEDOR_REGISTER(check_unhandled_exception_filter, "debugger.exception_tricks", "fast", false, "design.unhandled_exception_filter");
PERDEDOR_REGISTER(check_write_watch, "debugger.api_flags", "fast", false, "design.write_watch");
PERDEDOR_REGISTER(check_page_exception_breakpoint, "debugger.hardware_breakpoints", "fast", false, "design.page_exception_breakpoint");
PERDEDOR_REGISTER(check_process_job_object, "debugger.api_flags", "fast", false, "design.process_job_object");

// Group 2: Module Scanning & Memory Integrity Checks
PERDEDOR_REGISTER(check_scan_dotnet_module_structures, "analysis_tools.loaded_modules", "medium", false, "design.scan_dotnet_module_structures");
PERDEDOR_REGISTER(check_scan_modules_enumprocessmodulesex_32, "analysis_tools.loaded_modules", "fast", false, "design.scan_modules_enumprocessmodulesex_32");
PERDEDOR_REGISTER(check_scan_modules_enumprocessmodulesex_64, "analysis_tools.loaded_modules", "fast", false, "design.scan_modules_enumprocessmodulesex_64");
PERDEDOR_REGISTER(check_scan_modules_ldr_direct, "analysis_tools.loaded_modules", "fast", false, "design.scan_modules_ldr_direct");
PERDEDOR_REGISTER(check_scan_modules_ldr_enumerate, "analysis_tools.loaded_modules", "fast", false, "design.scan_modules_ldr_enumerate");
PERDEDOR_REGISTER(check_scan_modules_memory_walk_gmi, "analysis_tools.loaded_modules", "medium", false, "design.scan_modules_memory_walk_gmi");
PERDEDOR_REGISTER(check_scan_modules_memory_walk_hidden, "analysis_tools.loaded_modules", "medium", false, "design.scan_modules_memory_walk_hidden");

// Group 3: Cuckoo / CAPE Hook & Trampoline Probes
PERDEDOR_REGISTER(check_cuckoo_tls_hooks, "instrumentation.inline_hooks", "fast", false, "design.cuckoo_tls_hooks");
PERDEDOR_REGISTER(check_cuckoo_argument_checks, "instrumentation.inline_hooks", "fast", false, "design.cuckoo_argument_checks");
PERDEDOR_REGISTER(check_cuckoo_raised_exceptions, "debugger.exception_tricks", "fast", false, "design.cuckoo_raised_exceptions");
PERDEDOR_REGISTER(check_cuckoo_taskscheduler_process, "instrumentation.tracing_facilities", "medium", false, "design.cuckoo_taskscheduler_process");
PERDEDOR_REGISTER(check_cuckoo_unbalanced_stack, "instrumentation.inline_hooks", "fast", false, "design.cuckoo_unbalanced_stack");
PERDEDOR_REGISTER(check_cuckoo_wmi_process, "instrumentation.tracing_facilities", "medium", false, "design.cuckoo_wmi_process");
PERDEDOR_REGISTER(check_cuckoo_whitelisted_process, "instrumentation.tracing_facilities", "fast", false, "design.cuckoo_whitelisted_process");

// Group 4: CPU & Instruction Tracing Probes
PERDEDOR_REGISTER(check_instruction_counting, "debugger.tracer", "fast", false, "design.instruction_counting");
PERDEDOR_REGISTER(check_instruction_prefixes, "cpu.undefined_instruction_behaviour", "fast", false, "design.instruction_prefixes");
PERDEDOR_REGISTER(check_popf_and_cpuid, "debugger.exception_tricks", "fast", false, "design.popf_and_cpuid");
PERDEDOR_REGISTER(check_ss_register_trap, "debugger.exception_tricks", "fast", false, "design.ss_register_trap");
PERDEDOR_REGISTER(check_raise_exception_inspection, "debugger.exception_tricks", "fast", false, "design.raise_exception_inspection");
PERDEDOR_REGISTER(check_dbgprint_exception, "debugger.api_flags", "fast", false, "design.dbgprint_exception");
PERDEDOR_REGISTER(check_selector_register_values, "cpu.descriptor_tables", "fast", false, "design.selector_register_values");
PERDEDOR_REGISTER(check_debugger_device_objects, "debugger.debug_objects", "fast", false, "design.debugger_device_objects");

// Group 5: Behavioural Checks
PERDEDOR_REGISTER(check_rtt_confirm_dialog, "human.foreground_activity", "slow", false, "behavioural.rtt_confirm_dialog");
PERDEDOR_REGISTER(check_system_parameters_info, "wear_and_tear.usage_traces", "fast", false, "behavioural.system_parameters_info");

}  // namespace perdedor
