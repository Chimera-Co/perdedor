#include "lowlevel_support.hpp"
#include "../common/pe.hpp"
#include <psapi.h>
#include <array>
#include <map>
#include <set>

namespace perdedor {
namespace {
using namespace lowlevel;
using namespace win_lowlevel;
constexpr size_t kMaxImageBytes = 128 * 1024 * 1024;  // Local resource cap; docs/notes/lowlevel.md.
constexpr unsigned kEvidenceLimit = 32;
std::string ascii(const std::wstring& value) { std::string out; for (wchar_t c : value) out += c < 128 ? static_cast<char>(c) : '?'; return out; }
bool disk_bytes(HMODULE module, std::vector<unsigned char>& out) {
    std::array<wchar_t, 32768> path{}; const DWORD length = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) return false;
    Handle file(CreateFileW(path.data(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file.valid()) return false;
    LARGE_INTEGER size{}; if (!GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 || size.QuadPart > static_cast<LONGLONG>(kMaxImageBytes)) return false;
    out.resize(static_cast<size_t>(size.QuadPart)); DWORD read = 0;
    return ReadFile(file.get(), out.data(), static_cast<DWORD>(out.size()), &read, nullptr) && read == out.size();
}
bool memory_bytes(HMODULE module, std::vector<unsigned char>& out) {
    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof info) || !info.SizeOfImage || info.SizeOfImage > kMaxImageBytes) return false;
    out.assign(info.SizeOfImage, 0); const uintptr_t base = reinterpret_cast<uintptr_t>(module); size_t offset = 0;
    while (offset < out.size()) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<const void*>(base + offset), &region, sizeof region)) return false;
        const auto region_end = reinterpret_cast<uintptr_t>(region.BaseAddress) + region.RegionSize;
        if (region_end <= base + offset) return false;
        const size_t size = std::min<size_t>(region_end - base - offset, out.size() - offset);
        if (region.State == MEM_COMMIT && !(region.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            if (!read_memory(reinterpret_cast<const void*>(base + offset), out.data() + offset, size)) return false;
        offset += size;
    }
    return true;
}
// Where does a branching prologue lead? A hook jumps into memory that is not a
// system image (an injected DLL or a private trampoline); a legitimate thunk such
// as kernel32's JMP [IAT] lands in another module under %SystemRoot%.
enum class Destination { Unresolved, SameModule, SystemImage, ForeignImage, NonImage };
const char* destination_name(Destination d) {
    switch (d) {
        case Destination::SameModule: return "same-module";
        case Destination::SystemImage: return "system-image";
        case Destination::ForeignImage: return "non-system-image";
        case Destination::NonImage: return "private-memory";
        default: return "unresolved";
    }
}
bool system_path(const std::wstring& path) {
    std::array<wchar_t, MAX_PATH> root{};
    const UINT n = GetSystemWindowsDirectoryW(root.data(), static_cast<UINT>(root.size()));
    if (!n || n >= root.size()) return false;
    std::wstring prefix(root.data(), n); if (prefix.back() != L'\\') prefix += L'\\';
    if (path.size() < prefix.size()) return false;
    return CompareStringOrdinal(path.c_str(), static_cast<int>(prefix.size()), prefix.c_str(), static_cast<int>(prefix.size()), TRUE) == CSTR_EQUAL;
}
Destination classify(uint64_t target, HMODULE owner) {
    if (!target || target > UINTPTR_MAX) return Destination::Unresolved;
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(reinterpret_cast<const void*>(static_cast<uintptr_t>(target)), &region, sizeof region) || region.State != MEM_COMMIT)
        return Destination::Unresolved;
    if (region.Type != MEM_IMAGE) return Destination::NonImage;
    const auto module = static_cast<HMODULE>(region.AllocationBase);
    if (module == owner) return Destination::SameModule;
    std::array<wchar_t, 32768> path{};
    const DWORD n = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    if (!n || n >= path.size()) return Destination::ForeignImage;
    return system_path(std::wstring(path.data(), n)) ? Destination::SystemImage : Destination::ForeignImage;
}
// Follows at most one branch at `address` (whose first bytes are `code`).
Destination follow(const unsigned char* code, size_t size, uintptr_t address, HMODULE owner, uint64_t* where = nullptr) {
    const auto branch = decode_branch(code, size, address, sizeof(void*) == 8);
    if (!branch.decoded) return Destination::Unresolved;
    uint64_t target = branch.target;
    if (branch.indirect) {
        uintptr_t pointer = 0;
        if (branch.slot > UINTPTR_MAX || !read_value(static_cast<uintptr_t>(branch.slot), pointer)) return Destination::Unresolved;
        target = pointer;
    }
    if (where) *where = target;
    return classify(target, owner);
}
bool hook_destination(Destination d) { return d == Destination::ForeignImage || d == Destination::NonImage; }
std::vector<Finding> syscall_stubs(Context&) {
    const HMODULE module = GetModuleHandleW(L"ntdll.dll"); std::vector<unsigned char> bytes;
    if (!memory_bytes(module, bytes)) return {unavailable("design.ntdll_syscall_stubs", "NT syscall stubs", "ntdll memory unreadable", Severity::High)};
    PeImage image(bytes, true); bool complete = false; const auto exports = image.exports(&complete);
    if (!image.valid() || !complete) return {unavailable("design.ntdll_syscall_stubs", "NT syscall stubs", "Malformed/incomplete PE exports", Severity::High)};
    constexpr uint32_t kExecute = 0x20000000;  // IMAGE_SCN_MEM_EXECUTE (PE format).
    const auto executable = [&](uint32_t rva) {
        for (const auto& sec : image.sections())
            if (rva >= sec.rva && rva < uint64_t(sec.rva) + sec.virtual_size) return (sec.flags & kExecute) != 0;
        return false;
    };
    Json hits = Json::array(); unsigned scanned = 0, unrecognized = 0, hooks = 0, internal = 0; std::set<uint32_t> seen;
    for (const auto& e : exports) {
        if (e.forwarded || (e.name.rfind("Nt", 0) != 0 && e.name.rfind("Zw", 0) != 0) || e.name.rfind("Ntdll", 0) == 0) continue;
        // Data exports (NtBuildNumber) and the user-mode helpers NtGetTickCount and
        // NtCurrentTeb are not syscall stubs; Zw*/Nt* aliases share one stub.
        if (!executable(e.rva) || e.name == "NtGetTickCount" || e.name == "NtCurrentTeb" || !seen.insert(e.rva).second) continue;
        const auto* p = image.at(e.rva, 32); if (!p) { complete = false; continue; } ++scanned;
        if (syscall_stub(p, 32, image.x64())) continue;
        const auto shape = prologue(p, 32, image.x64());
        uint64_t target = 0;
        const auto destination = shape == Prologue::Ordinary ? Destination::Unresolved
                                                             : follow(p, 32, reinterpret_cast<uintptr_t>(module) + e.rva, module, &target);
        const bool hook = shape == Prologue::Breakpoint || hook_destination(destination);
        if (hook) ++hooks; else if (destination == Destination::SameModule || destination == Destination::SystemImage) ++internal; else ++unrecognized;
        if (hits.size() < kEvidenceLimit && (hook || shape != Prologue::Ordinary)) {
            Json row = Json::object(); row.set("function", e.name); row.set("shape", prologue_name(shape));
            row.set("destination", destination_name(destination)); row.set("hook", hook); hits.push(row);
        }
    }
    if (!scanned) return {unavailable("design.ntdll_syscall_stubs", "NT syscall stubs", "No syscall export sample", Severity::High)};
    return {measured("design.ntdll_syscall_stubs", "NT syscall stubs", "Every Nt*/Zw* stub must have the native shape (x64 MOV R10,RCX; MOV EAX,SSN; native/WOW64 x86 gates). A stub that starts with INT3 or branches out of system images is a user-mode hook.", Severity::High,
                     hooks != 0, hits, numbers({{"scanned", scanned}, {"hooked", hooks}, {"internal_branches", internal}, {"unrecognized_shapes", unrecognized}, {"complete", complete}}), 0.85)};
}
std::vector<Finding> export_hooks(Context&) {
    // Functions sandboxes and API monitors hook most often (process, memory,
    // file, registry, network, timing, debugger queries). Pafish hooks.c checks
    // DeleteFileW, ShellExecuteExW and CreateProcessA with a MOV EDI,EDI test that
    // fails on Windows 8+; here the branch destination is resolved instead.
    struct Selection { const wchar_t* module; const char* name; };
    const Selection functions[] = {
        {L"kernel32.dll", "CreateProcessA"}, {L"kernel32.dll", "CreateProcessW"}, {L"kernel32.dll", "DeleteFileW"},
        {L"kernel32.dll", "GetTickCount"}, {L"kernel32.dll", "Sleep"}, {L"kernel32.dll", "IsDebuggerPresent"},
        {L"kernel32.dll", "LoadLibraryW"}, {L"kernel32.dll", "GetProcAddress"}, {L"kernel32.dll", "VirtualAlloc"},
        {L"kernel32.dll", "WriteProcessMemory"}, {L"kernel32.dll", "CreateRemoteThread"}, {L"kernel32.dll", "WriteFile"},
        {L"kernelbase.dll", "SleepEx"}, {L"kernelbase.dll", "CreateFileW"}, {L"kernelbase.dll", "VirtualProtect"},
        {L"kernelbase.dll", "ReadFile"}, {L"kernelbase.dll", "CreateProcessInternalW"},
        {L"user32.dll", "GetCursorPos"}, {L"user32.dll", "SetWindowsHookExW"}, {L"user32.dll", "GetAsyncKeyState"},
        {L"shell32.dll", "ShellExecuteExW"},
        {L"ws2_32.dll", "connect"}, {L"ws2_32.dll", "send"}, {L"ws2_32.dll", "getaddrinfo"},
        {L"advapi32.dll", "RegOpenKeyExW"}, {L"advapi32.dll", "RegSetValueExW"}, {L"advapi32.dll", "CreateServiceW"}};
    Json hits = Json::array(); unsigned scanned = 0, unavailable_count = 0, hooks = 0, thunks = 0;
    for (const auto& f : functions) {
        HMODULE module = GetModuleHandleW(f.module); const auto fn = module ? GetProcAddress(module, f.name) : nullptr;
        std::array<unsigned char, 32> code{};
        if (!fn || !read_memory(reinterpret_cast<const void*>(fn), code.data(), code.size())) { ++unavailable_count; continue; }
        ++scanned; const auto shape = prologue(code.data(), code.size(), sizeof(void*) == 8);
        if (shape == Prologue::Ordinary) continue;
        const auto destination = follow(code.data(), code.size(), reinterpret_cast<uintptr_t>(fn), module);
        const bool hook = shape == Prologue::Breakpoint || hook_destination(destination);
        hooks += hook; thunks += !hook;
        if (hits.size() < kEvidenceLimit) {
            Json row = Json::object(); row.set("function", f.name); row.set("module", ascii(f.module)); row.set("shape", prologue_name(shape));
            row.set("destination", destination_name(destination)); row.set("hook", hook); hits.push(row);
        }
    }
    if (!scanned) return {unavailable("design.system_export_prologues", "System export prologues", "No selected exports loaded/readable")};
    return {measured("design.system_export_prologues", "System export prologues", "JMP, PUSH/RET and INT3 prologues of commonly hooked exports; branches are followed and count as hooks only when they leave system images (forwarding thunks into kernelbase are normal).", Severity::High,
                     hooks != 0, hits, numbers({{"scanned", scanned}, {"hooked", hooks}, {"system_thunks", thunks}, {"not_loaded", unavailable_count}}), 0.85)};
}
std::vector<Finding> module_integrity(Context&) {
    Json modules = Json::array(); unsigned completed = 0, failed = 0; uint64_t total_diff = 0, total_compared = 0;
    for (const wchar_t* name : {L"ntdll.dll", L"kernelbase.dll"}) {
        const HMODULE module = GetModuleHandleW(name); std::vector<unsigned char> disk, mem;
        if (!module || !disk_bytes(module, disk) || !memory_bytes(module, mem)) { ++failed; continue; }
        PeImage raw(disk), loaded(mem, true);
        if (!raw.valid() || !loaded.valid() || raw.timestamp() != loaded.timestamp() || raw.image_size() != loaded.image_size()) { ++failed; continue; }
        bool processed = false; uint64_t diff = 0, compared = 0, relocated = 0; Json functions = Json::array();
        for (const auto& section : raw.sections()) {
            if (section.name != ".text") continue;
            const size_t size = std::min(section.raw_size, section.virtual_size); const auto* a = raw.at(section.rva, size);
            const auto* b = loaded.at(section.rva, size); std::vector<bool> mask;
            if (!a || !b || !raw.relocation_mask(section.rva, size, mask)) continue;
            // Verify actual text readability; zero-filled inaccessible pages in the snapshot are not evidence.
            std::vector<unsigned char> actual(size);
            if (!read_memory(reinterpret_cast<const unsigned char*>(module) + section.rva, actual.data(), size)) continue;
            std::vector<uint32_t> differences;
            for (size_t i = 0; i < size; ++i) {
                if (mask[i]) { ++relocated; continue; } ++compared;
                if (a[i] != actual[i]) { ++diff; differences.push_back(section.rva + static_cast<uint32_t>(i)); }
            }
            auto exports = raw.exports();
            std::sort(exports.begin(), exports.end(), [](const auto& x, const auto& y) { return x.rva < y.rva; });
            for (size_t i = 0; i < exports.size() && functions.size() < kEvidenceLimit; ++i) {
                const auto& e = exports[i]; if (e.forwarded || e.rva < section.rva || e.rva >= uint64_t(section.rva) + size) continue;
                uint32_t end = section.rva + static_cast<uint32_t>(size);
                for (size_t j = i + 1; j < exports.size(); ++j) if (exports[j].rva > e.rva) { end = std::min(end, exports[j].rva); break; }
                const auto at = std::lower_bound(differences.begin(), differences.end(), e.rva);
                if (at != differences.end() && *at < end) functions.push(e.name);
            }
            processed = true;
        }
        if (!processed) { ++failed; continue; }
        ++completed; total_diff += diff; total_compared += compared;
        Json row = numbers({{"different_bytes", static_cast<double>(diff)}, {"compared_bytes", static_cast<double>(compared)}, {"relocation_bytes_excluded", static_cast<double>(relocated)}});
        row.set("module", ascii(name)); row.set("nearest_exports", functions); modules.push(row);
    }
    Json m = numbers({{"modules_compared", completed}, {"unavailable_modules", failed}, {"different_bytes", static_cast<double>(total_diff)}, {"compared_bytes", static_cast<double>(total_compared)}});
    if (!completed || (failed && !total_diff)) { auto f = unavailable("design.system_module_text_integrity", "System module text integrity", "One or more disk/memory comparisons unavailable", Severity::High); f.evidence = modules; f.measurement = m; return {f}; }
    return {measured("design.system_module_text_integrity", "System module text integrity", "Compares ntdll/kernelbase .text against matching disk PE images, excluding relocation slots. Hotpatches and security software can legitimately change bytes.", Severity::High,
                     total_diff != 0, modules, m, 0.8)};
}
std::vector<Finding> redirection(Context&) {
    const HMODULE own = GetModuleHandleW(nullptr); std::vector<unsigned char> disk, mem;
    if (!disk_bytes(own, disk) || !memory_bytes(own, mem)) return {unavailable("design.import_export_redirection", "IAT/EAT redirection", "Own PE image unavailable", Severity::High)};
    PeImage raw(disk), loaded(mem, true);
    if (!raw.valid() || !loaded.valid()) return {unavailable("design.import_export_redirection", "IAT/EAT redirection", "Invalid own PE image", Severity::High)};
    unsigned checked = 0, unresolved = 0, mismatches = 0, eats = 0; Json hits = Json::array();
    const auto dir = raw.directory(1), size = raw.directory_size(1); const unsigned stride = raw.x64() ? 8 : 4;
    constexpr unsigned kMaxImports = 16384;  // Local PE parser work cap.
    for (uint32_t offset = 0; offset + 20 <= size && checked + unresolved < kMaxImports; offset += 20) {
        if (dir > UINT32_MAX - offset || !raw.at(dir + offset, 20)) { ++unresolved; break; }
        const uint32_t table = raw.u32(dir + offset), name_rva = raw.u32(dir + offset + 12), iat = raw.u32(dir + offset + 16);
        if (!table && !name_rva && !iat) break;
        const auto library = raw.string(name_rva); const HMODULE module = GetModuleHandleA(library.c_str());
        if (!table || !module) { ++unresolved; continue; }
        for (unsigned i = 0; checked + unresolved < kMaxImports; ++i) {
            const uint64_t lookup = uint64_t(table) + i * stride, address = uint64_t(iat) + i * stride;
            if (lookup > UINT32_MAX || address > UINT32_MAX || !raw.at(static_cast<uint32_t>(lookup), stride) || !loaded.at(static_cast<uint32_t>(address), stride)) { ++unresolved; break; }
            const uint64_t item = raw.pointer(static_cast<uint32_t>(lookup)); if (!item) break;
            const uint64_t flag = raw.x64() ? (uint64_t{1} << 63) : (uint64_t{1} << 31);
            std::string name; FARPROC expected = nullptr;
            if (item & flag) { name = "ordinal:" + std::to_string(item & 65535); expected = GetProcAddress(module, reinterpret_cast<const char*>(static_cast<uintptr_t>(item & 65535))); }
            else if (item < UINT32_MAX - 2) { name = raw.string(static_cast<uint32_t>(item) + 2); if (!name.empty()) expected = GetProcAddress(module, name.c_str()); }
            if (!expected) { ++unresolved; continue; }
            ++checked;
            if (loaded.pointer(static_cast<uint32_t>(address)) != reinterpret_cast<uintptr_t>(expected)) {
                ++mismatches; if (hits.size() < kEvidenceLimit) hits.push(library + "!" + name);
            }
        }
    }
    // al-khaser ModuleBoundsHookCheck: GetProcAddress for a module's own
    // (non-forwarded) exports must return an address inside that module.
    unsigned bounds_checked = 0, out_of_bounds = 0;
    for (HMODULE module : {GetModuleHandleW(L"ntdll.dll"), GetModuleHandleW(L"kernel32.dll"), GetModuleHandleW(L"kernelbase.dll")}) {
        MODULEINFO info{}; std::vector<unsigned char> image_bytes;
        if (!module || !GetModuleInformation(GetCurrentProcess(), module, &info, sizeof info) || !memory_bytes(module, image_bytes)) { ++unresolved; continue; }
        PeImage live(image_bytes, true); if (!live.valid()) { ++unresolved; continue; }
        const uintptr_t lo = reinterpret_cast<uintptr_t>(info.lpBaseOfDll), hi = lo + info.SizeOfImage;
        for (const auto& e : live.exports()) {
            if (e.forwarded) continue;
            const auto address = reinterpret_cast<uintptr_t>(GetProcAddress(module, e.name.c_str()));
            if (!address) continue;
            ++bounds_checked;
            if (address < lo || address >= hi) { ++out_of_bounds; ++mismatches; if (hits.size() < kEvidenceLimit) hits.push("bounds:" + e.name); }
        }
    }
    for (HMODULE module : {own, GetModuleHandleW(L"ntdll.dll"), GetModuleHandleW(L"kernelbase.dll")}) {
        std::vector<unsigned char> d, m; if (!module || !disk_bytes(module, d) || !memory_bytes(module, m)) { ++unresolved; continue; }
        PeImage a(d), b(m, true); if (!a.valid() || !b.valid() || a.timestamp() != b.timestamp()) { ++unresolved; continue; }
        // Compare EAT slots, including ordinal-only exports and forwarder RVAs.
        const uint32_t x = a.directory(0), y = b.directory(0);
        if (!x && !y) continue;
        if (!a.at(x, 40) || !b.at(y, 40)) { ++unresolved; continue; }
        const auto count = a.u32(x + 20), table = a.u32(x + 28), live = b.u32(y + 28);
        if (count > 65536 || count != b.u32(y + 20) || !a.at(table, count * 4ull) || !b.at(live, count * 4ull)) { ++unresolved; continue; }
        for (uint32_t i = 0; i < count; ++i) { ++eats; if (a.u32(table + i * 4) != b.u32(live + i * 4)) ++mismatches; }
    }
    Json m = numbers({{"imports_checked", checked}, {"exports_checked", eats}, {"bounds_checked", bounds_checked}, {"out_of_bounds", out_of_bounds}, {"unresolved", unresolved}, {"redirections", mismatches}});
    if ((!checked && !eats) || (unresolved && !mismatches)) { auto f = unavailable("design.import_export_redirection", "IAT/EAT redirection", "Incomplete import/export comparison", Severity::High); f.measurement = m; return {f}; }
    return {measured("design.import_export_redirection", "IAT/EAT redirection", "Compares own IAT with loader-resolved exports, own/ntdll/kernelbase EAT slots with disk, and checks that GetProcAddress keeps non-forwarded ntdll/kernel32/kernelbase exports inside their module.", Severity::High, mismatches != 0, hits, m, 0.85)};
}
std::vector<Finding> modules(Context&) {
    std::array<HMODULE, 1024> list{}; DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), list.data(), sizeof list, &needed) || needed > sizeof list)
        return {unavailable("design.unexpected_loaded_modules", "Unexpected own modules", "Module inventory unavailable/truncated")};
    Json matches = Json::array(); unsigned count = 0, unresolved = 0;
    for (unsigned i = 0; i < needed / sizeof(HMODULE); ++i) {
        std::array<wchar_t, 512> name{};
        if (!GetModuleBaseNameW(GetCurrentProcess(), list[i], name.data(), static_cast<DWORD>(name.size()))) { ++unresolved; continue; }
        ++count; const auto s = lower(ascii(name.data()));
        // al-khaser loaded_dlls list (exact names) plus instrumentation frameworks.
        static const char* const exact[] = {"avghookx.dll", "avghooka.dll", "snxhk.dll", "sbiedll.dll", "dbghelp.dll", "api_log.dll",
                                            "dir_watch.dll", "pstorec.dll", "vmcheck.dll", "wpespy.dll", "cmdvrt64.dll", "cmdvrt32.dll"};
        static const char* const tokens[] = {"frida", "dynamorio", "pinvm", "detours", "easyhook", "cuckoomon", "capemon", "scyllahide"};
        bool hit = false;
        for (const char* name : exact) if (s == name) hit = true;
        for (const char* token : tokens) if (s.find(token) != std::string::npos) hit = true;
        if (hit) matches.push(s);
    }
    if (unresolved && !matches.size()) return {unavailable("design.unexpected_loaded_modules", "Unexpected own modules", "Some module names unreadable")};
    return {measured("design.unexpected_loaded_modules", "Unexpected own modules", "Recognized analysis or injection libraries in this process. Crash-reporting DLLs such as dbghelp can be legitimate.", Severity::Medium,
                     matches.size() != 0, matches, numbers({{"module_count", count}, {"recognized", static_cast<double>(matches.size())}}), 0.55)};
}
std::vector<Finding> injection_registry(Context&) {
    unsigned appinit = 0, enabled = 0, appcert = 0, denied = 0, queried = 0;
    for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
        HKEY key = nullptr; LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_READ | view, &key);
        if (rc == ERROR_SUCCESS) {
            ++queried; std::array<wchar_t, 4096> values{}; DWORD type = 0, size = sizeof values, load = 0, dsize = sizeof load;
            const LONG value = RegQueryValueExW(key, L"AppInit_DLLs", nullptr, &type, reinterpret_cast<BYTE*>(values.data()), &size);
            if (value == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) && size > sizeof(wchar_t) && values[0]) ++appinit;
            else if (value != ERROR_SUCCESS && value != ERROR_FILE_NOT_FOUND) ++denied;
            if (RegQueryValueExW(key, L"LoadAppInit_DLLs", nullptr, &type, reinterpret_cast<BYTE*>(&load), &dsize) == ERROR_SUCCESS && type == REG_DWORD && load) ++enabled;
            RegCloseKey(key);
        } else if (rc != ERROR_FILE_NOT_FOUND) ++denied;
        rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", 0, KEY_READ | view, &key);
        if (rc == ERROR_SUCCESS) {
            ++queried; DWORD values = 0;
            if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &values, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) appcert += values; else ++denied;
            RegCloseKey(key);
        } else if (rc != ERROR_FILE_NOT_FOUND) ++denied;
    }
    if (denied && !appinit && !appcert) return {unavailable("design.appinit_appcert_libraries", "AppInit/AppCert injection configuration", "Registry views partly unreadable")};
    return {measured("design.appinit_appcert_libraries", "AppInit/AppCert injection configuration", "Nonempty AppInit_DLLs or AppCertDlls values expose injection configuration. Secure Boot and load policy may prevent actual AppInit injection.", Severity::Medium,
                     appinit || appcert, "Counts both registry views; shared keys can be counted twice. DLL paths are not emitted.", numbers({{"appinit_nonempty_views", appinit}, {"appinit_enabled_views", enabled}, {"appcert_values_across_views", appcert}, {"keys_read", queried}, {"access_failures", denied}}), 0.65)};
}
std::vector<Finding> callback(Context&) {
    const auto query = nt<QueryProcess>("NtQueryInformationProcess");
    if (!query) return {unavailable("design.process_instrumentation_callback", "Process instrumentation callback", "NT query unavailable")};
    struct Callback { ULONG version = 0, reserved = 0; PVOID address = nullptr; } value;
    // phnt ntpsapi.h marks class 40 as set-only on many versions; querying it
    // is not universally implemented. Never install/clear a callback as a test.
    const LONG rc = query(GetCurrentProcess(), 40, &value, sizeof value, nullptr);
    Json m = numbers({{"nt_status", static_cast<uint32_t>(rc)}, {"callback_nonnull", value.address != nullptr}});
    if (rc < 0) { auto f = unavailable("design.process_instrumentation_callback", "Process instrumentation callback", "ProcessInstrumentationCallback query unsupported/denied; set-only on many Windows versions"); f.measurement = m; return {f}; }
    return {measured("design.process_instrumentation_callback", "Process instrumentation callback", "Best-effort read-only class 40 query; a nonnull callback indicates user-mode return instrumentation.", Severity::Medium,
                     value.address != nullptr, "No callback is installed or modified.", m, 0.7)};
}
std::vector<Finding> etw_hook(Context&) {
    const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "EtwEventWrite"); std::array<unsigned char, 32> bytes{};
    if (!address || !read_memory(reinterpret_cast<const void*>(address), bytes.data(), bytes.size()))
        return {unavailable("design.etw_event_write_hook", "EtwEventWrite prologue", "Export unreadable")};
    const auto shape = prologue(bytes.data(), bytes.size(), sizeof(void*) == 8);
    // Common patches: XOR EAX,EAX; RET (x64) and XOR EAX,EAX; RET 14h (x86 stdcall, five arguments).
    const bool zero_return = bytes[0] == 0x33 && bytes[1] == 0xc0 && (bytes[2] == 0xc3 || (bytes[2] == 0xc2 && bytes[3] == 0x14 && bytes[4] == 0));
    const auto destination = shape == Prologue::Jump || shape == Prologue::PushReturn
                                 ? follow(bytes.data(), bytes.size(), reinterpret_cast<uintptr_t>(address), GetModuleHandleW(L"ntdll.dll"))
                                 : Destination::Unresolved;
    const bool patched = zero_return || shape == Prologue::Breakpoint || shape == Prologue::ReturnOnly || hook_destination(destination);
    return {measured("design.etw_event_write_hook", "EtwEventWrite prologue", "Detects branch/breakpoint/return stubs and XOR EAX,EAX; RET at the provider export. Legitimate thunking remains a possible explanation.", Severity::Medium,
                     patched, Json(std::string(prologue_name(shape)) + "/" + destination_name(destination)), numbers({{"zero_return", zero_return}, {"prologue_kind", static_cast<int>(shape)}}), 0.75)};
}
}  // namespace
PERDEDOR_REGISTER(syscall_stubs, "instrumentation.inline_hooks", "medium", false, "design.ntdll_syscall_stubs");
PERDEDOR_REGISTER(export_hooks, "instrumentation.inline_hooks", "fast", false, "design.system_export_prologues");
PERDEDOR_REGISTER(module_integrity, "instrumentation.module_integrity", "medium", false, "design.system_module_text_integrity");
PERDEDOR_REGISTER(redirection, "instrumentation.module_integrity", "medium", false, "design.import_export_redirection");
PERDEDOR_REGISTER(modules, "instrumentation.injected_libraries", "fast", false, "design.unexpected_loaded_modules");
PERDEDOR_REGISTER(injection_registry, "instrumentation.injected_libraries", "fast", false, "design.appinit_appcert_libraries");
PERDEDOR_REGISTER(callback, "instrumentation.tracing_facilities", "fast", false, "design.process_instrumentation_callback");
PERDEDOR_REGISTER(etw_hook, "instrumentation.inline_hooks", "fast", false, "design.etw_event_write_hook");
}  // namespace perdedor
