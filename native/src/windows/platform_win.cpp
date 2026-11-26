#define WIN32_LEAN_AND_MEAN
#include <string>
#include <windows.h>

#include <cstdio>
#include <io.h>
#include <memory>

#include "../core/perdedor.hpp"
#include "winutil.hpp"

namespace perdedor {
namespace platform {

const char* name() { return "windows"; }
const char* id_prefix() { return "win"; }

std::string hostname() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD n = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(buf, &n)) return "unknown";
    return win::narrow(buf);
}

Json metadata() {
    Json m = Json::object();
    m.set("os", "Windows");
    // RtlGetVersion is not subject to the manifest-based version lie of GetVersionEx.
    typedef LONG(WINAPI * RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof v;
    auto fn = reinterpret_cast<RtlGetVersionFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")));
    if (fn && fn(&v) == 0) {
        const std::string buf = std::to_string(v.dwMajorVersion) + "." + std::to_string(v.dwMinorVersion) + "." +
                                std::to_string(v.dwBuildNumber);
        m.set("os_release", buf);
    }
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    m.set("machine", si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64   ? "AMD64"
                     : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "ARM64"
                     : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? "x86"
                                                                                 : "other");
#ifdef _WIN64
    m.set("process_bits", 64);
#else
    BOOL wow = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow);
    m.set("process_bits", 32);
    m.set("wow64", static_cast<bool>(wow));
#endif
    return m;
}

Json host_facts() {
    Json facts = Json::object();
    typedef LONG(WINAPI * RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof v;
    auto fn = reinterpret_cast<RtlGetVersionFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion")));
    if (fn && fn(&v) == 0) {
        const std::string buf = std::to_string(v.dwMajorVersion) + "." + std::to_string(v.dwMinorVersion) + "." +
                                std::to_string(v.dwBuildNumber);
        facts.set("os_build", buf);
    } else {
        facts.set("os_build", "unknown");
    }

    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    facts.set("core_count", si.dwNumberOfProcessors > 0 ? static_cast<long long>(si.dwNumberOfProcessors) : 1LL);

    std::string cpu_model = "unknown";
    HKEY hkey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        wchar_t buf[256] = {0};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExW(hkey, L"ProcessorNameString", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
            cpu_model = win::narrow(buf);
        }
        RegCloseKey(hkey);
    }
    facts.set("cpu_model", cpu_model);
    return facts;
}

namespace {
struct Job {
    std::function<void()> fn;
};
DWORD WINAPI trampoline(LPVOID arg) {
    std::unique_ptr<Job> job(static_cast<Job*>(arg));
    job->fn();
    return 0;
}
}  // namespace

bool run_with_timeout(const std::function<void()>& fn, double seconds) {
    auto* job = new Job{fn};
    HANDLE th = CreateThread(nullptr, 8 * 1024 * 1024, trampoline, job, 0, nullptr);
    if (!th) {
        delete job;
        fn();
        return true;
    }
    DWORD rc = WaitForSingleObject(th, static_cast<DWORD>(seconds * 1000.0));
    CloseHandle(th);
    return rc == WAIT_OBJECT_0;
}

void hard_exit(int code) {
    std::fflush(nullptr);
    ExitProcess(static_cast<UINT>(code));
}

std::FILE* open_for_write(const std::string& path) {
    // Windows ACLs are inherited from the directory; there is no POSIX mode to restrict.
    std::FILE* f = nullptr;
    return fopen_s(&f, path.c_str(), "wb") == 0 ? f : nullptr;
}

void flush_to_disk(std::FILE* f) {
    if (!f) return;
    std::fflush(f);
    _commit(_fileno(f));
}

}  // namespace platform
}  // namespace perdedor
