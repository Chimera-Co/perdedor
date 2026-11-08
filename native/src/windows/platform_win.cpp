#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
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
        char buf[64];
        std::snprintf(buf, sizeof buf, "%lu.%lu.%lu", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
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

}  // namespace platform
}  // namespace perdedor
