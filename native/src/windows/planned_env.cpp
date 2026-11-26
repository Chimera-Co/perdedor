#include <winsock2.h>
#include <ws2tcpip.h>
#include "lowlevel_support.hpp"
#include "system_checks.hpp"
#include "winutil.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winhttp.h>

namespace perdedor {
namespace {
using namespace lowlevel;
using namespace win_lowlevel;
using namespace winsys;

struct InternetHandle {
    HINTERNET h = nullptr;
    explicit InternetHandle(HINTERNET handle = nullptr) : h(handle) {}
    ~InternetHandle() {
        if (h)
            WinHttpCloseHandle(h);
    }
    InternetHandle(const InternetHandle &) = delete;
    InternetHandle &operator=(const InternetHandle &) = delete;
    HINTERNET get() const { return h; }
    explicit operator bool() const { return h != nullptr; }
};

struct LibraryHandle {
    HMODULE h = nullptr;
    explicit LibraryHandle(HMODULE handle = nullptr) : h(handle) {}
    ~LibraryHandle() {
        if (h)
            FreeLibrary(h);
    }
    LibraryHandle(const LibraryHandle &) = delete;
    LibraryHandle &operator=(const LibraryHandle &) = delete;
    HMODULE get() const { return h; }
    explicit operator bool() const { return h != nullptr; }
};

struct HttpResponse {
    DWORD status = 0;
    std::string body;
    bool ok = false;
};

HttpResponse http_request(const std::wstring &host, INTERNET_PORT port, const std::wstring &path,
                          const std::wstring &headers, DWORD timeout_ms) {
    HttpResponse resp;
    InternetHandle session(
        WinHttpOpen(L"PERDEDOR/2.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session)
        return resp;

    WinHttpSetTimeouts(session.get(), timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    InternetHandle connect(WinHttpConnect(session.get(), host.c_str(), port, 0));
    if (!connect)
        return resp;

    DWORD flags = (port == INTERNET_DEFAULT_HTTPS_PORT) ? WINHTTP_FLAG_SECURE : 0;
    InternetHandle req(WinHttpOpenRequest(connect.get(), L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!req)
        return resp;

    DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES;
    WinHttpSetOption(req.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled));

    LPCWSTR hdr_str = headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str();
    DWORD hdr_len = headers.empty() ? 0 : static_cast<DWORD>(headers.size());

    if (!WinHttpSendRequest(req.get(), hdr_str, hdr_len, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        return resp;
    if (!WinHttpReceiveResponse(req.get(), nullptr))
        return resp;

    DWORD status_code = 0;
    DWORD code_size = sizeof(status_code);
    if (!WinHttpQueryHeaders(req.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &code_size, WINHTTP_NO_HEADER_INDEX)) {
        return resp;
    }
    resp.status = status_code;

    char buffer[4096];
    DWORD bytes_read = 0;
    while (WinHttpReadData(req.get(), buffer, sizeof(buffer) - 1, &bytes_read) && bytes_read > 0) {
        resp.body.append(buffer, bytes_read);
        if (resp.body.size() > 65536)
            break;
    }
    resp.ok = true;
    return resp;
}

// 1. win.env.hypervisor_exception_quirks
void probe_single_step(void *) {
#if defined(__x86_64__)
    asm volatile(
        "pushfq\n"
        "orq $0x100, (%%rsp)\n"
        "popfq\n"
        "nop\n"
        :
        :
        : "memory");
#elif defined(__i386__)
    asm volatile(
        "pushfl\n"
        "orl $0x100, (%%esp)\n"
        "popfl\n"
        "nop\n"
        :
        :
        : "memory");
#endif
}

void probe_shadow(void *p) {
    auto *stage = static_cast<int *>(p);
#if defined(__x86_64__)
    asm volatile(
        "pushfq\n"
        "orq $0x100, (%%rsp)\n"
        "popfq\n"
        ".byte 0x66, 0x8c, 0xd0\n"
        ".byte 0x8e, 0xd0\n"
        "movl $1, %0\n"
        "movl $2, %0\n"
        : "=m"(*stage)
        :
        : "rax", "memory");
#elif defined(__i386__)
    asm volatile(
        "pushfl\n"
        "orl $0x100, (%%esp)\n"
        "popfl\n"
        ".byte 0x66, 0x8c, 0xd0\n"
        ".byte 0x8e, 0xd0\n"
        "movl $1, %0\n"
        "movl $2, %0\n"
        : "=m"(*stage)
        :
        : "eax", "memory");
#endif
}

void probe_cpuid_step(void *) {
#if defined(__x86_64__)
    asm volatile(
        "pushfq\n"
        "orq $0x100, (%%rsp)\n"
        "popfq\n"
        "xor %%eax, %%eax\n"
        "cpuid\n"
        :
        :
        : "rax", "rbx", "rcx", "rdx", "memory");
#elif defined(__i386__)
    asm volatile(
        "pushfl\n"
        "orl $0x100, (%%esp)\n"
        "popfl\n"
        "xor %%eax, %%eax\n"
        "push %%ebx\n"
        "cpuid\n"
        "pop %%ebx\n"
        :
        :
        : "eax", "ecx", "edx", "memory");
#endif
}

std::vector<Finding> hypervisor_exception_quirks(Context &) {
    const auto r1 = guard::run(probe_single_step);
    int shadow_stage = 0;
    const auto r2 = guard::run(probe_shadow, &shadow_stage);
    const auto r3 = guard::run(probe_cpuid_step);

    if (r1.code == guard::kUnavailable)
        return {fault_skip("env.hypervisor_exception_quirks", "Hypervisor exception quirks", Severity::Medium, r1)};

    constexpr uint32_t kSingleStepCode = 0x80000004u;
    const bool step_ok = (r1.faulted && r1.code == kSingleStepCode);
    const bool shadow_ok = (r2.faulted && shadow_stage >= 1);
    const bool cpuid_step_ok = (r3.faulted && r3.code == kSingleStepCode);
    const bool detected = (!step_ok || !shadow_ok || !cpuid_step_ok);

    Json ev = Json::object();
    ev.set("single_step_faulted", r1.faulted);
    ev.set("single_step_code", hex(r1.code));
    ev.set("interrupt_shadow_stage", static_cast<long long>(shadow_stage));
    ev.set("interrupt_shadow_faulted", r2.faulted);
    ev.set("cpuid_step_faulted", r3.faulted);
    ev.set("cpuid_step_code", hex(r3.code));

    Json m = numbers({
        {"single_step_ok", static_cast<double>(step_ok)},
        {"interrupt_shadow_ok", static_cast<double>(shadow_ok)},
        {"cpuid_step_ok", static_cast<double>(cpuid_step_ok)},
    });

    return {measured(
        "env.hypervisor_exception_quirks", "Hypervisor exception quirks",
        "Tests single-step trap delivery, interrupt shadow retention across MOV SS, and single-step across CPUID VM-exit.",
        Severity::Medium, detected, ev, m, 0.85)};
}

// 2. win.env.ept_hook_timing
struct EptTimingContext {
    FARPROC proc = nullptr;
    volatile const unsigned char *local_buf = nullptr;
    double code_delta = 0;
    double local_delta = 0;
};

void probe_ept_read(void *p) {
    auto *ctx = static_cast<EptTimingContext *>(p);
    const uint64_t t0 = ordered_tsc();
    volatile unsigned char b1 = *reinterpret_cast<const volatile unsigned char *>(ctx->proc);
    const uint64_t t1 = ordered_tsc();
    (void)b1;

    const uint64_t t2 = ordered_tsc();
    volatile unsigned char b2 = *ctx->local_buf;
    const uint64_t t3 = ordered_tsc();
    (void)b2;

    ctx->code_delta = (t1 >= t0) ? static_cast<double>(t1 - t0) : 0;
    ctx->local_delta = (t3 >= t2) ? static_cast<double>(t3 - t2) : 0;
}

std::vector<Finding> ept_hook_timing(Context &ctx) {
    if (!counter_access().rdtsc)
        return {unavailable("env.ept_hook_timing", "EPT hook timing", "RDTSC unavailable", Severity::Medium)};

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return {unavailable("env.ept_hook_timing", "EPT hook timing", "ntdll.dll not loaded", Severity::Medium)};

    FARPROC proc = GetProcAddress(ntdll, "NtClose");
    if (!proc)
        return {unavailable("env.ept_hook_timing", "EPT hook timing", "NtClose export missing", Severity::Medium)};

    constexpr unsigned kEptSamples = 64;
    volatile unsigned char local_storage[64]{0x90};
    std::vector<double> code_samples, local_samples;
    code_samples.reserve(kEptSamples);
    local_samples.reserve(kEptSamples);

    for (unsigned i = 0; i < kEptSamples; ++i) {
        EptTimingContext test_ctx{proc, &local_storage[i % sizeof(local_storage)], 0, 0};
        const auto r = guard::run(probe_ept_read, &test_ctx);
        if (r.faulted)
            continue;
        if (test_ctx.code_delta > 0 && test_ctx.local_delta > 0) {
            code_samples.push_back(test_ctx.code_delta);
            local_samples.push_back(test_ctx.local_delta);
        }
    }

    if (code_samples.empty() || local_samples.empty())
        return {unavailable("env.ept_hook_timing", "EPT hook timing", "No timing samples gathered", Severity::Medium)};

    const auto code_stats = statistics(code_samples);
    const auto local_stats = statistics(local_samples);
    const double ratio = code_stats.median / std::max(local_stats.median, 1.0);

    const double thresh_cycles = bounded_double(ctx, "timing.ept_cycles", 3000.0, 100.0, 100000.0);
    const double thresh_ratio = bounded_double(ctx, "timing.ept_ratio", 20.0, 2.0, 1000.0);

    const bool detected = (code_stats.median > thresh_cycles && ratio > thresh_ratio);

    Json m = code_stats.json();
    m.set("local_read_median", local_stats.median);
    m.set("code_read_median", code_stats.median);
    m.set("latency_ratio", ratio);
    m.set("threshold_cycles", thresh_cycles);
    m.set("threshold_ratio", thresh_ratio);

    Json ev = Json::object();
    ev.set("target_function", "ntdll!NtClose");
    ev.set("code_median_cycles", code_stats.median);
    ev.set("local_median_cycles", local_stats.median);
    ev.set("latency_ratio", ratio);

    return {measured(
        "env.ept_hook_timing", "EPT/altp2m hook read-latency side channel",
        "Measures read latency on monitored code pages vs local buffer to detect EPT/altp2m execute-only split views.",
        Severity::Medium, detected, ev, m, statistical_confidence(code_stats, 0.75))};
}

// 3. win.env.azure_cloud
std::vector<Finding> azure_cloud(Context &ctx) {
    std::vector<std::string> hits;
    bool imds_responsive = false;

    if (ctx.network) {
        auto resp = http_request(L"169.254.169.254", INTERNET_DEFAULT_HTTP_PORT,
                                 L"/metadata/instance?api-version=2021-02-01", L"Metadata: true\r\n", 1000);
        if (resp.ok && resp.status == 200) {
            if (resp.body.find("compute") != std::string::npos || resp.body.find("azEnvironment") != std::string::npos) {
                imds_responsive = true;
                hits.push_back("imds:169.254.169.254 answered with Azure metadata");
            }
        }
    }

    if (win::reg_key_exists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Auto")) {
        hits.push_back("reg:HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Auto");
    }
    if (win::reg_key_exists(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Azure Guest Agent")) {
        hits.push_back("reg:HKLM\\SOFTWARE\\Microsoft\\Windows Azure Guest Agent");
    }

    std::wstring bios_maker;
    if (win::reg_read_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer",
                             bios_maker)) {
        std::string s = winlogic::lower(win::narrow(bios_maker));
        if (s.find("microsoft") != std::string::npos) {
            std::wstring prod_name;
            if (win::reg_read_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName",
                                     prod_name)) {
                std::string p = winlogic::lower(win::narrow(prod_name));
                if (p.find("virtual machine") != std::string::npos) {
                    hits.push_back("bios:Microsoft Virtual Machine");
                }
            }
        }
    }

    std::wstring asset_tag;
    if (win::reg_read_string(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"ChassisAssetTag",
                             asset_tag)) {
        std::string a = winlogic::lower(win::narrow(asset_tag));
        if (a.find("7783-7084-3265-9085-8269-3286-77") != std::string::npos || a.find("azure") != std::string::npos) {
            hits.push_back("bios:Azure chassis asset tag");
        }
    }

    const bool detected = imds_responsive || !hits.empty();
    Ev ev;
    ev.set("imds_responsive", imds_responsive);
    ev.set("network_probed", ctx.network);
    Json sigs = Json::array();
    for (const auto &h : hits)
        sigs.push(h);
    ev.set("signatures", sigs);

    return {result("env.azure_cloud", "Azure cloud VM detection", detected, ev, Severity::Medium, 0.85,
                   "Block access to link-local cloud metadata IP 169.254.169.254 in the containment firewall.")};
}

// 4. win.env.gamarue_volume_serial
std::vector<Finding> gamarue_volume_serial(Context &) {
    DWORD serial = 0;
    if (!GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        return {fail("env.gamarue_volume_serial", "Gamarue volume serial blacklist", win::last_error_message(),
                     Severity::High)};
    }

    static const uint32_t kBlacklist[] = {
        0xCD233B43u, 0x70144646u, 0x58212132u, 0x4864A508u, 0xEC889158u, 0x1A2B3C4Du,
        0x8C4A7A85u, 0x946110D2u, 0x3B53C93Au, 0x18084B20u, 0x4A6B8B12u, 0x6CE35D10u,
        0x2B62020Fu, 0x004A6B8Bu, 0x00000000u, 0xFFFFFFFFu};

    bool hit = false;
    for (uint32_t b : kBlacklist) {
        if (serial == b) {
            hit = true;
            break;
        }
    }

    Ev ev;
    ev.set("volume_serial", hex(serial));
    ev.set("matched_blacklist", hit);

    return {result("env.gamarue_volume_serial", "Gamarue volume serial blacklist", hit, ev, Severity::High, 0.9,
                   "Randomize system drive volume serial in the Windows golden image.")};
}

// 5. win.env.tpm_measured_boot
std::vector<Finding> tpm_measured_boot(Context &) {
    LibraryHandle tbs(LoadLibraryW(L"tbs.dll"));
    if (!tbs) {
        Ev ev;
        ev.set("tbs_dll", "absent");
        return {result("env.tpm_measured_boot", "TPM 2.0 measured boot", true, ev, Severity::Medium, 0.8,
                       "Enable vTPM 2.0 emulation with persistent measurement logs.")};
    }

    struct TbsContextParams {
        uint32_t version;
    } params{1};

    using TbsiCreateFn = DWORD(WINAPI *)(TbsContextParams *, PVOID *);
    using TbsiGetLogFn = DWORD(WINAPI *)(PVOID, PBYTE, PDWORD);
    using TbsiCloseFn = DWORD(WINAPI *)(PVOID);

    auto fnCreate = symbol<TbsiCreateFn>(tbs.get(), "Tbsi_Context_Create");
    auto fnGetLog = symbol<TbsiGetLogFn>(tbs.get(), "Tbsi_Get_TCG_Log");
    auto fnClose = symbol<TbsiCloseFn>(tbs.get(), "Tbsip_Context_Close");

    if (!fnCreate || !fnGetLog || !fnClose) {
        Ev ev;
        ev.set("tbs_symbols", "incomplete");
        return {result("env.tpm_measured_boot", "TPM 2.0 measured boot", true, ev, Severity::Medium, 0.7,
                       "Enable vTPM 2.0 emulation with persistent measurement logs.")};
    }

    PVOID hContext = nullptr;
    DWORD status = fnCreate(&params, &hContext);
    DWORD log_size = 0;
    if (status == 0 && hContext) {
        fnGetLog(hContext, nullptr, &log_size);
        fnClose(hContext);
    }

    const bool detected = (status != 0 || log_size == 0);
    Ev ev;
    ev.set("tbs_create_status", static_cast<unsigned long long>(status));
    ev.set("tcg_log_bytes", static_cast<unsigned long long>(log_size));
    ev.set("measured_boot_active", !detected);

    return {result("env.tpm_measured_boot", "TPM 2.0 measured boot", detected, ev, Severity::Medium, 0.85,
                   "Enable vTPM 2.0 emulation with persistent measurement logs.")};
}

// 6. win.env.uefi_nvram_variables
std::vector<Finding> uefi_nvram_variables(Context &) {
    DWORD dummy = 0;
    SetLastError(0);
    GetFirmwareEnvironmentVariableW(L"", L"{00000000-0000-0000-0000-000000000000}", &dummy, sizeof(dummy));
    DWORD err = GetLastError();

    const bool legacy_bios = (err == ERROR_INVALID_FUNCTION || err == ERROR_NOT_SUPPORTED);

    std::vector<unsigned char> buf(512);
    DWORD boot_order_len =
        GetFirmwareEnvironmentVariableW(L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", buf.data(), static_cast<DWORD>(buf.size()));
    const bool boot_order_present = (boot_order_len > 0);

    DWORD qemu_dir =
        GetFirmwareEnvironmentVariableW(L"QemuDirectory", L"{77FA9ABD-0359-4D32-BD60-28F4E78F784B}", buf.data(), static_cast<DWORD>(buf.size()));
    const bool qemu_nvram_found = (qemu_dir > 0);

    const bool detected = (legacy_bios || qemu_nvram_found || !boot_order_present);

    Ev ev;
    ev.set("legacy_bios", legacy_bios);
    ev.set("boot_order_present", boot_order_present);
    ev.set("qemu_nvram_found", qemu_nvram_found);
    ev.set("error_code", static_cast<unsigned long long>(err));

    return {result("env.uefi_nvram_variables", "UEFI NVRAM environment variables", detected, ev, Severity::Medium,
                   0.85, "Override OVMF variable store with vendor-neutral NVRAM template.")};
}

// 7. win.env.thread_mismatch
std::vector<Finding> thread_mismatch(Context &) {
    if (!x86::available())
        return {unavailable("env.thread_mismatch", "Processor thread topology mismatch", "CPUID unavailable")};

    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const DWORD os_threads = si.dwNumberOfProcessors;

    const x86::Regs r1 = x86::cpuid(1);
    const uint32_t leaf1_max_logical = (r1.ebx >> 16) & 0xff;

    const x86::Regs rB = x86::cpuid(0x0B, 1);
    const uint32_t leaf0b_threads = rB.ebx & 0xffff;

    const bool detected = (os_threads == 1 && leaf1_max_logical > 1) ||
                          (leaf0b_threads > 0 && os_threads < leaf0b_threads);

    Json ev = Json::object();
    ev.set("os_logical_processors", static_cast<long long>(os_threads));
    ev.set("cpuid_leaf1_max_logical", static_cast<long long>(leaf1_max_logical));
    ev.set("cpuid_leaf0b_package_threads", static_cast<long long>(leaf0b_threads));

    Json m = numbers({
        {"os_logical_processors", static_cast<double>(os_threads)},
        {"leaf1_max_logical", static_cast<double>(leaf1_max_logical)},
        {"leaf0b_package_threads", static_cast<double>(leaf0b_threads)},
    });

    return {measured("env.thread_mismatch", "Processor thread topology mismatch",
                     "Compares OS-reported logical processor count with raw CPUID hardware topology.", Severity::Medium,
                     detected, ev, m, 0.85)};
}

// 8. win.env.big_ram_alloc
std::vector<Finding> big_ram_alloc(Context &ctx) {
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    const bool mem_ok = GlobalMemoryStatusEx(&ms) != FALSE;
    const uint64_t total_ram_mb = mem_ok ? (ms.ullTotalPhys / (1024 * 1024)) : 0;

    const size_t target_bytes = (sizeof(void *) == 8) ? (1024ULL * 1024 * 1024) : (512UL * 1024 * 1024);
    void *ptr = VirtualAlloc(nullptr, target_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    const bool alloc_ok = (ptr != nullptr);
    if (ptr) {
        *static_cast<volatile char *>(ptr) = 1;
        VirtualFree(ptr, 0, MEM_RELEASE);
    }

    const double ram_limit_mb = bounded_double(ctx, "resources.ram_limit_mb", 2048.0, 512.0, 32768.0);
    const bool detected = (!alloc_ok || (total_ram_mb > 0 && total_ram_mb < ram_limit_mb));

    Json m = numbers({
        {"total_ram_mb", static_cast<double>(total_ram_mb)},
        {"target_alloc_bytes", static_cast<double>(target_bytes)},
        {"alloc_succeeded", static_cast<double>(alloc_ok)},
        {"threshold_mb", ram_limit_mb},
    });

    Json ev = Json::object();
    ev.set("total_phys_ram_mb", static_cast<long long>(total_ram_mb));
    ev.set("requested_bytes", static_cast<long long>(target_bytes));
    ev.set("allocation_succeeded", alloc_ok);

    return {measured("env.big_ram_alloc", "Large physical memory allocation",
                     "Attempts large memory allocation (1-2 GB) to detect low-memory sandbox constraints.",
                     Severity::Medium, detected, ev, m, 0.8)};
}

// 9. win.env.office_emulation_artifacts
std::vector<Finding> office_emulation_artifacts(Context &) {
    std::vector<std::string> hits;

    if (GetEnvironmentVariableW(L"OFFICE_EMULATION", nullptr, 0) > 0)
        hits.push_back("env:OFFICE_EMULATION");
    if (GetEnvironmentVariableW(L"VBA_SANDBOX", nullptr, 0) > 0)
        hits.push_back("env:VBA_SANDBOX");

    wchar_t user[256];
    DWORD user_len = sizeof(user) / sizeof(user[0]);
    if (GetUserNameW(user, &user_len)) {
        std::string u = winlogic::lower(win::narrow(user));
        if (u == "office" || u == "sandboxuser" || u == "currentuser") {
            hits.push_back("user:" + u);
        }
    }

    if (win::reg_key_exists(HKEY_CURRENT_USER, L"Software\\Microsoft\\Office\\Common\\Dummy"))
        hits.push_back("reg:HKCU\\Software\\Microsoft\\Office\\Common\\Dummy");
    if (win::reg_key_exists(HKEY_CURRENT_USER, L"Software\\Microsoft\\VBA"))
        hits.push_back("reg:HKCU\\Software\\Microsoft\\VBA");

    static const wchar_t *kTempFiles[] = {
        L"C:\\Users\\Default\\AppData\\Local\\Temp\\Word8.0",
        L"C:\\Users\\Default\\AppData\\Local\\Temp\\Excel8.0",
    };
    for (const auto *p : kTempFiles) {
        if (win::path_exists(p))
            hits.push_back("file:" + win::narrow(p));
    }

    const bool detected = !hits.empty();
    Ev ev;
    Json sigs = Json::array();
    for (const auto &h : hits)
        sigs.push(h);
    ev.set("signatures", sigs);

    return {result("env.office_emulation_artifacts", "Microsoft Office emulation artifacts", detected, ev,
                   Severity::Medium, 0.8,
                   "Install genuine Office desktop apps on Windows analysis images.")};
}

// 10. win.env.windows_sandbox_vsgpu
std::vector<Finding> windows_sandbox_vsgpu(Context &) {
    bool device_found = false;
    HANDLE h = CreateFileW(L"\\\\.\\vsgpu", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        device_found = true;
        CloseHandle(h);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION)
            device_found = true;
    }

    const bool driver_exists = win::path_exists(L"C:\\Windows\\System32\\drivers\\vsgpu.sys");
    const bool reg_service = win::reg_key_exists(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vsgpu");

    const bool detected = (device_found || driver_exists || reg_service);
    Ev ev;
    ev.set("device_found", device_found);
    ev.set("driver_file", driver_exists);
    ev.set("service_key", reg_service);

    return {result("env.windows_sandbox_vsgpu", "Windows Sandbox vsgpu device", detected, ev, Severity::High, 0.9,
                   "Xen Windows HVM guest uses standard emulated display adapters without vsgpu.")};
}

// 11. win.env.windows_sandbox_dns_suffix
std::vector<Finding> windows_sandbox_dns_suffix(Context &) {
    std::vector<std::string> suffixes;
    bool matched = false;

    ULONG size = 16384;
    std::vector<BYTE> buffer(size);
    ULONG res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
                                     reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
    if (res == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
                                   reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
    }

    if (res == NO_ERROR) {
        auto *p = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
        for (; p; p = p->Next) {
            if (p->DnsSuffix && *p->DnsSuffix) {
                std::string s = winlogic::lower(win::narrow(p->DnsSuffix));
                suffixes.push_back(s);
                if (s == "mshome.net" || s == "sandbox.local") {
                    matched = true;
                }
            }
        }
    }

    std::wstring reg_domain;
    if (win::reg_read_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                             L"DhcpDomain", reg_domain) ||
        win::reg_read_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"Domain",
                             reg_domain)) {
        std::string s = winlogic::lower(win::narrow(reg_domain));
        if (!s.empty()) {
            suffixes.push_back(s);
            if (s == "mshome.net" || s == "sandbox.local")
                matched = true;
        }
    }

    Ev ev;
    ev.set("matched_container_suffix", matched);
    Json a = Json::array();
    for (const auto &s : suffixes)
        a.push(s);
    ev.set("adapter_dns_suffixes", a);

    return {result("env.windows_sandbox_dns_suffix", "Windows Sandbox DNS suffix", matched, ev, Severity::Medium, 0.85,
                   "CHIMERA DHCP server issues standard local domain search suffix.")};
}

// 12. win.env.windefend_emulator_artifacts
std::vector<Finding> windefend_emulator_artifacts(Context &) {
    std::vector<std::string> hits;

    wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD comp_len = sizeof(computer) / sizeof(computer[0]);
    if (GetComputerNameW(computer, &comp_len)) {
        std::string c = win::narrow(computer);
        if (c == "HAL9TH")
            hits.push_back("computer_name:HAL9TH");
    }

    wchar_t user[256];
    DWORD user_len = sizeof(user) / sizeof(user[0]);
    if (GetUserNameW(user, &user_len)) {
        std::string u = win::narrow(user);
        if (u == "JohnDoe")
            hits.push_back("user_name:JohnDoe");
    }

    DWORD serial = 0;
    if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        if (serial == 0x58212132u)
            hits.push_back("volume_serial:0x58212132");
    }

    static const wchar_t *kArtifactFiles[] = {L"C:\\myapp.exe", L"C:\\test\\test.exe"};
    for (const auto *p : kArtifactFiles) {
        if (win::path_exists(p))
            hits.push_back("file:" + win::narrow(p));
    }

    const bool detected = !hits.empty();
    Ev ev;
    Json sigs = Json::array();
    for (const auto &h : hits)
        sigs.push(h);
    ev.set("signatures", sigs);

    return {result("env.windefend_emulator_artifacts", "Windows Defender MpEngine emulator artifacts", detected, ev,
                   Severity::High, 0.95, "Windows HVM uses randomized hostname and realistic user profiles.")};
}

// 13. win.env.vmware_mutexes
std::vector<Finding> vmware_mutexes(Context &) {
    static const wchar_t *kNames[] = {
        L"__VMware_Tools__",
        L"VMwareGuestInitEvent",
        L"VMwareGuestInitEventGlobal",
        L"VMwareUserHide",
        L"VMwareDNFCacheMutex",
        L"Global\\__VMware_Tools__",
        L"Global\\VMwareGuestInitEvent",
        L"Global\\VMwareDNFCacheMutex",
        L"Global\\VMwareToolsRpcMutex"};

    std::vector<std::string> hits;
    for (const auto *name : kNames) {
        HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, name);
        if (m) {
            hits.push_back("mutex:" + win::narrow(name));
            CloseHandle(m);
        } else if (GetLastError() == ERROR_ACCESS_DENIED) {
            hits.push_back("mutex:" + win::narrow(name));
        }

        HANDLE e = OpenEventW(SYNCHRONIZE, FALSE, name);
        if (e) {
            hits.push_back("event:" + win::narrow(name));
            CloseHandle(e);
        } else if (GetLastError() == ERROR_ACCESS_DENIED) {
            hits.push_back("event:" + win::narrow(name));
        }
    }

    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());

    const bool detected = !hits.empty();
    Ev ev;
    Json sigs = Json::array();
    for (const auto &h : hits)
        sigs.push(h);
    ev.set("signatures", sigs);

    return {result("env.vmware_mutexes", "VMware Tools named mutexes", detected, ev, Severity::High, 0.95,
                   "CHIMERA runs under Xen with no VMware drivers or services.")};
}

// 14. win.env.cuckoo_agent_artifacts
std::vector<Finding> cuckoo_agent_artifacts(Context &) {
    static const wchar_t *kPaths[] = {
        L"C:\\agent.py",
        L"C:\\agent.pyw",
        L"C:\\tmp\\agent.py",
        L"C:\\cuckoo\\agent.py",
        L"C:\\cuckoo",
        L"C:\\analyzer\\analyzer.py",
        L"C:\\analyzer",
        L"C:\\drakvuf\\agent.py",
    };

    std::vector<std::string> hits;
    for (const auto *p : kPaths) {
        if (win::path_exists(p))
            hits.push_back(win::narrow(p));
    }

    std::wstring temp_agent = win::expand_env(L"%TEMP%\\agent.py");
    if (win::path_exists(temp_agent))
        hits.push_back(win::narrow(temp_agent));

    std::wstring temp_cuckoo = win::expand_env(L"%TEMP%\\cuckoo");
    if (win::path_exists(temp_cuckoo))
        hits.push_back(win::narrow(temp_cuckoo));

    const bool detected = !hits.empty();
    Ev ev;
    Json sigs = Json::array();
    for (const auto &h : hits)
        sigs.push(h);
    ev.set("signatures", sigs);

    return {result("env.cuckoo_agent_artifacts", "Cuckoo agent filesystem artifacts", detected, ev, Severity::High,
                   0.9, "CHIMERA uses DRAKVUF agentless VMI and leaves no agent binaries on guest disks.")};
}

// 15. win.env.cuckoo_agent_listener
std::vector<Finding> cuckoo_agent_listener(Context &) {
    bool port_listening = false;
    ULONG size = 0;
    DWORD res = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (res == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<BYTE> buffer(size);
        res = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (res == NO_ERROR) {
            auto *table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buffer.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                if (ntohs(static_cast<u_short>(table->table[i].dwLocalPort)) == 8000 &&
                    table->table[i].dwState == MIB_TCP_STATE_LISTEN) {
                    port_listening = true;
                    break;
                }
            }
        }
    }

    std::vector<std::string> procs;
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snap.valid()) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap.get(), &pe)) {
            do {
                std::string name = winlogic::lower(win::narrow(pe.szExeFile));
                if (name == "agent.py" || name == "agent.exe" || name == "cuckoo.exe") {
                    procs.push_back(name);
                }
            } while (Process32NextW(snap.get(), &pe));
        }
    }

    const bool detected = port_listening || !procs.empty();
    Ev ev;
    ev.set("port_8000_listening", port_listening);
    Json p = Json::array();
    for (const auto &name : procs)
        p.push(name);
    ev.set("matched_processes", p);

    return {result("env.cuckoo_agent_listener", "Cuckoo agent listener", detected, ev, Severity::High, 0.9,
                   "DRAKVUF introspection needs no guest-side listening socket.")};
}

// 16. win.env.cuckoo_cuckoomon_config
std::vector<Finding> cuckoo_cuckoomon_config(Context &) {
    static const wchar_t *kPaths[] = {
        L"C:\\cuckoomon.ini",
        L"C:\\capemon.ini",
        L"C:\\analyzer\\cuckoomon.ini",
        L"C:\\analyzer\\capemon.ini",
        L"C:\\Windows\\cuckoomon.ini",
        L"C:\\Windows\\capemon.ini",
        L"C:\\Windows\\System32\\cuckoomon.ini",
    };

    std::vector<std::string> hits;
    for (const auto *p : kPaths) {
        if (win::path_exists(p))
            hits.push_back(win::narrow(p));
    }

    std::wstring temp_cuckoomon = win::expand_env(L"%TEMP%\\cuckoomon.ini");
    if (win::path_exists(temp_cuckoomon))
        hits.push_back(win::narrow(temp_cuckoomon));

    std::wstring temp_capemon = win::expand_env(L"%TEMP%\\capemon.ini");
    if (win::path_exists(temp_capemon))
        hits.push_back(win::narrow(temp_capemon));

    const bool detected = !hits.empty();
    Ev ev;
    Json sigs = Json::array();
    for (const auto &h : hits)
        sigs.push(h);
    ev.set("signatures", sigs);

    return {result("env.cuckoo_cuckoomon_config", "Cuckoomon configuration files", detected, ev, Severity::High,
                   0.95, "DRAKVUF monitors from dom0; no monitor configs exist inside guest.")};
}

// 17. win.network.hosting_provider_check
std::vector<Finding> hosting_provider_check(Context &ctx) {
    if (!ctx.network)
        return {skipped("network.hosting_provider_check", "Hosting provider IP check",
                        "Public IP reputation check.", Severity::High, "Network checks disabled")};

    auto resp = http_request(L"ip-api.com", INTERNET_DEFAULT_HTTP_PORT,
                             L"/json/?fields=status,message,country,isp,org,as,hosting", L"", 3000);
    if (!resp.ok || resp.status != 200) {
        Ev ev;
        ev.set("http_status", static_cast<unsigned long long>(resp.status));
        ev.set("response_ok", resp.ok);
        return {result("network.hosting_provider_check", "Hosting provider IP check", false, ev, Severity::High,
                       0.5, "INetSim local traffic sink prevents public IP disclosure during offline runs.")};
    }

    std::string body_lower = winlogic::lower(resp.body);
    bool hosting_flag = (body_lower.find("\"hosting\":true") != std::string::npos ||
                         body_lower.find("\"hosting\": true") != std::string::npos);

    static const std::vector<std::string> kProviders = {
        "amazon", "google", "microsoft", "digitalocean", "hetzner", "ovh", "oracle", "alibaba",
        "linode", "vultr",  "leaseweb",  "choopa",       "contabo", "tencent", "fastly", "cloudflare"};

    std::string matched_provider = winlogic::match(body_lower, kProviders);
    const bool detected = hosting_flag || !matched_provider.empty();

    Ev ev;
    ev.set("hosting_flag", hosting_flag);
    ev.set("matched_provider", matched_provider);
    ev.set("response_snippet", resp.body.substr(0, 256));

    return {result("network.hosting_provider_check", "Hosting provider IP check", detected, ev, Severity::High,
                   0.85, "Route outbound guest traffic through residential proxy networks or clean ISP connections.")};
}

// 18. win.network.net_validate_name_emulation
std::vector<Finding> net_validate_name_emulation(Context &) {
    LibraryHandle netapi(LoadLibraryW(L"netapi32.dll"));
    if (!netapi) {
        return {skipped("network.net_validate_name_emulation", "NetValidateName anti-emulation",
                        "netapi32.dll unavailable", Severity::Medium, "Failed to load netapi32.dll")};
    }

    using NetValidateNameFn = DWORD(WINAPI *)(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD);
    auto fnNetValidateName = symbol<NetValidateNameFn>(netapi.get(), "NetValidateName");
    if (!fnNetValidateName) {
        return {skipped("network.net_validate_name_emulation", "NetValidateName anti-emulation",
                        "NetValidateName symbol unavailable", Severity::Medium, "GetProcAddress failed")};
    }

    // Pass an obviously nonexistent fictitious domain name; real Windows returns an error
    // (e.g. NERR_NetNameNotFound 2268, ERROR_NO_SUCH_DOMAIN 1355, ERROR_BAD_NETPATH 53).
    // An emulation stub returns 0 (NERR_Success).
    DWORD status = fnNetValidateName(nullptr, L"fictitious_domain_perdedor_probe_test.xyz", nullptr, nullptr, 1);

    const bool detected = (status == 0);
    Ev ev;
    ev.set("status_code", static_cast<unsigned long long>(status));
    ev.set("status_hex", hex(status));
    ev.set("bogus_success", detected);

    return {result("network.net_validate_name_emulation", "NetValidateName anti-emulation", detected, ev,
                   Severity::Medium, 0.85,
                   "Ensure NetValidateName behaves identically to real Windows workgroup/domain environments.")};
}

}  // namespace

PERDEDOR_REGISTER(hypervisor_exception_quirks, "cpu.undefined_instruction_behaviour", "fast", false,
                  "env.hypervisor_exception_quirks");
PERDEDOR_REGISTER(ept_hook_timing, "instrumentation.vmi_side_channel", "medium", false,
                  "env.ept_hook_timing");
PERDEDOR_REGISTER(azure_cloud, "network.cloud_metadata", "fast", true,
                  "env.azure_cloud");
PERDEDOR_REGISTER(gamarue_volume_serial, "hardware.disk_identity", "fast", false,
                  "env.gamarue_volume_serial");
PERDEDOR_REGISTER(tpm_measured_boot, "firmware.boot_mode", "fast", false,
                  "env.tpm_measured_boot");
PERDEDOR_REGISTER(uefi_nvram_variables, "firmware.bios_metadata", "fast", false,
                  "env.uefi_nvram_variables");
PERDEDOR_REGISTER(thread_mismatch, "cpu.topology_consistency", "fast", false,
                  "env.thread_mismatch");
PERDEDOR_REGISTER(big_ram_alloc, "resources.memory_size", "medium", false,
                  "env.big_ram_alloc");
PERDEDOR_REGISTER(office_emulation_artifacts, "container.app_sandbox", "fast", false,
                  "env.office_emulation_artifacts");
PERDEDOR_REGISTER(windows_sandbox_vsgpu, "container.app_sandbox", "fast", false,
                  "env.windows_sandbox_vsgpu");
PERDEDOR_REGISTER(windows_sandbox_dns_suffix, "container.app_sandbox", "fast", false,
                  "env.windows_sandbox_dns_suffix");
PERDEDOR_REGISTER(windefend_emulator_artifacts, "cpu.emulation_quirks", "fast", false,
                  "env.windefend_emulator_artifacts");
PERDEDOR_REGISTER(vmware_mutexes, "artifacts.named_objects", "fast", false,
                  "env.vmware_mutexes");
PERDEDOR_REGISTER(cuckoo_agent_artifacts, "artifacts.files", "fast", false,
                  "env.cuckoo_agent_artifacts");
PERDEDOR_REGISTER(cuckoo_agent_listener, "analysis_tools.processes", "fast", false,
                  "env.cuckoo_agent_listener");
PERDEDOR_REGISTER(cuckoo_cuckoomon_config, "artifacts.files", "fast", false,
                  "env.cuckoo_cuckoomon_config");
PERDEDOR_REGISTER(hosting_provider_check, "network.public_ip_reputation", "fast", true,
                  "network.hosting_provider_check");
PERDEDOR_REGISTER(net_validate_name_emulation, "network.connectivity", "fast", false,
                  "network.net_validate_name_emulation");

}  // namespace perdedor
