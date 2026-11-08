// Small Windows helpers shared by the Windows check modules.
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include "system_logic.hpp"

namespace perdedor {
namespace win {

std::string narrow(const std::wstring &w);
std::wstring widen(const std::string &s);
std::string last_error_message(DWORD code = GetLastError());

// Registry helpers (return false / empty when absent). `view` adds KEY_WOW64_64KEY
// so a 32-bit build reads the native view.
bool reg_key_exists(HKEY root, const std::wstring &path);
bool reg_read_string(HKEY root, const std::wstring &path, const std::wstring &value, std::wstring &out);
bool reg_read_dword(HKEY root, const std::wstring &path, const std::wstring &value, DWORD &out);
std::vector<std::wstring> reg_subkeys(HKEY root, const std::wstring &path);
bool reg_read_binary(HKEY root, const std::wstring &path, const std::wstring &value,
                     std::vector<unsigned char> &out);

bool path_exists(const std::wstring &path);
std::wstring expand_env(const std::wstring &s);

template <class T> struct Result {
    T value{};
    std::string error;
    bool absent = false;
    long code = 0; // optional provider status (HRESULT / Win32 error) behind error or absent
    bool ok() const { return error.empty(); }
};
class Handle {
    HANDLE h_;

  public:
    explicit Handle(HANDLE h = nullptr) : h_(h) {}
    ~Handle() {
        if (h_ && h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
    }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    HANDLE get() const { return h_; }
    explicit operator bool() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
};
// A timeout never terminates a thread inside COM/driver code. The worker owns all
// captured state until it returns. `outstanding` counts this collector's abandoned
// workers that are still running; once kMaxAbandonedWorkers are stuck, new calls fail
// fast instead of piling up threads. A stuck worker that later finishes frees its slot,
// so one slow query (for example a cold WMI service start) does not disable a collector
// for the rest of the run. The process exit reclaims workers that never return.
constexpr LONG kMaxAbandonedWorkers = 2;
template <class T> Result<T> bounded(std::function<Result<T>()> fn, DWORD ms, volatile LONG &outstanding) {
    if (InterlockedCompareExchange(&outstanding, 0, 0) >= kMaxAbandonedWorkers)
        return {{}, "collector disabled: earlier calls are still blocked"};
    struct Job {
        Handle done{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        std::function<Result<T>()> fn;
        Result<T> result;
        volatile LONG state = 0; // 0 running, 1 finished, 2 abandoned by the caller
        volatile LONG *outstanding = nullptr;
        static DWORD WINAPI run(LPVOID p) {
            std::unique_ptr<std::shared_ptr<Job>> owned(static_cast<std::shared_ptr<Job> *>(p));
            auto j = *owned;
            try {
                j->result = j->fn();
            } catch (const std::exception &e) {
                j->result.error = e.what();
            } catch (...) {
                j->result.error = "collector exception";
            }
            if (InterlockedCompareExchange(&j->state, 1, 0) == 2)
                InterlockedDecrement(j->outstanding);
            SetEvent(j->done.get());
            return 0;
        }
    };
    auto job = std::make_shared<Job>();
    if (!job->done)
        return {{}, last_error_message()};
    job->fn = std::move(fn);
    job->outstanding = &outstanding;
    auto *owner = new std::shared_ptr<Job>(job);
    Handle thread(CreateThread(nullptr, 0, Job::run, owner, 0, nullptr));
    if (!thread) {
        delete owner;
        return {{}, last_error_message()};
    }
    if (WaitForSingleObject(job->done.get(), ms) != WAIT_OBJECT_0 &&
        InterlockedCompareExchange(&job->state, 2, 0) == 0) {
        InterlockedIncrement(&outstanding);
        return {{}, "collector timed out after " + std::to_string(ms) + " ms"};
    }
    WaitForSingleObject(job->done.get(), INFINITE); // finished; only the event signal may be pending
    return std::move(job->result);
}
template <class T> T proc(HMODULE m, const char *name) {
    return m ? reinterpret_cast<T>(reinterpret_cast<void *>(GetProcAddress(m, name))) : nullptr;
}
HMODULE system_library(const wchar_t *name);
Result<std::vector<unsigned char>> registry_value(HKEY root, const std::wstring &path,
                                                  const std::wstring &name, DWORD &type,
                                                  REGSAM view = KEY_WOW64_64KEY);
Result<std::vector<std::wstring>> registry_names(HKEY root, const std::wstring &path, bool values = false,
                                                 REGSAM view = KEY_WOW64_64KEY);
Result<bool> registry_exists(HKEY root, const std::wstring &path, REGSAM view = KEY_WOW64_64KEY);
Result<std::string> registry_string(HKEY root, const std::wstring &path, const std::wstring &name,
                                    REGSAM view = KEY_WOW64_64KEY);
Result<uint64_t> registry_number(HKEY root, const std::wstring &path, const std::wstring &name,
                                 REGSAM view = KEY_WOW64_64KEY);
using Row = std::map<std::string, std::string>;
using Rows = std::vector<Row>;
// WMI query on a worker thread. `ms` bounds connection + enumeration. Status codes:
// access denied -> error with code; missing namespace/class -> absent with code;
// provider "not supported" -> absent with code WBEM_E_NOT_SUPPORTED.
Result<Rows> wmi(const std::wstring &space, const std::wstring &query,
                 const std::vector<std::wstring> &properties, DWORD ms = winlogic::kWmiMs);
constexpr long kWbemAccessDenied = static_cast<long>(0x80041003L), kWbemNotSupported = static_cast<long>(0x8004100CL),
               kWbemInvalidClass = static_cast<long>(0x80041010L), kWbemInvalidNamespace = static_cast<long>(0x8004100EL);
bool access_denied(long code);
std::string field(const Row &row, const std::string &key);
Result<std::vector<unsigned char>> firmware(DWORD provider, DWORD id);
Result<std::vector<DWORD>> firmware_ids(DWORD provider);
struct Device {
    std::string id, name, hardware, driver;
    bool present = false;
};
Result<std::vector<Device>> devices();
struct Process {
    DWORD pid = 0, parent = 0;
    std::string name;
};
Result<std::vector<Process>> processes();
Result<std::vector<std::string>> loaded_modules();
Result<std::vector<std::string>> loaded_drivers();
struct Window {
    HWND handle = nullptr;
    std::string klass, title;
    bool visible = false;
};
Result<std::vector<Window>> windows();
struct Service {
    std::string name;
    DWORD state = 0; // SERVICE_RUNNING etc.
};
Result<std::vector<Service>> services();
Result<std::vector<std::string>> objects(const std::wstring &path);
Result<uint64_t> handle_count();
Result<bool> named_object(const std::wstring &path, const std::string &kind);
struct Files {
    uint64_t count = 0, aged = 0, bytes = 0, denied = 0;
    bool truncated = false; // entry/time budget reached; counts are lower bounds
};
Result<Files> file_count(const std::wstring &path, bool recurse = false, const std::wstring &pattern = L"*");
Result<uint64_t> file_size(const std::wstring &path);
std::wstring native_path(const std::wstring &path);
struct Program {
    std::string name, date;
};
Result<std::vector<Program>> programs();
int64_t now_days();

} // namespace win
} // namespace perdedor
