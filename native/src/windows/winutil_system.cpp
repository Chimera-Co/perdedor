#include "winutil.hpp"
#include <wbemidl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <shlwapi.h>
#include <algorithm>
#include <cstring>
#include <set>

namespace perdedor {
namespace win {
namespace {
bool missing(LONG e) { return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND; }
struct Key {
    HKEY h = nullptr;
    ~Key() {
        if (h)
            RegCloseKey(h);
    }
};
template <class T> struct Com {
    T *p = nullptr;
    ~Com() {
        if (p)
            p->Release();
    }
    T **out() { return &p; }
    T *operator->() const { return p; }
};
struct Bstr {
    BSTR p;
    explicit Bstr(const std::wstring &s) : p(SysAllocStringLen(s.data(), static_cast<UINT>(s.size()))) {}
    ~Bstr() { SysFreeString(p); }
};
std::string hr_error(const char *stage, HRESULT hr) {
    return std::string(stage) + ": " + last_error_message(static_cast<DWORD>(hr));
}
std::string variant_text(VARIANT &v) {
    if (v.vt == VT_NULL || v.vt == VT_EMPTY)
        return {};
    if (v.vt == VT_BOOL)
        return v.boolVal ? "1" : "0";
    if (v.vt & VT_ARRAY) {
        if (!v.parray || SafeArrayGetDim(v.parray) != 1)
            return {};
        LONG lo = 0, hi = -1;
        SafeArrayGetLBound(v.parray, 1, &lo);
        SafeArrayGetUBound(v.parray, 1, &hi);
        if (hi < lo || int64_t(hi) - lo > int64_t(winlogic::kMaxRows))
            return {};
        std::string text;
        for (LONG i = lo; i <= hi; ++i) {
            VARIANT item;
            VariantInit(&item);
            item.vt = v.vt & VT_TYPEMASK;
            HRESULT h;
            switch (item.vt) {
            case VT_UI1:
                h = SafeArrayGetElement(v.parray, &i, &item.bVal);
                break;
            case VT_UI2:
                h = SafeArrayGetElement(v.parray, &i, &item.uiVal);
                break;
            case VT_I2:
                h = SafeArrayGetElement(v.parray, &i, &item.iVal);
                break;
            case VT_UI4:
                h = SafeArrayGetElement(v.parray, &i, &item.ulVal);
                break;
            case VT_I4:
                h = SafeArrayGetElement(v.parray, &i, &item.lVal);
                break;
            case VT_BSTR:
                h = SafeArrayGetElement(v.parray, &i, &item.bstrVal);
                break;
            default:
                return {};
            }
            if (SUCCEEDED(h)) {
                if (!text.empty())
                    text += ',';
                text += variant_text(item);
            }
            VariantClear(&item);
        }
        return text;
    }
    VARIANT out;
    VariantInit(&out);
    std::string text;
    if (SUCCEEDED(VariantChangeType(&out, &v, 0, VT_BSTR)) && out.bstrVal)
        text = narrow(std::wstring(out.bstrVal, SysStringLen(out.bstrVal)));
    VariantClear(&out);
    return text;
}
void wmi_status(Result<Rows> &r, const char *stage, HRESULT hr) {
    r.code = hr;
    if (hr == kWbemInvalidNamespace || hr == kWbemInvalidClass || hr == kWbemNotSupported) {
        r.absent = true;
        r.error.clear();
        return;
    }
    r.error = hr_error(stage, hr);
    if (access_denied(hr))
        r.error += " (requires elevated rights)";
}
Result<Rows> wmi_sync(const std::wstring &space, const std::wstring &query,
                      const std::vector<std::wstring> &props, DWORD ms) {
    Result<Rows> r;
    const HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(init)) {
        r.error = hr_error("CoInitializeEx", init);
        return r;
    }
    struct Apartment {
        ~Apartment() { CoUninitialize(); }
    } apartment;
    HRESULT hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                                      RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        r.error = hr_error("CoInitializeSecurity", hr);
        return r;
    }
    Com<IWbemLocator> loc;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                          reinterpret_cast<void **>(loc.out()));
    if (FAILED(hr)) {
        r.error = hr_error("IWbemLocator", hr);
        return r;
    }
    Com<IWbemServices> svc;
    Bstr ns(space);
    // ConnectServer's flag is a provider-side upper bound; bounded() enforces our shorter wall deadline.
    hr = loc->ConnectServer(ns.p, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr,
                            svc.out());
    if (FAILED(hr)) {
        wmi_status(r, "ConnectServer", hr);
        return r;
    }
    hr = CoSetProxyBlanket(svc.p, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        r.error = hr_error("CoSetProxyBlanket", hr);
        return r;
    }
    Com<IEnumWbemClassObject> rows;
    Bstr wql(L"WQL"), q(query);
    hr = svc->ExecQuery(wql.p, q.p, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr,
                        rows.out());
    if (FAILED(hr)) {
        wmi_status(r, "ExecQuery", hr);
        return r;
    }
    const auto end = GetTickCount64() + ms;
    for (;;) {
        if (GetTickCount64() >= end) {
            r.error = "WMI enumeration deadline exceeded";
            break;
        }
        Com<IWbemClassObject> row;
        ULONG count = 0;
        hr = rows->Next(static_cast<LONG>(end - GetTickCount64()), 1, row.out(), &count);
        if (hr == WBEM_S_TIMEDOUT) {
            r.error = "WMI enumeration deadline exceeded";
            break;
        }
        if (FAILED(hr)) {
            // Providers report unsupported/missing classes lazily, on the first Next().
            wmi_status(r, "IEnumWbemClassObject::Next", hr);
            if (r.absent)
                r.value.clear();
            break;
        }
        if (!count)
            break;
        if (r.value.size() >= winlogic::kMaxRows) {
            r.error = "WMI row limit exceeded";
            break;
        }
        Row values;
        for (const auto &prop : props) {
            VARIANT v;
            VariantInit(&v);
            hr = row->Get(prop.c_str(), 0, &v, nullptr, nullptr);
            if (FAILED(hr) && hr != static_cast<HRESULT>(WBEM_E_NOT_FOUND))
                r.error = hr_error("IWbemClassObject::Get", hr);
            if (SUCCEEDED(hr))
                values[narrow(prop)] = variant_text(v);
            VariantClear(&v);
        }
        r.value.push_back(std::move(values));
        if (!r.ok())
            break;
    }
    return r;
}
} // namespace
HMODULE system_library(const wchar_t *name) {
    wchar_t path[MAX_PATH];
    UINT n = GetSystemDirectoryW(path, MAX_PATH);
    if (!n || n >= MAX_PATH)
        return nullptr;
    return LoadLibraryW((std::wstring(path) + L"\\" + name).c_str());
}
Result<std::vector<unsigned char>> registry_value(HKEY root, const std::wstring &path,
                                                  const std::wstring &name, DWORD &type, REGSAM view) {
    Result<std::vector<unsigned char>> r;
    Key k;
    LONG e = RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE | view, &k.h);
    if (e != ERROR_SUCCESS) {
        r.absent = missing(e);
        if (!r.absent)
            r.error = last_error_message(e);
        r.code = e;
        return r;
    }
    DWORD n = 0;
    e = RegQueryValueExW(k.h, name.c_str(), nullptr, &type, nullptr, &n);
    if (e != ERROR_SUCCESS) {
        r.absent = missing(e);
        if (!r.absent)
            r.error = last_error_message(e);
        r.code = e;
        return r;
    }
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        if (n > winlogic::kMaxBlob) {
            r.error = "registry value exceeds size limit";
            return r;
        }
        r.value.resize(n);
        DWORD got = n;
        e = RegQueryValueExW(k.h, name.c_str(), nullptr, &type, r.value.data(), &got);
        if (e == ERROR_MORE_DATA) {
            n = got;
            continue;
        }
        if (e == ERROR_SUCCESS) {
            r.value.resize(got);
            return r;
        }
        r.error = last_error_message(e);
        return r;
    }
    r.error = "registry value changed repeatedly during read";
    return r;
}
Result<std::vector<std::wstring>> registry_names(HKEY root, const std::wstring &path, bool values,
                                                 REGSAM view) {
    Result<std::vector<std::wstring>> r;
    Key k;
    LONG e = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &k.h);
    if (e != ERROR_SUCCESS) {
        r.absent = missing(e);
        if (!r.absent)
            r.error = last_error_message(e);
        r.code = e;
        return r;
    }
    const auto end = GetTickCount64() + winlogic::kScanMs;
    for (DWORD i = 0;; ++i) {
        wchar_t name[16384];
        DWORD n = 16384;
        e = values ? RegEnumValueW(k.h, i, name, &n, nullptr, nullptr, nullptr, nullptr)
                   : RegEnumKeyExW(k.h, i, name, &n, nullptr, nullptr, nullptr, nullptr);
        if (e == ERROR_NO_MORE_ITEMS)
            break;
        if (e != ERROR_SUCCESS) {
            r.error = last_error_message(e);
            r.code = e;
            break;
        }
        if (i >= winlogic::kMaxEntries || GetTickCount64() >= end) {
            r.error = "registry enumeration limit exceeded";
            break;
        }
        r.value.emplace_back(name, n);
    }
    return r;
}
Result<bool> registry_exists(HKEY root, const std::wstring &path, REGSAM view) {
    Key k;
    LONG e = RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | view, &k.h);
    return {e == ERROR_SUCCESS, (e == ERROR_SUCCESS || missing(e)) ? "" : last_error_message(e), missing(e), e};
}
Result<std::string> registry_string(HKEY root, const std::wstring &path, const std::wstring &name,
                                    REGSAM view) {
    DWORD type = 0;
    auto v = registry_value(root, path, name, type, view);
    Result<std::string> r{{}, v.error, v.absent, v.code};
    if (!r.ok() || r.absent)
        return r;
    if ((type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ) || v.value.size() % 2) {
        r.error = "unexpected registry string type/length";
        return r;
    }
    std::wstring s(v.value.size() / 2, L'\0');
    if (!s.empty())
        std::memcpy(&s[0], v.value.data(), v.value.size());
    for (auto &c : s)
        if (!c)
            c = L' ';
    r.value = winlogic::trim(narrow(s));
    return r;
}
Result<uint64_t> registry_number(HKEY root, const std::wstring &path, const std::wstring &name, REGSAM view) {
    DWORD type = 0;
    auto v = registry_value(root, path, name, type, view);
    Result<uint64_t> r{0, v.error, v.absent, v.code};
    if (!r.ok() || r.absent)
        return r;
    if (type == REG_DWORD && v.value.size() == 4)
        r.value = winlogic::u32(v.value, 0);
    else if (type == REG_QWORD && v.value.size() == 8)
        std::memcpy(&r.value, v.value.data(), 8);
    else
        r.error = "unexpected registry number type/length";
    return r;
}
bool access_denied(long code) {
    return code == kWbemAccessDenied || code == static_cast<long>(E_ACCESSDENIED) ||
           code == static_cast<long>(ERROR_ACCESS_DENIED);
}
Result<Rows> wmi(const std::wstring &space, const std::wstring &query,
                 const std::vector<std::wstring> &properties, DWORD ms) {
    static volatile LONG outstanding = 0;
    // Immutable copies of the result cross thread/apartment boundaries, never COM interfaces.
    // The wall budget adds a fixed margin for COM start-up and ConnectServer.
    constexpr DWORD kConnectMarginMs = 4000;
    return bounded<Rows>([space, query, properties, ms] { return wmi_sync(space, query, properties, ms); },
                         ms + kConnectMarginMs, outstanding);
}
std::string field(const Row &row, const std::string &key) {
    auto p = row.find(key);
    return p == row.end() ? "" : p->second;
}
Result<std::vector<unsigned char>> firmware(DWORD provider, DWORD id) {
    Result<std::vector<unsigned char>> r;
    SetLastError(ERROR_SUCCESS);
    UINT n = GetSystemFirmwareTable(provider, id, nullptr, 0);
    if (!n) {
        DWORD e = GetLastError();
        r.absent = e == ERROR_INVALID_FUNCTION || e == ERROR_NOT_SUPPORTED || e == ERROR_FILE_NOT_FOUND;
        if (!r.absent)
            r.error = last_error_message(e);
        r.code = e;
        return r;
    }
    if (n > winlogic::kMaxBlob) {
        r.error = "firmware table exceeds size limit";
        return r;
    }
    r.value.resize(n);
    UINT got = GetSystemFirmwareTable(provider, id, r.value.data(), n);
    if (!got || got > n) {
        r.error = got > n ? "firmware table grew during read" : last_error_message();
        r.value.clear();
    } else
        r.value.resize(got);
    return r;
}
Result<std::vector<DWORD>> firmware_ids(DWORD provider) {
    Result<std::vector<DWORD>> r;
    SetLastError(ERROR_SUCCESS);
    UINT n = EnumSystemFirmwareTables(provider, nullptr, 0);
    if (!n) {
        DWORD e = GetLastError();
        r.absent = e == ERROR_SUCCESS || e == ERROR_NOT_SUPPORTED || e == ERROR_INVALID_FUNCTION;
        if (!r.absent)
            r.error = last_error_message(e);
        r.code = e;
        return r;
    }
    if (n > winlogic::kMaxBlob || n % 4) {
        r.error = "invalid firmware ID list length";
        return r;
    }
    r.value.resize(n / 4);
    UINT got = EnumSystemFirmwareTables(provider, r.value.data(), n);
    if (!got || got > n || got % 4) {
        r.error = "firmware enumeration failed or changed";
        r.value.clear();
    } else
        r.value.resize(got / 4);
    return r;
}
Result<std::vector<Device>> devices() {
    Result<std::vector<Device>> r;
    HDEVINFO h = SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
                                      DIGCF_ALLCLASSES); // deliberately includes non-present devices
    if (h == INVALID_HANDLE_VALUE) {
        r.error = last_error_message();
        return r;
    }
    struct List {
        HDEVINFO h;
        ~List() { SetupDiDestroyDeviceInfoList(h); }
    } list{h};
    const auto end = GetTickCount64() + winlogic::kDeviceScanMs;
    for (DWORD i = 0;; ++i) {
        SP_DEVINFO_DATA d{};
        d.cbSize = sizeof d;
        if (!SetupDiEnumDeviceInfo(h, i, &d)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS)
                r.error = last_error_message();
            break;
        }
        if (i >= winlogic::kMaxEntries || GetTickCount64() >= end) {
            r.error = "device enumeration limit exceeded";
            break;
        }
        wchar_t id[MAX_DEVICE_ID_LEN]{};
        if (!SetupDiGetDeviceInstanceIdW(h, &d, id, MAX_DEVICE_ID_LEN, nullptr)) {
            r.error = last_error_message();
            break;
        }
        auto prop = [&](DWORD key) {
            DWORD size = 0, type = 0;
            SetupDiGetDeviceRegistryPropertyW(h, &d, key, &type, nullptr, 0, &size);
            if (!size || size > winlogic::kMaxBlob)
                return std::string();
            std::vector<wchar_t> b(size / 2 + 2);
            if (!SetupDiGetDeviceRegistryPropertyW(h, &d, key, &type, reinterpret_cast<BYTE *>(b.data()),
                                                   size, nullptr))
                return std::string();
            std::wstring s(b.data(), size / 2);
            for (auto &c : s)
                if (!c)
                    c = L' ';
            return winlogic::trim(narrow(s));
        };
        ULONG status = 0, problem = 0;
        CONFIGRET rc = CM_Get_DevNode_Status(&status, &problem, d.DevInst, 0);
        DEVINST present_node = 0;
        bool present = CM_Locate_DevNodeW(&present_node, id, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS;
        if (rc != CR_SUCCESS && rc != CR_NO_SUCH_DEVNODE) {
            r.error = "CM_Get_DevNode_Status failed: " + std::to_string(rc);
            break;
        }
        r.value.push_back(
            {narrow(id), prop(SPDRP_DEVICEDESC), prop(SPDRP_HARDWAREID), prop(SPDRP_DRIVER), present});
    }
    return r;
}
Result<std::vector<Process>> processes() {
    Result<std::vector<Process>> r;
    Handle h(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!h) {
        r.error = last_error_message();
        return r;
    }
    PROCESSENTRY32W p{};
    p.dwSize = sizeof p;
    if (!Process32FirstW(h.get(), &p)) {
        r.error = last_error_message();
        return r;
    }
    do {
        if (r.value.size() >= winlogic::kMaxEntries) {
            r.error = "process enumeration limit exceeded";
            return r;
        }
        r.value.push_back({p.th32ProcessID, p.th32ParentProcessID, narrow(p.szExeFile)});
    } while (Process32NextW(h.get(), &p));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        r.error = last_error_message();
    return r;
}
Result<std::vector<std::string>> loaded_modules() {
    Result<std::vector<std::string>> r;
    Handle h(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId()));
    if (!h) {
        r.error = last_error_message();
        return r;
    }
    MODULEENTRY32W m{};
    m.dwSize = sizeof m;
    if (!Module32FirstW(h.get(), &m)) {
        r.error = last_error_message();
        return r;
    }
    do {
        r.value.push_back(narrow(m.szModule));
    } while (r.value.size() < winlogic::kMaxEntries && Module32NextW(h.get(), &m));
    if (GetLastError() != ERROR_NO_MORE_FILES)
        r.error = last_error_message();
    return r;
}
Result<std::vector<std::string>> loaded_drivers() {
    Result<std::vector<std::string>> r;
    std::vector<LPVOID> addresses(winlogic::kMaxEntries);
    DWORD n = 0;
    if (!EnumDeviceDrivers(addresses.data(), static_cast<DWORD>(addresses.size() * sizeof(LPVOID)), &n)) {
        r.error = last_error_message();
        return r;
    }
    if (n > addresses.size() * sizeof(LPVOID)) {
        r.error = "driver enumeration exceeds size limit";
        return r;
    }
    for (size_t i = 0; i < n / sizeof(LPVOID); ++i) {
        // Windows 11 24H2 can succeed but return NULL bases without SeDebugPrivilege.
        if (!addresses[i]) {
            r.error = "driver bases withheld (privilege required by this Windows build)";
            return r;
        }
        wchar_t name[MAX_PATH];
        if (!GetDeviceDriverBaseNameW(addresses[i], name, MAX_PATH)) {
            r.error = last_error_message();
            return r;
        }
        r.value.push_back(narrow(name));
    }
    return r;
}
namespace {
BOOL CALLBACK window_cb(HWND h, LPARAM p) {
    auto &r = *reinterpret_cast<Result<std::vector<Window>> *>(p);
    if (r.value.size() >= winlogic::kMaxEntries) {
        r.error = "window enumeration limit exceeded";
        return FALSE;
    }
    wchar_t klass[256]{}, title[512]{};
    GetClassNameW(h, klass, 256);
    // GetWindowText does not send messages to another process; never use WM_GETTEXT on foreign windows.
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != GetCurrentProcessId())
        GetWindowTextW(h, title, 512);
    r.value.push_back({h, narrow(klass), narrow(title), IsWindowVisible(h) != FALSE});
    return TRUE;
}
} // namespace
Result<std::vector<Window>> windows() {
    Result<std::vector<Window>> r;
    SetLastError(ERROR_SUCCESS);
    if (!EnumWindows(window_cb, reinterpret_cast<LPARAM>(&r)) && r.error.empty())
        r.error = last_error_message();
    return r;
}
Result<std::vector<Service>> services() {
    Result<std::vector<Service>> r;
    SC_HANDLE h = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!h) {
        r.error = last_error_message();
        return r;
    }
    struct Sc {
        SC_HANDLE h;
        ~Sc() { CloseServiceHandle(h); }
    } sc{h};
    std::vector<BYTE> b(256 * 1024);
    DWORD resume = 0, needed = 0, count = 0;
    for (unsigned page = 0; page < 16; ++page) {
        BOOL ok =
            EnumServicesStatusExW(h, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
                                  b.data(), static_cast<DWORD>(b.size()), &needed, &count, &resume, nullptr);
        DWORD e = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && e != ERROR_MORE_DATA) {
            r.error = last_error_message(e);
            return r;
        }
        auto *s = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW *>(b.data());
        for (DWORD i = 0; i < count; ++i)
            r.value.push_back({narrow(s[i].lpServiceName), s[i].ServiceStatusProcess.dwCurrentState});
        if (ok)
            return r;
        if (r.value.size() > winlogic::kMaxEntries)
            break;
    }
    r.error = "service enumeration limit exceeded";
    return r;
}
Result<std::vector<std::string>> objects(const std::wstring &path) {
    using Open = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    using Query = NTSTATUS(NTAPI *)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto open = proc<Open>(ntdll, "NtOpenDirectoryObject");
    auto query = proc<Query>(ntdll, "NtQueryDirectoryObject");
    Result<std::vector<std::string>> r;
    if (!open || !query) {
        r.absent = true;
        return r;
    }
    UNICODE_STRING name{};
    name.Buffer = const_cast<PWSTR>(path.c_str());
    name.Length = static_cast<USHORT>(path.size() * 2);
    name.MaximumLength = name.Length;
    OBJECT_ATTRIBUTES a{};
    a.Length = sizeof a;
    a.ObjectName = &name;
    a.Attributes = OBJ_CASE_INSENSITIVE;
    HANDLE raw = nullptr;
    NTSTATUS s = open(&raw, 1, &a);
    if (static_cast<ULONG>(s) == 0xc0000034UL || static_cast<ULONG>(s) == 0xc000003aUL) {
        r.absent = true; // STATUS_OBJECT_NAME/PATH_NOT_FOUND: the directory does not exist
        return r;
    }
    if (s < 0) {
        r.error = "NtOpenDirectoryObject status " + std::to_string(s);
        return r;
    }
    Handle h(raw);
    std::vector<BYTE> b(65536);
    ULONG ctx = 0, size = 0;
    struct Entry {
        UNICODE_STRING name, type;
    };
    for (size_t i = 0; i < winlogic::kMaxEntries; ++i) {
        s = query(h.get(), b.data(), static_cast<ULONG>(b.size()), TRUE, FALSE, &ctx, &size);
        if (static_cast<ULONG>(s) == 0x8000001aUL)
            return r; // STATUS_NO_MORE_ENTRIES
        if (s < 0 || size > b.size()) {
            r.error = "NtQueryDirectoryObject status " + std::to_string(s);
            return r;
        }
        auto *e = reinterpret_cast<Entry *>(b.data());
        auto begin = reinterpret_cast<uintptr_t>(b.data()), ptr = reinterpret_cast<uintptr_t>(e->name.Buffer);
        if (e->name.Length % 2 || ptr < begin || ptr > begin + b.size() ||
            e->name.Length > begin + b.size() - ptr) {
            r.error = "invalid object directory result";
            return r;
        }
        r.value.push_back(narrow(std::wstring(e->name.Buffer, e->name.Length / 2)));
    }
    r.error = "object enumeration limit exceeded";
    return r;
}
Result<uint64_t> handle_count() {
    using Query = NTSTATUS(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
    auto fn = proc<Query>(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    Result<uint64_t> r;
    if (!fn) {
        r.absent = true;
        return r;
    }
    std::vector<BYTE> b(65536);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        ULONG n = 0;
        NTSTATUS s = fn(64, b.data(), static_cast<ULONG>(b.size()), &n); // SystemExtendedHandleInformation
        if (static_cast<ULONG>(s) == 0xc0000004UL) {
            size_t next = std::max<size_t>(n, b.size() * 2);
            if (next > winlogic::kMaxBlob)
                break;
            b.resize(next);
            continue;
        }
        if (s < 0) {
            r.error = "NtQuerySystemInformation status " + std::to_string(s);
            return r;
        }
        if (b.size() < 2 * sizeof(ULONG_PTR))
            break;
        ULONG_PTR count = 0;
        std::memcpy(&count, b.data(), sizeof count);
        r.value = count;
        return r;
    }
    r.error = "system handle table exceeds bounded buffer";
    return r;
}
Result<bool> named_object(const std::wstring &path, const std::string &kind) {
    static volatile LONG stalled = 0;
    return bounded<bool>(
        [path, kind] {
            HANDLE raw = nullptr;
            if (kind == "mutex")
                raw = OpenMutexW(SYNCHRONIZE, FALSE, path.c_str());
            else if (kind == "event")
                raw = OpenEventW(SYNCHRONIZE, FALSE, path.c_str());
            else
                raw = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                                  nullptr); // metadata only; never read/write device or pipe
            Handle h(raw);
            if (h)
                return Result<bool>{true};
            DWORD e = GetLastError();
            // The name resolved to an object we may not open: it exists.
            if (e == ERROR_PIPE_BUSY || e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED)
                return Result<bool>{true};
            if (missing(e) || e == ERROR_INVALID_NAME || e == ERROR_BAD_PATHNAME ||
                e == ERROR_INVALID_PARAMETER)
                return Result<bool>{false};
            return Result<bool>{false, last_error_message(e)};
        },
        winlogic::kIoMs, stalled);
}
std::wstring native_path(const std::wstring &path) {
    std::wstring s = expand_env(path);
#ifndef _WIN64
    BOOL wow = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &wow) && wow) {
        const std::wstring sys = expand_env(L"%WINDIR%\\System32\\");
        if (winlogic::lower(narrow(s)).find(winlogic::lower(narrow(sys))) == 0)
            s = expand_env(L"%WINDIR%\\Sysnative\\") + s.substr(sys.size());
    }
#endif
    return s;
}
Result<uint64_t> file_size(const std::wstring &path) {
    WIN32_FILE_ATTRIBUTE_DATA d{};
    auto p = native_path(path);
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &d)) {
        DWORD e = GetLastError();
        return {0, missing(e) ? "" : last_error_message(e), missing(e)};
    }
    if (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return {0};
    return {(uint64_t(d.nFileSizeHigh) << 32) | d.nFileSizeLow};
}
int64_t now_days() {
    FILETIME f;
    GetSystemTimeAsFileTime(&f);
    return static_cast<int64_t>((uint64_t(f.dwHighDateTime) << 32) | f.dwLowDateTime) / 864000000000LL -
           134774;
}
Result<Files> file_count(const std::wstring &path, bool recurse, const std::wstring &pattern) {
    Result<Files> r;
    std::vector<std::wstring> pending{native_path(path)};
    const auto end = GetTickCount64() + (recurse ? winlogic::kTreeScanMs : winlogic::kScanMs);
    const int64_t today = now_days();
    size_t visited = 0;
    bool root = true;
    while (!pending.empty()) {
        auto dir = pending.back();
        pending.pop_back();
        WIN32_FIND_DATAW d{};
        // Subdirectories are always walked with "*"; the pattern filters counted files.
        HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &d);
        const bool top = root;
        root = false;
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            if (top && missing(e))
                r.absent = true;
            else if (top && e != ERROR_FILE_NOT_FOUND) {
                r.error = last_error_message(e);
                r.code = static_cast<long>(e);
            }
            else if (e == ERROR_ACCESS_DENIED)
                ++r.value.denied; // protected subfolders are counted, not fatal
            continue;
        }
        struct Find {
            HANDLE h;
            ~Find() { FindClose(h); }
        } close{h};
        do {
            if (++visited > winlogic::kMaxEntries || GetTickCount64() >= end) {
                r.value.truncated = true;
                return r;
            }
            if (d.cFileName[0] == L'.' && (!d.cFileName[1] || (d.cFileName[1] == L'.' && !d.cFileName[2])))
                continue;
            if (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue; // never follow junctions/symlinks
            if (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (recurse)
                    pending.push_back(dir + L"\\" + d.cFileName);
                continue;
            }
            if (pattern != L"*" && !PathMatchSpecW(d.cFileName, pattern.c_str()))
                continue;
            ++r.value.count;
            r.value.bytes += (uint64_t(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
            int64_t days = static_cast<int64_t>((uint64_t(d.ftLastWriteTime.dwHighDateTime) << 32) |
                                                d.ftLastWriteTime.dwLowDateTime) /
                               864000000000LL -
                           134774;
            if (today - days >= winlogic::kAgedDays)
                ++r.value.aged;
        } while (FindNextFileW(h, &d));
        DWORD e = GetLastError();
        if (e != ERROR_NO_MORE_FILES) {
            r.error = last_error_message(e);
            return r;
        }
    }
    return r;
}
Result<std::vector<Program>> programs() {
    Result<std::vector<Program>> r;
    std::set<std::string> seen;
    const std::wstring base = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    for (HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER})
        for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
            auto keys = registry_names(root, base, false, view);
            if (!keys.ok()) {
                r.error = keys.error;
                return r;
            }
            for (const auto &k : keys.value) {
                auto n = registry_string(root, base + L"\\" + k, L"DisplayName", view);
                auto d = registry_string(root, base + L"\\" + k, L"InstallDate", view);
                if (!n.ok() || !d.ok()) {
                    r.error = !n.ok() ? n.error : d.error;
                    return r;
                }
                if (!n.absent && !n.value.empty() && seen.insert(winlogic::lower(n.value)).second)
                    r.value.push_back({n.value, d.value});
            }
        }
    return r;
}
} // namespace win
} // namespace perdedor
