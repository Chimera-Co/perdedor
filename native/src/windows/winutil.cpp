#include "winutil.hpp"

#include <cstring>

namespace perdedor {
namespace win {

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &out[0], n, nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &out[0], n);
    return out;
}

std::string last_error_message(DWORD code) {
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring msg = buf ? buf : L"";
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == L'\n' || msg.back() == L'\r')) msg.pop_back();
    return "error " + std::to_string(code) + (msg.empty() ? "" : ": " + narrow(msg));
}

static const REGSAM kView = KEY_WOW64_64KEY;

bool reg_key_exists(HKEY root, const std::wstring& path) {
    HKEY k;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | kView, &k) != ERROR_SUCCESS) return false;
    RegCloseKey(k);
    return true;
}

// Reads one value through the 64-bit registry view. RegOpenKeyEx + RegQueryValueEx work on Windows 7 and
// later from both the x64 and the x86 build (KEY_WOW64_64KEY is ignored on 32-bit Windows).
static bool reg_query(HKEY root, const std::wstring& path, const std::wstring& value, DWORD& type,
                      std::vector<unsigned char>& data) {
    HKEY k;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_QUERY_VALUE | kView, &k) != ERROR_SUCCESS) return false;
    DWORD size = 0;
    LONG rc = RegQueryValueExW(k, value.c_str(), nullptr, &type, nullptr, &size);
    for (int attempt = 0; rc == ERROR_SUCCESS && attempt < 4; ++attempt) {
        data.assign(size + sizeof(wchar_t) * 2, 0);  // room for a terminator the value may lack
        DWORD got = size;
        rc = RegQueryValueExW(k, value.c_str(), nullptr, &type, data.data(), &got);
        if (rc == ERROR_MORE_DATA) {
            size = got;
            rc = ERROR_SUCCESS;
            continue;
        }
        if (rc == ERROR_SUCCESS) data.resize(got);
        break;
    }
    RegCloseKey(k);
    return rc == ERROR_SUCCESS;
}

bool reg_read_string(HKEY root, const std::wstring& path, const std::wstring& value, std::wstring& out) {
    DWORD type = 0;
    std::vector<unsigned char> data;
    if (!reg_query(root, path, value, type, data)) return false;
    if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ) return false;
    std::wstring buf(reinterpret_cast<const wchar_t*>(data.data()), data.size() / sizeof(wchar_t));
    if (type == REG_MULTI_SZ) {
        while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        for (auto& ch : buf)
            if (ch == L'\0') ch = L'\n';
    } else {
        buf.resize(wcsnlen(buf.c_str(), buf.size()));
    }
    while (!buf.empty() && buf.back() == L'\n') buf.pop_back();
    out = buf;
    return true;
}

bool reg_read_dword(HKEY root, const std::wstring& path, const std::wstring& value, DWORD& out) {
    DWORD type = 0;
    std::vector<unsigned char> data;
    if (!reg_query(root, path, value, type, data) || type != REG_DWORD || data.size() < sizeof(DWORD)) return false;
    std::memcpy(&out, data.data(), sizeof(DWORD));
    return true;
}

bool reg_read_binary(HKEY root, const std::wstring& path, const std::wstring& value, std::vector<unsigned char>& out) {
    DWORD type = 0;
    if (!reg_query(root, path, value, type, out)) return false;
    return type == REG_BINARY;
}

std::vector<std::wstring> reg_subkeys(HKEY root, const std::wstring& path) {
    std::vector<std::wstring> out;
    HKEY k;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | kView, &k) != ERROR_SUCCESS) return out;
    wchar_t name[512];
    for (DWORD i = 0;; ++i) {
        DWORD n = 512;
        LONG rc = RegEnumKeyExW(k, i, name, &n, nullptr, nullptr, nullptr, nullptr);
        if (rc != ERROR_SUCCESS) break;
        out.emplace_back(name, n);
    }
    RegCloseKey(k);
    return out;
}

bool path_exists(const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; }

std::wstring expand_env(const std::wstring& s) {
    wchar_t buf[4096];
    DWORD n = ExpandEnvironmentStringsW(s.c_str(), buf, 4096);
    return (n && n <= 4096) ? std::wstring(buf) : s;
}

}  // namespace win
}  // namespace perdedor
