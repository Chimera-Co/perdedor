#include "winutil.hpp"

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

bool reg_read_string(HKEY root, const std::wstring& path, const std::wstring& value, std::wstring& out) {
    DWORD type = 0, size = 0;
    if (RegGetValueW(root, path.c_str(), value.c_str(), RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_MULTI_SZ | RRF_SUBKEY_WOW6464KEY,
                     &type, nullptr, &size) != ERROR_SUCCESS)
        return false;
    std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
    if (RegGetValueW(root, path.c_str(), value.c_str(), RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_MULTI_SZ | RRF_SUBKEY_WOW6464KEY,
                     &type, &buf[0], &size) != ERROR_SUCCESS)
        return false;
    if (type == REG_MULTI_SZ) {
        for (auto& ch : buf)
            if (ch == L'\0') ch = L'\n';
    }
    buf.resize(wcsnlen(buf.c_str(), buf.size()));
    while (!buf.empty() && buf.back() == L'\n') buf.pop_back();
    out = buf;
    return true;
}

bool reg_read_dword(HKEY root, const std::wstring& path, const std::wstring& value, DWORD& out) {
    DWORD size = sizeof out;
    return RegGetValueW(root, path.c_str(), value.c_str(), RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &out, &size) ==
           ERROR_SUCCESS;
}

bool reg_read_binary(HKEY root, const std::wstring& path, const std::wstring& value, std::vector<unsigned char>& out) {
    DWORD size = 0;
    if (RegGetValueW(root, path.c_str(), value.c_str(), RRF_RT_REG_BINARY | RRF_SUBKEY_WOW6464KEY, nullptr, nullptr, &size) != ERROR_SUCCESS)
        return false;
    out.resize(size);
    return RegGetValueW(root, path.c_str(), value.c_str(), RRF_RT_REG_BINARY | RRF_SUBKEY_WOW6464KEY, nullptr, out.data(), &size) ==
           ERROR_SUCCESS;
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
