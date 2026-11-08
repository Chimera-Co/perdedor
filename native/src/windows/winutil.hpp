// Small Windows helpers shared by the Windows check modules.
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

namespace perdedor {
namespace win {

std::string narrow(const std::wstring& w);
std::wstring widen(const std::string& s);
std::string last_error_message(DWORD code = GetLastError());

// Registry helpers (return false / empty when absent). `view` adds KEY_WOW64_64KEY
// so a 32-bit build reads the native view.
bool reg_key_exists(HKEY root, const std::wstring& path);
bool reg_read_string(HKEY root, const std::wstring& path, const std::wstring& value, std::wstring& out);
bool reg_read_dword(HKEY root, const std::wstring& path, const std::wstring& value, DWORD& out);
std::vector<std::wstring> reg_subkeys(HKEY root, const std::wstring& path);
bool reg_read_binary(HKEY root, const std::wstring& path, const std::wstring& value, std::vector<unsigned char>& out);

bool path_exists(const std::wstring& path);
std::wstring expand_env(const std::wstring& s);

}  // namespace win
}  // namespace perdedor
