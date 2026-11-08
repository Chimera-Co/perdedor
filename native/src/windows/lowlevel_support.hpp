#pragma once
#include "../common/lowlevel.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>

namespace perdedor::win_lowlevel {
template<class Function> Function symbol(HMODULE module, const char* name) {
    Function fn = nullptr; const FARPROC address = module ? GetProcAddress(module, name) : nullptr;
    static_assert(sizeof(fn) == sizeof(address)); std::memcpy(&fn, &address, sizeof(fn)); return fn;
}
template<class Function> Function nt(const char* name) { return symbol<Function>(GetModuleHandleW(L"ntdll.dll"), name); }
using QueryProcess = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using QuerySystem = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
inline bool read_memory(const void* source, void* destination, size_t size) {
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), source, destination, size, &read) && read == size;
}
template<class T> bool read_value(uintptr_t address, T& value) { return read_memory(reinterpret_cast<const void*>(address), &value, sizeof(value)); }
class Handle {
  public:
    explicit Handle(HANDLE h = nullptr) : value_(h) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    bool valid() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
  private:
    HANDLE value_;
};
inline uintptr_t peb() {
    uintptr_t value = 0;
#if defined(__x86_64__)
    asm volatile("movq %%gs:0x60,%0" : "=r"(value));
#else
    asm volatile("movl %%fs:0x30,%0" : "=r"(value));
#endif
    return value;
}
inline Finding unavailable(const char* id, const char* name, const char* why, Severity severity = Severity::Medium) {
    return skipped(id, name, "Native Windows low-level observation.", severity, why);
}
}  // namespace perdedor::win_lowlevel
