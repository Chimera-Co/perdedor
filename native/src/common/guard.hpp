#pragma once
#include <cstdint>

namespace perdedor::guard {
struct Result {
    bool faulted = false;
    uint32_t code = 0;  // POSIX signal number or Windows exception code.
};
constexpr uint32_t kUnavailable = 0xffffffffu;
using Probe = void (*)(void*);

// Only leaf probes: no C++ exceptions, locks, ownership, or nontrivial local
// destructors across a fault. Put results in caller-owned POD storage. Recovery
// bypasses the callback's stack frames. Nested guards and concurrent threads
// are supported. Unrelated threads/signals retain the previous disposition.
Result run(Probe probe, void* argument = nullptr) noexcept;
}  // namespace perdedor::guard
