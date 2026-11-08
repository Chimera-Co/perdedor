#include "../src/common/lowlevel.hpp"
#include "../src/common/pe.hpp"
#include "../src/linux/lowlevel_parsers.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <limits>
#include <string>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <csignal>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/prctl.h>
#endif

using namespace perdedor;
using namespace perdedor::lowlevel;
namespace {
void ud2(void*) { asm volatile("ud2" : : : "memory"); }
void breakpoint(void*) { asm volatile("int3" : : : "memory"); }
void invalid_read(void* p) { const volatile auto value = *static_cast<volatile unsigned char*>(p); (void)value; }
void normal(void* p) { ++*static_cast<unsigned*>(p); }
void nested(void* p) {
    const auto fault = guard::run(ud2);
    assert(fault.faulted && fault.code != guard::kUnavailable);
    const auto ok = guard::run(normal, p);
    assert(!ok.faulted);
    asm volatile("ud2" : : : "memory");  // Recover through the outer frame as well.
}
#ifdef _WIN32
constexpr uint32_t kIllegal = EXCEPTION_ILLEGAL_INSTRUCTION, kReadFault = EXCEPTION_ACCESS_VIOLATION, kTrap = EXCEPTION_BREAKPOINT;
DWORD WINAPI thread_test(void* p) {
#else
constexpr uint32_t kIllegal = SIGILL, kReadFault = SIGSEGV, kTrap = SIGTRAP;
volatile sig_atomic_t chained = 0;
void previous_trap(int) { chained = 1; }
void async_trap(void*) { raise(SIGTRAP); }
void* thread_test(void* p) {
#endif
    for (unsigned i = 0; i < 100; ++i) {
        const auto a = guard::run(ud2), b = guard::run(invalid_read, p);
        assert(a.faulted && a.code == kIllegal);
        assert(b.faulted && b.code == kReadFault);
        unsigned count = 0;
        const auto c = guard::run(nested, &count);
        assert(c.faulted && c.code == kIllegal && count == 1);
    }
    return 0;
}
void test_guard() {
#ifdef _WIN32
    void* inaccessible = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    assert(inaccessible);
    std::array<HANDLE, 8> threads{};
    for (auto& thread : threads) { thread = CreateThread(nullptr, 0, thread_test, inaccessible, 0, nullptr); assert(thread); }
    assert(WaitForMultipleObjects(static_cast<DWORD>(threads.size()), threads.data(), TRUE, 10000) == WAIT_OBJECT_0);
    for (HANDLE thread : threads) CloseHandle(thread);
    VirtualFree(inaccessible, 0, MEM_RELEASE);
#else
    struct sigaction action{};
    action.sa_handler = previous_trap;
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGTRAP, &action, nullptr) == 0);
    void* inaccessible = mmap(nullptr, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(inaccessible != MAP_FAILED);
    std::array<pthread_t, 8> threads{};
    for (auto& thread : threads) assert(pthread_create(&thread, nullptr, thread_test, inaccessible) == 0);
    for (auto thread : threads) assert(pthread_join(thread, nullptr) == 0);
    munmap(inaccessible, 4096);
    // Asynchronous signals must retain the previous disposition even inside a guard.
    assert(!guard::run(async_trap).faulted && chained == 1);
    chained = 0; raise(SIGTRAP); assert(chained == 1);
    sigset_t mask{};
    assert(pthread_sigmask(SIG_SETMASK, nullptr, &mask) == 0);
    for (int signal : {SIGILL, SIGSEGV, SIGBUS, SIGTRAP}) assert(sigismember(&mask, signal) == 0);
#ifdef ARCH_SET_CPUID
    if (syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0) == 0) {
        const bool usable = x86::available();
        assert(syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1) == 0);
        assert(!usable);
    }
#endif
#endif
    const auto trap = guard::run(breakpoint);
    assert(trap.faulted && trap.code == kTrap);
    unsigned count = 0;
    assert(!guard::run(normal, &count).faulted && count == 1);
    assert(guard::run(nullptr).code == guard::kUnavailable);
}
void test_statistics() {
    assert(statistics({}).count == 0);
    const auto one = statistics({7}); assert(one.median == 7 && one.mad == 0 && one.p90 == 7);
    const auto even = statistics({4, 1, 3, 2});
    assert(even.min == 1 && even.max == 4 && even.median == 2.5 && even.p90 == 4 && even.mad == 1 && even.trimmed_mean == 2.5);
    const auto odd = statistics({9, 1, 2}); assert(odd.median == 2 && odd.mad == 1);
    const auto trimmed = statistics({1, 2, 3, 4, 5, 6, 7, 8, 9, 10000});
    assert(trimmed.trimmed_mean == 5.5 && trimmed.p90 == 9 && trimmed.mad == 2.5);
    const auto finite = statistics({1, std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN(), 3});
    assert(finite.count == 2 && finite.median == 2);
    const auto stable = statistics(std::vector<double>(1000, 100));
    assert(std::abs(statistical_confidence(stable) - 0.8) < 1e-12);
    auto noisy = stable; noisy.mad = 100;
    assert(statistical_confidence(noisy) < statistical_confidence(stable));
    assert(statistical_confidence(statistics({0})) == 0);
    Context ctx; ctx.params["v"] = "nan";
    assert(bounded_double(ctx, "v", 4, 1, 10) == 4);
    ctx.params["v"] = "-100"; assert(bounded_int(ctx, "v", 4, 1, 10) == 1);
    ctx.params["v"] = "999"; assert(bounded_int(ctx, "v", 4, 1, 10) == 10);
    assert(stable.json()["median"].number() == 100);
    // Nearest-rank percentiles and mean (harness-compatible fields).
    std::vector<double> hundred; for (int i = 1; i <= 100; ++i) hundred.push_back(i);
    const auto h = statistics(hundred);
    assert(h.p5 == 5 && h.p25 == 25 && h.p75 == 75 && h.p90 == 90 && h.p95 == 95 && h.p99 == 99 && h.mean == 50.5);
    assert(h.min <= h.p5 && h.p5 <= h.p25 && h.p25 <= h.median && h.median <= h.p75 && h.p75 <= h.p99 && h.p99 <= h.max);
    assert(nearest_rank({3}, 0.01) == 3 && nearest_rank({1, 2}, 1.0) == 2);
    auto j = h.json();
    for (const char* key : {"p5", "p25", "p75", "p95", "p99", "mean"}) assert(j[key].number() > 0);
}
void test_prologues() {
    const auto shape = [](std::initializer_list<unsigned char> code, bool x64 = true) { return prologue(code.begin(), code.size(), x64); };
    assert(prologue(nullptr, 0, true) == Prologue::Ordinary);
    assert(shape({0xe9, 0, 0, 0, 0}) == Prologue::Jump);
    assert(shape({0xe9, 0}) == Prologue::Ordinary);
    assert(shape({0xeb, 0}) == Prologue::Jump);
    assert(shape({0xff, 0x25, 0, 0, 0, 0}) == Prologue::Jump);
    assert(shape({0x68, 1, 2, 3, 4, 0xc3}) == Prologue::PushReturn);
    assert(shape({0x6a, 0, 0xc3}) == Prologue::PushReturn);
    assert(shape({0xcc}) == Prologue::Breakpoint);
    assert(shape({0xc3}) == Prologue::ReturnOnly);
    assert(shape({0xf3, 0x0f, 0x1e, 0xfa, 0xcc}) == Prologue::Breakpoint);
    assert(shape({0x8b, 0xff, 0xcc}, false) == Prologue::Breakpoint);
    assert(shape({0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0}) == Prologue::Jump);
    assert(shape({0x49, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xff, 0xe3}) == Prologue::Jump);
    const unsigned char x64[] = {0x4c, 0x8b, 0xd1, 0xb8, 0x23, 0, 0, 0, 0x0f, 0x05, 0xc3};
    assert(syscall_stub(x64, sizeof x64, true));
    for (size_t n = 0; n < 8; ++n) assert(!syscall_stub(x64, n, true));
    const unsigned char wow64[] = {0xb8, 0x23, 0, 0, 0, 0xba, 0, 0, 0, 0, 0xff, 0xd2, 0xc2, 0x14, 0};
    assert(syscall_stub(wow64, sizeof wow64, false));
    assert(!syscall_stub(wow64, sizeof wow64, true));
    assert(!syscall_stub(x64, sizeof x64, false));
    const unsigned char jump[] = {0xe9, 0, 0, 0, 0, 0x90, 0x90, 0x90};
    assert(!syscall_stub(jump, sizeof jump, true));
    const unsigned char win7_wow64[] = {0xb8, 0x52, 0, 0, 0, 0xb9, 0, 0, 0, 0, 0x8d, 0x54, 0x24, 0x04};
    assert(syscall_stub(win7_wow64, sizeof win7_wow64, false));
}
void test_branches() {
    const auto at = [](std::initializer_list<unsigned char> code, uint64_t address, bool x64 = true) {
        return decode_branch(code.begin(), code.size(), address, x64);
    };
    // E9 rel32: target = next instruction + rel (forward and backward).
    auto b = at({0xe9, 0x10, 0, 0, 0}, 0x1000); assert(b.decoded && !b.indirect && b.target == 0x1015);
    b = at({0xe9, 0xfb, 0xff, 0xff, 0xff}, 0x1000); assert(b.target == 0x1000);
    b = at({0xeb, 0xfe}, 0x2000); assert(b.decoded && b.target == 0x2000);
    // x64 JMP [RIP+disp32] and REX.W form: slot is relative to the next instruction.
    b = at({0xff, 0x25, 0x20, 0, 0, 0}, 0x3000); assert(b.decoded && b.indirect && b.slot == 0x3026);
    b = at({0x48, 0xff, 0x25, 0x20, 0, 0, 0}, 0x3000); assert(b.indirect && b.slot == 0x3027);
    // x86 JMP [abs32].
    b = at({0xff, 0x25, 0x78, 0x56, 0x34, 0x12}, 0x3000, false); assert(b.indirect && b.slot == 0x12345678);
    // x86 hotpatch prefix and CET ENDBR are skipped; address advances with them.
    b = at({0x8b, 0xff, 0xe9, 0, 0, 0, 0}, 0x4000, false); assert(b.decoded && b.target == 0x4007);
    b = at({0xf3, 0x0f, 0x1e, 0xfa, 0xe9, 0, 0, 0, 0}, 0x4000); assert(b.target == 0x4009);
    // 32-bit wrap-around stays in the 32-bit address space.
    b = at({0xe9, 0x00, 0x00, 0x00, 0x80}, 0x80000000, false); assert(b.target == 0x5);
    // PUSH imm32; RET sign-extends in 64-bit mode.
    b = at({0x68, 0x00, 0x00, 0x00, 0x80, 0xc3}, 0, true); assert(b.target == 0xffffffff80000000ull);
    b = at({0x68, 0x00, 0x00, 0x00, 0x80, 0xc3}, 0, false); assert(b.target == 0x80000000ull);
    b = at({0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 0xff, 0xe0}, 0); assert(b.target == 0x0807060504030201ull);
    b = at({0x49, 0xbb, 1, 0, 0, 0, 0, 0, 0, 0, 0x41, 0xff, 0xe3}, 0); assert(b.target == 1);
    b = at({0xb8, 0x44, 0x33, 0x22, 0x11, 0xff, 0xe0}, 0, false); assert(b.target == 0x11223344);
    assert(!at({0x4c, 0x8b, 0xd1, 0xb8}, 0).decoded && !at({0xe9, 0}, 0).decoded && !decode_branch(nullptr, 0, 0, true).decoded);
}
void test_classifiers() {
    assert(!shared_kd(0).enabled && !shared_kd(0).present);
    assert(shared_kd(1).enabled && !shared_kd(1).present);
    assert(shared_kd(3).enabled && shared_kd(3).present);
    assert(std::string(bochs_brand_quirk("AMD Athlon(tm) processor")) == "bochs_cpu_amd1");
    assert(!bochs_brand_quirk("AMD Athlon(tm) Processor"));
    assert(std::string(bochs_brand_quirk("              Intel(R) Pentium(R) 4 CPU        ")) == "bochs_cpu_intel1");
    assert(!bochs_brand_quirk("Intel(R) Pentium(R) 4 CPU 3.00GHz") && !bochs_brand_quirk(""));
    assert(std::string(remediation_for("env.cpuid_hypervisor_bit")).find("cpuidmon") != std::string::npos);
    assert(std::string(remediation_for("no.such_id")).find("catalog") != std::string::npos);
    CpuPin pin; (void)pin.pinned();  // Pinning may be refused (containers, affinity policy); it must not fail.
}
std::vector<unsigned char> pe_fixture(bool x64) {
    std::vector<unsigned char> b(0x800);
    const auto word = [&](size_t at, uint32_t value) { for (unsigned i = 0; i < 4; ++i) b[at + i] = value >> (8 * i); };
    b[0] = 'M'; b[1] = 'Z'; word(0x3c, 0x80); word(0x80, 0x4550);
    b[0x86] = 1; b[0x94] = x64 ? 0xf0 : 0xe0; b[0x98] = 0x0b; b[0x99] = x64 ? 2 : 1;
    word(0x98 + 56, 0x2000); word(0x98 + 60, 0x200);
    const size_t directory = 0x98 + (x64 ? 112 : 96), section = 0x98 + (x64 ? 240 : 224);
    word(directory - 4, 16); word(directory, 0x1000); word(directory + 4, 0x100);
    word(directory + 40, 0x1200); word(directory + 44, 12);
    const char name[] = ".text"; std::copy(name, name + 5, b.begin() + section);
    word(section + 8, 0x600); word(section + 12, 0x1000); word(section + 16, 0x600); word(section + 20, 0x200);
    word(0x200 + 16, 1); word(0x200 + 20, 1); word(0x200 + 24, 1);
    word(0x200 + 28, 0x1040); word(0x200 + 32, 0x1050); word(0x200 + 36, 0x1060);
    word(0x240, 0x1100); word(0x250, 0x1070);
    const char symbol[] = "NtFixture"; std::copy(symbol, symbol + sizeof symbol, b.begin() + 0x270);
    word(0x400, 0x1000); word(0x404, 12); b[0x408] = 0; b[0x409] = x64 ? 0xa1 : 0x31;
    return b;
}
void test_pe() {
    for (bool x64 : {false, true}) {
        auto bytes = pe_fixture(x64); PeImage image(bytes); assert(image.valid() && image.x64() == x64);
        bool complete = false; const auto exports = image.exports(&complete);
        assert(complete && exports.size() == 1 && exports[0].name == "NtFixture" && exports[0].rva == 0x1100 && !exports[0].forwarded);
        std::vector<bool> mask; assert(image.relocation_mask(0x1100, 16, mask));
        assert(std::count(mask.begin(), mask.end(), true) == (x64 ? 8 : 4));
        assert(!image.at(UINT32_MAX, 8) && !image.at(0x1fff, 2) && !image.at(0x1700, 1));
        auto mapped = bytes; mapped.resize(0x2000); std::copy(bytes.begin() + 0x200, bytes.end(), mapped.begin() + 0x1000);
        PeImage live(mapped, true); assert(live.exports(&complete).size() == 1 && complete);
        bytes[0x404] = 7; assert(!PeImage(bytes).relocation_mask(0x1100, 16, mask));
        bytes = pe_fixture(x64); bytes[0x260] = 2; assert(PeImage(bytes).exports(&complete).empty() && !complete);
        bytes = pe_fixture(x64); bytes[0x240] = 0x70; bytes[0x241] = 0x10;
        assert(PeImage(bytes).exports()[0].forwarded);
        bytes.resize(0x100); assert(!PeImage(bytes).valid());
    }
    std::vector<unsigned char> empty; assert(!PeImage(empty).valid());
}
void test_procfs() {
    long value = -1;
    assert(linux_lowlevel::status_number("Name:\tx\nTracerPid:\t12\nSeccomp:\t2\n", "TracerPid", value) && value == 12);
    assert(!linux_lowlevel::status_number("TracerPidExtra: 3\nTracerPid: 1x\n", "TracerPid", value));
    assert(!linux_lowlevel::status_number("TracerPid: 9999999999999999999999999999", "TracerPid", value));
    assert(!linux_lowlevel::status_number("TracerPid:\n", "TracerPid", value));
    assert(linux_lowlevel::mapped_path("00400000-00401000 r-xp 0000 08:01 2 /tmp/with space.so") == "/tmp/with space.so");
    assert(linux_lowlevel::mapped_path("invalid").empty());
}
}
int main() {
    test_guard(); test_statistics(); test_prologues(); test_branches(); test_classifiers(); test_pe(); test_procfs();
    std::puts("lowlevel: guard, statistics, stub, branch, classifier, PE and procfs fixtures passed");
}
