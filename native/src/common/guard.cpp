#include "guard.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// A VEH resumes at this assembly recovery point, restoring every ABI-preserved
// register from the original stack. No SEH unwind, __try, or executable buffer.
// ABI: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention
extern "C" int perdedor_guard_call(perdedor::guard::Probe, void*, uintptr_t*);
#if defined(__x86_64__)
asm(
    ".text\n.globl perdedor_guard_call\nperdedor_guard_call:\n"
    "push %rbp\n push %rbx\n push %rsi\n push %rdi\n"
    "push %r12\n push %r13\n push %r14\n push %r15\n sub $200,%rsp\n"
    "movdqu %xmm6,32(%rsp)\n movdqu %xmm7,48(%rsp)\n"
    "movdqu %xmm8,64(%rsp)\n movdqu %xmm9,80(%rsp)\n"
    "movdqu %xmm10,96(%rsp)\n movdqu %xmm11,112(%rsp)\n"
    "movdqu %xmm12,128(%rsp)\n movdqu %xmm13,144(%rsp)\n"
    "movdqu %xmm14,160(%rsp)\n movdqu %xmm15,176(%rsp)\n"
    "mov %rsp,0(%r8)\n lea .Lperdedor_recover(%rip),%rax\n mov %rax,8(%r8)\n"
    "mov %rcx,%rax\n mov %rdx,%rcx\n call *%rax\n xor %eax,%eax\n"
    "jmp .Lperdedor_restore\n.Lperdedor_recover:\n mov $1,%eax\n.Lperdedor_restore:\n"
    "movdqu 32(%rsp),%xmm6\n movdqu 48(%rsp),%xmm7\n"
    "movdqu 64(%rsp),%xmm8\n movdqu 80(%rsp),%xmm9\n"
    "movdqu 96(%rsp),%xmm10\n movdqu 112(%rsp),%xmm11\n"
    "movdqu 128(%rsp),%xmm12\n movdqu 144(%rsp),%xmm13\n"
    "movdqu 160(%rsp),%xmm14\n movdqu 176(%rsp),%xmm15\n"
    "add $200,%rsp\n pop %r15\n pop %r14\n pop %r13\n pop %r12\n"
    "pop %rdi\n pop %rsi\n pop %rbx\n pop %rbp\n ret\n");
#elif defined(__i386__)
asm(
    ".text\n.globl _perdedor_guard_call\n_perdedor_guard_call:\n"
    "push %ebp\n push %ebx\n push %esi\n push %edi\n"
    "mov 20(%esp),%eax\n mov 24(%esp),%ecx\n mov 28(%esp),%edx\n"
    "sub $8,%esp\n mov %esp,0(%edx)\n movl $.Lperdedor_recover,4(%edx)\n"
    "push %ecx\n call *%eax\n add $4,%esp\n xor %eax,%eax\n jmp .Lperdedor_restore\n"
    ".Lperdedor_recover:\n mov $1,%eax\n.Lperdedor_restore:\n"
    "add $8,%esp\n pop %edi\n pop %esi\n pop %ebx\n pop %ebp\n ret\n");
#endif

namespace perdedor::guard {
namespace {
struct Frame { uintptr_t recovery[2]{}; uint32_t code = 0; Frame* previous = nullptr; };
thread_local Frame* active = nullptr;
INIT_ONCE once = INIT_ONCE_STATIC_INIT;
PVOID handler = nullptr;
LONG CALLBACK exception_handler(EXCEPTION_POINTERS* ep) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (!active || !active->recovery[0]) return EXCEPTION_CONTINUE_SEARCH;
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_ILLEGAL_INSTRUCTION: case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_DATATYPE_MISALIGNMENT: case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP: case EXCEPTION_INVALID_HANDLE:
        case EXCEPTION_GUARD_PAGE:
        case 0xC0000235u:  // STATUS_HANDLE_NOT_CLOSABLE (protected handle closed under a debugger).
            break;
        default: return EXCEPTION_CONTINUE_SEARCH;
    }
    active->code = code;
#if defined(__x86_64__)
    ep->ContextRecord->Rsp = active->recovery[0];
    ep->ContextRecord->Rip = active->recovery[1];
#else
    ep->ContextRecord->Esp = active->recovery[0];
    ep->ContextRecord->Eip = active->recovery[1];
#endif
    ep->ContextRecord->EFlags &= ~0x100u;  // Clear TF before resuming recovery.
    active->recovery[0] = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}
BOOL CALLBACK install(PINIT_ONCE, PVOID, PVOID*) {
    handler = AddVectoredExceptionHandler(1, exception_handler);
    return TRUE;
}
}  // namespace
Result run(Probe probe, void* argument) noexcept {
    InitOnceExecuteOnce(&once, install, nullptr, nullptr);
    if (!handler || !probe) return {true, kUnavailable};
    Frame frame;
    frame.previous = active;
    active = &frame;
    const bool faulted = perdedor_guard_call(probe, argument, frame.recovery) != 0;
    active = frame.previous;
    return {faulted, frame.code};
}
}  // namespace perdedor::guard
#else
#include <csignal>
#include <csetjmp>
#include <pthread.h>
#include <unistd.h>

namespace perdedor::guard {
namespace {
struct Frame { sigjmp_buf recovery; volatile sig_atomic_t code = 0; Frame* previous = nullptr; };
thread_local Frame* active = nullptr;
constexpr int signals[] = {SIGILL, SIGSEGV, SIGBUS, SIGTRAP};
struct sigaction previous[4]{};
pthread_once_t once = PTHREAD_ONCE_INIT;
bool installed = false;

void signal_handler(int signal, siginfo_t* info, void* context) {
    // SI_USER/SI_TKILL asynchronous signals are not probe faults.
    if (active && info && info->si_code > 0) {
        active->code = signal;
        siglongjmp(active->recovery, 1);
    }
    unsigned index = 0;
    while (index < 4 && signals[index] != signal) ++index;
    if (index == 4) _exit(128 + signal);
    const auto& old = previous[index];
    if (old.sa_handler == SIG_IGN) return;
    if (old.sa_handler == SIG_DFL) {
        sigaction(signal, &old, nullptr);
        raise(signal);
        return;
    }
    if (old.sa_flags & SA_SIGINFO) old.sa_sigaction(signal, info, context);
    else old.sa_handler(signal);
}

void install() {
    struct sigaction action{};
    action.sa_sigaction = signal_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    for (int signal : signals) sigaddset(&action.sa_mask, signal);
    unsigned i = 0;
    for (; i < 4; ++i) if (sigaction(signals[i], &action, &previous[i]) != 0) break;
    installed = i == 4;
    if (!installed) while (i) { --i; sigaction(signals[i], &previous[i], nullptr); }
}
}  // namespace
Result run(Probe probe, void* argument) noexcept {
    pthread_once(&once, install);
    if (!installed || !probe) return {true, kUnavailable};
    Frame frame;
    frame.previous = active;
    const int resumed = sigsetjmp(frame.recovery, 1);
    if (!resumed) { active = &frame; probe(argument); }
    active = frame.previous;
    return {resumed != 0, static_cast<uint32_t>(frame.code)};
}
}  // namespace perdedor::guard
#endif
