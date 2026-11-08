#include "../common/lowlevel.hpp"
#include "lowlevel_parsers.hpp"
#include <array>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

namespace perdedor {
namespace {
using namespace lowlevel;
bool read_bounded(const std::string& path, std::string& out, size_t limit = 65536) {
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    std::array<char, 4096> buf{}; out.clear(); bool ok = true;
    while (out.size() < limit) {
        const auto n = read(fd, buf.data(), std::min(buf.size(), limit - out.size()));
        if (n == 0) break;
        if (n < 0) { ok = false; break; }
        out.append(buf.data(), static_cast<size_t>(n));
    }
    close(fd); return ok;
}
std::vector<Finding> tracer(Context&) {
    std::string text; long pid = 0;
    if (!read_bounded("/proc/self/status", text) || !linux_lowlevel::status_number(text, "TracerPid", pid))
        return {skipped("design.tracer_pid", "TracerPid", "Kernel ptrace ownership of this process.", Severity::High, "TracerPid unavailable in procfs")};
    return {measured("design.tracer_pid", "TracerPid", "Nonzero TracerPid indicates a ptrace tracer visible in this PID namespace.", Severity::High,
                     pid != 0, "PID namespaces can hide an external tracer.", numbers({{"tracer_pid", static_cast<double>(pid)}}), 0.95)};
}
std::vector<Finding> ptrace_child(Context&) {
    // Only the disposable child requests tracing. No exec, SIGSTOP, or changes
    // to the agent's ptrace state. Child uses async-signal-safe calls after fork.
    const pid_t child = fork();
    if (child < 0) return {skipped("design.ptrace_traceme_child", "PTRACE_TRACEME child", "Isolated ptrace availability self-test.", Severity::Medium, "fork unavailable: errno " + std::to_string(errno))};
    if (child == 0) {
        errno = 0; const long rc = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        _exit(rc == 0 ? 0 : (errno == EPERM ? 1 : 2));
    }
    constexpr double kChildDeadlineNs = 1e9;  // Local bounded child lifetime; docs/notes/lowlevel.md.
    const double deadline = monotonic_ns() + kChildDeadlineNs;
    int status = 0; pid_t result = 0;
    while ((result = waitpid(child, &status, WNOHANG | __WALL)) == 0 && monotonic_ns() < deadline) bounded_sleep(1);
    if (result == child && WIFSTOPPED(status)) { ptrace(PTRACE_CONT, child, nullptr, nullptr); result = 0; }
    if (result != child) {
        kill(child, SIGKILL);
        while (waitpid(child, &status, __WALL) < 0 && errno == EINTR) {}
        return {skipped("design.ptrace_traceme_child", "PTRACE_TRACEME child", "Isolated ptrace availability self-test.", Severity::Medium, "Child exceeded deadline or wait failed; child reaped")};
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) == 2)
        return {skipped("design.ptrace_traceme_child", "PTRACE_TRACEME child", "Isolated ptrace availability self-test.", Severity::Medium, "Child blocked/killed or unsupported ptrace result")};
    const int code = WEXITSTATUS(status);
    return {measured("design.ptrace_traceme_child", "PTRACE_TRACEME child", "Denial can indicate inherited tracing, seccomp, Yama or another security policy; it does not prove a debugger.", Severity::Medium,
                     code != 0, "The parent agent never requests tracing for itself.", numbers({{"child_exit", code}}), 0.35)};
}
std::vector<Finding> parent(Context&) {
    std::string name;
    if (!read_bounded("/proc/" + std::to_string(getppid()) + "/comm", name, 256))
        return {skipped("design.debugger_parent", "Debugger parent", "Immediate parent executable name.", Severity::Medium, "Parent procfs entry unavailable")};
    while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
    const auto n = lower(name); bool match = false;
    for (const auto* tool : {"gdb", "gdbserver", "strace", "ltrace", "lldb", "rr"}) if (n == tool) match = true;
    return {measured("design.debugger_parent", "Debugger parent", "Immediate parent name matches a debugger or syscall tracer.", Severity::Medium, match,
                     match ? Json(name) : Json("No debugger-name match"), numbers({{"matched", match}}), 0.7)};
}
std::vector<Finding> terminal_env(Context&) {
    const bool lines = std::getenv("LINES") != nullptr, columns = std::getenv("COLUMNS") != nullptr;
    return {measured("design.debugger_terminal_environment", "Debugger terminal environment", "GDB can propagate LINES and COLUMNS; ordinary shells also set them, so this is weak corroboration only.", Severity::Low,
                     lines && columns, "Reports presence only, not environment contents.", numbers({{"lines_present", lines}, {"columns_present", columns}}), 0.15)};
}
}  // namespace
PERDEDOR_REGISTER(tracer, "debugger.tracer", "fast", false, "design.tracer_pid");
PERDEDOR_REGISTER(ptrace_child, "debugger.tracer", "medium", false, "design.ptrace_traceme_child");
PERDEDOR_REGISTER(parent, "debugger.api_flags", "fast", false, "design.debugger_parent");
PERDEDOR_REGISTER(terminal_env, "debugger.api_flags", "fast", false, "design.debugger_terminal_environment");
}  // namespace perdedor
