#include "linux_util.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <set>
#include <sstream>
#include <ctime>

extern char** environ;
namespace perdedor { namespace linuxutil {
namespace {
struct Fd {
    int value;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() { if (value >= 0) close(value); }
};
constexpr unsigned kSymlinkLimit = 40; // https://man7.org/linux/man-pages/man7/path_resolution.7.html
constexpr size_t kPathLimit = 4096;    // Linux PATH_MAX; same source.
}

Root::Root(const Context& ctx) {
    const char* env = std::getenv("PERDEDOR_ROOT");
    std::string root = ctx.param("root", env ? env : "");
    fixture_ = !root.empty() && root != "/";
    fd_ = open(root.empty() ? "/" : root.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
}
Root::~Root() { if (fd_ >= 0) close(fd_); }

int Root::open_path(const std::string& path, int flags, bool follow) const {
    if (fd_ < 0) { errno = EBADF; return -1; }
    if (path.empty() || path.front() != '/' || path.size() > kPathLimit) { errno = EINVAL; return -1; }
    std::deque<std::string> todo;
    for (const auto& p : split(path, '/')) if (!p.empty()) todo.push_back(p);
    std::vector<int> parents{dup(fd_)};
    auto finish = [&](int result, int err) {
        for (int p : parents) close(p);
        errno = err;
        return result;
    };
    unsigned links = 0;
    while (!todo.empty()) {
        std::string part = todo.front(); todo.pop_front();
        if (part == ".") continue;
        if (part == "..") {
            if (parents.size() > 1) { close(parents.back()); parents.pop_back(); }
            continue;
        }
        int probe = openat(parents.back(), part.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (probe < 0) return finish(-1, errno);
        struct stat st {};
        if (fstat(probe, &st) < 0) { int e = errno; close(probe); return finish(-1, e); }
        if (S_ISLNK(st.st_mode) && (follow || !todo.empty())) {
            char target[kPathLimit + 1];
            ssize_t n = readlinkat(probe, "", target, kPathLimit);
            close(probe);
            if (n < 0) return finish(-1, errno);
            if (static_cast<size_t>(n) == kPathLimit || ++links > kSymlinkLimit) return finish(-1, ELOOP);
            std::string link(target, static_cast<size_t>(n));
            if (!link.empty() && link.front() == '/') {
                while (parents.size() > 1) { close(parents.back()); parents.pop_back(); }
            }
            auto parts = split(link, '/');
            for (auto it = parts.rbegin(); it != parts.rend(); ++it) if (!it->empty()) todo.push_front(*it);
            continue;
        }
        if (todo.empty()) {
            if (flags & O_PATH) return finish(probe, 0);
            // Do not open arbitrary device nodes or FIFOs while scanning files.
            bool allow_kmsg = path == "/dev/kmsg" && S_ISCHR(st.st_mode);
            if (!(S_ISREG(st.st_mode) || S_ISDIR(st.st_mode) || allow_kmsg)) {
                close(probe); return finish(-1, ENOTSUP);
            }
            close(probe);
            int result = openat(parents.back(), part.c_str(), flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            return finish(result, result < 0 ? errno : 0);
        }
        if (!S_ISDIR(st.st_mode)) { close(probe); return finish(-1, ENOTDIR); }
        parents.push_back(probe);
    }
    int result = openat(parents.back(), ".", flags | O_CLOEXEC | O_NONBLOCK);
    return finish(result, result < 0 ? errno : 0);
}

Read Root::read(const std::string& path, size_t limit, bool kmsg) const {
    Read r;
    if (path == "/dev/kmsg" && !kmsg) { r.err = ENOTSUP; return r; }
    Fd fd(open_path(path, O_RDONLY));
    if (fd.value < 0) { r.err = errno; return r; }
    struct stat st {};
    if (fstat(fd.value, &st) != 0 || (!S_ISREG(st.st_mode) && !(kmsg && S_ISCHR(st.st_mode)))) {
        r.err = ENOTSUP; return r;
    }
    char buf[8192];
    while (r.value.size() <= limit) {
        size_t want = std::min(sizeof buf, limit + 1 - r.value.size());
        ssize_t n = ::read(fd.value, buf, want);
        if (n > 0) r.value.append(buf, static_cast<size_t>(n));
        else if (n == 0 || (kmsg && errno == EAGAIN)) break;
        else if (errno == EINTR) continue;
        else { r.err = errno; return r; }
    }
    r.ok = true;
    r.truncated = r.value.size() > limit;
    if (r.truncated) r.value.resize(limit);
    return r;
}
Read Root::link(const std::string& path) const {
    Read r;
    Fd fd(open_path(path, O_PATH, false));
    if (fd.value < 0) { r.err = errno; return r; }
    char buf[kPathLimit];
    ssize_t n = readlinkat(fd.value, "", buf, sizeof buf);
    if (n < 0) { r.err = errno; return r; }
    r.ok = true; r.value.assign(buf, static_cast<size_t>(n));
    r.truncated = static_cast<size_t>(n) == sizeof buf;
    return r;
}
Metadata Root::stat(const std::string& path, bool follow) const {
    Metadata m;
    Fd fd(open_path(path, O_PATH, follow));
    if (fd.value < 0) { m.err = errno; return m; }
    m.ok = fstat(fd.value, &m.st) == 0;
    if (!m.ok) m.err = errno;
#if defined(SYS_statx) && defined(STATX_BTIME)
    struct statx sx {};
    // Fixture trees are fresh copies: their birth times say nothing about the system they model.
    if (!fixture_ && syscall(SYS_statx, fd.value, "", AT_EMPTY_PATH, STATX_BTIME, &sx) == 0 &&
        (sx.stx_mask & STATX_BTIME))
        m.birth = sx.stx_btime.tv_sec;
#endif
    return m;
}
Listing Root::list(const std::string& path) const {
    Listing l;
    int fd = open_path(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) { l.err = errno; return l; }
    DIR* d = fdopendir(fd);
    if (!d) { l.err = errno; close(fd); return l; }
    errno = 0;
    while (dirent* ent = readdir(d)) {
        std::string n = ent->d_name;
        if (n == "." || n == "..") continue;
        if (l.names.size() == kEntryLimit) { l.truncated = true; break; }
        l.names.push_back(n);
    }
    l.err = errno; closedir(d);
    l.ok = l.err == 0;
    std::sort(l.names.begin(), l.names.end());
    return l;
}
Listing Root::walk(const std::string& path, unsigned depth) const {
    Listing out; out.ok = true;
    std::deque<std::pair<std::string, unsigned>> pending{{path, depth}};
    size_t visited = 0;
    while (!pending.empty() && visited < kEntryLimit) {
        auto cur = pending.front(); pending.pop_front();
        auto dir = list(cur.first);
        if (!dir.ok) { out.ok = false; out.err = dir.err; continue; }
        out.truncated |= dir.truncated;
        for (const auto& n : dir.names) {
            if (++visited > kEntryLimit) { out.truncated = true; break; }
            std::string p = cur.first + "/" + n;
            auto st = stat(p, false);
            if (!st.ok) { out.ok = false; out.err = st.err; continue; }
            if (S_ISREG(st.st.st_mode)) out.names.push_back(p);
            else if (S_ISDIR(st.st.st_mode)) {
                if (cur.second) pending.emplace_back(p, cur.second - 1);
                else out.truncated = true;
            }
        }
    }
    out.truncated |= !pending.empty();
    return out;
}

std::map<std::string, std::string> Root::environment() const {
    std::map<std::string, std::string> env;
    auto r = read("/proc/self/environ");
    if (r.ok) for (auto& s : split(r.value, '\0')) {
        auto pos = s.find('=');
        if (pos != std::string::npos) env[s.substr(0, pos)] = s.substr(pos + 1);
    }
    // /proc/self/environ describes the original environment. Live getenv also
    // covers changes made after exec. Never fall back to the host in root mode.
    if (!fixture_) for (char** p = environ; p && *p; ++p) {
        std::string s(*p); auto pos = s.find('=');
        if (pos != std::string::npos) env[s.substr(0, pos)] = s.substr(pos + 1);
    }
    return env;
}
std::string Root::home() const {
    auto env = environment(); auto it = env.find("HOME");
    if (it != env.end() && !it->second.empty() && it->second[0] == '/') return it->second;
    return "";
}
std::string Root::username() const {
    auto env = environment();
    for (const char* key : {"USER", "LOGNAME"}) if (env.count(key) && !env[key].empty()) return env[key];
    // Services and cron jobs often run without USER: resolve the uid through /etc/passwd.
    long long id = uid();
    if (id < 0) return "";
    auto passwd = read("/etc/passwd");
    if (passwd.ok) for (const auto& line : lines(passwd.value)) {
        auto f = split(line, ':');
        long long n;
        if (f.size() > 2 && number(f[2], n) && n == id) return f[0];
    }
    return "";
}
std::string Root::hostname() const {
    auto r = read("/proc/sys/kernel/hostname");
    if (r.ok && !trim(r.value).empty()) return trim(r.value);
    auto etc = read("/etc/hostname");
    if (etc.ok && !trim(etc.value).empty()) return trim(lines(etc.value)[0]);
    if (fixture_) return "";
    char buf[256] = {0};
    if (gethostname(buf, sizeof buf - 1) != 0) return "";
    return buf;
}
long long Root::uid() const {
    auto st = read("/proc/self/status");
    if (st.ok) {
        auto f = fields(st.value);
        auto it = f.find("Uid");
        if (it != f.end()) {
            std::istringstream in(it->second);
            long long real = -1, effective = -1;
            in >> real >> effective;
            if (effective >= 0) return effective;
        }
    }
    return fixture_ ? -1 : static_cast<long long>(geteuid());
}
long long Root::now() const { return static_cast<long long>(std::time(nullptr)); }

Read Root::command(const std::vector<std::string>& argv) const {
    Read r;
    if (fixture_ || argv.empty()) { r.err = ENOTSUP; return r; }
    // Only fixed, read-only commands supplied by checks; no shell or PATH lookup.
    auto executable = stat(argv.front());
    if (!executable.ok) { r.err = executable.err; return r; }
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) { r.err = errno; return r; }
    std::vector<char*> args;
    for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    pid_t child = fork();
    if (child == 0) {
        setpgid(0, 0);
        dup2(pipefd[1], STDOUT_FILENO);
        close(STDERR_FILENO); close(STDIN_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        execv(args[0], args.data()); _exit(127);
    }
    close(pipefd[1]);
    Fd output(pipefd[0]);
    if (child < 0) { r.err = errno; return r; }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kCommandTimeoutMs);
    int status = 0;
    bool finished = false;
    while (std::chrono::steady_clock::now() < deadline) {
        char buf[8192];
        ssize_t n = ::read(output.value, buf, sizeof buf);
        if (n > 0) {
            r.value.append(buf, static_cast<size_t>(n));
            if (r.value.size() > kPackageLimit) { r.truncated = true; break; }
        }
        if (waitpid(child, &status, WNOHANG) == child) { finished = true; }
        if (finished && n <= 0) break;
        pollfd p{output.value, POLLIN, 0}; poll(&p, 1, 10);
    }
    if (!finished) {
        kill(-child, SIGKILL); kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        r.err = ETIMEDOUT; return r;
    }
    r.ok = WIFEXITED(status) && (WEXITSTATUS(status) == 0 ||
            (basename(argv[0]) == "systemd-detect-virt" && WEXITSTATUS(status) == 1));
    if (!r.ok) r.err = EIO;
    return r;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n\0", 0, 5);
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n\0", std::string::npos, 5);
    return s.substr(a, b - a + 1);
}
std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out; size_t p = 0;
    while (p <= s.size()) {
        auto end = s.find(delim, p); out.push_back(s.substr(p, end == std::string::npos ? end : end - p));
        if (end == std::string::npos) break;
        p = end + 1;
    }
    return out;
}
std::vector<std::string> lines(const std::string& s) { return split(s, '\n'); }
std::string basename(const std::string& s) { return s.substr(s.find_last_of('/') + 1); }
bool number(const std::string& s, long long& value, int base) {
    std::string t = trim(s); if (t.empty()) return false;
    char* end = nullptr; errno = 0;
    long long n = std::strtoll(t.c_str(), &end, base);
    if (errno || end == t.c_str() || *end != '\0') return false;
    value = n; return true;
}
std::string match(const std::string& s, const std::vector<std::string>& signatures) {
    std::string text = lower(s);
    for (const auto& sig : signatures) if (text.find(lower(sig)) != std::string::npos) return sig;
    return "";
}
std::map<std::string, std::string> fields(const std::string& s, char separator) {
    std::map<std::string, std::string> out;
    for (const auto& line : lines(s)) {
        auto pos = line.find(separator);
        if (pos != std::string::npos) out[trim(line.substr(0, pos))] = trim(line.substr(pos + 1));
    }
    return out;
}
const std::vector<std::string>& vm_signatures() {
    // v1 signatures plus VMAware v2.8.2 DMI_SCAN and systemd v257 detect_vm_dmi_vendor.
    static const std::vector<std::string> s = {"qemu", "bochs", "kvm", "virtualbox", "vbox", "innotek",
        "vmware", "xen", "microsoft corporation", "parallels", "bhyve", "amazon ec2", "google compute engine",
        "ovmf", "seabios", "hvmloader", "virtual machine", "openstack", "kubevirt", "nutanix", "acrn",
        "oracle corporation", "smbios-base", "virtual platform"};
    return s;
}
const std::vector<std::string>& guest_names() {
    static const std::vector<std::string> s = {"qemu-ga", "qemu-guest-agent", "vboxservice", "vboxclient",
        "virtualbox-guest", "vmtoolsd", "vmware-toolbox-cmd", "open-vm-tools", "xe-daemon", "xe-guest",
        "spice-vdagent", "hv_kvp_daemon", "hv_vss_daemon", "hv_fcopy_daemon", "waagent", "walinuxagent",
        "cloud-init", "xenstore", "xen-guest", "prltoolsd", "prl-tools"};
    return s;
}
const std::vector<std::string>& tool_names() {
    static const std::vector<std::string> s = {"strace", "ltrace", "gdb", "edb", "wireshark", "tshark",
        "tcpdump", "mitmproxy", "mitmdump", "mitmweb", "burpsuite", "zaproxy", "fakenet", "inetsim",
        "volatility", "vol.py", "vol3", "ida64", "ida", "ghidra", "radare2", "r2", "x64dbg", "binwalk",
        "sysdig", "bpftrace", "frida-server", "frida-helper", "falco", "auditd", "osqueryd", "cuckoo",
        "cape", "drakvuf", "drakrun", "drakvuf-injector", "gdbserver", "rr"};
    return s;
}
void Evidence::add(const std::string& hit) {
    if (hits.size() < kEvidenceLimit && std::find(hits.begin(), hits.end(), hit) == hits.end())
        hits.push_back(hit.substr(0, 160));
}
void Evidence::scan(const Read& r, const std::vector<std::string>& signatures, const std::string& label) {
    if (!r.ok) { ++unavailable; return; }
    ++observed; partial |= r.truncated;
    auto hit = match(r.value, signatures); if (!hit.empty()) add(label + ":" + hit);
}
void Evidence::paths(const Root& root, const std::vector<std::string>& paths) {
    for (const auto& p : paths) {
        auto st = root.stat(p, false);
        if (st.ok) { ++observed; add(p); }
        else if (st.err == ENOENT || st.err == ENOTDIR) ++observed;
        else ++unavailable;
    }
}
Json Evidence::json() const {
    Json e = Json::object(); e.set("inspected", static_cast<long long>(observed));
    e.set("unavailable", static_cast<long long>(unavailable)); e.set("partial", partial);
    e.set("matches", Json(hits)); return e;
}
Finding Evidence::finding(const std::string& id, const std::string& name, const std::string& desc,
                         Severity severity, const std::string& fix, double confidence) const {
    Finding f;
    if (!hits.empty()) f = detected(id, name, desc, severity, json(), fix);
    else if (!observed) f = skipped(id, name, desc, severity, "no readable applicable source");
    else if (partial || unavailable) f = skipped(id, name, desc, severity, "inspection incomplete; no match in inspected subset");
    else f = clean(id, name, desc, severity, json());
    f.evidence = json(); f.confidence = confidence; return f;
}
Finding unavailable(const std::string& id, const std::string& name, Severity severity, int err,
                    const std::string& detail) {
    if (err == ENOENT || err == ENOTDIR || err == ENOTSUP)
        return skipped(id, name, detail, severity, detail + ": interface absent or not applicable");
    if (err == EACCES || err == EPERM)
        return skipped(id, name, detail, severity, detail + ": permission denied (needs root)");
    return error(id, name, detail, severity, detail + ": " + std::strerror(err ? err : EINVAL));
}
Finding measured(const std::string& id, const std::string& name, const std::string& desc,
                 double value, double threshold, bool hit, const std::string& unit,
                 const std::string& fix, Severity severity, double confidence) {
    Json e = Json::object(); e.set("value", value); e.set("threshold", threshold); e.set("unit", unit);
    auto f = bool_check(id, name, desc, severity, hit, e, fix);
    f.measurement = e; f.confidence = confidence; return f;
}
std::vector<Finding> scan_file(Context& ctx, const char* id, const char* name, const char* path,
                               const std::vector<std::string>& signatures, Severity severity, const char* fix) {
    Root root(ctx); auto r = root.read(path);
    if (!r.ok) return {unavailable(id, name, severity, r.err, path)};
    Evidence e; e.scan(r, signatures, path);
    return {e.finding(id, name, "Matches known signatures in the named kernel or system interface.", severity, fix)};
}

Packages packages(const Root& root) {
    Packages p;
    auto dpkg = root.read("/var/lib/dpkg/status", kPackageLimit);
    if (dpkg.ok) {
        p.ok = true; p.manager = "dpkg"; p.partial = dpkg.truncated;
        std::string name, status;
        for (const auto& line : lines(dpkg.value + "\n\n")) {
            if (line.rfind("Package: ", 0) == 0) name = trim(line.substr(9));
            if (line.rfind("Status: ", 0) == 0) status = trim(line.substr(8));
            if (line.empty()) { if (!name.empty() && status == "install ok installed") p.names.push_back(name); name.clear(); status.clear(); }
        }
        return p;
    }
    auto apk = root.read("/lib/apk/db/installed", kPackageLimit);
    if (apk.ok) {
        p.ok = true; p.manager = "apk"; p.partial = apk.truncated;
        for (const auto& line : lines(apk.value)) if (line.rfind("P:", 0) == 0) p.names.push_back(line.substr(2));
        return p;
    }
    auto pacman = root.list("/var/lib/pacman/local");
    if (pacman.ok) {
        p.ok = true; p.manager = "pacman"; p.partial = pacman.truncated;
        for (const auto& n : pacman.names) {
            auto desc = root.read("/var/lib/pacman/local/" + n + "/desc");
            if (!desc.ok) { if (n != "ALPM_DB_VERSION") p.partial = true; continue; }
            auto ls = lines(desc.value);
            for (size_t i = 0; i + 1 < ls.size(); ++i) if (ls[i] == "%NAME%") p.names.push_back(ls[i + 1]);
        }
        return p;
    }
    // RPM databases are binary. Use RPM's read-only query instead of guessing
    // their format; alternate roots never execute a fixture or host binary.
    if (!root.fixture()) {
        auto rpm = root.command({"/usr/bin/rpm", "-qa", "--qf", "%{NAME}\n"});
        if (rpm.ok) { p.ok = true; p.manager = "rpm"; p.partial = rpm.truncated;
            for (const auto& line : lines(rpm.value)) if (!line.empty()) p.names.push_back(line); }
    }
    return p;
}
Evidence process_matches(const Root& root, const std::vector<std::string>& signatures) {
    Evidence e; auto procs = root.list("/proc");
    if (!procs.ok) { e.unavailable++; return e; }
    e.partial = procs.truncated;
    for (const auto& pid : procs.names) {
        long long n; if (!number(pid, n) || n <= 0) continue;
        auto comm = root.read("/proc/" + pid + "/comm");
        if (!comm.ok) { if (comm.err != ENOENT && comm.err != ESRCH) ++e.unavailable; continue; }
        ++e.observed;
        std::string name = lower(trim(comm.value));
        for (const auto& sig : signatures) {
            // Linux comm is TASK_COMM_LEN-1 bytes. Match exact names and their
            // kernel truncation, never short substrings such as 'r2' or 'ida'.
            if (name == sig || (sig.size() > 15 && name == sig.substr(0, 15))) e.add(sig);
        }
    }
    return e;
}

bool process(const Root& root, const std::string& pid, Proc& out) {
    auto comm = root.read("/proc/" + pid + "/comm");
    if (!comm.ok) return false;
    out.pid = pid;
    out.comm = trim(comm.value);
    auto cmd = root.read("/proc/" + pid + "/cmdline", 4096);
    if (cmd.ok) {
        auto args = split(cmd.value, '\0');
        if (!args.empty()) out.argv0 = basename(args[0]);
        if (args.size() > 1) out.argv1 = basename(args[1]);
    }
    auto stat = root.read("/proc/" + pid + "/stat");
    if (stat.ok) {
        // Field 4 follows the parenthesised comm, which may itself contain spaces or ')'.
        auto close = stat.value.rfind(')');
        if (close != std::string::npos) {
            std::istringstream in(stat.value.substr(close + 1));
            std::string state;
            long long ppid = -1;
            in >> state >> ppid;
            out.ppid = ppid;
        }
    }
    return true;
}
ProcList processes(const Root& root, bool with_cmdline) {
    ProcList out;
    auto procs = root.list("/proc");
    if (!procs.ok) { out.err = procs.err; return out; }
    out.ok = true;
    out.partial = procs.truncated;
    for (const auto& pid : procs.names) {
        long long n;
        if (!number(pid, n) || n <= 0) continue;
        Proc p;
        if (with_cmdline) {
            if (process(root, pid, p)) out.procs.push_back(p);
            continue;
        }
        auto comm = root.read("/proc/" + pid + "/comm");
        if (!comm.ok) continue;  // exited while listing
        p.pid = pid;
        p.comm = trim(comm.value);
        out.procs.push_back(p);
    }
    return out;
}
std::map<std::string, std::string> os_release(const Root& root) {
    std::map<std::string, std::string> out;
    for (const char* path : {"/etc/os-release", "/usr/lib/os-release"}) {
        auto r = root.read(path);
        if (!r.ok) continue;
        for (const auto& line : lines(r.value)) {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string v = trim(line.substr(eq + 1));
            if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'')) v = v.substr(1, v.size() - 2);
            out[trim(line.substr(0, eq))] = v;
        }
        break;
    }
    return out;
}
std::string read_value(const Root& root, const std::string& path, bool& ok) {
    auto r = root.read(path);
    ok = r.ok;
    return r.ok ? trim(r.value) : std::string();
}
bool hex_string(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}
bool has_word(const std::string& text, const std::string& word) {
    std::string t = lower(text), w = lower(word);
    for (size_t p = t.find(w); p != std::string::npos; p = t.find(w, p + 1)) {
        bool left = p == 0 || !std::isalnum(static_cast<unsigned char>(t[p - 1]));
        size_t end = p + w.size();
        bool right = end >= t.size() || !std::isalnum(static_cast<unsigned char>(t[end]));
        if (left && right) return true;
    }
    return false;
}
Listing entries(const Root& root, const std::string& path) { return root.list(path); }
Count count_files(const Root& root, const std::string& path, const std::vector<std::string>& suffixes,
                  unsigned depth) {
    Count c;
    auto top = root.stat(path);
    if (!top.ok) return c;
    c.ok = true;
    auto w = root.walk(path, depth);
    c.partial = w.truncated || !w.ok;
    for (const auto& f : w.names) {
        std::string n = lower(f);
        bool want = suffixes.empty();
        for (const auto& s : suffixes)
            if (n.size() >= s.size() && n.compare(n.size() - s.size(), s.size(), s) == 0) want = true;
        if (!want) continue;
        auto st = root.stat(f, false);
        if (!st.ok) continue;
        ++c.files;
        c.bytes += st.st.st_size;
        long long m = st.st.st_mtime;
        if (!c.oldest || m < c.oldest) c.oldest = m;
        if (m > c.newest) c.newest = m;
    }
    return c;
}
std::string join(const std::vector<std::string>& items, const std::string& sep) {
    std::string out;
    for (const auto& i : items) out += (out.empty() ? "" : sep) + i;
    return out;
}
Finding unreadable(const std::string& id, const std::string& name, const std::string& desc, Severity severity,
                   int err, const std::string& what) {
    Finding f = unavailable(id, name, severity, err, what);
    f.description = desc;
    return f;
}
std::vector<std::string> unit_files(const Root& root, bool& ok) {
    // systemd.unit(5): system unit search path.
    std::set<std::string> names;
    ok = false;
    for (const char* dir : {"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
                            "/usr/local/lib/systemd/system", "/run/systemd/system"}) {
        auto l = root.list(dir);
        if (!l.ok) continue;
        ok = true;
        for (const auto& n : l.names) names.insert(n);
        for (const auto& n : l.names) {
            if (n.size() > 6 && n.compare(n.size() - 6, 6, ".wants") == 0) {
                auto wants = root.list(std::string(dir) + "/" + n);
                for (const auto& u : wants.names) names.insert(u);
            }
        }
    }
    auto init = root.list("/etc/init.d");
    if (init.ok) { ok = true; for (const auto& n : init.names) names.insert(n); }
    return std::vector<std::string>(names.begin(), names.end());
}
} }  // namespace perdedor::linuxutil
