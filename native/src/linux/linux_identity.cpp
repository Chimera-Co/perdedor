// Identity, analysis tooling and OS configuration on Linux.
//
// Sources: v1 Linux agent design.py/signatures.py (name tokens, exact user
// list, tool list, framework paths); al-khaser AntiVM/Generic.cpp
// (known_usernames, known_hostnames, known_file_names); VMAware v2.8.2
// (LINUX_USER_HOST, AZURE); Linux Documentation/admin-guide/sysctl/kernel.rst
// (randomize_va_space, core_pattern), Documentation/admin-guide/LSM/Yama.rst,
// kernel_lockdown(7); Ubuntu security features (ptrace_scope=1 default).
#include <cerrno>
#include <algorithm>
#include <cstring>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

// randomize_va_space: 2 = full randomisation (kernel default since 2.6.25).
constexpr long long kFullAslr = 2;

const std::vector<std::string>& name_tokens() {
    // v1 SUSPICIOUS_NAME_TOKENS.
    static const std::vector<std::string> s = {"sandbox", "malware", "sample", "analysis", "cuckoo", "detonat",
        "honeypot", "virus"};
    return s;
}

std::vector<Finding> hostname_or_user(Context& ctx) {
    const char* id = "design.suspicious_hostname_or_user";
    const char* name = "Hostname/username plausibility (substring)";
    const char* desc = "Hostnames/usernames containing 'sandbox', 'malware', 'sample', 'analysis', 'cuckoo'... are "
                       "an easy, high-confidence tell.";
    Root root(ctx);
    std::string host = root.hostname(), user = root.username();
    if (host.empty() && user.empty()) return {skipped(id, name, desc, Severity::Low, "no hostname or username")};
    std::vector<std::string> hits;
    if (!match(host, name_tokens()).empty()) hits.push_back("hostname=" + host);
    if (!match(user, name_tokens()).empty()) hits.push_back("user=" + user);
    Json ev = Json::object();
    ev.set("hostname", host);
    ev.set("user", user);
    ev.set("matches", Json(hits));
    return {bool_check(id, name, desc, Severity::Low, !hits.empty(), ev,
                       "Give the image a plausible everyday hostname and account name.")};
}

std::vector<Finding> exact_username(Context& ctx) {
    const char* id = "design.exact_sandbox_username";
    const char* name = "Username exact-match blacklist (al-khaser style)";
    const char* desc = "The user name equals one on public sandbox lists (v1 list plus al-khaser known_usernames: "
                       "Gootkit, ostap, Betabot, Satan and Emotet lists).";
    // v1 SANDBOX_USERNAME_EXACT + al-khaser known_usernames().
    static const std::vector<std::string> names = {"sandbox", "malware", "maltest", "currentuser", "sample", "virus",
        "test", "test user", "vmuser", "john doe", "emily", "hapubws", "hong lee", "it-admin", "johnson", "miller",
        "milozs", "peter wilson", "timmy", "user", "sand box", "wilber", "abby", "cuckoo"};
    Root root(ctx);
    std::string user = lower(root.username());
    if (user.empty()) return {skipped(id, name, desc, Severity::Low, "username unknown")};
    bool hit = std::find(names.begin(), names.end(), user) != names.end();
    return {bool_check(id, name, desc, Severity::Low, hit, "user=" + user,
                       "Use a plausible full-name-style account, never a generic or test name.")};
}

std::vector<Finding> sandbox_hostnames(Context& ctx) {
    const char* id = "design.sandbox_hostname_list";
    const char* name = "Hostname on public sandbox lists";
    const char* desc = "Hostname equals one checked by Gootkit, ostap, Shifu and Emotet (al-khaser known_hostnames).";
    static const std::vector<std::string> names = {"sandbox", "7silvia", "hanspeter-pc", "john-pc", "mueller-pc",
        "win7-traps", "fortinet", "tequilaboomboom", "systemit", "klone_x64-pc"};
    Root root(ctx);
    std::string host = lower(root.hostname());
    if (host.empty()) return {skipped(id, name, desc, Severity::Medium, "hostname unknown")};
    std::string shortname = host.substr(0, host.find('.'));
    bool hit = std::find(names.begin(), names.end(), shortname) != names.end();
    return {bool_check(id, name, desc, Severity::Medium, hit, "hostname=" + host, "Rename the image.")};
}

std::vector<Finding> live_user_host(Context& ctx) {
    const char* id = "design.linux_user_host";
    const char* name = "Live-session default user and host";
    const char* desc = "User 'liveuser' on host 'localhost-live' (Fedora live images; VMAware LINUX_USER_HOST), or "
                       "other live-media defaults (ubuntu@ubuntu, kali@kali).";
    Root root(ctx);
    std::string user = lower(root.username()), host = lower(root.hostname());
    if (user.empty() || host.empty()) return {skipped(id, name, desc, Severity::Low, "user or hostname unknown")};
    bool hit = (user == "liveuser" && host == "localhost-live") || (user == "ubuntu" && host == "ubuntu") ||
               (user == "kali" && host == "kali");
    Json ev = Json::object();
    ev.set("user", user);
    ev.set("hostname", host);
    return {bool_check(id, name, desc, Severity::Low, hit, ev, "Install the OS; do not run samples on live media.")};
}

std::vector<Finding> default_hostname(Context& ctx) {
    const char* id = "design.default_hostname";
    const char* name = "Default or generated hostname";
    const char* desc = "Image-default hostnames (localhost, debian, ubuntu, kali, fedora...), the EC2 'ip-a-b-c-d' "
                       "scheme or a 12-hex-digit Docker container id.";
    static const std::vector<std::string> defaults = {"localhost", "localhost.localdomain", "debian", "ubuntu", "kali",
        "fedora", "archlinux", "alpine", "centos", "rocky", "almalinux", "raspberrypi", "linux", "box", "vagrant"};
    Root root(ctx);
    std::string host = lower(root.hostname());
    if (host.empty()) return {skipped(id, name, desc, Severity::Low, "hostname unknown")};
    std::string s = host.substr(0, host.find('.'));
    std::string why;
    if (std::find(defaults.begin(), defaults.end(), host) != defaults.end() ||
        std::find(defaults.begin(), defaults.end(), s) != defaults.end())
        why = "distribution default";
    if (s.rfind("ip-", 0) == 0 && s.find_first_not_of("0123456789-", 3) == std::string::npos) why = "EC2 ip-* name";
    if (s.size() == 12 && hex_string(s)) why = "container id";
    Json ev = Json::object();
    ev.set("hostname", host);
    if (!why.empty()) ev.set("reason", why);
    return {bool_check(id, name, desc, Severity::Low, !why.empty(), ev, "Set a personal-looking hostname.")};
}

std::vector<Finding> ci_hostname(Context& ctx) {
    const char* id = "design.ci_runner_hostname";
    const char* name = "Hosted CI runner hostname";
    const char* desc = "13-character hostnames starting with 'runnervm' are GitHub-hosted Azure runners (VMAware AZURE).";
    Root root(ctx);
    std::string host = root.hostname();
    if (host.empty()) return {skipped(id, name, desc, Severity::Low, "hostname unknown")};
    bool hit = host.size() == 13 && host.rfind("runnervm", 0) == 0;
    return {bool_check(id, name, desc, Severity::Low, hit, "hostname=" + host, "Do not detonate on CI runners.")};
}

std::vector<Finding> ci_env(Context& ctx) {
    const char* id = "design.ci_environment";
    const char* name = "CI environment variables";
    const char* desc = "Variables set by CI systems (GITHUB_ACTIONS, GITLAB_CI, JENKINS_URL, BUILDKITE, TF_BUILD, "
                       "CIRCLECI, TRAVIS, CI). Names only.";
    Root root(ctx);
    Evidence e;
    e.observed = 1;
    auto env = root.environment();
    for (const char* k : {"GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE", "TF_BUILD", "CIRCLECI", "TRAVIS",
                          "CI", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER", "RUNNER_NAME"})
        if (env.count(k)) e.add(k);
    return {e.finding(id, name, desc, Severity::Low, "Do not detonate on CI runners.")};
}

std::vector<Finding> sandbox_env(Context& ctx) {
    const char* id = "design.sandbox_environment_variables";
    const char* name = "Sandbox environment variables";
    const char* desc = "Environment variable names mentioning sandbox or analysis software (CUCKOO, CAPE, DRAKVUF, "
                       "SANDBOX, MALWARE, INETSIM, FAKENET, ANALYZER). Names only, never values.";
    static const std::vector<std::string> sigs = {"CUCKOO", "CAPE", "DRAKVUF", "DRAKRUN", "SANDBOX", "MALWARE",
        "INETSIM", "FAKENET", "ANALYZER", "ANALYSIS", "DETONAT", "KARTON", "FRIDA"};
    Root root(ctx);
    auto env = root.environment();
    if (env.empty()) return {skipped(id, name, desc, Severity::Medium, "environment not readable")};
    Evidence e;
    e.observed = env.size();
    for (const auto& kv : env) {
        std::string k = kv.first;
        if (k.rfind("PERDEDOR", 0) == 0) continue;  // the operator's own settings
        std::string up = k;
        for (char& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        for (const auto& s : sigs)
            if (up.find(s) != std::string::npos) e.add(k);
    }
    return {e.finding(id, name, desc, Severity::Medium, "Start samples with a clean user environment.")};
}

std::vector<Finding> sample_path(Context& ctx) {
    const char* id = "design.sample_path";
    const char* name = "Sample runs from a sandbox-like location";
    const char* desc = "This process's executable (/proc/self/exe) lives in /tmp, /var/tmp, /dev/shm or a directory "
                       "named sample, malware, analysis, analyzer, sandbox or cuckoo.";
    static const std::vector<std::string> dirs = {"/tmp/", "/var/tmp/", "/dev/shm/"};
    static const std::vector<std::string> words = {"sample", "malware", "analysis", "analyzer", "sandbox", "cuckoo",
        "virus", "detonat", "submission"};
    Root root(ctx);
    auto l = root.link("/proc/self/exe");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/proc/self/exe")};
    std::string exe = l.value, dir = exe.substr(0, exe.rfind('/') + 1);
    std::vector<std::string> why;
    for (const auto& d : dirs)
        if (dir.rfind(d, 0) == 0) why.push_back("temporary directory " + d);
    if (!match(dir, words).empty()) why.push_back("directory name contains '" + match(dir, words) + "'");
    Json ev = Json::object();
    ev.set("directory", dir.substr(0, 120));
    ev.set("reasons", Json(why));
    return {bool_check(id, name, desc, Severity::Medium, !why.empty(), ev,
                       "Drop samples into a user-like location (~/Downloads) under a plausible name.")};
}

std::vector<Finding> sample_name(Context& ctx) {
    const char* id = "design.sample_name";
    const char* name = "Sample file name is a hash or sandbox name";
    const char* desc = "The executable's name is an MD5/SHA-1/SHA-256 hex string or a name sandboxes use "
                       "(al-khaser known_file_names: sample, bot, sandbox, malware, test, klavme, myapp, testapp).";
    static const std::vector<std::string> names = {"sample", "bot", "sandbox", "malware", "test", "klavme", "myapp",
        "testapp", "file", "binary", "payload"};
    Root root(ctx);
    auto l = root.link("/proc/self/exe");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/proc/self/exe")};
    std::string base = basename(l.value);
    if (base.size() > 10 && base.compare(base.size() - 10, 10, " (deleted)") == 0) base.resize(base.size() - 10);
    std::string stem = lower(base.substr(0, base.find('.')));
    std::string why;
    if ((stem.size() == 32 || stem.size() == 40 || stem.size() == 64) && hex_string(stem)) why = "hash-like name";
    if (std::find(names.begin(), names.end(), stem) != names.end()) why = "sandbox file name";
    Json ev = Json::object();
    ev.set("name", base.substr(0, 80));
    if (!why.empty()) ev.set("reason", why);
    return {bool_check(id, name, desc, Severity::Medium, !why.empty(), ev,
                       "Rename samples to a plausible original name before running them.")};
}

std::vector<Finding> parent_process(Context& ctx) {
    const char* id = "design.parent_process";
    const char* name = "Launched by an analysis agent";
    const char* desc = "The parent process is a sandbox agent or tracer: python running agent.py/analyzer.py "
                       "(Cuckoo/CAPE), strace, ltrace, gdb, valgrind, frida, drakrun.";
    static const std::vector<std::string> parents = {"strace", "ltrace", "gdb", "gdbserver", "valgrind", "frida",
        "frida-server", "drakrun", "drakvuf", "injector", "rr", "qemu-x86_64", "qemu-i386", "box64", "fakenet",
        "inetsim"};
    static const std::vector<std::string> scripts = {"agent.py", "agent.pyw", "analyzer.py", "analyzer.pyw",
        "cuckoo", "cape"};
    Root root(ctx);
    Proc self;
    if (!process(root, "self", self) || self.ppid <= 0)
        return {skipped(id, name, desc, Severity::Medium, "parent pid unknown")};
    Proc parent;
    if (!process(root, std::to_string(self.ppid), parent))
        return {skipped(id, name, desc, Severity::Medium, "parent not readable")};
    std::string why;
    for (const auto& p : parents)
        if (lower(parent.comm) == p || lower(parent.argv0) == p) why = p;
    for (const auto& s : scripts)
        if (lower(parent.argv1) == s) why = parent.argv0 + " " + s;
    Json ev = Json::object();
    ev.set("parent", parent.comm);
    if (!why.empty()) ev.set("match", why);
    return {bool_check(id, name, desc, Severity::Medium, !why.empty(), ev,
                       "Start samples the way a user would (file manager, shell, xdg-open), not from the agent "
                       "(CHIMERA: DRAKVUF injection avoids an in-guest agent).")};
}

std::string locale_of(const Root& root) {
    auto env = root.environment();
    for (const char* k : {"LC_ALL", "LC_MESSAGES", "LANG"})
        if (env.count(k) && !env[k].empty()) return env[k];
    for (const char* f : {"/etc/default/locale", "/etc/locale.conf"}) {
        auto r = root.read(f);
        if (!r.ok) continue;
        auto kv = fields(r.value, '=');
        if (kv.count("LANG")) {
            std::string v = kv["LANG"];
            if (v.size() >= 2 && v.front() == '"') v = v.substr(1, v.size() - 2);
            return v;
        }
    }
    return "";
}

std::vector<Finding> locale_generic(Context& ctx) {
    const char* id = "design.locale_generic";
    const char* name = "Generic C/POSIX locale";
    const char* desc = "LANG/LC_ALL unset or C/POSIX/C.UTF-8: automation and minimal images, not a person's desktop.";
    Root root(ctx);
    std::string loc = locale_of(root);
    std::string l = lower(loc);
    bool generic = l.empty() || l == "c" || l == "posix" || l == "c.utf-8" || l == "c.utf8";
    Json ev = Json::object();
    ev.set("locale", loc.empty() ? "(unset)" : loc);
    return {bool_check(id, name, desc, Severity::Low, generic, ev, "Configure the impersonated user's locale.")};
}

std::vector<Finding> cis_locale(Context& ctx) {
    const char* id = "design.cis_locale_guardrail";
    const char* name = "CIS language or time zone (sample guardrail)";
    const char* desc = "A Russian/CIS locale or time zone: many families exit on such systems, so the sandbox never "
                       "sees their behaviour.";
    static const std::vector<std::string> langs = {"ru_", "uk_", "be_", "kk_", "hy_", "az_", "ka_", "ky_", "tg_",
        "uz_", "tk_", "ro_md"};
    static const std::vector<std::string> zones = {"europe/moscow", "europe/minsk", "europe/kiev", "europe/kyiv",
        "asia/almaty", "asia/yerevan", "asia/baku", "asia/tbilisi", "asia/bishkek", "asia/tashkent", "asia/dushanbe",
        "asia/ashgabat", "europe/chisinau", "europe/samara", "asia/novosibirsk", "asia/yekaterinburg"};
    Root root(ctx);
    std::string loc = lower(locale_of(root));
    std::string tz;
    auto l = root.link("/etc/localtime");
    if (l.ok) tz = lower(l.value.substr(l.value.find("zoneinfo/") == std::string::npos ? 0 : l.value.find("zoneinfo/") + 9));
    bool ok;
    if (tz.empty()) tz = lower(read_value(root, "/etc/timezone", ok));
    std::vector<std::string> hits;
    for (const auto& x : langs)
        if (loc.rfind(x, 0) == 0) hits.push_back("locale " + loc);
    for (const auto& z : zones)
        if (tz == z) hits.push_back("timezone " + tz);
    Json ev = Json::object();
    ev.set("locale", loc);
    ev.set("timezone", tz);
    ev.set("matches", Json(hits));
    return {bool_check(id, name, desc, Severity::Medium, !hits.empty(), ev,
                       "Use a non-CIS locale and time zone for the analysis image.")};
}

std::vector<Finding> running_as_root(Context& ctx) {
    const char* id = "design.running_as_root";
    const char* name = "Sample runs as root";
    const char* desc = "Effective uid 0: sandboxes often start samples as root, desktop users do not.";
    Root root(ctx);
    long long uid = root.uid();
    if (uid < 0) return {skipped(id, name, desc, Severity::Medium, "uid unknown")};
    Json ev = Json::object();
    ev.set("euid", uid);
    return {bool_check(id, name, desc, Severity::Medium, uid == 0, ev, "Run samples as an unprivileged desktop user.")};
}

// ---- analysis tooling ----

std::vector<Finding> tools_running(Context& ctx) {
    const char* id = "design.analysis_tools_running";
    const char* name = "Malware-analysis tooling running";
    const char* desc = "Process names of debuggers, tracers, sniffers, disassemblers, monitors and sandbox agents.";
    Root root(ctx);
    auto e = process_matches(root, tool_names());
    if (!e.observed && e.unavailable) return {error(id, name, desc, Severity::Medium, "cannot read /proc")};
    return {e.finding(id, name, desc, Severity::Medium,
                      "Run analysis tooling outside the guest (CHIMERA: DRAKVUF introspection from dom0).")};
}

std::vector<Finding> tool_cmdline(Context& ctx) {
    const char* id = "design.analysis_tool_cmdline";
    const char* name = "Interpreted analysis tools running";
    const char* desc = "Script-based tools whose process name is the interpreter: argv[0]/argv[1] of agent.py "
                       "(Cuckoo/CAPE agent), analyzer.py, inetsim, fakenet, mitmdump, vol.py, karton.";
    static const std::vector<std::string> names = {"agent.py", "agent.pyw", "analyzer.py", "inetsim", "fakenet",
        "fakenet.py", "mitmdump", "mitmproxy", "mitmweb", "vol.py", "vol", "volatility", "volatility3", "karton-system",
        "drakrun", "frida", "frida-trace", "tracee", "sysdig", "falco"};
    Root root(ctx);
    auto procs = processes(root, true);
    if (!procs.ok) return {unreadable(id, name, desc, Severity::Medium, procs.err, "/proc")};
    Evidence e;
    e.observed = procs.procs.size();
    for (const auto& p : procs.procs)
        for (const auto& n : names)
            if (lower(p.argv1) == n || lower(p.argv0) == n) e.add(n);
    return {e.finding(id, name, desc, Severity::Medium, "Run analysis tooling outside the guest.")};
}

std::vector<Finding> tool_binaries(Context& ctx) {
    const char* id = "design.analysis_tool_binaries";
    const char* name = "Analysis tools installed";
    const char* desc = "Debuggers, tracers, sniffers and instrumentation installed in the standard binary "
                       "directories (strace, ltrace, gdb, tcpdump, tshark, frida-server, radare2, sysdig, bpftrace...).";
    static const std::vector<std::string> bins = {"strace", "ltrace", "gdb", "gdbserver", "tcpdump", "tshark",
        "wireshark", "dumpcap", "mitmproxy", "mitmdump", "frida", "frida-server", "radare2", "r2", "ghidraRun",
        "sysdig", "bpftrace", "falco", "osqueryd", "inetsim", "fakenet", "volatility", "vol", "binwalk", "edb", "rr",
        "valgrind", "ida64", "x64dbg"};
    Root root(ctx);
    Evidence e;
    std::vector<std::string> paths;
    for (const char* d : {"/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/opt/"})
        for (const auto& b : bins) paths.push_back(std::string(d) + b);
    e.paths(root, paths);
    return {e.finding(id, name, desc, Severity::Low, "Do not install analysis tools in the detonation image.", 0.5)};
}

std::vector<Finding> framework_paths(Context& ctx) {
    const char* id = "env.sandbox_framework_paths";
    const char* name = "Known analysis-framework marker paths";
    const char* desc = "Installation and configuration directories of Cuckoo, CAPE, INetSim, FakeNet, DRAKVUF/drakrun "
                       "and Frida left in the guest.";
    Root root(ctx);
    Evidence e;
    // v1 SANDBOX_FRAMEWORK_PATHS first.
    e.paths(root, {"/etc/cuckoo", "/opt/cuckoo", "/etc/inetsim", "/opt/inetsim", "/opt/CAPEv2", "/opt/cape",
                   "/etc/cape", "/tmp/cuckoo", "/tmp/cuckoo-tmp", "/usr/share/inetsim", "/var/lib/inetsim",
                   "/opt/fakenet", "/opt/drakvuf", "/opt/drakrun", "/etc/drakrun", "/var/lib/drakrun", "/opt/frida",
                   "/data/local/tmp/frida-server", "/usr/local/bin/frida-server", "/tmp/analyzer"});
    return {e.finding(id, name, desc, Severity::Medium, "Keep framework files on the host, not in the guest image.")};
}

std::vector<Finding> tool_packages(Context& ctx) {
    const char* id = "design.analysis_tool_packages";
    const char* name = "Analysis tool packages installed";
    const char* desc = "Package database entries of analysis and monitoring tools (names only).";
    static const std::vector<std::string> pkgs = {"strace", "ltrace", "gdb", "gdbserver", "wireshark", "tshark",
        "wireshark-common", "tcpdump", "sysdig", "falco", "osquery", "auditd", "audit", "inetsim", "bpftrace",
        "bpfcc-tools", "radare2", "ghidra", "volatility", "volatility3", "mitmproxy", "binwalk", "valgrind", "rr",
        "edb-debugger", "frida-tools"};
    Root root(ctx);
    auto p = packages(root);
    if (!p.ok) return {skipped(id, name, desc, Severity::Low, "no readable package database")};
    Evidence e;
    e.observed = p.names.size();
    e.partial = p.partial;
    for (const auto& n : p.names)
        if (std::find(pkgs.begin(), pkgs.end(), n) != pkgs.end()) e.add(n);
    return {e.finding(id, name, desc, Severity::Low, "Purge analysis packages from the image.", 0.5)};
}

std::vector<Finding> listening_ports(Context& ctx) {
    const char* id = "design.listening_ports";
    const char* name = "Analysis agent ports listening";
    const char* desc = "TCP listeners in /proc/net/tcp{,6} on ports of analysis agents: 8000 (Cuckoo/CAPE agent.py), "
                       "27042 (frida-server), 5555 (adb), 23946 (IDA remote debug server).";
    static const std::map<long long, std::string> ports = {{8000, "Cuckoo/CAPE agent"}, {27042, "Frida server"},
        {27043, "Frida server"}, {5555, "adb"}, {23946, "IDA remote debugger"}};
    Root root(ctx);
    Evidence e;
    for (const char* f : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        auto r = root.read(f);
        if (!r.ok) { if (r.err != ENOENT) ++e.unavailable; continue; }
        ++e.observed;
        auto ls = lines(r.value);
        for (size_t i = 1; i < ls.size(); ++i) {
            std::vector<std::string> g;
            for (const auto& x : split(trim(ls[i]), ' '))
                if (!x.empty()) g.push_back(x);
            if (g.size() < 4 || g[3] != "0A") continue;  // TCP_LISTEN (include/net/tcp_states.h)
            auto colon = g[1].rfind(':');
            long long port;
            if (colon == std::string::npos || !number(g[1].substr(colon + 1), port, 16)) continue;
            auto it = ports.find(port);
            if (it != ports.end()) e.add(std::to_string(port) + " (" + it->second + ")");
        }
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no /proc/net/tcp")};
    return {e.finding(id, name, desc, Severity::Medium, "Use agentless analysis or move the agent to an unremarkable port.")};
}

std::vector<Finding> core_pattern(Context& ctx) {
    const char* id = "design.core_pattern";
    const char* name = "Crash dumps piped to a collector";
    const char* desc = "kernel.core_pattern pipes core dumps ('|...') to something other than systemd-coredump, "
                       "apport or abrt -- a crash collector of an analysis setup.";
    static const std::vector<std::string> normal = {"systemd-coredump", "apport", "abrt-hook-ccpp", "abrt"};
    Root root(ctx);
    bool ok;
    std::string pat = read_value(root, "/proc/sys/kernel/core_pattern", ok);
    if (!ok) return {skipped(id, name, desc, Severity::Low, "core_pattern not readable")};
    bool pipe = !pat.empty() && pat[0] == '|';
    std::string prog = pipe ? basename(split(pat.substr(1), ' ')[0]) : "";
    bool unusual = pipe && std::find(normal.begin(), normal.end(), prog) == normal.end();
    Json ev = Json::object();
    ev.set("handler", pipe ? prog : "file");
    return {bool_check(id, name, desc, Severity::Low, unusual, ev, "Keep the distribution's core dump handler.")};
}

std::vector<Finding> monitoring_services(Context& ctx) {
    const char* id = "design.monitoring_services";
    const char* name = "Monitoring and EDR services installed";
    const char* desc = "Unit files of audit, monitoring and EDR agents (auditd, falco, osqueryd, Sysmon for Linux, "
                       "Wazuh/OSSEC, Elastic Agent, CrowdStrike falcon-sensor, Defender mdatp, Carbon Black, "
                       "SentinelOne, Velociraptor, Tracee).";
    static const std::vector<std::string> units = {"auditd", "falco", "falco-modern-bpf", "falco-kmod", "osqueryd",
        "sysmon", "wazuh-agent", "ossec", "elastic-agent", "falcon-sensor", "mdatp", "cbagentd", "sentinelone",
        "velociraptor_client", "tracee", "sysdig"};
    Root root(ctx);
    bool ok;
    auto all = unit_files(root, ok);
    if (!ok) return {skipped(id, name, desc, Severity::Low, "no systemd unit directory or init.d")};
    Evidence e;
    e.observed = all.size();
    for (const auto& u : all) {
        std::string base = u.substr(0, u.find('.'));
        if (std::find(units.begin(), units.end(), base) != units.end()) e.add(u);
    }
    return {e.finding(id, name, desc, Severity::Low, "Monitor from outside the guest instead (CHIMERA: DRAKVUF).", 0.5)};
}

// ---- OS configuration ----

bool distro_like(const std::map<std::string, std::string>& osr, const std::vector<std::string>& names) {
    std::string all = lower((osr.count("ID") ? osr.at("ID") : "") + " " + (osr.count("ID_LIKE") ? osr.at("ID_LIKE") : ""));
    for (const auto& n : names)
        if (has_word(all, n)) return true;
    return false;
}

std::vector<Finding> selinux(Context& ctx) {
    const char* id = "design.selinux_state";
    const char* name = "SELinux permissive or disabled";
    const char* desc = "/sys/fs/selinux/enforce is 0, or SELinux is absent on a distribution that enforces it by "
                       "default (RHEL, Fedora, CentOS, Rocky, Alma).";
    Root root(ctx);
    bool ok;
    std::string enf = read_value(root, "/sys/fs/selinux/enforce", ok);
    auto osr = os_release(root);
    Json ev = Json::object();
    ev.set("distribution", osr.count("ID") ? osr["ID"] : "");
    if (ok) {
        ev.set("enforce", enf);
        return {bool_check(id, name, desc, Severity::Low, enf == "0", ev, "Set SELinux to enforcing.")};
    }
    if (distro_like(osr, {"rhel", "fedora", "centos", "rocky", "almalinux"})) {
        ev.set("enforce", "absent");
        return {detected(id, name, desc, Severity::Low, ev, "Re-enable SELinux (SELINUX=enforcing).")};
    }
    return {skipped(id, name, desc, Severity::Low, "SELinux is not this distribution's default LSM")};
}

std::vector<Finding> apparmor(Context& ctx) {
    const char* id = "design.apparmor_state";
    const char* name = "AppArmor disabled";
    const char* desc = "AppArmor is off on Debian/Ubuntu/SUSE, where it is enabled by default.";
    Root root(ctx);
    auto osr = os_release(root);
    if (!distro_like(osr, {"debian", "ubuntu", "suse", "opensuse"}))
        return {skipped(id, name, desc, Severity::Low, "AppArmor is not this distribution's default LSM")};
    bool ok;
    std::string en = read_value(root, "/sys/module/apparmor/parameters/enabled", ok);
    Json ev = Json::object();
    ev.set("enabled", ok ? en : "module absent");
    if (!ok && !root.exists("/sys/module")) return {skipped(id, name, desc, Severity::Low, "no sysfs")};
    return {bool_check(id, name, desc, Severity::Low, !ok || en != "Y", ev, "Keep AppArmor enabled.")};
}

std::vector<Finding> lockdown(Context& ctx) {
    const char* id = "design.kernel_lockdown";
    const char* name = "Kernel lockdown off under Secure Boot";
    const char* desc = "Secure Boot is on but /sys/kernel/security/lockdown is [none] (kernel_lockdown(7)); "
                       "distribution kernels lock down automatically under Secure Boot.";
    Root root(ctx);
    bool ok;
    std::string ld = read_value(root, "/sys/kernel/security/lockdown", ok);
    if (!ok) return {skipped(id, name, desc, Severity::Low, "no lockdown LSM interface")};
    auto sb = root.read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    if (!sb.ok || sb.value.size() < 5) return {skipped(id, name, desc, Severity::Low, "Secure Boot state unknown")};
    bool secure = sb.value[4] == 1;
    bool none = ld.find("[none]") != std::string::npos;
    Json ev = Json::object();
    ev.set("lockdown", ld);
    ev.set("secure_boot", secure);
    return {bool_check(id, name, desc, Severity::Low, secure && none, ev, "Do not disable lockdown on the kernel command line.")};
}

std::vector<Finding> aslr(Context& ctx) {
    const char* id = "design.aslr_disabled";
    const char* name = "ASLR weakened";
    const char* desc = "kernel.randomize_va_space below 2 (sysctl/kernel.rst): analysis machines disable it for "
                       "reproducible addresses.";
    Root root(ctx);
    bool ok;
    long long v;
    std::string s = read_value(root, "/proc/sys/kernel/randomize_va_space", ok);
    if (!ok || !number(s, v)) return {skipped(id, name, desc, Severity::Medium, "randomize_va_space not readable")};
    Json ev = Json::object();
    ev.set("randomize_va_space", v);
    return {bool_check(id, name, desc, Severity::Medium, v < kFullAslr, ev, "Set kernel.randomize_va_space=2.")};
}

std::vector<Finding> ptrace_scope(Context& ctx) {
    const char* id = "design.ptrace_scope";
    const char* name = "Yama ptrace restriction relaxed";
    const char* desc = "kernel.yama.ptrace_scope is 0 on Ubuntu, whose default is 1 (Yama.rst; Ubuntu security "
                       "features): set so debuggers can attach to anything.";
    Root root(ctx);
    bool ok;
    long long v;
    std::string s = read_value(root, "/proc/sys/kernel/yama/ptrace_scope", ok);
    if (!ok || !number(s, v)) return {skipped(id, name, desc, Severity::Low, "Yama not present")};
    auto osr = os_release(root);
    Json ev = Json::object();
    ev.set("ptrace_scope", v);
    if (!distro_like(osr, {"ubuntu"})) {
        ev.set("note", "distribution default is 0");
        return {clean(id, name, desc, Severity::Low, ev)};
    }
    return {bool_check(id, name, desc, Severity::Low, v == 0, ev, "Restore kernel.yama.ptrace_scope=1.")};
}

std::vector<Finding> autologin(Context& ctx) {
    const char* id = "design.autologin";
    const char* name = "Automatic login configured";
    const char* desc = "GDM, LightDM, SDDM or a getty override logs a user in without a password -- how unattended "
                       "analysis images reach a desktop. Reports file and key only.";
    Root root(ctx);
    Evidence e;
    struct Probe {
        const char* file;
        const char* key;
    };
    for (const Probe& p : {Probe{"/etc/gdm3/daemon.conf", "AutomaticLoginEnable"}, {"/etc/gdm3/custom.conf", "AutomaticLoginEnable"},
                           {"/etc/gdm/custom.conf", "AutomaticLoginEnable"}, {"/etc/lightdm/lightdm.conf", "autologin-user"},
                           {"/etc/sddm.conf", "User"}, {"/etc/lxdm/lxdm.conf", "autologin"}}) {
        auto r = root.read(p.file);
        if (!r.ok) continue;
        ++e.observed;
        for (const auto& l : lines(r.value)) {
            std::string t = trim(l);
            if (t.empty() || t[0] == '#' || t[0] == ';') continue;
            auto eq = t.find('=');
            if (eq == std::string::npos || trim(t.substr(0, eq)) != p.key) continue;
            std::string v = lower(trim(t.substr(eq + 1)));
            if (!v.empty() && v != "false" && v != "0") e.add(std::string(p.file) + " " + p.key);
        }
    }
    for (const char* d : {"/etc/systemd/system/getty@tty1.service.d", "/etc/systemd/system/serial-getty@ttyS0.service.d"}) {
        auto l = root.list(d);
        for (const auto& n : l.names) {
            auto r = root.read(std::string(d) + "/" + n);
            if (!r.ok) continue;
            ++e.observed;
            if (r.value.find("--autologin") != std::string::npos) e.add(std::string(d) + "/" + n + " --autologin");
        }
    }
    if (!e.observed) return {clean(id, name, desc, Severity::Low, "no display manager or getty configuration")};
    return {e.finding(id, name, desc, Severity::Low, "Log in through the normal greeter (hidsim can type the password).")};
}

std::vector<Finding> sudo_nopasswd(Context& ctx) {
    const char* id = "design.sudo_nopasswd";
    const char* name = "Password-less sudo";
    const char* desc = "NOPASSWD rules in /etc/sudoers or /etc/sudoers.d (mode 0440, needs root to read).";
    Root root(ctx);
    Evidence e;
    std::vector<std::string> files = {"/etc/sudoers"};
    auto l = root.list("/etc/sudoers.d");
    for (const auto& n : l.names) files.push_back("/etc/sudoers.d/" + n);
    int denied = 0;
    for (const auto& f : files) {
        auto r = root.read(f);
        if (!r.ok) { if (r.err == EACCES || r.err == EPERM) ++denied; continue; }
        ++e.observed;
        for (const auto& line : lines(r.value)) {
            std::string t = trim(line);
            if (!t.empty() && t[0] != '#' && t.find("NOPASSWD") != std::string::npos) { e.add(f); break; }
        }
    }
    if (!e.observed && denied) return {skipped(id, name, desc, Severity::Low, "sudoers needs root")};
    if (!e.observed) return {skipped(id, name, desc, Severity::Low, "sudo not configured")};
    e.partial = denied > 0;
    return {e.finding(id, name, desc, Severity::Low, "Require a password for sudo in the image.")};
}

}  // namespace

PERDEDOR_REGISTER(hostname_or_user, "identity.hostname", "fast", false, "design.suspicious_hostname_or_user");
PERDEDOR_REGISTER(exact_username, "identity.username", "fast", false, "design.exact_sandbox_username");
PERDEDOR_REGISTER(sandbox_hostnames, "identity.hostname", "fast", false, "design.sandbox_hostname_list");
PERDEDOR_REGISTER(live_user_host, "identity.username", "fast", false, "design.linux_user_host");
PERDEDOR_REGISTER(default_hostname, "identity.hostname", "fast", false, "design.default_hostname");
PERDEDOR_REGISTER(ci_hostname, "identity.hostname", "fast", false, "design.ci_runner_hostname");
PERDEDOR_REGISTER(ci_env, "identity.environment_variables", "fast", false, "design.ci_environment");
PERDEDOR_REGISTER(sandbox_env, "identity.environment_variables", "fast", false, "design.sandbox_environment_variables");
PERDEDOR_REGISTER(sample_path, "identity.sample_path", "fast", false, "design.sample_path");
PERDEDOR_REGISTER(sample_name, "identity.sample_path", "fast", false, "design.sample_name");
PERDEDOR_REGISTER(parent_process, "identity.parent_process", "fast", false, "design.parent_process");
PERDEDOR_REGISTER(locale_generic, "identity.locale", "fast", false, "design.locale_generic");
PERDEDOR_REGISTER(cis_locale, "identity.locale", "fast", false, "design.cis_locale_guardrail");
PERDEDOR_REGISTER(running_as_root, "os_config.uac_sip", "fast", false, "design.running_as_root");
PERDEDOR_REGISTER(tools_running, "analysis_tools.processes", "fast", false, "design.analysis_tools_running");
PERDEDOR_REGISTER(tool_cmdline, "analysis_tools.processes", "fast", false, "design.analysis_tool_cmdline");
PERDEDOR_REGISTER(tool_binaries, "analysis_tools.files", "fast", false, "design.analysis_tool_binaries");
PERDEDOR_REGISTER(framework_paths, "analysis_tools.files", "fast", false, "env.sandbox_framework_paths");
PERDEDOR_REGISTER(tool_packages, "analysis_tools.files", "fast", false, "design.analysis_tool_packages");
PERDEDOR_REGISTER(listening_ports, "analysis_tools.listening_ports", "fast", false, "design.listening_ports");
PERDEDOR_REGISTER(core_pattern, "analysis_tools.drivers_services", "fast", false, "design.core_pattern");
PERDEDOR_REGISTER(monitoring_services, "analysis_tools.drivers_services", "fast", false, "design.monitoring_services");
PERDEDOR_REGISTER(selinux, "integrity.selinux", "fast", false, "design.selinux_state");
PERDEDOR_REGISTER(apparmor, "os_config.uac_sip", "fast", false, "design.apparmor_state");
PERDEDOR_REGISTER(lockdown, "os_config.uac_sip", "fast", false, "design.kernel_lockdown");
PERDEDOR_REGISTER(aslr, "os_config.uac_sip", "fast", false, "design.aslr_disabled");
PERDEDOR_REGISTER(ptrace_scope, "os_config.uac_sip", "fast", false, "design.ptrace_scope");
PERDEDOR_REGISTER(autologin, "os_config.uac_sip", "fast", false, "design.autologin");
PERDEDOR_REGISTER(sudo_nopasswd, "os_config.uac_sip", "fast", false, "design.sudo_nopasswd");

}  // namespace perdedor
