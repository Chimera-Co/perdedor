// Containers, application sandboxes, WSL and the OS's own virtualisation
// report.
//
// Sources: systemd src/basic/virt.c (detect_container, detect_container_files,
// running_in_pidns, detect_vm order), virt-what 1.27, VMAware v2.8.2
// (DOCKERENV, PODMAN_FILE, CGROUP, CONTAINER_PID, WSL_PROC), Linux
// include/linux/proc_ns.h, Docker default capability set
// (moby oci/caps/defaults.go), gVisor pkg/sentry/kernel/version/version.go,
// Flatpak sandbox documentation (/.flatpak-info).
#include <cerrno>
#include <cstdint>
#include <cstring>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

// include/linux/proc_ns.h: inode numbers of the initial namespaces (fixed since Linux 3.8).
constexpr unsigned long long kInitIpc = 0xEFFFFFFFULL, kInitUts = 0xEFFFFFFEULL, kInitUser = 0xEFFFFFFDULL,
                             kInitPid = 0xEFFFFFFCULL, kInitCgroup = 0xEFFFFFFBULL;
// moby/moby oci/caps/defaults.go DefaultCapabilities: CHOWN DAC_OVERRIDE FSETID FOWNER MKNOD NET_RAW SETGID
// SETUID SETFCAP SETPCAP NET_BIND_SERVICE SYS_CHROOT KILL AUDIT_WRITE = bounding set 0x00000000a80425fb.
constexpr unsigned long long kDockerDefaultCaps = 0xa80425fbULL;
// gVisor pkg/sentry/kernel/version/version.go: LinuxVersion.
const char* kGvisorVersion = "#1 SMP Sun Jan 10 15:06:54 PST 2016";

std::vector<Finding> container_or_wsl(Context& ctx) {
    const char* id = "env.container_or_wsl";
    const char* name = "Container/WSL execution environment";
    const char* desc = "Checks for /.dockerenv, cgroup container markers in /proc/1/cgroup and WSL's kernel version.";
    Root root(ctx);
    Evidence e;
    e.observed = 1;
    if (root.exists("/.dockerenv")) e.add("/.dockerenv present");
    auto cg = root.read("/proc/1/cgroup");
    if (cg.ok && !match(cg.value, {"docker", "lxc", "kubepods"}).empty()) e.add("container marker in /proc/1/cgroup");
    auto v = root.read("/proc/version");
    if (!v.ok && !cg.ok) return {unreadable(id, name, desc, Severity::Medium, v.err, "/proc/version")};
    if (v.ok && !match(v.value, {"microsoft", "wsl"}).empty()) e.add("/proc/version=" + trim(v.value).substr(0, 80));
    return {e.finding(id, name, desc, Severity::Medium,
                      "Detonate inside a full VM guest, not a container or WSL.")};
}

std::vector<Finding> path_marker(Context& ctx, const char* id, const char* name, const char* desc,
                                 const std::vector<std::string>& paths, const char* fix) {
    Root root(ctx);
    if (!root.exists("/proc/version") && !root.exists("/etc")) return {skipped(id, name, desc, Severity::High, "empty root")};
    Evidence e;
    e.paths(root, paths);
    return {e.finding(id, name, desc, Severity::High, fix)};
}

std::vector<Finding> dockerenv(Context& ctx) {
    return path_marker(ctx, "env.dockerenv", "Docker marker files",
                       "/.dockerenv or /.dockerinit at the root (VMAware DOCKERENV, virt-what, systemd).",
                       {"/.dockerenv", "/.dockerinit"}, "Do not run samples in a Docker container.");
}

std::vector<Finding> containerenv(Context& ctx) {
    return path_marker(ctx, "env.podman_containerenv", "Podman/Buildah marker file",
                       "/run/.containerenv (VMAware PODMAN_FILE, systemd detect_container_files).",
                       {"/run/.containerenv"}, "Do not run samples in a Podman container.");
}

std::vector<Finding> cgroup(Context& ctx) {
    const char* id = "env.cgroup_container";
    const char* name = "Container cgroup path";
    const char* desc = "/proc/self/cgroup naming docker, containerd, kubepods, lxc, libpod, a 64-hex container id, "
                       "or a cgroup-namespace root '0::/' (VMAware CGROUP, virt-what).";
    Root root(ctx);
    auto r = root.read("/proc/self/cgroup");
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/proc/self/cgroup")};
    Evidence e;
    ++e.observed;
    static const std::vector<std::string> sigs = {"docker", "containerd", "kubepods", "/lxc", "libpod-", "machine.slice",
        "garden", "actions_job"};
    for (const auto& line : lines(r.value)) {
        std::string l = trim(line);
        if (l.empty()) continue;
        std::string hit = match(l, sigs);
        if (!hit.empty()) e.add(hit);
        for (const auto& part : split(l.substr(l.rfind(':') + 1), '/'))
            if (part.size() >= 64 && hex_string(part.substr(part.size() - 64))) e.add("64-hex container id");
        if (l == "0::/") e.add("cgroup namespace root 0::/");
    }
    return {e.finding(id, name, desc, Severity::High, "Run samples in a full VM guest, not a container.")};
}

std::vector<Finding> container_pid1(Context& ctx) {
    const char* id = "env.container_pid1";
    const char* name = "PID 1 is not an init system";
    const char* desc = "In containers PID 1 is the application or a tiny init (sh, tini, dumb-init, node...) and a "
                       "process may itself be PID 1 with parent 0 (VMAware CONTAINER_PID).";
    static const std::vector<std::string> inits = {"systemd", "init", "openrc-init", "runit", "runit-init",
        "busybox", "s6-svscan", "upstart", "launchd", "sysvinit"};
    Root root(ctx);
    Proc self, one;
    bool have_self = process(root, "self", self);
    if (!process(root, "1", one)) return {skipped(id, name, desc, Severity::High, "cannot read /proc/1")};
    Evidence e;
    e.observed = 1;
    bool init = false;
    for (const auto& i : inits)
        if (one.comm == i || one.argv0 == i) init = true;
    if (!init) e.add("pid1=" + one.comm);
    if (have_self && self.pid == "self") {
        auto st = root.read("/proc/self/status");
        if (st.ok) {
            auto f = fields(st.value);
            if (f["Pid"] == "1" && f["PPid"] == "0") e.add("this process is PID 1");
        }
    }
    return {e.finding(id, name, desc, Severity::High, "Run samples on a full OS with a normal init.")};
}

std::vector<Finding> container_manager(Context& ctx) {
    const char* id = "env.container_manager_marker";
    const char* name = "Container manager declaration";
    const char* desc = "/run/systemd/container, /run/host/container-manager or a 'container=' variable in this "
                       "process's or PID 1's environment (systemd detect_container, virt-what lxc/podman/oci).";
    Root root(ctx);
    Evidence e;
    e.observed = 1;
    bool ok;
    for (const char* f : {"/run/systemd/container", "/run/host/container-manager"}) {
        std::string v = read_value(root, f, ok);
        if (ok && !v.empty()) e.add(std::string(f) + "=" + v.substr(0, 30));
    }
    auto env = root.environment();
    if (env.count("container") && !env["container"].empty()) e.add("container=" + env["container"].substr(0, 30));
    auto one = root.read("/proc/1/environ");
    if (one.ok)
        for (const auto& kv : split(one.value, '\0'))
            if (kv.rfind("container=", 0) == 0 && kv.size() > 10) e.add("pid1 " + kv.substr(0, 40));
    return {e.finding(id, name, desc, Severity::High, "Run samples on a full OS, not in a container.")};
}

std::vector<Finding> overlay_root(Context& ctx) {
    const char* id = "env.overlay_root";
    const char* name = "Container root filesystem";
    const char* desc = "The root mount in /proc/self/mountinfo is overlayfs, aufs, fuse-overlayfs or shiftfs -- "
                       "container image layers, not a disk partition.";
    Root root(ctx);
    auto r = root.read("/proc/self/mountinfo");
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/proc/self/mountinfo")};
    std::string fstype;
    for (const auto& line : lines(r.value)) {
        // proc(5): fields ... mount point (5th) ... " - " fstype source options.
        auto f = split(line, ' ');
        auto dash = line.find(" - ");
        if (f.size() < 5 || dash == std::string::npos || f[4] != "/") continue;
        fstype = split(line.substr(dash + 3), ' ')[0];
    }
    if (fstype.empty()) return {error(id, name, desc, Severity::High, "no root mount in mountinfo")};
    bool hit = fstype == "overlay" || fstype == "aufs" || fstype == "fuse-overlayfs" || fstype == "shiftfs" ||
               fstype == "fuse.fuse-overlayfs";
    Json ev = Json::object();
    ev.set("root_fstype", fstype);
    return {bool_check(id, name, desc, Severity::High, hit, ev, "Run samples from a real disk-backed root.")};
}

unsigned long long ns_inode(const Root& root, const std::string& ns, bool& ok) {
    auto l = root.link("/proc/self/ns/" + ns);
    ok = false;
    if (!l.ok) return 0;
    auto a = l.value.find('['), b = l.value.find(']');
    long long n;
    if (a == std::string::npos || b == std::string::npos || !number(l.value.substr(a + 1, b - a - 1), n)) return 0;
    ok = true;
    return static_cast<unsigned long long>(n);
}

Finding ns_check(Context& ctx, const char* id, const char* name, const char* desc,
                 const std::vector<std::pair<std::string, unsigned long long>>& wanted, const char* fix) {
    Root root(ctx);
    Evidence e;
    for (const auto& w : wanted) {
        bool ok;
        unsigned long long ino = ns_inode(root, w.first, ok);
        if (!ok) { ++e.unavailable; continue; }
        ++e.observed;
        if (ino != w.second) e.add(w.first + ":[" + std::to_string(ino) + "]");
    }
    if (!e.observed) return skipped(id, name, desc, Severity::Medium, "/proc/self/ns not readable");
    Finding f = e.finding(id, name, desc, Severity::Medium, fix);
    return f;
}

std::vector<Finding> pid_ns(Context& ctx) {
    return {ns_check(ctx, "env.pid_namespace", "Non-initial PID namespace",
                     "/proc/self/ns/pid differs from the initial PID namespace inode 0xEFFFFFFC (systemd "
                     "running_in_pidns): containers and sandboxes such as bwrap, firejail and nsjail.",
                     {{"pid", kInitPid}}, "Run samples in the initial PID namespace of a full VM.")};
}

std::vector<Finding> user_ns(Context& ctx) {
    return {ns_check(ctx, "env.user_namespace", "Non-initial user namespace",
                     "/proc/self/ns/user differs from the initial user namespace 0xEFFFFFFD: rootless containers, "
                     "Flatpak/bwrap and browser sandboxes.",
                     {{"user", kInitUser}}, "Run samples outside user-namespace sandboxes.")};
}

std::vector<Finding> other_ns(Context& ctx) {
    return {ns_check(ctx, "env.uts_ipc_cgroup_namespace", "Non-initial UTS/IPC/cgroup namespaces",
                     "UTS (0xEFFFFFFE), IPC (0xEFFFFFFF) or cgroup (0xEFFFFFFB) namespace differs from the initial "
                     "one (include/linux/proc_ns.h).",
                     {{"uts", kInitUts}, {"ipc", kInitIpc}, {"cgroup", kInitCgroup}},
                     "Run samples in the initial namespaces.")};
}

std::vector<Finding> capabilities(Context& ctx) {
    const char* id = "env.capability_bounding_set";
    const char* name = "Reduced capability bounding set";
    const char* desc = "CapBnd in /proc/self/status lacks capabilities a normal session keeps (all up to "
                       "cap_last_cap); Docker's default set is exactly 0xa80425fb.";
    Root root(ctx);
    auto st = root.read("/proc/self/status");
    if (!st.ok) return {unreadable(id, name, desc, Severity::Medium, st.err, "/proc/self/status")};
    auto f = fields(st.value);
    long long bnd;
    if (!f.count("CapBnd") || !number(f["CapBnd"], bnd, 16))
        return {error(id, name, desc, Severity::Medium, "no CapBnd in status")};
    bool ok;
    long long last = 0;
    std::string lc = read_value(root, "/proc/sys/kernel/cap_last_cap", ok);
    if (!ok || !number(lc, last) || last < 0 || last > 63) last = 40;  // CAP_CHECKPOINT_RESTORE, Linux 5.9+
    unsigned long long full = last >= 63 ? ~0ULL : ((1ULL << (last + 1)) - 1);
    unsigned long long b = static_cast<unsigned long long>(bnd);
    Json ev = Json::object();
    ev.set("CapBnd", f["CapBnd"]);
    ev.set("cap_last_cap", last);
    if (b == kDockerDefaultCaps) ev.set("profile", "docker default");
    return {bool_check(id, name, desc, Severity::Medium, (b & full) != full, ev,
                       "Run samples with the full bounding set of an ordinary login session.")};
}

std::vector<Finding> seccomp(Context& ctx) {
    const char* id = "env.seccomp_filter";
    const char* name = "Seccomp filter on the process";
    const char* desc = "Seccomp: 2 in /proc/self/status: a syscall filter installed by a container runtime or "
                       "sandbox (Docker, Flatpak/bwrap, firejail, nsjail, systemd SystemCallFilter).";
    Root root(ctx);
    auto st = root.read("/proc/self/status");
    if (!st.ok) return {unreadable(id, name, desc, Severity::Medium, st.err, "/proc/self/status")};
    auto f = fields(st.value);
    if (!f.count("Seccomp")) return {skipped(id, name, desc, Severity::Medium, "kernel without seccomp status")};
    Json ev = Json::object();
    ev.set("Seccomp", f["Seccomp"]);
    if (f.count("NoNewPrivs")) ev.set("NoNewPrivs", f["NoNewPrivs"]);
    return {bool_check(id, name, desc, Severity::Medium, f["Seccomp"] == "2", ev,
                       "Start samples from a normal session without a seccomp filter.")};
}

std::vector<Finding> wsl_kernel(Context& ctx) {
    const char* id = "env.wsl_kernel";
    const char* name = "WSL kernel";
    const char* desc = "/proc/sys/kernel/osrelease and /proc/version name Microsoft/WSL (VMAware WSL_PROC, systemd "
                       "detect_container).";
    Root root(ctx);
    bool a, b;
    std::string rel = read_value(root, "/proc/sys/kernel/osrelease", a), ver = read_value(root, "/proc/version", b);
    if (!a && !b) return {skipped(id, name, desc, Severity::High, "no kernel version files")};
    bool hit = (rel.find("Microsoft") != std::string::npos || rel.find("WSL") != std::string::npos ||
                rel.find("microsoft") != std::string::npos);
    Json ev = Json::object();
    ev.set("osrelease", rel.substr(0, 80));
    return {bool_check(id, name, desc, Severity::High, hit, ev, "Analyse Linux samples in a Linux VM, not WSL.")};
}

std::vector<Finding> wsl_interop(Context& ctx) {
    const char* id = "env.wsl_interop";
    const char* name = "WSL interop artifacts";
    const char* desc = "WSL binfmt interop entry, /run/WSL, /mnt/wsl, /usr/lib/wsl and the WSL_DISTRO_NAME / "
                       "WSL_INTEROP variables.";
    Root root(ctx);
    Evidence e;
    e.paths(root, {"/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late", "/run/WSL",
                   "/mnt/wsl", "/usr/lib/wsl", "/init"});
    // /init exists on many initramfs-less images too; only count it together with another marker.
    bool init_only = e.hits.size() == 1 && e.hits[0] == "/init";
    if (init_only) e.hits.clear();
    auto env = root.environment();
    for (const char* k : {"WSL_DISTRO_NAME", "WSL_INTEROP", "WSLENV"})
        if (env.count(k)) e.add(std::string("env ") + k);
    return {e.finding(id, name, desc, Severity::High, "Analyse Linux samples in a Linux VM, not WSL.")};
}

std::vector<Finding> gvisor(Context& ctx) {
    const char* id = "env.gvisor";
    const char* name = "gVisor sandbox kernel";
    const char* desc = "gVisor's Sentry reports a fixed kernel version '#1 SMP Sun Jan 10 15:06:54 PST 2016' and a "
                       "'-gvisor' release (pkg/sentry/kernel/version/version.go).";
    Root root(ctx);
    bool a, b;
    std::string ver = read_value(root, "/proc/version", a), rel = read_value(root, "/proc/sys/kernel/osrelease", b);
    if (!a && !b) return {skipped(id, name, desc, Severity::High, "no kernel version files")};
    bool hit = ver.find(kGvisorVersion) != std::string::npos || rel.find("-gvisor") != std::string::npos;
    Json ev = Json::object();
    ev.set("osrelease", rel.substr(0, 60));
    return {bool_check(id, name, desc, Severity::High, hit, ev, "Do not use gVisor as the detonation environment.")};
}

std::vector<Finding> app_sandbox(Context& ctx) {
    const char* id = "env.app_sandbox_markers";
    const char* name = "Application sandbox markers";
    const char* desc = "Flatpak (/.flatpak-info, FLATPAK_ID), Snap (SNAP, SNAP_NAME), firejail, bubblewrap or "
                       "nsjail as PID 1 or parent, /run/firejail.";
    Root root(ctx);
    Evidence e;
    e.paths(root, {"/.flatpak-info", "/run/firejail/sandbox", "/run/firejail/mnt"});
    auto env = root.environment();
    for (const char* k : {"FLATPAK_ID", "SNAP", "SNAP_NAME", "FIREJAIL", "container_ttys"})
        if (env.count(k)) e.add(std::string("env ") + k);
    Proc one, self;
    static const std::vector<std::string> launchers = {"firejail", "bwrap", "nsjail", "minijail0", "sandbox-exec"};
    if (process(root, "1", one))
        for (const auto& l : launchers)
            if (one.comm == l) e.add("pid1=" + l);
    if (process(root, "self", self) && self.ppid > 0) {
        Proc parent;
        if (process(root, std::to_string(self.ppid), parent))
            for (const auto& l : launchers)
                if (parent.comm == l) e.add("parent=" + l);
    }
    return {e.finding(id, name, desc, Severity::High, "Start samples outside application sandboxes.")};
}

std::vector<Finding> kubernetes(Context& ctx) {
    const char* id = "env.kubernetes_pod";
    const char* name = "Kubernetes pod";
    const char* desc = "KUBERNETES_SERVICE_HOST in the environment or a mounted service-account token directory.";
    Root root(ctx);
    Evidence e;
    e.paths(root, {"/var/run/secrets/kubernetes.io/serviceaccount", "/run/secrets/kubernetes.io/serviceaccount"});
    auto env = root.environment();
    if (env.count("KUBERNETES_SERVICE_HOST")) e.add("env KUBERNETES_SERVICE_HOST");
    return {e.finding(id, name, desc, Severity::High, "Do not detonate in Kubernetes pods.")};
}

std::vector<Finding> openvz(Context& ctx) {
    const char* id = "env.openvz";
    const char* name = "OpenVZ/Virtuozzo container";
    const char* desc = "/proc/vz exists but /proc/bc does not (inside a container; systemd detect_container, "
                       "virt-what openvz, VMAware PROCESSES).";
    Root root(ctx);
    if (!root.exists("/proc/version")) return {skipped(id, name, desc, Severity::High, "no procfs")};
    bool vz = root.exists("/proc/vz"), bc = root.exists("/proc/bc");
    Json ev = Json::object();
    ev.set("proc_vz", vz);
    ev.set("proc_bc", bc);
    return {bool_check(id, name, desc, Severity::High, vz && !bc, ev, "Do not detonate in OpenVZ containers.")};
}

std::vector<Finding> chroot_check(Context& ctx) {
    const char* id = "env.chroot";
    const char* name = "Running in a chroot";
    const char* desc = "/proc/1/root differs from / (systemd running_in_chroot); needs access to PID 1.";
    Root root(ctx);
    if (root.fixture()) return {skipped(id, name, desc, Severity::Medium, "not meaningful for an alternate root")};
    auto a = root.stat("/proc/1/root/"), b = root.stat("/");
    if (!a.ok) return {unreadable(id, name, desc, Severity::Medium, a.err, "/proc/1/root")};
    bool differs = a.st.st_dev != b.st.st_dev || a.st.st_ino != b.st.st_ino;
    return {bool_check(id, name, desc, Severity::Medium, differs, differs ? "root differs from PID 1" : "same root",
                       "Run samples in the system root, not a chroot.")};
}

std::vector<Finding> systemd_detect_virt(Context& ctx) {
    const char* id = "env.systemd_detect_virt";
    const char* name = "systemd-detect-virt";
    const char* desc = "Runs systemd's own virtualisation detector (read-only, no arguments) where it is installed "
                       "(VMAware SYSTEMD).";
    Root root(ctx);
    if (root.fixture()) return {skipped(id, name, desc, Severity::High, "programs are not run against an alternate root")};
    Read out;
    for (const char* p : {"/usr/bin/systemd-detect-virt", "/bin/systemd-detect-virt"}) {
        out = root.command({p});
        if (out.ok || out.err != ENOENT) break;
    }
    if (!out.ok) {
        if (out.err == ENOENT) return {skipped(id, name, desc, Severity::High, "systemd-detect-virt not installed")};
        return {error(id, name, desc, Severity::High, std::string("systemd-detect-virt failed: ") + std::strerror(out.err))};
    }
    std::string v = trim(out.value);
    return {bool_check(id, name, desc, Severity::High, !v.empty() && v != "none", v,
                       "systemd identifies the platform; fix the CPUID/DMI/device findings it relies on.")};
}

std::vector<Finding> native_detect_virt(Context& ctx) {
    const char* id = "env.virtualisation_self_report";
    const char* name = "OS-level virtualisation verdict";
    const char* desc = "Re-implements systemd's detect_virtualization order without running a program: DMI vendor "
                       "table, /sys/hypervisor/type, /proc/xen, UML, /proc/sysinfo, then container files.";
    // systemd v257 detect_vm_dmi_vendor: prefix match of these files against dmi_vendor_table.
    static const std::vector<std::pair<std::string, std::string>> table = {{"KVM", "kvm"}, {"OpenStack", "kvm"},
        {"KubeVirt", "kvm"}, {"Alibaba Cloud ECS", "kvm"}, {"Amazon EC2", "amazon"}, {"QEMU", "qemu"},
        {"VMware", "vmware"}, {"VMW", "vmware"}, {"innotek GmbH", "oracle"}, {"VirtualBox", "oracle"},
        {"Oracle Corporation", "oracle"}, {"Xen", "xen"}, {"Bochs", "bochs"}, {"Parallels", "parallels"},
        {"BHYVE", "bhyve"}, {"Hyper-V", "microsoft"}, {"Apple Virtualization", "apple"},
        {"Google Compute Engine", "google"}};
    Root root(ctx);
    std::string verdict, source;
    for (const char* f : {"product_name", "sys_vendor", "board_vendor", "bios_vendor", "product_version"}) {
        bool ok;
        std::string v = read_value(root, std::string("/sys/class/dmi/id/") + f, ok);
        if (!ok) continue;
        for (const auto& t : table)
            if (v.rfind(t.first, 0) == 0 && verdict.empty()) { verdict = t.second; source = std::string("dmi ") + f; }
    }
    bool ok;
    if (verdict.empty()) {
        std::string hv = read_value(root, "/sys/hypervisor/type", ok);
        if (ok && hv == "xen") { verdict = "xen"; source = "/sys/hypervisor/type"; }
    }
    if (verdict.empty() && root.exists("/proc/xen")) { verdict = "xen"; source = "/proc/xen"; }
    if (verdict.empty()) {
        auto ci = root.read("/proc/cpuinfo");
        if (ci.ok && ci.value.find("User Mode Linux") != std::string::npos) { verdict = "uml"; source = "cpuinfo"; }
    }
    if (verdict.empty()) {
        auto si = root.read("/proc/sysinfo");
        if (si.ok && si.value.find("VM00 Control Program") != std::string::npos) { verdict = "zvm"; source = "sysinfo"; }
    }
    if (verdict.empty()) {
        if (root.exists("/proc/vz") && !root.exists("/proc/bc")) { verdict = "openvz"; source = "/proc/vz"; }
        else if (read_value(root, "/proc/sys/kernel/osrelease", ok).find("WSL") != std::string::npos) {
            verdict = "wsl";
            source = "osrelease";
        } else if (root.exists("/run/.containerenv")) { verdict = "podman"; source = "/run/.containerenv"; }
        else if (root.exists("/.dockerenv")) { verdict = "docker"; source = "/.dockerenv"; }
    }
    if (!root.exists("/sys") && !root.exists("/proc/version"))
        return {skipped(id, name, desc, Severity::High, "neither sysfs nor procfs readable")};
    Json ev = Json::object();
    ev.set("virtualization", verdict.empty() ? "none" : verdict);
    if (!source.empty()) ev.set("source", source);
    return {bool_check(id, name, desc, Severity::High, !verdict.empty(), ev,
                       "Fix the source named in the evidence; systemd and many samples apply the same order.")};
}

}  // namespace

PERDEDOR_REGISTER(container_or_wsl, "container.container_runtime", "fast", false, "env.container_or_wsl");
PERDEDOR_REGISTER(dockerenv, "container.container_runtime", "fast", false, "env.dockerenv");
PERDEDOR_REGISTER(containerenv, "container.container_runtime", "fast", false, "env.podman_containerenv");
PERDEDOR_REGISTER(cgroup, "container.container_runtime", "fast", false, "env.cgroup_container");
PERDEDOR_REGISTER(container_pid1, "container.container_runtime", "fast", false, "env.container_pid1");
PERDEDOR_REGISTER(container_manager, "container.container_runtime", "fast", false, "env.container_manager_marker");
PERDEDOR_REGISTER(overlay_root, "container.container_runtime", "fast", false, "env.overlay_root");
PERDEDOR_REGISTER(pid_ns, "container.container_runtime", "fast", false, "env.pid_namespace");
PERDEDOR_REGISTER(user_ns, "container.app_sandbox", "fast", false, "env.user_namespace");
PERDEDOR_REGISTER(other_ns, "container.container_runtime", "fast", false, "env.uts_ipc_cgroup_namespace");
PERDEDOR_REGISTER(capabilities, "container.container_runtime", "fast", false, "env.capability_bounding_set");
PERDEDOR_REGISTER(seccomp, "container.app_sandbox", "fast", false, "env.seccomp_filter");
PERDEDOR_REGISTER(wsl_kernel, "container.wsl", "fast", false, "env.wsl_kernel");
PERDEDOR_REGISTER(wsl_interop, "container.wsl", "fast", false, "env.wsl_interop");
PERDEDOR_REGISTER(gvisor, "container.app_sandbox", "fast", false, "env.gvisor");
PERDEDOR_REGISTER(app_sandbox, "container.app_sandbox", "fast", false, "env.app_sandbox_markers");
PERDEDOR_REGISTER(kubernetes, "container.container_runtime", "fast", false, "env.kubernetes_pod");
PERDEDOR_REGISTER(openvz, "container.container_runtime", "fast", false, "env.openvz");
PERDEDOR_REGISTER(chroot_check, "container.app_sandbox", "fast", false, "env.chroot");
PERDEDOR_REGISTER(systemd_detect_virt, "container.virtualisation_report", "fast", false, "env.systemd_detect_virt");
PERDEDOR_REGISTER(native_detect_virt, "container.virtualisation_report", "fast", false,
                  "env.virtualisation_self_report");

}  // namespace perdedor
