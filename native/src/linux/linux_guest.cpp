// Guest tools, paravirtual drivers and hypervisor artifacts on Linux: kernel
// modules, guest buses, agent binaries/processes/services/packages, kernel and
// boot logs, kernel command line, /sys/hypervisor, /proc/xen, device nodes,
// QEMU fw_cfg, /proc/ioports, hypervisor files.
//
// Sources: v1 Linux agent signatures.py; VMAware v2.8.2 (VBOX_MODULE,
// PROCESSES, KMSG, DMESG, SYSINFO_PROC, HYPERVISOR_DIR, QEMU_FW_CFG,
// BLUESTACKS_FOLDERS); systemd src/basic/virt.c (detect_vm_xen,
// detect_vm_xen_dom0, detect_vm_hypervisor, detect_vm_zvm); virt-what 1.27.
#include <cerrno>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

// Kernel log bytes read per source; the boot banner (hypervisor detection, DMI line) is in the first few KiB.
constexpr size_t kLogLimit = 512 * 1024;

std::vector<Finding> kernel_modules(Context& ctx) {
    const char* id = "env.guest_kernel_modules";
    const char* name = "Loaded guest-integration kernel modules";
    const char* desc = "Reads /proc/modules for virtio/VirtualBox/VMware/Xen/Hyper-V paravirtualised driver modules "
                       "(VMAware VBOX_MODULE).";
    // v1 GUEST_KERNEL_MODULES prefixes.
    static const std::vector<std::pair<std::string, std::string>> prefixes = {
        {"virtio", "virtio"}, {"vboxguest", "VirtualBox Guest Additions"}, {"vboxsf", "VirtualBox shared folders"},
        {"vboxvideo", "VirtualBox video"}, {"vmwgfx", "VMware SVGA"}, {"vmw_balloon", "VMware balloon"},
        {"vmw_vmci", "VMware VMCI"}, {"vmw_vsock", "VMware VSOCK"}, {"xen_", "Xen PV drivers"},
        {"hv_", "Hyper-V"}, {"hyperv_", "Hyper-V"}, {"qemu_fw_cfg", "QEMU fw_cfg"}, {"vmxnet", "VMware vmxnet"},
        {"vmw_pvscsi", "VMware PVSCSI"}, {"prl_", "Parallels Tools"}};
    Root root(ctx);
    auto r = root.read("/proc/modules");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Medium, r.err, "/proc/modules")};
    Evidence e;
    ++e.observed;
    for (const auto& line : lines(r.value)) {
        std::string mod = split(trim(line), ' ')[0];
        for (const auto& p : prefixes)
            if (!mod.empty() && mod.rfind(p.first, 0) == 0) e.add(mod + " (" + p.second + ")");
    }
    return {e.finding(id, name, desc, Severity::Medium,
                      "Blacklist paravirtual guest modules in the golden image (Xen HVM: xen_platform_pci=0 keeps "
                      "the PV frontends from binding).")};
}

std::vector<Finding> guest_buses(Context& ctx) {
    const char* id = "env.guest_driver_buses";
    const char* name = "Paravirtual device buses";
    const char* desc = "Devices on the virtio, xen or vmbus buses in /sys/bus (catches built-in drivers that "
                       "/proc/modules does not list; virt-what: /sys/bus/xen without xen-backend = Xen HVM guest).";
    Root root(ctx);
    if (!root.exists("/sys/bus")) return {skipped(id, name, desc, Severity::High, "no /sys/bus")};
    Evidence e;
    e.observed = 1;
    for (const char* bus : {"virtio", "xen", "vmbus"}) {
        auto l = root.list(std::string("/sys/bus/") + bus + "/devices");
        if (l.ok && !l.names.empty())
            e.add(std::string(bus) + ": " + std::to_string(l.names.size()) + " devices (" + l.names[0] + ")");
    }
    if (root.exists("/sys/bus/xen") && !root.exists("/sys/bus/xen-backend")) e.add("xen bus without xen-backend");
    return {e.finding(id, name, desc, Severity::High,
                      "Do not expose paravirtual buses to the guest (Xen: xen_platform_pci=0, no vif/vbd frontends).")};
}

std::vector<Finding> agent_binaries(Context& ctx) {
    const char* id = "env.guest_agent_binaries";
    const char* name = "Guest-integration agent binaries on disk";
    const char* desc = "Checks for qemu-ga/VBoxService/vmtoolsd/xe-daemon/spice-vdagent/hv_kvp_daemon/waagent "
                       "binaries, whose presence alone identifies a VM guest.";
    Root root(ctx);
    Evidence e;
    // v1 GUEST_AGENT_PATHS first, then the other guest agents named in the brief.
    e.paths(root, {"/usr/bin/qemu-ga", "/usr/sbin/VBoxService", "/usr/bin/VBoxClient", "/usr/bin/vmtoolsd",
                   "/usr/bin/vmware-toolbox-cmd", "/usr/bin/open-vm-tools", "/usr/sbin/qemu-ga",
                   "/usr/sbin/xe-daemon", "/usr/bin/spice-vdagent", "/usr/sbin/spice-vdagentd", "/usr/sbin/hv_kvp_daemon",
                   "/usr/sbin/hv_vss_daemon", "/usr/sbin/hv_fcopy_daemon", "/usr/sbin/waagent", "/usr/bin/prltoolsd",
                   "/usr/bin/vmhgfs-fuse", "/usr/bin/VBoxControl", "/usr/sbin/mount.vboxsf"});
    return {e.finding(id, name, desc, Severity::Medium,
                      "Uninstall guest-integration packages (qemu-guest-agent, open-vm-tools, virtualbox-guest-utils, "
                      "xe-guest-utilities) from the golden image.")};
}

std::vector<Finding> agent_processes(Context& ctx) {
    const char* id = "env.guest_tool_processes";
    const char* name = "Guest-tool processes";
    const char* desc = "Running guest agents (qemu-ga -- VMAware PROCESSES --, vmtoolsd, VBoxService, VBoxClient, "
                       "xe-daemon, spice-vdagent, hv_kvp_daemon, waagent, prltoolsd).";
    Root root(ctx);
    auto e = process_matches(root, guest_names());
    if (!e.observed && e.unavailable) return {error(id, name, desc, Severity::High, "cannot read /proc")};
    // waagent runs under python; its argv[1] carries the name.
    auto procs = processes(root, true);
    for (const auto& p : procs.procs)
        if (lower(p.argv1) == "waagent" || lower(p.argv0) == "waagent") e.add("waagent");
    return {e.finding(id, name, desc, Severity::High, "Remove guest agents from the image; do not start them.")};
}

const std::vector<std::string>& guest_units() {
    static const std::vector<std::string> s = {"qemu-guest-agent", "open-vm-tools", "vmtoolsd", "vboxadd",
        "vboxadd-service", "vboxservice", "virtualbox-guest-utils", "xe-daemon", "xe-linux-distribution",
        "xenstored", "spice-vdagentd", "spice-vdagent", "hv-kvp-daemon", "hv_kvp_daemon", "hv-vss-daemon",
        "hv-fcopy-daemon", "hypervkvpd", "hypervvssd", "walinuxagent", "waagent", "cloud-init", "cloud-config",
        "cloud-final", "google-guest-agent", "amazon-ssm-agent", "prltoolsd", "parallels-tools"};
    return s;
}

std::vector<Finding> guest_services(Context& ctx) {
    const char* id = "env.guest_tool_services";
    const char* name = "Guest-integration services installed";
    const char* desc = "systemd unit files and init scripts of guest agents and cloud guest tooling.";
    Root root(ctx);
    bool ok;
    auto units = unit_files(root, ok);
    if (!ok) return {skipped(id, name, desc, Severity::Medium, "no systemd unit directory or init.d")};
    Evidence e;
    e.observed = units.size();
    for (const auto& u : units) {
        std::string base = u.substr(0, u.find('.'));
        for (const auto& g : guest_units())
            if (base == g) e.add(u);
    }
    return {e.finding(id, name, desc, Severity::Medium, "Remove guest-agent and cloud-init units from the image.")};
}

std::vector<Finding> guest_packages(Context& ctx) {
    const char* id = "env.guest_tool_packages";
    const char* name = "Guest-integration packages installed";
    const char* desc = "Package database entries of hypervisor guest tools (qemu-guest-agent, open-vm-tools, "
                       "virtualbox-guest-*, xe-guest-utilities, spice-vdagent, hyperv-daemons, walinuxagent, "
                       "cloud-init).";
    static const std::vector<std::string> pkgs = {"qemu-guest-agent", "open-vm-tools", "open-vm-tools-desktop",
        "virtualbox-guest-utils", "virtualbox-guest-x11", "virtualbox-guest-dkms", "virtualbox-guest-additions-iso",
        "xe-guest-utilities", "xen-tools", "xenstore-utils", "spice-vdagent", "hyperv-daemons", "hyperv-tools",
        "walinuxagent", "WALinuxAgent", "cloud-init", "google-guest-agent", "amazon-ssm-agent", "ec2-instance-connect"};
    Root root(ctx);
    auto p = packages(root);
    if (!p.ok) return {skipped(id, name, desc, Severity::Medium, "no readable package database")};
    Evidence e;
    e.observed = p.names.size();
    e.partial = p.partial;
    for (const auto& n : p.names)
        for (const auto& g : pkgs)
            if (n == g) e.add(p.manager + ":" + n);
    return {e.finding(id, name, desc, Severity::Medium, "Purge guest-tool packages before freezing the image.")};
}

const std::vector<std::string>& kernel_log_sigs() {
    // VMAware DMESG/KMSG strings, plus the DMI banner and paravirt subsystem lines the kernel prints.
    static const std::vector<std::string> s = {"Hypervisor detected", "Booting paravirtualized kernel on",
        "DMI: QEMU", "DMI: innotek", "DMI: VMware", "DMI: Xen", "DMI: Microsoft Corporation Virtual Machine",
        "DMI: Parallels", "DMI: Red Hat KVM", "QEMU Virtual CPU", "vboxguest", "kvm-clock: Using",
        "Xen HVM callback", "xen: --> pirq", "Xen version", "Hyper-V: ", "vmw_vmci", "VMware vmxnet3", "virtio_net"};
    return s;
}

std::vector<Finding> kernel_log(Context& ctx) {
    const char* id = "env.kernel_log_hypervisor";
    const char* name = "Kernel log names a hypervisor";
    const char* desc = "/dev/kmsg (the kernel ring buffer; VMAware KMSG and DMESG) for 'Hypervisor detected', "
                       "paravirt boot banners and hypervisor DMI lines. Restricted when kernel.dmesg_restrict=1.";
    Root root(ctx);
    auto r = root.read("/dev/kmsg", kLogLimit, true);
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/dev/kmsg")};
    Evidence e;
    ++e.observed;
    for (const auto& line : lines(r.value)) {
        std::string hit = match(line, kernel_log_sigs());
        if (!hit.empty()) {
            auto semi = line.find(';');
            e.add(trim(semi == std::string::npos ? line : line.substr(semi + 1)).substr(0, 100));
        }
    }
    return {e.finding(id, name, desc, Severity::High,
                      "Hide the hypervisor from the guest kernel (Xen + DRAKVUF: cpuidmon -s, no PV clock); set "
                      "kernel.dmesg_restrict=1 so unprivileged code cannot read the log.")};
}

std::vector<Finding> boot_logs(Context& ctx) {
    const char* id = "env.boot_log_hypervisor";
    const char* name = "Boot logs name a hypervisor";
    const char* desc = "Persistent logs (/var/log/dmesg, kern.log, syslog, messages, boot.log) containing kernel "
                       "hypervisor lines; only the matched line is reported.";
    Root root(ctx);
    Evidence e;
    for (const char* f : {"/var/log/dmesg", "/var/log/kern.log", "/var/log/syslog", "/var/log/messages",
                          "/var/log/boot.log"}) {
        auto r = root.read(f, kLogLimit);
        if (!r.ok) {
            if (r.err != ENOENT) ++e.unavailable;
            continue;
        }
        ++e.observed;
        e.partial |= r.truncated;
        for (const auto& line : lines(r.value))
            if (!match(line, kernel_log_sigs()).empty()) {
                e.add(std::string(f) + ": " + match(line, kernel_log_sigs()));
                break;
            }
    }
    if (!e.observed && e.unavailable) return {skipped(id, name, desc, Severity::Medium, "logs need adm/root")};
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no persistent kernel logs")};
    return {e.finding(id, name, desc, Severity::Medium, "Rotate and clear boot logs in the golden image after hardening.")};
}

std::vector<Finding> kernel_cmdline(Context& ctx) {
    const char* id = "env.kernel_cmdline";
    const char* name = "Kernel command line of a VM";
    const char* desc = "/proc/cmdline parameters typical of virtual machines: console=ttyS0/hvc0, root=/dev/vda or "
                       "/dev/xvda, xen*, virtio*, kvm-clock or cloud-image boot options.";
    static const std::vector<std::string> sigs = {"console=ttyS0", "console=hvc0", "root=/dev/vda", "root=/dev/xvda",
        "xen_", "xencons", "virtio", "kvm-clock", "clocksource=xen", "xen_emul_unplug", "ds=nocloud", "vmw_"};
    Root root(ctx);
    auto r = root.read("/proc/cmdline");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "/proc/cmdline")};
    Evidence e;
    ++e.observed;
    for (const auto& tok : split(trim(r.value), ' '))
        for (const auto& s : sigs)
            if (tok.find(s) != std::string::npos) e.add(tok.substr(0, 60));
    return {e.finding(id, name, desc, Severity::Low, "Boot the image with a desktop-style command line (no serial "
                                                      "console, root by UUID).")};
}

std::vector<Finding> sysinfo(Context& ctx) {
    const char* id = "env.sysinfo_proc";
    const char* name = "/proc/sysinfo VM levels";
    const char* desc = "On IBM Z, /proc/sysinfo has 'VM00' entries under z/VM or KVM (VMAware SYSINFO_PROC, systemd "
                       "detect_vm_zvm, virt-what ibm_systemz).";
    Root root(ctx);
    auto r = root.read("/proc/sysinfo");
    if (!r.ok) return {unreadable(id, name, desc, Severity::High, r.err, "/proc/sysinfo")};
    Evidence e;
    e.scan(r, {"VM00", "Control Program"}, "/proc/sysinfo");
    return {e.finding(id, name, desc, Severity::High, "Run the analysis in an LPAR rather than a z/VM or KVM guest.")};
}

std::vector<Finding> sys_hypervisor(Context& ctx) {
    const char* id = "env.sys_hypervisor";
    const char* name = "/sys/hypervisor";
    const char* desc = "/sys/hypervisor/type (xen) and its properties, uuid and version (VMAware HYPERVISOR_DIR, "
                       "systemd detect_vm_hypervisor).";
    Root root(ctx);
    auto l = root.list("/sys/hypervisor");
    if (!l.ok) return {unreadable(id, name, desc, Severity::High, l.err, "/sys/hypervisor")};
    Evidence e;
    e.observed = 1;
    bool ok;
    std::string type = read_value(root, "/sys/hypervisor/type", ok);
    if (ok && !type.empty()) e.add("type=" + type);
    std::string ver = read_value(root, "/sys/hypervisor/version/major", ok);
    if (ok) e.add("version/major=" + ver);
    if (root.exists("/sys/hypervisor/uuid")) e.add("uuid present");
    return {e.finding(id, name, desc, Severity::High, "Unload xen_sys / do not expose the hypervisor sysfs node.")};
}

std::vector<Finding> proc_xen(Context& ctx) {
    const char* id = "env.proc_xen";
    const char* name = "/proc/xen";
    const char* desc = "/proc/xen exists in Xen guests; capabilities containing 'control_d' marks dom0 (systemd "
                       "detect_vm_xen/detect_vm_xen_dom0, VMAware PROCESSES, virt-what).";
    Root root(ctx);
    auto st = root.stat("/proc/xen");
    if (!st.ok && st.err != ENOENT) return {unreadable(id, name, desc, Severity::High, st.err, "/proc/xen")};
    if (!root.exists("/proc/version")) return {skipped(id, name, desc, Severity::High, "no procfs")};
    Json ev = Json::object();
    ev.set("present", st.ok);
    if (st.ok) {
        bool ok;
        std::string caps = read_value(root, "/proc/xen/capabilities", ok);
        ev.set("role", ok && caps.find("control_d") != std::string::npos ? "dom0" : "domU");
    }
    return {bool_check(id, name, desc, Severity::High, st.ok, ev, "Do not mount xenfs in the guest; blacklist xenfs.")};
}

std::vector<Finding> device_nodes(Context& ctx) {
    const char* id = "env.hypervisor_device_nodes";
    const char* name = "Hypervisor device nodes";
    const char* desc = "Device nodes created by guest drivers: /dev/vboxguest, /dev/vboxuser, /dev/vmci, "
                       "/dev/xen/*, /dev/hvc0, /dev/virtio-ports, /dev/vport*.";
    Root root(ctx);
    if (!root.exists("/dev")) return {skipped(id, name, desc, Severity::High, "no /dev")};
    Evidence e;
    e.paths(root, {"/dev/vboxguest", "/dev/vboxuser", "/dev/vmci", "/dev/xen/evtchn", "/dev/xen/privcmd",
                   "/dev/xen/xenbus", "/dev/xen/gntdev", "/dev/hvc0", "/dev/virtio-ports", "/dev/vport0p1",
                   "/dev/vport1p1", "/dev/vmbus", "/dev/prl_tg"});
    return {e.finding(id, name, desc, Severity::High, "Remove the guest drivers that create these nodes.")};
}

std::vector<Finding> qemu_fw_cfg(Context& ctx) {
    const char* id = "env.qemu_fw_cfg";
    const char* name = "QEMU fw_cfg interface";
    const char* desc = "/sys/firmware/qemu_fw_cfg and /sys/module/qemu_fw_cfg (VMAware QEMU_FW_CFG).";
    Root root(ctx);
    if (!root.exists("/sys")) return {skipped(id, name, desc, Severity::High, "no sysfs")};
    Evidence e;
    e.paths(root, {"/sys/firmware/qemu_fw_cfg", "/sys/module/qemu_fw_cfg", "/proc/device-tree/fw-cfg"});
    return {e.finding(id, name, desc, Severity::High, "Blacklist qemu_fw_cfg; hide the fw_cfg ACPI device.")};
}

std::vector<Finding> ioports(Context& ctx) {
    const char* id = "env.ioports_iomem";
    const char* name = "Hypervisor resources in /proc/ioports and /proc/iomem";
    const char* desc = "Resource owner names stay visible to unprivileged users (addresses are zeroed): "
                       "QEMU0002 fw_cfg, Xen, VMware, VirtualBox, Hyper-V VMBus ranges.";
    static const std::vector<std::string> sigs = {"QEMU0002", "qemu", "xen", "vmware", "vbox", "vmbus", "hyperv",
        "Hyper-V"};
    Root root(ctx);
    Evidence e;
    for (const char* f : {"/proc/ioports", "/proc/iomem"}) {
        auto r = root.read(f);
        if (!r.ok) { if (r.err != ENOENT) ++e.unavailable; continue; }
        ++e.observed;
        for (const auto& line : lines(r.value)) {
            auto c = line.find(':');
            std::string owner = c == std::string::npos ? "" : trim(line.substr(c + 1));
            if (!match(owner, sigs).empty()) e.add(std::string(f) + ": " + owner.substr(0, 50));
        }
    }
    return {e.finding(id, name, desc, Severity::Medium, "Remove the paravirtual devices that claim these ranges.")};
}

std::vector<Finding> hypervisor_files(Context& ctx) {
    const char* id = "env.hypervisor_files";
    const char* name = "Files left by virtualisation software";
    const char* desc = "Installation directories and logs of guest additions and cloud agents.";
    Root root(ctx);
    Evidence e;
    e.paths(root, {"/etc/vmware-tools", "/usr/lib/vmware-tools", "/etc/init.d/vboxadd", "/var/log/vboxadd-install.log",
                   "/var/log/vboxadd-setup.log", "/usr/lib/virtualbox-guest", "/opt/VBoxGuestAdditions",
                   "/etc/xen", "/var/lib/xenstored", "/var/lib/cloud", "/etc/cloud/cloud.cfg", "/var/lib/waagent",
                   "/etc/waagent.conf", "/usr/share/qemu-guest-agent", "/etc/qemu/qemu-ga.conf",
                   "/usr/lib/parallels-tools", "/etc/spice-vdagentd"});
    auto opt = root.list("/opt");
    for (const auto& n : opt.names)
        if (n.rfind("VBoxGuestAdditions", 0) == 0) e.add("/opt/" + n);
    return {e.finding(id, name, desc, Severity::Medium, "Delete guest-tool leftovers from the golden image.")};
}

std::vector<Finding> bluestacks(Context& ctx) {
    const char* id = "env.bluestacks_folders";
    const char* name = "BlueStacks shared folders";
    const char* desc = "/mnt/windows/BstSharedFolder or /sdcard/windows/BstSharedFolder (VMAware BLUESTACKS_FOLDERS), "
                       "present when this binary runs inside the BlueStacks Android emulator.";
    Root root(ctx);
    Evidence e;
    e.paths(root, {"/mnt/windows/BstSharedFolder", "/sdcard/windows/BstSharedFolder"});
    return {e.finding(id, name, desc, Severity::High, "Do not use BlueStacks for analysis.")};
}

}  // namespace

PERDEDOR_REGISTER(kernel_modules, "guest_tools.drivers_modules", "fast", false, "env.guest_kernel_modules");
PERDEDOR_REGISTER(guest_buses, "guest_tools.drivers_modules", "fast", false, "env.guest_driver_buses");
PERDEDOR_REGISTER(agent_binaries, "guest_tools.processes", "fast", false, "env.guest_agent_binaries");
PERDEDOR_REGISTER(agent_processes, "guest_tools.processes", "fast", false, "env.guest_tool_processes");
PERDEDOR_REGISTER(guest_services, "guest_tools.services", "fast", false, "env.guest_tool_services");
PERDEDOR_REGISTER(guest_packages, "guest_tools.services", "fast", false, "env.guest_tool_packages");
PERDEDOR_REGISTER(kernel_log, "artifacts.kernel_messages", "fast", false, "env.kernel_log_hypervisor");
PERDEDOR_REGISTER(boot_logs, "artifacts.kernel_messages", "fast", false, "env.boot_log_hypervisor");
PERDEDOR_REGISTER(kernel_cmdline, "artifacts.kernel_messages", "fast", false, "env.kernel_cmdline");
PERDEDOR_REGISTER(sysinfo, "artifacts.hypervisor_interfaces", "fast", false, "env.sysinfo_proc");
PERDEDOR_REGISTER(sys_hypervisor, "artifacts.hypervisor_interfaces", "fast", false, "env.sys_hypervisor");
PERDEDOR_REGISTER(proc_xen, "artifacts.hypervisor_interfaces", "fast", false, "env.proc_xen");
PERDEDOR_REGISTER(device_nodes, "artifacts.hypervisor_interfaces", "fast", false, "env.hypervisor_device_nodes");
PERDEDOR_REGISTER(qemu_fw_cfg, "artifacts.hypervisor_interfaces", "fast", false, "env.qemu_fw_cfg");
PERDEDOR_REGISTER(ioports, "artifacts.hypervisor_interfaces", "fast", false, "env.ioports_iomem");
PERDEDOR_REGISTER(hypervisor_files, "artifacts.files", "fast", false, "env.hypervisor_files");
PERDEDOR_REGISTER(bluestacks, "emulator.android_vendor_emulators", "fast", false, "env.bluestacks_folders");

}  // namespace perdedor
