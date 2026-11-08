"""macOS signature lists and thresholds. Every value names its source.

VMAware (v2.8.2, NotRequiem/VMAware src/vmaware.hpp) macOS techniques:
HWMODEL, MAC_MEMSIZE, MAC_IOKIT, IOREG_GREP, MAC_SIP, MAC_SYS, THREAD_COUNT.
Check Point Evasion Encyclopedia, macOS chapter:
https://evasions.checkpoint.com/src/MacOS/macos.html
"""

from __future__ import annotations

# -- hardware identity ---------------------------------------------------------------

# hw.model / Model Identifier of virtual Macs. VirtualMac2,1 is the model Apple's
# Virtualization.framework presents to macOS guests on Apple Silicon (used by UTM,
# Tart, VirtualBuddy, Parallels on Apple Silicon); VMware Fusion presents VMware7,1
# (Check Point shows "VMware7,0"); Parallels Desktop on Intel presents "Parallels-..."
# style identifiers.
VIRTUAL_MODEL_TOKENS = ("virtualmac", "vmware", "parallels", "virtualbox", "qemu", "kvm")
# VMAware HWMODEL / MacRansom: a real Mac's hw.model contains "Mac" (MacBookPro18,3,
# Mac14,2, iMac21,1, Macmini9,1, MacPro7,1).
REAL_MODEL_MARKER = "mac"

# Strings that name a hypervisor anywhere in system_profiler or the I/O Registry.
# Union of VMAware MAC_IOKIT / IOREG_GREP / MAC_SYS tokens ("VirtualBox", "VMware",
# "innotek", "Virtual Machine") and the Check Point ioreg -l grep
# ("virtualbox", "oracle", "vmware"), extended with Parallels, QEMU/UTM and the
# Apple Virtualization.framework device names (AppleVirtIO*, AppleParavirt*,
# "Apple Virtual Machine", "VirtualMac").
HYPERVISOR_TOKENS = (
    "virtualbox",
    "innotek",
    "vmware",
    "parallels",
    "qemu",
    "bochs",
    "virtual machine",
    "virtualmac",
    "applevirtio",
    "appleparavirt",
    "applevirtualplatform",
    "vma2macos",
)
# Narrower set for free-text fields where "virtual" alone is too common
# (e.g. "Virtual Memory" in system_profiler).
VENDOR_TOKENS = ("virtualbox", "innotek", "vmware", "parallels", "qemu", "bochs", "virtio", "paravirtual")

# Paravirtual GPU names reported by SPDisplaysDataType "sppci_model".
VIRTUAL_GPU_TOKENS = (
    "paravirtual",  # "Apple Paravirtual device" (Virtualization.framework)
    "vmware svga",
    "vmware",
    "parallels",
    "virtualbox",
    "qemu",
    "virtio",
    "bochs",
    "display adapter",
)

# Disk / NIC / audio names of virtual devices.
VIRTUAL_DEVICE_TOKENS = ("virtio", "vmware", "virtual", "qemu", "vbox", "virtualbox", "parallels")

# Loaded kexts per hypervisor (bundle id prefixes). com.apple.driver.AppleVirtIO and
# com.apple.driver.AppleParavirtGPU ship on every Mac but are only *loaded* inside
# Virtualization.framework guests.
KEXT_PREFIXES = {
    "vmware": ("com.vmware.kext.",),
    "parallels": ("com.parallels.kext.", "com.parallels."),
    "virtualbox": ("org.virtualbox.kext.",),
    "apple_virtualization": (
        "com.apple.driver.applevirtio",
        "com.apple.driver.appleparavirtgpu",
        "com.apple.driver.applevirtualplatform",
        "com.apple.driver.applevirtualgraphics",
    ),
}

# Guest-tool daemons per vendor (VMware Tools for macOS, Parallels Tools,
# VirtualBox Guest Additions, SPICE / QEMU guest agent used by UTM).
GUEST_TOOL_PROCESSES = (
    "vmware-tools-daemon",
    "vmtoolsd",
    "vmware-vmx",
    "prl_client_app",
    "prl_tools_service",
    "prl_tools",
    "prl_disp_service",
    "VBoxService",
    "VBoxClient",
    "spice-vdagent",
    "spice-vdagentd",
    "qemu-ga",
)
# Substrings of launchd labels / LaunchDaemons / Application Support names.
GUEST_TOOL_NAME_TOKENS = ("vmware", "parallels", "virtualbox", "vbox", "spice", "qemu", "utm.")

# IEEE OUIs registered to hypervisor vendors (first three octets).
# VMware 00:05:69, 00:0c:29, 00:1c:14, 00:50:56; Parallels 00:1c:42; Oracle
# VirtualBox 08:00:27; QEMU/KVM default 52:54:00; Xen 00:16:3e.
# Same list as al-khaser / Pafish MAC checks.
HYPERVISOR_OUIS = {
    "00:05:69": "VMware",
    "00:0c:29": "VMware",
    "00:1c:14": "VMware",
    "00:50:56": "VMware",
    "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3e": "Xen",
}

# Default NAT subnets of desktop hypervisors on macOS hosts.
# Parallels "Shared" network 10.211.55.0/24; VirtualBox / QEMU user-mode NAT
# 10.0.2.0/24; Apple Virtualization.framework NAT (vmnet, used by UTM, Tart,
# Lima) 192.168.64.0/24; VirtualBox host-only 192.168.56.0/24.
DEFAULT_SUBNETS = {
    "10.211.55.": "Parallels shared network",
    "10.0.2.": "VirtualBox/QEMU user-mode NAT",
    "192.168.64.": "Apple Virtualization.framework vmnet NAT",
    "192.168.56.": "VirtualBox host-only",
}

# -- resources -------------------------------------------------------------------------

# VMAware MAC_MEMSIZE: hw.memsize <= 4,000,000,000 bytes is treated as a VM.
MIN_MEMSIZE_BYTES = 4_000_000_000
# VMAware THREAD_COUNT flags <= 2 logical CPUs; every Apple Silicon Mac has >= 8
# cores (M1) and every Intel Mac since 2011 has >= 2 cores / 4 threads.
MIN_LOGICAL_CPUS = 4
# Apple has not sold a Mac with less than 128 GB of internal storage since 2017
# (MacBook Air 128 GB); Apple Silicon Macs start at 256 GB. A volume group under
# 100 GB therefore points at a VM disk. Overridable with param disk.min_gb.
MIN_DISK_BYTES = 100 * 1000**3
# Default framebuffers of VMware SVGA / QEMU / VirtualBox: 1024x768 or 800x600.
# The smallest display Apple has shipped in a Mac since 2010 is 1366x768
# (11-inch MacBook Air).
MIN_SCREEN_WIDTH = 1280
MIN_SCREEN_HEIGHT = 720

# -- analysis tools -------------------------------------------------------------------

# Process names grouped by tool family. Sources: Objective-See tool list
# (https://objective-see.org/tools.html), macOS developer tools (lldb, dtrace,
# fs_usage, eslogger are Apple binaries), and the tool lists macOS stealers check
# (Banshee / Cuckoo stealer: see docs/notes/apple.md).
ANALYSIS_PROCESS_GROUPS = {
    "debuggers": ("lldb", "debugserver", "gdb", "lldb-rpc-server", "hopperv4", "Hopper Disassembler v4"),
    "tracers": ("dtrace", "dtruss", "fs_usage", "sc_usage", "opensnoop", "execsnoop", "eslogger", "ktrace"),
    "sniffers": ("Wireshark", "tshark", "dumpcap", "tcpdump", "termshark"),
    "proxies": ("mitmproxy", "mitmdump", "mitmweb", "Charles", "Proxyman", "Burp Suite", "HTTP Toolkit"),
    "objective_see": (
        "LuLu",
        "BlockBlock",
        "BlockBlock Helper",
        "KnockKnock",
        "TaskExplorer",
        "ProcessMonitor",
        "FileMonitor",
        "ReiKey",
        "Netiquette",
        "OverSight",
        "DNSMonitor",
        "RansomWhere",
    ),
    "firewalls": ("Little Snitch", "Little Snitch Agent", "littlesnitch", "Radio Silence", "Vallum"),
    "disassemblers": ("ida", "ida64", "idat", "idat64", "ghidraRun", "Ghidra", "Binary Ninja", "Cutter", "r2", "radare2"),
    "instrumentation": ("frida-server", "frida", "frida-helper", "frida-trace", "objection"),
    "sandbox_agents": ("agent.py", "/cuckoo", "/cape", "analyzer.py"),
}
# Application bundles of the same families in /Applications and ~/Applications.
ANALYSIS_APP_GROUPS = {
    "disassemblers": (
        "Hopper Disassembler v4.app",
        "Hopper Disassembler.app",
        "Ghidra.app",
        "Binary Ninja.app",
        "Cutter.app",
        "MachOView.app",
        "Hex Fiend.app",
        "IDA Pro.app",
        "IDA Professional.app",
        "IDA Freeware.app",
    ),
    "network": ("Wireshark.app", "Charles.app", "Proxyman.app", "Burp Suite Community Edition.app",
                "Burp Suite Professional.app", "HTTP Toolkit.app", "mitmproxy.app"),
    "objective_see": (
        "LuLu.app",
        "BlockBlock Helper.app",
        "KnockKnock.app",
        "TaskExplorer.app",
        "ProcessMonitor.app",
        "FileMonitor.app",
        "ReiKey.app",
        "Netiquette.app",
        "OverSight.app",
        "DNSMonitor.app",
        "KextViewr.app",
        "WhatsYourSign.app",
    ),
    "firewalls": ("Little Snitch.app", "Radio Silence.app", "Vallum.app"),
    "inspection": ("Suspicious Package.app", "Apparency.app", "Xcode.app"),
}
# Command-line analysis tools installed by Homebrew / pip (not shipped with macOS).
ANALYSIS_CLI_TOOLS = ("frida", "frida-trace", "frida-ps", "objection", "r2", "radare2", "rizin", "mitmdump",
                      "mitmproxy", "class-dump", "jtool2", "ghidraRun", "volatility", "yara")
ANALYSIS_CLI_DIRS = ("/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin")

# Interception-proxy root certificate common names.
MITM_CERT_TOKENS = ("mitmproxy", "charles proxy", "proxyman", "portswigger", "http toolkit", "fiddler", "burp")

# Default agent / instrumentation ports: Frida 27042/27043 (frida-server default),
# Cuckoo / CAPE guest agent 8000 (agent.py default port).
AGENT_PORTS = {27042: "frida-server", 27043: "frida-server", 8000: "Cuckoo/CAPE agent.py"}

# -- identity -------------------------------------------------------------------------

# Generic or sandbox user names. macOS-specific additions: "admin" (default account
# of Cirrus Labs Tart macOS images), "runner" (GitHub Actions macOS runners),
# "ec2-user" (Amazon EC2 Mac AMIs), "vagrant" (Vagrant macOS boxes).
SANDBOX_USERNAMES = (
    "admin",
    "runner",
    "ec2-user",
    "vagrant",
    "sandbox",
    "malware",
    "virus",
    "sample",
    "test",
    "user",
    "analyst",
    "cuckoo",
    "maltest",
    "john",
    "currentuser",
)
SANDBOX_HOSTNAME_TOKENS = ("virtual machine", "vmware", "parallels", "-vm", "sandbox", "malware", "cuckoo",
                           "analysis", "admins-virtual", "runner")
# Environment variables set by CI / VM image tooling.
SANDBOX_ENV_VARS = ("CI", "GITHUB_ACTIONS", "CIRRUS_CI", "BUILDKITE", "TF_BUILD", "JENKINS_URL",
                    "TART_VM", "VAGRANT_HOME", "PERDEDOR_SANDBOX")

# CIS / Russian-language guardrails: Banshee and AMOS-family stealers exit when the
# system language or keyboard is Russian (see docs/notes/apple.md for sources).
CIS_LANGUAGE_PREFIXES = ("ru", "be", "kk", "uk", "hy", "az", "ky", "tg", "uz")
CIS_INPUT_TOKENS = ("russian", "belarusian", "kazakh", "ukrainian", "armenian", "uzbek")

# -- timing / wear ---------------------------------------------------------------------

# Pafish gensandbox_uptime(): uptime under 12 minutes is a sandbox tell.
MIN_UPTIME_SECONDS = 12 * 60
# Setup / install younger than this is a freshly built image.
MIN_SYSTEM_AGE_DAYS = 14
# Last software / security data update older than this: image not maintained.
MAX_UPDATE_AGE_DAYS = 120
# Wear-and-tear minimums: an everyday user account has at least this many items.
# Chosen far below what a used Mac holds so that any real account passes.
MIN_RECENT_ITEMS_FILES = 2
MIN_BROWSER_HISTORY_BYTES = 64 * 1024  # an empty Safari/Chrome History DB is ~20-40 KB
MIN_USER_FOLDER_ENTRIES = 2
MIN_THIRD_PARTY_APPS = 5
MIN_SHELL_HISTORY_LINES = 10
MIN_DOCK_MOD_COUNT = 5  # com.apple.dock "mod-count" increments with every Dock change
MIN_PROCESSES = 150  # an idle macOS 13+ desktop session runs several hundred processes
MIN_INSTALL_HISTORY_ENTRIES = 5
# HID idle longer than this share of the uptime: nobody has touched the machine.
IDLE_UPTIME_RATIO = 0.95
MIN_IDLE_SECONDS_FOR_VERDICT = 30 * 60
# Pafish / CPUID timing: RDTSC around CPUID averaging above 1000 cycles means a
# trapping hypervisor (pafish cpu_rdtsc_force_vmexit).
CPUID_VMEXIT_CYCLES = 1000
# Sleep acceleration: target clock advancing this much faster or slower than the
# host clock over the sleep window.
SLEEP_SKEW_RATIO = 0.25

# Local scarcity policy, not universal device limits. See docs/notes/apple.md.
# The underlying inspection interfaces: https://ss64.com/mac/ and Apple man pages.
MIN_LOG_KIB = 50 * 1024
MIN_FOREGROUND_APPS = 3
MIN_ARP_ENTRIES = 2
INPUT_IDLE_RATIO = 0.9
MIN_SHELL_HISTORY_BYTES = 1024
