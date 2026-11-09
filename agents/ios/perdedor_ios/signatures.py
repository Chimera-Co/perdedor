"""iOS signature lists and thresholds. Every value names its source.

Path lists follow securing/IOSSecuritySuite (JailbreakChecker.swift
checkExistenceOfSuspiciousFiles, checkSuspiciousFilesCanBeOpened,
checkSymbolicLinks, checkURLSchemes, checkDYLD, checkSuspiciousObjCClasses;
ReverseEngineeringToolsChecker.swift checkDYLD / checkOpenedPorts) at master,
fetched 2026-11-08, and thii/DTTJailbreakDetection isJailbroken. Every path is
probed both as given (rootful) and below /var/jb (rootless: Dopamine,
palera1n rootless), which is where rootless bootstraps place the same tree.
"""

from __future__ import annotations

ROOTLESS_PREFIXES = ("", "/var/jb")

JAILBREAK_GROUPS = {
    # IOSSecuritySuite "Modern rootless jailbreaks" block.
    "rootless_bootstrap": (
        "/var/jb/usr/bin",
        "/var/jb/Library/LaunchDaemons",
        "/var/jb/etc/rc.d",
        "/var/Liy/.procursus_strapped",
        "/var/Liy",
    ),
    "dopamine": ("/Applications/Dopamine.app", "/var/mobile/Library/Preferences/com.opa334.Dopamine.plist"),
    "palera1n": (
        "/Applications/palera1nLoader.app",
        "/usr/bin/palera1n-helper",
        "/var/mobile/Library/Preferences/com.samiiau.loader.plist",
    ),
    "checkra1n": ("/var/binpack", "/var/binpack/Applications/loader.app"),
    "unc0ver": (
        "/.cydia_no_stash",
        "/.installed_unc0ver",
        "/jb/offsets.plist",
        "/usr/share/jailbreak/injectme.plist",
        "/etc/apt/undecimus/undecimus.list",
        "/var/lib/dpkg/info/mobilesubstrate.md5sums",
        "/jb/jailbreakd.plist",
        "/jb/amfid_payload.dylib",
        "/jb/libjailbreak.dylib",
        "/var/lib/undecimus/apt",
    ),
    "electra": (
        "/etc/apt/sources.list.d/electra.list",
        "/etc/apt/sources.list.d/sileo.sources",
        "/.bootstrapped_electra",
        "/usr/lib/libjailbreak.dylib",
        "/jb/lzma",
    ),
    "package_managers": (
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/usr/libexec/cydia/firmware.sh",
        "/var/lib/cydia",
        "/private/var/lib/cydia",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    ),
    "apt_dpkg": (
        "/etc/apt",
        "/private/var/lib/apt",
        "/var/log/apt",
        "/private/var/cache/apt/",
        "/var/lib/dpkg",
        "/private/var/stash",
    ),
    # DTTJailbreakDetection and IOSSecuritySuite (non-emulator list).
    "shell_binaries": (
        "/bin/bash",
        "/usr/sbin/sshd",
        "/usr/libexec/ssh-keysign",
        "/bin/sh",
        "/etc/ssh/sshd_config",
        "/usr/libexec/sftp-server",
        "/usr/bin/ssh",
    ),
    "bypass_tweaks": (
        "/var/mobile/Library/Preferences/me.jjolano.shadow.plist",
        "/var/mobile/Library/Preferences/ABPattern",
        "/usr/lib/ABDYLD.dylib",
        "/usr/lib/ABSubLoader.dylib",
        "/Library/BawAppie/ABypass",
        "/Library/PreferenceBundles/LibertyPref.bundle",
        "/Library/PreferenceBundles/ShadowPreferences.bundle",
        "/Library/PreferenceBundles/ABypassPrefs.bundle",
        "/Library/PreferenceBundles/FlyJBPrefs.bundle",
        "/var/mobile/Library/Preferences/com.roothide.pref.plist",
    ),
    "legacy_apps": (
        "/Applications/Icy.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/blackra1n.app",
        "/Applications/SBSettings.app",
        "/Applications/FakeCarrier.app",
        "/Applications/WinterBoard.app",
        "/Applications/IntelliScreen.app",
        "/Applications/FlyJB.app",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    ),
}

HOOKING_FRAMEWORKS = {
    "substrate": (
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/CydiaSubstrate.dylib",
        "/usr/lib/substrate",
        "/Library/Frameworks/CydiaSubstrate.framework",
    ),
    "substitute": ("/usr/lib/libsubstitute.dylib", "/Library/PreferenceBundles/SubstitutePrefs.bundle"),
    "libhooker": ("/usr/lib/libhooker.dylib",),
    "ellekit": ("/usr/lib/libellekit.dylib",),
}
TWEAK_DIRECTORIES = (
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/TweakInject",
    "/var/jb/Library/MobileSubstrate/DynamicLibraries",
    "/var/jb/usr/lib/TweakInject",
)
SSL_KILL_SWITCH_NAMES = ("SSLKillSwitch2", "SSLKillSwitch", "SSLBypass")

# IOSSecuritySuite checkSymbolicLinks: these are directories on stock iOS; old
# rootful jailbreaks (stashing) turned them into symlinks.
STOCK_DIRECTORIES = (
    "/var/lib/undecimus/apt",
    "/Applications",
    "/Library/Ringtones",
    "/Library/Wallpaper",
    "/usr/arm-apple-darwin9",
    "/usr/include",
    "/usr/libexec",
    "/usr/share",
)

# IOSSecuritySuite checkURLSchemes ("cydia://" deliberately omitted there because
# an App Store app registers it; we report it separately as low-confidence).
JAILBREAK_URL_SCHEMES = ("undecimus", "sileo", "zbra", "filza", "dopamine", "palera1n")
WEAK_URL_SCHEMES = ("cydia", "activator")

# Application bundles of jailbreaks, package managers and jailbreak-only tools.
JAILBREAK_APPS = (
    "Cydia.app",
    "Sileo.app",
    "Zebra.app",
    "Installer.app",
    "Filza.app",
    "Dopamine.app",
    "palera1nLoader.app",
    "checkra1n.app",
    "unc0ver.app",
    "Taurine.app",
    "Odyssey.app",
    "Chimera.app",
    "Electra.app",
    "NewTerm.app",
    "loader.app",
)
TROLLSTORE_APPS = ("TrollStore.app", "TrollStorePersistenceHelper.app")

# IOSSecuritySuite JailbreakChecker suspiciousLibrariesLowercase +
# ReverseEngineeringToolsChecker suspiciousLibraries.
SUSPICIOUS_LIBRARIES = (
    "systemhook.dylib",
    "roothideinit.dylib",
    "libellekit.dylib",
    "libhooker.dylib",
    "libblackjack.dylib",
    "substrateloader.dylib",
    "mobilesubstrate.dylib",
    "tweakinject.dylib",
    "cydiasubstrate",
    "substrateinserter",
    "substratebootstrap",
    "libsubstitute.dylib",
    "sslkillswitch2.dylib",
    "sslkillswitch.dylib",
    "fridagadget",
    "frida",
    "libcycript",
    "cycript",
    "cynject",
    "abypass",
    "flyjb",
    "shadow",
    "liberty",
    "choicy",
    "unsub",
    "vnodebypass",
    "hidejb",
    "/.file",
    "preferenceloader",
    "rocketbootstrap",
    "weeloader",
    "customwidgeticons",
    "cephei",
    "electra",
    "appsyncunified-frontboard.dylib",
)

FRIDA_FILES = ("/usr/sbin/frida-server", "/usr/lib/frida", "/Library/LaunchDaemons/re.frida.server.plist")
CYCRIPT_FILES = ("/usr/bin/cycript", "/usr/lib/libcycript.dylib", "/usr/bin/cynject")
# IOSSecuritySuite checkOpenedPorts: 27042 Frida, 4444 Needle, 22 OpenSSH, 44 checkra1n.
SUSPICIOUS_PORTS = {
    27042: "frida-server",
    27043: "frida-server",
    4444: "Needle agent",
    22: "OpenSSH",
    44: "checkra1n dropbear",
}
ANALYSIS_PROCESSES = (
    "frida-server",
    "frida-helper",
    "debugserver",
    "lldb",
    "cycript",
    "cynject",
    "tcpdump",
    "sslsplit",
    "objection",
    "NeedleAgent",
    "gdb",
)
ANALYSIS_FILES = (
    "/usr/bin/debugserver",
    "/Developer/usr/bin/debugserver",
    "/usr/sbin/tcpdump",
    "/usr/bin/class-dump",
    "/usr/bin/lldb",
    "/usr/bin/gdb",
)

# launchd labels of telephony and radio daemons present on iPhones.
TELEPHONY_LABELS = ("com.apple.CommCenter",)
RADIO_LABELS = {"wifi": ("com.apple.wifid",), "bluetooth": ("com.apple.bluetoothd",)}

MITM_CERT_TOKENS = (
    "mitmproxy",
    "charles proxy",
    "proxyman",
    "portswigger",
    "http toolkit",
    "fiddler",
    "burp",
)

# -- thresholds -----------------------------------------------------------------------

# Conservative local resource and scarcity policies, not universal iOS limits.
# The simulator cannot reproduce all hardware: Apple's Simulator guide:
# https://developer.apple.com/library/archive/documentation/IDEs/Conceptual/iOS_Simulator_Guide/TestingontheiOSSimulator/TestingontheiOSSimulator.html
MIN_CPUS = 2
MIN_MEMORY_BYTES = 1_500_000_000
# Smallest storage of any iOS 15-capable device: 16 GB (iPhone 6s base).
MIN_DISK_BYTES = 12 * 1000**3
MIN_USER_APPS = 10
MIN_PHOTOS = 20
MIN_SYSTEM_AGE_DAYS = 14
MIN_UPTIME_SECONDS = 12 * 60  # Pafish gensandbox_uptime
SLEEP_SKEW_RATIO = 0.25

HYPERVISOR_OUIS = {
    "00:05:69": "VMware",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3e": "Xen",
}
VIRTUAL_TOKENS = ("corellium", "virtual", "vmware", "qemu", "simulator", "coresimulator")
CIS_LANGUAGE_PREFIXES = ("ru", "be", "kk", "uk", "hy", "az", "ky", "tg", "uz")
