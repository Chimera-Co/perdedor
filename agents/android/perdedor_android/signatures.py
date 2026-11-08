"""Android emulator, analysis-environment and tampering signatures.

Every list names where its entries come from. Upstream sources (read at the
revisions noted in docs/notes/android.md):

* AE  = strazzere/anti-emulator, FindEmulator.java / FindDebugger.java
        https://github.com/strazzere/anti-emulator
* FG  = framgia/android-emulator-detector, EmulatorDetector.java
        https://github.com/framgia/android-emulator-detector
* RV  = reveny/Android-Emulator-Detection, Include/EmulatorData.hpp + EmulatorDetection.cpp
        https://github.com/reveny/Android-Emulator-Detection
* CF  = CalebFenton/AndroidEmulatorDetect, Detector.java
        https://github.com/CalebFenton/AndroidEmulatorDetect
* GG  = gingo/android-emulator-detector, EmulatorDetector.java
        https://github.com/gingo/android-emulator-detector
* RB  = scottyab/rootbeer, Const.java / RootBeer.java
        https://github.com/scottyab/rootbeer
* DF  = darvincisec/DetectFrida, native-lib.c
        https://github.com/darvincisec/DetectFrida
* MD  = vvb2060/MagiskDetector, vvb2060.c
        https://github.com/vvb2060/MagiskDetector
* MOB = MobSF DynamicAnalyzer/views/android/environment.py (what MobSF writes to the device)
        https://github.com/MobSF/Mobile-Security-Framework-MobSF
* AOSP = Android Open Source Project device trees (device/generic/goldfish, device/google/cuttlefish)
"""

from __future__ import annotations

# ----------------------------------------------------------------------------- build identity
# Substrings seen in ro.product.* / ro.hardware / ro.build.fingerprint on
# commodity emulators but not on shipped consumer hardware (v1 list; AE, FG,
# CF, GG, RV; cutf_cvm/vsoc from AOSP device/google/cuttlefish).
BUILD_PROP_EMULATOR_SIGNATURES: tuple[str, ...] = (
    "generic",
    "goldfish",
    "ranchu",
    "sdk_gphone",
    "google_sdk",
    "vbox86",
    "emulator",
    "sdk_x86",
    "android_x86",
    "cutf_cvm",
    "cutf",
)

MANUFACTURER_SIGNATURES: tuple[str, ...] = ("genymotion", "unknown")

# Exact values of individual properties (AE known_props, FG checkBasic,
# RV products/manufacturers/deviceInfo/hardwares, CF hasQemuBuildProps,
# GG isEmulator, AOSP lunch targets sdk_gphone*_x86_64, emu64x/emu64a,
# vsoc_x86_64/vsoc_arm64 (Cuttlefish)).
EXACT_PROP_VALUES: dict[str, tuple[str, ...]] = {
    "ro.product.device": (
        "generic",
        "generic_x86",
        "generic_x86_64",
        "generic_arm64",
        "vbox86p",
        "emu64x",
        "emu64a",
        "emulator64_x86_64",
        "emulator64_arm64",
        "vsoc_x86",
        "vsoc_x86_64",
        "vsoc_arm64",
        "andy",
        "droid4x",
        "nox",
    ),
    "ro.product.name": (
        "sdk",
        "google_sdk",
        "sdk_x86",
        "sdk_x86_64",
        "sdk_google",
        "sdk_phone_x86",
        "sdk_phone_x86_64",
        "sdk_phone_arm64",
        "sdk_gphone_x86",
        "sdk_gphone_x86_64",
        "sdk_gphone64_x86_64",
        "sdk_gphone64_arm64",
        "vbox86p",
        "aosp_cf_x86_64_phone",
        "aosp_cf_arm64_phone",
        "andy",
        "droid4x",
        "nox",
    ),
    "ro.build.product": (
        "sdk",
        "google_sdk",
        "sdk_x86",
        "sdk_gphone_x86",
        "sdk_gphone64_x86_64",
        "sdk_gphone64_arm64",
        "vbox86p",
        "andy",
        "droid4x",
        "nox",
        "emu64x",
        "emu64a",
        "vsoc_x86_64",
        "vsoc_arm64",
        "generic",
        "generic_x86",
        "generic_x86_64",
    ),
    "ro.product.brand": ("generic", "generic_x86", "generic_x86_64", "Android", "android"),
    "ro.product.board": ("goldfish", "goldfish_x86", "goldfish_arm64", "ranchu", "unknown", "nox"),
    "ro.board.platform": ("goldfish", "ranchu", "android_x86", "android_x86_64", "vbox86", "unknown"),
    "ro.bootloader": ("unknown", "nox"),
    "ro.bootmode": ("unknown",),
}

# Substring patterns for ro.product.model (FG checkBasic, CF, GG).
MODEL_SUBSTRINGS: tuple[str, ...] = (
    "google_sdk",
    "Emulator",
    "Android SDK built for",
    "sdk_gphone",
    "droid4x",
    "Subsystem for Android",
    "Cuttlefish",
)

# ro.build.flavor/ro.build.product-style values of AOSP emulator and
# virtual-device lunch targets (AOSP build/target/product/sdk_*.mk,
# device/google/cuttlefish).
FLAVOR_SUBSTRINGS: tuple[str, ...] = ("sdk_", "sdk-", "gphone", "vbox86", "aosp_cf_", "cf_x86", "emulator")

# ro.serialno / ro.boot.serialno values of virtual devices: AVD serials start
# with EMULATOR (goldfish init sets androidboot.serialno=EMULATOR<ver>X<...>),
# Cuttlefish uses CUTTLEFISHCVD<nn>; FG checkBasic tests "nox" in Build.SERIAL.
SERIAL_PREFIXES: tuple[str, ...] = ("emulator", "cuttlefishcvd", "nox", "genymotion")
SERIAL_PLACEHOLDERS: tuple[str, ...] = ("unknown", "0123456789abcdef", "0123456789", "000000000000")

# Emulator init services (AE/FG: init.svc.qemud, init.svc.qemu-props; AOSP
# goldfish init.ranchu.rc defines goldfish-logcat, ranchu-setup, ranchu-net,
# qemu-adb-setup, qemu-props-bootcomplete).
INIT_SERVICE_TOKENS: tuple[str, ...] = (
    "qemud",
    "qemu-props",
    "qemu-adb",
    "goldfish",
    "ranchu",
    "genyd",
    "genybaseband",
    "vbox86-setup",
    "noxd",
    "bstsvcmgr",
    "ldinit",
)

# Graphics/HAL implementations of emulators (v1 + AOSP goldfish HAL names).
HAL_SIGNATURES: tuple[str, ...] = (
    "goldfish",
    "ranchu",
    "emulation",
    "swiftshader",
    "mesa",
    "gbm",
    "minigbm_gbm_mesa",
    "vbox86",
    "android_x86",
    "pastel",
)

# GLES renderer strings reported by SurfaceFlinger under emulation
# (Android Emulator host GPU translator, SwiftShader, Mesa llvmpipe/virgl,
# VirtualBox/VMware SVGA).
GL_RENDERER_SIGNATURES: tuple[str, ...] = (
    "Android Emulator OpenGL ES Translator",
    "SwiftShader",
    "llvmpipe",
    "softpipe",
    "virgl",
    "VirGL",
    "Mesa",
    "VMware SVGA",
    "SVGA3D",
    "VirtualBox",
    "Bluestacks",
    "Intel",
    "AMD Radeon",
    "Radeon",
    "NVIDIA GeForce",
)

# ----------------------------------------------------------------------------- files
# v1 nodes (AE known_pipes + goldfish device nodes).
QEMU_DEVICE_NODES: tuple[str, ...] = (
    "/dev/qemu_pipe",
    "/dev/goldfish_pipe",
    "/dev/goldfish_audio",
    "/dev/socket/qemud",
)

# AE known_files, CF hasQemuFile.
QEMU_FILES: tuple[str, ...] = (
    "/system/lib/libc_malloc_debug_qemu.so",
    "/sys/qemu_trace",
    "/system/bin/qemu-props",
    "/vendor/bin/qemu-props",
    "/system/bin/qemud",
    "/vendor/bin/qemud",
    "/dev/goldfish_sync",
    "/dev/goldfish_address_space",
    "/sys/devices/virtual/misc/goldfish_pipe",
    "/sys/devices/virtual/misc/goldfish_sync",
)

# init/ueventd/fstab files of goldfish/ranchu (CF /init.goldfish.rc; AOSP
# device/generic/goldfish installs init.ranchu.rc and fstab.ranchu).
GOLDFISH_INIT_FILES: tuple[str, ...] = (
    "/init.goldfish.rc",
    "/init.ranchu.rc",
    "/ueventd.goldfish.rc",
    "/ueventd.ranchu.rc",
    "/fstab.goldfish",
    "/fstab.ranchu",
    "/vendor/etc/init/hw/init.ranchu.rc",
    "/vendor/etc/fstab.ranchu",
    "/vendor/ueventd.rc.ranchu",
    "/system/etc/init/hw/init.ranchu.rc",
)

# FG X86_FILES (relative names, resolved from /), plus the Android-x86 init
# script names.
X86_VM_INIT_FILES: tuple[str, ...] = (
    "/ueventd.android_x86.rc",
    "/x86.prop",
    "/ueventd.ttVM_x86.rc",
    "/init.ttVM_x86.rc",
    "/fstab.ttVM_x86",
    "/fstab.vbox86",
    "/init.vbox86.rc",
    "/ueventd.vbox86.rc",
    "/init.android_x86.rc",
    "/init.android_x86_64.rc",
    "/fstab.android_x86",
    "/fstab.android_x86_64",
)

# v1: libhoudini (Intel ARM translator; RV checkArmTranslation).
LIBHOUDINI_PATHS: tuple[str, ...] = (
    "/system/lib/libhoudini.so",
    "/system/lib64/libhoudini.so",
    "/vendor/lib/libhoudini.so",
    "/vendor/lib64/libhoudini.so",
)

# Google's libndk_translation (AVD x86 images with ARM support, ChromeOS ARC,
# Windows Subsystem for Android).
NDK_TRANSLATION_PATHS: tuple[str, ...] = (
    "/system/lib/libndk_translation.so",
    "/system/lib64/libndk_translation.so",
    "/vendor/lib/libndk_translation.so",
    "/vendor/lib64/libndk_translation.so",
    "/system/bin/arm/linker",
    "/system/bin/arm64/linker64",
)

# Kernel modules of virtual hardware (RV /sys/module entries, VirtualBox and
# virtio guest drivers).
VM_KERNEL_MODULES: tuple[str, ...] = (
    "goldfish",
    "vboxguest",
    "vboxsf",
    "vboxvideo",
    "vboxpcismv",
    "virtio_pci",
    "virtio_blk",
    "virtio_net",
    "virtio_gpu",
    "virtio_input",
    "virtio_console",
    "vmw_vsock_virtio_transport",
    "xen_netfront",
    "xen_blkfront",
    "xenfs",
    "bstsensor",
    "bstpgaipc",
    "bstinput",
    "nemusf",
    "memuguest",
)

# Filesystems used to share folders between a VM and its host (RV checkMounts
# vboxsf; 9p/virtiofs for QEMU; BlueStacks shared folder).
VM_MOUNT_TOKENS: tuple[str, ...] = ("vboxsf", "9p", "virtiofs", "BstSharedFolder", "/mnt/windows", "prl_fs")

# /proc/tty/drivers (AE/FG hasQEmuDrivers "goldfish"; goldfish tty is ttyGF).
TTY_DRIVER_TOKENS: tuple[str, ...] = ("goldfish", "ttyGF")

# /proc/cmdline tokens of emulated boots (AOSP goldfish kernel command line,
# Cuttlefish, Android-x86 GRUB entries).
CMDLINE_TOKENS: tuple[str, ...] = (
    "androidboot.hardware=goldfish",
    "androidboot.hardware=ranchu",
    "androidboot.hardware=cutf_cvm",
    "androidboot.hardware=vbox86",
    "androidboot.qemu=1",
    "qemu=1",
    "android.qemud",
    "qemu.gles",
    "console=ttyGF",
    "androidboot.hardware=android_x86",
)

# /proc/version and /proc/cpuinfo tokens (AE/FG cpuinfo "goldfish", CF
# "Goldfish", RV "hypervisor"; QEMU's default CPU model names).
KERNEL_VERSION_TOKENS: tuple[str, ...] = (
    "goldfish",
    "ranchu",
    "qemu",
    "android-x86",
    "vbox",
    "genymotion",
    "cuttlefish",
)
CPUINFO_EMULATOR_TOKENS: tuple[str, ...] = (
    "goldfish",
    "ranchu",
    "QEMU Virtual CPU",
    "Common KVM processor",
    "KVM processor",
    "Virtual CPU",
    "Android virtual processor",
)

# PCI vendor ids of virtual devices (PCI-SIG vendor registry; pci.ids).
VIRTUAL_PCI_VENDORS: dict[str, str] = {
    "0x1af4": "Red Hat virtio",
    "0x1b36": "Red Hat QEMU",
    "0x1234": "QEMU (Bochs VGA)",
    "0x80ee": "VirtualBox (InnoTek)",
    "0x5853": "Xen platform device",
    "0x15ad": "VMware",
    "0x1414": "Microsoft Hyper-V",
    "0x1ab8": "Parallels",
}

# DMI strings of hypervisors (systemd-detect-virt dmi_vendor_table).
DMI_HYPERVISOR_TOKENS: tuple[str, ...] = (
    "QEMU",
    "KVM",
    "Xen",
    "HVM domU",
    "VirtualBox",
    "innotek",
    "VMware",
    "Microsoft Corporation Virtual Machine",
    "Parallels",
    "Bochs",
    "BHYVE",
    "Google Compute Engine",
    "Amazon EC2",
)
DMI_FILES: tuple[str, ...] = (
    "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/bios_vendor",
    "/sys/class/dmi/id/bios_version",
)

# Disk model strings of virtual disks.
VIRTUAL_DISK_TOKENS: tuple[str, ...] = ("QEMU", "VBOX", "VMware", "Virtual", "Xen")
VIRTUAL_BLOCK_PREFIXES: tuple[str, ...] = ("vd", "xvd")

# ----------------------------------------------------------------------------- vendor emulators
# One entry per product: properties (key prefixes), tokens in identity
# properties, files and packages. Source tags in each entry.
VENDOR_EMULATORS: dict[str, dict] = {
    "genymotion": {
        "title": "Genymotion",
        "sources": "AE known_geny_files, FG GENY_FILES + package list, RV, MOB get_environment",
        "prop_prefixes": ("ro.genymotion.", "ro.genyd."),
        "tokens": ("genymotion", "genymobile", "vbox86p"),
        "files": (
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/system/bin/genybaseband",
            "/system/bin/genyd",
        ),
        "packages": (
            "com.google.android.launcher.layouts.genymotion",
            "com.genymotion.superuser",
            "com.genymotion.systempatcher",
        ),
    },
    "bluestacks": {
        "title": "BlueStacks",
        "sources": "RV emulatorFiles/newEmulatorFiles + findEmulatorMemory, FG package list",
        "prop_prefixes": (),
        "tokens": ("bluestacks", "bstk"),
        "files": (
            "/system/priv-app/com.bluestacks.bstfolder.apk",
            "/dev/bst_gps",
            "/dev/bst_ime",
            "/dev/bstgyro",
            "/dev/bstmegn",
            "/data/.bluestacks.prop",
            "/data/.bstconf.prop",
            "/mnt/windows/BstSharedFolder",
            "/system/bin/bstfolder",
            "/system/bin/bstfolderd",
            "/system/bin/bstsyncfs",
            "/system/bin/bstsvcmgrtest",
            "/system/bin/bstshutdown",
            "/system/bin/bstime",
            "/sys/module/bstsensor",
            "/sys/module/bstpgaipc",
            "/system/xbin/bstk/su",
            "/boot/bstmods/bstpgaipc.ko",
            "/boot/bstsetup.env",
        ),
        "packages": (
            "com.bluestacks",
            "com.bluestacks.home",
            "com.bluestacks.launcher",
            "com.bluestacks.appmart",
            "com.bluestacks.bstfolder",
        ),
    },
    "nox": {
        "title": "Nox Player",
        "sources": "FG NOX_FILES + checkBasic, RV emulatorFiles + /data/property nox",
        "prop_prefixes": (),
        "tokens": ("nox", "bignox"),
        "files": (
            "/fstab.nox",
            "/init.nox.rc",
            "/ueventd.nox.rc",
            "/system/bin/nox-prop",
            "/system/bin/noxd",
            "/system/lib/libnoxd.so",
            "/system/lib/libnoxspeedup.so",
            "/system/etc/init.nox.sh",
            "/system/bin/nox",
            "/system/bin/nox-vbox-sf",
        ),
        "packages": ("com.bignox.app",),
    },
    "memu": {
        "title": "MEmu",
        "sources": "RV emulatorFiles (/dev/memu*, memuguest.ko)",
        "prop_prefixes": (),
        "tokens": ("microvirt", "memu"),
        "files": ("/dev/memufp", "/dev/memuguest", "/dev/memuuser", "/system/lib/memuguest.ko"),
        "packages": ("com.microvirt.tools", "com.microvirt.guide"),
    },
    "ldplayer": {
        "title": "LDPlayer",
        "sources": "RV emulatorFiles/newEmulatorFiles",
        "prop_prefixes": (),
        "tokens": ("ldplayer", "ldmnq"),
        "files": (
            "/system/lib/hw/gps.ld.so",
            "/system/lib/hw/sensors.ld.so",
            "/system/lib/libldutils.so",
            "/system/bin/ldinit",
            "/system/bin/ldmountsf",
            "/system/app/LDAppStore/LDAppStore.apk",
            "/data/data/com.ldmnq.launcher3/files/launcher.preferences",
        ),
        "packages": ("com.ldmnq.launcher3", "com.android.ld.appstore"),
    },
    "andy": {
        "title": "Andy",
        "sources": "FG ANDY_FILES, RV products/manufacturers/deviceInfo",
        "prop_prefixes": (),
        "tokens": ("andy",),
        "files": ("/fstab.andy", "/ueventd.andy.rc"),
        "packages": (),
    },
    "droid4x": {
        "title": "Droid4X",
        "sources": "FG checkBasic (model droid4x), RV emulatorFiles",
        "prop_prefixes": (),
        "tokens": ("droid4x",),
        "files": ("/system/bin/droid4x-vbox-sf", "/system/bin/droid4x"),
        "packages": (),
    },
    "koplayer": {
        "title": "KoPlayer",
        "sources": "RV emulatorFiles",
        "prop_prefixes": (),
        "tokens": ("koplayer",),
        "files": ("/system/bin/KOPLAYER.ini", "/data/data/com.koplay.launcher"),
        "packages": ("com.koplay.launcher",),
    },
    "mumu": {
        "title": "MuMu Player (NetEase)",
        "sources": "RV emulatorFiles (/sys/module/nemusf)",
        "prop_prefixes": (),
        "tokens": ("mumu", "nemu"),
        "files": ("/sys/module/nemusf",),
        "packages": (),
    },
    "waydroid": {
        "title": "Waydroid",
        "sources": "Waydroid container properties (waydroid.* set by waydroid's LXC config)",
        "prop_prefixes": ("waydroid.",),
        "tokens": ("waydroid",),
        "files": (),
        "packages": (),
    },
    "anbox": {
        "title": "Anbox",
        "sources": "Anbox kernel modules (anbox-binder, anbox-ashmem)",
        "prop_prefixes": (),
        "tokens": ("anbox",),
        "files": ("/dev/anbox-binder", "/dev/anbox-hwbinder", "/dev/anbox-vndbinder", "/system/bin/anboxd"),
        "packages": ("org.anbox.appmgr",),
    },
    "cuttlefish": {
        "title": "Cuttlefish (AOSP virtual device)",
        "sources": "AOSP device/google/cuttlefish (ro.hardware=cutf_cvm, vsoc_* products)",
        "prop_prefixes": (),
        "tokens": ("cutf_cvm", "cuttlefish", "vsoc_x86", "vsoc_x86_64", "vsoc_arm64", "aosp_cf"),
        "files": ("/vendor/etc/init/hw/init.cutf_cvm.rc", "/vendor/bin/socket_vsock_proxy"),
        "packages": (),
    },
    "android_x86": {
        "title": "Android-x86 family (Android-x86, Bliss OS, PrimeOS, Phoenix OS)",
        "sources": "RV emulatorFiles (Phoenix OS), FG X86_FILES, Android-x86 build properties",
        "prop_prefixes": ("ro.bliss.",),
        "tokens": (
            "android_x86",
            "android_x86_64",
            "android-x86",
            "blissos",
            "bliss",
            "primeos",
            "phoenixos",
        ),
        "files": (
            "/system/xbin/phoenix_compat",
            "/data/system/phoenixlog.addr",
            "/system/phoenixos",
            "/system/etc/init.sh",
        ),
        "packages": (),
    },
    "wsa": {
        "title": "Windows Subsystem for Android",
        "sources": "WSA build identity (ro.product.model 'Subsystem for Android(TM)', product windows_x86_64)",
        "prop_prefixes": (),
        "tokens": ("windows_x86_64", "windows_arm64", "subsystem for android"),
        "files": (),
        "packages": (),
    },
    "redroid": {
        "title": "Redroid (Android in a container)",
        "sources": "Redroid images set ro.boot.redroid_* boot properties",
        "prop_prefixes": ("ro.boot.redroid",),
        "tokens": ("redroid",),
        "files": (),
        "packages": (),
    },
    "corellium": {
        "title": "Corellium virtual device",
        "sources": "MOB get_environment ('corellium' in properties)",
        "prop_prefixes": (),
        "tokens": ("corellium",),
        "files": (),
        "packages": (),
    },
    "virtualbox": {
        "title": "VirtualBox guest (AndroVM, older Genymotion, BlueStacks/Nox back ends)",
        "sources": "RV emulatorFiles (vboxguest.ko, vboxsf, androidVM-vbox-sf, vboxpcismv)",
        "prop_prefixes": ("androVM.",),
        "tokens": ("androvm", "vbox86"),
        "files": (
            "/lib/vboxguest.ko",
            "/lib/vboxsf.ko",
            "/system/lib/vboxguest.ko",
            "/system/lib/vboxsf.ko",
            "/system/bin/androidVM-vbox-sf",
            "/sys/module/vboxsf",
            "/sys/module/vboxguest",
            "/sys/module/vboxpcismv",
        ),
        "packages": (),
    },
}

# Identity properties scanned for vendor tokens.
IDENTITY_PROPS: tuple[str, ...] = (
    "ro.product.model",
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.name",
    "ro.product.device",
    "ro.product.board",
    "ro.build.product",
    "ro.build.fingerprint",
    "ro.build.description",
    "ro.build.display.id",
    "ro.build.flavor",
    "ro.build.host",
    "ro.hardware",
    "ro.boot.hardware",
    "ro.board.platform",
    "ro.bootloader",
    "ro.serialno",
    "ro.boot.serialno",
    "ro.product.vendor.model",
    "ro.product.vendor.device",
    "ro.product.vendor.name",
    "ro.product.system.model",
    "ro.product.system.name",
)

# ----------------------------------------------------------------------------- telephony
# AE known_numbers / FG PHONE_NUMBERS: 1555521 + console port 5554..5584.
EMULATOR_PHONE_NUMBERS: tuple[str, ...] = tuple(f"1555521{port}" for port in range(5554, 5586, 2))
EMULATOR_PHONE_PREFIX = "155552155"  # CF hasEmulatorTelephonyProperty
EMULATOR_DEVICE_IDS: tuple[str, ...] = ("000000000000000", "e21833235b6eef10", "012345678912345")  # AE/FG
EMULATOR_IMSI: tuple[str, ...] = ("310260000000000",)  # AE/FG known_imsi_ids
EMULATOR_IMSI_SUFFIX = "0000000000"  # CF getSubscriberId().endsWith
EMULATOR_VOICEMAIL = "15552175049"  # CF getVoiceMailNumber
EMULATOR_OPERATOR_NAME = "android"  # AE isOperatorNameAndroid, CF getNetworkOperatorName
EMULATOR_MCC_MNC = "310260"  # AVD modem simulator reports MCC 310 / MNC 260

# ----------------------------------------------------------------------------- sensors / battery
SENSOR_EMULATOR_TOKENS: tuple[str, ...] = (
    "goldfish",
    "ranchu",
    "genymotion",
    "genymobile",
    "bluestacks",
    "nox",
    "vbox",
    "emulator",
    "virtual",
    "memu",
    "ldplayer",
)
AOSP_SENSOR_VENDOR = "The Android Open Source Project"
GOLDFISH_DEFAULT_TEMPERATURE_TENTHS = 250  # goldfish battery HAL reports 25.0 C
GOLDFISH_DEFAULT_LEVEL = 50  # v1 behaviour: AVD battery default 50 %, AC powered

# ----------------------------------------------------------------------------- network
AVD_DEFAULT_SUBNET_PREFIX = "10.0.2."
# https://developer.android.com/studio/run/emulator-networking: 10.0.2.2 host
# loopback alias, 10.0.2.3 first DNS server, 10.0.2.15 the emulated device.
AVD_GATEWAY = "10.0.2.2"
AVD_DNS = ("10.0.2.3", "10.0.2.4", "10.0.2.5", "10.0.2.6")
AVD_DEVICE_IP = "10.0.2.15"
# Other well-known virtualisation defaults: VirtualBox NAT for the second
# adapter (Genymotion host 10.0.3.2), VirtualBox host-only 192.168.56.0/24,
# libvirt default 192.168.122.0/24, Waydroid bridge 192.168.240.0/24, Docker
# bridge 172.17.0.0/16 (Redroid).
VM_DEFAULT_SUBNETS: dict[str, str] = {
    "10.0.3.": "VirtualBox NAT (Genymotion)",
    "192.168.56.": "VirtualBox host-only",
    "192.168.122.": "libvirt default network",
    "192.168.240.": "Waydroid bridge",
    "172.17.": "Docker default bridge (Redroid)",
}
# IEEE OUIs of hypervisor virtual NICs.
VM_MAC_OUIS: dict[str, str] = {
    "52:54:00": "QEMU/KVM",
    "08:00:27": "VirtualBox",
    "0a:00:27": "VirtualBox host-only",
    "00:16:3e": "Xen",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "00:1c:42": "Parallels",
}
AVD_WIFI_SSID = "AndroidWifi"  # SSID of the AVD's virtual access point (hostapd in the emulator)

# Root CA subjects of interception proxies.
MITM_CA_TOKENS: tuple[str, ...] = (
    "mitmproxy",
    "PortSwigger",
    "Charles Proxy",
    "Charles",
    "DO_NOT_TRUST_FiddlerRoot",
    "OWASP Zed Attack Proxy",
    "OWASP ZAP",
    "HTTP Toolkit",
    "MobSF",
    "Proxyman",
    "Reqable",
    "HttpCanary",
    "Burp",
)

# ----------------------------------------------------------------------------- packages
# RB knownRootAppsPackages + KernelSU/APatch/Magisk forks.
ROOT_MANAGER_PACKAGES: tuple[str, ...] = (
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.topjohnwu.magisk",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "io.github.vvb2060.magisk",
    "io.github.huskydg.magisk",
    "me.weishu.kernelsu",
    "me.bmax.apatch",
    "com.rifsxd.ksunext",
)
# RB knownRootCloakingPackages + modern hiders.
ROOT_CLOAKING_PACKAGES: tuple[str, ...] = (
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "com.devadvance.rootcloak2",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.zachspong.temprootremovejb",
    "com.amphoras.hidemyroot",
    "com.amphoras.hidemyrootadfree",
    "com.formyhm.hiderootPremium",
    "com.formyhm.hideroot",
    "com.tsng.hidemyapplist",
)
# RB knownDangerousAppsPackages (verbatim).
DANGEROUS_PACKAGES: tuple[str, ...] = (
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.android.vending.billing.InAppBillingService.COIN",
    "com.android.vending.billing.InAppBillingService.LUCK",
    "com.chelpus.luckypatcher",
    "com.blackmartalpha",
    "org.blackmart.market",
    "com.allinone.free",
    "com.repodroid.app",
    "org.creeplays.hack",
    "com.baseappfull.fwd",
    "com.zmapp",
    "com.dv.marketmod.installer",
    "org.mobilism.android",
    "com.android.wp.net.log",
    "com.android.camera.update",
    "cc.madkite.freedom",
    "com.solohsu.android.edxp.manager",
    "org.meowcat.edxposed.manager",
    "com.xmodgame",
    "com.cih.game_cih",
    "com.charles.lpoqasert",
    "catch_.me_.if_.you_.can_",
)
HOOKING_FRAMEWORK_PACKAGES: tuple[str, ...] = (
    "de.robv.android.xposed.installer",
    "org.meowcat.edxposed.manager",
    "com.solohsu.android.edxp.manager",
    "org.lsposed.manager",
    "org.lsposed.lspatch",
    "io.va.exposed",
    "io.va.exposed64",
    "top.canyie.dreamland.manager",
    "com.saurik.substrate",
    "re.frida.server",
)
# Xposed modules MobSF installs (MOB: JustTrustMe, SSLUnpinning, ProxyOn,
# RootCloak2) and other certificate-pinning bypasses.
SSL_UNPINNING_PACKAGES: tuple[str, ...] = (
    "just.trust.me",
    "mobi.acpm.sslunpinning",
    "mobi.acpm.proxyon",
    "com.virb3.trustmealready",
    "io.github.tehcneko.sslunpinning",
)
ANALYSIS_TOOL_PACKAGES: tuple[str, ...] = (
    "com.mwr.dz",  # drozer agent (MWR)
    "com.withsecure.dz",  # drozer agent (WithSecure)
    "opensecurity.clipdump",  # MobSF clipboard monitor (MOB start_clipmon)
    "mobi.acpm.inspeckage",  # Inspeckage
    "tech.httptoolkit.android.v1",  # HTTP Toolkit
    "com.guoshi.httpcanary",  # HttpCanary
    "com.guoshi.httpcanary.premium",
    "app.greyshirts.sslcapture",  # Packet Capture
    "com.emanuelef.remote_capture",  # PCAPdroid
    "com.reqable.android",  # Reqable
    "com.termux",  # Termux
    "com.termux.api",
    "ru.meefik.linuxdeploy",
    "com.android.adbkeyboard",
    "jp.co.cyberagent.stf",  # OpenSTF agent
    "com.afwsamples.testdpc",  # TestDPC
)
AUTOMATION_PACKAGES: tuple[str, ...] = (
    "io.appium.settings",
    "io.appium.uiautomator2.server",
    "io.appium.uiautomator2.server.test",
    "io.appium.unlock",
    "com.github.uiautomator",
    "com.github.uiautomator.test",
    "jp.co.cyberagent.stf",
    "jp.co.cyberagent.stf.rotationwatcher",
    "com.android.adbkeyboard",
    "com.arlosoft.macrodroid",
    "net.dinglisch.android.taskerm",
    "org.autojs.autojs",
    "org.autojs.autoxjs.v6",
    "com.stardust.scriptdroid",
    "io.selendroid",
    "com.genymotion.superuser",
)
APP_VIRTUALIZATION_PACKAGES: tuple[str, ...] = (
    "com.lbe.parallel.intl",
    "com.parallel.space.lite",
    "com.parallel.space.pro",
    "com.excelliance.dualaid",
    "com.ludashi.dualspace",
    "com.vmos.pro",
    "com.vmos.app",
    "com.vmos.glb",
    "io.virtualapp",
    "io.va.exposed",
    "com.applisto.appcloner",
    "com.oasisfeng.island",
)
EVERYDAY_PACKAGES: tuple[str, ...] = (
    "com.whatsapp",
    "com.facebook.katana",
    "com.facebook.orca",
    "com.instagram.android",
    "org.telegram.messenger",
    "com.zhiliaoapp.musically",
    "com.snapchat.android",
    "com.spotify.music",
    "com.netflix.mediaclient",
    "com.twitter.android",
    "com.google.android.youtube",
    "com.google.android.gm",
    "com.android.chrome",
    "com.google.android.apps.maps",
    "com.google.android.apps.photos",
    "com.amazon.mShop.android.shopping",
    "com.ubercab",
    "com.linkedin.android",
    "com.microsoft.teams",
    "com.viber.voip",
    "com.tencent.mm",
    "jp.naver.line.android",
    "com.paypal.android.p2pmobile",
)
GMS_PACKAGE = "com.google.android.gms"
PLAY_STORE_PACKAGE = "com.android.vending"

# ----------------------------------------------------------------------------- root / instrumentation
# RB Const.suPaths (verbatim) - su/busybox/magisk are looked up in each.
SU_PATHS: tuple[str, ...] = (
    "/data/local/",
    "/data/local/bin/",
    "/data/local/xbin/",
    "/sbin/",
    "/su/bin/",
    "/system/bin/",
    "/system/bin/.ext/",
    "/system/bin/failsafe/",
    "/system/sd/xbin/",
    "/system/usr/we-need-root/",
    "/system/xbin/",
    "/system_ext/bin/",
    "/cache/",
    "/data/",
    "/dev/",
)
# RB Const.pathsThatShouldNotBeWritable (verbatim).
PATHS_NOT_WRITABLE: tuple[str, ...] = (
    "/system",
    "/system/bin",
    "/system/sbin",
    "/system/xbin",
    "/vendor/bin",
    "/sbin",
    "/etc",
)
# Magisk: https://topjohnwu.github.io/Magisk/details.html (/sbin/.magisk on
# old releases, /debug_ramdisk on 2SI devices, /data/adb/magisk), MD
# haveMagicMount (module files mounted over /system).
MAGISK_PATHS: tuple[str, ...] = (
    "/sbin/.magisk",
    "/sbin/.core",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk",
    "/data/adb/magisk.db",
    "/data/adb/modules",
    "/debug_ramdisk/magisk",
    "/debug_ramdisk/.magisk",
    "/system/bin/magisk",
    "/system/xbin/magisk",
    "/sbin/magisk",
    "/init.magisk.rc",
)
MAGISK_MOUNT_TOKENS: tuple[str, ...] = ("magisk", "/debug_ramdisk", "/sbin/.magisk", "worker", "core/mirror")
# KernelSU https://kernelsu.org/guide/module.html (/data/adb/ksu, modules
# overlay mounted with source "KSU"); APatch (/data/adb/ap, /data/adb/apd).
KERNEL_ROOT_PATHS: tuple[str, ...] = (
    "/data/adb/ksu",
    "/data/adb/ksud",
    "/data/adb/ap",
    "/data/adb/apd",
    "/data/adb/kpatch",
)
KERNEL_ROOT_MOUNT_TOKENS: tuple[str, ...] = ("KSU", "APatch", "apatch")
XPOSED_PATHS: tuple[str, ...] = (
    "/system/framework/XposedBridge.jar",
    "/system/xposed.prop",
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/system/bin/app_process32_xposed",
    "/system/bin/app_process64_xposed",
    "/system/framework/edxp.jar",
    "/system/lib/libriru_edxp.so",
    "/system/lib64/libriru_edxp.so",
    "/data/adb/lspd",
    "/data/adb/riru",
    "/data/misc/riru",
)
SUBSTRATE_PATHS: tuple[str, ...] = (
    "/system/lib/libsubstrate.so",
    "/system/lib/libsubstrate-dvm.so",
    "/system/lib64/libsubstrate.so",
    "/data/local/tmp/substrate",
)
# Frida: default server names and the /data/local/tmp/re.frida.server work
# directory (https://frida.re/docs/android/); MobSF renames the server to
# fd_server (MOB).
FRIDA_PATHS: tuple[str, ...] = (
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida",
    "/data/local/tmp/frida-gadget.so",
    "/data/local/tmp/libfrida-gadget.so",
    "/data/local/tmp/mobsf/fd_server",
    "/data/local/tmp/mobsf-fd-server",
    "/system/fd_server",
    "/system/bin/frida-server",
    "/system/xbin/frida-server",
    "/sbin/frida-server",
)
FRIDA_PROCESS_TOKENS: tuple[str, ...] = (
    "frida-server",
    "frida",
    "re.frida.server",
    "fd_server",
    "frida-helper-32",
    "frida-helper-64",
    "frida-portal",
    "hluda-server",
    "florida",
)
# DF detect_frida_threads: gum-js-loop and gmain (also gdbus, pool-frida).
FRIDA_THREAD_NAMES_STRONG: tuple[str, ...] = ("gum-js-loop", "pool-frida", "linjector", "frida-agent")
FRIDA_THREAD_NAMES_WEAK: tuple[str, ...] = ("gmain", "gdbus")
FRIDA_PORTS: tuple[int, ...] = (27042, 27043)  # frida-server default listen port and the next
# Other analysis ports: adb over TCP 5555, drozer agent 31415, IDA android_server
# 23946, local interception proxies 8080/8888.
ANALYSIS_PORTS: dict[int, str] = {
    5555: "adb over TCP",
    31415: "drozer agent",
    23946: "IDA Pro android_server",
    8080: "HTTP proxy",
    8888: "HTTP proxy (Charles default)",
    8000: "Cuckoo/CAPE-style agent",
}
ANALYSIS_PROCESS_TOKENS: tuple[str, ...] = (
    "tcpdump",
    "strace",
    "ltrace",
    "gdbserver",
    "gdbserver64",
    "lldb-server",
    "android_server",
    "android_server64",
    "com.android.commands.monkey",
    "uiautomator",
    "com.mwr.dz",
    "com.withsecure.dz",
    "opensecurity.clipdump",
    "mitmdump",
    "objection",
    "droidmon",
    "inspeckage",
)
ANALYSIS_FILES: tuple[str, ...] = (
    "/data/local/tmp/mobsf",
    "/system/.mobsf-f",
    "/system/.mobsf-x",
    "/data/local/tmp/mobsf/.mobsf-f",
    "/data/local/tmp/android_server",
    "/data/local/tmp/android_server64",
    "/data/local/tmp/gdbserver",
    "/data/local/tmp/lldb-server",
    "/data/local/tmp/tcpdump",
    "/data/local/tmp/strace",
    "/data/local/tmp/drozer",
    "/data/local/tmp/agent.apk",
    "/data/local/tmp/objection",
)
ANALYSIS_TMP_NAME_TOKENS: tuple[str, ...] = (
    "frida",
    "gadget",
    "mobsf",
    "fd_server",
    "android_server",
    "gdbserver",
    "lldb",
    "objection",
    "drozer",
    "tcpdump",
    "strace",
    "inspeckage",
)
BUSYBOX = "busybox"

SUSPICIOUS_NAME_TOKENS: tuple[str, ...] = (
    "sandbox",
    "malware",
    "sample",
    "analysis",
    "cuckoo",
    "mobsf",
    "virus",
)
DEFAULT_DEVICE_NAMES: tuple[str, ...] = (
    "android sdk built for",
    "sdk_gphone",
    "generic",
    "android_x86",
    "vbox86",
    "genymotion",
    "emulator",
    "cuttlefish",
)

X86_CPU_ABIS: tuple[str, ...] = ("x86", "x86_64")


def su_candidates(binary: str) -> tuple[str, ...]:
    return tuple(p + binary for p in SU_PATHS)


def all_paths() -> tuple[str, ...]:
    """Every fixed path the checks test, so ``Device.exists`` resolves them in one round trip."""
    groups: list[tuple[str, ...]] = [
        QEMU_DEVICE_NODES,
        QEMU_FILES,
        GOLDFISH_INIT_FILES,
        X86_VM_INIT_FILES,
        LIBHOUDINI_PATHS,
        NDK_TRANSLATION_PATHS,
        MAGISK_PATHS,
        KERNEL_ROOT_PATHS,
        XPOSED_PATHS,
        SUBSTRATE_PATHS,
        FRIDA_PATHS,
        ANALYSIS_FILES,
        su_candidates("su"),
        su_candidates("magisk"),
        su_candidates(BUSYBOX),
        ("/sys/hypervisor/type", "/proc/xen", "/sys/class/dmi/id", "/data/misc/user/0/cacerts-added"),
    ]
    for vendor in VENDOR_EMULATORS.values():
        groups.append(tuple(vendor["files"]))
    out: list[str] = []
    for group in groups:
        out.extend(group)
    return tuple(dict.fromkeys(out))
