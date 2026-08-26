"""Known Android emulator/sandbox signatures, per CHIMERA Ch.3.3
(Android-Specific Evasion Landscape). No public Pafish/al-khaser/VMAware
equivalent exists for Android -- this is the gap PERDEDOR itself was proposed
to close (CHIMERA synopsis, Introduction), so this list is PERDEDOR-original
rather than ported from an upstream tool. See docs/CHECK_COVERAGE.md.
"""

from __future__ import annotations

# Substrings seen in ro.product.model / ro.hardware / ro.build.fingerprint /
# ro.build.characteristics / ro.boot.hardware on commodity emulators
# (BlueStacks, Genymotion, stock AVD, Cuttlefish) but never on shipped
# consumer hardware.
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
    "cutf_cvm",  # Cuttlefish, AOSP's official reference virtual device
    "cutf",
)

MANUFACTURER_SIGNATURES: tuple[str, ...] = (
    "genymotion",
    "unknown",
)

# Kernel/device nodes that only exist under an emulated goldfish/ranchu
# kernel, never on a real device.
QEMU_DEVICE_NODES: tuple[str, ...] = (
    "/dev/qemu_pipe",
    "/dev/goldfish_pipe",
    "/dev/goldfish_audio",
    "/dev/socket/qemud",
)

# The libhoudini ARM-translation shim. Its mere presence means the guest is
# an x86 hypervisor translating ARM code, not a genuine ARM execution path
# -- CHIMERA's own reason for choosing full-system ARM (TCG) emulation over
# an x86 Android VM (Ch.7.2).
LIBHOUDINI_PATHS: tuple[str, ...] = (
    "/system/lib/libhoudini.so",
    "/system/lib64/libhoudini.so",
    "/vendor/lib/libhoudini.so",
    "/vendor/lib64/libhoudini.so",
)

SUSPICIOUS_NAME_TOKENS: tuple[str, ...] = (
    "sandbox",
    "malware",
    "sample",
    "analysis",
    "cuckoo",
)

# x86 CPU ABI values -- if the reported ABI is one of these, any ARM-only
# native payload requires a translation layer (libhoudini or equivalent) to
# run at all, which is itself a detectable tell (Ch.3.3).
X86_CPU_ABIS: tuple[str, ...] = ("x86", "x86_64")

# Default AVD (Android Virtual Device) NAT subnet -- 10.0.2.0/24, with the
# emulated router/DNS conventionally at 10.0.2.2/10.0.2.3. Vanishingly rare
# on a real device's network configuration.
AVD_DEFAULT_SUBNET_PREFIX = "10.0.2."

# goldfish's default battery simulation is a fixed 25.0C / AC-powered state;
# see checks/behavioural.py for the paired "AC powered + level 50%" check.
GOLDFISH_DEFAULT_TEMPERATURE_TENTHS = 250
