"""iOS environment artifacts: Simulator and virtual-device markers, device
model identity, resources and the telephony / radio daemons a real iPhone runs.

Sources: IOSSecuritySuite EmulatorChecker (SIMULATOR_DEVICE_NAME, targetEnvironment
simulator), OWASP MASTG-KNOW-0135 / MASTG-DEMO-0131 (virtual device detection via
hw.machine and capability mismatches), freeRASP iOS ``simulator`` threat.
"""

from __future__ import annotations

import re

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext
from perdedor_macos import parsing
from perdedor_macos.checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, build, sysctl_value

from .. import signatures as sig
from ..device import IosTarget

P = Platform.IOS
DEVICE_MACHINE_PREFIXES = ("iphone", "ipad", "ipod", "watch", "appletv", "realitydevice")
SIMULATOR_VARIABLES = ("SIMULATOR_DEVICE_NAME", "SIMULATOR_UDID", "SIMULATOR_MODEL_IDENTIFIER",
                       "SIMULATOR_RUNTIME_VERSION", "SIMULATOR_ROOT")
SYSTEM_VERSION_PLIST = "/System/Library/CoreServices/SystemVersion.plist"


def probe_hw_machine(target: IosTarget, ctx: RunContext) -> Result:
    values = target.sysctl()
    if values is None:
        return Fail(UNREACHABLE + " (sysctl)")
    machine = values.get("hw.machine") or (target.out("uname_m", "uname -m") or "").strip()
    if not machine:
        return Fail("hw.machine / uname -m returned nothing")
    real = machine.lower().startswith(DEVICE_MACHINE_PREFIXES)
    return Verdict(not real, {"hw.machine": machine})


def probe_hw_model(target: IosTarget, ctx: RunContext) -> Result:
    model, fail = sysctl_value(target, "hw.model")
    if fail:
        return fail
    if not model:
        return Fail("hw.model returned nothing")
    # iOS devices report a board config such as D63AP / J517AP; a Simulator
    # reports the host Mac's model, virtual platforms their own names.
    hits = parsing.find_tokens(model, ("mac", "virtual", "vmware", "qemu", "corellium"))
    return Verdict(bool(hits), {"hw.model": model, "matched": hits})


def probe_simulator_env(target: IosTarget, ctx: RunContext) -> Result:
    found = {}
    for name in SIMULATOR_VARIABLES:
        value = target.env_value(name)
        if value:
            found[name] = value
    env = target.out("env", "env")
    if env is None and not found:
        return Fail("environment unavailable")
    env = env or ""
    for line in env.splitlines():
        key, _, value = line.partition("=")
        if key in SIMULATOR_VARIABLES and value:
            found.setdefault(key, value)
    return Verdict(bool(found), found or None)


def probe_simulator_device_type(target: IosTarget, ctx: RunContext) -> Result:
    record = target.device_record()
    if not record:
        return Skip("not a Simulator target (no simctl device record)")
    type_id = str(record.get("deviceTypeIdentifier") or "")
    return Verdict(True, {
        "deviceTypeIdentifier": type_id, "runtime": record.get("runtime"), "name": record.get("name")})


def probe_dyld_sim(target: IosTarget, ctx: RunContext) -> Result:
    found = target.exists(["/usr/lib/dyld_sim"])
    if found is None:
        return Fail(UNREACHABLE)
    return Verdict(bool(found), {"dyld_sim": bool(found)})


def _system_version(target: IosTarget) -> str | None:
    document = target.read_plist(SYSTEM_VERSION_PLIST)
    return str(document["ProductVersion"]) if isinstance(document, dict) and document.get("ProductVersion") else None


def probe_os_version_mismatch(target: IosTarget, ctx: RunContext) -> Result:
    kernel, fail = sysctl_value(target, "kern.osproductversion")
    if fail:
        return fail
    userland = _system_version(target)
    if not kernel or not userland:
        return Skip("kern.osproductversion or SystemVersion.plist ProductVersion unavailable")
    return Verdict(kernel.strip() != userland.strip(), {"kernel_reports": kernel, "system_version_plist": userland})


def probe_hv_vmm_present(target: IosTarget, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "kern.hv_vmm_present")
    if fail:
        return fail
    if value is None:
        return Skip("kern.hv_vmm_present not exposed by this kernel")
    return Verdict(value.strip() == "1", {"kern.hv_vmm_present": value})


def probe_virtual_vendor(target: IosTarget, ctx: RunContext) -> Result:
    values = target.sysctl()
    if values is None:
        return Fail(UNREACHABLE + " (sysctl)")
    uname = target.out("uname_a", "uname -a") or ""
    labels = target.launchd_labels() or []
    text = "\n".join([uname, values.get("kern.version", ""), values.get("hw.targettype", ""), *labels])
    hits = parsing.find_tokens(text, ("corellium",))
    return Verdict(bool(hits), {"matched": hits, "uname": uname.strip()[:200]})


def probe_cpu_count(target: IosTarget, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "hw.ncpu")
    if fail:
        return fail
    count = parsing.as_int(value)
    if count is None:
        return Fail("hw.ncpu missing")
    return Verdict(count < sig.MIN_CPUS, {"hw.ncpu": count}, measurement={"value": count, "threshold": sig.MIN_CPUS})


def probe_memory(target: IosTarget, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "hw.memsize")
    if fail:
        return fail
    size = parsing.as_int(value)
    if not size:
        return Fail("hw.memsize missing")
    minimum = ctx.param("memory.min_bytes", sig.MIN_MEMORY_BYTES)
    implausible = size < minimum
    return Verdict(implausible, {"hw.memsize": size},
                   measurement={"value": size, "min": sig.MIN_MEMORY_BYTES, "max": sig.MAX_MEMORY_BYTES})


def probe_disk(target: IosTarget, ctx: RunContext) -> Result:
    text = target.out("df_var", "df -k /private/var")
    if text is None:
        return Fail("df -k /private/var failed")
    kbytes = parsing.parse_df_kbytes(text)
    if kbytes is None:
        return Fail("df output unparseable")
    return Verdict(kbytes * 1024 < sig.MIN_DISK_BYTES, {"data_volume_bytes": kbytes * 1024})


def _labels(target: IosTarget) -> list[str] | Result:
    labels = target.launchd_labels()
    if labels is None:
        return Fail("launchctl list failed")
    return labels


def probe_telephony(target: IosTarget, ctx: RunContext) -> Result:
    labels = _labels(target)
    if not isinstance(labels, list):
        return labels
    machine = (target.sysctl() or {}).get("hw.machine", "")
    if machine.lower().startswith(("ipad", "ipod")):
        return Skip(f"{machine}: Wi-Fi-only models may legitimately lack CommCenter")
    present = [label for label in labels if label in sig.TELEPHONY_LABELS]
    return Verdict(not present, {"telephony_jobs": present, "launchd_jobs": len(labels)})


def probe_radios(target: IosTarget, ctx: RunContext) -> Result:
    labels = _labels(target)
    if not isinstance(labels, list):
        return labels
    missing = [radio for radio, wanted in sig.RADIO_LABELS.items() if not any(w in labels for w in wanted)]
    return Verdict(bool(missing), {"missing": missing})


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


_SIM_FIX = "Analyse evasive iOS samples on a physical device (or a virtual device that reports a real model)."

CHECKS = [
    _c("ios.env.hw_machine", "emulator.ios_simulator", "Device machine identifier",
       "hw.machine is not an iPhone/iPad/iPod identifier (a Simulator reports the host's x86_64/arm64; MASTG-DEMO-0131).",
       Severity.CRITICAL, _SIM_FIX, probe_hw_machine),
    _c("ios.env.hw_model", "emulator.ios_simulator", "Board model",
       "hw.model is a Mac model or a virtual platform name instead of an iOS board config (D63AP...).",
       Severity.HIGH, _SIM_FIX, probe_hw_model),
    _c("ios.env.simulator_environment", "emulator.ios_simulator", "Simulator environment variables",
       "SIMULATOR_DEVICE_NAME / SIMULATOR_UDID / SIMULATOR_MODEL_IDENTIFIER set (IOSSecuritySuite amIRunInEmulator).",
       Severity.CRITICAL, _SIM_FIX, probe_simulator_env),
    _c("ios.env.simulator_device_type", "emulator.ios_simulator", "CoreSimulator device type",
       "The target is a CoreSimulator device (simctl deviceTypeIdentifier).", Severity.CRITICAL, _SIM_FIX,
       probe_simulator_device_type),
    _c("ios.env.dyld_sim", "emulator.ios_simulator", "dyld_sim present",
       "/usr/lib/dyld_sim exists: the Simulator's user-space loader, absent on devices.", Severity.CRITICAL,
       _SIM_FIX, probe_dyld_sim),
    _c("ios.env.os_version_mismatch", "emulator.ios_simulator", "Kernel / user-space version mismatch",
       "kern.osproductversion (kernel) differs from SystemVersion.plist (user space): a Simulator runtime on a macOS kernel.",
       Severity.HIGH, _SIM_FIX, probe_os_version_mismatch),
    _c("ios.env.hv_vmm_present", "emulator.ios_simulator", "Kernel reports a hypervisor",
       "kern.hv_vmm_present = 1: the iOS kernel runs virtualised (virtual iPhones; MASTG-KNOW-0135).",
       Severity.CRITICAL, "Use a physical device, or a virtual platform that hides kern.hv_vmm_present.",
       probe_hv_vmm_present),
    _c("ios.env.virtual_vendor", "emulator.ios_simulator", "Virtual-device vendor strings",
       "uname, kern.version, hw.targettype or launchd jobs name Corellium.", Severity.HIGH,
       "Use a physical device for samples that look for virtual-device vendors.", probe_virtual_vendor),
    _c("ios.env.cpu_count", "resources.cpu_count", "CPU count",
       "Fewer cores than any device that runs current iOS.", Severity.MEDIUM,
       "Give the virtual device the core count of the model it claims.", probe_cpu_count),
    _c("ios.env.memory_size", "resources.memory_size", "Physical memory",
       "hw.memsize below a configurable lower bound; future device memory sizes are not capped.",
       Severity.HIGH, "Match memory to the claimed model.", probe_memory),
    _c("ios.env.disk_size", "resources.disk_size", "Data volume size",
       "Data volume smaller than any shipping storage tier.", Severity.LOW,
       "Give the virtual device a realistic storage size.", probe_disk),
    _c("ios.env.telephony_daemon", "mobile_device.telephony", "Telephony daemon",
       "CommCenter (CoreTelephony) not registered with launchd: no cellular stack, as in Simulators and virtual devices.",
       Severity.MEDIUM, "Use a device with a cellular modem (and a SIM).", probe_telephony),
    _c("ios.env.radio_daemons", "mobile_device.radios", "Wi-Fi / Bluetooth daemons",
       "wifid or bluetoothd not registered with launchd.", Severity.MEDIUM,
       "Use a physical device.", probe_radios),
]
