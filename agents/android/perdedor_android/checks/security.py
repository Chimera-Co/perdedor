"""Read-only root, instrumentation and device policy observations.

Sources: RootBeer.java (https://github.com/scottyab/rootbeer), Magisk
https://topjohnwu.github.io/Magisk/details.html, KernelSU
https://kernelsu.org/guide/module.html, https://github.com/bmax121/APatch,
https://frida.re/docs/android/ and the freeRASP threat documentation.
Shell visibility is broader than an app's; no privilege escalation is attempted.
"""

import re

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device
from ._base import Checks, ProbeError, Skip, Verdict, existing, need, packages, processes, props, settings

REG = Checks()


def register(name, technique, description, fn, remediation, severity=Severity.MEDIUM):
    REG.check(
        f"android.design.{name}",
        technique,
        name=name.replace("_", " ").capitalize(),
        description=description,
        severity=severity,
        remediation=remediation,
    )(fn)


def path_probe(paths):
    def probe(dev, ctx):
        hits = existing(dev, paths)
        return Verdict(bool(hits), {"visible_paths": hits})

    return probe


for _name, _paths, _tech in (
    ("su_paths", sig.su_candidates("su"), "integrity.root"),
    ("busybox_paths", sig.su_candidates("busybox"), "integrity.root"),
    ("magisk_paths", sig.MAGISK_PATHS, "integrity.root"),
    ("kernel_root_paths", sig.KERNEL_ROOT_PATHS, "integrity.root"),
    ("xposed_paths", sig.XPOSED_PATHS, "instrumentation.hooking_frameworks"),
    ("substrate_paths", sig.SUBSTRATE_PATHS, "instrumentation.hooking_frameworks"),
    ("frida_paths", sig.FRIDA_PATHS, "instrumentation.hooking_frameworks"),
    ("analysis_files", sig.ANALYSIS_FILES, "analysis_tools.files"),
):
    register(
        _name,
        _tech,
        "Known visible root or inspection paths; inaccessible paths are unknown.",
        path_probe(_paths),
        "Remove the identified binaries and modules from the baseline image; use host introspection.",
    )


def package_probe(names):
    def probe(dev, ctx):
        hits = sorted(set(packages(dev)).intersection(names))
        return Verdict(bool(hits), {"packages": hits})

    return probe


for _name, _names, _tech in (
    ("root_managers", sig.ROOT_MANAGER_PACKAGES, "integrity.root"),
    ("root_cloaking_apps", sig.ROOT_CLOAKING_PACKAGES, "integrity.root"),
    ("patching_apps", sig.DANGEROUS_PACKAGES, "integrity.root"),
    ("hooking_packages", sig.HOOKING_FRAMEWORK_PACKAGES, "instrumentation.hooking_frameworks"),
    ("unpinning_packages", sig.SSL_UNPINNING_PACKAGES, "instrumentation.hooking_frameworks"),
    ("analysis_packages", sig.ANALYSIS_TOOL_PACKAGES, "analysis_tools.files"),
    ("automation_packages", sig.AUTOMATION_PACKAGES, "analysis_tools.files"),
    ("app_virtualization", sig.APP_VIRTUALIZATION_PACKAGES, "container.app_sandbox"),
):
    register(
        _name,
        _tech,
        "Installed package names associated with root, analysis or automation; presence is not proof of use.",
        package_probe(_names),
        "Remove these packages from the baseline, keeping necessary automation on the host.",
    )


def property_probe(key, bad):
    def probe(dev, ctx):
        value = props(dev).get(key)
        if value is None or value == "":
            raise Skip(f"{key} is not exposed by this build")
        return Verdict(value.lower() in bad, {key: value})

    return probe


for _name, _key, _bad, _tech in (
    ("ro_secure", "ro.secure", ("0",), "integrity.debuggable_build"),
    ("ro_debuggable", "ro.debuggable", ("1",), "integrity.debuggable_build"),
    ("adb_secure", "ro.adb.secure", ("0",), "integrity.debuggable_build"),
    ("verified_boot", "ro.boot.verifiedbootstate", ("orange", "yellow", "red"), "integrity.bootloader"),
    ("flash_unlocked", "ro.boot.flash.locked", ("0",), "integrity.bootloader"),
    ("vbmeta_unlocked", "ro.boot.vbmeta.device_state", ("unlocked",), "integrity.bootloader"),
    ("verity_disabled", "ro.boot.veritymode", ("disabled", "logging"), "integrity.bootloader"),
):
    register(
        _name,
        _tech,
        f"Read { _key } without changing boot or debugging configuration.",
        property_probe(_key, _bad),
        "Use a production-signed user image with verified boot and a locked boot chain.",
    )


def setting_probe(namespace, key, empty=False):
    def probe(dev, ctx):
        value = settings(dev, namespace).get(key)
        if value is None:
            raise Skip(f"{namespace}.{key} is not exposed")
        active = value not in ("", "0", "null", "-1") if empty else value == "1"
        return Verdict(active, {"setting": key, "enabled": active})

    return probe


for _name, _ns, _key, _empty, _tech in (
    ("developer_options", "global", "development_settings_enabled", False, "integrity.developer_settings"),
    ("usb_debugging", "global", "adb_enabled", False, "integrity.developer_settings"),
    ("wireless_debugging", "global", "adb_wifi_enabled", False, "integrity.developer_settings"),
    ("mock_location", "secure", "mock_location", False, "integrity.developer_settings"),
    (
        "accessibility_services",
        "secure",
        "enabled_accessibility_services",
        True,
        "integrity.accessibility_overrides",
    ),
    (
        "notification_listeners",
        "secure",
        "enabled_notification_listeners",
        True,
        "integrity.accessibility_overrides",
    ),
    ("always_on_vpn", "secure", "always_on_vpn_app", True, "network.proxy_mitm"),
):
    register(
        _name,
        _tech,
        f"Read { _ns }.{ _key }; legitimate users may also enable this setting.",
        setting_probe(_ns, _key, _empty),
        "Review the enabled setting and remove analysis-only configuration from the baseline.",
        Severity.LOW,
    )


@REG.check(
    "android.design.adb_root",
    "integrity.debuggable_build",
    name="Shell UID",
    description="Whether the existing adb shell is uid 0; never invokes adb root or su.",
    severity=Severity.HIGH,
    remediation="Run adbd as the shell user on a production user build.",
)
def adb_root(dev: Device, ctx: RunContext):
    value = need(dev.sh("id -u"), "shell uid").strip()
    if not value.isdigit():
        raise ProbeError("unrecognized uid")
    return Verdict(value == "0", {"uid": int(value)})


@REG.check(
    "android.design.selinux",
    "integrity.selinux",
    name="SELinux enforcement",
    description="getenforce reports Permissive or Disabled.",
    severity=Severity.HIGH,
    remediation="Enable SELinux enforcing with the stock device policy.",
)
def selinux(dev: Device, ctx: RunContext):
    value = need(dev.sh("getenforce"), "SELinux status").strip().lower()
    if value not in ("enforcing", "permissive", "disabled"):
        raise ProbeError("unrecognized SELinux status")
    return Verdict(value != "enforcing", {"mode": value})


@REG.check(
    "android.design.writable_system",
    "integrity.root",
    name="Writable system mounts",
    description="Mount flags expose writable system/vendor partitions. No write is attempted.",
    severity=Severity.HIGH,
    remediation="Mount system and vendor read-only with verified boot; remove overlay mounts.",
)
def writable_system(dev: Device, ctx: RunContext):
    text = need(dev.mounts(), "mount table")
    hits = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] in sig.PATHS_NOT_WRITABLE and "rw" in parts[3].split(","):
            hits.append(parts[1])
    return Verdict(bool(hits), {"writable_mounts": hits})


@REG.check(
    "android.design.root_mounts",
    "integrity.root",
    name="Root framework mounts",
    description="Mount sources/paths naming Magisk, KernelSU or APatch.",
    severity=Severity.HIGH,
    remediation="Boot the stock boot/vendor_boot images and remove root modules from the baseline.",
)
def root_mounts(dev: Device, ctx: RunContext):
    text = need(dev.mounts(), "mount table").lower()
    tokens = ("magisk", "/debug_ramdisk", "/data/adb", "ksu", "apatch")
    hits = [t for t in tokens if t in text]
    return Verdict(bool(hits), {"markers": hits})


def process_probe(tokens):
    def probe(dev, ctx):
        rows = processes(dev)
        hits = sorted({p["name"] for p in rows if any(t in p["name"].lower() for t in tokens)})
        return Verdict(bool(hits), {"processes": hits})

    return probe


register(
    "frida_processes",
    "instrumentation.hooking_frameworks",
    "Visible instrumentation server processes.",
    process_probe(sig.FRIDA_PROCESS_TOKENS),
    "Remove instrumentation servers from the baseline.",
    Severity.HIGH,
)
register(
    "analysis_processes",
    "analysis_tools.processes",
    "Visible analysis and automation processes.",
    process_probe(sig.ANALYSIS_PROCESS_TOKENS),
    "Run monitoring on the host where possible.",
)


for _name, _ports in (("frida_ports", sig.FRIDA_PORTS), ("analysis_ports", tuple(sig.ANALYSIS_PORTS))):

    def _port_probe(ports):
        def probe(dev, ctx):
            rows = need(dev.listening_ports(), "listening sockets")
            hits = sorted({port for _, port in rows if port in ports})
            return Verdict(bool(hits), {"ports": hits}, confidence=0.5)

        return probe

    register(
        _name,
        "analysis_tools.listening_ports",
        "Local listening ports only; no connections or scanning.",
        _port_probe(_ports),
        "Remove unused guest listeners; a port number alone does not identify its owner.",
    )


@REG.check(
    "android.design.adb_tcp",
    "integrity.developer_settings",
    name="ADB TCP transport",
    description="service.adb.tcp.port or persist.adb.tcp.port enables network debugging.",
    severity=Severity.MEDIUM,
    remediation="Disable network adbd outside explicit maintenance windows.",
)
def adb_tcp(dev: Device, ctx: RunContext):
    values = props(dev)
    ports = [
        int(values[k])
        for k in ("service.adb.tcp.port", "persist.adb.tcp.port")
        if values.get(k, "").isdigit() and 0 < int(values[k]) <= 65535
    ]
    return Verdict(bool(ports), {"ports": ports})


@REG.check(
    "android.design.screen_lock",
    "integrity.developer_settings",
    name="Screen lock configured",
    description="dumpsys trust deviceSecure state; no credential is requested or tested.",
    severity=Severity.LOW,
    remediation="Provision a test screen lock and arrange normal unlock activity for analysis runs.",
)
def screen_lock(dev: Device, ctx: RunContext):
    text = need(dev.dumpsys("trust"), "trust service")
    states = re.findall(r"deviceSecure=(true|false|0|1)", text)
    if not states:
        raise Skip("trust service did not expose deviceSecure")
    return Verdict(any(s in ("false", "0") for s in states), {"secure_states": states}, confidence=0.5)


@REG.check(
    "android.design.device_admin",
    "integrity.accessibility_overrides",
    name="Device administration",
    description="Active device administrators or owners may indicate a managed analysis image.",
    severity=Severity.LOW,
    remediation="Review device-policy enrollment; remove test administrators before taking the baseline snapshot.",
)
def device_admin(dev: Device, ctx: RunContext):
    text = need(dev.dumpsys("device_policy"), "device policy")
    count = len(re.findall(r"ComponentInfo\{", text))
    return Verdict(count > 0, {"component_records": count}, confidence=0.3)


@REG.check(
    "android.design.mock_location_apps",
    "integrity.developer_settings",
    name="Mock location app grants",
    description="Read appops MOCK_LOCATION grants, including modern selected mock-location applications.",
    severity=Severity.LOW,
    remediation="Remove test mock-location grants from the baseline.",
)
def mock_apps(dev: Device, ctx: RunContext):
    text = need(dev.sh("cmd appops query-op android:mock_location allow"), "mock location grants")
    if "No operations" in text:
        return Verdict(False, {"packages": 0})
    rows = [v.strip() for v in text.splitlines() if re.fullmatch(r"[\w]+(?:\.[\w]+)+", v.strip())]
    if not rows:
        raise Skip("appops output not recognized")
    return Verdict(True, {"packages": len(rows)})


def target_pid(ctx):
    value = ctx.params.get("android.pid", "")
    if not re.fullmatch(r"[1-9][0-9]{0,8}", value):
        raise Skip("requires --param android.pid=<target process id>")
    return value


@REG.check(
    "android.design.tracer_pid",
    "debugger.tracer",
    name="Target process tracer",
    description="Read TracerPid for the operator-selected PID, subject to procfs permissions.",
    severity=Severity.HIGH,
    remediation="Detach the tracer and use host introspection for routine monitoring.",
)
def tracer(dev: Device, ctx: RunContext):
    text = need(dev.read(f"/proc/{target_pid(ctx)}/status"), "target status")
    match = re.search(r"(?m)^TracerPid:\s*(\d+)", text)
    if not match:
        raise Skip("TracerPid unavailable")
    return Verdict(int(match[1]) > 0, {"traced": int(match[1]) > 0})


@REG.check(
    "android.design.injected_libraries",
    "instrumentation.injected_libraries",
    name="Target mapped libraries",
    description="Read target PID mappings for Frida, Xposed, Zygisk and Substrate markers.",
    severity=Severity.HIGH,
    remediation="Remove injected libraries or run the analysis through host introspection.",
)
def mapped_libraries(dev: Device, ctx: RunContext):
    text = need(dev.read(f"/proc/{target_pid(ctx)}/maps"), "target mappings").lower()
    hits = [
        t for t in ("frida", "xposed", "lsposed", "zygisk", "substrate", "libgadget", "riru") if t in text
    ]
    return Verdict(bool(hits), {"markers": hits})


@REG.check(
    "android.design.frida_threads",
    "instrumentation.hooking_frameworks",
    name="Instrumentation thread names",
    description="Strong Frida thread names; common GLib names such as gmain alone are insufficient.",
    severity=Severity.HIGH,
    remediation="Remove the Frida session and server from the baseline.",
)
def frida_threads(dev: Device, ctx: RunContext):
    text = need(dev.sh("ps -A -T -o PID,TID,NAME"), "thread list")
    if "TID" not in text:
        raise Skip("thread listing unsupported")
    hits = [t for t in sig.FRIDA_THREAD_NAMES_STRONG if t in text]
    return Verdict(bool(hits), {"markers": hits})


@REG.check(
    "android.design.user_certificates",
    "network.proxy_mitm",
    name="User trust anchors",
    description="Count files in the user-added CA store; a directory alone is insufficient.",
    severity=Severity.LOW,
    remediation="Remove analysis CA trust anchors or record enterprise trust as an expected baseline.",
)
def user_certificates(dev: Device, ctx: RunContext):
    rows = dev.listdir("/data/misc/user/0/cacerts-added")
    if rows is None:
        raise Skip("user CA store not readable")
    return Verdict(bool(rows), {"certificate_files": len(rows)}, confidence=0.4)


CHECKS = REG.specs
