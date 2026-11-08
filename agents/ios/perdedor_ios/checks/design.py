"""iOS design-specific tells: jailbreak artifacts, hooking frameworks and
tweak injection, instrumentation and debugging, developer settings, proxies and
interception certificates, network and locale.

Every file list comes from IOSSecuritySuite / DTTJailbreakDetection (see
``signatures``). Probes are read-only: IOSSecuritySuite's
checkRestrictedDirectoriesWriteable writes a file to ``/``; here the same tell
is read from the mount table instead (root file system mounted read-write).
"""

from __future__ import annotations

import re
import shlex
import plistlib

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext
from perdedor_macos import parsing
from perdedor_macos.checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, build, paths_probe, process_probe
from perdedor_macos.checks.design import probe_dns_sinkhole, probe_simulated_internet
from perdedor_macos.transport import join_paths

from .. import signatures as sig
from ..device import IosTarget

P = Platform.IOS
APP_DIRECTORIES = ("/Applications", "/var/jb/Applications")
USER_APP_ROOT = "/var/containers/Bundle/Application"
# Upper bound on per-app container directories inspected (bounded runtime).
MAX_CONTAINERS = 400
TRUST_STORES = ("/private/var/protected/trustd/private/TrustStore.sqlite3", "/private/var/Keychains/TrustStore.sqlite3")
SC_PREFERENCES = "/private/var/preferences/SystemConfiguration/preferences.plist"
GLOBAL_PREFERENCES = "/var/mobile/Library/Preferences/.GlobalPreferences.plist"
DYLD_VARIABLES = ("DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH")


def _sim_skip(target: IosTarget, what: str) -> Result | None:
    if target.is_simulator:
        return Skip(f"{what} does not apply to the Simulator (host files would be judged)")
    return None


def jb_probe(paths, prefixes=sig.ROOTLESS_PREFIXES, *, sim_ok=False):
    inner = paths_probe(paths, prefixes)

    def probe(target: IosTarget, ctx: RunContext) -> Result:
        if not sim_ok:
            skip = _sim_skip(target, "jailbreak file probing")
            if skip:
                return skip
        return inner(target, ctx)

    return probe


def probe_rootless_prefix(target: IosTarget, ctx: RunContext) -> Result:
    info = target.stat(["/var/jb"])
    if info is None:
        return Fail(UNREACHABLE)
    entry = info.get("/var/jb")
    return Verdict(entry is not None, {"/var/jb": None if entry is None else {"kind": entry.kind, "target": entry.target}})


def probe_roothide(target: IosTarget, ctx: RunContext) -> Result:
    listing = target.listdir("/var")
    if listing is None:
        return Fail(UNREACHABLE)
    if listing.entries is None:
        return Fail(f"/var: {listing.error}")
    hits = [e for e in listing.entries if e.startswith(".jbroot-")]
    return Verdict(bool(hits), {"jbroot_dirs": hits})


def probe_symlinks(target: IosTarget, ctx: RunContext) -> Result:
    skip = _sim_skip(target, "stock-directory symlink probing")
    if skip:
        return skip
    info = target.stat(list(sig.STOCK_DIRECTORIES))
    if info is None:
        return Fail(UNREACHABLE)
    hits = {p: i.target for p, i in info.items() if i.kind == "link"}
    return Verdict(bool(hits), {"symlinked": hits})


def parse_root_mount(text: str) -> dict | None:
    """``/dev/disk1s1 on / (apfs, local, read-only, journaled)`` -> device, options."""
    for line in text.splitlines():
        match = re.match(r"^(\S+) on / \(([^)]*)\)", line)
        if match:
            options = [o.strip() for o in match.group(2).split(",")]
            return {"device": match.group(1), "options": options}
    return None


def probe_rootfs_writable(target: IosTarget, ctx: RunContext) -> Result:
    skip = _sim_skip(target, "root mount inspection")
    if skip:
        return skip
    text = target.mount_table()
    if text is None:
        return Fail("mount failed")
    root = parse_root_mount(text)
    if root is None:
        return Fail("no root file system in the mount table")
    writable = "read-only" not in root["options"] and "rdonly" not in root["options"]
    # Stock iOS mounts a sealed snapshot (com.apple.os.update-<hash>@/dev/diskXsY).
    snapshot = root["device"].startswith("com.apple.os.update-")
    return Verdict(writable, {**root, "sealed_snapshot": snapshot})


def _app_names(target: IosTarget) -> tuple[list[str], int] | Result:
    names: list[str] = []
    for directory in APP_DIRECTORIES:
        listing = target.listdir(directory)
        if listing is None:
            return Fail(UNREACHABLE)
        names += [e for e in (listing.entries or ()) if e.endswith(".app")]
    containers = target.listdir(USER_APP_ROOT)
    if containers is None:
        return Fail(UNREACHABLE)
    count = 0
    for uuid in (containers.entries or ())[:MAX_CONTAINERS]:
        inner = target.listdir(f"{USER_APP_ROOT}/{uuid}")
        for entry in (inner.entries if inner and inner.entries else ()):
            if entry.endswith(".app"):
                names.append(entry)
                count += 1
    return names, count


def app_probe(wanted):
    def probe(target: IosTarget, ctx: RunContext) -> Result:
        if target.is_simulator:
            text = target.out("simctl_listapps", f"xcrun simctl listapps {shlex.quote(target._udid())}")
            if text is None:
                return Fail("simctl listapps failed")
            hits = sorted({w for w in wanted if w.lower()[:-4] in text.lower()})
            return Verdict(bool(hits), {"apps": hits})
        result = _app_names(target)
        if not isinstance(result, tuple):
            return result
        hits = parsing.match_names(result[0], wanted)
        return Verdict(bool(hits), {"apps": hits})

    return probe


def declared_url_schemes(text):
    """Only CFBundleURLSchemes arrays, never unrelated Info.plist words."""
    schemes = set()
    for document in re.findall(r"<plist\b.*?</plist>", text, re.DOTALL):
        try:
            data = plistlib.loads(document.encode())
        except (ValueError, plistlib.InvalidFileException):
            continue
        if isinstance(data, dict):
            for item in data.get("CFBundleURLTypes", []):
                if isinstance(item, dict):
                    schemes.update(str(v).lower() for v in item.get("CFBundleURLSchemes", []))
    for array in re.findall(r"CFBundleURLSchemes\s*=\s*\(([^)]*)\)", text):
        schemes.update(v.strip().strip('"').lower() for v in array.split(",") if v.strip())
    return schemes


def probe_url_schemes(target: IosTarget, ctx: RunContext) -> Result:
    if target.is_simulator:
        text = target.out("simctl_listapps", f"xcrun simctl listapps {shlex.quote(target._udid())}")
    else:
        globs = " ".join(f"{d}/*.app/Info.plist" for d in APP_DIRECTORIES) + f" {USER_APP_ROOT}/*/*.app/Info.plist"
        text = target.out("info_plists", f'rc=0; seen=0; for f in {globs}; do '
                          '[ -f "$f" ] || continue; seen=1; plutil -convert xml1 -o - "$f" || rc=1; '
                          'done; [ "$seen" = 1 ] || exit 2; exit "$rc"')
    if text is None or not text.strip():
        return Skip("application URL declarations unavailable")
    tokens = declared_url_schemes(text)
    strong = sorted(tokens.intersection(sig.JAILBREAK_URL_SCHEMES))
    weak = sorted(tokens.intersection(sig.WEAK_URL_SCHEMES))
    return Verdict(bool(strong), {"declared_jailbreak_schemes": strong, "ambiguous_schemes": weak}, confidence=0.6)


def probe_sideloaded(target: IosTarget, ctx: RunContext) -> Result:
    skip = _sim_skip(target, "App Store receipt inspection")
    if skip:
        return skip
    containers = target.listdir(USER_APP_ROOT)
    if containers is None:
        return Fail(UNREACHABLE)
    if containers.entries is None:
        return Fail(f"{USER_APP_ROOT}: {containers.error}")
    uuids = list(containers.entries[:MAX_CONTAINERS])
    metadata = target.exists([f"{USER_APP_ROOT}/{u}/iTunesMetadata.plist" for u in uuids])
    if metadata is None:
        return Fail(UNREACHABLE)
    unofficial = [u for u in uuids if f"{USER_APP_ROOT}/{u}/iTunesMetadata.plist" not in metadata]
    return Verdict(bool(unofficial), {"apps": len(uuids), "without_app_store_metadata": len(unofficial)}, confidence=0.2)


def probe_tweak_dylibs(target: IosTarget, ctx: RunContext) -> Result:
    found = []
    for directory in sig.TWEAK_DIRECTORIES:
        listing = target.listdir(directory)
        if listing is None:
            return Fail(UNREACHABLE)
        found += [f"{directory}/{e}" for e in (listing.entries or ()) if e.endswith(".dylib")]
    return Verdict(bool(found), {"tweaks": len(found), "sample": [f.rsplit("/", 1)[-1] for f in found[:15]]})


def probe_ssl_kill_switch(target: IosTarget, ctx: RunContext) -> Result:
    found = []
    for directory in sig.TWEAK_DIRECTORIES:
        listing = target.listdir(directory)
        if listing is None:
            return Fail(UNREACHABLE)
        found += [e for e in (listing.entries or ()) if parsing.find_tokens(e, sig.SSL_KILL_SWITCH_NAMES)]
    return Verdict(bool(found), {"found": found})


def _proc_names(target: IosTarget, name: str) -> list[int]:
    procs = target.processes() or []
    return [p.pid for p in procs if p.executable == name]


def probe_injected_images(target: IosTarget, ctx: RunContext) -> Result:
    pids = _proc_names(target, "SpringBoard")
    if not pids:
        return Skip("SpringBoard not running (or ps unavailable)")
    result = target.run("lsof_springboard", f"lsof -p {pids[0]} -Fn")
    if result is None:
        return Fail(UNREACHABLE)
    if not result.ok:
        return Skip("lsof unavailable or target process mappings denied")
    images = sorted({line[1:] for line in result.stdout.splitlines() if line.startswith("n") and ".dylib" in line})
    hits = [i for i in images if parsing.find_tokens(i.rsplit("/", 1)[-1], sig.SUSPICIOUS_LIBRARIES)]
    if not images:
        return Skip("no readable mapped libraries; cannot infer absence of injection")
    return Verdict(bool(hits), {"process": "SpringBoard", "suspicious_images": hits[:20], "dylibs": len(images)})


def probe_dyld_env(target: IosTarget, ctx: RunContext) -> Result:
    found = {}
    available = False
    for name in DYLD_VARIABLES:
        value = target.env_value(name)
        available = available or value is not None
        if value:
            found[name] = value
    if not available:
        return Skip("launchd environment unavailable")
    return Verdict(bool(found), found or None)


def probe_frida_files(target: IosTarget, ctx: RunContext) -> Result:
    return jb_probe(sig.FRIDA_FILES)(target, ctx)


def probe_ports(target: IosTarget, ctx: RunContext) -> Result:
    text = target.out("netstat_listen", "netstat -an -p tcp")
    if text is None:
        text = target.out("lsof_listen", "lsof -nP -iTCP -sTCP:LISTEN")
    if text is None:
        return Fail("netstat / lsof failed")
    ports = parsing.parse_listen_ports(text)
    hits = {p: sig.SUSPICIOUS_PORTS[p] for p in ports if p in sig.SUSPICIOUS_PORTS}
    if target.is_simulator:
        hits.pop(22, None)  # the host Mac's own sshd is not the Simulator's
    return Verdict(bool(hits), {"ports": hits})


def probe_developer_mode(target: IosTarget, ctx: RunContext) -> Result:
    values = target.sysctl()
    if values is None:
        return Fail(UNREACHABLE + " (sysctl)")
    value = values.get("security.mac.amfi.developer_mode_status")
    if value is None:
        return Skip("security.mac.amfi.developer_mode_status not exposed (iOS < 16)")
    return Verdict(value.strip() == "1", {"developer_mode_status": value})


def probe_developer_disk_image(target: IosTarget, ctx: RunContext) -> Result:
    skip = _sim_skip(target, "Developer disk image inspection")
    if skip:
        return skip
    text = target.mount_table()
    if text is None:
        return Fail("mount failed")
    mounts = [line for line in text.splitlines() if " on /Developer " in line or "/private/var/personalized_" in line]
    return Verdict(bool(mounts), {"developer_mounts": mounts})


def probe_traced(target: IosTarget, ctx: RunContext) -> Result:
    procs = target.processes()
    if procs is None:
        return Fail(UNREACHABLE + " (ps)")
    hits = [f"{p.pid} {p.executable}" for p in parsing.traced(procs)]
    return Verdict(bool(hits), {"traced_processes": hits[:20]})


def probe_app_parent(target: IosTarget, ctx: RunContext) -> Result:
    procs = target.processes()
    if procs is None:
        return Fail(UNREACHABLE + " (ps)")
    by_pid = {p.pid: p for p in procs}
    apps = [p for p in procs if "/Containers/Bundle/Application/" in p.command or "/Applications/" in p.command]
    if target.is_simulator:
        launchd_sim = {p.pid for p in procs if p.executable == "launchd_sim"}
        odd = [p for p in apps if p.ppid not in launchd_sim and "CoreSimulator" in p.command]
    else:
        odd = [p for p in apps if p.ppid != 1]
    hits = [f"{p.pid} {p.executable} <- {by_pid[p.ppid].executable if p.ppid in by_pid else p.ppid}" for p in odd]
    return Verdict(bool(hits), {"apps_not_launched_by_launchd": hits[:20], "apps": len(apps)})


def probe_proxy(target: IosTarget, ctx: RunContext) -> Result:
    if target.is_simulator:
        text = target.out("scutil_proxy", "scutil --proxy")
        if text is None:
            return Fail("scutil --proxy failed")
        values = parsing.parse_scutil_proxy(text)
        enabled = [k for k in ("HTTPEnable", "HTTPSEnable", "ProxyAutoConfigEnable") if values.get(k) == "1"]
        return Verdict(bool(enabled), {"host_proxy_enabled": enabled})
    document = target.read_plist(SC_PREFERENCES)
    if not isinstance(document, dict):
        return Skip("system network preferences unavailable")
    def enabled_keys(value):
        found = set()
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ("HTTPEnable", "HTTPSEnable", "ProxyAutoConfigEnable", "SOCKSEnable") and child == 1:
                    found.add(key)
                found.update(enabled_keys(child))
        elif isinstance(value, list):
            for child in value:
                found.update(enabled_keys(child))
        return found
    enabled = sorted(enabled_keys(document))
    return Verdict(bool(enabled), {"enabled_proxy_keys": enabled}, confidence=0.5)


def probe_mitm_certs(target: IosTarget, ctx: RunContext) -> Result:
    counts = [target.sqlite_count(path, "tsettings") for path in TRUST_STORES]
    readable = [count for count in counts if count is not None]
    if not readable:
        return Skip("user trust database unavailable or schema unsupported")
    count = max(readable)
    return Verdict(count > 0, {"user_trust_records": count}, confidence=0.3)


def probe_mac_oui(target: IosTarget, ctx: RunContext) -> Result:
    text = target.out("ifconfig", "ifconfig -a")
    if text is None:
        return Fail("ifconfig failed")
    macs = parsing.parse_ifconfig_macs(text)
    hits = {i: f"{m} ({sig.HYPERVISOR_OUIS[m[:8]]})" for i, m in macs.items() if m[:8] in sig.HYPERVISOR_OUIS}
    return Verdict(bool(hits), {"matched": hits})


def _languages(target: IosTarget) -> list[str] | None:
    blob = target.read_text(GLOBAL_PREFERENCES)
    if blob is None:
        return None
    strings = parsing.strings_of(blob)
    return re.findall(r"\b([a-z]{2,3}(?:[-_][A-Za-z]{2,4})*)\b", strings.split("AppleLanguages", 1)[-1])[:10]


def probe_cis_locale(target: IosTarget, ctx: RunContext) -> Result:
    langs = _languages(target)
    if langs is None:
        return Fail(f"{GLOBAL_PREFERENCES} unreadable")
    hits = [code for code in langs if code.split("-")[0].split("_")[0] in sig.CIS_LANGUAGE_PREFIXES]
    return Verdict(bool(hits), {"languages": langs, "cis": hits})


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


_JB_FIX = "Use a non-jailbroken device for evasive samples, or hide the jailbreak (rootless + path hiding)."
_HOOK_FIX = "Remove tweak injection from the analysis device; instrument from outside the device instead."
_JB_GROUPS = {
    "rootless_bootstrap": ("Rootless bootstrap files", Severity.CRITICAL),
    "dopamine": ("Dopamine jailbreak files", Severity.CRITICAL),
    "palera1n": ("palera1n jailbreak files", Severity.CRITICAL),
    "checkra1n": ("checkra1n jailbreak files", Severity.CRITICAL),
    "unc0ver": ("unc0ver jailbreak files", Severity.CRITICAL),
    "electra": ("Electra jailbreak files", Severity.CRITICAL),
    "package_managers": ("Jailbreak package managers", Severity.CRITICAL),
    "apt_dpkg": ("APT / dpkg state", Severity.HIGH),
    "shell_binaries": ("Shell and SSH binaries", Severity.HIGH),
    "bypass_tweaks": ("Jailbreak-detection bypass tweaks", Severity.HIGH),
    "legacy_apps": ("Legacy jailbreak apps", Severity.HIGH),
}
_HOOK_NAMES = {"substrate": "Cydia Substrate", "substitute": "Substitute", "libhooker": "libhooker",
               "ellekit": "ElleKit"}

CHECKS = [
    _c("ios.design.jb_rootless_prefix", "integrity.jailbreak", "Rootless jailbreak prefix /var/jb",
       "/var/jb exists (symlink to the rootless bootstrap; IOSSecuritySuite checkSymbolicLinks).", Severity.CRITICAL,
       _JB_FIX, probe_rootless_prefix),
    _c("ios.design.jb_roothide", "integrity.jailbreak", "RootHide jbroot directory",
       "/var/.jbroot-<hex> directory of a RootHide jailbreak.", Severity.CRITICAL, _JB_FIX, probe_roothide),
    *[
        _c(f"ios.design.jb_{group}", "integrity.jailbreak", name,
           f"Files of the {group.replace('_', ' ')} group from IOSSecuritySuite checkExistenceOfSuspiciousFiles.",
           severity, _JB_FIX, jb_probe(sig.JAILBREAK_GROUPS[group]))
        for group, (name, severity) in _JB_GROUPS.items()
    ],
    _c("ios.design.jb_symlinks", "integrity.jailbreak", "Stock directories turned into symlinks",
       "/Applications, /usr/libexec, /usr/share... are symlinks (IOSSecuritySuite checkSymbolicLinks).",
       Severity.HIGH, _JB_FIX, probe_symlinks),
    _c("ios.design.jb_rootfs_writable", "integrity.jailbreak", "Root file system writable",
       "The root file system is mounted read-write (IOSSecuritySuite checkRestrictedDirectoriesWriteable, read-only variant).",
       Severity.CRITICAL, _JB_FIX, probe_rootfs_writable),
    _c("ios.design.jb_url_schemes", "integrity.jailbreak", "Jailbreak URL schemes registered",
       "An installed app registers undecimus://, sileo://, zbra://, filza://, dopamine:// or palera1n:// (IOSSecuritySuite checkURLSchemes).",
       Severity.HIGH, _JB_FIX, probe_url_schemes, cost="medium"),
    _c("ios.design.jb_apps", "integrity.jailbreak", "Jailbreak applications",
       "Cydia, Sileo, Zebra, Filza, Dopamine, palera1n loader, unc0ver, Taurine, Odyssey... installed.",
       Severity.CRITICAL, _JB_FIX, app_probe(sig.JAILBREAK_APPS), cost="medium"),
    _c("ios.design.trollstore", "integrity.jailbreak", "TrollStore installed",
       "TrollStore (permanent sideloading through a CoreTrust bug) is installed.", Severity.HIGH,
       "Remove TrollStore and its apps from the analysis device.", app_probe(sig.TROLLSTORE_APPS), cost="medium"),
    _c("ios.design.sideloaded_apps", "integrity.jailbreak", "Apps without App Store metadata",
       "User apps without iTunesMetadata.plist: installed outside the App Store (freeRASP unofficialStore).",
       Severity.LOW, "Install analysis-environment apps from the App Store.", probe_sideloaded, cost="medium"),
    *[
        _c(f"ios.design.hook_{key}", "instrumentation.hooking_frameworks", f"{label} installed",
           f"{label} hooking framework files present (IOSSecuritySuite suspicious files / dyld list).", Severity.HIGH,
           _HOOK_FIX, jb_probe(sig.HOOKING_FRAMEWORKS[key]))
        for key, label in _HOOK_NAMES.items()
    ],
    _c("ios.design.tweak_dylibs", "instrumentation.injected_libraries", "Tweak libraries",
       "Dynamic libraries in MobileSubstrate/DynamicLibraries or TweakInject: injected into apps.", Severity.HIGH,
       _HOOK_FIX, probe_tweak_dylibs),
    _c("ios.design.ssl_kill_switch", "network.proxy_mitm", "SSL pinning bypass tweak",
       "SSLKillSwitch / SSL bypass tweak installed (disables certificate validation for interception).",
       Severity.HIGH, "Remove TLS-bypass tweaks; intercept with a trusted CA where needed.", probe_ssl_kill_switch),
    _c("ios.design.injected_images", "instrumentation.injected_libraries", "Suspicious images in SpringBoard",
       "SpringBoard has a jailbreak or instrumentation library mapped (IOSSecuritySuite checkDYLD, via lsof).",
       Severity.HIGH, _HOOK_FIX, probe_injected_images, cost="medium"),
    _c("ios.design.dyld_environment", "instrumentation.injected_libraries", "DYLD injection variables",
       "DYLD_INSERT_LIBRARIES or related variables set in launchd's environment.", Severity.HIGH, _HOOK_FIX,
       probe_dyld_env),
    _c("ios.design.frida_files", "instrumentation.hooking_frameworks", "frida-server installed",
       "frida-server binary, library directory or launch daemon present (IOSSecuritySuite).", Severity.HIGH,
       "Remove frida-server from the device; attach only for targeted debugging.", probe_frida_files),
    _c("ios.design.frida_processes", "instrumentation.hooking_frameworks", "Frida processes",
       "frida-server or frida-helper running.", Severity.HIGH, "Stop frida-server during detonation.",
       process_probe(("frida-server", "frida-helper", "frida"))),
    _c("ios.design.cycript", "instrumentation.hooking_frameworks", "Cycript installed",
       "cycript / libcycript / cynject present (IOSSecuritySuite ReverseEngineeringToolsChecker).", Severity.MEDIUM,
       _HOOK_FIX, jb_probe(sig.CYCRIPT_FILES)),
    _c("ios.design.listening_ports", "analysis_tools.listening_ports", "Instrumentation ports listening",
       "Ports 27042 (Frida), 4444 (Needle), 22 (OpenSSH) or 44 (checkra1n) listening (IOSSecuritySuite checkOpenedPorts).",
       Severity.HIGH, "Close instrumentation and SSH ports during detonation (use USB-only access).", probe_ports),
    _c("ios.design.analysis_processes", "analysis_tools.processes", "Analysis tool processes",
       "debugserver, lldb, cycript, tcpdump, sslsplit or objection running.", Severity.HIGH,
       "Stop analysis tools on the device during detonation.", process_probe(sig.ANALYSIS_PROCESSES)),
    _c("ios.design.analysis_files", "analysis_tools.files", "Analysis tool files",
       "debugserver, tcpdump, class-dump, lldb or gdb installed on the device.", Severity.MEDIUM,
       "Remove analysis tools from the device image.", jb_probe(sig.ANALYSIS_FILES)),
    _c("ios.design.developer_mode", "integrity.developer_settings", "Developer Mode",
       "security.mac.amfi.developer_mode_status = 1 (iOS 16+ Developer Mode on).", Severity.MEDIUM,
       "Turn Developer Mode off on the analysis device.", probe_developer_mode),
    _c("ios.design.developer_disk_image", "integrity.developer_settings", "Developer disk image mounted",
       "/Developer (DDI) or a personalized developer image is mounted: Xcode/debugging attached.", Severity.MEDIUM,
       "Reboot the device after debugging to unmount the developer image.", probe_developer_disk_image),
    _c("ios.design.traced_processes", "debugger.tracer", "Traced processes (P_TRACED)",
       "Processes with P_TRACED set (IOSSecuritySuite amIDebugged).", Severity.HIGH,
       "Do not attach debuggers during detonation.", probe_traced),
    _c("ios.design.app_parent_process", "debugger.api_flags", "Apps not launched by launchd",
       "An app process whose parent is not launchd (IOSSecuritySuite isParentPidUnexpected): spawned by a debugger or Frida.",
       Severity.HIGH, "Launch apps normally (SpringBoard / launchd).", probe_app_parent),
    _c("ios.design.proxy_settings", "network.proxy_mitm", "HTTP proxy configured",
       "System proxy keys present in SystemConfiguration preferences (IOSSecuritySuite amIProxied).", Severity.MEDIUM,
       "Intercept transparently at the network layer instead of a device proxy.", probe_proxy),
    _c("ios.design.mitm_certificates", "network.proxy_mitm", "Interception root certificates",
       "The user trust store holds mitmproxy / Charles / Proxyman / PortSwigger / HTTP Toolkit roots.", Severity.HIGH,
       "Remove interception roots from the analysis device.", probe_mitm_certs),
    _c("ios.design.mac_oui", "network.mac_oui", "Hypervisor MAC OUI",
       "An interface MAC belongs to a hypervisor vendor (iOS private addresses are random, never a VM OUI).",
       Severity.HIGH, "Give the virtual device a random or Apple MAC.", probe_mac_oui),
    _c("ios.design.dns_sinkhole", "network.dns_sinkhole", "DNS answers non-existent names",
       "A random non-existent name resolves (fake DNS).", Severity.HIGH,
       "Return NXDOMAIN for names the simulated internet does not serve.", probe_dns_sinkhole, network=True),
    _c("ios.design.simulated_internet", "network.simulated_internet", "HTTP answers for random hosts",
       "A random non-existent host returns HTTP (simulated internet).", Severity.HIGH,
       "Only answer HTTP for names that resolve.", probe_simulated_internet, network=True),
    _c("ios.design.cis_locale", "identity.locale", "CIS language",
       "Preferred languages include Russian or another CIS language (stealer guardrail).", Severity.MEDIUM,
       "Use the language of the target population.", probe_cis_locale),
]
