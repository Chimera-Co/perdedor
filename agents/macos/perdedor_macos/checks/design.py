"""Design-specific tells on macOS: platform security configuration, analysis
tools, instrumentation, debugger state, network set-up and identity.

Sources: VMAware MAC_SIP; Check Point macOS chapter (SIP); Objective-See tool
list; Elastic BANSHEE analysis (Russian-language guardrail, sysctl debugger
check); IOSSecuritySuite amIProxied / amIDebugged (same Darwin APIs on macOS).
"""

from __future__ import annotations

import random
import re
import shlex
import string
from datetime import datetime, timezone

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext

from .. import parsing
from .. import signatures as sig
from ..checkkit import (
    UNREACHABLE,
    Fail,
    Meta,
    Result,
    Skip,
    Verdict,
    app_bundles,
    build,
    process_probe,
)
from ..target import Target

P = Platform.MACOS

XPROTECT_PLIST = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
XPROTECT_REMEDIATOR = "/Library/Apple/System/Library/CoreServices/XProtect.app"
SOFTWARE_UPDATE_PLIST = "/Library/Preferences/com.apple.SoftwareUpdate"
# Boot arguments that put the kernel in debug mode or disable code-signing /
# AMFI enforcement (XNU boot-args, documented in Apple's KDK ReadMe and the
# AMFI boot-arg used by research setups).
DEBUG_BOOT_ARGS = ("debug=", "kdp_match_name", "kcsuffix=development", "-zp", "wdt=-1", "pmuflags")
AMFI_BOOT_ARGS = (
    "amfi_get_out_of_my_way",
    "amfi=",
    "cs_enforcement_disable",
    "-arm64e_preview_abi",
    "ipc_control_port_options=0",
)
DYLD_VARIABLES = (
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
)
# System extension identifiers / team names of analysis and monitoring tools.
SYSEXT_TOKENS = (
    "objective-see",
    "lulu",
    "blockblock",
    "obdev",
    "littlesnitch",
    "processmonitor",
    "filemonitor",
    "dnsmonitor",
    "mitmproxy",
    "proxyman",
    "wireshark",
    "charles",
)
RANDOM_LABEL_LENGTH = 20
CURL_TIMEOUT_SECONDS = 5


def _profiler_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S %z"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def target_now(target: Target) -> datetime | None:
    text = target.out("date_epoch", "date +%s", timeout=10.0)
    if not text or not text.strip().isdigit():
        return None
    return datetime.fromtimestamp(int(text.strip()), tz=timezone.utc)


def install_history(target: Target) -> list[dict] | None:
    doc = target.profiler("SPInstallHistoryDataType", timeout=90.0)
    if doc is None:
        return None
    return parsing.profiler_items(doc, "SPInstallHistoryDataType")


# -- platform security -------------------------------------------------------------------


def _csrutil(target: Target) -> dict | None:
    text = target.out("csrutil_status", "csrutil status")
    return parsing.parse_csrutil(text) if text else None


def probe_sip(target: Target, ctx: RunContext) -> Result:
    status = _csrutil(target)
    if status is None:
        return Fail("csrutil status failed")
    if status["state"] == "unknown":
        return Skip("csrutil reports an unknown state (common inside VMs booted without NVRAM support)")
    disabled = status["state"].startswith("disabled") or any(
        v == "disabled" for v in status["protections"].values()
    )
    return Verdict(disabled, status)


def probe_sip_dtrace(target: Target, ctx: RunContext) -> Result:
    status = _csrutil(target)
    if status is None:
        return Fail("csrutil status failed")
    if status["state"] == "unknown":
        return Skip("SIP state unknown")
    dtrace = status["protections"].get("DTrace Restrictions")
    if dtrace is None:
        dtrace = "disabled" if status["state"].startswith("disabled") else "enabled"
    return Verdict(dtrace == "disabled", {"dtrace_restrictions": dtrace, "sip": status["state"]})


def probe_authenticated_root(target: Target, ctx: RunContext) -> Result:
    text = target.out("csrutil_authroot", "csrutil authenticated-root status")
    if text is None:
        return Skip("csrutil authenticated-root not available (macOS < 11)")
    if not re.search(r"authenticated root status: (enabled|disabled)", text, re.IGNORECASE):
        return Skip("authenticated-root status unrecognized")
    return Verdict("disabled" in text.lower(), {"output": text.strip()[:200]})


def probe_gatekeeper(target: Target, ctx: RunContext) -> Result:
    result = target.run("spctl_status", "spctl --status")
    if result is None:
        return Fail(UNREACHABLE)
    text = (result.stdout + result.stderr).strip()
    if not re.search(r"assessments (?:enabled|disabled)", text, re.IGNORECASE):
        return Skip("spctl status not recognized on this OS version")
    return Verdict("disabled" in text.lower(), {"spctl": text[:200]})


def _bootargs(target: Target) -> str | None:
    values = target.sysctl()
    if values is None:
        return None
    args = values.get("kern.bootargs") or ""
    nvram = target.out("nvram_bootargs", "nvram boot-args 2>/dev/null")
    if nvram:
        args += " " + nvram.partition("\t")[2]
    return args.strip()


def probe_boot_args_debug(target: Target, ctx: RunContext) -> Result:
    args = _bootargs(target)
    if args is None:
        return Fail(UNREACHABLE + " (sysctl)")
    hits = parsing.find_tokens(args, DEBUG_BOOT_ARGS)
    return Verdict(bool(hits), {"boot_args": args, "matched": hits})


def probe_boot_args_amfi(target: Target, ctx: RunContext) -> Result:
    args = _bootargs(target)
    if args is None:
        return Fail(UNREACHABLE + " (sysctl)")
    hits = parsing.find_tokens(args, AMFI_BOOT_ARGS)
    return Verdict(bool(hits), {"boot_args": args, "matched": hits})


def probe_xprotect(target: Target, ctx: RunContext) -> Result:
    found = target.exists([XPROTECT_PLIST, XPROTECT_REMEDIATOR])
    if found is None:
        return Fail(UNREACHABLE)
    version = target.out(
        "xprotect_version", f"defaults read {shlex.quote(XPROTECT_PLIST[:-6])} CFBundleShortVersionString"
    )
    missing = [p for p in (XPROTECT_PLIST, XPROTECT_REMEDIATOR) if p not in found]
    return Verdict(
        XPROTECT_PLIST not in found, {"missing": missing, "xprotect_version": (version or "").strip()}
    )


def probe_security_data_age(target: Target, ctx: RunContext) -> Result:
    history = install_history(target)
    now = target_now(target)
    if history is None or now is None:
        return Fail("system_profiler SPInstallHistoryDataType or date unavailable")
    dates = [
        _profiler_date(item.get("install_date"))
        for item in history
        if parsing.find_tokens(str(item.get("_name")), ("xprotect", "mrt", "gatekeeper"))
    ]
    dates = [d for d in dates if d]
    if not dates:
        return Verdict(True, {"note": "no XProtect / Gatekeeper data update ever installed"})
    age = (now - max(dates)).days
    limit = ctx.param("updates.max_age_days", sig.MAX_UPDATE_AGE_DAYS)
    return Verdict(
        age > limit, {"last_security_data_update_days": age}, measurement={"value": age, "threshold": limit}
    )


def probe_software_update(target: Target, ctx: RunContext) -> Result:
    keys = ("AutomaticCheckEnabled", "ConfigDataInstall", "CriticalUpdateInstall")
    disabled = []
    observed = []
    for key in keys:
        result = target.run(f"softwareupdate_{key}", f"defaults read {SOFTWARE_UPDATE_PLIST} {key}")
        if result is None:
            return Fail(UNREACHABLE)
        if result.ok and result.stdout.strip() in ("0", "1"):
            observed.append(key)
        if result.ok and result.stdout.strip() == "0":
            disabled.append(key)
    if not observed:
        return Skip("automatic update preferences unavailable or using OS defaults")
    return Verdict(bool(disabled), {"disabled": disabled, "observed": observed})


def probe_os_update_age(target: Target, ctx: RunContext) -> Result:
    history = install_history(target)
    now = target_now(target)
    if history is None or now is None:
        return Fail("system_profiler SPInstallHistoryDataType or date unavailable")
    dates = [
        _profiler_date(item.get("install_date"))
        for item in history
        if re.search(r"\bmacOS\b|Security Response|Background Security", str(item.get("_name")))
    ]
    dates = [d for d in dates if d]
    if not dates:
        return Verdict(True, {"note": "no macOS update in install history"})
    age = (now - max(dates)).days
    limit = ctx.param("updates.max_age_days", sig.MAX_UPDATE_AGE_DAYS)
    return Verdict(age > limit, {"last_os_update_days": age}, measurement={"value": age, "threshold": limit})


# -- analysis tools -------------------------------------------------------------------------


def app_group_probe(names):
    def probe(target: Target, ctx: RunContext) -> Result:
        home = target.home()
        dirs = ["/Applications", "/Applications/Utilities"] + ([f"{home}/Applications"] if home else [])
        apps, unreadable = app_bundles(target, dirs)
        if not apps and len(unreadable) == len(dirs):
            return Fail("no application directory readable")
        hits = parsing.match_names(apps, names)
        return Verdict(bool(hits), {"apps": hits})

    return probe


def probe_cli_tools(target: Target, ctx: RunContext) -> Result:
    home = target.home()
    dirs = list(sig.ANALYSIS_CLI_DIRS) + ([f"{home}/.local/bin"] if home else [])
    candidates = [f"{d}/{tool}" for d in dirs for tool in sig.ANALYSIS_CLI_TOOLS]
    found = target.exists(candidates)
    if found is None:
        return Fail(UNREACHABLE)
    hits = [c for c in candidates if c in found]
    return Verdict(bool(hits), {"found": hits})


def probe_system_extensions(target: Target, ctx: RunContext) -> Result:
    text = target.out("systemextensions", "systemextensionsctl list")
    if text is None:
        return Skip("systemextensionsctl list failed (macOS < 10.15 or not permitted)")
    lines = [line for line in text.splitlines() if "[activated" in line]
    hits = [line.strip()[:160] for line in lines if parsing.find_tokens(line, SYSEXT_TOKENS)]
    return Verdict(bool(hits), {"extensions": hits, "active": len(lines)})


def probe_dyld_env(target: Target, ctx: RunContext) -> Result:
    found = {}
    for name in DYLD_VARIABLES:
        result = target.run(f"getenv_{name}", f"launchctl getenv {name}")
        if result is None:
            return Fail(UNREACHABLE)
        if result.ok and result.stdout.strip():
            found[f"launchd:{name}"] = result.stdout.strip()
    env = target.out("env", "env")
    if env is None and not found:
        return Fail("session environment unavailable")
    for line in (env or "").splitlines():
        key, _, value = line.partition("=")
        if key in DYLD_VARIABLES and value:
            found[f"session:{key}"] = value
    return Verdict(bool(found), found or None)


def probe_traced(target: Target, ctx: RunContext) -> Result:
    procs = target.processes()
    if procs is None:
        return Fail(UNREACHABLE + " (ps)")
    hits = [f"{p.pid} {p.executable}" for p in parsing.traced(procs)]
    return Verdict(bool(hits), {"traced_processes": hits[:20]})


def _listening(target: Target) -> set[int] | None:
    text = target.out("netstat_listen", "netstat -an -p tcp")
    if text is None:
        text = target.out("lsof_listen", "lsof -nP -iTCP -sTCP:LISTEN")
    return None if text is None else parsing.parse_listen_ports(text)


def probe_listening_ports(target: Target, ctx: RunContext) -> Result:
    ports = _listening(target)
    if ports is None:
        return Fail("netstat / lsof failed")
    hits = {p: sig.AGENT_PORTS[p] for p in ports if p in sig.AGENT_PORTS}
    return Verdict(bool(hits), {"agent_ports": hits, "listening": sorted(ports)[:40]})


# -- network ------------------------------------------------------------------------------------


def _ifconfig(target: Target) -> str | None:
    return target.out("ifconfig", "ifconfig -a")


def _hardware_ports(target: Target) -> list[dict] | None:
    text = target.out("hardware_ports", "networksetup -listallhardwareports")
    return None if text is None else parsing.parse_hardware_ports(text)


def probe_mac_oui(target: Target, ctx: RunContext) -> Result:
    text = _ifconfig(target)
    if text is None:
        return Fail("ifconfig failed")
    macs = parsing.parse_ifconfig_macs(text)
    hits = {i: f"{m} ({sig.HYPERVISOR_OUIS[m[:8]]})" for i, m in macs.items() if m[:8] in sig.HYPERVISOR_OUIS}
    return Verdict(bool(hits), {"matched": hits, "interfaces": macs})


def probe_mac_local(target: Target, ctx: RunContext) -> Result:
    text = _ifconfig(target)
    ports = _hardware_ports(target)
    if text is None or ports is None:
        return Fail("ifconfig / networksetup failed")
    wifi = {p.get("Device") for p in ports if "wi-fi" in p.get("Hardware Port", "").lower()}
    # Thunderbolt ports carry locally administered MACs on real Macs; only
    # Ethernet ports are judged.
    wired = [
        p.get("Device")
        for p in ports
        if "ethernet" in p.get("Hardware Port", "").lower() and p.get("Device") not in wifi
    ]
    macs = parsing.parse_ifconfig_macs(text)
    # Private Wi-Fi addresses are locally administered by design (macOS 15), so
    # only wired interfaces are judged.
    hits = {d: macs[d] for d in wired if d in macs and parsing.mac_is_locally_administered(macs[d])}
    if not wired:
        return Skip("no Ethernet interface")
    return Verdict(bool(hits), {"locally_administered": hits, "wired": wired})


def probe_default_subnets(target: Target, ctx: RunContext) -> Result:
    text = _ifconfig(target)
    if text is None:
        return Fail("ifconfig failed")
    addrs = parsing.parse_ifconfig_inet(text)
    hits = {}
    for iface, ips in addrs.items():
        if iface.startswith(("bridge", "vmnet", "lo")):
            continue  # host-side bridges of a Mac that runs VMs itself
        for ip in ips:
            for prefix, label in sig.DEFAULT_SUBNETS.items():
                if ip.startswith(prefix):
                    hits[iface] = f"{ip} ({label})"
    return Verdict(bool(hits), {"matched": hits})


def probe_wifi_hardware(target: Target, ctx: RunContext) -> Result:
    ports = _hardware_ports(target)
    if ports is None:
        return Fail("networksetup -listallhardwareports failed")
    names = [p.get("Hardware Port", "") for p in ports]
    return Verdict(not any("wi-fi" in n.lower() or "airport" in n.lower() for n in names), {"ports": names})


def probe_adapter_count(target: Target, ctx: RunContext) -> Result:
    ports = _hardware_ports(target)
    if ports is None:
        return Fail("networksetup -listallhardwareports failed")
    physical = [p for p in ports if p.get("Device", "").startswith("en")]
    return Verdict(
        len(physical) < sig.MIN_NETWORK_PORTS, {"physical_ports": [p.get("Hardware Port") for p in physical]}
    )


def probe_default_route(target: Target, ctx: RunContext) -> Result:
    result = target.run("route_default", "route -n get default")
    if result is None:
        return Fail(UNREACHABLE)
    if not result.ok:
        if "not in table" in (result.stdout + result.stderr).lower():
            return Verdict(True, {"default_route": "absent"})
        return Skip("default route query failed")
    gateway = re.search(r"gateway:\s*(\S+)", result.stdout)
    if gateway is None:
        return Skip("default route format unsupported")
    return Verdict(False, {"gateway": gateway.group(1)})


def random_domain() -> str:
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=RANDOM_LABEL_LENGTH))
    return f"{label}.invalid"


def curl_probe(target: Target, key: str, url: str) -> tuple[int, str, str] | None:
    """(curl exit code, HTTP status, remote IP). Exit 6 = name did not resolve."""
    command = (
        f"curl -q -s -o /dev/null --noproxy '*' -m {CURL_TIMEOUT_SECONDS} "
        f"-w '%{{http_code}} %{{remote_ip}}' {shlex.quote(url)}; echo \" rc=$?\""
    )
    result = target.run(key, command, timeout=CURL_TIMEOUT_SECONDS + 10, cache=False)
    if result is None:
        return None
    match = re.search(r"^(\d{3})\s*(\S*)\s*rc=(\d+)", result.stdout.strip())
    if not match:
        return None
    return int(match.group(3)), match.group(1), match.group(2)


def probe_dns_sinkhole(target: Target, ctx: RunContext) -> Result:
    name = random_domain()
    answer = curl_probe(target, "curl_dns", f"http://{name}/")
    if answer is None:
        return Fail("curl did not run")
    rc, code, ip = answer
    if rc not in (0, 6, 7, 28) or (rc != 6 and not ip):
        return Skip("DNS outcome unavailable: curl did not obtain an address")
    resolved = bool(ip)
    return Verdict(resolved, {"name": name, "curl_exit": rc, "resolved_to": ip or None, "http_code": code})


def probe_simulated_internet(target: Target, ctx: RunContext) -> Result:
    name = random_domain()
    answer = curl_probe(target, "curl_http", f"http://{name}/")
    if answer is None:
        return Fail("curl did not run")
    rc, code, ip = answer
    if rc != 0:
        return Skip("HTTP outcome unavailable: DNS or connectivity failed")
    return Verdict(code != "000", {"name": name, "http_code": code, "remote_ip": ip or None})


def probe_cloud_metadata(target: Target, ctx: RunContext) -> Result:
    answer = curl_probe(target, "curl_metadata", "http://169.254.169.254/latest/meta-data/")
    if answer is None:
        return Fail("curl did not run")
    rc, code, _ = answer
    if rc != 0:
        return Skip("metadata endpoint unreachable or timed out")
    return Verdict(code.startswith("2"), {"http_code": code, "curl_exit": rc})


def probe_proxy(target: Target, ctx: RunContext) -> Result:
    text = target.out("scutil_proxy", "scutil --proxy")
    if text is None:
        return Fail("scutil --proxy failed")
    values = parsing.parse_scutil_proxy(text)
    enabled = [
        k
        for k in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable")
        if values.get(k) == "1"
    ]
    return Verdict(
        bool(enabled),
        {"enabled": enabled, "HTTPProxy": values.get("HTTPProxy"), "HTTPSProxy": values.get("HTTPSProxy")},
    )


def probe_mitm_certs(target: Target, ctx: RunContext) -> Result:
    command = (
        "security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null && "
        "security find-certificate -a 2>/dev/null"
    )
    text = target.out("keychain_certs", command, timeout=30.0)
    if text is None:
        return Fail("security find-certificate failed")
    labels = sorted(set(re.findall(r'"labl"<blob>="([^"]*)"', text)))
    hits = [label for label in labels if parsing.find_tokens(label, sig.MITM_CERT_TOKENS)]
    return Verdict(bool(hits), {"certificates": hits, "total": len(labels)})


# -- identity -----------------------------------------------------------------------------------


def probe_username(target: Target, ctx: RunContext) -> Result:
    user = target.out("whoami", "id -un")
    if user is None:
        return Fail("id -un failed")
    user = user.strip()
    return Verdict(user.lower() in sig.SANDBOX_USERNAMES, {"user": user})


def _names(target: Target) -> dict[str, str] | None:
    out = {}
    for key in ("ComputerName", "LocalHostName", "HostName"):
        result = target.run(f"scutil_{key}", f"scutil --get {key}")
        if result is None:
            return None
        if result.ok:
            out[key] = result.stdout.strip()
    return out or None


def probe_hostname(target: Target, ctx: RunContext) -> Result:
    names = _names(target)
    if names is None:
        return Fail(UNREACHABLE)
    text = " ".join(names.get(k, "") for k in ("LocalHostName", "HostName"))
    if not text.strip():
        return Skip("host names unavailable")
    hits = parsing.find_tokens(text, sig.SANDBOX_HOSTNAME_TOKENS)
    return Verdict(bool(hits), {**names, "matched": hits})


def probe_computer_name(target: Target, ctx: RunContext) -> Result:
    names = _names(target)
    if names is None:
        return Fail(UNREACHABLE)
    name = names.get("ComputerName", "")
    if not name:
        return Skip("ComputerName unavailable")
    hits = parsing.find_tokens(name.replace("’", "'"), sig.SANDBOX_HOSTNAME_TOKENS)
    return Verdict(bool(hits), {"ComputerName": name, "matched": hits})


def probe_env_vars(target: Target, ctx: RunContext) -> Result:
    env = target.out("env", "env")
    if env is None:
        return Fail("env failed")
    keys = {line.partition("=")[0] for line in env.splitlines()}
    hits = sorted(k for k in sig.SANDBOX_ENV_VARS if k in keys)
    return Verdict(bool(hits), {"variables": hits})


def _locale(target: Target) -> dict | None:
    locale = target.out("apple_locale", "defaults read -g AppleLocale")
    languages = target.out("apple_languages", "defaults read -g AppleLanguages")
    inputs = target.out("input_sources", "defaults read com.apple.HIToolbox AppleEnabledInputSources")
    if locale is None and languages is None and inputs is None:
        return None
    langs = re.findall(r'"?([a-zA-Z]{2,3}(?:[-_][A-Za-z0-9]+)*)"?\s*,?\s*$', languages or "", re.MULTILINE)
    layouts = re.findall(r'"KeyboardLayout Name"\s*=\s*"?([^";]+)"?;', inputs or "")
    return {
        "locale": (locale or "").strip(),
        "languages": [x for x in langs if x not in ("(", ")")],
        "keyboard_layouts": layouts,
    }


def probe_cis_locale(target: Target, ctx: RunContext) -> Result:
    info = _locale(target)
    if info is None:
        return Fail("defaults read -g failed")
    codes = [info["locale"]] + info["languages"]
    lang_hits = [c for c in codes if c and c.lower().split("_")[0].split("-")[0] in sig.CIS_LANGUAGE_PREFIXES]
    kb_hits = [k for k in info["keyboard_layouts"] if parsing.find_tokens(k, sig.CIS_INPUT_TOKENS)]
    return Verdict(bool(lang_hits or kb_hits), {**info, "cis_languages": lang_hits, "cis_layouts": kb_hits})


def probe_default_locale(target: Target, ctx: RunContext) -> Result:
    info = _locale(target)
    if info is None:
        return Fail("defaults read -g failed")
    only_default = (
        info["locale"] in ("", "en_US") and len(info["keyboard_layouts"]) <= 1 and len(info["languages"]) <= 1
    )
    return Verdict(only_default, info, confidence=0.3)


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


_TOOL_FIX = (
    "Remove analysis tools from the detonation image; run them from the host or the hypervisor instead."
)
_PROC_GROUPS = {
    "debuggers": ("analysis_tools.processes", "Debugger processes", Severity.HIGH),
    "tracers": ("instrumentation.tracing_facilities", "Kernel tracing tools running", Severity.HIGH),
    "sniffers": ("analysis_tools.processes", "Packet capture processes", Severity.HIGH),
    "proxies": ("analysis_tools.processes", "Interception proxy processes", Severity.HIGH),
    "objective_see": ("analysis_tools.processes", "Objective-See monitoring tools running", Severity.HIGH),
    "firewalls": ("analysis_tools.processes", "Application firewall processes", Severity.MEDIUM),
    "disassemblers": ("analysis_tools.processes", "Disassembler processes", Severity.HIGH),
    "instrumentation": ("instrumentation.hooking_frameworks", "Frida / objection processes", Severity.HIGH),
    "sandbox_agents": ("analysis_tools.processes", "Sandbox guest agent processes", Severity.CRITICAL),
}
_APP_GROUPS = {
    "disassemblers": ("Disassemblers installed", Severity.MEDIUM),
    "network": ("Network analysis apps installed", Severity.MEDIUM),
    "objective_see": ("Objective-See tools installed", Severity.MEDIUM),
    "firewalls": ("Application firewalls installed", Severity.LOW),
    "inspection": ("Package / binary inspection apps installed", Severity.LOW),
}

CHECKS = [
    _c(
        "macos.design.sip_status",
        "os_config.uac_sip",
        "System Integrity Protection",
        "csrutil status reports SIP disabled or partly disabled (VMAware MAC_SIP, Check Point).",
        Severity.HIGH,
        "Keep SIP enabled; use signed system extensions (Endpoint Security) rather than unsigned kexts for monitoring.",
        probe_sip,
    ),
    _c(
        "macos.design.sip_dtrace",
        "instrumentation.tracing_facilities",
        "DTrace restrictions lifted",
        "SIP's DTrace restrictions are disabled, which is what dtrace-based tracing needs.",
        Severity.MEDIUM,
        "Re-enable SIP fully; trace from outside the guest.",
        probe_sip_dtrace,
    ),
    _c(
        "macos.design.authenticated_root",
        "os_config.uac_sip",
        "Signed system volume",
        "csrutil authenticated-root is disabled (sealed system volume broken for modification).",
        Severity.MEDIUM,
        "Re-enable authenticated root.",
        probe_authenticated_root,
    ),
    _c(
        "macos.design.gatekeeper",
        "os_config.uac_sip",
        "Gatekeeper",
        "spctl --status reports assessments disabled.",
        Severity.MEDIUM,
        "Keep Gatekeeper enabled; open samples the way a user would (right-click Open).",
        probe_gatekeeper,
    ),
    _c(
        "macos.design.boot_args_debug",
        "debugger.kernel_debugger",
        "Kernel debug boot arguments",
        "kern.bootargs / nvram boot-args enable kernel debugging (debug=, kdp_match_name, development kernel).",
        Severity.HIGH,
        "Clear debug boot-args from NVRAM in the analysis image.",
        probe_boot_args_debug,
    ),
    _c(
        "macos.design.boot_args_amfi",
        "os_config.uac_sip",
        "Code-signing enforcement boot arguments",
        "Boot arguments that disable AMFI / code-signing enforcement.",
        Severity.HIGH,
        "Remove amfi/cs_enforcement boot-args.",
        probe_boot_args_amfi,
    ),
    _c(
        "macos.design.xprotect",
        "os_config.security_software",
        "XProtect present",
        "XProtect bundle missing (deleted or stripped image).",
        Severity.MEDIUM,
        "Keep XProtect and XProtect Remediator installed.",
        probe_xprotect,
    ),
    _c(
        "macos.design.security_data_age",
        "os_config.security_software",
        "Security data freshness",
        "Last XProtect / Gatekeeper data update older than the limit (image frozen in time).",
        Severity.LOW,
        "Refresh the golden image's security data before each snapshot.",
        probe_security_data_age,
        cost="medium",
    ),
    _c(
        "macos.design.software_update_disabled",
        "os_config.activation_updates",
        "Automatic updates disabled",
        "SoftwareUpdate AutomaticCheckEnabled / ConfigDataInstall / CriticalUpdateInstall set to 0.",
        Severity.LOW,
        "Leave automatic security updates on in the image (block the network instead).",
        probe_software_update,
    ),
    _c(
        "macos.design.os_update_age",
        "os_config.activation_updates",
        "OS update age",
        "Last macOS / Rapid Security Response install older than the limit.",
        Severity.LOW,
        "Patch the golden image regularly.",
        probe_os_update_age,
        cost="medium",
    ),
    *[
        _c(
            f"macos.design.processes_{group}",
            technique,
            name,
            f"Running processes of {group.replace('_', ' ')} tools: {', '.join(sig.ANALYSIS_PROCESS_GROUPS[group][:6])}...",
            severity,
            _TOOL_FIX,
            process_probe(sig.ANALYSIS_PROCESS_GROUPS[group]),
        )
        for group, (technique, name, severity) in _PROC_GROUPS.items()
    ],
    *[
        _c(
            f"macos.design.apps_{group}",
            "analysis_tools.files",
            name,
            f"Application bundles of {group.replace('_', ' ')} tools in /Applications or ~/Applications.",
            severity,
            _TOOL_FIX,
            app_group_probe(sig.ANALYSIS_APP_GROUPS[group]),
        )
        for group, (name, severity) in _APP_GROUPS.items()
    ],
    _c(
        "macos.design.cli_tools",
        "analysis_tools.files",
        "Analysis command-line tools",
        "frida, objection, radare2, mitmproxy, class-dump... in Homebrew / MacPorts / user bin directories.",
        Severity.MEDIUM,
        _TOOL_FIX,
        probe_cli_tools,
    ),
    _c(
        "macos.design.system_extensions",
        "analysis_tools.drivers_services",
        "Monitoring system extensions",
        "Activated system extensions of monitoring tools (LuLu, Little Snitch, Objective-See ES clients).",
        Severity.MEDIUM,
        "Monitor from the hypervisor instead of in-guest extensions.",
        probe_system_extensions,
    ),
    _c(
        "macos.design.dyld_environment",
        "instrumentation.injected_libraries",
        "DYLD injection variables",
        "DYLD_INSERT_LIBRARIES (and related) set in the launchd or session environment.",
        Severity.HIGH,
        "Do not inject monitoring libraries via DYLD variables.",
        probe_dyld_env,
    ),
    _c(
        "macos.design.traced_processes",
        "debugger.tracer",
        "Traced processes (P_TRACED)",
        "ps flags show processes with P_TRACED set: a debugger is attached (BANSHEE sysctl check, IOSSecuritySuite amIDebugged).",
        Severity.HIGH,
        "Do not attach debuggers inside the guest.",
        probe_traced,
    ),
    _c(
        "macos.design.listening_ports",
        "analysis_tools.listening_ports",
        "Agent ports listening",
        "Frida (27042) or Cuckoo/CAPE agent (8000) ports listening.",
        Severity.HIGH,
        "Stop in-guest agents; drive the guest from outside.",
        probe_listening_ports,
    ),
    _c(
        "macos.design.mac_oui",
        "network.mac_oui",
        "Hypervisor MAC OUI",
        "An interface MAC belongs to VMware, Parallels, VirtualBox, QEMU or Xen.",
        Severity.HIGH,
        "Set the VM MAC to an Apple OUI.",
        probe_mac_oui,
    ),
    _c(
        "macos.design.mac_locally_administered",
        "network.mac_oui",
        "Locally administered wired MAC",
        "A wired interface uses a locally administered (random) MAC, as Virtualization.framework assigns by default.",
        Severity.MEDIUM,
        "Assign a fixed MAC with an Apple OUI to the VM's network device.",
        probe_mac_local,
    ),
    _c(
        "macos.design.default_subnets",
        "network.default_subnets",
        "Hypervisor default subnet",
        "An interface address is in a hypervisor's default NAT range (Parallels 10.211.55/24, VZ 192.168.64/24...).",
        Severity.MEDIUM,
        "Use an addressing plan that looks like a home or office LAN.",
        probe_default_subnets,
    ),
    _c(
        "macos.design.wifi_hardware",
        "network.adapter_count",
        "Wi-Fi hardware",
        "No Wi-Fi hardware port: every current Mac has Wi-Fi.",
        Severity.MEDIUM,
        "Pass through a Wi-Fi adapter, or accept on bare-metal desktops with Wi-Fi removed.",
        probe_wifi_hardware,
    ),
    _c(
        "macos.design.adapter_count",
        "network.adapter_count",
        "Physical network adapters",
        "Fewer than two physical (en*) interfaces.",
        Severity.LOW,
        "Present both an Ethernet and a Wi-Fi interface.",
        probe_adapter_count,
    ),
    _c(
        "macos.design.default_route",
        "network.connectivity",
        "Default route",
        "No default gateway: the machine is offline.",
        Severity.LOW,
        "Give the analysis network a default route (to the simulated internet).",
        probe_default_route,
    ),
    _c(
        "macos.design.dns_sinkhole",
        "network.dns_sinkhole",
        "DNS answers non-existent names",
        "A random non-existent .com name resolves (fake DNS such as INetSim).",
        Severity.HIGH,
        "Return NXDOMAIN for names the simulated internet does not serve.",
        probe_dns_sinkhole,
        network=True,
    ),
    _c(
        "macos.design.simulated_internet",
        "network.simulated_internet",
        "HTTP answers for random hosts",
        "A random non-existent host returns an HTTP response (simulated internet).",
        Severity.HIGH,
        "Only answer HTTP for names that resolve.",
        probe_simulated_internet,
        network=True,
    ),
    _c(
        "macos.design.cloud_metadata",
        "network.cloud_metadata",
        "Cloud metadata endpoint",
        "169.254.169.254 answers (EC2 Mac or another cloud host).",
        Severity.MEDIUM,
        "Block the metadata address from the analysis guest (or require IMDSv2 tokens).",
        probe_cloud_metadata,
        network=True,
    ),
    _c(
        "macos.design.proxy_settings",
        "network.proxy_mitm",
        "System proxy configured",
        "scutil --proxy shows an HTTP/HTTPS/SOCKS proxy or PAC (IOSSecuritySuite amIProxied on Darwin).",
        Severity.MEDIUM,
        "Intercept transparently at the network layer instead of a configured proxy.",
        probe_proxy,
    ),
    _c(
        "macos.design.mitm_certificates",
        "network.proxy_mitm",
        "Interception root certificates",
        "Keychains hold mitmproxy / Charles / Proxyman / PortSwigger / HTTP Toolkit / Fiddler roots.",
        Severity.HIGH,
        "Remove interception CA certificates from the image.",
        probe_mitm_certs,
        cost="medium",
    ),
    _c(
        "macos.design.username",
        "identity.username",
        "User name",
        "User name is generic or a known VM/CI image default (admin, runner, ec2-user, vagrant...).",
        Severity.MEDIUM,
        "Use a realistic first-name account in the image.",
        probe_username,
    ),
    _c(
        "macos.design.hostname",
        "identity.hostname",
        "Host name",
        "LocalHostName / HostName names a VM, sandbox or CI runner.",
        Severity.MEDIUM,
        "Give the image a realistic host name (e.g. Annas-MacBook-Pro).",
        probe_hostname,
    ),
    _c(
        "macos.design.computer_name",
        "identity.hostname",
        "Computer name",
        "ComputerName contains 'Virtual Machine' (the initial setup default in VZ guests) or a sandbox name.",
        Severity.MEDIUM,
        "Rename the computer in System Settings > General > About.",
        probe_computer_name,
    ),
    _c(
        "macos.design.environment_variables",
        "identity.environment_variables",
        "CI / VM environment variables",
        "The session environment has CI or VM-image variables (CI, GITHUB_ACTIONS, CIRRUS_CI...).",
        Severity.MEDIUM,
        "Start samples from a clean user session.",
        probe_env_vars,
    ),
    _c(
        "macos.design.cis_locale",
        "identity.locale",
        "CIS language or keyboard",
        "Russian/CIS language or keyboard: stealers such as BANSHEE and AMOS exit on these.",
        Severity.MEDIUM,
        "Use the language and keyboard of the target population in the analysis image.",
        probe_cis_locale,
    ),
    _c(
        "macos.design.default_locale",
        "identity.locale",
        "Untouched default locale",
        "Only en_US with a single keyboard layout: the untouched installer default.",
        Severity.LOW,
        "Configure locale, languages and keyboards like a real user.",
        probe_default_locale,
    ),
]
