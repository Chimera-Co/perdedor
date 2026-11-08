"""Human presence and wear-and-tear on macOS. Only counts and sizes are
reported, never file names or contents (DESIGN-V2 privacy rule).

Several user folders (Desktop, Documents, Downloads, Safari) are protected by
TCC since macOS 10.15. When the driver's process lacks Full Disk Access the
probe reports ``error`` with that reason instead of a misleading ``clean``.
"""

from __future__ import annotations

import re
import time
import math
import shlex

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext

from .. import parsing
from .. import signatures as sig
from ..checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, app_bundles, build, count_entries, sysctl_value
from ..target import Target
from .design import install_history, target_now

P = Platform.MACOS
# Bundle id prefix of applications that ship with macOS or come from Apple.
APPLE_APP_NAMES = ("Safari.app", "Utilities", "Pages.app", "Numbers.app", "Keynote.app", "iMovie.app",
                   "GarageBand.app", "Xcode.app")
# Input sampling window of the deep-profile activity probe (seconds).
INPUT_WINDOW_SECONDS = 30.0
NANOSECONDS = 1_000_000_000


def _home(target: Target) -> str | Result:
    home = target.home()
    return home if home else Fail("could not determine $HOME")


def _hid_idle_seconds(target: Target) -> float | None:
    text = target.run("hid_idle", "ioreg -r -c IOHIDSystem -d 1", cache=False)
    if text is None or not text.ok:
        return None
    match = re.search(r'"HIDIdleTime"\s*=\s*(\d+)', text.stdout)
    return int(match.group(1)) / NANOSECONDS if match else None


def probe_hid_idle(target: Target, ctx: RunContext) -> Result:
    idle = _hid_idle_seconds(target)
    value, fail = sysctl_value(target, "kern.boottime")
    if fail:
        return fail
    boot = parsing.parse_boottime(value)
    now = target_now(target)
    if idle is None or boot is None or now is None:
        return Fail("IOHIDSystem HIDIdleTime or kern.boottime unavailable")
    uptime = now.timestamp() - boot
    never_touched = uptime > sig.MIN_IDLE_SECONDS_FOR_VERDICT and idle >= sig.IDLE_UPTIME_RATIO * uptime
    return Verdict(never_touched, {"hid_idle_seconds": int(idle), "uptime_seconds": int(uptime)},
                   measurement={"idle": idle, "uptime": uptime, "ratio": sig.IDLE_UPTIME_RATIO})


def probe_input_activity(target: Target, ctx: RunContext) -> Result:
    window = ctx.param("human.window_seconds", INPUT_WINDOW_SECONDS)
    if not math.isfinite(window) or not 0 < window <= 30:
        return Fail("human.window_seconds must be greater than 0 and at most 30")
    first = _hid_idle_seconds(target)
    if first is None:
        return Fail("IOHIDSystem HIDIdleTime unavailable")
    time.sleep(window)
    second = _hid_idle_seconds(target)
    if second is None:
        return Fail("IOHIDSystem HIDIdleTime unavailable")
    # Idle time resets to ~0 on any mouse or keyboard event.
    no_input = second >= first + window * sig.INPUT_IDLE_RATIO
    return Verdict(no_input, {"idle_before": round(first, 1), "idle_after": round(second, 1), "window": window})


def probe_gui_session(target: Target, ctx: RunContext) -> Result:
    console = target.out("console_user", "stat -f %Su /dev/console")
    procs = target.processes()
    if console is None or procs is None:
        return Fail(UNREACHABLE)
    names = {p.executable for p in procs}
    missing = [n for n in ("WindowServer", "Dock", "Finder") if n not in names]
    user = console.strip()
    return Verdict(user in ("root", "") or bool(missing), {"console_user": user, "missing": missing})


def probe_running_apps(target: Target, ctx: RunContext) -> Result:
    text = target.out("lsappinfo", "lsappinfo list")
    if text is None:
        return Skip("lsappinfo unavailable (no GUI session)")
    foreground = len(re.findall(r'type="Foreground"', text))
    return Verdict(foreground < sig.MIN_FOREGROUND_APPS, {"foreground_apps": foreground})


def _count_check(path_fn, minimum, *, label):
    def probe(target: Target, ctx: RunContext) -> Result:
        home = _home(target)
        if not isinstance(home, str):
            return home
        path = path_fn(home)
        count, reason = count_entries(target, path)
        if count is None:
            return Fail(reason or "unreadable")
        return Verdict(count < minimum, {label: count}, measurement={"value": count, "threshold": minimum})

    return probe


def probe_recent_items(target: Target, ctx: RunContext) -> Result:
    home = _home(target)
    if not isinstance(home, str):
        return home
    base = f"{home}/Library/Application Support/com.apple.sharedfilelist"
    listing = target.listdir(base)
    if listing is None:
        return Fail(UNREACHABLE)
    if listing.entries is None:
        return Skip(f"recent-items directory: {listing.error}")
    files = [e for e in listing.entries if e.endswith((".sfl2", ".sfl3"))]
    sub = target.listdir(f"{base}/com.apple.LSSharedFileList.ApplicationRecentDocuments")
    per_app = len(sub.entries) if sub and sub.entries else 0
    total = len(files) + per_app
    return Verdict(total < sig.MIN_RECENT_ITEMS_FILES, {"recent_lists": len(files), "app_recent_lists": per_app})


def browser_probe(paths_fn, browser):
    def probe(target: Target, ctx: RunContext) -> Result:
        home = _home(target)
        if not isinstance(home, str):
            return home
        candidates, profile_dir = paths_fn(target, home)
        if candidates is None:
            return Fail(profile_dir)
        info = target.stat(candidates)
        if info is None:
            return Fail(UNREACHABLE)
        sizes = {p: i.size or 0 for p, i in info.items()}
        if not sizes:
            return Verdict(True, {"browser": browser, "history_files": 0})
        biggest = max(sizes.values())
        return Verdict(biggest < sig.MIN_BROWSER_HISTORY_BYTES,
                       {"browser": browser, "history_files": len(sizes), "largest_bytes": biggest})

    return probe


def _safari_paths(target: Target, home: str):
    listing = target.listdir(f"{home}/Library/Safari")
    if listing is not None and listing.entries is None and listing.error != "missing":
        return None, f"~/Library/Safari {listing.error}"
    return [f"{home}/Library/Safari/History.db"], None


def _chromium_paths(target: Target, home: str):
    roots = ("Google/Chrome", "Microsoft Edge", "BraveSoftware/Brave-Browser", "Chromium")
    out = []
    for root in roots:
        base = f"{home}/Library/Application Support/{root}"
        listing = target.listdir(base)
        for entry in (listing.entries if listing and listing.entries else ()):
            if entry == "Default" or entry.startswith("Profile "):
                out.append(f"{base}/{entry}/History")
    return out, None


def _firefox_paths(target: Target, home: str):
    base = f"{home}/Library/Application Support/Firefox/Profiles"
    listing = target.listdir(base)
    return [f"{base}/{e}/places.sqlite" for e in (listing.entries if listing and listing.entries else ())], None


def probe_third_party_apps(target: Target, ctx: RunContext) -> Result:
    home = target.home()
    dirs = ["/Applications"] + ([f"{home}/Applications"] if home else [])
    apps, unreadable = app_bundles(target, dirs)
    if unreadable == dirs:
        return Fail("application folders unreadable")
    third_party = [a for a in apps if a not in APPLE_APP_NAMES]
    minimum = ctx.param("apps.min_third_party", sig.MIN_THIRD_PARTY_APPS)
    return Verdict(len(third_party) < minimum, {"third_party_apps": len(third_party), "all_apps": len(apps)},
                   measurement={"value": len(third_party), "threshold": minimum})


def probe_launch_agents(target: Target, ctx: RunContext) -> Result:
    home = target.home()
    total = 0
    for directory in ("/Library/LaunchAgents", "/Library/LaunchDaemons") + ((f"{home}/Library/LaunchAgents",) if home else ()):
        count, _ = count_entries(target, directory)
        total += count or 0
    return Verdict(total == 0, {"third_party_launchd_plists": total})


def probe_dock(target: Target, ctx: RunContext) -> Result:
    text = target.out("dock_modcount", "defaults read com.apple.dock mod-count")
    if text is None:
        return Skip("com.apple.dock has no mod-count (Dock never changed or no GUI login yet)")
    count = parsing.as_int(text)
    if count is None:
        return Fail(f"unparseable mod-count {text!r}")
    return Verdict(count < sig.MIN_DOCK_MOD_COUNT, {"dock_mod_count": count},
                   measurement={"value": count, "threshold": sig.MIN_DOCK_MOD_COUNT})


def probe_shell_history(target: Target, ctx: RunContext) -> Result:
    home = _home(target)
    if not isinstance(home, str):
        return home
    info = target.stat([f"{home}/.zsh_history", f"{home}/.bash_history"])
    if info is None:
        return Fail("shell history metadata unavailable")
    # Inspect sizes only: no command history or tokens leave the target.
    sizes = [entry.size for entry in info.values() if entry.size is not None]
    return Verdict(not sizes or max(sizes) < sig.MIN_SHELL_HISTORY_BYTES,
                   {"history_files": len(sizes), "largest_bytes": max(sizes, default=0)}, confidence=0.3)


def probe_unified_log(target: Target, ctx: RunContext) -> Result:
    result = target.run("diagnostics_size", "du -sk /private/var/db/diagnostics 2>&1")
    if result is None:
        return Fail(UNREACHABLE)
    match = re.match(r"^(\d+)", result.stdout.strip())
    if not match or "Permission denied" in result.stdout:
        return Skip("unified log store needs root to size (run the driver as root / sudo for this check)")
    kbytes = int(match.group(1))
    # A system that has run for weeks keeps hundreds of MB of unified logs.
    return Verdict(kbytes < sig.MIN_LOG_KIB, {"diagnostics_kbytes": kbytes})


def probe_setup_age(target: Target, ctx: RunContext) -> Result:
    info = target.stat(["/var/db/.AppleSetupDone", "/var/log/install.log"])
    now = target_now(target)
    if info is None or now is None:
        return Fail(UNREACHABLE)
    marker = info.get("/var/db/.AppleSetupDone")
    if marker is None or marker.mtime is None:
        return Fail("/var/db/.AppleSetupDone missing (Setup Assistant never completed?)")
    days = (now.timestamp() - marker.mtime) / 86400
    minimum = ctx.param("age.min_days", sig.MIN_SYSTEM_AGE_DAYS)
    return Verdict(days < minimum, {"setup_completed_days_ago": round(days, 1)},
                   measurement={"value": days, "threshold": minimum})


def probe_install_history(target: Target, ctx: RunContext) -> Result:
    history = install_history(target)
    if history is None:
        return Fail("system_profiler SPInstallHistoryDataType returned nothing")
    return Verdict(len(history) < sig.MIN_INSTALL_HISTORY_ENTRIES, {"install_history_entries": len(history)})


def probe_known_networks(target: Target, ctx: RunContext) -> Result:
    text = target.out("hardware_ports", "networksetup -listallhardwareports")
    if text is None:
        return Fail("networksetup failed")
    wifi = [p.get("Device") for p in parsing.parse_hardware_ports(text) if "wi-fi" in p.get("Hardware Port", "").lower()]
    if not wifi:
        return Skip("no Wi-Fi hardware (see macos.design.wifi_hardware)")
    result = target.run("preferred_wifi", f"networksetup -listpreferredwirelessnetworks {shlex.quote(wifi[0])}")
    if result is None or not result.ok:
        return Fail("networksetup -listpreferredwirelessnetworks failed")
    networks = [line for line in result.stdout.splitlines()[1:] if line.strip()]
    return Verdict(not networks, {"known_wifi_networks": len(networks)})


def probe_arp_cache(target: Target, ctx: RunContext) -> Result:
    text = target.out("arp", "arp -an")
    if text is None:
        return Fail("arp -an failed")
    entries = [line for line in text.splitlines() if " at " in line and "incomplete" not in line]
    return Verdict(len(entries) < sig.MIN_ARP_ENTRIES, {"arp_entries": len(entries)})


def probe_bluetooth_paired(target: Target, ctx: RunContext) -> Result:
    doc = target.profiler("SPBluetoothDataType")
    if doc is None:
        return Fail("system_profiler SPBluetoothDataType returned nothing")
    items = parsing.profiler_items(doc, "SPBluetoothDataType")
    if not items or not items[0].get("controller_properties"):
        return Skip("no Bluetooth controller (see macos.env.bluetooth_controller)")
    paired = 0
    for key in ("device_connected", "device_not_connected", "devices_list"):
        value = items[0].get(key)
        paired += len(value) if isinstance(value, list) else 0
    return Verdict(paired == 0, {"paired_devices": paired})


def probe_printers(target: Target, ctx: RunContext) -> Result:
    result = target.run("lpstat", "lpstat -p")
    if result is None:
        return Fail(UNREACHABLE)
    printers = [line for line in result.stdout.splitlines() if line.startswith("printer ")]
    return Verdict(not printers, {"printers": len(printers)}, confidence=0.4)


def probe_process_count(target: Target, ctx: RunContext) -> Result:
    procs = target.processes()
    if procs is None:
        return Fail(UNREACHABLE + " (ps)")
    minimum = ctx.param("processes.min", sig.MIN_PROCESSES)
    return Verdict(len(procs) < minimum, {"processes": len(procs)},
                   measurement={"value": len(procs), "threshold": minimum})


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


_WEAR_FIX = "Age the golden image with real usage (documents, browsing, apps) before snapshotting."

CHECKS = [
    _c("macos.behavioural.hid_idle_time", "human.idle_time", "Input idle since boot",
       "IOHIDSystem HIDIdleTime is about as long as the uptime: no keyboard or mouse event since boot.",
       Severity.MEDIUM, "Simulate user input (the macOS equivalent of hidsim) during detonation.", probe_hid_idle),
    _c("macos.behavioural.input_activity", "human.mouse_activity", "Input during a waiting window",
       "No keyboard or mouse event during the sampling window (deep profile).", Severity.MEDIUM,
       "Drive simulated mouse and keyboard input while the sample runs.", probe_input_activity, cost="slow",
       tags=("interactive",)),
    _c("macos.behavioural.gui_session", "human.foreground_activity", "Logged-in GUI session",
       "Nobody is logged in at the console, or WindowServer / Dock / Finder are not running.", Severity.MEDIUM,
       "Detonate inside an auto-logged-in desktop session.", probe_gui_session),
    _c("macos.behavioural.running_apps", "human.foreground_activity", "Foreground applications",
       "Fewer than three foreground (Dock) applications running.", Severity.LOW,
       "Open everyday apps (browser, mail, notes) in the session before detonation.", probe_running_apps),
    _c("macos.behavioural.recent_items", "wear_and_tear.recent_files", "Recent items",
       "No or almost no shared file lists (Recent Documents / Applications / Servers).", Severity.MEDIUM, _WEAR_FIX,
       probe_recent_items),
    _c("macos.behavioural.safari_history", "wear_and_tear.browser_history", "Safari history",
       "Safari History.db missing or nearly empty.", Severity.MEDIUM, _WEAR_FIX,
       browser_probe(_safari_paths, "Safari")),
    _c("macos.behavioural.chromium_history", "wear_and_tear.browser_history", "Chrome / Edge / Brave history",
       "No Chromium-family profile with a non-trivial History database.", Severity.LOW, _WEAR_FIX,
       browser_probe(_chromium_paths, "Chromium family")),
    _c("macos.behavioural.firefox_history", "wear_and_tear.browser_history", "Firefox history",
       "No Firefox profile with a non-trivial places.sqlite.", Severity.INFO, _WEAR_FIX,
       browser_probe(_firefox_paths, "Firefox")),
    _c("macos.behavioural.desktop_files", "wear_and_tear.user_files", "Desktop items",
       "Desktop is empty.", Severity.LOW, _WEAR_FIX,
       _count_check(lambda h: f"{h}/Desktop", sig.MIN_USER_FOLDER_ENTRIES, label="desktop_entries")),
    _c("macos.behavioural.documents_files", "wear_and_tear.user_files", "Documents items",
       "Documents folder is empty.", Severity.MEDIUM, _WEAR_FIX,
       _count_check(lambda h: f"{h}/Documents", sig.MIN_USER_FOLDER_ENTRIES, label="documents_entries")),
    _c("macos.behavioural.downloads_files", "wear_and_tear.user_files", "Downloads items",
       "Downloads folder is empty.", Severity.MEDIUM, _WEAR_FIX,
       _count_check(lambda h: f"{h}/Downloads", sig.MIN_USER_FOLDER_ENTRIES, label="downloads_entries")),
    _c("macos.behavioural.third_party_apps", "wear_and_tear.installed_software", "Third-party applications",
       "Fewer than five applications beyond those Apple ships.", Severity.MEDIUM,
       "Install everyday apps (browsers, office, chat, media) in the image.", probe_third_party_apps),
    _c("macos.behavioural.launch_agents", "wear_and_tear.installed_software", "Third-party launchd jobs",
       "No third-party LaunchAgents / LaunchDaemons at all (no updaters, sync clients...).", Severity.LOW,
       "Installed everyday software brings its updaters; install it.", probe_launch_agents),
    _c("macos.behavioural.dock_customisation", "wear_and_tear.usage_traces", "Dock customisation",
       "com.apple.dock mod-count is small: the Dock was never rearranged.", Severity.LOW, _WEAR_FIX, probe_dock),
    _c("macos.behavioural.shell_history", "wear_and_tear.usage_traces", "Shell history",
       "No zsh/bash history and no saved Terminal sessions.", Severity.INFO, _WEAR_FIX, probe_shell_history),
    _c("macos.behavioural.unified_log_volume", "wear_and_tear.system_logs", "Unified log volume",
       "The unified log store (/private/var/db/diagnostics) is small: a young system.", Severity.LOW,
       "Run the image for some time before snapshotting.", probe_unified_log, cost="medium", tags=("needs-root",)),
    _c("macos.behavioural.setup_age", "wear_and_tear.system_age", "Time since setup",
       "/var/db/.AppleSetupDone is younger than the limit: freshly installed system.", Severity.MEDIUM,
       "Build images well ahead of use, or backdate consistently.", probe_setup_age),
    _c("macos.behavioural.install_history", "wear_and_tear.system_age", "Install history length",
       "Few entries in the install history (no updates or apps installed over time).", Severity.LOW,
       "Install updates and apps over the image's life.", probe_install_history, cost="medium"),
    _c("macos.behavioural.known_wifi_networks", "wear_and_tear.network_history", "Known Wi-Fi networks",
       "Wi-Fi hardware present but no remembered networks.", Severity.LOW,
       "Add a few remembered networks to the image.", probe_known_networks),
    _c("macos.behavioural.arp_cache", "wear_and_tear.network_history", "ARP cache",
       "Fewer than two neighbours in the ARP cache.", Severity.INFO,
       "Put a few other hosts (printer, NAS, router) on the analysis LAN.", probe_arp_cache),
    _c("macos.behavioural.bluetooth_paired", "wear_and_tear.peripherals_history", "Paired Bluetooth devices",
       "Bluetooth controller present but nothing ever paired.", Severity.LOW, _WEAR_FIX, probe_bluetooth_paired,
       cost="medium"),
    _c("macos.behavioural.printers", "wear_and_tear.peripherals_history", "Printers",
       "No printer configured.", Severity.INFO, "Add a printer queue to the image.", probe_printers),
    _c("macos.behavioural.process_count", "wear_and_tear.process_count", "Process count",
       "Fewer processes than an idle macOS desktop session runs.", Severity.LOW,
       "Detonate in a full desktop session with everyday apps running.", probe_process_count),
]
