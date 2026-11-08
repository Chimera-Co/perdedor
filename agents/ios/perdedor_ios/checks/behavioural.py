"""Wear and tear on iOS: installed apps, personal data stores, usage traces and
system age. Only counts and sizes are reported, never contents.

Paths are the standard iOS data locations under /var/mobile (they are root- or
mobile-readable over ssh on a jailbroken device, and live under the device data
directory for the Simulator).
"""

from __future__ import annotations

from datetime import datetime, timezone
import shlex

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext

from perdedor_macos.checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, build, count_entries

from .. import signatures as sig
from ..device import IosTarget

P = Platform.IOS
USER_APP_ROOT = "/var/containers/Bundle/Application"
PERSONAL_STORES = {
    "contacts": ("/var/mobile/Library/AddressBook/AddressBook.sqlitedb",),
    "messages": ("/var/mobile/Library/SMS/sms.db",),
    "call_history": ("/var/mobile/Library/CallHistoryDB/CallHistory.storedata",),
    "accounts": ("/var/mobile/Library/Accounts/Accounts3.sqlite",),
}
KEYBOARD_DIR = "/var/mobile/Library/Keyboard"
SAFARI_HISTORY = ("/var/mobile/Library/Safari/History.db",)
DCIM = "/var/mobile/Media/DCIM"
MEDIA = "/var/mobile/Media"
AGE_MARKERS = ("/var/mobile/Library/Preferences/com.apple.purplebuddy.plist", "/var/mobile/Library")


def _now(target: IosTarget) -> datetime | None:
    text = target.out("date_epoch", "date +%s", timeout=10.0)
    if not text or not text.strip().isdigit():
        return None
    return datetime.fromtimestamp(int(text.strip()), tz=timezone.utc)


def probe_installed_apps(target: IosTarget, ctx: RunContext) -> Result:
    if target.is_simulator:
        text = target.out("simctl_listapps", f"xcrun simctl listapps {shlex.quote(target._udid())}")
        if text is None:
            return Fail("simctl listapps failed")
        count = text.count('ApplicationType = User;')
    else:
        count, reason = count_entries(target, USER_APP_ROOT)
        if count is None:
            return Fail(reason or UNREACHABLE)
    return Verdict(count < sig.MIN_USER_APPS, {"user_apps": count},
                   measurement={"value": count, "threshold": sig.MIN_USER_APPS})


def probe_photos(target: IosTarget, ctx: RunContext) -> Result:
    listing = target.listdir(DCIM)
    if listing is None:
        return Fail(UNREACHABLE)
    if listing.entries is None:
        return Skip(f"DCIM directory: {listing.error}")
    total = 0
    for folder in listing.entries:
        count, _ = count_entries(target, f"{DCIM}/{folder}")
        total += count or 0
    return Verdict(total < sig.MIN_PHOTOS, {"photos": total}, measurement={"value": total, "threshold": sig.MIN_PHOTOS})


# Schema names used by the stock stores; unsupported versions return unknown.
# https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0064/
STORE_TABLES = {
    PERSONAL_STORES["contacts"][0]: "ABPerson",
    PERSONAL_STORES["messages"][0]: "message",
    PERSONAL_STORES["call_history"][0]: "ZCALLRECORD",
    PERSONAL_STORES["accounts"][0]: "ZACCOUNT",
}
MIN_PERSONAL_ROWS = 1  # Local empty-store policy; never read row contents.


def store_probe(paths):
    def probe(target: IosTarget, ctx: RunContext) -> Result:
        counts = [target.sqlite_count(path, STORE_TABLES.get(path, "history_items")) for path in paths]
        readable = [count for count in counts if count is not None]
        if not readable:
            return Skip("personal store unavailable, sqlite3 absent, or schema unsupported")
        count = max(readable)
        return Verdict(count < MIN_PERSONAL_ROWS, {"records": count}, confidence=0.4)
    return probe


def probe_safari(target: IosTarget, ctx: RunContext) -> Result:
    candidates = list(SAFARI_HISTORY)
    containers = target.listdir("/var/mobile/Containers/Data/Application")
    for uuid in (containers.entries if containers and containers.entries else ())[:400]:
        candidates.append(f"/var/mobile/Containers/Data/Application/{uuid}/Library/Safari/History.db")
    return store_probe(candidates)(target, ctx)


def probe_keyboard(target: IosTarget, ctx: RunContext) -> Result:
    listing = target.listdir(KEYBOARD_DIR)
    if listing is None:
        return Fail(UNREACHABLE)
    if listing.entries is None:
        return Skip(f"keyboard directory: {listing.error}")
    learned = [e for e in listing.entries if "dynamic" in e.lower() or e.endswith(".dat")]
    return Verdict(not learned, {"keyboard_files": len(listing.entries), "learned_text_files": len(learned)})


def probe_media(target: IosTarget, ctx: RunContext) -> Result:
    count, reason = count_entries(target, MEDIA)
    if count is None:
        return Fail(reason or UNREACHABLE)
    downloads, _ = count_entries(target, f"{MEDIA}/Downloads")
    recordings, _ = count_entries(target, f"{MEDIA}/Recordings")
    items = (downloads or 0) + (recordings or 0)
    return Verdict(items == 0, {"media_folders": count, "downloads": downloads or 0, "recordings": recordings or 0})


def probe_system_age(target: IosTarget, ctx: RunContext) -> Result:
    info = target.stat(list(AGE_MARKERS))
    now = _now(target)
    if info is None or now is None:
        return Fail(UNREACHABLE)
    stamps = [i.mtime for i in info.values() if i.mtime]
    if not stamps:
        return Skip("no setup marker readable")
    days = (now.timestamp() - min(stamps)) / 86400
    return Verdict(days < sig.MIN_SYSTEM_AGE_DAYS, {"oldest_marker_days": round(days, 1)},
                   measurement={"value": days, "threshold": sig.MIN_SYSTEM_AGE_DAYS})


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


_WEAR_FIX = "Use a device with a lived-in user profile (apps, photos, contacts, messages) for detonation."

CHECKS = [
    _c("ios.behavioural.installed_apps", "wear_and_tear.installed_software", "Installed user apps",
       "Fewer than ten user-installed apps.", Severity.MEDIUM, _WEAR_FIX, probe_installed_apps),
    _c("ios.behavioural.photos", "wear_and_tear.personal_data", "Photos",
       "Camera roll (DCIM) empty or nearly empty.", Severity.MEDIUM, _WEAR_FIX, probe_photos),
    _c("ios.behavioural.contacts", "wear_and_tear.personal_data", "Contacts database",
       "AddressBook database unreadable or empty (counts only).", Severity.MEDIUM, _WEAR_FIX,
       store_probe(PERSONAL_STORES["contacts"])),
    _c("ios.behavioural.messages", "wear_and_tear.personal_data", "Messages database",
       "sms.db unreadable or empty (counts only).", Severity.MEDIUM, _WEAR_FIX, store_probe(PERSONAL_STORES["messages"])),
    _c("ios.behavioural.call_history", "wear_and_tear.personal_data", "Call history",
       "CallHistory store unreadable or empty (counts only).", Severity.LOW, _WEAR_FIX,
       store_probe(PERSONAL_STORES["call_history"])),
    _c("ios.behavioural.accounts", "wear_and_tear.personal_data", "Accounts",
       "Accounts database unreadable or empty (counts only) (no iCloud / mail accounts).", Severity.LOW, _WEAR_FIX,
       store_probe(PERSONAL_STORES["accounts"])),
    _c("ios.behavioural.safari_history", "wear_and_tear.browser_history", "Safari history",
       "Safari History.db missing or nearly empty.", Severity.MEDIUM, _WEAR_FIX, probe_safari, cost="medium"),
    _c("ios.behavioural.keyboard_learning", "wear_and_tear.usage_traces", "Keyboard learned text",
       "No keyboard learning files: nobody has typed on the device.", Severity.LOW, _WEAR_FIX, probe_keyboard),
    _c("ios.behavioural.media_files", "wear_and_tear.user_files", "User media",
       "No downloads or voice recordings in /var/mobile/Media.", Severity.INFO, _WEAR_FIX, probe_media),
    _c("ios.behavioural.system_age", "wear_and_tear.system_age", "Time since setup",
       "Setup Assistant / user library younger than the limit.", Severity.MEDIUM,
       "Set devices up well ahead of use.", probe_system_age),
]


