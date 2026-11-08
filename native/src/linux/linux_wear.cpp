// Human presence and wear-and-tear on Linux. Every check reports counts, sizes
// and ages only -- never file names of user documents or file contents.
//
// Sources: v1 Linux agent behavioural.py (thresholds kept), Miramirkhani et
// al., "Spotless Sandboxes: Evading Malware Analysis Systems using
// Wear-and-Tear Artifacts", IEEE S&P 2017 (artifact families: system age,
// logs, browser, user files, network history), VMAware v2.8.2
// FILE_ACCESS_HISTORY, al-khaser lack_user_input (Windows equivalent).
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

constexpr long long kDay = 24 * 3600;
// v1 behavioural.py constants.
constexpr long long kMinHistoryLines = 20;
constexpr long long kMinAgedFiles = 5;
constexpr long long kAgedFileSeconds = 7 * kDay;
constexpr long long kMinPackages = 50;
constexpr long long kMinFonts = 30;
constexpr long long kMinProcesses = 40;
// VMAware v2.8.2 file_access_history(): "return (count <= 10)".
constexpr long long kMaxRecentHrefs = 10;
// Spotless Sandboxes found sandboxes cluster at near-zero values for these artifact families; the cut-offs
// below are deliberately low (a lightly used machine passes) and can be raised with --param.
constexpr long long kMinHistoryAgeDays = 7;
constexpr long long kMinUserFiles = 10;
constexpr long long kMinSystemAgeDays = 30;
constexpr long long kMinLogAgeDays = 7;
constexpr long long kMinBrowserUsedBytes = 2 * 1024 * 1024;
constexpr long long kMinJournalFiles = 3;  // journald.conf(5): files rotate by size/MaxFileSec; one boot leaves 1-2
constexpr long long kMinLoginRecords = 10;
constexpr long long kUtmpRecordBytes = 384;  // sizeof(struct utmp) on glibc x86_64/aarch64 (utmp(5))
constexpr long long kMinDesktopEntries = 20;
constexpr long long kMinInputInterrupts = 10;  // boot-time i8042 probing alone stays below this
constexpr double kInputCheckMinUptime = 600;   // same as timing.low_uptime

Finding home_missing(const char* id, const char* name, const char* desc, Severity sev) {
    return skipped(id, name, desc, sev, "no home directory (HOME unset)");
}

std::vector<Finding> shell_history(Context& ctx) {
    const char* id = "behavioural.shell_history";
    const char* name = "Shell history depth";
    const char* desc = "A near-empty ~/.bash_history/.zsh_history is implausible for a machine with real usage.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    long long lines_total = 0;
    int found = 0;
    for (const char* f : {"/.bash_history", "/.zsh_history", "/.local/share/fish/fish_history", "/.history"}) {
        auto r = root.read(home + f, kPackageLimit);
        if (!r.ok) continue;
        ++found;
        for (const auto& l : lines(r.value))
            if (!trim(l).empty()) ++lines_total;
    }
    std::string fix = "Seed the golden image with realistic shell history.";
    if (!found) return {detected(id, name, desc, Severity::Low, "no shell history file found", fix)};
    long long limit = ctx.param_int("behavioural.min_history_lines", kMinHistoryLines);
    return {measured(id, name, desc, static_cast<double>(lines_total), static_cast<double>(limit), lines_total < limit,
                     "lines", fix, Severity::Low, 0.5)};
}

std::vector<Finding> history_age(Context& ctx) {
    const char* id = "behavioural.shell_history_age";
    const char* name = "Shell history age";
    const char* desc = "Oldest timestamp in shell history (zsh extended ': <epoch>:' or bash '#<epoch>' lines) or "
                       "the history file's birth time: a fresh history means a fresh machine.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    long long oldest = 0;
    for (const char* f : {"/.bash_history", "/.zsh_history"}) {
        std::string p = home + f;
        auto r = root.read(p, kPackageLimit);
        if (!r.ok) continue;
        for (const auto& l : lines(r.value)) {
            long long t = 0;
            if (l.size() > 1 && l[0] == '#' && number(l.substr(1), t)) {
            } else if (l.rfind(": ", 0) == 0 && l.find(':', 2) != std::string::npos) {
                number(l.substr(2, l.find(':', 2) - 2), t);
            }
            if (t > 0 && (!oldest || t < oldest)) oldest = t;
        }
        auto st = root.stat(p);
        if (st.ok && st.birth > 0 && (!oldest || st.birth < oldest)) oldest = st.birth;
    }
    if (!oldest) return {skipped(id, name, desc, Severity::Low, "no timestamped history and no birth time")};
    long long days = (root.now() - oldest) / kDay;
    long long limit = ctx.param_int("behavioural.min_history_age_days", kMinHistoryAgeDays);
    return {measured(id, name, desc, static_cast<double>(days), static_cast<double>(limit), days < limit, "days",
                     "Build the image's history over time (or with back-dated timestamps).", Severity::Low, 0.5)};
}

std::vector<Finding> aged_files(Context& ctx) {
    const char* id = "behavioural.aged_files";
    const char* name = "Filesystem 'wear and tear' age";
    const char* desc = "Counts files under $HOME older than a week; a home directory that is all brand-new is a tell.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    auto w = root.walk(home, 4);
    if (!w.ok && w.names.empty()) return {unreadable(id, name, desc, Severity::Low, w.err, "$HOME")};
    long long now = root.now(), aged = 0;
    for (const auto& f : w.names) {
        auto st = root.stat(f, false);
        if (st.ok && now - st.st.st_mtime > kAgedFileSeconds && ++aged >= kMinAgedFiles) break;
    }
    return {measured(id, name, desc, static_cast<double>(aged), static_cast<double>(kMinAgedFiles), aged < kMinAgedFiles,
                     "files older than 7 days", "Populate the image with aged documents before freezing it.",
                     Severity::Low, 0.5)};
}

std::vector<Finding> installed_packages(Context& ctx) {
    const char* id = "behavioural.installed_packages";
    const char* name = "Installed package count";
    const char* desc = "A machine with very few installed packages beyond the base OS looks freshly provisioned.";
    Root root(ctx);
    auto p = packages(root);
    if (!p.ok) return {skipped(id, name, desc, Severity::Low, "no readable package database (dpkg/apk/pacman/rpm)")};
    long long n = static_cast<long long>(p.names.size());
    long long limit = ctx.param_int("behavioural.min_packages", kMinPackages);
    auto f = measured(id, name, desc, static_cast<double>(n), static_cast<double>(limit), n < limit, "packages",
                      "Install a realistic mix of everyday software on the golden image.", Severity::Low, 0.5);
    f.evidence.set("manager", p.manager);
    return {f};
}

std::vector<Finding> font_count(Context& ctx) {
    const char* id = "behavioural.font_count";
    const char* name = "Installed font count";
    const char* desc = "Fewer than 30 font files in the fontconfig directories looks like a minimal or headless "
                       "provisioning (fonts.conf(5) default directories).";
    static const std::vector<std::string> sfx = {".ttf", ".otf", ".ttc", ".pcf", ".pcf.gz", ".pfb", ".woff",
        ".woff2", ".otb"};
    Root root(ctx);
    long long n = 0;
    bool any = false, partial = false;
    std::vector<std::string> dirs = {"/usr/share/fonts", "/usr/local/share/fonts"};
    std::string home = root.home();
    if (!home.empty()) {
        dirs.push_back(home + "/.local/share/fonts");
        dirs.push_back(home + "/.fonts");
    }
    for (const auto& d : dirs) {
        auto c = count_files(root, d, sfx);
        if (!c.ok) continue;
        any = true;
        partial |= c.partial;
        n += c.files;
    }
    if (!any) return {detected(id, name, desc, Severity::Info, "no font directories", "Install a desktop font set.")};
    auto f = measured(id, name, desc, static_cast<double>(n), static_cast<double>(kMinFonts), n < kMinFonts, "fonts",
                      "Install a normal desktop font set on the golden image.", Severity::Info, 0.4);
    if (partial && n < kMinFonts) return {skipped(id, name, desc, Severity::Info, "font walk truncated")};
    return {f};
}

std::vector<Finding> process_count(Context& ctx) {
    const char* id = "behavioural.running_process_count";
    const char* name = "Running process count";
    const char* desc = "Fewer than 40 processes looks like a minimal sandbox rather than a desktop session.";
    Root root(ctx);
    auto p = processes(root, false);
    if (!p.ok) return {unreadable(id, name, desc, Severity::Info, p.err, "/proc")};
    long long n = static_cast<long long>(p.procs.size());
    long long limit = ctx.param_int("behavioural.min_processes", kMinProcesses);
    return {measured(id, name, desc, static_cast<double>(n), static_cast<double>(limit), n < limit, "processes",
                     "Start the normal desktop session and its background services before detonating.", Severity::Info,
                     0.4)};
}

std::vector<Finding> recently_used(Context& ctx) {
    const char* id = "behavioural.recently_used_xbel";
    const char* name = "Recently used files list";
    const char* desc = "~/.local/share/recently-used.xbel (GTK recent files) with 10 or fewer entries "
                       "(VMAware FILE_ACCESS_HISTORY).";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    auto r = root.read(home + "/.local/share/recently-used.xbel", kPackageLimit);
    long long count = 0;
    if (r.ok)
        for (size_t p = r.value.find("href"); p != std::string::npos; p = r.value.find("href", p + 4)) ++count;
    else if (r.err != ENOENT)
        return {unreadable(id, name, desc, Severity::Low, r.err, "recently-used.xbel")};
    auto f = measured(id, name, desc, static_cast<double>(count), static_cast<double>(kMaxRecentHrefs),
                      count <= kMaxRecentHrefs, "entries", "Open documents in the image so the recents list fills.",
                      Severity::Low, 0.5);
    f.evidence.set("present", r.ok);
    return {f};
}

struct Browser {
    std::string label, path;
};
std::vector<Browser> browser_files(const Root& root, const std::string& home) {
    std::vector<Browser> out;
    for (const char* base : {"/.mozilla/firefox", "/snap/firefox/common/.mozilla/firefox",
                             "/.var/app/org.mozilla.firefox/.mozilla/firefox"}) {
        auto l = root.list(home + base);
        for (const auto& p : l.names)
            if (root.exists(home + base + "/" + p + "/places.sqlite"))
                out.push_back({"firefox", home + base + "/" + p + "/places.sqlite"});
    }
    for (const char* base : {"/.config/google-chrome", "/.config/chromium", "/.config/BraveSoftware/Brave-Browser",
                             "/.config/microsoft-edge", "/.config/vivaldi", "/.config/opera", "/snap/chromium/common/chromium"}) {
        auto l = root.list(home + base);
        for (const auto& p : l.names)
            if ((p == "Default" || p.rfind("Profile ", 0) == 0) && root.exists(home + base + "/" + p + "/History"))
                out.push_back({basename(base), home + base + "/" + p + "/History"});
    }
    return out;
}

std::vector<Finding> browser_profiles(Context& ctx) {
    const char* id = "behavioural.browser_profiles";
    const char* name = "Browser profiles";
    const char* desc = "No Firefox or Chromium-family profile with a history database in the user's home.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Medium)};
    auto b = browser_files(root, home);
    std::vector<std::string> labels;
    for (const auto& x : b) labels.push_back(x.label);
    Json ev = Json::object();
    ev.set("profiles", static_cast<long long>(b.size()));
    ev.set("browsers", Json(labels));
    return {bool_check(id, name, desc, Severity::Medium, b.empty(), ev,
                       "Install a browser in the image and browse with it before freezing.")};
}

long long sqlite_used_bytes(const Root& root, const std::string& path, bool& ok) {
    // SQLite file format section 1.3: page size at offset 16 (big-endian u16, 1 means 65536), in-header page
    // count at 28 and freelist page count at 36 (big-endian u32).
    ok = false;
    auto r = root.read(path, 100);
    if (!r.ok || r.value.size() < 40 || r.value.compare(0, 15, "SQLite format 3") != 0) return 0;
    auto u8 = [&](size_t i) { return static_cast<unsigned long long>(static_cast<unsigned char>(r.value[i])); };
    unsigned long long page = (u8(16) << 8) | u8(17);
    if (page == 1) page = 65536;
    unsigned long long pages = (u8(28) << 24) | (u8(29) << 16) | (u8(30) << 8) | u8(31);
    unsigned long long freel = (u8(36) << 24) | (u8(37) << 16) | (u8(38) << 8) | u8(39);
    ok = true;
    return pages >= freel ? static_cast<long long>((pages - freel) * page) : 0;
}

std::vector<Finding> browser_history_size(Context& ctx) {
    const char* id = "behavioural.browser_history_size";
    const char* name = "Browser history volume";
    const char* desc = "Used pages of the largest browser history database (SQLite header, not its contents): an "
                       "unused profile holds little more than the empty schema.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    auto b = browser_files(root, home);
    if (b.empty()) return {skipped(id, name, desc, Severity::Low, "no browser profile (see behavioural.browser_profiles)")};
    long long best = 0;
    for (const auto& x : b) {
        bool ok;
        long long used = sqlite_used_bytes(root, x.path, ok);
        if (!ok) {
            auto st = root.stat(x.path);
            used = st.ok ? st.st.st_size : 0;
        }
        if (used > best) best = used;
    }
    long long limit = ctx.param_int("behavioural.min_browser_history_bytes", kMinBrowserUsedBytes);
    return {measured(id, name, desc, static_cast<double>(best), static_cast<double>(limit), best < limit, "bytes",
                     "Browse with the image's browser for a while before freezing it.", Severity::Low, 0.4)};
}

std::vector<Finding> user_files(Context& ctx) {
    const char* id = "behavioural.xdg_user_files";
    const char* name = "Files in the user's folders";
    const char* desc = "Number of files in Desktop, Documents, Downloads, Pictures, Music and Videos.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    long long n = 0;
    bool any = false;
    for (const char* d : {"Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"}) {
        auto c = count_files(root, home + "/" + d, {}, 3);
        if (!c.ok) continue;
        any = true;
        n += c.files;
    }
    long long limit = ctx.param_int("behavioural.min_user_files", kMinUserFiles);
    auto f = measured(id, name, desc, static_cast<double>(n), static_cast<double>(limit), n < limit, "files",
                      "Put plausible documents, downloads and pictures in the user's folders.", Severity::Low, 0.5);
    f.evidence.set("xdg_dirs_present", any);
    return {f};
}

std::vector<Finding> system_age(Context& ctx) {
    const char* id = "behavioural.system_age";
    const char* name = "Operating system age";
    const char* desc = "Install date estimated from /var/log/installer, /lost+found, /etc/machine-id and the root "
                       "file system's birth time (Spotless Sandboxes 'system age' artifacts).";
    Root root(ctx);
    long long oldest = 0;
    std::vector<std::string> sources;
    for (const char* p : {"/var/log/installer", "/lost+found", "/etc/machine-id", "/var/lib/dpkg/info/base-files.list",
                          "/etc/hostname"}) {
        auto st = root.stat(p, false);
        if (!st.ok) continue;
        long long t = st.st.st_mtime;
        if (st.birth > 0 && st.birth < t) t = st.birth;
        if (!oldest || t < oldest) oldest = t;
        sources.push_back(p);
    }
    auto r = root.stat("/");
    if (r.ok && r.birth > 0 && (!oldest || r.birth < oldest)) { oldest = r.birth; sources.push_back("/ (birth)"); }
    if (!oldest) return {skipped(id, name, desc, Severity::Medium, "no install-time source")};
    long long days = (root.now() - oldest) / kDay;
    long long limit = ctx.param_int("behavioural.min_system_age_days", kMinSystemAgeDays);
    auto f = measured(id, name, desc, static_cast<double>(days), static_cast<double>(limit), days < limit, "days",
                      "Build the golden image well before use, or back-date it consistently.", Severity::Medium, 0.5);
    f.evidence.set("sources", Json(sources));
    return {f};
}

std::vector<Finding> log_age(Context& ctx) {
    const char* id = "behavioural.log_age";
    const char* name = "Age of system logs";
    const char* desc = "Oldest file under /var/log: logrotate keeps weeks of history on a used system.";
    Root root(ctx);
    auto c = count_files(root, "/var/log", {}, 2);
    if (!c.ok) return {skipped(id, name, desc, Severity::Low, "no /var/log")};
    if (!c.files) return {detected(id, name, desc, Severity::Low, "no log files", "Keep the image's logs.")};
    long long days = (root.now() - c.oldest) / kDay;
    long long limit = ctx.param_int("behavioural.min_log_age_days", kMinLogAgeDays);
    auto f = measured(id, name, desc, static_cast<double>(days), static_cast<double>(limit), days < limit, "days",
                      "Do not wipe /var/log when building the image; let it age.", Severity::Low, 0.5);
    f.evidence.set("files", c.files);
    return {f};
}

std::vector<Finding> journal(Context& ctx) {
    const char* id = "behavioural.journal_files";
    const char* name = "Persistent journal history";
    const char* desc = "Number of journal files in /var/log/journal: each rotation and user adds files; a first "
                       "boot leaves one or two.";
    Root root(ctx);
    auto c = count_files(root, "/var/log/journal", {".journal", ".journal~"}, 2);
    if (!c.ok) return {skipped(id, name, desc, Severity::Low, "no persistent journal (volatile or not systemd)")};
    auto f = measured(id, name, desc, static_cast<double>(c.files), static_cast<double>(kMinJournalFiles),
                      c.files < kMinJournalFiles, "files", "Keep the journal of the image's build and use period.",
                      Severity::Low, 0.4);
    f.evidence.set("bytes", c.bytes);
    return {f};
}

std::vector<Finding> logins(Context& ctx) {
    const char* id = "behavioural.login_records";
    const char* name = "Login history (wtmp)";
    const char* desc = "Records in /var/log/wtmp (size / sizeof(struct utmp)): few logins and reboots mean a "
                       "machine nobody uses.";
    Root root(ctx);
    auto st = root.stat("/var/log/wtmp");
    if (!st.ok) {
        if (root.exists("/var/lib/wtmpdb/wtmp.db"))
            return {skipped(id, name, desc, Severity::Low, "wtmpdb in use (SQLite, not counted)")};
        return {unreadable(id, name, desc, Severity::Low, st.err, "/var/log/wtmp")};
    }
    long long n = st.st.st_size / kUtmpRecordBytes;
    return {measured(id, name, desc, static_cast<double>(n), static_cast<double>(kMinLoginRecords), n < kMinLoginRecords,
                     "records", "Log in and reboot the image several times while building it.", Severity::Low, 0.4)};
}

std::vector<Finding> known_hosts(Context& ctx) {
    const char* id = "behavioural.ssh_known_hosts";
    const char* name = "SSH known hosts";
    const char* desc = "Entries in ~/.ssh/known_hosts (count only).";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Info)};
    auto r = root.read(home + "/.ssh/known_hosts", kPackageLimit);
    long long n = 0;
    if (r.ok)
        for (const auto& l : lines(r.value))
            if (!trim(l).empty() && trim(l)[0] != '#') ++n;
    return {measured(id, name, desc, static_cast<double>(n), 1, n < 1, "hosts",
                     "Optional: connect to a few hosts while building the image.", Severity::Info, 0.2)};
}

std::vector<Finding> arp(Context& ctx) {
    const char* id = "behavioural.arp_neighbors";
    const char* name = "ARP neighbours";
    const char* desc = "Entries in /proc/net/arp: an isolated analysis network shows only the gateway.";
    Root root(ctx);
    auto r = root.read("/proc/net/arp");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Info, r.err, "/proc/net/arp")};
    long long n = 0;
    auto ls = lines(r.value);
    for (size_t i = 1; i < ls.size(); ++i)
        if (!trim(ls[i]).empty()) ++n;
    return {measured(id, name, desc, static_cast<double>(n), 1, n <= 1, "entries",
                     "Put a few simulated hosts on the analysis network.", Severity::Info, 0.3)};
}

std::vector<Finding> desktop_entries(Context& ctx) {
    const char* id = "behavioural.desktop_entries";
    const char* name = "Desktop applications";
    const char* desc = "Number of .desktop launchers in the XDG application directories.";
    Root root(ctx);
    long long n = 0;
    std::vector<std::string> dirs = {"/usr/share/applications", "/usr/local/share/applications",
                                     "/var/lib/flatpak/exports/share/applications", "/var/lib/snapd/desktop/applications"};
    std::string home = root.home();
    if (!home.empty()) dirs.push_back(home + "/.local/share/applications");
    for (const auto& d : dirs) {
        auto c = count_files(root, d, {".desktop"}, 2);
        n += c.files;
    }
    return {measured(id, name, desc, static_cast<double>(n), static_cast<double>(kMinDesktopEntries),
                     n < kMinDesktopEntries, "launchers", "Install everyday desktop applications.", Severity::Low, 0.4)};
}

std::vector<Finding> thumbnails(Context& ctx) {
    const char* id = "behavioural.thumbnail_cache";
    const char* name = "Thumbnail cache";
    const char* desc = "Files in ~/.cache/thumbnails (freedesktop thumbnail spec): file managers fill it as soon as "
                       "someone browses pictures or documents.";
    Root root(ctx);
    std::string home = root.home();
    if (home.empty()) return {home_missing(id, name, desc, Severity::Low)};
    auto c = count_files(root, home + "/.cache/thumbnails", {".png"}, 2);
    return {measured(id, name, desc, static_cast<double>(c.files), 1, c.files < 1, "thumbnails",
                     "Browse pictures in the image's file manager.", Severity::Low, 0.3)};
}

std::vector<Finding> cron_jobs(Context& ctx) {
    const char* id = "behavioural.scheduled_jobs";
    const char* name = "Scheduled jobs";
    const char* desc = "cron.d / cron.daily entries and systemd timer units: zero means a stripped image.";
    Root root(ctx);
    long long n = 0;
    for (const char* d : {"/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/var/spool/cron/crontabs"}) {
        auto l = root.list(d);
        for (const auto& e : l.names)
            if (e != ".placeholder") ++n;
    }
    bool ok;
    for (const auto& u : unit_files(root, ok))
        if (u.size() > 6 && u.compare(u.size() - 6, 6, ".timer") == 0) ++n;
    return {measured(id, name, desc, static_cast<double>(n), 1, n < 1, "jobs", "Keep the distribution's default jobs.",
                     Severity::Info, 0.3)};
}

std::vector<Finding> input_interrupts(Context& ctx) {
    const char* id = "behavioural.input_interrupts";
    const char* name = "Keyboard/mouse interrupts since boot";
    const char* desc = "i8042 (PS/2 keyboard and mouse) interrupt counts in /proc/interrupts: with no USB input "
                       "device, near zero after ten minutes means nobody typed or moved the mouse (al-khaser "
                       "lack_user_input on Windows).";
    Root root(ctx);
    auto r = root.read("/proc/interrupts");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Medium, r.err, "/proc/interrupts")};
    auto inp = root.read("/proc/bus/input/devices");
    if (inp.ok)
        for (const auto& l : lines(inp.value))
            if (l.rfind("P: Phys=usb", 0) == 0)
                return {skipped(id, name, desc, Severity::Medium, "USB input devices present; i8042 is not the input path")};
    long long total = 0;
    bool seen = false;
    for (const auto& l : lines(r.value)) {
        if (l.find("i8042") == std::string::npos) continue;
        seen = true;
        std::istringstream in(l.substr(l.find(':') + 1));
        std::string tok;
        while (in >> tok) {
            long long v;
            if (!number(tok, v)) break;
            total += v;
        }
    }
    if (!seen) return {skipped(id, name, desc, Severity::Medium, "no i8042 controller")};
    auto up = root.read("/proc/uptime");
    double uptime = up.ok ? std::strtod(up.value.c_str(), nullptr) : 0;
    if (uptime < kInputCheckMinUptime) return {skipped(id, name, desc, Severity::Medium, "uptime too short to judge")};
    return {measured(id, name, desc, static_cast<double>(total), static_cast<double>(kMinInputInterrupts),
                     total < kMinInputInterrupts, "interrupts",
                     "Simulate input during analysis (CHIMERA: hidsim injects PS/2 keyboard and mouse events).",
                     Severity::Medium, 0.6)};
}

}  // namespace

PERDEDOR_REGISTER(shell_history, "wear_and_tear.recent_files", "fast", false, "behavioural.shell_history");
PERDEDOR_REGISTER(history_age, "wear_and_tear.recent_files", "fast", false, "behavioural.shell_history_age");
PERDEDOR_REGISTER(aged_files, "wear_and_tear.user_files", "fast", false, "behavioural.aged_files");
PERDEDOR_REGISTER(installed_packages, "wear_and_tear.installed_software", "fast", false, "behavioural.installed_packages");
PERDEDOR_REGISTER(font_count, "wear_and_tear.fonts", "fast", false, "behavioural.font_count");
PERDEDOR_REGISTER(process_count, "wear_and_tear.process_count", "fast", false, "behavioural.running_process_count");
PERDEDOR_REGISTER(recently_used, "wear_and_tear.recent_files", "fast", false, "behavioural.recently_used_xbel");
PERDEDOR_REGISTER(browser_profiles, "wear_and_tear.browser_history", "fast", false, "behavioural.browser_profiles");
PERDEDOR_REGISTER(browser_history_size, "wear_and_tear.browser_history", "fast", false, "behavioural.browser_history_size");
PERDEDOR_REGISTER(user_files, "wear_and_tear.user_files", "fast", false, "behavioural.xdg_user_files");
PERDEDOR_REGISTER(system_age, "wear_and_tear.system_age", "fast", false, "behavioural.system_age");
PERDEDOR_REGISTER(log_age, "wear_and_tear.system_logs", "fast", false, "behavioural.log_age");
PERDEDOR_REGISTER(journal, "wear_and_tear.system_logs", "fast", false, "behavioural.journal_files");
PERDEDOR_REGISTER(logins, "wear_and_tear.system_logs", "fast", false, "behavioural.login_records");
PERDEDOR_REGISTER(known_hosts, "wear_and_tear.network_history", "fast", false, "behavioural.ssh_known_hosts");
PERDEDOR_REGISTER(arp, "wear_and_tear.network_history", "fast", false, "behavioural.arp_neighbors");
PERDEDOR_REGISTER(desktop_entries, "wear_and_tear.installed_software", "fast", false, "behavioural.desktop_entries");
PERDEDOR_REGISTER(thumbnails, "wear_and_tear.recent_files", "fast", false, "behavioural.thumbnail_cache");
PERDEDOR_REGISTER(cron_jobs, "wear_and_tear.installed_software", "fast", false, "behavioural.scheduled_jobs");
PERDEDOR_REGISTER(input_interrupts, "human.idle_time", "fast", false, "behavioural.input_interrupts");

}  // namespace perdedor
