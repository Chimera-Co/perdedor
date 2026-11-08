// Non-CPU timing tells on Linux: uptime, paravirtual clock sources, time zone,
// NTP synchronisation and file times in the future.
//
// Sources: v1 Linux agent timing.py (low uptime), Pafish/al-khaser uptime
// checks (GetTickCount), Linux Documentation/timers and clocksource sysfs ABI,
// adjtimex(2).
#include <sys/timex.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

// v1 _LOW_UPTIME_SECONDS (Pafish-class "booted for this sample" threshold).
constexpr double kLowUptimeSeconds = 600.0;
// Files modified more than a day after the current clock: beyond any time-zone or DST error.
constexpr long long kFutureSlackSeconds = 24 * 3600;

const std::vector<std::string>& pv_clocks() {
    // Clocksource names registered by arch/x86/kernel/kvmclock.c ("kvm-clock"), arch/x86/xen/time.c ("xen"),
    // drivers/clocksource/hyperv_timer.c ("hyperv_clocksource_tsc_page", "hyperv_clocksource_msr").
    static const std::vector<std::string> s = {"kvm-clock", "xen", "hyperv_clocksource_tsc_page",
        "hyperv_clocksource_msr", "lguest", "vmware"};
    return s;
}

std::vector<Finding> uptime(Context& ctx) {
    const char* id = "timing.low_uptime";
    const char* name = "System uptime";
    const char* desc = "Low uptime suggests the VM was booted specifically for this analysis run (Pafish-class check).";
    Root root(ctx);
    auto r = root.read("/proc/uptime");
    if (!r.ok) return {unreadable(id, name, desc, Severity::Low, r.err, "/proc/uptime")};
    char* end = nullptr;
    double up = std::strtod(r.value.c_str(), &end);
    if (end == r.value.c_str()) return {error(id, name, desc, Severity::Low, "unparseable /proc/uptime")};
    double limit = ctx.param_double("timing.min_uptime_seconds", kLowUptimeSeconds);
    return {measured(id, name, desc, up, limit, up < limit, "s",
                     "Boot the sandbox and idle (or restore a snapshot taken long after boot) before detonating.",
                     Severity::Low, 0.4)};
}

std::vector<Finding> clock_source(Context& ctx) {
    const char* id = "timing.clock_source";
    const char* name = "Paravirtual clock source in use";
    const char* desc = "/sys/devices/system/clocksource/clocksource0/current_clocksource is kvm-clock, xen or a "
                       "Hyper-V clock: the kernel trusts a hypervisor time interface.";
    Root root(ctx);
    bool ok;
    std::string cur = read_value(root, "/sys/devices/system/clocksource/clocksource0/current_clocksource", ok);
    if (!ok) return {skipped(id, name, desc, Severity::High, "no clocksource sysfs")};
    bool hit = false;
    for (const auto& c : pv_clocks())
        if (cur == c) hit = true;
    Json ev = Json::object();
    ev.set("current", cur);
    return {bool_check(id, name, desc, Severity::High, hit, ev,
                       "Make the guest use tsc (Xen HVM: tsc_mode='native' or 'always_emulate' plus clocksource=tsc; "
                       "do not expose the Xen PV clock).")};
}

std::vector<Finding> clock_available(Context& ctx) {
    const char* id = "timing.clock_source_available";
    const char* name = "Paravirtual clock source registered";
    const char* desc = "available_clocksource lists a hypervisor clock even when tsc is selected.";
    Root root(ctx);
    bool ok;
    std::string av = read_value(root, "/sys/devices/system/clocksource/clocksource0/available_clocksource", ok);
    if (!ok) return {skipped(id, name, desc, Severity::Medium, "no clocksource sysfs")};
    std::vector<std::string> hits;
    for (const auto& tok : split(av, ' '))
        for (const auto& c : pv_clocks())
            if (tok == c) hits.push_back(tok);
    Json ev = Json::object();
    ev.set("available", av);
    return {bool_check(id, name, desc, Severity::Medium, !hits.empty(), ev,
                       "Hide the hypervisor so the guest kernel never registers its clock (Xen + DRAKVUF: cpuidmon -s "
                       "masks the leaves the kernel probes).")};
}

std::vector<Finding> time_zone(Context& ctx) {
    const char* id = "timing.time_zone_utc";
    const char* name = "Time zone is UTC";
    const char* desc = "/etc/timezone, the /etc/localtime link or TZ say UTC/GMT/Etc: servers and sandboxes keep "
                       "the image default, end-user desktops are set to a local zone.";
    Root root(ctx);
    std::string tz;
    auto env = root.environment();
    if (env.count("TZ")) tz = env["TZ"];
    bool ok;
    if (tz.empty()) tz = read_value(root, "/etc/timezone", ok);
    if (tz.empty()) {
        auto l = root.link("/etc/localtime");
        if (l.ok) {
            auto p = l.value.find("zoneinfo/");
            tz = p == std::string::npos ? l.value : l.value.substr(p + 9);
        }
    }
    if (tz.empty()) return {skipped(id, name, desc, Severity::Low, "time zone not determinable")};
    std::string t = lower(tz);
    if (!t.empty() && t[0] == ':') t = t.substr(1);
    bool utc = t == "utc" || t == "etc/utc" || t == "gmt" || t == "etc/gmt" || t == "universal" || t == "zulu" ||
               t == "etc/universal" || t == "etc/zulu" || t == "uct" || t == "etc/uct" || t == "gmt0" || t == "etc/gmt0";
    Json ev = Json::object();
    ev.set("timezone", tz.substr(0, 60));
    auto f = bool_check(id, name, desc, Severity::Low, utc, ev, "Set the time zone the impersonated user would have.");
    f.confidence = 0.5;
    return {f};
}

std::vector<Finding> ntp(Context& ctx) {
    const char* id = "timing.ntp_unsynchronised";
    const char* name = "Clock not NTP-synchronised";
    const char* desc = "adjtimex(2) read-only query reports TIME_ERROR (clock unsynchronised): isolated analysis "
                       "networks have no time source.";
    Root root(ctx);
    if (root.fixture()) {
        bool synced = root.exists("/run/systemd/timesync/synchronized");
        return {bool_check(id, name, desc, Severity::Low, !synced, synced ? "timesyncd synchronized" : "no sync marker",
                           "Give the analysis network an NTP server (INetSim ntp service or a local chrony).")};
    }
    struct timex tx {};
    tx.modes = 0;  // query only
    int state = adjtimex(&tx);
    if (state < 0) return {error(id, name, desc, Severity::Low, std::string("adjtimex: ") + std::strerror(errno))};
    Json ev = Json::object();
    ev.set("state", state);
    ev.set("status", static_cast<long long>(tx.status));
    ev.set("unsync", (tx.status & STA_UNSYNC) != 0);
    return {bool_check(id, name, desc, Severity::Low, state == TIME_ERROR, ev,
                       "Give the analysis network an NTP server (INetSim ntp service or a local chrony).")};
}

std::vector<Finding> future_files(Context& ctx) {
    const char* id = "timing.future_file_times";
    const char* name = "Files modified in the future";
    const char* desc = "Logs and configuration modified more than a day after the current clock: the clock was "
                       "reset or a snapshot was restored without advancing time.";
    Root root(ctx);
    long long now = root.now();
    Evidence e;
    for (const char* dir : {"/var/log", "/etc", "/var/lib/dpkg"}) {
        auto c = count_files(root, dir, {}, 2);
        if (!c.ok) continue;
        ++e.observed;
        e.partial |= c.partial;
        if (c.newest > now + kFutureSlackSeconds)
            e.add(std::string(dir) + ": newest mtime " + std::to_string((c.newest - now) / 86400) + " days ahead");
    }
    Finding f = e.finding(id, name, desc, Severity::Medium,
                          "Advance the guest clock to real time after restoring a snapshot (Xen: xl restore keeps "
                          "the saved time; set it from the host or with NTP).");
    if (f.status == Status::Skipped && e.observed && e.hits.empty()) f = clean(id, name, desc, Severity::Medium, e.json());
    return {f};
}

}  // namespace

PERDEDOR_REGISTER(uptime, "timing.uptime", "fast", false, "timing.low_uptime");
PERDEDOR_REGISTER(clock_source, "timing.clock_source", "fast", false, "timing.clock_source");
PERDEDOR_REGISTER(clock_available, "timing.clock_source", "fast", false, "timing.clock_source_available");
PERDEDOR_REGISTER(time_zone, "timing.time_plausibility", "fast", false, "timing.time_zone_utc");
PERDEDOR_REGISTER(ntp, "timing.time_plausibility", "fast", false, "timing.ntp_unsynchronised");
PERDEDOR_REGISTER(future_files, "timing.time_plausibility", "fast", false, "timing.future_file_times");

}  // namespace perdedor
