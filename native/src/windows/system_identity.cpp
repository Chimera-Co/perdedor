#include "system_checks.hpp"
#include <lm.h>
#include <shellapi.h>
#include <algorithm>
#include <cstring>
namespace perdedor {
namespace {
using namespace winsys;
win::Result<std::string> username() {
    wchar_t value[UNLEN + 1];
    DWORD n = UNLEN + 1;
    if (!GetUserNameW(value, &n))
        return {{}, win::last_error_message()};
    return {win::narrow(value)};
}
win::Result<std::string> computer_name() {
    wchar_t value[256];
    DWORD n = 256;
    if (!GetComputerNameExW(ComputerNameDnsHostname, value, &n))
        return {{}, win::last_error_message()};
    return {win::narrow(std::wstring(value, n))};
}
std::vector<Finding> names(Context &, int kind) {
    const char *ids[] = {"design.suspicious_hostname_or_user", "design.exact_sandbox_username",
                         "design.exact_sandbox_hostname", "env.windows_sandbox_account"};
    const char *titles[] = {"Sandbox tokens in host or user names", "Exact sandbox user name",
                            "Exact sandbox host name", "Windows Sandbox account"};
    const auto id = ids[kind], name = titles[kind];
    auto u = username(), h = computer_name();
    if (!u.ok() || !h.ok())
        return {fail(id, name, !u.ok() ? u.error : h.error)};
    std::vector<std::string> hits;
    if (kind == 0) {
        for (const auto &text : {u.value, h.value}) {
            auto s = winlogic::match(text, winlogic::name_tokens());
            if (!s.empty())
                hits.push_back(s);
        }
    } else {
        auto s = winlogic::match(kind == 2 ? h.value : u.value,
                                 kind == 1   ? winlogic::usernames()
                                 : kind == 2 ? winlogic::hostnames()
                                             : std::vector<std::string>{"WDAGUtilityAccount"},
                                 true);
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, kind == 0 ? 2 : 1))};
}
std::vector<Finding> path_check(Context &ctx, int kind) {
    const char *ids[] = {"design.sample_filename", "design.sample_hash_name", "design.sample_directory",
                         "design.sample_location", "design.sample_short_path"};
    const char *titles[] = {"Known sample executable name", "Hash-like executable name",
                            "Analysis directory in executable path",
                            "Executable in Desktop or temporary directory", "Short executable path"};
    const char *id = ids[kind], *name = titles[kind];
    std::vector<wchar_t> path(32768);
    DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!n || n >= path.size())
        return {fail(id, name, "GetModuleFileNameW failed or truncated")};
    auto text = win::narrow(std::wstring(path.data(), n));
    bool hit = false;
    if (kind == 0)
        hit = winlogic::known_filename(text);
    if (kind == 1)
        hit = winlogic::hash_name(text);
    if (kind == 2)
        hit = winlogic::suspicious_path(text);
    if (kind == 3)
        hit = !winlogic::match(text, {"\\desktop\\", "\\temp\\", "\\tmp\\"}).empty();
    // A root-level executable is a weak automation hint. This is a policy default,
    // not an empirical classifier; docs/notes/windows.md explains the limitation.
    constexpr unsigned kShallowPathSeparators = 2;
    auto depth = std::count(text.begin(), text.end(), '\\');
    if (kind == 4)
        hit = depth <= std::max<long long>(
                           0, ctx.param_int("identity.max_shallow_separators", kShallowPathSeparators));
    return {result(
        id, name, hit,
        Ev().set("path_characters", n).set("directory_separators", static_cast<long long>(depth)))};
}
std::vector<Finding> parent(Context &) {
    const char *id = "design.parent_process", *name = "Analysis launcher parent process";
    auto all = win::processes();
    if (!all.ok())
        return {fail(id, name, all.error)};
    DWORD parent_pid = 0;
    for (const auto &p : all.value)
        if (p.pid == GetCurrentProcessId())
            parent_pid = p.parent;
    for (const auto &p : all.value)
        if (p.pid == parent_pid) {
            auto s = winlogic::match(p.name, winlogic::analysis_processes(), true);
            bool script = !winlogic::match(p.name,
                                           {"python.exe", "pythonw.exe", "wscript.exe", "cscript.exe",
                                            "powershell.exe", "pwsh.exe"},
                                           true)
                               .empty();
            return {result(id, name, !s.empty() || script,
                           Ev().set("analysis_signature", s).set("script_launcher", script))};
        }
    return {absent(id, name, "parent exited or was absent from the process snapshot")};
}
std::vector<Finding> command_line(Context &) {
    const char *id = "design.command_line", *name = "Sandbox tokens in process arguments";
    int n = 0;
    LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!args)
        return {fail(id, name, win::last_error_message())};
    unsigned hits = 0;
    for (int i = 1; i < n; ++i)
        if (!winlogic::match(win::narrow(args[i]), winlogic::name_tokens()).empty())
            ++hits;
    LocalFree(args);
    return {result(id, name, hits > 0,
                   Ev().set("argument_count", n - 1).set("matching_arguments", hits))};
}
std::vector<Finding> environment(Context &) {
    const char *id = "design.sandbox_environment", *name = "Analysis environment variable names";
    LPWCH block = GetEnvironmentStringsW();
    if (!block)
        return {fail(id, name, win::last_error_message())};
    std::vector<std::string> hits;
    size_t count = 0;
    for (const wchar_t *p = block; *p; p += std::wcslen(p) + 1) {
        if (++count > winlogic::kMaxEntries) {
            FreeEnvironmentStringsW(block);
            return {fail(id, name, "environment entry limit exceeded")};
        }
        std::wstring entry(p);
        auto end = entry.find(L'=');
        if (end == std::wstring::npos || end == 0)
            continue;
        auto key = win::narrow(entry.substr(0, end));
        auto signature = winlogic::match(key, {"cuckoo", "cape_", "sandbox", "drakvuf", "frida"});
        if (!signature.empty())
            hits.push_back(signature);
    }
    FreeEnvironmentStringsW(block);
    return {result(id, name, !hits.empty(), matched(hits, count))};
}
std::vector<Finding> domain(Context &) {
    const char *id = "design.domain_membership", *name = "Domain membership and default workgroup";
    LPWSTR value = nullptr;
    NETSETUP_JOIN_STATUS state = NetSetupUnknownStatus;
    auto e = NetGetJoinInformation(nullptr, &value, &state);
    if (e)
        return {fail(id, name, win::last_error_message(e))};
    bool generic = value && winlogic::lower(win::narrow(value)) == "workgroup";
    if (value)
        NetApiBufferFree(value);
    return {result(
        id, name, state == NetSetupWorkgroupName,
        Ev().set("join_status", static_cast<unsigned>(state)).set("default_workgroup", generic),
        Severity::Info, 0.2)}; // most home PCs are workgroup members; targeted malware wants a domain
}
std::vector<Finding> locale(Context &ctx, int kind) {
    const char *ids[] = {"design.locale",    "design.ui_language", "design.keyboard_layouts",
                         "design.time_zone", "design.geo_region",  "behavioural.installed_languages"};
    const char *titles[] = {"User locale", "User interface language", "Keyboard layouts",
                            "Time zone",   "Geographic region",       "Installed UI languages"};
    const char *id = ids[kind], *name = titles[kind];
    Ev ev = Ev();
    bool hit = false;
    std::string actual;
    if (kind == 0) {
        wchar_t s[LOCALE_NAME_MAX_LENGTH];
        if (!GetUserDefaultLocaleName(s, LOCALE_NAME_MAX_LENGTH))
            return {fail(id, name, win::last_error_message())};
        actual = win::narrow(s);
        ev.set("locale", actual);
    }
    if (kind == 1) {
        auto lang = GetUserDefaultUILanguage();
        actual = std::to_string(lang);
        ev.set("language_id", lang);
    }
    if (kind == 2) {
        int n = GetKeyboardLayoutList(0, nullptr);
        if (!n)
            return {fail(id, name, win::last_error_message())};
        std::vector<HKL> layouts(static_cast<size_t>(n));
        int got = GetKeyboardLayoutList(n, layouts.data());
        if (!got)
            return {fail(id, name, win::last_error_message())};
        Json list = Json::array();
        for (int i = 0; i < got; ++i)
            list.push(static_cast<unsigned>(reinterpret_cast<uintptr_t>(layouts[i]) & 0xffff));
        ev.set("language_ids", list);
    }
    if (kind == 3) {
        DYNAMIC_TIME_ZONE_INFORMATION z{};
        DWORD rc = GetDynamicTimeZoneInformation(&z);
        if (rc == TIME_ZONE_ID_INVALID)
            return {fail(id, name, win::last_error_message())};
        actual = win::narrow(z.TimeZoneKeyName);
        ev.set("key", actual).set("bias_minutes", z.Bias);
    }
    if (kind == 4) {
        GEOID g = GetUserGeoID(GEOCLASS_NATION);
        if (g == GEOID_NOT_AVAILABLE)
            return {absent(id, name, "user geographic region unset")};
        actual = std::to_string(g);
        ev.set("geo_id", g);
    }
    if (kind == 5) {
        auto v =
            win::registry_names(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\MUI\\UILanguages");
        if (!v.ok())
            return {fail(id, name, v.error)};
        if (v.absent)
            return {absent(id, name, "UI language inventory unavailable")};
        ev.set("count", static_cast<unsigned>(v.value.size()));
    }
    auto expected = ctx.param(std::string("identity.") + ids[kind] + ".expected", "");
    if (!expected.empty() && !actual.empty())
        hit = winlogic::lower(expected) != winlogic::lower(actual);
    ev.set("expectation_supplied", !expected.empty());
    return {result(id, name, hit, ev, Severity::Info)};
}
std::vector<Finding> os_age(Context &) {
    const char *id = "behavioural.os_install_age", *name = "Windows installation age";
    auto v = win::registry_number(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                                  L"InstallDate");
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {absent(id, name, "installation date unavailable")};
    int64_t age = win::now_days() - static_cast<int64_t>(v.value / 86400);
    if (age < 0)
        return {fail(id, name, "installation date is in the future")};
    return {result(id, name, age < winlogic::kYoungDays,
                   Ev().set("age_days", static_cast<long long>(age)))};
}
std::vector<Finding> os_product(Context &ctx) {
    const char *id = "design.os_product_build", *name = "Windows product and build policy";
    const wchar_t *key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    auto p = win::registry_string(HKEY_LOCAL_MACHINE, key, L"ProductName"),
         b = win::registry_string(HKEY_LOCAL_MACHINE, key, L"CurrentBuildNumber");
    if (!p.ok() || !b.ok())
        return {fail(id, name, !p.ok() ? p.error : b.error)};
    uint64_t build = 0;
    if (b.absent || !winlogic::integer(b.value, build))
        return {absent(id, name, "numeric Windows build unavailable")};
    auto minimum =
        std::max<long long>(0, ctx.param_int("identity.minimum_build", 0)); // no default expiry policy
    return {result(id, name, build < static_cast<uint64_t>(minimum),
                   Ev().set("product", p.value).set("build", build).set("minimum_build", minimum),
                   Severity::Info)};
}
std::vector<Finding> wine(Context &) {
    const char *id = "env.wine_exports", *name = "Wine compatibility exports";
    bool unix_name = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "wine_get_unix_file_name") != nullptr;
    bool version = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version") != nullptr;
    return {result(id, name, unix_name || version,
                   Ev().set("wine_get_unix_file_name", unix_name).set("wine_get_version", version),
                   Severity::High, 0.99)};
}

std::vector<Finding> name_0(Context &ctx) { return names(ctx, 0); }

std::vector<Finding> name_1(Context &ctx) { return names(ctx, 1); }

std::vector<Finding> name_2(Context &ctx) { return names(ctx, 2); }

std::vector<Finding> name_3(Context &ctx) { return names(ctx, 3); }

std::vector<Finding> path_0(Context &ctx) { return path_check(ctx, 0); }

std::vector<Finding> path_1(Context &ctx) { return path_check(ctx, 1); }

std::vector<Finding> path_2(Context &ctx) { return path_check(ctx, 2); }

std::vector<Finding> path_3(Context &ctx) { return path_check(ctx, 3); }

std::vector<Finding> path_4(Context &ctx) { return path_check(ctx, 4); }

std::vector<Finding> locale_0(Context &ctx) { return locale(ctx, 0); }

std::vector<Finding> locale_1(Context &ctx) { return locale(ctx, 1); }

std::vector<Finding> locale_2(Context &ctx) { return locale(ctx, 2); }

std::vector<Finding> locale_3(Context &ctx) { return locale(ctx, 3); }

std::vector<Finding> locale_4(Context &ctx) { return locale(ctx, 4); }

std::vector<Finding> locale_5(Context &ctx) { return locale(ctx, 5); }
} // namespace
PERDEDOR_REGISTER(name_0, "identity.hostname", "fast", false, "design.suspicious_hostname_or_user");
PERDEDOR_REGISTER(name_1, "identity.username", "fast", false, "design.exact_sandbox_username");
PERDEDOR_REGISTER(name_2, "identity.hostname", "fast", false, "design.exact_sandbox_hostname");
PERDEDOR_REGISTER(name_3, "container.app_sandbox", "fast", false, "env.windows_sandbox_account");
PERDEDOR_REGISTER(path_0, "identity.sample_path", "fast", false, "design.sample_filename");
PERDEDOR_REGISTER(path_1, "identity.sample_path", "fast", false, "design.sample_hash_name");
PERDEDOR_REGISTER(path_2, "identity.sample_path", "fast", false, "design.sample_directory");
PERDEDOR_REGISTER(path_3, "identity.sample_path", "fast", false, "design.sample_location");
PERDEDOR_REGISTER(path_4, "identity.sample_path", "fast", false, "design.sample_short_path");
PERDEDOR_REGISTER(locale_0, "identity.locale", "fast", false, "design.locale");
PERDEDOR_REGISTER(locale_1, "identity.locale", "fast", false, "design.ui_language");
PERDEDOR_REGISTER(locale_2, "identity.locale", "fast", false, "design.keyboard_layouts");
PERDEDOR_REGISTER(locale_3, "identity.locale", "fast", false, "design.time_zone");
PERDEDOR_REGISTER(locale_4, "identity.locale", "fast", false, "design.geo_region");
PERDEDOR_REGISTER(locale_5, "identity.locale", "fast", false, "behavioural.installed_languages");
PERDEDOR_REGISTER(parent, "identity.parent_process", "fast", false, "design.parent_process");
PERDEDOR_REGISTER(command_line, "identity.sample_path", "fast", false, "design.command_line");
PERDEDOR_REGISTER(environment, "identity.environment_variables", "fast", false, "design.sandbox_environment");
PERDEDOR_REGISTER(domain, "identity.domain_membership", "medium", false, "design.domain_membership");
PERDEDOR_REGISTER(os_age, "wear_and_tear.system_age", "fast", false, "behavioural.os_install_age");
PERDEDOR_REGISTER(os_product, "identity.locale", "fast", false, "design.os_product_build");
PERDEDOR_REGISTER(wine, "emulator.wine", "fast", false, "env.wine_exports");
} // namespace perdedor
