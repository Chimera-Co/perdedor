#include "system_checks.hpp"
#include <winternl.h>
#include <algorithm>
namespace perdedor {
namespace {
using namespace winsys;
std::vector<Finding> number_policy(const char *id, const char *name, HKEY root, const wchar_t *path,
                                   const wchar_t *key, bool zero) {
    auto v = win::registry_number(root, path, key);
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {absent(id, name, "explicit registry policy is not configured")};
    return {result(id, name, zero ? v.value == 0 : v.value != 0, Ev().set("value", v.value))};
}
std::vector<Finding> string_policy(const char *id, const char *name, HKEY root, const wchar_t *path,
                                   const wchar_t *key, const std::vector<std::string> &tokens) {
    auto v = win::registry_string(root, path, key);
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {absent(id, name, "explicit registry policy is not configured")};
    auto s = winlogic::match(v.value, tokens, true);
    return {result(id, name, !s.empty(), Ev().set("matched_setting", s))};
}
std::vector<Finding> boot_flags(Context &, int kind) {
    const char *ids[] = {"design.boot_test_signing", "design.boot_debug", "design.boot_no_integrity",
                         "design.hypervisor_launch_type"};
    const char *names[] = {"Test signing boot option", "Debug boot option",
                           "Integrity-check bypass boot option", "Hypervisor launch boot option"};
    auto v = win::registry_string(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control",
                                  L"SystemStartOptions");
    if (!v.ok())
        return {fail(ids[kind], names[kind], v.error)};
    if (v.absent)
        return {absent(ids[kind], names[kind], "SystemStartOptions is not exposed")};
    const std::vector<std::vector<std::string>> flags = {
        {"testsigning", "testsigning=on", "testsigning=yes"},
        {"debug", "debug=on", "debug=yes"},
        {"nointegritychecks", "nointegritychecks=on", "disable_integrity_checks"},
        {"hypervisorlaunchtype=auto", "hypervisorlaunchtype=off"}};
    std::vector<std::string> hits;
    std::string token;
    for (char c : v.value + " ") {
        if (c == ' ' || c == '\t') {
            auto s = winlogic::match(token, flags[kind], true);
            if (!s.empty())
                hits.push_back(s);
            token.clear();
        } else
            token += c;
    }
    // The boot loader writes the kernel load options it applied (TESTSIGNING, DEBUG,
    // DISABLE_INTEGRITY_CHECKS ...) into SystemStartOptions, so their absence means the
    // running kernel was not started with them. hypervisorlaunchtype is a BCD-only
    // setting that never appears there; its absence is therefore inconclusive.
    if (hits.empty() && kind == 3)
        return {absent(ids[kind], names[kind], "hypervisorlaunchtype is not reflected in SystemStartOptions")};
    return {result(ids[kind], names[kind], !hits.empty(), matched(hits, 1))};
}
std::vector<Finding> code_integrity(Context &, bool test) {
    const char *id = test ? "design.code_integrity_test_signing" : "design.driver_signature_enforcement";
    const char *name =
        test ? "Active code integrity test-signing state" : "Active driver signature enforcement";
    // SystemCodeIntegrityInformation and option bits, Microsoft NtQuerySystemInformation documentation.
    constexpr ULONG kSystemCodeIntegrityInformation = 103, kEnabled = 1, kTestSign = 2;
    using Query = NTSTATUS(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
    auto query = win::proc<Query>(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!query)
        return {absent(id, name, "NtQuerySystemInformation unavailable")};
    struct Info {
        ULONG length, options;
    } info{sizeof(Info), 0};
    ULONG returned = 0;
    NTSTATUS s = query(kSystemCodeIntegrityInformation, &info, sizeof info, &returned);
    if (s < 0)
        return {fail(id, name, "SystemCodeIntegrityInformation status " + std::to_string(s))};
    if (returned != sizeof info)
        return {fail(id, name, "unexpected code integrity structure length")};
    return {result(id, name, test ? (info.options & kTestSign) != 0 : (info.options & kEnabled) == 0,
                   Ev().set("options", info.options))};
}
std::vector<Finding> license_vm(Context &) {
    const char *id = "env.license_virtual_machine", *name = "Kernel licensing virtual-machine report";
    using Query = NTSTATUS(NTAPI *)(PUNICODE_STRING, PULONG, PVOID, ULONG, PULONG);
    auto query = win::proc<Query>(GetModuleHandleW(L"ntdll.dll"), "NtQueryLicenseValue");
    if (!query)
        return {absent(id, name, "NtQueryLicenseValue unavailable")};
    // al-khaser query_license_value; value is an OS virtualization report, not an activation bypass.
    wchar_t text[] = L"Kernel-VMDetection-Private";
    UNICODE_STRING key{};
    key.Buffer = text;
    key.Length = sizeof(text) - sizeof(wchar_t);
    key.MaximumLength = sizeof text;
    ULONG type = 0, value = 0, bytes = 0;
    NTSTATUS s = query(&key, &type, &value, sizeof value, &bytes);
    if (static_cast<ULONG>(s) == 0xc0000034UL)
        return {absent(id, name, "licensing value absent on this Windows edition")};
    if (s < 0)
        return {fail(id, name, "NtQueryLicenseValue status " + std::to_string(s))};
    if (type != REG_DWORD || bytes != sizeof value)
        return {fail(id, name, "unexpected licensing value type or size")};
    return {result(id, name, value != 0, Ev().set("virtual_machine", value != 0))};
}

std::vector<Finding> config_uac_enabled(Context &) {
    return number_policy("design.uac_enabled", "Uac enabled", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA",
                         true);
}

std::vector<Finding> config_uac_admin_consent(Context &) {
    return number_policy("design.uac_admin_consent", "Uac admin consent", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                         L"ConsentPromptBehaviorAdmin", true);
}

std::vector<Finding> config_defender_disabled(Context &) {
    return number_policy("design.defender_disabled", "Defender disabled", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", false);
}

std::vector<Finding> config_defender_realtime_disabled(Context &) {
    return number_policy("design.defender_realtime_disabled", "Defender realtime disabled",
                         HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                         L"DisableRealtimeMonitoring", false);
}

std::vector<Finding> config_antivirus_policy_disabled(Context &) {
    return number_policy("design.antivirus_policy_disabled", "Antivirus policy disabled", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiVirus", false);
}

std::vector<Finding> config_powershell_policy_machine(Context &) {
    return string_policy("design.powershell_policy_machine", "Powershell policy machine", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
                         L"ExecutionPolicy", {"Bypass", "Unrestricted"});
}

std::vector<Finding> config_powershell_group_policy_machine(Context &) {
    return string_policy("design.powershell_group_policy_machine", "Powershell group policy machine",
                         HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
                         L"ExecutionPolicy", {"Bypass", "Unrestricted"});
}

std::vector<Finding> config_script_host_disabled_machine(Context &) {
    return number_policy("design.script_host_disabled_machine", "Script host disabled machine",
                         HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Script Host\\Settings",
                         L"Enabled", true);
}

std::vector<Finding> config_powershell_policy_user(Context &) {
    return string_policy("design.powershell_policy_user", "Powershell policy user", HKEY_CURRENT_USER,
                         L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
                         L"ExecutionPolicy", {"Bypass", "Unrestricted"});
}

std::vector<Finding> config_powershell_group_policy_user(Context &) {
    return string_policy("design.powershell_group_policy_user", "Powershell group policy user",
                         HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell",
                         L"ExecutionPolicy", {"Bypass", "Unrestricted"});
}

std::vector<Finding> config_script_host_disabled_user(Context &) {
    return number_policy("design.script_host_disabled_user", "Script host disabled user", HKEY_CURRENT_USER,
                         L"SOFTWARE\\Microsoft\\Windows Script Host\\Settings", L"Enabled", true);
}

std::vector<Finding> config_autologon(Context &) {
    return string_policy("design.autologon", "Autologon", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AutoAdminLogon",
                         {"1"});
}

std::vector<Finding> config_smartscreen_off(Context &) {
    return string_policy("design.smartscreen_off", "Smartscreen off", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer", L"SmartScreenEnabled",
                         {"Off"});
}

std::vector<Finding> config_smartscreen_policy_off(Context &) {
    return number_policy("design.smartscreen_policy_off", "Smartscreen policy off", HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", L"EnableSmartScreen", true);
}

std::vector<Finding> boot_0(Context &ctx) { return boot_flags(ctx, 0); }

std::vector<Finding> boot_1(Context &ctx) { return boot_flags(ctx, 1); }

std::vector<Finding> boot_2(Context &ctx) { return boot_flags(ctx, 2); }

std::vector<Finding> boot_3(Context &ctx) { return boot_flags(ctx, 3); }

std::vector<Finding> ci_test(Context &ctx) { return code_integrity(ctx, true); }
std::vector<Finding> ci_enforce(Context &ctx) { return code_integrity(ctx, false); }
} // namespace
PERDEDOR_REGISTER(config_uac_enabled, "os_config.uac_sip", "fast", false, "design.uac_enabled");
PERDEDOR_REGISTER(config_uac_admin_consent, "os_config.uac_sip", "fast", false, "design.uac_admin_consent");
PERDEDOR_REGISTER(config_defender_disabled, "os_config.security_software", "fast", false,
                  "design.defender_disabled");
PERDEDOR_REGISTER(config_defender_realtime_disabled, "os_config.security_software", "fast", false,
                  "design.defender_realtime_disabled");
PERDEDOR_REGISTER(config_antivirus_policy_disabled, "os_config.security_software", "fast", false,
                  "design.antivirus_policy_disabled");
PERDEDOR_REGISTER(config_powershell_policy_machine, "os_config.script_policies", "fast", false,
                  "design.powershell_policy_machine");
PERDEDOR_REGISTER(config_powershell_group_policy_machine, "os_config.script_policies", "fast", false,
                  "design.powershell_group_policy_machine");
PERDEDOR_REGISTER(config_script_host_disabled_machine, "os_config.script_policies", "fast", false,
                  "design.script_host_disabled_machine");
PERDEDOR_REGISTER(config_powershell_policy_user, "os_config.script_policies", "fast", false,
                  "design.powershell_policy_user");
PERDEDOR_REGISTER(config_powershell_group_policy_user, "os_config.script_policies", "fast", false,
                  "design.powershell_group_policy_user");
PERDEDOR_REGISTER(config_script_host_disabled_user, "os_config.script_policies", "fast", false,
                  "design.script_host_disabled_user");
PERDEDOR_REGISTER(config_autologon, "os_config.script_policies", "fast", false, "design.autologon");
PERDEDOR_REGISTER(config_smartscreen_off, "os_config.security_software", "fast", false,
                  "design.smartscreen_off");
PERDEDOR_REGISTER(config_smartscreen_policy_off, "os_config.security_software", "fast", false,
                  "design.smartscreen_policy_off");
PERDEDOR_REGISTER(boot_0, "os_config.boot_debug_flags", "fast", false, "design.boot_test_signing");
PERDEDOR_REGISTER(boot_1, "os_config.boot_debug_flags", "fast", false, "design.boot_debug");
PERDEDOR_REGISTER(boot_2, "os_config.boot_debug_flags", "fast", false, "design.boot_no_integrity");
PERDEDOR_REGISTER(boot_3, "os_config.boot_debug_flags", "fast", false, "design.hypervisor_launch_type");
PERDEDOR_REGISTER(ci_test, "os_config.boot_debug_flags", "fast", false, "design.code_integrity_test_signing");
PERDEDOR_REGISTER(ci_enforce, "os_config.boot_debug_flags", "fast", false,
                  "design.driver_signature_enforcement");
PERDEDOR_REGISTER(license_vm, "container.virtualisation_report", "fast", false,
                  "env.license_virtual_machine");
} // namespace perdedor
