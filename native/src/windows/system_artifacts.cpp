#include "system_checks.hpp"
#include <algorithm>
namespace perdedor {
namespace {
using namespace winsys;
struct RegistryRule {
    HKEY root;
    std::wstring path;
    std::vector<std::wstring> values;
    std::vector<std::string> tokens;
    bool recurse = false, subkeys = false;
};
// Recursion depth below the rule's root: Enum\<bus>\<device>\<instance> and
// Class\{guid}\<index> both sit within three levels; DEVICEMAP\Scsi needs four.
constexpr int kRegistryDepth = 4;
constexpr size_t kRegistryKeys = 3 * winlogic::kMaxEntries;
bool redirected(const std::wstring &path) {
    // Only HKLM\SOFTWARE (and HKCU\Software\Classes views of it) differ between the 32- and
    // 64-bit registry views; scanning SYSTEM/HARDWARE twice would only double the cost.
    return winlogic::lower(win::narrow(path)).rfind("software", 0) == 0;
}
std::vector<Finding> registry_probe(const char *id, const char *name,
                                    const std::vector<RegistryRule> &rules) {
    std::vector<std::string> hits;
    size_t visited = 0, denied = 0;
    std::string failure;
    auto deadline = GetTickCount64() + winlogic::kTreeScanMs;
    auto note = [&](const std::string &error, long code) {
        if (error.empty())
            return;
        if (code == ERROR_ACCESS_DENIED || error.rfind("error 5:", 0) == 0)
            ++denied;
        else
            failure = error;
    };
    for (const auto &rule : rules)
        for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
            if (view == KEY_WOW64_32KEY && !redirected(rule.path))
                continue;
            std::vector<std::pair<std::wstring, int>> todo{{rule.path, 0}};
            while (!todo.empty()) {
                auto item = todo.back();
                todo.pop_back();
                const auto &path = item.first;
                if (++visited > kRegistryKeys || GetTickCount64() >= deadline)
                    return {fail(id, name, "registry scan budget exhausted before the tree was covered")};
                if (rule.values.empty() && !rule.subkeys) {
                    auto v = win::registry_exists(rule.root, path, view);
                    note(v.error, v.code);
                    if (v.value)
                        hits.push_back(win::narrow(path));
                } else
                    for (const auto &key : rule.values) {
                        auto v = win::registry_string(rule.root, path, key, view);
                        // A same-named value of another type (binary DriverDesc etc.) is not a string match.
                        if (v.error != "unexpected registry string type/length")
                            note(v.error, v.code);
                        auto sig = winlogic::match(v.value, rule.tokens);
                        if (!sig.empty())
                            hits.push_back(win::narrow(key) + ": " + sig);
                    }
                if ((rule.recurse && item.second < kRegistryDepth) || (rule.subkeys && item.second == 0)) {
                    auto children = win::registry_names(rule.root, path, false, view);
                    note(children.error, children.code);
                    for (const auto &c : children.value) {
                        if (rule.subkeys) {
                            auto sig = winlogic::match(win::narrow(c), rule.tokens);
                            if (!sig.empty())
                                hits.push_back(sig);
                        }
                        if (rule.recurse && item.second < kRegistryDepth)
                            todo.push_back({path + L"\\" + c, item.second + 1});
                    }
                }
            }
        }
    if (!failure.empty() && hits.empty())
        return {fail(id, name, failure)};
    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    auto ev = matched(hits, visited);
    ev.set("access_denied_keys", static_cast<unsigned long long>(denied));
    return {result(id, name, !hits.empty(), ev, Severity::High, 0.85,
                   "Remove obsolete guest-tool installations and device remnants from the golden image; "
                   "preserve required active drivers.")};
}
std::vector<Finding> files_probe(const char *id, const char *name, const std::vector<std::wstring> &paths) {
    std::vector<std::string> hits;
    for (const auto &p : paths) {
        auto f = win::file_size(p);
        if (!f.ok())
            return {fail(id, name, f.error)};
        if (!f.absent)
            hits.push_back(win::narrow(p));
    }
    return {result(id, name, !hits.empty(), matched(hits, paths.size()), Severity::High, 0.8,
                   "Uninstall the identified guest additions or sandbox software when it is not required by "
                   "the guest.")};
}
std::vector<Finding> names_probe(const char *id, const char *name, const std::string &source,
                                 const std::vector<std::string> &tokens) {
    win::Result<std::vector<std::string>> values;
    if (source == "process") {
        auto p = win::processes();
        values.error = p.error;
        for (const auto &row : p.value)
            values.value.push_back(row.name);
    } else if (source == "module")
        values = win::loaded_modules();
    else if (source == "driver")
        values = win::loaded_drivers();
    else if (source == "service") {
        auto all = win::services();
        values.error = all.error;
        for (const auto &svc : all.value) {
            // The Hyper-V integration services (vmic*) ship inbox with every Windows 8+
            // install; they only run when a VMBus channel offers them, i.e. in a Hyper-V
            // (or Viridian-enlightened) guest. Registered-but-stopped is therefore no tell.
            if (winlogic::lower(svc.name).rfind("vmic", 0) == 0 && svc.state != SERVICE_RUNNING)
                continue;
            values.value.push_back(svc.name);
        }
    }
    else {
        auto w = win::windows();
        values.error = w.error;
        for (const auto &row : w.value)
            values.value.push_back(source == "title" ? row.title : row.klass);
    }
    if (!values.ok())
        return {fail(id, name, values.error)};
    std::vector<std::string> hits;
    for (const auto &v : values.value) {
        auto s = winlogic::match(v, tokens, source != "title" && source != "driver");
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, values.value.size()), Severity::Medium, 0.7,
                   "Keep analysis tools outside the guest and remove unneeded guest integration software "
                   "from the image.")};
}
std::vector<Finding> object_probe(const char *id, const char *name, const std::wstring &directory,
                                  const std::vector<std::string> &tokens) {
    auto v = win::objects(directory);
    if (!v.ok())
        return {fail(id, name, v.error)};
    if (v.absent)
        return {absent(id, name, "native object enumeration unavailable")};
    std::vector<std::string> hits;
    for (const auto &x : v.value) {
        auto s = winlogic::match(x, tokens);
        if (!s.empty())
            hits.push_back(s);
    }
    return {result(id, name, !hits.empty(), matched(hits, v.value.size()), Severity::High, 0.9)};
}
std::vector<Finding> named_probe(const char *id, const char *name, const char *kind,
                                 const std::vector<std::wstring> &paths) {
    std::vector<std::string> hits;
    for (const auto &p : paths) {
        auto v = win::named_object(p, kind);
        if (!v.ok())
            return {fail(id, name, v.error)};
        if (v.value)
            hits.push_back(win::narrow(p));
    }
    return {result(id, name, !hits.empty(), matched(hits, paths.size()), Severity::High, 0.9)};
}

std::vector<Finding> artifact_env_bochs_bochs_systembiosversion_registry_key(Context &) {
    return registry_probe("env.bochs_bochs_systembiosversion_registry_key",
                          "bochs: BOCHS SystemBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"SystemBiosVersion"},
                            {"BOCHS"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_bochs_bochs_videobiosversion_registry_key(Context &) {
    return registry_probe("env.bochs_bochs_videobiosversion_registry_key",
                          "bochs: BOCHS VideoBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"VideoBiosVersion"},
                            {"BOCHS"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_generic_diskenum_registry_key(Context &) {
    return registry_probe("env.generic_diskenum_registry_key", "generic: DiskEnum Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services\\Disk\\Enum",
                            {L"0"},
                            {"virtual"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_hyperv_hyper_v_hklm_registry_keys(Context &) {
    return registry_probe(
        "env.hyperv_hyper_v_hklm_registry_keys", "hyperv: Hyper-V HKLM Registry Keys",
        {{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Hyper-V", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\VirtualMachine", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_hyperv_hyper_v_services_registry_keys(Context &) {
    // InviZzzible tests that the vmic* service keys exist. Windows 8+ registers them on
    // every install, so the native check requires the services to be running (the SCM
    // state reflects the key's service); see names_probe.
    return names_probe("env.hyperv_hyper_v_services_registry_keys", "hyperv: Hyper-V Services Registry Keys",
                       "service", {"vmicheartbeat", "vmicvss", "vmicshutdown", "vmicexchange"});
}

std::vector<Finding> artifact_env_hyperv_hyper_v_directory_device_object(Context &) {
    return object_probe("env.hyperv_hyper_v_directory_device_object",
                        "hyperv: Hyper-V Directory Device Object", L"\\Device", {"VmGenerationCounter"});
}

std::vector<Finding> artifact_env_joebox_joebox_windows_product_id_registry_key(Context &) {
    return registry_probe("env.joebox_joebox_windows_product_id_registry_key",
                          "joebox: JoeBox Windows Product ID Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                            {L"ProductID"},
                            {"55274-640-2673064-23950"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_joebox_joebox_windows_nt_product_id_registry_key(Context &) {
    return registry_probe("env.joebox_joebox_windows_nt_product_id_registry_key",
                          "joebox: JoeBox Windows NT Product ID Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                            {L"ProductID"},
                            {"55274-640-2673064-23950"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_joebox_joebox_processes(Context &) {
    return names_probe("env.joebox_joebox_processes", "joebox: JoeBox Processes", "process",
                       {"joeboxserver.exe", "joeboxcontrol.exe"});
}

std::vector<Finding> artifact_env_misc_side_processes(Context &) {
    return names_probe("env.misc_side_processes", "misc: Side Processes", "process", {"WPE Pro.exe"});
}

std::vector<Finding> artifact_env_misc_sandbox_registry_keys(Context &) {
    return registry_probe(
        "env.misc_sandbox_registry_keys", "misc: Sandbox Registry Keys",
        {{HKEY_LOCAL_MACHINE, L"Software\\Classes\\Folder\\shell\\sandbox", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_misc_sandbox_specific_files(Context &) {
    return files_probe("env.misc_sandbox_specific_files", "misc: Sandbox Specific Files",
                       {L"c:\\analysis\\", L"C:\\Symbols\\aagmmc.pdb", L"C:\\take_screenshot.ps1",
                        L"C:\\loaddll.exe", L"C:\\email.doc", L"C:\\email.htm", L"C:\\123\\email.doc",
                        L"C:\\123\\email.docx", L"C:\\a\\foobar.bmp", L"C:\\a\\foobar.doc",
                        L"C:\\a\\foobar.gif"});
}

std::vector<Finding> artifact_env_parallels_parallels_driver_files(Context &) {
    return files_probe("env.parallels_parallels_driver_files", "parallels: Parallels Driver Files",
                       {L"%WINDIR%\\system32\\prleth.sys", L"%WINDIR%\\system32\\prlfs.sys",
                        L"%WINDIR%\\system32\\prlmouse.sys", L"%WINDIR%\\system32\\prlvideo.sys",
                        L"%WINDIR%\\system32\\prltime.sys", L"%WINDIR%\\system32\\prl_pv32.sys",
                        L"%WINDIR%\\system32\\prl_paravirt_32.sys"});
}

std::vector<Finding> artifact_env_parallels_enumpci_registry_subkey(Context &) {
    return registry_probe(
        "env.parallels_enumpci_registry_subkey", "parallels: EnumPCI Registry SubKey",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_1AB8"}, false, true}});
}

std::vector<Finding> artifact_env_parallels_parallels_systembiosversion_registry_key(Context &) {
    return registry_probe("env.parallels_parallels_systembiosversion_registry_key",
                          "parallels: Parallels SystemBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"SystemBiosVersion"},
                            {"PARALLELS"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_parallels_parallels_videobiosversion_registry_key(Context &) {
    return registry_probe("env.parallels_parallels_videobiosversion_registry_key",
                          "parallels: Parallels VideoBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"VideoBiosVersion"},
                            {"PARALLELS"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_parallels_parallels_processes(Context &) {
    return names_probe("env.parallels_parallels_processes", "parallels: Parallels Processes", "process",
                       {"prl_cc.exe", "prl_tools.exe"});
}

std::vector<Finding> artifact_env_parallels_directory_device_object(Context &) {
    return object_probe("env.parallels_directory_device_object", "parallels: Directory Device Object",
                        L"\\Device", {"prl_pv", "prl_tg", "prl_time"});
}

std::vector<Finding> artifact_env_qemu_qemu_systembiosversion_registry_key(Context &) {
    return registry_probe("env.qemu_qemu_systembiosversion_registry_key",
                          "qemu: QEMU SystemBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"SystemBiosVersion"},
                            {"QEMU"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_qemu_qemu_videobiosversion_registry_key(Context &) {
    return registry_probe("env.qemu_qemu_videobiosversion_registry_key",
                          "qemu: QEMU VideoBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"VideoBiosVersion"},
                            {"QEMU"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_qemu_qemu_bios_description(Context &) {
    return registry_probe("env.qemu_qemu_bios_description", "qemu: QEMU BIOS Description",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System\\BIOS",
                            {L"SystemManufacturer"},
                            {"QEMU"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_qemu_qemu_scsiport0_registry_key(Context &) {
    return registry_probe(
        "env.qemu_qemu_scsiport0_registry_key", "qemu: QEMU ScsiPort0 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"QEMU"},
          false,
          false}});
}

std::vector<Finding> artifact_env_qemu_qemu_scsiport1_registry_key(Context &) {
    return registry_probe(
        "env.qemu_qemu_scsiport1_registry_key", "qemu: QEMU ScsiPort1 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"QEMU"},
          false,
          false}});
}

std::vector<Finding> artifact_env_qemu_qemu_scsiport2_registry_key(Context &) {
    return registry_probe(
        "env.qemu_qemu_scsiport2_registry_key", "qemu: QEMU ScsiPort2 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"QEMU"},
          false,
          false}});
}

std::vector<Finding> artifact_env_qemu_qemu_diskenum_registry_key(Context &) {
    return registry_probe("env.qemu_qemu_diskenum_registry_key", "qemu: QEMU DiskEnum Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services\\Disk\\Enum",
                            {L"0"},
                            {"qemu"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_sandboxie_sandboxie_services_registry_keys(Context &) {
    return registry_probe(
        "env.sandboxie_sandboxie_services_registry_keys", "sandboxie: Sandboxie Services Registry Keys",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SbieDrv", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_sandboxie_sandboxie_uninstall_registry_keys(Context &) {
    return registry_probe("env.sandboxie_sandboxie_uninstall_registry_keys",
                          "sandboxie: Sandboxie Uninstall Registry Keys",
                          {{HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie",
                            {},
                            {},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_sandboxie_directory_device_object(Context &) {
    return object_probe("env.sandboxie_directory_device_object", "sandboxie: Directory Device Object",
                        L"\\Device", {"SandboxieDriverApi"});
}

std::vector<Finding> artifact_env_sandboxie_directory_driver_object(Context &) {
    return object_probe("env.sandboxie_directory_driver_object", "sandboxie: Directory Driver Object",
                        L"\\Driver", {"SbieDrv"});
}

std::vector<Finding> artifact_env_sandboxie_directory_rpc_control_object(Context &) {
    return object_probe("env.sandboxie_directory_rpc_control_object",
                        "sandboxie: Directory RPC Control Object", L"\\RPC Control", {"SbieSvcPort"});
}

std::vector<Finding> artifact_env_sandboxie_injected_sbiedll_module(Context &) {
    return names_probe("env.sandboxie_injected_sbiedll_module", "sandboxie: Injected sbiedll module",
                       "module", {"sbiedll.dll"});
}

std::vector<Finding> artifact_env_vbox_vbox_guest_additions_registry_key(Context &) {
    return registry_probe(
        "env.vbox_vbox_guest_additions_registry_key", "vbox: VBox Guest Additions Registry Key",
        {{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_vbox_systembiosdate_registry_key(Context &) {
    return registry_probe("env.vbox_systembiosdate_registry_key", "vbox: SystemBiosDate Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\DESCRIPTION\\System",
                            {L"SystemBiosDate"},
                            {"06/23/99"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_vbox_hardware_device_registry_keys(Context &) {
    return registry_probe("env.vbox_hardware_device_registry_keys", "vbox: Hardware Device Registry Keys",
                          {{HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", {}, {}, false, false},
                           {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\VBOX__", {}, {}, false, false},
                           {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\RSDT\\VBOX__", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_vbox_vbox_services_registry_keys(Context &) {
    return registry_probe(
        "env.vbox_vbox_services_registry_keys", "vbox: VBox Services Registry Keys",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxMouse", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxService", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxVideo", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxGuest", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_vbox_scsiport0_registry_key(Context &) {
    return registry_probe(
        "env.vbox_scsiport0_registry_key", "vbox: ScsiPort0 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"VBOX"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vbox_scsiport1_registry_key(Context &) {
    return registry_probe(
        "env.vbox_scsiport1_registry_key", "vbox: ScsiPort1 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"VBOX"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vbox_scsiport2_registry_key(Context &) {
    return registry_probe(
        "env.vbox_scsiport2_registry_key", "vbox: ScsiPort2 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"VBOX"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vbox_systembiosversion_registry_key(Context &) {
    return registry_probe("env.vbox_systembiosversion_registry_key", "vbox: SystemBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"SystemBiosVersion"},
                            {"VBOX"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_vbox_videobiosversion_registry_key(Context &) {
    return registry_probe("env.vbox_videobiosversion_registry_key", "vbox: VideoBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"VideoBiosVersion"},
                            {"VIRTUALBOX"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_vbox_vbox_enumpci_registry_subkey(Context &) {
    return registry_probe(
        "env.vbox_vbox_enumpci_registry_subkey", "vbox: VBox EnumPCI Registry SubKey",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_80EE"}, false, true}});
}

std::vector<Finding> artifact_env_vbox_controlset001_registry_key(Context &) {
    return registry_probe("env.vbox_controlset001_registry_key", "vbox: ControlSet001 Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet001\\Enum",
                            {L"DeviceDesc", L"FriendlyName"},
                            {"VBOX"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vbox_controlset002_registry_key(Context &) {
    return registry_probe("env.vbox_controlset002_registry_key", "vbox: ControlSet002 Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet002\\Enum",
                            {L"DeviceDesc", L"FriendlyName"},
                            {"VBOX"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vbox_controlset003_registry_key(Context &) {
    return registry_probe("env.vbox_controlset003_registry_key", "vbox: ControlSet003 Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet003\\Enum",
                            {L"DeviceDesc", L"FriendlyName"},
                            {"VBOX"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vbox_vbox_processes(Context &) {
    return names_probe("env.vbox_vbox_processes", "vbox: VBox Processes", "process",
                       {"vboxservice.exe", "vboxtray.exe"});
}

std::vector<Finding> artifact_env_vbox_vbox_devices(Context &) {
    return named_probe("env.vbox_vbox_devices", "vbox: VBox Devices", "device",
                       {L"\\\\.\\VBoxMiniRdr", L"\\\\.\\VBoxMiniRdDN", L"\\\\.\\VBoxMiniRdrDN",
                        L"\\\\.\\VBoxGuest", L"\\\\.\\VBoxTrayIPC", L"\\\\.\\VBoxMouse", L"\\\\.\\VBoxVideo",
                        L"\\\\.\\pipe\\VBoxMiniRdDN", L"\\\\.\\pipe\\VBoxTrayIPC"});
}

std::vector<Finding> artifact_env_vbox_vbox_driver_files(Context &) {
    return files_probe(
        "env.vbox_vbox_driver_files", "vbox: VBox Driver Files",
        {L"%WINDIR%\\system32\\drivers\\VBoxMouse.sys", L"%WINDIR%\\system32\\drivers\\VBoxGuest.sys",
         L"%WINDIR%\\system32\\drivers\\VBoxSF.sys", L"%WINDIR%\\system32\\drivers\\VBoxVideo.sys",
         L"%WINDIR%\\system32\\vboxdisp.dll", L"%WINDIR%\\system32\\vboxhook.dll",
         L"%WINDIR%\\system32\\vboxmrxnp.dll", L"%WINDIR%\\system32\\vboxogl.dll",
         L"%WINDIR%\\system32\\vboxoglarrayspu.dll", L"%WINDIR%\\system32\\vboxoglcrutil.dll",
         L"%WINDIR%\\system32\\vboxoglerrorspu.dll", L"%WINDIR%\\system32\\vboxoglfeedbackspu.dll",
         L"%WINDIR%\\system32\\vboxoglpackspu.dll", L"%WINDIR%\\system32\\vboxoglpassthroughspu.dll",
         L"%WINDIR%\\system32\\vboxservice.exe", L"%WINDIR%\\system32\\vboxtray.exe",
         L"%WINDIR%\\system32\\VBoxControl.exe", L"%ProgramFiles%\\oracle\\virtualbox guest additions\\"});
}

std::vector<Finding> artifact_env_vbox_directory_device_object(Context &) {
    return object_probe("env.vbox_directory_device_object", "vbox: Directory Device Object", L"\\Device",
                        {"VBoxGuest", "VBoxMiniRdr"});
}

std::vector<Finding> artifact_env_vbox_directory_driver_object(Context &) {
    return object_probe("env.vbox_directory_driver_object", "vbox: Directory Driver Object", L"\\Driver",
                        {"VBoxVideo", "VBoxMouse"});
}

std::vector<Finding> artifact_env_vbox_window_class_name(Context &) {
    return names_probe("env.vbox_window_class_name", "vbox: Window Class Name", "class",
                       {"VBoxTrayToolWndClass"});
}

std::vector<Finding> artifact_env_vbox_window_name(Context &) {
    return names_probe("env.vbox_window_name", "vbox: Window Name", "title", {"VBoxTrayToolWnd"});
}

std::vector<Finding> artifact_env_virtualpc_virtualpc_driver_files(Context &) {
    return files_probe(
        "env.virtualpc_virtualpc_driver_files", "virtualpc: VirtualPC Driver Files",
        {L"%WINDIR%\\system32\\drivers\\vmsrvc.sys", L"%WINDIR%\\system32\\drivers\\vpc-s3.sys"});
}

std::vector<Finding> artifact_env_virtualpc_virtualpc_services_registry_keys(Context &) {
    return registry_probe(
        "env.virtualpc_virtualpc_services_registry_keys", "virtualpc: VirtualPC Services Registry Keys",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vpcbus", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vpc-s3", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vpcuhub", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\msvmmouf", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_virtualpc_virtualpc_enumpci_registry_subkey(Context &) {
    return registry_probe(
        "env.virtualpc_virtualpc_enumpci_registry_subkey", "virtualpc: VirtualPC EnumPCI Registry SubKey",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_5333"}, false, true}});
}

std::vector<Finding> artifact_env_virtualpc_virtualpc_processes(Context &) {
    return names_probe("env.virtualpc_virtualpc_processes", "virtualpc: VirtualPC Processes", "process",
                       {"vmsrvc.exe", "vmusrvc.exe"});
}

std::vector<Finding> artifact_env_virtualpc_directory_device_object(Context &) {
    return object_probe("env.virtualpc_directory_device_object", "virtualpc: Directory Device Object",
                        L"\\Device", {"VirtualMachineServices"});
}

std::vector<Finding> artifact_env_virtualpc_directory_driver_object(Context &) {
    return object_probe("env.virtualpc_directory_driver_object", "virtualpc: Directory Driver Object",
                        L"\\Driver", {"1-driver-vmsrvc"});
}

std::vector<Finding> artifact_env_vmware_vmware_tools_registry_machine_key(Context &) {
    return registry_probe(
        "env.vmware_vmware_tools_registry_machine_key", "vmware: VMWare Tools Registry Machine Key",
        {{HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_vmware_vmware_tools_registry_user_key(Context &) {
    return registry_probe(
        "env.vmware_vmware_tools_registry_user_key", "vmware: VMWare Tools Registry User Key",
        {{HKEY_CURRENT_USER, L"SOFTWARE\\VMware, Inc.\\VMware Tools", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_vmware_vmware_service_registry_key(Context &) {
    return registry_probe(
        "env.vmware_vmware_service_registry_key", "vmware: VMWare Service Registry Key",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmdebug", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmmouse", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VMTools", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VMMEMCTL", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmware", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmci", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmx86", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmxnet", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmx_svga", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_vmware_scsiport0_registry_key(Context &) {
    return registry_probe(
        "env.vmware_scsiport0_registry_key", "vmware: ScsiPort0 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"VMWARE"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vmware_scsiport1_registry_key(Context &) {
    return registry_probe(
        "env.vmware_scsiport1_registry_key", "vmware: ScsiPort1 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"VMWARE"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vmware_scsiport2_registry_key(Context &) {
    return registry_probe(
        "env.vmware_scsiport2_registry_key", "vmware: ScsiPort2 Registry Key",
        {{HKEY_LOCAL_MACHINE,
          L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
          {L"Identifier"},
          {"VMWARE"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vmware_diskidentifier_registry_key(Context &) {
    return registry_probe("env.vmware_diskidentifier_registry_key", "vmware: DiskIdentifier Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
                            {L"0", L"1"},
                            {"VMware"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_vmware_driver_description_registry_keys(Context &) {
    return registry_probe(
        "env.vmware_driver_description_registry_keys", "vmware: Driver Description Registry Keys",
        {{HKEY_LOCAL_MACHINE,
          L"SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000",
          {L"CoInstallers32", L"DriverDesc", L"InfSection", L"ProviderName"},
          {"VMware", "vmx"},
          false,
          false}});
}

std::vector<Finding> artifact_env_vmware_controlset001_registry_key(Context &) {
    return registry_probe("env.vmware_controlset001_registry_key", "vmware: ControlSet001 Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet001\\Enum",
                            {L"DeviceDesc", L"FriendlyName"},
                            {"VMware"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vmware_controlset002_registry_key(Context &) {
    return registry_probe("env.vmware_controlset002_registry_key", "vmware: ControlSet002 Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet002\\Enum",
                            {L"DeviceDesc", L"FriendlyName"},
                            {"VMware"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vmware_controlset003_registry_key(Context &) {
    return registry_probe("env.vmware_controlset003_registry_key", "vmware: ControlSet003 Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\ControlSet003\\Enum",
                            {L"DeviceDesc", L"FriendlyName"},
                            {"VMware"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vmware_productsinstaller_registry_key(Context &) {
    return registry_probe(
        "env.vmware_productsinstaller_registry_key", "vmware: ProductsInstaller Registry Key",
        {{HKEY_CLASSES_ROOT, L"Installer\\Products", {L"ProductName"}, {"vmware tools"}, true, false}});
}

std::vector<Finding> artifact_env_vmware_productsuninstaller_registry_key_currentuser(Context &) {
    return registry_probe("env.vmware_productsuninstaller_registry_key_currentuser",
                          "vmware: ProductsUninstaller Registry Key (CurrentUser)",
                          {{HKEY_CURRENT_USER,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                            {L"DisplayName"},
                            {"vmware tools"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vmware_productsuninstaller_registry_key_localmachine(Context &) {
    return registry_probe("env.vmware_productsuninstaller_registry_key_localmachine",
                          "vmware: ProductsUninstaller Registry Key (LocalMachine)",
                          {{HKEY_LOCAL_MACHINE,
                            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                            {L"DisplayName"},
                            {"vmware tools"},
                            true,
                            false}});
}

std::vector<Finding> artifact_env_vmware_systembiosversion_registry_key(Context &) {
    return registry_probe("env.vmware_systembiosversion_registry_key",
                          "vmware: SystemBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"SystemBiosVersion"},
                            {"INTEL  - 6040000", "VMWARE"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_vmware_videobiosversion_registry_key(Context &) {
    return registry_probe("env.vmware_videobiosversion_registry_key", "vmware: VideoBiosVersion Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"HARDWARE\\Description\\System",
                            {L"VideoBiosVersion"},
                            {"VMWARE"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_vmware_enumpci_registry_subkey(Context &) {
    return registry_probe(
        "env.vmware_enumpci_registry_subkey", "vmware: EnumPCI Registry SubKey",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_15AD"}, false, true}});
}

std::vector<Finding> artifact_env_vmware_enumide_registry_subkey(Context &) {
    return registry_probe("env.vmware_enumide_registry_subkey", "vmware: EnumIDE Registry SubKey",
                          {{HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\CurrentControlSet\\Enum\\IDE",
                            {},
                            {"CdRomNECVMWar", "DiskVMware"},
                            false,
                            true}});
}

std::vector<Finding> artifact_env_vmware_vmware_device_hgfs(Context &) {
    return named_probe("env.vmware_vmware_device_hgfs", "vmware: VMWare Device HGFS", "device",
                       {L"\\\\.\\HGFS"});
}

std::vector<Finding> artifact_env_vmware_vmware_device_vmci(Context &) {
    return named_probe("env.vmware_vmware_device_vmci", "vmware: VMWare Device vmci", "device",
                       {L"\\\\.\\vmci"});
}

std::vector<Finding> artifact_env_vmware_vmware_files(Context &) {
    return files_probe("env.vmware_vmware_files", "vmware: VMWare Files",
                       {L"%WINDIR%\\system32\\drivers\\vmmouse.sys",
                        L"%WINDIR%\\system32\\drivers\\vmnet.sys", L"%WINDIR%\\system32\\drivers\\vmxnet.sys",
                        L"%WINDIR%\\system32\\drivers\\vmhgfs.sys", L"%WINDIR%\\system32\\drivers\\vmx86.sys",
                        L"%WINDIR%\\system32\\hgfs.sys", L"%WINDIR%\\system32\\vmhgfs.sys",
                        L"%ProgramFiles%\\VMware\\"});
}

std::vector<Finding> artifact_env_vmware_vmware_processes(Context &) {
    return names_probe(
        "env.vmware_vmware_processes", "vmware: VMWare Processes", "process",
        {"vmtoolsd.exe", "vmacthlp.exe", "vmwaretray.exe", "vmwareuser.exe", "vmware.exe", "vmount2.exe"});
}

std::vector<Finding> artifact_env_vmware_directory_device_object(Context &) {
    return object_probe("env.vmware_directory_device_object", "vmware: Directory Device Object", L"\\Device",
                        {"vmmemctl"});
}

std::vector<Finding> artifact_env_vmware_vmware_diskenum_registry_key(Context &) {
    return registry_probe("env.vmware_vmware_diskenum_registry_key", "vmware: VMWare DiskEnum Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services\\Disk\\Enum",
                            {L"0"},
                            {"vmware"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_wine_wine_hklm_registry_keys(Context &) {
    return registry_probe("env.wine_wine_hklm_registry_keys", "wine: Wine HKLM Registry Keys",
                          {{HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wine", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_wine_wine_hkcu_registry_keys(Context &) {
    return registry_probe("env.wine_wine_hkcu_registry_keys", "wine: Wine HKCU Registry Keys",
                          {{HKEY_CURRENT_USER, L"SOFTWARE\\Wine", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_xen_xen_hardware_device_registry_keys(Context &) {
    return registry_probe("env.xen_xen_hardware_device_registry_keys",
                          "xen: Xen Hardware Device Registry Keys",
                          {{HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\xen", {}, {}, false, false},
                           {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\xen", {}, {}, false, false},
                           {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\RSDT\\xen", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_xen_xen_services_registry_keys(Context &) {
    return registry_probe(
        "env.xen_xen_services_registry_keys", "xen: Xen Services Registry Keys",
        {{HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xenevtchn", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xennet", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xennet6", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xensvc", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xenvdb", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_xen_xen_processes(Context &) {
    return names_probe("env.xen_xen_processes", "xen: Xen Processes", "process",
                       {"xenservice.exe", "xsvc_depriv.exe"});
}

std::vector<Finding> artifact_env_xen_xen_diskenum_registry_key(Context &) {
    return registry_probe("env.xen_xen_diskenum_registry_key", "xen: Xen DiskEnum Registry Key",
                          {{HKEY_LOCAL_MACHINE,
                            L"System\\CurrentControlSet\\Services\\Disk\\Enum",
                            {L"0"},
                            {"xen"},
                            false,
                            false}});
}

std::vector<Finding> artifact_env_registry_artifacts(Context &) {
    return registry_probe(
        "env.registry_artifacts", "Hypervisor and sandbox registry artifacts",
        {{HKEY_CURRENT_USER, L"SOFTWARE\\Wine", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VMWARE__", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\Xen", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\VBOX__", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\VMWARE__", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\RSDT\\VBOX__", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE,
          L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
          {},
          {},
          false,
          false},
         {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wine", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE,
          L"SYSTEM\\ControlSet001\\Control\\Class\\{4D36E96D-E325-11CE-BFC1-08002BE10318}"
          L"\\0000\\CoInstallers32",
          {},
          {},
          false,
          false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\BALLOON", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\BalloonService", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\SbieDrv", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxGuest", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxMouse", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxService", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxVideo", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VMMEMCTL", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VMTools", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VirtioSerial", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\netkvm", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vioscsi", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\viostor", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmci", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmdebug", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmmouse", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\vmx86", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xenevtchn", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xennet", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\xensvc", {}, {}, false, false},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_15AD"}, false, true},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_1AB8"}, false, true},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_1AF4"}, false, true},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_1B36"}, false, true},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_5333"}, false, true},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\PCI", {}, {"VEN_5853"}, false, true},
         {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SbieDrv", {}, {}, false, false}});
}

std::vector<Finding> artifact_env_artifact_files(Context &) {
    return files_probe("env.artifact_files", "Guest driver and integration files",
                       {L"%ProgramFiles%\\Oracle\\VirtualBox Guest Additions",
                        L"%ProgramFiles%\\SPICE Guest Tools",
                        L"%ProgramFiles%\\VMware\\VMware Tools",
                        L"%ProgramFiles%\\Virtio-Win",
                        L"%ProgramFiles%\\XenTools",
                        L"%ProgramFiles%\\qemu-ga",
                        L"%WINDIR%\\System32\\VBoxControl.exe",
                        L"%WINDIR%\\System32\\drivers\\VBoxGuest.sys",
                        L"%WINDIR%\\System32\\drivers\\VBoxMouse.sys",
                        L"%WINDIR%\\System32\\drivers\\VBoxSF.sys",
                        L"%WINDIR%\\System32\\drivers\\VBoxVideo.sys",
                        L"%WINDIR%\\System32\\drivers\\balloon.sys",
                        L"%WINDIR%\\System32\\drivers\\netkvm.sys",
                        L"%WINDIR%\\System32\\drivers\\pvpanic.sys",
                        L"%WINDIR%\\System32\\drivers\\viofs.sys",
                        L"%WINDIR%\\System32\\drivers\\viogpudo.sys",
                        L"%WINDIR%\\System32\\drivers\\vioinput.sys",
                        L"%WINDIR%\\System32\\drivers\\viorng.sys",
                        L"%WINDIR%\\System32\\drivers\\vioscsi.sys",
                        L"%WINDIR%\\System32\\drivers\\vioser.sys",
                        L"%WINDIR%\\System32\\drivers\\viostor.sys",
                        L"%WINDIR%\\System32\\drivers\\vm3dmp.sys",
                        L"%WINDIR%\\System32\\drivers\\vmci.sys",
                        L"%WINDIR%\\System32\\drivers\\vmhgfs.sys",
                        L"%WINDIR%\\System32\\drivers\\vmkdb.sys",
                        L"%WINDIR%\\System32\\drivers\\vmmemctl.sys",
                        L"%WINDIR%\\System32\\drivers\\vmmouse.sys",
                        L"%WINDIR%\\System32\\drivers\\vmnet.sys",
                        L"%WINDIR%\\System32\\drivers\\vmnetadapter.sys",
                        L"%WINDIR%\\System32\\drivers\\vmnetuserif.sys",
                        L"%WINDIR%\\System32\\drivers\\vmrawdsk.sys",
                        L"%WINDIR%\\System32\\drivers\\vmusb.sys",
                        L"%WINDIR%\\System32\\drivers\\vmusbmouse.sys",
                        L"%WINDIR%\\System32\\drivers\\vmx86.sys",
                        L"%WINDIR%\\System32\\drivers\\xenevtchn.sys",
                        L"%WINDIR%\\System32\\drivers\\xennet.sys",
                        L"%WINDIR%\\System32\\vboxdisp.dll",
                        L"%WINDIR%\\System32\\vboxhook.dll",
                        L"%WINDIR%\\System32\\vboxmrxnp.dll",
                        L"%WINDIR%\\System32\\vboxogl.dll",
                        L"%WINDIR%\\System32\\vboxoglarrayspu.dll",
                        L"%WINDIR%\\System32\\vboxoglcrutil.dll",
                        L"%WINDIR%\\System32\\vboxoglerrorspu.dll",
                        L"%WINDIR%\\System32\\vboxoglfeedbackspu.dll",
                        L"%WINDIR%\\System32\\vboxoglpackspu.dll",
                        L"%WINDIR%\\System32\\vboxoglpassthroughspu.dll",
                        L"%WINDIR%\\System32\\vboxservice.exe",
                        L"%WINDIR%\\System32\\vboxtray.exe",
                        L"%WINDIR%\\System32\\vm3dgl.dll"});
}

std::vector<Finding> artifact_env_guest_services(Context &) {
    return names_probe("env.guest_services", "Guest integration services", "service",
                       winlogic::guest_services());
}

std::vector<Finding> artifact_env_guest_processes(Context &) {
    return names_probe("env.guest_processes", "Guest integration processes", "process",
                       winlogic::guest_processes());
}

std::vector<Finding> artifact_env_guest_loaded_drivers(Context &) {
    return names_probe("env.guest_loaded_drivers", "Loaded guest drivers", "driver",
                       winlogic::guest_services());
}

std::vector<Finding> artifact_design_analysis_tools_running(Context &) {
    return names_probe("design.analysis_tools_running", "Analysis tool processes", "process",
                       winlogic::analysis_processes());
}

std::vector<Finding> artifact_design_blacklisted_dlls(Context &) {
    return names_probe("design.blacklisted_dlls", "Known monitoring modules loaded in this process", "module",
                       winlogic::modules());
}

std::vector<Finding> artifact_design_window_class_artifacts(Context &) {
    return names_probe("design.window_class_artifacts", "Guest tool window classes", "class",
                       {"VBoxTrayToolWndClass", "VBoxTrayToolWnd", "VMwareTrayIcon", "vm3dversion_wc"});
}

std::vector<Finding> artifact_env_sandboxie_mutex(Context &) {
    return named_probe("env.sandboxie_mutex", "Sandboxie mutex", "mutex",
                       {L"Sandboxie_SingleInstanceMutex_Control",
                        L"Global\\Sandboxie_SingleInstanceMutex_Control",
                        L"SBIE_BOXED_ServiceInitComplete_Mutex1"});
}

std::vector<Finding> artifact_env_virtualpc_mutex(Context &) {
    return named_probe("env.virtualpc_mutex", "Virtualpc mutex", "mutex",
                       {L"MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex"});
}

std::vector<Finding> artifact_env_cuckoo_pipe(Context &) {
    return named_probe("env.cuckoo_pipe", "Cuckoo pipe", "device", {L"\\\\.\\pipe\\cuckoo"});
}

std::vector<Finding> artifact_env_hyperv_driver_objects(Context &) {
    return object_probe("env.hyperv_driver_objects", "Hyperv driver objects", L"\\Driver",
                        {"VMBusHID", "vmbus", "HyperVideo", "hyperkbd"});
}

std::vector<Finding> artifact_env_hyperv_global_objects(Context &) {
    return object_probe("env.hyperv_global_objects", "Hyperv global objects", L"\\GLOBAL??",
                        {"VMBUS#", "VmGenerationCounter"});
}

std::vector<Finding> artifact_env_sandboxie_service(Context &) {
    return names_probe("env.sandboxie_service", "Sandboxie service", "service", {"SbieSvc", "SbieDrv"});
}

std::vector<Finding> artifact_env_comodo_modules(Context &) {
    return names_probe("env.comodo_modules", "Comodo modules", "module", {"cmdvrt32.dll", "cmdvrt64.dll"});
}

std::vector<Finding> artifact_env_qihoo_modules(Context &) {
    return names_probe("env.qihoo_modules", "Qihoo modules", "module", {"SxIn.dll"});
}

std::vector<Finding> artifact_env_deepfreeze_services(Context &) {
    return names_probe("env.deepfreeze_services", "Deepfreeze services", "service", {"DFServ", "DeepFrz"});
}

std::vector<Finding> artifact_env_shadowdefender_services(Context &) {
    return names_probe("env.shadowdefender_services", "Shadowdefender services", "service",
                       {"diskpt", "DefenderDaemon"});
}

std::vector<Finding> artifact_env_returnil_services(Context &) {
    return names_probe("env.returnil_services", "Returnil services", "service",
                       {"rvsmon", "rvh", "rvsystem"});
}

std::vector<Finding> artifact_env_windows_sandbox_services(Context &) {
    return names_probe("env.windows_sandbox_services", "Windows sandbox services", "service",
                       {"CmService", "ContainerService"});
}

std::vector<Finding> artifact_design_analysis_windows(Context &) {
    return names_probe("design.analysis_windows", "Analysis windows", "title",
                       {"x64dbg", "x32dbg", "OllyDbg", "WinDbg", "Wireshark", "Process Monitor -",
                        "Process Explorer -", "IDA Pro", "IDA Freeware", "IDA -", "API Monitor", "Fiddler",
                        "Immunity Debugger", "Process Hacker", "System Informer", "PE-bear", "dnSpy",
                        "Ghidra", "HTTP Debugger", "Cheat Engine"});
}

std::vector<Finding> artifact_design_analysis_window_classes(Context &) {
    return names_probe("design.analysis_window_classes", "Analysis window classes", "class",
                       // Window classes registered by common debuggers and monitors (FindWindow targets).
                       {"OLLYDBG", "WinDbgFrameClass", "ID", "Zeta Debugger", "Rock Debugger",
                        "ObsidianGUI", "PROCMON_WINDOW_CLASS", "ProcessHacker", "PROCEXPL"});
}

std::vector<Finding> artifact_design_monitoring_services(Context &) {
    return names_probe("design.monitoring_services", "Monitoring services", "service",
                       {"Sysmon", "Sysmon64", "SysmonDrv", "PROCMON24", "PROCMON23", "PROCMON22", "NPF",
                        "npcap", "npf_wifi", "kprocesshacker2", "kprocesshacker3", "KSystemInformer"});
}

std::vector<Finding> artifact_design_monitoring_drivers(Context &) {
    return names_probe(
        "design.monitoring_drivers", "Monitoring drivers", "driver",
        {"sysmon", "procmon", "npcap", "npf.sys", "kprocesshacker", "ksysteminformer", "apimonitor"});
}

std::vector<Finding> artifact_design_analysis_tool_files(Context &) {
    return files_probe("design.analysis_tool_files", "Installed analysis tool folders",
                       {L"%ProgramFiles%\\Wireshark", L"%ProgramFiles%\\Process Hacker 2",
                        L"%ProgramFiles%\\IDA Pro", L"%ProgramFiles%\\Npcap", L"%ProgramFiles%\\WinPcap",
                        L"%ProgramFiles%\\API Monitor", L"%LOCALAPPDATA%\\Programs\\Fiddler", L"C:\\analysis",
                        L"C:\\cuckoo", L"C:\\cape", L"C:\\agent.py"});
}

std::vector<Finding> artifact_env_windows_sandbox_paths(Context &) {
    return files_probe("env.windows_sandbox_paths", "Windows Sandbox image paths",
                       {L"%ProgramData%\\Microsoft\\Windows\\Containers\\BaseImages",
                        L"C:\\Users\\WDAGUtilityAccount", L"C:\\Users\\WDAGUtilityAccount\\Desktop"});
}

std::vector<Finding> artifact_env_deepfreeze_files(Context &) {
    return files_probe(
        "env.deepfreeze_files", "Deep Freeze files",
        {L"%WINDIR%\\System32\\drivers\\DeepFrz.sys", L"%ProgramFiles%\\Faronics\\Deep Freeze"});
}

std::vector<Finding> artifact_env_shadowdefender_files(Context &) {
    return files_probe("env.shadowdefender_files", "Shadow Defender files",
                       {L"%ProgramFiles%\\Shadow Defender", L"%WINDIR%\\System32\\drivers\\diskpt.sys"});
}

std::vector<Finding> artifact_env_returnil_files(Context &) {
    return files_probe("env.returnil_files", "Returnil files",
                       {L"%ProgramFiles%\\Returnil", L"%WINDIR%\\System32\\drivers\\rvsystem.sys"});
}

std::vector<Finding> acpi_registry(Context&) {
    return registry_probe("env.acpi_registry_oems","ACPI registry OEM hierarchy",{
        {HKEY_LOCAL_MACHINE,L"HARDWARE\\ACPI\\DSDT",{},winlogic::vendors(),true,true},
        {HKEY_LOCAL_MACHINE,L"HARDWARE\\ACPI\\FADT",{},winlogic::vendors(),true,true},
        {HKEY_LOCAL_MACHINE,L"HARDWARE\\ACPI\\RSDT",{},winlogic::vendors(),true,true}});
}
std::vector<Finding> scsi_registry(Context&) {
    return registry_probe("env.scsi_registry_identifiers","SCSI registry identities",{
        {HKEY_LOCAL_MACHINE,L"HARDWARE\\DEVICEMAP\\Scsi",{L"Identifier"},winlogic::vendors(),true,false}});
}
std::vector<Finding> device_class_registry(Context&) {
    return registry_probe("env.device_class_registry","Virtual device class driver identities",{
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Class",{L"DriverDesc",L"ProviderName",L"MatchingDeviceId",L"CoInstallers32"},winlogic::vendors(),true,false}});
}
std::vector<Finding> bios_registry(Context&) {
    return registry_probe("env.bios_registry_strings","BIOS registry versions and vendor strings",{
        {HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System",{L"SystemBiosVersion",L"VideoBiosVersion"},winlogic::vendors()},
        {HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System\\BIOS",{L"BIOSVendor",L"BIOSVersion",L"SystemManufacturer",L"SystemProductName"},winlogic::vendors()}});
}
std::vector<Finding> cuckoo_event(Context&) {
    auto event=L"CuckooEvent"+std::to_wstring(GetCurrentProcessId());
    return named_probe("env.cuckoo_process_event","Cuckoo current-process event","event",{event});
}
std::vector<Finding> guest_driver_files(Context&) {
    std::vector<std::wstring> paths;
    for(const auto& s:winlogic::guest_services())paths.push_back(L"%WINDIR%\\System32\\drivers\\"+win::widen(s)+L".sys");
    return files_probe("env.guest_driver_files","Guest driver file inventory",paths);
}
std::vector<Finding> virtualpc_provider(Context&) {
    return registry_probe("env.virtualbox_network_provider","VirtualBox shared-folder network provider",{
        {HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Services\\VBoxSF\\NetworkProvider",{L"Name"},{"VirtualBox Shared Folders"}}});
}
} // namespace
PERDEDOR_REGISTER(artifact_env_bochs_bochs_systembiosversion_registry_key, "artifacts.registry", "fast",
                  false, "env.bochs_bochs_systembiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_bochs_bochs_videobiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.bochs_bochs_videobiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_generic_diskenum_registry_key, "artifacts.registry", "fast", false,
                  "env.generic_diskenum_registry_key");
PERDEDOR_REGISTER(artifact_env_hyperv_hyper_v_hklm_registry_keys, "artifacts.registry", "fast", false,
                  "env.hyperv_hyper_v_hklm_registry_keys");
PERDEDOR_REGISTER(artifact_env_hyperv_hyper_v_services_registry_keys, "artifacts.registry", "fast", false,
                  "env.hyperv_hyper_v_services_registry_keys");
PERDEDOR_REGISTER(artifact_env_hyperv_hyper_v_directory_device_object, "artifacts.named_objects", "fast",
                  false, "env.hyperv_hyper_v_directory_device_object");
PERDEDOR_REGISTER(artifact_env_joebox_joebox_windows_product_id_registry_key, "artifacts.registry", "fast",
                  false, "env.joebox_joebox_windows_product_id_registry_key");
PERDEDOR_REGISTER(artifact_env_joebox_joebox_windows_nt_product_id_registry_key, "artifacts.registry", "fast",
                  false, "env.joebox_joebox_windows_nt_product_id_registry_key");
PERDEDOR_REGISTER(artifact_env_joebox_joebox_processes, "analysis_tools.processes", "fast", false,
                  "env.joebox_joebox_processes");
PERDEDOR_REGISTER(artifact_env_misc_side_processes, "analysis_tools.processes", "fast", false,
                  "env.misc_side_processes");
PERDEDOR_REGISTER(artifact_env_misc_sandbox_registry_keys, "artifacts.registry", "fast", false,
                  "env.misc_sandbox_registry_keys");
PERDEDOR_REGISTER(artifact_env_misc_sandbox_specific_files, "artifacts.files", "fast", false,
                  "env.misc_sandbox_specific_files");
PERDEDOR_REGISTER(artifact_env_parallels_parallels_driver_files, "artifacts.files", "fast", false,
                  "env.parallels_parallels_driver_files");
PERDEDOR_REGISTER(artifact_env_parallels_enumpci_registry_subkey, "artifacts.registry", "fast", false,
                  "env.parallels_enumpci_registry_subkey");
PERDEDOR_REGISTER(artifact_env_parallels_parallels_systembiosversion_registry_key, "artifacts.registry",
                  "fast", false, "env.parallels_parallels_systembiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_parallels_parallels_videobiosversion_registry_key, "artifacts.registry",
                  "fast", false, "env.parallels_parallels_videobiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_parallels_parallels_processes, "guest_tools.processes", "fast", false,
                  "env.parallels_parallels_processes");
PERDEDOR_REGISTER(artifact_env_parallels_directory_device_object, "artifacts.named_objects", "fast", false,
                  "env.parallels_directory_device_object");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_systembiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_systembiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_videobiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_videobiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_bios_description, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_bios_description");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_scsiport0_registry_key, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_scsiport0_registry_key");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_scsiport1_registry_key, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_scsiport1_registry_key");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_scsiport2_registry_key, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_scsiport2_registry_key");
PERDEDOR_REGISTER(artifact_env_qemu_qemu_diskenum_registry_key, "artifacts.registry", "fast", false,
                  "env.qemu_qemu_diskenum_registry_key");
PERDEDOR_REGISTER(artifact_env_sandboxie_sandboxie_services_registry_keys, "artifacts.registry", "fast",
                  false, "env.sandboxie_sandboxie_services_registry_keys");
PERDEDOR_REGISTER(artifact_env_sandboxie_sandboxie_uninstall_registry_keys, "artifacts.registry", "fast",
                  false, "env.sandboxie_sandboxie_uninstall_registry_keys");
PERDEDOR_REGISTER(artifact_env_sandboxie_directory_device_object, "artifacts.named_objects", "fast", false,
                  "env.sandboxie_directory_device_object");
PERDEDOR_REGISTER(artifact_env_sandboxie_directory_driver_object, "artifacts.named_objects", "fast", false,
                  "env.sandboxie_directory_driver_object");
PERDEDOR_REGISTER(artifact_env_sandboxie_directory_rpc_control_object, "artifacts.named_objects", "fast",
                  false, "env.sandboxie_directory_rpc_control_object");
PERDEDOR_REGISTER(artifact_env_sandboxie_injected_sbiedll_module, "container.app_sandbox", "fast", false,
                  "env.sandboxie_injected_sbiedll_module");
PERDEDOR_REGISTER(artifact_env_vbox_vbox_guest_additions_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_vbox_guest_additions_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_systembiosdate_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_systembiosdate_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_hardware_device_registry_keys, "artifacts.registry", "fast", false,
                  "env.vbox_hardware_device_registry_keys");
PERDEDOR_REGISTER(artifact_env_vbox_vbox_services_registry_keys, "artifacts.registry", "fast", false,
                  "env.vbox_vbox_services_registry_keys");
PERDEDOR_REGISTER(artifact_env_vbox_scsiport0_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_scsiport0_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_scsiport1_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_scsiport1_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_scsiport2_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_scsiport2_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_systembiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_systembiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_videobiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.vbox_videobiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_vbox_enumpci_registry_subkey, "artifacts.registry", "fast", false,
                  "env.vbox_vbox_enumpci_registry_subkey");
PERDEDOR_REGISTER(artifact_env_vbox_controlset001_registry_key, "artifacts.registry", "medium", false,
                  "env.vbox_controlset001_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_controlset002_registry_key, "artifacts.registry", "medium", false,
                  "env.vbox_controlset002_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_controlset003_registry_key, "artifacts.registry", "medium", false,
                  "env.vbox_controlset003_registry_key");
PERDEDOR_REGISTER(artifact_env_vbox_vbox_processes, "guest_tools.processes", "fast", false,
                  "env.vbox_vbox_processes");
PERDEDOR_REGISTER(artifact_env_vbox_vbox_devices, "artifacts.named_objects", "medium", false,
                  "env.vbox_vbox_devices");
PERDEDOR_REGISTER(artifact_env_vbox_vbox_driver_files, "artifacts.files", "fast", false,
                  "env.vbox_vbox_driver_files");
PERDEDOR_REGISTER(artifact_env_vbox_directory_device_object, "artifacts.named_objects", "fast", false,
                  "env.vbox_directory_device_object");
PERDEDOR_REGISTER(artifact_env_vbox_directory_driver_object, "artifacts.named_objects", "fast", false,
                  "env.vbox_directory_driver_object");
PERDEDOR_REGISTER(artifact_env_vbox_window_class_name, "artifacts.window_classes", "fast", false,
                  "env.vbox_window_class_name");
PERDEDOR_REGISTER(artifact_env_vbox_window_name, "artifacts.window_classes", "fast", false,
                  "env.vbox_window_name");
PERDEDOR_REGISTER(artifact_env_virtualpc_virtualpc_driver_files, "artifacts.files", "fast", false,
                  "env.virtualpc_virtualpc_driver_files");
PERDEDOR_REGISTER(artifact_env_virtualpc_virtualpc_services_registry_keys, "artifacts.registry", "fast",
                  false, "env.virtualpc_virtualpc_services_registry_keys");
PERDEDOR_REGISTER(artifact_env_virtualpc_virtualpc_enumpci_registry_subkey, "artifacts.registry", "fast",
                  false, "env.virtualpc_virtualpc_enumpci_registry_subkey");
PERDEDOR_REGISTER(artifact_env_virtualpc_virtualpc_processes, "guest_tools.processes", "fast", false,
                  "env.virtualpc_virtualpc_processes");
PERDEDOR_REGISTER(artifact_env_virtualpc_directory_device_object, "artifacts.named_objects", "fast", false,
                  "env.virtualpc_directory_device_object");
PERDEDOR_REGISTER(artifact_env_virtualpc_directory_driver_object, "artifacts.named_objects", "fast", false,
                  "env.virtualpc_directory_driver_object");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_tools_registry_machine_key, "artifacts.registry", "fast", false,
                  "env.vmware_vmware_tools_registry_machine_key");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_tools_registry_user_key, "artifacts.registry", "fast", false,
                  "env.vmware_vmware_tools_registry_user_key");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_service_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_vmware_service_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_scsiport0_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_scsiport0_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_scsiport1_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_scsiport1_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_scsiport2_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_scsiport2_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_diskidentifier_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_diskidentifier_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_driver_description_registry_keys, "artifacts.registry", "fast", false,
                  "env.vmware_driver_description_registry_keys");
PERDEDOR_REGISTER(artifact_env_vmware_controlset001_registry_key, "artifacts.registry", "medium", false,
                  "env.vmware_controlset001_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_controlset002_registry_key, "artifacts.registry", "medium", false,
                  "env.vmware_controlset002_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_controlset003_registry_key, "artifacts.registry", "medium", false,
                  "env.vmware_controlset003_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_productsinstaller_registry_key, "artifacts.registry", "medium", false,
                  "env.vmware_productsinstaller_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_productsuninstaller_registry_key_currentuser, "artifacts.registry",
                  "medium", false, "env.vmware_productsuninstaller_registry_key_currentuser");
PERDEDOR_REGISTER(artifact_env_vmware_productsuninstaller_registry_key_localmachine, "artifacts.registry",
                  "medium", false, "env.vmware_productsuninstaller_registry_key_localmachine");
PERDEDOR_REGISTER(artifact_env_vmware_systembiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_systembiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_videobiosversion_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_videobiosversion_registry_key");
PERDEDOR_REGISTER(artifact_env_vmware_enumpci_registry_subkey, "artifacts.registry", "fast", false,
                  "env.vmware_enumpci_registry_subkey");
PERDEDOR_REGISTER(artifact_env_vmware_enumide_registry_subkey, "artifacts.registry", "fast", false,
                  "env.vmware_enumide_registry_subkey");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_device_hgfs, "artifacts.named_objects", "medium", false,
                  "env.vmware_vmware_device_hgfs");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_device_vmci, "artifacts.named_objects", "medium", false,
                  "env.vmware_vmware_device_vmci");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_files, "artifacts.files", "fast", false,
                  "env.vmware_vmware_files");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_processes, "guest_tools.processes", "fast", false,
                  "env.vmware_vmware_processes");
PERDEDOR_REGISTER(artifact_env_vmware_directory_device_object, "artifacts.named_objects", "fast", false,
                  "env.vmware_directory_device_object");
PERDEDOR_REGISTER(artifact_env_vmware_vmware_diskenum_registry_key, "artifacts.registry", "fast", false,
                  "env.vmware_vmware_diskenum_registry_key");
PERDEDOR_REGISTER(artifact_env_wine_wine_hklm_registry_keys, "artifacts.registry", "fast", false,
                  "env.wine_wine_hklm_registry_keys");
PERDEDOR_REGISTER(artifact_env_wine_wine_hkcu_registry_keys, "artifacts.registry", "fast", false,
                  "env.wine_wine_hkcu_registry_keys");
PERDEDOR_REGISTER(artifact_env_xen_xen_hardware_device_registry_keys, "artifacts.registry", "fast", false,
                  "env.xen_xen_hardware_device_registry_keys");
PERDEDOR_REGISTER(artifact_env_xen_xen_services_registry_keys, "artifacts.registry", "fast", false,
                  "env.xen_xen_services_registry_keys");
PERDEDOR_REGISTER(artifact_env_xen_xen_processes, "guest_tools.processes", "fast", false,
                  "env.xen_xen_processes");
PERDEDOR_REGISTER(artifact_env_xen_xen_diskenum_registry_key, "artifacts.registry", "fast", false,
                  "env.xen_xen_diskenum_registry_key");
PERDEDOR_REGISTER(artifact_env_registry_artifacts, "artifacts.registry", "fast", false,
                  "env.registry_artifacts");
PERDEDOR_REGISTER(artifact_env_artifact_files, "artifacts.files", "fast", false, "env.artifact_files");
PERDEDOR_REGISTER(artifact_env_guest_services, "guest_tools.services", "fast", false, "env.guest_services");
PERDEDOR_REGISTER(artifact_env_guest_processes, "guest_tools.processes", "fast", false,
                  "env.guest_processes");
PERDEDOR_REGISTER(artifact_env_guest_loaded_drivers, "guest_tools.drivers_modules", "fast", false,
                  "env.guest_loaded_drivers");
PERDEDOR_REGISTER(artifact_design_analysis_tools_running, "analysis_tools.processes", "fast", false,
                  "design.analysis_tools_running");
PERDEDOR_REGISTER(artifact_design_blacklisted_dlls, "analysis_tools.loaded_modules", "fast", false,
                  "design.blacklisted_dlls");
PERDEDOR_REGISTER(artifact_design_window_class_artifacts, "artifacts.window_classes", "fast", false,
                  "design.window_class_artifacts");
PERDEDOR_REGISTER(artifact_env_sandboxie_mutex, "container.app_sandbox", "medium", false,
                  "env.sandboxie_mutex");
PERDEDOR_REGISTER(artifact_env_virtualpc_mutex, "artifacts.named_objects", "medium", false,
                  "env.virtualpc_mutex");
PERDEDOR_REGISTER(artifact_env_cuckoo_pipe, "artifacts.named_objects", "medium", false, "env.cuckoo_pipe");
PERDEDOR_REGISTER(artifact_env_hyperv_driver_objects, "artifacts.hypervisor_interfaces", "fast", false,
                  "env.hyperv_driver_objects");
PERDEDOR_REGISTER(artifact_env_hyperv_global_objects, "artifacts.hypervisor_interfaces", "fast", false,
                  "env.hyperv_global_objects");
PERDEDOR_REGISTER(artifact_env_sandboxie_service, "container.app_sandbox", "fast", false,
                  "env.sandboxie_service");
PERDEDOR_REGISTER(artifact_env_comodo_modules, "container.app_sandbox", "fast", false, "env.comodo_modules");
PERDEDOR_REGISTER(artifact_env_qihoo_modules, "container.app_sandbox", "fast", false, "env.qihoo_modules");
PERDEDOR_REGISTER(artifact_env_deepfreeze_services, "container.app_sandbox", "fast", false,
                  "env.deepfreeze_services");
PERDEDOR_REGISTER(artifact_env_shadowdefender_services, "container.app_sandbox", "fast", false,
                  "env.shadowdefender_services");
PERDEDOR_REGISTER(artifact_env_returnil_services, "container.app_sandbox", "fast", false,
                  "env.returnil_services");
PERDEDOR_REGISTER(artifact_env_windows_sandbox_services, "container.app_sandbox", "fast", false,
                  "env.windows_sandbox_services");
PERDEDOR_REGISTER(artifact_design_analysis_windows, "analysis_tools.windows", "fast", false,
                  "design.analysis_windows");
PERDEDOR_REGISTER(artifact_design_analysis_window_classes, "analysis_tools.windows", "fast", false,
                  "design.analysis_window_classes");
PERDEDOR_REGISTER(artifact_design_monitoring_services, "analysis_tools.drivers_services", "fast", false,
                  "design.monitoring_services");
PERDEDOR_REGISTER(artifact_design_monitoring_drivers, "analysis_tools.drivers_services", "fast", false,
                  "design.monitoring_drivers");
PERDEDOR_REGISTER(artifact_design_analysis_tool_files, "analysis_tools.files", "fast", false,
                  "design.analysis_tool_files");
PERDEDOR_REGISTER(artifact_env_windows_sandbox_paths, "container.app_sandbox", "fast", false,
                  "env.windows_sandbox_paths");
PERDEDOR_REGISTER(artifact_env_deepfreeze_files, "container.app_sandbox", "fast", false,
                  "env.deepfreeze_files");
PERDEDOR_REGISTER(artifact_env_shadowdefender_files, "container.app_sandbox", "fast", false,
                  "env.shadowdefender_files");
PERDEDOR_REGISTER(artifact_env_returnil_files, "container.app_sandbox", "fast", false, "env.returnil_files");
PERDEDOR_REGISTER(acpi_registry, "firmware.acpi_tables", "medium", false, "env.acpi_registry_oems");
PERDEDOR_REGISTER(scsi_registry, "hardware.disk_identity", "medium", false, "env.scsi_registry_identifiers");
PERDEDOR_REGISTER(device_class_registry, "artifacts.registry", "medium", false, "env.device_class_registry");
PERDEDOR_REGISTER(bios_registry, "firmware.bios_metadata", "medium", false, "env.bios_registry_strings");
PERDEDOR_REGISTER(cuckoo_event, "artifacts.named_objects", "medium", false, "env.cuckoo_process_event");
PERDEDOR_REGISTER(guest_driver_files, "guest_tools.drivers_modules", "medium", false, "env.guest_driver_files");
PERDEDOR_REGISTER(virtualpc_provider, "artifacts.registry", "medium", false, "env.virtualbox_network_provider");
} // namespace perdedor
