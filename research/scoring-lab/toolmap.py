"""Map check ids of other evasion suites onto Perdedor technique keys.

The scoring lab needs every finding, whatever tool produced it, expressed as a technique from
catalog/techniques.json, so that the same environment measured by different suites can be scored
by one model. Perdedor ids map through the check catalogs; al-khaser, Pafish and VMAware ids map
through the ordered rules below (first match wins). Unmapped ids are returned as None and counted
by the lab, never silently dropped.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]

# (tool, regex on the tool's own id, technique). Ordered: first match wins.
RULES: List[Tuple[str, str, str]] = [
    # al-khaser ------------------------------------------------------------------------------
    ("alkhaser", r"(current_temperature|cpu_fan|voltageprobe|thermalzoneinfo|cim_(numeric|temperature|voltage)?sensor)", "hardware.thermal_sensors"),
    ("alkhaser", r"cachememory_wmi", "hardware.cpu_cache_clock"),
    ("alkhaser", r"(cim_memory|memoryarray|memorydevice|physicalmemory|smbiosmemory)_wmi", "hardware.memory_modules"),
    ("alkhaser", r"(portconnector|cim_physicalconnector|cim_slot)_wmi", "hardware.port_connectors"),
    ("alkhaser", r"(number_smbios_tables|_firmware_smbios)", "firmware.smbios_raw_table"),
    ("alkhaser", r"firmware_acpi", "firmware.acpi_tables"),
    ("alkhaser", r"hyperv_(driver|global)_objects", "artifacts.named_objects"),
    ("alkhaser", r"rdtsc_diff_locky", "timing.rdtsc_api_ratio"),
    ("alkhaser", r"rdtsc_diff_vmexit", "timing.cpuid_vmexit"),
    ("alkhaser", r"(accelerated_sleep|timing_)", "timing.sleep_acceleration"),
    ("alkhaser", r"parent_is_explorer", "identity.parent_process"),
    ("alkhaser", r"process_in_job", "container.app_sandbox"),
    ("alkhaser", r"module_bounds_hook_check", "instrumentation.inline_hooks"),
    ("alkhaser", r"scan_modules_", "instrumentation.injected_libraries"),
    ("alkhaser", r"mouse_movement", "human.mouse_activity"),
    ("alkhaser", r"lack_user_input", "human.idle_time"),
    ("alkhaser", r"cpuid_is_hypervisor", "cpu.hypervisor_bit"),
    ("alkhaser", r"cpuid_hypervisor_vendor", "cpu.hypervisor_vendor_leaf"),
    ("alkhaser", r"process_id_processor_wmi", "cpu.brand_string"),
    ("alkhaser", r"(gdt|idt|ldt|str)_trick", "cpu.descriptor_tables"),
    ("alkhaser", r"disk_size_|memory_space", "resources.disk_size"),
    ("alkhaser", r"(setupdi_diskdrive|registry_disk_enum|registry_services_disk_enum)", "hardware.disk_identity"),
    ("alkhaser", r"(model|manufacturer)_computer_system_wmi", "firmware.smbios_strings"),
    ("alkhaser", r"(serial_number_bios_wmi|vbox_baseboard_wmi)", "firmware.smbios_serials_uuid"),
    ("alkhaser", r"(check_mac|mac_wmi|hybridanalysismacdetect)", "network.mac_oui"),
    ("alkhaser", r"window_class", "artifacts.window_classes"),
    ("alkhaser", r"vm_driver_services", "guest_tools.services"),
    ("alkhaser", r"(vbox_dir|vmware_dir|kvm_dir|vbox_network_share|vbox_eventlogfile)", "artifacts.files"),
    ("alkhaser", r"(number_cores_wmi|number_of_processors)", "resources.cpu_count"),
    ("alkhaser", r"(pirated_windows|query_license_value)", "os_config.activation_updates"),
    ("alkhaser", r"power_capabilities", "hardware.battery_power"),
    ("alkhaser", r"hosting_check", "network.public_ip_reputation"),
    ("alkhaser", r"wine_exports", "emulator.wine"),
    ("alkhaser", r"(vbox_bus_wmi|vbox_pnpentity)", "hardware.pci_vendor_ids"),
    ("alkhaser", r"vmware_adapter_name", "hardware.nic_identity"),
    ("alkhaser", r"(kernel_debugger|kd_debugger|nt_system_debug_control|wudf_is_kernel)", "debugger.kernel_debugger"),
    ("alkhaser", r"(hardware_breakpoints|memory_breakpoints|page_exception_breakpoint|software_breakpoints)", "debugger.hardware_breakpoints"),
    ("alkhaser", r"(ntqip_debug_object|ntqo_object|close_handle)", "debugger.debug_objects"),
    ("alkhaser", r"(interrupt_|trap_flag|unhandled_exception|output_debug_string|thread_hide|tls_|nt_yield)", "debugger.exception_tricks"),
    ("alkhaser", r"(debugger_present|heap_|nt_global_flag|ntqip_debug|se_debug|low_fragmentation|valloc_write_watch|wudf_is)", "debugger.api_flags"),
    ("alkhaser", r"^environment_artifact\.generic_", "artifacts.registry"),
    ("alkhaser", r"^design_specific\.generic_", "analysis_tools.processes"),
    # Pafish ---------------------------------------------------------------------------------
    ("pafish", r"rdtsc_forcing_vm_exit", "timing.cpuid_vmexit"),
    ("pafish", r"(processor_name|cpu_brand_string)", "cpu.brand_string"),
    ("pafish", r"vbox_processes", "guest_tools.processes"),
    ("pafish", r"(drivers_vbox|vmhgfs_sys|vmmouse_sys)", "guest_tools.drivers_modules"),
    ("pafish", r"(sample_names|checking_file_path)", "identity.sample_path"),
    ("pafish", r"nativevhdboot", "firmware.boot_mode"),
    ("pafish", r"uptime", "timing.uptime"),
    ("pafish", r"sbiedll", "container.app_sandbox"),
    ("pafish", r"wine", "emulator.wine"),
    ("pafish", r"disk_size", "resources.disk_size"),
    ("pafish", r"scsi_port", "hardware.disk_identity"),
    ("pafish", r"pseudo_devices", "artifacts.named_objects"),
    ("pafish", r"devices_using_wmi", "hardware.pci_vendor_ids"),
    ("pafish", r"network_share", "artifacts.files"),
    ("pafish", r"_windows$", "artifacts.window_classes"),
    ("pafish", r"network_adapter_name", "hardware.nic_identity"),
    ("pafish", r"serial_number", "firmware.smbios_serials_uuid"),
    ("pafish", r"rdtsc", "timing.rdtsc_api_ratio"),
    ("pafish", r"hypervisor_bit", "cpu.hypervisor_bit"),
    ("pafish", r"hypervisor_vendor", "cpu.hypervisor_vendor_leaf"),
    ("pafish", r"(mouse_click|double_click|dialog)", "human.clicks_keyboard"),
    ("pafish", r"mouse", "human.mouse_activity"),
    ("pafish", r"sleep", "timing.sleep_acceleration"),
    ("pafish", r"(disk|drive)", "hardware.disk_identity"),
    ("pafish", r"mac", "network.mac_oui"),
    ("pafish", r"(memory|ram)", "resources.memory_size"),
    ("pafish", r"(process|cores|cpu)", "resources.cpu_count"),
    ("pafish", r"(reg|key)", "artifacts.registry"),
    ("pafish", r"(file|dll|dir)", "artifacts.files"),
    ("pafish", r"debugger", "debugger.api_flags"),
    ("pafish", r"(username|path|sandbox)", "identity.username"),
    # VMAware --------------------------------------------------------------------------------
    ("vmaware", r"HYPERVISOR_BIT", "cpu.hypervisor_bit"),
    ("vmaware", r"(HYPERVISOR_STR|VMID|CPU_BRAND)", "cpu.hypervisor_vendor_leaf"),
    ("vmaware", r"(TIMER|KVM_INTERCEPTION|INTERRUPT_SHADOW|SINGLE_STEP|TRAP)", "timing.cpuid_vmexit"),
    ("vmaware", r"(THREAD_MISMATCH|VIRTUAL_PROCESSORS)", "cpu.topology_consistency"),
    ("vmaware", r"FIRMWARE", "firmware.acpi_tables"),
    ("vmaware", r"DEVICES", "hardware.pci_vendor_ids"),
    ("vmaware", r"GPU", "hardware.gpu_identity"),
    ("vmaware", r"DISK", "hardware.disk_identity"),
    # CHIMERA's original single-purpose tools ---------------------------------------------------
    ("cpuid-timing", r"rdtsc_cpuid", "timing.cpuid_vmexit"),
]


def perdedor_ids(root: Path = ROOT) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for f in sorted((root / "catalog" / "checks").glob("*.json")):
        for c in json.loads(f.read_text())["checks"]:
            out[c["id"]] = c["technique"]
    return out


class ToolMap:
    def __init__(self, root: Path = ROOT):
        self.perdedor = perdedor_ids(root)
        self.rules = [(t, re.compile(rx), tech) for t, rx, tech in RULES]

    def technique(self, tool: str, check_id: str) -> Optional[str]:
        if tool == "perdedor":
            return self.perdedor.get(check_id)
        local = check_id.split(".", 1)[1] if check_id.startswith(tool + ".") else check_id
        for t, rx, tech in self.rules:
            if t == tool and rx.search(local):
                return tech
        return None
