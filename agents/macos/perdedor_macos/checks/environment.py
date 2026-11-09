"""Environment artifacts on macOS: hardware model and firmware identity,
CPU/hypervisor flags, virtual devices, resources and guest tools.

Sources: VMAware v2.8.2 macOS techniques (HWMODEL, MAC_MEMSIZE, MAC_IOKIT,
IOREG_GREP, MAC_SIP, MAC_SYS, THREAD_COUNT), Check Point Evasion Encyclopedia
macOS chapter, Elastic's BANSHEE analysis and AMOS reports (see
docs/notes/apple.md for every URL).
"""

from __future__ import annotations

import re

from perdedor_common.models import Platform, Severity
from perdedor_common.registry import RunContext

from .. import parsing
from .. import signatures as sig
from ..checkkit import UNREACHABLE, Fail, Meta, Result, Skip, Verdict, build, sysctl_value
from ..target import Target

P = Platform.MACOS
# VMware derives the SMBIOS UUID of a VM from bytes 56 4D ("VM").
VMWARE_UUID_PREFIX = "564D"
# Apple serial numbers: 11/12 characters (pre-2021) or 10 randomised characters.
APPLE_SERIAL_RE = re.compile(r"^[A-Z0-9]{10,12}$")
# HID usage page / usage of Apple temperature sensors (IOHIDFamily
# AppleHIDUsageTables.h: kHIDPage_AppleVendor 0xff00, kHIDUsage_AppleVendor_TemperatureSensor 5).
APPLE_VENDOR_USAGE_PAGE = 0xFF00
APPLE_TEMPERATURE_USAGE = 5
LAPTOP_MODEL_PREFIXES = ("macbook",)
BUILT_IN_CAMERA_MODEL_PREFIXES = ("macbook", "imac")


def _arm64(target: Target) -> bool | None:
    values = target.sysctl()
    if values is None:
        return None
    if values.get("hw.optional.arm64") == "1":
        return True
    return "x86_64" not in (values.get("hw.machine") or "") and "Apple" in (
        values.get("machdep.cpu.brand_string") or ""
    )


def _hardware(target: Target) -> dict | None:
    items = parsing.profiler_items(target.profiler("SPHardwareDataType"), "SPHardwareDataType")
    return dict(items[0]) if items else None


def _platform_props(target: Target) -> dict[str, str] | None:
    text = target.ioreg("platform", "-rd1 -c IOPlatformExpertDevice")
    if text is None:
        return None
    return parsing.parse_ioreg_properties(text) or None


def _model(target: Target) -> str:
    values = target.sysctl() or {}
    return values.get("hw.model") or ""


# -- hardware model ------------------------------------------------------------------------


def probe_hw_model(target: Target, ctx: RunContext) -> Result:
    model, fail = sysctl_value(target, "hw.model")
    if fail:
        return fail
    if not model:
        return Fail("sysctl hw.model returned nothing")
    hits = parsing.find_tokens(model, sig.VIRTUAL_MODEL_TOKENS)
    no_mac = sig.REAL_MODEL_MARKER not in model.lower()
    return Verdict(bool(hits) or no_mac, {"hw.model": model, "matched": hits, "lacks_mac": no_mac})


def probe_profiler_model(target: Target, ctx: RunContext) -> Result:
    hw = _hardware(target)
    if hw is None:
        return Fail("system_profiler SPHardwareDataType returned nothing")
    fields = {
        k: hw.get(k) for k in ("machine_model", "machine_name", "chip_type", "cpu_type", "model_number")
    }
    text = " ".join(str(v) for v in fields.values() if v)
    hits = parsing.find_tokens(text, ("virtual", "vmware", "parallels", "virtualbox", "qemu"))
    return Verdict(bool(hits), {**fields, "matched": hits})


def probe_hv_vmm_present(target: Target, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "kern.hv_vmm_present")
    if fail:
        return fail
    if value is None:
        return Skip("kern.hv_vmm_present not available on this macOS version")
    return Verdict(value.strip() == "1", {"kern.hv_vmm_present": value})


def probe_cpu_features_vmm(target: Target, ctx: RunContext) -> Result:
    features, fail = sysctl_value(target, "machdep.cpu.features")
    if fail:
        return fail
    if features is None:
        return Skip("machdep.cpu.features exists only on Intel Macs (Apple Silicon has no CPUID)")
    flags = features.upper().split()
    return Verdict("VMM" in flags, {"machdep.cpu.features": features[:400]})


def probe_cpu_brand(target: Target, ctx: RunContext) -> Result:
    brand, fail = sysctl_value(target, "machdep.cpu.brand_string")
    if fail:
        return fail
    if not brand:
        return Fail("machdep.cpu.brand_string is empty")
    hits = parsing.find_tokens(
        brand, ("(virtual)", "virtual cpu", "qemu", "kvm", "vmware", "bochs", "virtualapple")
    )
    return Verdict(bool(hits), {"brand": brand, "matched": hits})


def probe_hv_support(target: Target, ctx: RunContext) -> Result:
    values = target.sysctl()
    if values is None:
        return Fail(UNREACHABLE + " (sysctl)")
    support = values.get("kern.hv_support")
    if support is None:
        return Skip("kern.hv_support not available")
    arm64 = _arm64(target)
    features = (values.get("machdep.cpu.features") or "").upper().split()
    # Every Apple Silicon Mac and every Intel Mac with VT-x supports
    # Hypervisor.framework on bare metal; a guest normally does not.
    capable = bool(arm64) or "VMX" in features
    if not capable:
        return Skip("CPU does not advertise virtualisation support (no VMX), so 0 is expected")
    return Verdict(support.strip() == "0", {"kern.hv_support": support, "arm64": arm64})


def probe_cpu_topology(target: Target, ctx: RunContext) -> Result:
    values = target.sysctl()
    if values is None:
        return Fail(UNREACHABLE + " (sysctl)")
    logical = parsing.as_int(values.get("hw.logicalcpu"))
    physical = parsing.as_int(values.get("hw.physicalcpu"))
    levels = parsing.as_int(values.get("hw.nperflevels"))
    if _arm64(target):
        # Every M-series chip combines performance and efficiency cores (two perf levels).
        if levels is None:
            return Skip("hw.nperflevels not available")
        return Verdict(
            levels < sig.MIN_ARM_PERFORMANCE_LEVELS,
            {"hw.nperflevels": levels, "hw.physicalcpu": physical},
            confidence=0.4,
        )
    if not logical or not physical:
        return Fail("hw.logicalcpu / hw.physicalcpu missing")
    # Check Point: hyper-threaded Intel Macs report logical = 2 x physical; many
    # hypervisors present one thread per core. Outdated for some 2018+ models.
    return Verdict(
        logical == physical,
        {"hw.logicalcpu": logical, "hw.physicalcpu": physical},
        confidence=0.5,
    )


def probe_cpu_count(target: Target, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "hw.logicalcpu")
    if fail:
        return fail
    count = parsing.as_int(value) or parsing.as_int((target.sysctl() or {}).get("hw.ncpu"))
    if count is None:
        return Fail("hw.logicalcpu / hw.ncpu missing")
    minimum = ctx.param("cpu.min", sig.MIN_LOGICAL_CPUS)
    return Verdict(
        count < minimum, {"logical_cpus": count}, measurement={"value": count, "threshold": minimum}
    )


def probe_memsize(target: Target, ctx: RunContext) -> Result:
    value, fail = sysctl_value(target, "hw.memsize")
    if fail:
        return fail
    size = parsing.as_int(value)
    if not size:
        return Fail(f"hw.memsize unparseable: {value!r}")
    limit = ctx.param("memory.min_bytes", sig.MIN_MEMSIZE_BYTES)
    return Verdict(size <= limit, {"hw.memsize": size}, measurement={"value": size, "threshold": limit})


def probe_disk_size(target: Target, ctx: RunContext) -> Result:
    text = target.out("df_root", "df -k /")
    if text is None:
        return Fail("df -k / failed")
    kbytes = parsing.parse_df_kbytes(text)
    if kbytes is None:
        return Fail(f"df output unparseable: {text[:200]!r}")
    size = kbytes * 1024
    minimum = int(ctx.param("disk.min_gb", sig.MIN_DISK_BYTES // 1000**3)) * 1000**3
    return Verdict(
        size < minimum, {"root_volume_bytes": size}, measurement={"value": size, "threshold": minimum}
    )


def _displays(target: Target) -> tuple[list[dict], list[dict]] | None:
    doc = target.profiler("SPDisplaysDataType")
    if doc is None:
        return None
    gpus = parsing.profiler_items(doc, "SPDisplaysDataType")
    screens = [s for g in gpus for s in g.get("spdisplays_ndrvs", []) if isinstance(s, dict)]
    return gpus, screens


def probe_display_resolution(target: Target, ctx: RunContext) -> Result:
    data = _displays(target)
    if data is None:
        return Fail("system_profiler SPDisplaysDataType returned nothing")
    _, screens = data
    if not screens:
        return Skip("no display attached (see macos.env.display_present)")
    resolutions = []
    for screen in screens:
        res = parsing.parse_resolution(
            screen.get("_spdisplays_pixels") or screen.get("_spdisplays_resolution")
        )
        if res:
            resolutions.append(res)
    if not resolutions:
        return Fail("no parseable display resolution")
    best = max(resolutions, key=lambda r: r[0] * r[1])
    small = best[0] < sig.MIN_SCREEN_WIDTH or best[1] < sig.MIN_SCREEN_HEIGHT
    return Verdict(small, {"resolutions": [f"{w}x{h}" for w, h in resolutions]})


def probe_display_present(target: Target, ctx: RunContext) -> Result:
    data = _displays(target)
    if data is None:
        return Fail("system_profiler SPDisplaysDataType returned nothing")
    _, screens = data
    return Verdict(not screens, {"displays": [s.get("_name") for s in screens]})


def probe_gpu_identity(target: Target, ctx: RunContext) -> Result:
    data = _displays(target)
    if data is None:
        return Fail("system_profiler SPDisplaysDataType returned nothing")
    gpus, _ = data
    names = [str(g.get("sppci_model") or g.get("_name") or "") for g in gpus]
    if not names:
        return Verdict(True, {"gpus": [], "note": "no graphics adapter reported"})
    hits = parsing.find_tokens(" ".join(names), sig.VIRTUAL_GPU_TOKENS)
    return Verdict(bool(hits), {"gpus": names, "matched": hits})


# -- firmware / platform identity --------------------------------------------------------------


def probe_platform_serial(target: Target, ctx: RunContext) -> Result:
    props = _platform_props(target)
    if props is None:
        return Fail("ioreg -c IOPlatformExpertDevice failed")
    serial = parsing.ioreg_string(props.get("IOPlatformSerialNumber")) or ""
    reasons = []
    if serial in ("", "0"):
        reasons.append("empty or '0' (Check Point / VMAware MAC_IOKIT)")
    if parsing.find_tokens(serial, sig.VENDOR_TOKENS):
        reasons.append("hypervisor vendor in serial")
    if serial and serial not in ("0",) and not APPLE_SERIAL_RE.match(serial):
        reasons.append("not in Apple serial-number format")
    return Verdict(bool(reasons), {"IOPlatformSerialNumber": serial, "reasons": reasons})


def probe_platform_uuid(target: Target, ctx: RunContext) -> Result:
    props = _platform_props(target)
    if props is None:
        return Fail("ioreg -c IOPlatformExpertDevice failed")
    uuid = (parsing.ioreg_string(props.get("IOPlatformUUID")) or "").upper()
    if not uuid:
        return Verdict(True, {"IOPlatformUUID": None, "reason": "missing"})
    hexdigits = uuid.replace("-", "")
    reasons = []
    if set(hexdigits) <= {"0"} or set(hexdigits) <= {"F"}:
        reasons.append("all-zero / all-F UUID")
    if hexdigits.startswith(VMWARE_UUID_PREFIX):
        reasons.append("VMware UUID prefix 564D")
    return Verdict(bool(reasons), {"IOPlatformUUID": uuid, "reasons": reasons})


def probe_board_id(target: Target, ctx: RunContext) -> Result:
    props = _platform_props(target)
    if props is None:
        return Fail("ioreg -c IOPlatformExpertDevice failed")
    board = parsing.ioreg_string(props.get("board-id")) or ""
    target_type = parsing.ioreg_string(props.get("target-type")) or ""
    compatible = parsing.ioreg_string(props.get("compatible")) or ""
    text = " ".join((board, target_type, compatible))
    if not text.strip():
        return Skip("board identity fields unavailable")
    hits = parsing.find_tokens(text, sig.HYPERVISOR_TOKENS)
    return Verdict(
        bool(hits), {"board-id": board, "target-type": target_type, "compatible": compatible, "matched": hits}
    )


def probe_platform_manufacturer(target: Target, ctx: RunContext) -> Result:
    props = _platform_props(target)
    if props is None:
        return Fail("ioreg -c IOPlatformExpertDevice failed")
    manufacturer = parsing.ioreg_string(props.get("manufacturer"))
    if manufacturer is None:
        return Skip("IOPlatformExpertDevice has no manufacturer property on this machine")
    return Verdict("apple" not in manufacturer.lower(), {"manufacturer": manufacturer})


def probe_boot_rom(target: Target, ctx: RunContext) -> Result:
    hw = _hardware(target)
    if hw is None:
        return Fail("system_profiler SPHardwareDataType returned nothing")
    rom = str(hw.get("boot_rom_version") or "")
    if not rom:
        return Skip("boot ROM version unavailable")
    hits = parsing.find_tokens(
        rom, ("virtualbox", "vmw", "vmware", "parallels", "qemu", "ovmf", "edk", "seabios")
    )
    return Verdict(bool(hits), {"boot_rom_version": rom, "matched": hits})


def probe_ioreg_strings(target: Target, ctx: RunContext) -> Result:
    text = target.ioreg("all", "-l -w0")
    if text is None:
        return Fail("ioreg -l failed")
    lowered = text.lower()
    counts = {t: lowered.count(t) for t in sig.HYPERVISOR_TOKENS if t in lowered}
    return Verdict(bool(counts), {"occurrences": counts})


def probe_device_tree(target: Target, ctx: RunContext) -> Result:
    text = target.ioreg("devicetree", "-lw0 -p IODeviceTree")
    if text is None:
        return Fail("ioreg -p IODeviceTree failed")
    hits = parsing.find_tokens(text, ("virtual machine", "vma2macos", "applevirtualplatform", "virtualmac"))
    return Verdict(bool(hits), {"matched": hits})


def probe_memory_vendor(target: Target, ctx: RunContext) -> Result:
    doc = target.profiler("SPMemoryDataType")
    if doc is None:
        return Fail("system_profiler SPMemoryDataType returned nothing")
    text = parsing.flatten_strings(doc)
    hits = parsing.find_tokens(text, ("qemu", "vmware", "kvm", "virtualbox", "parallels"))
    return Verdict(bool(hits), {"matched": hits, "summary": text[:300]})


def probe_secure_enclave(target: Target, ctx: RunContext) -> Result:
    arm64 = _arm64(target)
    if arm64 is None:
        return Fail(UNREACHABLE + " (sysctl)")
    if not arm64:
        return Skip("Intel Macs without a T2 chip have no Secure Enclave")
    text = target.ioreg("sep", "-rd1 -c AppleSEPManager")
    if text is None:
        return Fail("ioreg -c AppleSEPManager failed")
    present = "AppleSEPManager" in text
    return Verdict(not present, {"AppleSEPManager": present})


# -- devices ---------------------------------------------------------------------------------


def probe_usb_vendors(target: Target, ctx: RunContext) -> Result:
    text = target.ioreg("usb", "-rd1 -c IOUSBHostDevice")
    if text is None:
        return Fail("ioreg -c IOUSBHostDevice failed")
    vendors = sorted(set(re.findall(r'"USB Vendor Name"\s*=\s*"([^"]*)"', text)))
    hits = parsing.find_tokens(" ".join(vendors), sig.VENDOR_TOKENS + ("virtual",))
    return Verdict(bool(hits), {"vendors": vendors, "matched": hits})


def probe_usb_count(target: Target, ctx: RunContext) -> Result:
    doc = target.profiler("SPUSBDataType")
    key = "SPUSBDataType"
    if doc is None:
        doc, key = target.profiler("SPUSBHostDataType"), "SPUSBHostDataType"
    if doc is None:
        return Fail("system_profiler SPUSBDataType / SPUSBHostDataType returned nothing")
    devices = [i for i in parsing.walk_items(parsing.profiler_items(doc, key)) if "_name" in i]
    names = [str(d.get("_name")) for d in devices]
    hits = parsing.find_tokens(" ".join(names), sig.VENDOR_TOKENS)
    return Verdict(not devices or bool(hits), {"usb_entries": names[:30], "matched": hits})


def probe_storage(target: Target, ctx: RunContext) -> Result:
    doc = target.profiler("SPStorageDataType")
    if doc is None:
        return Fail("system_profiler SPStorageDataType returned nothing")
    drives = []
    for item in parsing.profiler_items(doc, "SPStorageDataType"):
        phys = item.get("physical_drive") or {}
        drives.append(
            " ".join(str(phys.get(k, "")) for k in ("device_name", "media_name", "protocol")).strip()
        )
    hits = parsing.find_tokens(" ".join(drives), sig.VIRTUAL_DEVICE_TOKENS)
    return Verdict(bool(hits), {"drives": sorted(set(drives)), "matched": hits})


def probe_nic(target: Target, ctx: RunContext) -> Result:
    text = target.ioreg("ethernet", "-r -c IOEthernetController -d 1")
    if text is None:
        return Fail("ioreg -c IOEthernetController failed")
    classes = sorted(set(re.findall(r"\+-o\s+(\S+)", text)))
    props = parsing.parse_ioreg_properties(text)
    model = " ".join(filter(None, (props.get("IOModel"), props.get("IOVendor"), props.get("IOClass"))))
    hits = parsing.find_tokens(
        " ".join(classes) + " " + model, ("virtio", "vmxnet", "vmware", "parallels", "qemu")
    )
    return Verdict(bool(hits), {"controllers": classes, "model": model, "matched": hits})


def probe_audio(target: Target, ctx: RunContext) -> Result:
    doc = target.profiler("SPAudioDataType")
    if doc is None:
        return Fail("system_profiler SPAudioDataType returned nothing")
    devices = [
        str(i.get("_name")) for i in parsing.walk_items(parsing.profiler_items(doc, "SPAudioDataType"))
    ]
    devices = [d for d in devices if d and d != "None" and d != "coreaudio_device"]
    hits = parsing.find_tokens(" ".join(devices), sig.VIRTUAL_DEVICE_TOKENS)
    return Verdict(not devices or bool(hits), {"devices": devices, "matched": hits})


def _hid_temperature_sensors(text: str) -> int:
    count = 0
    for block in re.split(r"\+-o ", text):
        page = re.search(r'"PrimaryUsagePage"\s*=\s*(\d+)', block)
        usage = re.search(r'"PrimaryUsage"\s*=\s*(\d+)', block)
        if (
            page
            and usage
            and int(page.group(1)) == APPLE_VENDOR_USAGE_PAGE
            and int(usage.group(1)) == APPLE_TEMPERATURE_USAGE
        ):
            count += 1
    return count


def probe_thermal(target: Target, ctx: RunContext) -> Result:
    arm64 = _arm64(target)
    if arm64 is None:
        return Fail(UNREACHABLE + " (sysctl)")
    if arm64:
        text = target.ioreg("hid_sensors", "-r -c IOHIDEventService -k PrimaryUsagePage -d 1")
        if text is None:
            return Fail("ioreg -c IOHIDEventService failed")
        sensors = _hid_temperature_sensors(text)
        return Verdict(sensors == 0, {"apple_temperature_sensors": sensors})
    text = target.ioreg("smc", "-r -c AppleSMC -d 1")
    if text is None:
        return Fail("ioreg -c AppleSMC failed")
    # VMware and Parallels emulate an SMC for macOS guests, so a present SMC is
    # not proof of hardware; an absent one is a strong tell.
    present = "AppleSMC" in text
    return Verdict(not present, {"AppleSMC": present}, confidence=0.6)


def probe_battery(target: Target, ctx: RunContext) -> Result:
    model = _model(target)
    if not model:
        return Fail("hw.model unavailable")
    text = target.ioreg("battery", "-r -c AppleSmartBattery -d 1")
    if text is None:
        return Fail("ioreg -c AppleSmartBattery failed")
    present = "AppleSmartBattery" in text
    hardware = _hardware(target) or {}
    family = str(hardware.get("machine_name", "")).lower().replace(" ", "")
    laptop = model.lower().startswith(LAPTOP_MODEL_PREFIXES) or family.startswith(LAPTOP_MODEL_PREFIXES)
    if not family and re.fullmatch(r"Mac\d+,\d+", model):
        return Skip("hardware family unavailable for unified Mac identifier")
    props = parsing.parse_ioreg_properties(text)
    evidence = {"hw.model": model, "battery": present, "CycleCount": parsing.as_int(props.get("CycleCount"))}
    if not laptop:
        return Verdict(False, {**evidence, "note": "desktop model: no battery expected"})
    return Verdict(not present, evidence)


def probe_bluetooth(target: Target, ctx: RunContext) -> Result:
    doc = target.profiler("SPBluetoothDataType")
    if doc is None:
        return Fail("system_profiler SPBluetoothDataType returned nothing")
    items = parsing.profiler_items(doc, "SPBluetoothDataType")
    controller = items[0].get("controller_properties") if items else None
    return Verdict(not controller, {"controller": bool(controller)})


def probe_camera(target: Target, ctx: RunContext) -> Result:
    model = _model(target)
    doc = target.profiler("SPCameraDataType")
    if doc is None:
        return Fail("system_profiler SPCameraDataType returned nothing")
    cameras = [str(i.get("_name")) for i in parsing.profiler_items(doc, "SPCameraDataType")]
    hardware = _hardware(target) or {}
    family = str(hardware.get("machine_name", "")).lower().replace(" ", "")
    builtin_expected = model.lower().startswith(BUILT_IN_CAMERA_MODEL_PREFIXES) or family.startswith(
        BUILT_IN_CAMERA_MODEL_PREFIXES
    )
    if not family and re.fullmatch(r"Mac\d+,\d+", model):
        return Skip("hardware family unavailable for unified Mac identifier")
    hits = parsing.find_tokens(" ".join(cameras), sig.VIRTUAL_DEVICE_TOKENS)
    if not builtin_expected and not hits:
        return Verdict(False, {"hw.model": model, "cameras": cameras, "note": "no built-in camera expected"})
    return Verdict(not cameras or bool(hits), {"hw.model": model, "cameras": cameras, "matched": hits})


def probe_cpu_cache(target: Target, ctx: RunContext) -> Result:
    values = target.sysctl()
    if values is None:
        return Fail(UNREACHABLE + " (sysctl)")
    l2 = parsing.as_int(values.get("hw.l2cachesize"))
    line = parsing.as_int(values.get("hw.cachelinesize"))
    if l2 is None or line is None:
        return Skip("CPU cache sizes are not exposed by this kernel")
    return Verdict(not l2 or not line, {"hw.l2cachesize": l2, "hw.cachelinesize": line})


# -- guest tools --------------------------------------------------------------------------------


def _loaded_kexts(target: Target) -> list[str] | None:
    text = target.out("kmutil_loaded", "kmutil showloaded --list-only 2>/dev/null || kextstat -l")
    if text is None:
        return None
    return [k.lower() for k in parsing.parse_kext_bundles(text)]


def kext_probe(vendor: str):
    prefixes = sig.KEXT_PREFIXES[vendor]

    def probe(target: Target, ctx: RunContext) -> Result:
        kexts = _loaded_kexts(target)
        if kexts is None:
            return Fail("kmutil showloaded / kextstat failed")
        hits = sorted({k for k in kexts if k.startswith(prefixes)})
        return Verdict(bool(hits), {"loaded": hits, "total_loaded": len(kexts)})

    return probe


def probe_guest_processes(target: Target, ctx: RunContext) -> Result:
    procs = target.processes()
    if procs is None:
        return Fail(UNREACHABLE + " (ps)")
    hits = parsing.matching_processes(procs, sig.GUEST_TOOL_PROCESSES)
    return Verdict(bool(hits), {"processes": hits[:20]})


def probe_guest_launchd(target: Target, ctx: RunContext) -> Result:
    labels = target.launchd_labels()
    if labels is None:
        return Fail("launchctl list failed")
    hits = sorted(label for label in labels if parsing.find_tokens(label, sig.GUEST_TOOL_NAME_TOKENS))
    return Verdict(bool(hits), {"labels": hits[:20]})


GUEST_TOOL_DIRS = (
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    "/Library/Application Support",
    "/Library/Extensions",
    "/Applications",
)


def probe_guest_files(target: Target, ctx: RunContext) -> Result:
    hits = []
    for directory in GUEST_TOOL_DIRS:
        listing = target.listdir(directory)
        if listing is None:
            return Fail(UNREACHABLE)
        if listing.entries is None and listing.error != "missing":
            return Skip("guest-tool directory unreadable")
        for entry in listing.entries or ():
            if parsing.find_tokens(entry, sig.GUEST_TOOL_NAME_TOKENS):
                hits.append(f"{directory}/{entry}")
    return Verdict(bool(hits), {"found": hits[:30]})


# -- CPU as an x86_64 sample sees it ---------------------------------------------------------------


def probe_rosetta_brand(target: Target, ctx: RunContext) -> Result:
    arm64 = _arm64(target)
    if arm64 is None:
        return Fail(UNREACHABLE + " (sysctl)")
    if not arm64:
        return Skip("Intel Mac: no Rosetta translation")
    result = target.run("rosetta_brand", "arch -x86_64 /usr/sbin/sysctl -n machdep.cpu.brand_string")
    if result is None:
        return Fail(UNREACHABLE)
    if not result.ok:
        return Skip("Rosetta 2 is not installed (x86_64 samples cannot run at all)")
    brand = result.stdout.strip()
    return Verdict("virtualapple" in brand.lower(), {"x86_64_brand_string": brand})


def _c(check_id, technique, name, description, severity, remediation, probe, **kw):
    return build(P, Meta(check_id, technique, name, description, severity, remediation), probe, **kw)


_MODEL_FIX = "Run macOS analysis on bare-metal Apple hardware, or patch the VM's platform identity (model, board-id, serial) to a real Mac's values."
_DEVICE_FIX = (
    "Present real or passthrough devices, or rename the virtual device in the hypervisor configuration."
)

CHECKS = [
    _c(
        "macos.env.hw_model",
        "emulator.macos_virtual_model",
        "Hardware model (hw.model)",
        "sysctl hw.model names a virtual Mac (VirtualMac2,1, VMware7,1, Parallels) or lacks 'Mac' (VMAware HWMODEL, MacRansom).",
        Severity.CRITICAL,
        _MODEL_FIX,
        probe_hw_model,
    ),
    _c(
        "macos.env.profiler_model",
        "emulator.macos_virtual_model",
        "system_profiler model identifier",
        "SPHardwareDataType Model Identifier / Model Name contains 'Virtual' (BANSHEE, VMAware MAC_SYS) or a hypervisor name.",
        Severity.CRITICAL,
        _MODEL_FIX,
        probe_profiler_model,
        cost="medium",
    ),
    _c(
        "macos.env.hv_vmm_present",
        "container.virtualisation_report",
        "kern.hv_vmm_present",
        "The kernel reports it runs under a hypervisor (VMAware MAC_SIP first test).",
        Severity.CRITICAL,
        "Hide the VMM flag in the hypervisor (CPUID leaf 1 ECX[31] on Intel; not configurable in Virtualization.framework).",
        probe_hv_vmm_present,
    ),
    _c(
        "macos.env.cpu_features_vmm",
        "cpu.hypervisor_bit",
        "VMM flag in machdep.cpu.features",
        "Intel Macs list CPUID feature flags in machdep.cpu.features; 'VMM' is the hypervisor-present bit.",
        Severity.CRITICAL,
        "Mask CPUID leaf 1 ECX bit 31 in the hypervisor CPUID policy.",
        probe_cpu_features_vmm,
    ),
    _c(
        "macos.env.cpu_brand",
        "cpu.brand_string",
        "CPU brand string",
        "machdep.cpu.brand_string names a virtual CPU ('Apple M2 (Virtual)', QEMU, KVM).",
        Severity.HIGH,
        "Pass the host CPU model through to the guest.",
        probe_cpu_brand,
    ),
    _c(
        "macos.env.hv_support",
        "cpu.feature_consistency",
        "Hypervisor.framework support",
        "kern.hv_support is 0 although the CPU supports virtualisation: guests normally cannot nest Hypervisor.framework.",
        Severity.MEDIUM,
        "Enable nested virtualisation where the host supports it, or use bare metal.",
        probe_hv_support,
    ),
    _c(
        "macos.env.cpu_topology",
        "cpu.topology_consistency",
        "CPU topology",
        "Apple Silicon reports two performance levels (P and E cores); hyper-threaded Intel Macs report logical = 2 x physical (Check Point).",
        Severity.LOW,
        "Give the VM a topology matching the claimed model (threads per core, core types).",
        probe_cpu_topology,
    ),
    _c(
        "macos.env.cpu_count",
        "resources.cpu_count",
        "Logical CPU count",
        "Fewer logical CPUs than any current Mac (VMAware THREAD_COUNT).",
        Severity.MEDIUM,
        "Assign at least 4 vCPUs (8 to match an M1).",
        probe_cpu_count,
    ),
    _c(
        "macos.env.memsize",
        "resources.memory_size",
        "Physical memory (hw.memsize)",
        "hw.memsize at or below 4 GB (VMAware MAC_MEMSIZE, Check Point memory size method).",
        Severity.MEDIUM,
        "Assign at least 8 GB of memory to the VM.",
        probe_memsize,
    ),
    _c(
        "macos.env.disk_size",
        "resources.disk_size",
        "Root volume size",
        "Boot volume smaller than the smallest Mac SSD.",
        Severity.MEDIUM,
        "Give the VM disk at least 256 GB (thin-provisioned).",
        probe_disk_size,
    ),
    _c(
        "macos.env.display_resolution",
        "resources.screen",
        "Display resolution",
        "Largest display below 1280x720: default VMware SVGA / QEMU framebuffer sizes.",
        Severity.MEDIUM,
        "Configure a Retina-class virtual display (e.g. 2560x1600).",
        probe_display_resolution,
        cost="medium",
    ),
    _c(
        "macos.env.display_present",
        "resources.screen",
        "Display attached",
        "No display reported at all (headless VM).",
        Severity.MEDIUM,
        "Attach a virtual display or a dummy HDMI plug on bare metal.",
        probe_display_present,
        cost="medium",
    ),
    _c(
        "macos.env.gpu_identity",
        "hardware.gpu_identity",
        "Graphics adapter",
        "SPDisplaysDataType chipset is a paravirtual adapter ('Apple Paravirtual device', VMware SVGA, Parallels Display Adapter).",
        Severity.HIGH,
        _DEVICE_FIX,
        probe_gpu_identity,
        cost="medium",
    ),
    _c(
        "macos.env.platform_serial",
        "firmware.smbios_serials_uuid",
        "Platform serial number",
        "IOPlatformSerialNumber is '0', empty, vendor-named, malformed, or on the AMOS sandbox serial list.",
        Severity.HIGH,
        "Set a plausible Apple serial in the VM configuration (VMware serialNumber, UTM/VZ machine identifier).",
        probe_platform_serial,
    ),
    _c(
        "macos.env.platform_uuid",
        "firmware.smbios_serials_uuid",
        "Platform UUID",
        "IOPlatformUUID all-zero or with the VMware 564D prefix.",
        Severity.MEDIUM,
        "Generate a random RFC 4122 UUID for the VM (VMware uuid.bios, VZ machine identifier).",
        probe_platform_uuid,
    ),
    _c(
        "macos.env.board_id",
        "firmware.smbios_strings",
        "Board id / device tree target",
        "board-id, target-type or compatible names a hypervisor (VirtualBox, VMware, VMA2MACOS, AppleVirtualPlatform) (VMAware MAC_IOKIT).",
        Severity.HIGH,
        _MODEL_FIX,
        probe_board_id,
    ),
    _c(
        "macos.env.platform_manufacturer",
        "firmware.smbios_strings",
        "Platform manufacturer",
        "IOPlatformExpertDevice manufacturer is not Apple (VMAware MAC_IOKIT: innotek GmbH).",
        Severity.HIGH,
        _MODEL_FIX,
        probe_platform_manufacturer,
    ),
    _c(
        "macos.env.boot_rom_version",
        "firmware.smbios_strings",
        "Boot ROM version",
        "SPHardwareDataType Boot ROM Version names a hypervisor firmware (Check Point; OceanLotus).",
        Severity.HIGH,
        "Use firmware that reports an Apple Boot ROM version, or bare metal.",
        probe_boot_rom,
        cost="medium",
    ),
    _c(
        "macos.env.ioreg_hypervisor_strings",
        "emulator.macos_virtual_model",
        "Hypervisor strings in the I/O Registry",
        "ioreg -l contains hypervisor or paravirtual device names (Check Point ioreg -l grep).",
        Severity.HIGH,
        _DEVICE_FIX,
        probe_ioreg_strings,
        cost="medium",
    ),
    _c(
        "macos.env.device_tree_virtual",
        "emulator.macos_virtual_model",
        "Virtual platform in the device tree",
        "IODeviceTree contains 'Virtual Machine' (VMAware MAC_IOKIT keyboard test) or the VZ platform names.",
        Severity.HIGH,
        _MODEL_FIX,
        probe_device_tree,
        cost="medium",
    ),
    _c(
        "macos.env.memory_module_vendor",
        "hardware.memory_modules",
        "Memory module vendor",
        "SPMemoryDataType names QEMU, VMware or KVM (AMOS anti-VM AppleScript).",
        Severity.HIGH,
        "Report a real DRAM vendor in the VM's SMBIOS type 17 strings.",
        probe_memory_vendor,
        cost="medium",
    ),
    _c(
        "macos.env.secure_enclave",
        "firmware.boot_mode",
        "Secure Enclave",
        "Apple Silicon without an AppleSEPManager: no Secure Enclave, unlike every Apple Silicon Mac.",
        Severity.MEDIUM,
        "Accept as a residual Virtualization.framework gap or use bare metal.",
        probe_secure_enclave,
    ),
    _c(
        "macos.env.usb_vendor_names",
        "hardware.usb_devices",
        "USB vendor names",
        "IOUSBHostDevice 'USB Vendor Name' names a hypervisor (Check Point, VMAware IOREG_GREP).",
        Severity.HIGH,
        _DEVICE_FIX,
        probe_usb_vendors,
    ),
    _c(
        "macos.env.usb_devices",
        "hardware.usb_devices",
        "USB device tree",
        "No USB devices at all, or virtual ones, in system_profiler.",
        Severity.LOW,
        "Pass through or emulate ordinary USB peripherals.",
        probe_usb_count,
        cost="medium",
    ),
    _c(
        "macos.env.storage_identity",
        "hardware.disk_identity",
        "Storage device identity",
        "Boot drive model names a virtual disk (virtio, VMware Virtual, QEMU HARDDISK, VBOX).",
        Severity.HIGH,
        _DEVICE_FIX,
        probe_storage,
        cost="medium",
    ),
    _c(
        "macos.env.nic_identity",
        "hardware.nic_identity",
        "Ethernet controller identity",
        "Ethernet controller is a virtio / vmxnet / Parallels adapter.",
        Severity.MEDIUM,
        _DEVICE_FIX,
        probe_nic,
    ),
    _c(
        "macos.env.audio_devices",
        "hardware.audio_devices",
        "Audio devices",
        "No audio device, or a virtual one.",
        Severity.LOW,
        "Attach a virtual sound device with a realistic name.",
        probe_audio,
        cost="medium",
    ),
    _c(
        "macos.env.thermal_sensors",
        "hardware.thermal_sensors",
        "Temperature sensors",
        "No Apple temperature sensors (Apple Silicon HID usage 0xff00/5) or no SMC (Intel).",
        Severity.MEDIUM,
        "Not configurable in common hypervisors; use bare metal or accept the residual risk.",
        probe_thermal,
    ),
    _c(
        "macos.env.battery",
        "hardware.battery_power",
        "Battery on a laptop model",
        "A MacBook model without a battery (AppleSmartBattery).",
        Severity.MEDIUM,
        "Do not claim a laptop model in a VM, or emulate a battery.",
        probe_battery,
    ),
    _c(
        "macos.env.bluetooth_controller",
        "mobile_device.radios",
        "Bluetooth controller",
        "No Bluetooth controller: every Mac since 2011 has one.",
        Severity.MEDIUM,
        "Pass through a USB Bluetooth adapter or use bare metal.",
        probe_bluetooth,
        cost="medium",
    ),
    _c(
        "macos.env.camera",
        "mobile_device.camera",
        "Built-in camera",
        "A MacBook / iMac model without a camera, or a virtual camera.",
        Severity.LOW,
        "Pass through a USB camera, or do not claim a model with a built-in camera.",
        probe_camera,
        cost="medium",
    ),
    _c(
        "macos.env.cpu_cache",
        "hardware.cpu_cache_clock",
        "CPU cache sizes",
        "hw.l2cachesize or hw.cachelinesize is zero or missing.",
        Severity.LOW,
        "Expose the host cache topology to the guest.",
        probe_cpu_cache,
    ),
    _c(
        "macos.env.kext_vmware",
        "guest_tools.drivers_modules",
        "VMware kexts loaded",
        "Loaded com.vmware.kext.* drivers (VMware Tools).",
        Severity.HIGH,
        "Uninstall VMware Tools from the analysis image.",
        kext_probe("vmware"),
    ),
    _c(
        "macos.env.kext_parallels",
        "guest_tools.drivers_modules",
        "Parallels kexts loaded",
        "Loaded com.parallels.* drivers (Parallels Tools).",
        Severity.HIGH,
        "Uninstall Parallels Tools from the analysis image.",
        kext_probe("parallels"),
    ),
    _c(
        "macos.env.kext_virtualbox",
        "guest_tools.drivers_modules",
        "VirtualBox kexts loaded",
        "Loaded org.virtualbox.kext.* drivers (Guest Additions).",
        Severity.HIGH,
        "Uninstall the VirtualBox Guest Additions.",
        kext_probe("virtualbox"),
    ),
    _c(
        "macos.env.kext_apple_virtualization",
        "guest_tools.drivers_modules",
        "Virtualization.framework drivers loaded",
        "AppleVirtIO / AppleParavirtGPU / AppleVirtualPlatform kexts are loaded (they only load inside VZ guests).",
        Severity.HIGH,
        "Unavoidable in a Virtualization.framework guest; use bare metal for evasive samples.",
        kext_probe("apple_virtualization"),
    ),
    _c(
        "macos.env.guest_tools_processes",
        "guest_tools.processes",
        "Guest tool processes",
        "vmware-tools-daemon, prl_tools_service, VBoxService, spice-vdagent or qemu-ga running.",
        Severity.HIGH,
        "Remove guest tools from the analysis image.",
        probe_guest_processes,
    ),
    _c(
        "macos.env.guest_tools_launchd",
        "guest_tools.services",
        "Guest tool launchd jobs",
        "launchctl list shows VMware / Parallels / VirtualBox / SPICE / QEMU jobs.",
        Severity.HIGH,
        "Remove guest tools and their launchd plists.",
        probe_guest_launchd,
    ),
    _c(
        "macos.env.guest_tools_files",
        "artifacts.files",
        "Guest tool files",
        "LaunchDaemons, LaunchAgents, Application Support, Extensions or Applications entries of hypervisor tools.",
        Severity.MEDIUM,
        "Delete the leftover guest-tool files from the image.",
        probe_guest_files,
    ),
    _c(
        "macos.env.rosetta_cpu_brand",
        "cpu.brand_string",
        "CPU brand seen by x86_64 code",
        "Under Rosetta 2, x86_64 code reads the CPU brand 'VirtualApple @ 2.50GHz processor'.",
        Severity.LOW,
        "None on Apple Silicon; analyse x86_64-only samples on Intel hardware if they key on it.",
        probe_rosetta_brand,
    ),
]
