"""Temporary static x86_64 probes. Nothing persists after a completed session."""

import json
import re
import struct
from pathlib import Path

from perdedor_common.models import Finding, Platform, Severity, Status
from perdedor_common.registry import CLASS_CATEGORY, spec

from ..adb import shell_quote
from ._base import device_for

# The low-level probes only native code can run: the cpu/timing registrations in
# native/src/common/*.cpp and native/src/linux/lowlevel_*.cpp. Kernel and file-based Linux
# checks are left out because the adb checks read the same data. A regression test keeps
# this table equal to the native source.
NATIVE_CHECKS = {
    "env.cpuid_hypervisor_bit": ("cpu.hypervisor_bit", Severity.CRITICAL),
    "env.cpuid_hypervisor_vendor": ("cpu.hypervisor_vendor_leaf", Severity.CRITICAL),
    "env.cpu_brand_string": ("cpu.brand_string", Severity.HIGH),
    "env.cpuid_hypervisor_leaf_range": ("cpu.hypervisor_leaf_range", Severity.HIGH),
    "env.cpuid_enlightenments": ("cpu.hypervisor_leaf_range", Severity.HIGH),
    "env.cpu_vendor_brand_consistency": ("cpu.feature_consistency", Severity.MEDIUM),
    "env.cpu_feature_consistency": ("cpu.feature_consistency", Severity.MEDIUM),
    "env.cpu_topology_consistency": ("cpu.topology_consistency", Severity.MEDIUM),
    "env.cpu_cache_descriptors": ("cpu.feature_consistency", Severity.LOW),
    "env.cpu_descriptor_tables": ("cpu.descriptor_tables", Severity.LOW),
    "env.vmware_backdoor": ("cpu.vmware_backdoor", Severity.HIGH),
    "env.virtualpc_opcode": ("cpu.undefined_instruction_behaviour", Severity.HIGH),
    "env.hypercall_behavior": ("cpu.undefined_instruction_behaviour", Severity.MEDIUM),
    "env.cpu_emulation_quirks": ("cpu.emulation_quirks", Severity.LOW),
    "timing.rdtsc_cpuid_vmexit": ("timing.cpuid_vmexit", Severity.HIGH),
    "timing.tsc_instruction_availability": ("timing.tsc_stability", Severity.LOW),
    "timing.cpuid_leaf_timing": ("timing.cpuid_vmexit", Severity.LOW),
    "timing.tsc_frequency_stability": ("timing.tsc_stability", Severity.MEDIUM),
    "timing.sleep_acceleration": ("timing.sleep_acceleration", Severity.HIGH),
    "timing.sleep_acceleration_long": ("timing.sleep_acceleration", Severity.HIGH),
    "timing.timer_resolution": ("timing.tsc_stability", Severity.LOW),
    "timing.syscall_instrumentation_latency": ("timing.instrumentation_latency", Severity.MEDIUM),
}
# DESIGN-V2 slow profile budget is <120 seconds; leave room for cleanup.
NATIVE_TIMEOUT_SECONDS = 60
TRANSFER_TIMEOUT_SECONDS = 15
DEFAULT_BINARY = Path(__file__).resolve().parents[4] / "native/build/perdedor-linux-x86_64"


def static_x86_64(path):
    """ELF64 little-endian x86_64 executable without a PT_INTERP segment."""
    try:
        with Path(path).open("rb") as stream:
            header = stream.read(64)
            if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
                return False
            if struct.unpack_from("<H", header, 18)[0] != 62:
                return False
            offset = struct.unpack_from("<Q", header, 32)[0]
            size, count = struct.unpack_from("<HH", header, 54)
            if size != 56 or not 0 < count <= 128:
                return False
            stream.seek(offset)
            segments = stream.read(size * count)
            return len(segments) == size * count and all(
                struct.unpack_from("<I", segments, i * size)[0] != 3 for i in range(count)
            )
    except (OSError, ValueError, struct.error):
        return False


def native_results(ctx):
    dev = device_for(ctx)
    cache_key = "native_results"
    if cache_key in dev._cache:
        return dev._cache[cache_key]
    result = ({}, Status.ERROR, "native run failed")
    if not dev.reachable():
        return {}, Status.ERROR, "adb target unreachable"
    abi = dev.prop("ro.product.cpu.abi")
    if abi is None:
        return {}, Status.ERROR, "device ABI unavailable"
    if abi != "x86_64":
        return {}, Status.SKIPPED, "native helper requires an x86_64 device"
    binary = Path(ctx.params.get("native.binary", str(DEFAULT_BINARY)))
    if not binary.is_file():
        return {}, Status.SKIPPED, "static native binary is not available"
    if not static_x86_64(binary):
        return {}, Status.ERROR, "native.binary must be a static ELF64 x86_64 binary"
    dev.deadline = None
    created = dev.run("mktemp -d /data/local/tmp/perdedor.XXXXXXXX", timeout=5)
    directory = created.stdout.strip() if created is not None and created.returncode == 0 else ""
    if not re.fullmatch(r"/data/local/tmp/perdedor\.[A-Za-z0-9]{8}", directory):
        return {}, Status.ERROR, "could not allocate a private temporary directory"
    remote = directory + "/probe"
    try:
        if not dev.push(str(binary), remote, timeout=TRANSFER_TIMEOUT_SECONDS):
            raise ValueError("native push failed")
        mode = dev.run(f"chmod 700 {shell_quote(remote)}", timeout=5)
        if mode is None or mode.returncode != 0:
            raise ValueError("cannot mark temporary helper executable")
        output = dev.run(
            f"timeout {NATIVE_TIMEOUT_SECONDS} {shell_quote(remote)} "
            "--only class:cpu,class:timing --no-network",
            timeout=NATIVE_TIMEOUT_SECONDS + 2,
        )
        if output is None or output.returncode != 0:
            raise ValueError("native helper failed or timed out")
        document = json.loads(output.stdout)
        if document.get("platform") != "linux" or not isinstance(document.get("findings"), list):
            raise ValueError("unexpected native report schema")
        rows = {}
        for row in document["findings"]:
            rel = row.get("id", "").removeprefix("linux.")
            if rel not in NATIVE_CHECKS or row.get("id") != "linux." + rel:
                continue
            if row.get("technique") != NATIVE_CHECKS[rel][0] or rel in rows:
                raise ValueError("native technique mismatch or duplicate id")
            Status(row["status"])
            rows[rel] = row
        result = rows, Status.ERROR, "native report omitted a registered check"
    except (OSError, ValueError, TypeError, KeyError) as exc:
        result = {}, Status.ERROR, str(exc)
    finally:
        cleanup = dev.run(f"rm -f {shell_quote(remote)} && rmdir {shell_quote(directory)}", timeout=5)
        if cleanup is None or cleanup.returncode != 0:
            result = {}, Status.ERROR, f"cleanup failed; remove temporary helper at {directory}"
    dev._cache[cache_key] = result
    return result


def probe(rel, technique, severity):
    def run(ctx):
        rows, unavailable, detail = native_results(ctx)
        row = rows.get(rel)
        return Finding(
            id="android." + rel,
            platform=Platform.ANDROID,
            category=CLASS_CATEGORY[technique.split(".")[0]],
            name=row.get("name", rel) if row else rel,
            description="CPU/timing observation from the temporary static native helper.",
            status=Status(row["status"]) if row else unavailable,
            severity=severity,
            evidence=row.get("evidence") if row else None,
            error_detail=row.get("error_detail") if row else detail,
            remediation=row.get("remediation") if row else None,
            confidence=row.get("confidence") if row else None,
            measurement=row.get("measurement") if row else None,
        )

    return run


CHECKS = [
    spec("android." + rel, probe(rel, technique, severity), technique, cost="slow", tags=("native",))
    for rel, (technique, severity) in NATIVE_CHECKS.items()
]
