"""Category 2 (Ch.3.2.2): timing-based detection.

RDTSC-class checks cannot be fixed by artifact spoofing -- they arise from
the underlying execution model. See CHIMERA KVM report Section 5.5 for the
empirical detail behind the thresholds used here.
"""

from __future__ import annotations

from perdedor_common import FindingFactory
from perdedor_common.models import Category, Finding, Platform, Severity

from .. import cpu, utils

_PLATFORM = Platform.LINUX
_CATEGORY = Category.TIMING
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)

# PAfish-class threshold: an uptime below this looks like "just booted for
# this sample", which malware treats as a sandbox tell.
_LOW_UPTIME_SECONDS = 600.0

# Heuristic RDTSC-around-CPUID VM-exit floor. The CHIMERA KVM report measured
# ~1816 cycles as the hardware VM-exit floor on a hardened Tiger Lake-H host
# even after config-level mitigation -- real bare-metal CPUID (no VM exit)
# typically costs on the order of a few hundred cycles. This threshold is
# intentionally conservative and documented as a heuristic, not a hard proof.
_RDTSC_JITTER_THRESHOLD_CYCLES = 1000


def check_uptime() -> Finding:
    check_id, name = "linux.timing.low_uptime", "System uptime"
    description = (
        "Low uptime suggests the VM was booted specifically for this analysis run (PAfish-class check)."
    )
    raw = utils.read_text("/proc/uptime")
    if raw is None:
        return _f.error(check_id, name, description, Severity.LOW, "could not read /proc/uptime")
    try:
        uptime_seconds = float(raw.split()[0])
    except (ValueError, IndexError):
        return _f.error(check_id, name, description, Severity.LOW, f"unparseable /proc/uptime: {raw!r}")
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=uptime_seconds < _LOW_UPTIME_SECONDS,
        evidence=f"{uptime_seconds:.0f}s",
        remediation=f"Boot the sandbox and idle for >= {_LOW_UPTIME_SECONDS:.0f}s before detonating a sample.",
    )


def check_rdtsc_cpuid_jitter() -> Finding:
    check_id, name = "linux.timing.rdtsc_cpuid_jitter", "RDTSC-around-CPUID VM-exit timing"
    description = (
        "Times the RDTSC delta across a CPUID call (which always forces a VM exit under KVM) and "
        "compares the median cost against a bare-metal-plausible threshold."
    )
    jitter = cpu.rdtsc_cpuid_jitter(iterations=2000)
    if jitter is None:
        return _f.skipped(
            check_id,
            name,
            description,
            Severity.HIGH,
            "RDTSC/CPUID unavailable (non-x86 host or native helper failed to build)",
        )
    evidence = {
        "median_cycles": jitter.median_cycles,
        "mean_cycles": round(jitter.mean_cycles, 1),
        "min_cycles": jitter.min_cycles,
        "max_cycles": jitter.max_cycles,
        "samples": jitter.samples,
    }
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.HIGH,
        is_detected=jitter.median_cycles > _RDTSC_JITTER_THRESHOLD_CYCLES,
        evidence=evidence,
        remediation=(
            "This is the hard case (CHIMERA KVM report Section 8.2/5.5): requires host-kernel KVM "
            "TSC-handling patches, or migration to Xen+DRAKVUF. Config-level TSC pinning reduces "
            "jitter but does not remove the hardware VM-exit floor."
        ),
    )


def run_all() -> list[Finding]:
    return [check_uptime(), check_rdtsc_cpuid_jitter()]
