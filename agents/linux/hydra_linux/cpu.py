"""Thin wrapper around the native cpuid_rdtsc helper.

CPUID and RDTSC are not reachable from pure Python, so this module shells
out to a tiny C binary built on first use (see agents/linux/native/). Every
public function returns None instead of raising when the primitive is
unavailable (non-x86 host, no C compiler present) -- callers turn that into
a "skipped" finding rather than crashing the whole scan over one probe.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

_NATIVE_DIR = Path(__file__).resolve().parent.parent / "native"
_BINARY = _NATIVE_DIR / "cpuid_rdtsc"
_USAGE_EXIT_CODE = 1
_NOT_APPLICABLE_EXIT_CODE = 2


def _is_runnable(binary: Path) -> bool:
    """A stale binary compiled for a different OS/arch (e.g. reused from a
    bind-mounted repo across host and container, or across containers of
    different --platform) fails at exec() rather than at runtime -- that
    must not be mistaken for a legitimate build failure and silently
    swallowed. Calling with no args should deterministically hit the usage
    error path (exit 1); anything else means the binary doesn't belong here."""
    try:
        result = subprocess.run([str(binary)], capture_output=True, timeout=5, check=False)
    except OSError:
        return False
    return result.returncode == _USAGE_EXIT_CODE


def _ensure_built() -> Path | None:
    if _BINARY.exists() and not _is_runnable(_BINARY):
        _BINARY.unlink(missing_ok=True)
    if not _BINARY.exists():
        try:
            subprocess.run(
                ["make", "-C", str(_NATIVE_DIR)],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            return None
    return _BINARY if _BINARY.exists() and _is_runnable(_BINARY) else None


def _run(*args: str) -> str | None:
    binary = _ensure_built()
    if binary is None:
        return None
    try:
        result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == _NOT_APPLICABLE_EXIT_CODE:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


@dataclass(frozen=True)
class CpuidResult:
    eax: int
    ebx: int
    ecx: int
    edx: int

    @property
    def vendor_string(self) -> str:
        """Decode ebx/ecx/edx as an ASCII vendor string for the hypervisor
        signature leaf (0x40000000). Note this register order (EBX,ECX,EDX)
        is specific to the hypervisor leaf, per the QEMU/KVM signature
        convention -- it differs from leaf 0's vendor string, which uses
        EBX,EDX,ECX. Mixing the two up is an easy, silent-wrong-answer bug."""
        raw = self.ebx.to_bytes(4, "little") + self.ecx.to_bytes(4, "little") + self.edx.to_bytes(4, "little")
        return raw.decode("ascii", errors="replace")


def cpuid(leaf: int, subleaf: int = 0) -> CpuidResult | None:
    """Query a CPUID leaf; None if CPUID is unavailable on this host."""
    out = _run("cpuid", hex(leaf), hex(subleaf))
    if out is None:
        return None
    fields = dict(part.split("=") for part in out.split())
    return CpuidResult(
        eax=int(fields["eax"], 16),
        ebx=int(fields["ebx"], 16),
        ecx=int(fields["ecx"], 16),
        edx=int(fields["edx"], 16),
    )


@dataclass(frozen=True)
class RdtscJitter:
    min_cycles: int
    median_cycles: int
    mean_cycles: float
    max_cycles: int
    samples: int


def rdtsc_cpuid_jitter(iterations: int = 2000) -> RdtscJitter | None:
    """Time `iterations` RDTSC-around-CPUID round trips; None if unavailable."""
    out = _run("rdtsc_jitter", str(iterations))
    if out is None:
        return None
    fields = dict(part.split("=") for part in out.split())
    return RdtscJitter(
        min_cycles=int(fields["min"]),
        median_cycles=int(fields["median"]),
        mean_cycles=float(fields["mean"]),
        max_cycles=int(fields["max"]),
        samples=int(fields["n"]),
    )


def brand_string() -> str | None:
    """CPU brand string from CPUID leaves 0x80000002-0x80000004 (e.g. 'QEMU
    Virtual CPU version 2.5+', 'Common KVM processor', 'Virtual CPU @ 2.6GHz'
    for Hyper-V). Unlike the hypervisor-signature leaf, this one packs ASCII
    straight across EAX,EBX,ECX,EDX in that order for each of the three
    leaves -- no register-order gotcha here. None if CPUID/leaf unsupported."""
    chunks: list[bytes] = []
    for leaf in (0x80000002, 0x80000003, 0x80000004):
        result = cpuid(leaf)
        if result is None:
            return None
        chunks.append(
            result.eax.to_bytes(4, "little")
            + result.ebx.to_bytes(4, "little")
            + result.ecx.to_bytes(4, "little")
            + result.edx.to_bytes(4, "little")
        )
    raw = b"".join(chunks)
    return raw.decode("ascii", errors="replace").rstrip("\x00").strip()


def jitter_coefficient_of_variation(deltas_summary: RdtscJitter) -> float:
    """A crude stability metric: (max-min)/median. Real hardware VM-exit
    floors are fairly stable run-to-run; heavily virtualised/emulated hosts
    tend to show wider spread. This is a heuristic signal, not a hard
    threshold -- see the 'timing' category docs in docs/ARCHITECTURE.md."""
    if deltas_summary.median_cycles == 0:
        return 0.0
    return (deltas_summary.max_cycles - deltas_summary.min_cycles) / deltas_summary.median_cycles
