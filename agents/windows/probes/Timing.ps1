<#
.SYNOPSIS
    Category 2 (CHIMERA Ch.3.2.2): timing-based detection.

    Note on fidelity: .NET does not expose an RDTSC intrinsic (only
    X86Base/SSE/AVX/etc.), so the jitter check here uses
    System.Diagnostics.Stopwatch (QueryPerformanceCounter under the hood)
    around a forced-VM-exit CPUID call rather than raw TSC cycle counts.
    This is the same class of measurement as PAfish's own GetTickCount/QPC
    checks, just coarser than a true RDTSC delta -- documented honestly
    rather than claiming cycle-accurate timing PERDEDOR does not actually do.
    A native RDTSC helper (mirroring agents/linux/native/cpuid_rdtsc.c) is
    the natural upgrade path if cycle-accurate measurement is needed later.
#>

$Script:LowUptimeSeconds = 600.0
$Script:JitterThresholdTicks = 20000  # heuristic; Stopwatch.Frequency ticks, not TSC cycles

function Test-Uptime {
    $id = 'win.timing.low_uptime'
    $name = 'System uptime'
    $description = 'Low uptime suggests the VM was booted specifically for this analysis run (PAfish-class GetTickCount check).'
    $uptimeSeconds = [System.Environment]::TickCount64 / 1000.0
    New-PerdedorBoolFinding -Id $id -Category timing -Name $name -Description $description -Severity low `
        -IsDetected ($uptimeSeconds -lt $Script:LowUptimeSeconds) -Evidence "$([Math]::Round($uptimeSeconds))s" `
        -Remediation "Boot the sandbox and idle for >= $($Script:LowUptimeSeconds)s before detonating a sample."
}

function Test-TimingJitter {
    $id = 'win.timing.cpuid_qpc_jitter'
    $name = 'QPC-around-CPUID VM-exit timing (heuristic)'
    $description = 'Times a high-resolution stopwatch across repeated CPUID calls (which always force a VM exit under KVM) and checks for elevated, unstable overhead. Heuristic approximation of RDTSC-class timing -- see script header.'
    if (-not [System.Runtime.Intrinsics.X86.X86Base]::IsSupported) {
        return New-PerdedorFinding -Id $id -Category timing -Name $name -Description $description `
            -Status skipped -Severity high -ErrorDetail 'X86Base CPUID intrinsic unsupported on this CLR/architecture'
    }

    $iterations = 2000
    $deltas = [System.Collections.Generic.List[double]]::new()
    $sw = [System.Diagnostics.Stopwatch]::new()
    for ($i = 0; $i -lt $iterations; $i++) {
        $sw.Restart()
        [void][System.Runtime.Intrinsics.X86.X86Base]::CpuId(0, 0)
        $sw.Stop()
        $deltas.Add([double]$sw.ElapsedTicks)
    }
    $sorted = $deltas | Sort-Object
    $median = $sorted[[int]($sorted.Count / 2)]
    $mean = ($sorted | Measure-Object -Average).Average
    $min = $sorted[0]
    $max = $sorted[$sorted.Count - 1]
    $evidence = [PSCustomObject]@{
        median_ticks = $median
        mean_ticks   = [Math]::Round($mean, 2)
        min_ticks    = $min
        max_ticks    = $max
        samples      = $iterations
        note         = 'ticks are Stopwatch/QPC ticks, not raw TSC cycles'
    }

    New-PerdedorBoolFinding -Id $id -Category timing -Name $name -Description $description -Severity high `
        -IsDetected ($median -gt $Script:JitterThresholdTicks) -Evidence $evidence `
        -Remediation 'Requires host-kernel KVM TSC-handling patches or migration to Xen+DRAKVUF; config-level TSC pinning reduces jitter but not the hardware VM-exit floor (CHIMERA KVM report Section 8.2/5.5).'
}

function Invoke-TimingChecks {
    @(
        Test-Uptime
        Test-TimingJitter
    )
}
