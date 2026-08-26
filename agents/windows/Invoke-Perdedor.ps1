<#
.SYNOPSIS
    PERDEDOR Windows agent entry point. Runs every check across all four
    detection categories and emits a schema-conformant JSON report.

.DESCRIPTION
    Run from an elevated PowerShell 7 prompt inside the golden image (not
    the disposable overlay -- verification should happen on the image that
    gets frozen, so a clean result actually describes what ships).

.PARAMETER OutputPath
    If given, write the JSON report there instead of stdout.

.EXAMPLE
    pwsh -File .\Invoke-Perdedor.ps1 -OutputPath C:\perdedor\windows-report.json
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

Import-Module (Join-Path $scriptRoot 'common/Perdedor.Common.psm1') -Force
. (Join-Path $scriptRoot 'common/Signatures.ps1')
. (Join-Path $scriptRoot 'probes/Environment.ps1')
. (Join-Path $scriptRoot 'probes/Timing.ps1')
. (Join-Path $scriptRoot 'probes/Behavioural.ps1')
. (Join-Path $scriptRoot 'probes/Design.ps1')

$findings = @()
$findings += Invoke-EnvironmentChecks
$findings += Invoke-TimingChecks
$findings += Invoke-BehaviouralChecks
$findings += Invoke-DesignChecks

$report = New-PerdedorReport -Findings $findings
$json = $report | ConvertTo-Json -Depth 10

# Status/summary lines go to stderr so stdout stays pure JSON when no
# -OutputPath is given (mirrors agents/linux/perdedor_linux/__main__.py) --
# a caller piping stdout straight into a JSON parser must never see them.
if ($OutputPath) {
    $json | Out-File -FilePath $OutputPath -Encoding utf8
    [Console]::Error.WriteLine("Wrote report to $OutputPath")
}
else {
    Write-Output $json
}

$s = $report.summary
[Console]::Error.WriteLine("PERDEDOR windows scan: $($s.raw_score) clean, weighted $($s.weighted_score)/100 ($($s.errored) errored, $($s.skipped) skipped)")
