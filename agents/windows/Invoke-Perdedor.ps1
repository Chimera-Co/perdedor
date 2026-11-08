<#
.SYNOPSIS
    PERDEDOR Windows agent entry point. Runs the selected checks across all
    four detection categories and emits a schema-conformant JSON report.

.DESCRIPTION
    Run from PowerShell 7 inside the golden image (or let CHIMERA stage it into
    a disposable overlay). Every probes/*.ps1 file registers its checks with
    Register-PerdedorCheck; this script selects and runs them.

.PARAMETER OutputPath
    Write the JSON report there instead of stdout.
.PARAMETER Profile
    quick (fast checks only), standard (default) or deep (also slow checks:
    long timing series, interaction waits).
.PARAMETER Only
    Run only checks matching any pattern: an id glob (win.timing.*) or a
    selector (class:timing, category:design_specific, technique:cpu.*,
    cost:slow, tag:needs-admin). Naming a check here runs it even if it is
    above the profile's cost ceiling.
.PARAMETER Skip
    Never run checks matching any pattern (wins over -Only).
.PARAMETER Param
    Probe parameters as key=value (for example timing.iterations=20000).
.PARAMETER NoNetwork
    Do not run checks that send network traffic.
.PARAMETER ListChecks
    Print the selected checks as JSON and exit without running them.

.EXAMPLE
    pwsh -File .\Invoke-Perdedor.ps1 -OutputPath C:\perdedor\windows-report.json
.EXAMPLE
    pwsh -File .\Invoke-Perdedor.ps1 -Profile deep -Only 'class:timing','class:cpu'
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateSet('quick', 'standard', 'deep')][string]$Profile = 'standard',
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [string[]]$Param = @(),
    [switch]$NoNetwork,
    [switch]$ListChecks
)

$ErrorActionPreference = 'Stop'
$scriptRoot = $PSScriptRoot

# A comma-separated single argument (pwsh -File ... -Only a,b) arrives as one string.
$Only = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Skip = @($Skip | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Param = @($Param | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

Import-Module (Join-Path $scriptRoot 'common/Perdedor.Common.psm1') -Force
. (Join-Path $scriptRoot 'common/Signatures.ps1')
foreach ($probe in Get-ChildItem -LiteralPath (Join-Path $scriptRoot 'probes') -Filter '*.ps1' | Sort-Object Name) {
    . $probe.FullName
}

$params = @{}
foreach ($pair in $Param) {
    $k, $v = $pair -split '=', 2
    if (-not $k -or $null -eq $v) { throw "-Param expects key=value, got '$pair'" }
    $params[$k.Trim()] = $v.Trim()
}
Set-PerdedorContext -Profile $Profile -Params $params -Network (-not $NoNetwork)

$selected = Select-PerdedorChecks -Checks (Get-PerdedorChecks) -Profile $Profile -Only $Only -Skip $Skip -NoNetwork:$NoNetwork

if ($ListChecks) {
    $selected | ForEach-Object {
        [ordered]@{ ids = @($_.Ids); technique = $_.Technique; class = $_.Class; category = $_.Category; cost = $_.Cost; network = $_.Network; tags = @($_.Tags) }
    } | ConvertTo-Json -Depth 5 -AsArray
    exit 0
}

$findings = Invoke-PerdedorChecks -Checks $selected
$selection = [ordered]@{ profile = $Profile; only = @($Only); skip = @($Skip); params = $params; network = (-not $NoNetwork) }
$report = New-PerdedorReport -Findings $findings -Selection $selection
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
