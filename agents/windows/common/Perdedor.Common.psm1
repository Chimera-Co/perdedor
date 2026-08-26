<#
.SYNOPSIS
    Shared helpers for the PERDEDOR Windows agent: finding construction,
    severity-weighted scoring, and report assembly.

    Mirrors common/python/perdedor_common exactly (same fields, same severity
    weights, same scoring formula) so a Windows-produced report and a
    Linux/Android-produced report are byte-for-byte comparable once
    aggregated -- see docs/ARCHITECTURE.md, "one suite, three platforms".
#>

$Script:SeverityWeight = @{
    info     = 0.05
    low      = 0.15
    medium   = 0.35
    high     = 0.65
    critical = 1.0
}

function New-PerdedorFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('environment_artifact', 'timing', 'behavioural_interaction', 'design_specific')][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][ValidateSet('clean', 'detected', 'error', 'skipped')][string]$Status,
        [Parameter(Mandatory)][ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity,
        $Evidence = $null,
        # Deliberately untyped ($null, not [string]): a typed [string] parameter
        # coerces an omitted/$null argument to "" in PowerShell, which would
        # silently drift from the schema's `null` for an absent remediation/
        # error_detail rather than round-tripping it faithfully.
        $Remediation = $null,
        $ErrorDetail = $null
    )
    if ($Status -eq 'error' -and [string]::IsNullOrEmpty($ErrorDetail)) {
        throw "New-PerdedorFinding: status 'error' requires -ErrorDetail (check id: $Id)"
    }
    [PSCustomObject]@{
        id            = $Id
        category      = $Category
        platform      = 'windows'
        name          = $Name
        description   = $Description
        status        = $Status
        severity      = $Severity
        evidence      = $Evidence
        remediation   = $Remediation
        error_detail  = $ErrorDetail
    }
}

function Get-PerdedorSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings)

    $total = $Findings.Count
    $clean = @($Findings | Where-Object { $_.status -eq 'clean' }).Count
    $detected = @($Findings | Where-Object { $_.status -eq 'detected' }).Count
    $errored = @($Findings | Where-Object { $_.status -eq 'error' }).Count
    $skipped = @($Findings | Where-Object { $_.status -eq 'skipped' }).Count
    $applicable = $clean + $detected

    $rawScore = if ($applicable -gt 0) { "$clean/$applicable" } else { '0/0' }

    if ($applicable -eq 0) {
        $weighted = 100.0
    }
    else {
        $penalty = 0.0
        foreach ($finding in $Findings) {
            if ($finding.status -eq 'detected') {
                $penalty += $Script:SeverityWeight[$finding.severity]
            }
        }
        $weighted = [Math]::Max(0.0, 100.0 * (1.0 - $penalty / $applicable))
    }

    [PSCustomObject]@{
        total          = $total
        clean          = $clean
        detected       = $detected
        errored        = $errored
        skipped        = $skipped
        raw_score      = $rawScore
        weighted_score = [Math]::Round($weighted, 2)
    }
}

function New-PerdedorReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings,
        [string]$PerdedorVersion = '0.1.0'
    )

    $osVersion = try { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { [System.Environment]::OSVersion.VersionString }

    [PSCustomObject]@{
        perdedor_version  = $PerdedorVersion
        platform       = 'windows'
        hostname       = [System.Environment]::MachineName
        generated_at   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        agent_metadata = [PSCustomObject]@{
            os      = 'Windows'
            os_name = $osVersion
            machine = [System.Environment]::MachineName
        }
        findings       = @($Findings)
        summary        = Get-PerdedorSummary -Findings $Findings
    }
}

function New-PerdedorBoolFinding {
    <#
    .SYNOPSIS
        Convenience for the common "detected if condition else clean" shape
        -- mirrors perdedor_common.FindingFactory.bool_check on the Python side.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('environment_artifact', 'timing', 'behavioural_interaction', 'design_specific')][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][ValidateSet('info', 'low', 'medium', 'high', 'critical')][string]$Severity,
        [Parameter(Mandatory)][bool]$IsDetected,
        $Evidence = $null,
        $Remediation = $null
    )
    $status = if ($IsDetected) { 'detected' } else { 'clean' }
    $effectiveRemediation = if ($IsDetected) { $Remediation } else { $null }
    New-PerdedorFinding -Id $Id -Category $Category -Name $Name -Description $Description `
        -Status $status -Severity $Severity -Evidence $Evidence -Remediation $effectiveRemediation
}

function Find-PerdedorSignature {
    <#
    .SYNOPSIS
        Case-insensitive substring search; returns the matched signature or
        $null. Mirrors perdedor_linux.utils.any_signature_in.
    #>
    [CmdletBinding()]
    param([string]$Text, [Parameter(Mandatory)][array]$Signatures)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    foreach ($signature in $Signatures) {
        if ($Text.ToLowerInvariant().Contains($signature.ToLowerInvariant())) {
            return $signature
        }
    }
    return $null
}

Export-ModuleMember -Function New-PerdedorFinding, New-PerdedorBoolFinding, Get-PerdedorSummary, New-PerdedorReport, Find-PerdedorSignature
