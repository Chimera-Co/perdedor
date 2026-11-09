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
        [string]$PerdedorVersion = '2.0.1',
        $Selection = $null
    )

    $osVersion = try { (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { [System.Environment]::OSVersion.VersionString }

    $report = [ordered]@{
        schema_version   = 2
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
    if ($null -ne $Selection) { $report['selection'] = $Selection }
    [PSCustomObject]$report
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

# ---------------------------------------------------------------------------
# Check registry and selection. Mirrors common/python/perdedor_common/registry.py:
# same profiles, same cost ceiling, same pattern syntax (glob on id, or
# class:/category:/technique:/cost:/tag:/id: selectors), same precedence
# (--Only overrides the profile's cost ceiling; -Skip and -NoNetwork always win).
# ---------------------------------------------------------------------------

$Script:PerdedorChecks = [System.Collections.Generic.List[object]]::new()
$Script:PerdedorCosts = @('fast', 'medium', 'slow')
$Script:PerdedorProfiles = @{ quick = 'fast'; standard = 'medium'; deep = 'slow' }
$Script:PerdedorContext = @{ Profile = 'standard'; Params = @{}; Network = $true }
$Script:PerdedorClassCategory = @{
    cpu = 'environment_artifact'; firmware = 'environment_artifact'; hardware = 'environment_artifact'
    resources = 'environment_artifact'; guest_tools = 'environment_artifact'; artifacts = 'environment_artifact'
    container = 'environment_artifact'; emulator = 'environment_artifact'; mobile_device = 'environment_artifact'
    timing = 'timing'; human = 'behavioural_interaction'; wear_and_tear = 'behavioural_interaction'
    identity = 'design_specific'; analysis_tools = 'design_specific'; debugger = 'design_specific'
    instrumentation = 'design_specific'; network = 'design_specific'; os_config = 'design_specific'
    integrity = 'design_specific'
}

function Register-PerdedorCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Ids,
        [Parameter(Mandatory)][string]$Technique,
        [Parameter(Mandatory)][scriptblock]$Run,
        [ValidateSet('fast', 'medium', 'slow')][string]$Cost = 'fast',
        [switch]$Network,
        [string[]]$Tags = @()
    )
    $class = $Technique.Split('.')[0]
    if (-not $Script:PerdedorClassCategory.ContainsKey($class)) {
        throw "Register-PerdedorCheck: unknown class '$class' for $($Ids[0])"
    }
    foreach ($existing in $Script:PerdedorChecks) {
        foreach ($i in $Ids) { if ($existing.Ids -contains $i) { throw "check id $i registered twice" } }
    }
    $Script:PerdedorChecks.Add([PSCustomObject]@{
            Ids       = $Ids
            Technique = $Technique
            Class     = $class
            Category  = $Script:PerdedorClassCategory[$class]
            Cost      = $Cost
            Network   = [bool]$Network
            Tags      = $Tags
            Run       = $Run
        })
}

function Get-PerdedorChecks { , $Script:PerdedorChecks.ToArray() }

function Test-PerdedorPattern {
    param([string]$Pattern, $Check)
    $idx = $Pattern.IndexOf(':')
    if ($idx -lt 0) {
        foreach ($i in $Check.Ids) { if ($i -clike $Pattern) { return $true } }
        return $false
    }
    $kind = $Pattern.Substring(0, $idx); $value = $Pattern.Substring($idx + 1).Trim()
    switch ($kind) {
        'class' { return $Check.Class -clike $value }
        'category' { return $Check.Category -clike $value }
        'technique' { return $Check.Technique -clike $value }
        'cost' { return $Check.Cost -ceq $value }
        'tag' { return $Check.Tags -contains $value }
        'id' { foreach ($i in $Check.Ids) { if ($i -clike $value) { return $true } }; return $false }
        default { throw "unknown selector '${kind}:' in pattern '$Pattern'" }
    }
}

function Select-PerdedorChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Checks,
        [ValidateSet('quick', 'standard', 'deep')][string]$Profile = 'standard',
        [string[]]$Only = @(),
        [string[]]$Skip = @(),
        [switch]$NoNetwork
    )
    $ceiling = [array]::IndexOf($Script:PerdedorCosts, $Script:PerdedorProfiles[$Profile])
    $chosen = @()
    foreach ($check in $Checks) {
        $explicit = $false
        if ($Only.Count -gt 0) {
            foreach ($p in $Only) { if (Test-PerdedorPattern -Pattern $p -Check $check) { $explicit = $true; break } }
            if (-not $explicit) { continue }
        }
        if (-not $explicit -and [array]::IndexOf($Script:PerdedorCosts, $check.Cost) -gt $ceiling) { continue }
        $skipped = $false
        foreach ($p in $Skip) { if (Test-PerdedorPattern -Pattern $p -Check $check) { $skipped = $true; break } }
        if ($skipped) { continue }
        if ($check.Network -and $NoNetwork) { continue }
        $chosen += $check
    }
    , $chosen
}

function Set-PerdedorContext {
    param([string]$Profile = 'standard', [hashtable]$Params = @{}, [bool]$Network = $true)
    $Script:PerdedorContext = @{ Profile = $Profile; Params = $Params; Network = $Network }
}

function Get-PerdedorContext { $Script:PerdedorContext }

function Get-PerdedorParam {
    <# Operator override (-Param key=value) for a probe parameter, cast to the default's type. #>
    param([Parameter(Mandatory)][string]$Key, $Default)
    $params = $Script:PerdedorContext.Params
    if (-not $params.ContainsKey($Key)) { return $Default }
    $raw = [string]$params[$Key]
    if ($null -eq $Default) { return $raw }
    try {
        if ($Default -is [bool]) { return @('1', 'true', 'yes', 'on') -contains $raw.ToLowerInvariant() }
        return [System.Management.Automation.LanguagePrimitives]::ConvertTo($raw, $Default.GetType())
    }
    catch { return $Default }
}

function Invoke-PerdedorChecks {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Checks)
    $findings = @()
    foreach ($check in $Checks) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $produced = @(& $check.Run)
        }
        catch {
            $produced = @(New-PerdedorFinding -Id $check.Ids[0] -Category $check.Category -Name $check.Ids[0] `
                    -Description 'Probe raised before producing a result.' -Status error -Severity info `
                    -ErrorDetail "$($_.Exception.GetType().Name): $($_.Exception.Message)")
        }
        $sw.Stop()
        $share = [Math]::Round($sw.Elapsed.TotalMilliseconds / [Math]::Max(1, $produced.Count), 2)
        foreach ($f in $produced) {
            if ($null -eq $f) { continue }
            if (-not $f.PSObject.Properties['technique']) { $f | Add-Member -NotePropertyName technique -NotePropertyValue $check.Technique }
            if (-not $f.PSObject.Properties['class']) { $f | Add-Member -NotePropertyName class -NotePropertyValue $check.Class }
            if (-not $f.PSObject.Properties['duration_ms']) { $f | Add-Member -NotePropertyName duration_ms -NotePropertyValue $share }
            $findings += $f
        }
    }
    , $findings
}

Export-ModuleMember -Function New-PerdedorFinding, New-PerdedorBoolFinding, Get-PerdedorSummary, New-PerdedorReport, Find-PerdedorSignature, Register-PerdedorCheck, Get-PerdedorChecks, Select-PerdedorChecks, Test-PerdedorPattern, Set-PerdedorContext, Get-PerdedorContext, Get-PerdedorParam, Invoke-PerdedorChecks
