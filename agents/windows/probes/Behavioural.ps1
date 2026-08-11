<#
.SYNOPSIS
    Category 3 (CHIMERA Ch.3.2.3): behavioural / interaction-based
    detection -- the Miramirkhani et al. "wear and tear" result, plus
    al-khaser's "Human Interface" section (mouse movement, font/process
    count as a proxy for a genuinely-used desktop).
#>

$Script:MinAgedFiles = 5
$Script:AgedFileThresholdDays = 7
$Script:MinInstalledPrograms = 20
$Script:MinFontCount = 100
$Script:MinRunningProcesses = 40

function Test-BrowserHistory {
    $id = 'win.behavioural.browser_history'
    $name = 'Browser history presence'
    $description = 'An absent or empty browser history profile is implausible for a machine with real usage.'
    if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status skipped -Severity low -ErrorDetail '%LOCALAPPDATA% is not set (not a Windows host)'
    }
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\History'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\History')
    )
    $found = @()
    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $size = (Get-Item -LiteralPath $path).Length
            if ($size -gt 20KB) { $found += "$path ($size bytes)" }
        }
    }
    New-HydraBoolFinding -Id $id -Category behavioural_interaction -Name $name -Description $description -Severity low `
        -IsDetected ($found.Count -eq 0) `
        -Evidence $(if ($found.Count -gt 0) { $found } else { 'no populated browser history file found' }) `
        -Remediation 'Seed the golden image with realistic browsing history before freezing it (CHIMERA forward plan: humanized user-activity simulation).'
}

function Test-AgedFiles {
    $id = 'win.behavioural.aged_files'
    $name = "Filesystem 'wear and tear' age"
    $description = 'Counts files under common user folders older than a week; an all brand-new profile is a tell.'
    if ([string]::IsNullOrEmpty($env:USERPROFILE)) {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status skipped -Severity low -ErrorDetail '%USERPROFILE% is not set (not a Windows host)'
    }
    $roots = @('Documents', 'Downloads', 'Desktop', 'Pictures') | ForEach-Object { Join-Path $env:USERPROFILE $_ }
    $threshold = (Get-Date).AddDays(-$Script:AgedFileThresholdDays)
    $aged = 0
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            $aged += @(Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $threshold }).Count
        }
        catch { continue }
        if ($aged -ge $Script:MinAgedFiles) { break }
    }
    $evidence = if ($aged -lt $Script:MinAgedFiles) { "$aged files older than $($Script:AgedFileThresholdDays) days" } else { ">= $aged files older than $($Script:AgedFileThresholdDays) days" }
    New-HydraBoolFinding -Id $id -Category behavioural_interaction -Name $name -Description $description -Severity low `
        -IsDetected ($aged -lt $Script:MinAgedFiles) -Evidence $evidence `
        -Remediation 'Populate the golden image with realistic aged documents/downloads before freezing it.'
}

function Test-InstalledPrograms {
    $id = 'win.behavioural.installed_programs'
    $name = 'Installed program count'
    $description = 'A machine with very few installed programs beyond the OS default set looks freshly provisioned.'
    if (-not (Test-Path -LiteralPath 'HKLM:\')) {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status skipped -Severity low -ErrorDetail 'HKLM: registry drive is not available on this platform'
    }
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    try {
        $count = @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName }).Count
    }
    catch {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status error -Severity low -ErrorDetail "registry query failed: $($_.Exception.Message)"
    }
    New-HydraBoolFinding -Id $id -Category behavioural_interaction -Name $name -Description $description -Severity low `
        -IsDetected ($count -lt $Script:MinInstalledPrograms) -Evidence "$count programs" `
        -Remediation 'Install a realistic mix of everyday software (browsers, office tools, media players) on the golden image.'
}

function Test-FontCount {
    $id = 'win.behavioural.font_count'
    $name = 'Installed font count'
    $description = "A machine with fewer than $($Script:MinFontCount) fonts installed looks like a minimal provisioning rather than a real desktop (al-khaser's font-enumeration check)."
    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $collection = New-Object System.Drawing.Text.InstalledFontCollection
        $count = $collection.Families.Count
    }
    catch {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status skipped -Severity info -ErrorDetail "System.Drawing font enumeration unavailable: $($_.Exception.Message)"
    }
    New-HydraBoolFinding -Id $id -Category behavioural_interaction -Name $name -Description $description -Severity info `
        -IsDetected ($count -lt $Script:MinFontCount) -Evidence "$count fonts" `
        -Remediation 'Install a normal desktop font set (or leave default Windows fonts intact) on the golden image.'
}

function Test-RunningProcessCount {
    $id = 'win.behavioural.running_process_count'
    $name = 'Running process count'
    $description = "A machine running fewer than $($Script:MinRunningProcesses) processes looks like a minimal sandbox rather than a real desktop session."
    try {
        $count = @(Get-Process -ErrorAction Stop).Count
    }
    catch {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status error -Severity info -ErrorDetail "Get-Process failed: $($_.Exception.Message)"
    }
    New-HydraBoolFinding -Id $id -Category behavioural_interaction -Name $name -Description $description -Severity info `
        -IsDetected ($count -lt $Script:MinRunningProcesses) -Evidence "$count processes" `
        -Remediation 'A minimal process list is expected right after boot; re-run this check after normal desktop session startup.'
}

function Test-MouseMovement {
    $id = 'win.behavioural.mouse_movement'
    $name = 'Mouse cursor movement (al-khaser Human Interface check)'
    $description = 'Samples the cursor position twice with a short delay; an identical position both times suggests no human is present (or a sandbox that does not simulate input).'
    if (-not ('Hydra.Mouse' -as [type])) {
        # A custom POINT struct, not System.Drawing.Point: on modern .NET,
        # System.Drawing.Point is type-forwarded to System.Drawing.Primitives,
        # which Add-Type's default reference set does not pull in -- this
        # failed to even compile until switched to the plain P/Invoke idiom.
        Add-Type -Namespace Hydra -Name Mouse -MemberDefinition @'
public struct POINT { public int X; public int Y; }

[DllImport("user32.dll")]
public static extern bool GetCursorPos(out POINT lpPoint);
'@
    }
    try {
        $p1 = New-Object Hydra.Mouse+POINT
        [void][Hydra.Mouse]::GetCursorPos([ref]$p1)
        Start-Sleep -Milliseconds 300
        $p2 = New-Object Hydra.Mouse+POINT
        [void][Hydra.Mouse]::GetCursorPos([ref]$p2)
    }
    catch {
        return New-HydraFinding -Id $id -Category behavioural_interaction -Name $name -Description $description `
            -Status skipped -Severity low -ErrorDetail "GetCursorPos unavailable on this platform: $($_.Exception.Message)"
    }
    $unchanged = ($p1.X -eq $p2.X) -and ($p1.Y -eq $p2.Y)
    New-HydraBoolFinding -Id $id -Category behavioural_interaction -Name $name -Description $description -Severity low `
        -IsDetected $unchanged -Evidence "($($p1.X),$($p1.Y)) -> ($($p2.X),$($p2.Y))" `
        -Remediation 'This single sample is a weak signal on its own (a real user can be briefly idle); use CHIMERA forward-plan human-interaction simulation for the real mitigation.'
}

function Invoke-BehaviouralChecks {
    @(
        Test-BrowserHistory
        Test-AgedFiles
        Test-InstalledPrograms
        Test-FontCount
        Test-RunningProcessCount
        Test-MouseMovement
    )
}
