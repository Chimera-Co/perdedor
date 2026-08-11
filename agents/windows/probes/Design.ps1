<#
.SYNOPSIS
    Category 4 (CHIMERA Ch.3.2.4): design-choice / platform-specific
    detection -- quirks of a particular analysis platform rather than
    virtualisation in general. Covers al-khaser's "Analysis Tools",
    "Generic sandbox" window-class/DLL checks, and a representative subset
    of its "Debugger Detection" section (see docs/CHECK_COVERAGE.md for
    which deeper anti-debug tricks -- hardware breakpoints, PEB flags,
    timing-based single-step detection -- are explicitly out of scope).
#>

if (-not ('Hydra.Debug' -as [type])) {
    Add-Type -Namespace Hydra -Name Debug -MemberDefinition @'
[DllImport("kernel32.dll")]
public static extern bool IsDebuggerPresent();

[DllImport("kernel32.dll")]
public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

[DllImport("kernel32.dll")]
public static extern IntPtr GetCurrentProcess();
'@
}

if (-not ('Hydra.Window' -as [type])) {
    Add-Type -Namespace Hydra -Name Window -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
'@
}

function Test-AnalysisToolsRunning {
    $id = 'win.design.analysis_tools_running'
    $name = 'Malware-analysis tooling running'
    $description = 'Checks the process list for debuggers/sniffers/analysis suites whose presence alone signals analysis.'
    try {
        $running = @(Get-Process -ErrorAction Stop | Select-Object -ExpandProperty ProcessName) | ForEach-Object { $_.ToLowerInvariant() }
    }
    catch {
        return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
            -Status error -Severity medium -ErrorDetail "Get-Process failed: $($_.Exception.Message)"
    }
    $hits = @($Script:AnalysisToolProcessNames | Where-Object { $running -contains $_ })
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity medium `
        -IsDetected ($hits.Count -gt 0) -Evidence $hits `
        -Remediation 'Run analysis tooling out-of-guest (host-side memory acquisition) instead of inside the detonation VM.'
}

function Test-SuspiciousHostnameOrUser {
    $id = 'win.design.suspicious_hostname_or_user'
    $name = 'Hostname/username plausibility (substring)'
    $description = "Hostnames/usernames like 'sandbox' or 'malware' are an easy, high-confidence tell malware checks for."
    $hostname = [System.Environment]::MachineName
    $username = [System.Environment]::UserName
    $hits = @()
    if (Find-HydraSignature -Text $hostname -Signatures $Script:SuspiciousNameTokens) { $hits += "hostname='$hostname'" }
    if (Find-HydraSignature -Text $username -Signatures $Script:SuspiciousNameTokens) { $hits += "user='$username'" }
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity low `
        -IsDetected ($hits.Count -gt 0) -Evidence $(if ($hits.Count -gt 0) { $hits } else { "hostname='$hostname' user='$username'" }) `
        -Remediation 'Rename the golden image hostname/user account to a plausible everyday identity (per CHIMERA build guide: OOBE-pattern computer name, full-name user account).'
}

function Test-ExactSandboxUsername {
    $id = 'win.design.exact_sandbox_username'
    $name = 'Username exact-match blacklist (al-khaser style)'
    $description = "al-khaser checks the current username against an exact-match blacklist (e.g. 'test', 'sandbox', 'john doe') rather than a substring -- short names like 'test' would false-positive under substring matching."
    $username = [System.Environment]::UserName.ToLowerInvariant()
    $matched = $Script:SandboxUsernameExact -contains $username
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity low `
        -IsDetected $matched -Evidence "user='$username'" `
        -Remediation "Use a plausible full-name-style user account (e.g. the CHIMERA build guide's 'Arjun Mehta' convention), never a generic/test-sounding name."
}

function Test-MacOui {
    $id = 'win.design.mac_oui'
    $name = 'NIC MAC address OUI'
    $description = "Compares each adapter's MAC OUI against well-known virtual-NIC vendor prefixes."
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop
    }
    catch {
        return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
            -Status error -Severity medium -ErrorDetail "CIM query failed: $($_.Exception.Message)"
    }
    $hits = @()
    foreach ($adapter in $adapters) {
        if (-not $adapter.MACAddress) { continue }
        $oui = $adapter.MACAddress.Substring(0, 8).ToUpperInvariant()
        if ($Script:MacOuiSignatures.ContainsKey($oui)) {
            $hits += "$($adapter.Description)=$($adapter.MACAddress) ($($Script:MacOuiSignatures[$oui]))"
        }
    }
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity medium `
        -IsDetected ($hits.Count -gt 0) -Evidence $hits `
        -Remediation 'Assign a MAC address consistent with the spoofed hardware vendor (e.g. an ASUS-registered OUI).'
}

function Test-BlacklistedDlls {
    $id = 'win.design.blacklisted_dlls'
    $name = 'Blacklisted DLLs loaded in current process'
    $description = "Checks the running PowerShell process's loaded modules for hypervisor guest-hook/sandbox API-hooking DLLs (VirtualBox's vboxhook.dll, Sandboxie's sbiedll.dll, and similar)."
    try {
        $loaded = @(Get-Process -Id $PID -ErrorAction Stop).Modules | ForEach-Object { $_.ModuleName.ToLowerInvariant() }
    }
    catch {
        return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
            -Status error -Severity medium -ErrorDetail "could not enumerate process modules: $($_.Exception.Message)"
    }
    $hits = @($Script:BlacklistedDllNames | Where-Object { $loaded -contains $_ })
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity medium `
        -IsDetected ($hits.Count -gt 0) -Evidence $hits `
        -Remediation 'Uninstall the guest-integration/sandbox tooling responsible for injecting the listed DLL.'
}

function Test-WindowClassArtifacts {
    $id = 'win.design.window_class_artifacts'
    $name = 'Hypervisor guest-tool window classes'
    $description = "Uses FindWindow to look for tray-tool window classes created by VirtualBox/VMware guest tools (al-khaser's window-class detection technique)."
    $hits = @()
    foreach ($className in $Script:VmWindowClassNames) {
        try {
            $handle = [Hydra.Window]::FindWindow($className, $null)
            if ($handle -ne [IntPtr]::Zero) { $hits += $className }
        }
        catch {
            return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
                -Status skipped -Severity medium -ErrorDetail "FindWindow unavailable on this platform: $($_.Exception.Message)"
        }
    }
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity medium `
        -IsDetected ($hits.Count -gt 0) -Evidence $hits `
        -Remediation 'Disable/uninstall the guest-tool tray application responsible for the listed window class.'
}

function Test-DebuggerPresent {
    $id = 'win.design.debugger_present'
    $name = 'IsDebuggerPresent (al-khaser Debugger Detection)'
    $description = 'Kernel32 IsDebuggerPresent -- the most basic and most commonly checked anti-debug primitive.'
    try {
        $present = [Hydra.Debug]::IsDebuggerPresent()
    }
    catch {
        return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
            -Status skipped -Severity high -ErrorDetail "IsDebuggerPresent unavailable on this platform: $($_.Exception.Message)"
    }
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity high `
        -IsDetected $present -Evidence "IsDebuggerPresent()=$present" `
        -Remediation 'Detach any attached debugger before running the sample; a debugger present during detonation invalidates results the same way an evasion-aware sample would react to it.'
}

function Test-RemoteDebuggerPresent {
    $id = 'win.design.remote_debugger_present'
    $name = 'CheckRemoteDebuggerPresent (al-khaser Debugger Detection)'
    $description = 'Kernel32 CheckRemoteDebuggerPresent against the current process -- catches debuggers attached out-of-process.'
    try {
        $handle = [Hydra.Debug]::GetCurrentProcess()
        $isPresent = $false
        $result = [Hydra.Debug]::CheckRemoteDebuggerPresent($handle, [ref]$isPresent)
    }
    catch {
        return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
            -Status skipped -Severity high -ErrorDetail "CheckRemoteDebuggerPresent unavailable on this platform: $($_.Exception.Message)"
    }
    if (-not $result) {
        return New-HydraFinding -Id $id -Category design_specific -Name $name -Description $description `
            -Status error -Severity high -ErrorDetail 'CheckRemoteDebuggerPresent returned failure'
    }
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity high `
        -IsDetected $isPresent -Evidence "CheckRemoteDebuggerPresent()=$isPresent" `
        -Remediation 'Detach any attached debugger before running the sample.'
}

function Test-ManagedDebuggerAttached {
    $id = 'win.design.managed_debugger_attached'
    $name = '.NET Debugger.IsAttached'
    $description = 'Checks whether a managed (.NET) debugger is attached to this PowerShell host process.'
    $attached = [System.Diagnostics.Debugger]::IsAttached
    New-HydraBoolFinding -Id $id -Category design_specific -Name $name -Description $description -Severity medium `
        -IsDetected $attached -Evidence "Debugger.IsAttached=$attached" `
        -Remediation 'Detach any attached managed debugger before running the sample.'
}

function Invoke-DesignChecks {
    @(
        Test-AnalysisToolsRunning
        Test-SuspiciousHostnameOrUser
        Test-ExactSandboxUsername
        Test-MacOui
        Test-BlacklistedDlls
        Test-WindowClassArtifacts
        Test-DebuggerPresent
        Test-RemoteDebuggerPresent
        Test-ManagedDebuggerAttached
    )
}
