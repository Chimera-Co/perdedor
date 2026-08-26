<#
.SYNOPSIS
    Category 1 (CHIMERA Ch.3.2.1): hardware/firmware/driver signatures.
    Dot-source this after importing Perdedor.Common.psm1 and Signatures.ps1.

    Covers Pafish's QEMU/VirtualBox/VMware artifact checks, al-khaser's
    "Generic sandbox/VM" + per-hypervisor registry/file sections, and
    VMAware's CPUID/DMI/PCI/MAC/raw-firmware-table technique classes -- see
    docs/CHECK_COVERAGE.md for the full mapping.
#>

$Script:LowCoreCountThreshold = 2
$Script:LowRamGbThreshold = 4
$Script:SmallDiskGbThreshold = 60

# P/Invoke for GetSystemFirmwareTable -- lets us read the *raw* SMBIOS/ACPI
# tables the way VMAware does, which catches vendor strings that survive
# WMI/CIM-level spoofing because they're baked into the firmware table
# itself rather than the higher-level provider that WMI reads from.
if (-not ('Perdedor.Firmware' -as [type])) {
    Add-Type -Namespace Perdedor -Name Firmware -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern uint GetSystemFirmwareTable(uint FirmwareTableProviderSignature, uint FirmwareTableID, byte[] pFirmwareTableBuffer, uint BufferSize);
'@
}

function ConvertTo-PerdedorFirmwareSignature {
    param([Parameter(Mandatory)][string]$Text)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Text.PadRight(4).Substring(0, 4))
    return [uint32]($bytes[0] -bor ($bytes[1] -shl 8) -bor ($bytes[2] -shl 16) -bor ($bytes[3] -shl 24))
}

function Get-PerdedorFirmwareTableBytes {
    param([Parameter(Mandatory)][string]$Provider, [string]$TableId = '')
    try {
        $providerSig = ConvertTo-PerdedorFirmwareSignature -Text $Provider
        $tableSig = if ($TableId) { ConvertTo-PerdedorFirmwareSignature -Text $TableId } else { [uint32]0 }
        $size = [Perdedor.Firmware]::GetSystemFirmwareTable($providerSig, $tableSig, $null, 0)
        if ($size -eq 0) { return $null }
        $buffer = New-Object byte[] $size
        $written = [Perdedor.Firmware]::GetSystemFirmwareTable($providerSig, $tableSig, $buffer, $size)
        if ($written -eq 0) { return $null }
        return $buffer
    }
    catch {
        return $null
    }
}

function Test-SmbiosVendor {
    $id = 'win.env.smbios_vendor'
    $name = 'SMBIOS/Win32_ComputerSystem + Win32_BIOS vendor strings'
    $description = 'Manufacturer/Model/BIOS strings checked against known hypervisor vendor names.'
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    }
    catch {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status error -Severity high -ErrorDetail "CIM query failed: $($_.Exception.Message)"
    }

    $candidates = @($cs.Manufacturer, $cs.Model, $bios.Manufacturer, $bios.Version, $bios.SerialNumber)
    $hit = $null
    foreach ($candidate in $candidates) {
        $match = Find-PerdedorSignature -Text $candidate -Signatures $Script:DmiVendorSignatures
        if ($match) { $hit = "$candidate (matched '$match')"; break }
    }
    $evidence = "CS.Manufacturer=$($cs.Manufacturer) CS.Model=$($cs.Model) BIOS.Manufacturer=$($bios.Manufacturer) BIOS.Version=$($bios.Version)"
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ([bool]$hit) -Evidence $evidence `
        -Remediation 'Override SMBIOS via libvirt <sysinfo> (or -smbios flags) to a real vendor identity.'
}

function Test-CpuidHypervisorBit {
    $id = 'win.env.cpuid_hypervisor_bit'
    $name = 'CPUID hypervisor-present bit'
    $description = 'CPUID leaf 1, ECX bit 31 -- set by every mainstream hypervisor to advertise itself to the guest.'
    if (-not [System.Runtime.Intrinsics.X86.X86Base]::IsSupported) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity critical -ErrorDetail 'X86Base CPUID intrinsic unsupported on this CLR/architecture'
    }
    $r = [System.Runtime.Intrinsics.X86.X86Base]::CpuId(1, 0)
    $present = ($r.Ecx -band (1 -shl 31)) -ne 0
    $evidence = "ecx=0x{0:x8} bit31={1}" -f $r.Ecx, $(if ($present) { '1' } else { '0' })
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity critical `
        -IsDetected $present -Evidence $evidence `
        -Remediation "Set <kvm><hidden state='on'/></kvm> in the libvirt domain XML."
}

function Test-CpuidHypervisorVendor {
    $id = 'win.env.cpuid_hypervisor_vendor'
    $name = 'CPUID hypervisor vendor string'
    $description = "CPUID leaf 0x40000000 -- the hypervisor vendor ID string (e.g. 'KVMKVMKVM')."
    if (-not [System.Runtime.Intrinsics.X86.X86Base]::IsSupported) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity critical -ErrorDetail 'X86Base CPUID intrinsic unsupported on this CLR/architecture'
    }
    $r = [System.Runtime.Intrinsics.X86.X86Base]::CpuId(0x40000000, 0)
    # EBX,ECX,EDX order per the QEMU/KVM hypervisor-signature convention
    # (leaf 0's own vendor string instead uses EBX,EDX,ECX -- easy to
    # transpose and get a silent wrong answer; see the Linux agent's
    # regression test for the same bug).
    $bytes = [BitConverter]::GetBytes([int32]$r.Ebx) + [BitConverter]::GetBytes([int32]$r.Ecx) + [BitConverter]::GetBytes([int32]$r.Edx)
    $vendorString = [System.Text.Encoding]::ASCII.GetString($bytes)
    $known = $Script:CpuidHypervisorVendors[$vendorString]
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity critical `
        -IsDetected ([bool]$known) -Evidence "'$vendorString'$(if ($known) { " ($known)" })" `
        -Remediation 'A patched QEMU build is required to change this string; libvirt alone cannot.'
}

function Test-CpuBrandString {
    $id = 'win.env.cpu_brand_string'
    $name = 'CPU brand string (Pafish-class)'
    $description = "CPUID leaves 0x80000002-4 -- Pafish's classic check for 'QEMU Virtual CPU'/'Common KVM processor'/Hyper-V's 'Virtual CPU'."
    if (-not [System.Runtime.Intrinsics.X86.X86Base]::IsSupported) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity high -ErrorDetail 'X86Base CPUID intrinsic unsupported on this CLR/architecture'
    }
    $bytes = [System.Collections.Generic.List[byte]]::new()
    foreach ($leaf in 0x80000002, 0x80000003, 0x80000004) {
        $r = [System.Runtime.Intrinsics.X86.X86Base]::CpuId($leaf, 0)
        foreach ($reg in $r.Eax, $r.Ebx, $r.Ecx, $r.Edx) {
            $bytes.AddRange([BitConverter]::GetBytes([int32]$reg))
        }
    }
    $brand = [System.Text.Encoding]::ASCII.GetString($bytes.ToArray()).Trim([char]0).Trim()
    $match = Find-PerdedorSignature -Text $brand -Signatures $Script:CpuBrandStringSignatures
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ([bool]$match) -Evidence $brand `
        -Remediation 'Use CPU host-passthrough with a real-CPU model string, or patch the brand string via a custom QEMU build.'
}

function Test-PnpVirtualDevices {
    $id = 'win.env.pnp_virtual_devices'
    $name = 'PnP device vendor ID enumeration'
    $description = 'Scans Win32_PnPEntity DeviceIDs for known virtio/QEMU/VMware/VirtualBox/Xen PCI vendor IDs.'
    try {
        $devices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop
    }
    catch {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status error -Severity high -ErrorDetail "CIM query failed: $($_.Exception.Message)"
    }
    $hits = @()
    foreach ($device in $devices) {
        foreach ($ven in $Script:PnpVirtualVendorIds.Keys) {
            if ($device.DeviceID -and $device.DeviceID.ToUpperInvariant().Contains($ven)) {
                $hits += "$($device.DeviceID) ($($Script:PnpVirtualVendorIds[$ven]))"
            }
        }
    }
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ($hits.Count -gt 0) -Evidence $hits `
        -Remediation 'Remove virtio devices from the domain XML; use e1000e NIC and SATA/ICH9 controllers instead. Also clear ghost (non-present) devices from Device Manager -- see CHIMERA KVM report Section 7.7.'
}

function Test-GuestServices {
    $id = 'win.env.guest_services'
    $name = 'Guest-integration services'
    $description = 'Checks for VBoxService/VMware Tools/qemu-ga/Xen/Parallels Windows services, whose presence alone identifies a VM guest.'
    if (-not (Get-Command Get-Service -ErrorAction SilentlyContinue)) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity medium -ErrorDetail 'Get-Service is not available on this platform (Windows-only cmdlet)'
    }
    $found = @()
    foreach ($svcName in $Script:GuestServiceNames) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop
            $found += "$($svc.Name) ($($svc.Status))"
        }
        catch {
            continue
        }
    }
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity medium `
        -IsDetected ($found.Count -gt 0) -Evidence $found `
        -Remediation 'Uninstall guest-integration tools (VirtualBox Guest Additions, VMware Tools, qemu-guest-agent) from the golden image.'
}

function Test-RegistryArtifacts {
    $id = 'win.env.registry_artifacts'
    $name = 'Hypervisor/sandbox registry key artifacts'
    $description = "Checks $($Script:RegistryArtifactKeys.Count) known registry keys left by VirtualBox/VMware/Xen/Wine/Sandboxie guest tooling -- the single largest technique category in Pafish/al-khaser by check count."
    if (-not (Test-Path -LiteralPath 'HKLM:\')) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity high -ErrorDetail 'registry drives are not available on this platform'
    }
    $found = @()
    foreach ($key in $Script:RegistryArtifactKeys.Keys) {
        if (Test-Path -LiteralPath $key -ErrorAction SilentlyContinue) {
            $found += "$key ($($Script:RegistryArtifactKeys[$key]))"
        }
    }
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ($found.Count -gt 0) -Evidence $found `
        -Remediation 'Remove guest-integration tooling and registry remnants for whichever hypervisor is listed in the evidence from the golden image.'
}

function Test-ArtifactFiles {
    $id = 'win.env.artifact_files'
    $name = 'Hypervisor guest driver/tool files on disk'
    $description = "Checks $($Script:ArtifactFilePaths.Count) known file/directory paths left by VirtualBox/VMware/Xen guest drivers and tools."
    $found = @()
    foreach ($path in $Script:ArtifactFilePaths.Keys) {
        if (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue) {
            $found += "$path ($($Script:ArtifactFilePaths[$path]))"
        }
    }
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ($found.Count -gt 0) -Evidence $found `
        -Remediation 'Uninstall guest-integration drivers/tools for whichever hypervisor is listed in the evidence from the golden image.'
}

function Test-SmbiosFirmwareTableRaw {
    $id = 'win.env.smbios_firmware_table_raw'
    $name = 'Raw SMBIOS firmware table scan'
    $description = "Reads the raw SMBIOS table via GetSystemFirmwareTable('RSMB', ...) and scans its bytes directly -- catches vendor strings that survive WMI/CIM-level spoofing because WMI reads from a higher-level provider than the raw table itself (VMAware's approach)."
    $buffer = Get-PerdedorFirmwareTableBytes -Provider 'RSMB'
    if ($null -eq $buffer) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity high -ErrorDetail 'GetSystemFirmwareTable unavailable on this platform, or the call failed'
    }
    $text = [System.Text.Encoding]::ASCII.GetString($buffer)
    $match = Find-PerdedorSignature -Text $text -Signatures $Script:DmiVendorSignatures
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity high `
        -IsDetected ([bool]$match) -Evidence "$($buffer.Length) bytes scanned$(if ($match) { "; matched '$match'" })" `
        -Remediation 'The raw SMBIOS table itself carries the hypervisor identity -- a patched QEMU/hypervisor firmware build is required, not just guest-OS-level overrides.'
}

function Test-LowCoreCount {
    $id = 'win.env.low_core_count'
    $name = 'Logical CPU count'
    $description = "A sandbox is commonly provisioned with very few vCPUs (<= $($Script:LowCoreCountThreshold))."
    $count = [System.Environment]::ProcessorCount
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity low `
        -IsDetected ($count -le $Script:LowCoreCountThreshold) -Evidence "$count logical CPUs" `
        -Remediation 'Provision the sandbox with a realistic core count (4+) for the spoofed hardware identity.'
}

function Test-LowRam {
    $id = 'win.env.low_ram'
    $name = 'Total RAM'
    $description = "A sandbox is commonly provisioned with very little RAM (<= $($Script:LowRamGbThreshold) GiB)."
    try {
        $totalBytes = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
    }
    catch {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status error -Severity low -ErrorDetail "CIM query failed: $($_.Exception.Message)"
    }
    $gb = [Math]::Round($totalBytes / 1GB, 1)
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity low `
        -IsDetected ($gb -le $Script:LowRamGbThreshold) -Evidence "$gb GiB" `
        -Remediation 'Provision the sandbox with realistic RAM (8GB+) for the spoofed hardware identity.'
}

function Test-SmallDisk {
    $id = 'win.env.small_disk'
    $name = 'Primary disk size'
    $description = "A sandbox is commonly provisioned with a small disk (<= $($Script:SmallDiskGbThreshold) GiB)."
    try {
        $disks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
    }
    catch {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status error -Severity low -ErrorDetail "CIM query failed: $($_.Exception.Message)"
    }
    if (-not $disks) {
        return New-PerdedorFinding -Id $id -Category environment_artifact -Name $name -Description $description `
            -Status skipped -Severity low -ErrorDetail 'no disk drives enumerated'
    }
    $largestGb = [Math]::Round((($disks | Measure-Object -Property Size -Maximum).Maximum) / 1GB, 1)
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity low `
        -IsDetected ($largestGb -le $Script:SmallDiskGbThreshold) -Evidence "$largestGb GiB" `
        -Remediation 'Provision the sandbox with a realistic disk size (120GB+) for the spoofed hardware identity.'
}

function Test-CloudMetadataReachable {
    $id = 'win.env.cloud_metadata_reachable'
    $name = 'Cloud instance-metadata endpoint'
    $description = "Attempts a short-timeout request to $($Script:CloudMetadataUrl) -- reachability alone identifies a cloud VM. Not checked by Pafish/al-khaser/VMAware, which predate cloud-native detonation infrastructure."
    $reachable = $false
    try {
        $request = [System.Net.WebRequest]::Create($Script:CloudMetadataUrl)
        $request.Timeout = 1000
        $response = $request.GetResponse()
        $response.Close()
        $reachable = $true
    }
    catch {
        $reachable = $false
    }
    New-PerdedorBoolFinding -Id $id -Category environment_artifact -Name $name -Description $description -Severity medium `
        -IsDetected $reachable -Evidence $(if ($reachable) { 'metadata endpoint responded' } else { 'unreachable' }) `
        -Remediation 'Ensure the sandbox network has no route to the cloud metadata service (169.254.169.254) if cloud infrastructure is being used for hosting only, not as the detonation identity.'
}

function Invoke-EnvironmentChecks {
    @(
        Test-SmbiosVendor
        Test-CpuidHypervisorBit
        Test-CpuidHypervisorVendor
        Test-CpuBrandString
        Test-PnpVirtualDevices
        Test-GuestServices
        Test-RegistryArtifacts
        Test-ArtifactFiles
        Test-SmbiosFirmwareTableRaw
        Test-LowCoreCount
        Test-LowRam
        Test-SmallDisk
        Test-CloudMetadataReachable
    )
}
