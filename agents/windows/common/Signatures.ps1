<#
.SYNOPSIS
    Known hypervisor/VM/sandbox identity signatures shared across Windows
    checks. Mirrors agents/linux/perdedor_linux/signatures.py where the same
    concept applies to both platforms, and additionally carries the
    Windows-only registry/file/window-class catalogs that are the bulk of
    Pafish's and al-khaser's actual technique lists (see docs/CHECK_COVERAGE.md).
#>

$Script:DmiVendorSignatures = @(
    'qemu', 'bochs', 'kvm', 'virtualbox', 'vbox', 'innotek', 'vmware', 'xen',
    'microsoft corporation', 'parallels', 'bhyve', 'amazon ec2', 'google compute engine'
)

# CPUID leaf 0x80000002-4 processor brand string signatures (Pafish's
# classic "QEMU Virtual CPU" check).
$Script:CpuBrandStringSignatures = @('qemu virtual cpu', 'common kvm processor', 'virtual cpu')

# Hypervisor CPUID leaf 0x40000000 vendor strings (EBX,ECX,EDX byte order).
$Script:CpuidHypervisorVendors = @{
    "KVMKVMKVM`0`0`0" = 'KVM'
    'TCGTCGTCGTCG'    = 'QEMU TCG (software emulation)'
    'VMwareVMware'    = 'VMware'
    'XenVMMXenVMM'    = 'Xen'
    'Microsoft Hv'    = 'Hyper-V'
    'prl hyperv  '    = 'Parallels'
    'VBoxVBoxVBox'    = 'VirtualBox (minimal vendor id)'
    'bhyve bhyve '    = 'bhyve'
}

$Script:PnpVirtualVendorIds = @{
    'VEN_1AF4' = 'Red Hat / virtio'
    'VEN_1B36' = 'QEMU (red hat virtual PCI device)'
    'VEN_15AD' = 'VMware'
    'VEN_80EE' = 'VirtualBox (Oracle/innotek)'
    'VEN_5853' = 'Xen'
}

$Script:GuestServiceNames = @(
    'VBoxService', 'VBoxSF', 'VBoxGuest', 'VBoxMouse', 'VBoxVideo',
    'VMTools', 'VMMEMCTL', 'vmvss', 'vmmouse', 'vm3dservice', 'vmci', 'vmx86', 'tpautoconnsvc',
    'qemu-ga', 'xenevtchn', 'xenvbd', 'xennet', 'xensvc', 'prl_tools', 'prl_cc'
)

$Script:MacOuiSignatures = @{
    '52:54:00' = 'QEMU/KVM (libvirt default OUI)'
    '08:00:27' = 'VirtualBox (Oracle/innotek default OUI)'
    '0A:00:27' = 'VirtualBox (host-only adapter)'
    '00:0C:29' = 'VMware (auto-generated OUI)'
    '00:50:56' = 'VMware (manually-assigned OUI)'
    '00:1C:14' = 'VMware (older OUI block)'
    '00:05:69' = 'VMware (very old OUI block)'
    '00:16:3E' = 'Xen (default OUI)'
    '00:03:FF' = 'Microsoft Hyper-V/Virtual PC'
    '00:15:5D' = 'Microsoft Hyper-V'
}

# Extends al-khaser's "Analysis Tools" process-name section.
$Script:AnalysisToolProcessNames = @(
    'procmon', 'procmon64', 'procexp', 'procexp64', 'wireshark', 'fiddler',
    'x64dbg', 'x32dbg', 'ida64', 'ida', 'idaq', 'idaq64', 'ollydbg',
    'immunitydebugger', 'windbg', 'httpdebuggerui', 'dumpcap', 'tcpview',
    'autoruns', 'autorunsc', 'regmon', 'filemon', 'processhacker', 'pestudio',
    'apimonitor-x64', 'apimonitor-x86', 'importrec', 'lordpe', 'sysinspector',
    'joeboxcontrol', 'joeboxserver', 'ksdumperclient', 'vboxservice', 'vmtoolsd', 'vmwaretray'
)

$Script:SuspiciousNameTokens = @('sandbox', 'malware', 'sample', 'analysis', 'cuckoo', 'detonat', 'honeypot', 'virus')

# al-khaser checks these as exact (not substring) username matches -- kept
# separate because short entries would false-positive under substring match.
$Script:SandboxUsernameExact = @('sandbox', 'malware', 'maltest', 'currentuser', 'sample', 'virus', 'test', 'test user', 'vmuser', 'john doe')

# DLLs that only get loaded into a process by a specific hypervisor's guest
# integration layer or a sandbox's API-hooking engine.
$Script:BlacklistedDllNames = @(
    'vboxhook.dll', 'vboxmrxnp.dll', 'vboxservice.dll', 'vboxtray.dll',
    'vmGuestLib.dll', 'vmhgfs.dll', 'sbiedll.dll', 'wpespy.dll',
    'api_log.dll', 'dir_watch.dll', 'pstorec.dll', 'cmdvrt32.dll', 'cmdvrt64.dll'
)

# Window class names created by hypervisor guest-integration tray tools.
$Script:VmWindowClassNames = @('VBoxTrayToolWndClass', 'VBoxTrayToolWnd', 'VMwareTrayIcon', 'vm3dversion_wc')

# Registry key -> vendor label. Existence alone is the tell (Pafish/al-khaser's
# largest single technique category by check count).
$Script:RegistryArtifactKeys = @{
    'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions'                    = 'VirtualBox'
    'HKLM:\SYSTEM\ControlSet001\Services\VBoxGuest'                       = 'VirtualBox'
    'HKLM:\SYSTEM\ControlSet001\Services\VBoxMouse'                       = 'VirtualBox'
    'HKLM:\SYSTEM\ControlSet001\Services\VBoxService'                     = 'VirtualBox'
    'HKLM:\SYSTEM\ControlSet001\Services\VBoxSF'                          = 'VirtualBox'
    'HKLM:\SYSTEM\ControlSet001\Services\VBoxVideo'                       = 'VirtualBox'
    'HKLM:\HARDWARE\ACPI\DSDT\VBOX__'                                     = 'VirtualBox'
    'HKLM:\HARDWARE\ACPI\FADT\VBOX__'                                     = 'VirtualBox'
    'HKLM:\HARDWARE\ACPI\RSDT\VBOX__'                                     = 'VirtualBox'
    'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools'                            = 'VMware'
    'HKLM:\SYSTEM\ControlSet001\Services\vmdebug'                         = 'VMware'
    'HKLM:\SYSTEM\ControlSet001\Services\vmmouse'                         = 'VMware'
    'HKLM:\SYSTEM\ControlSet001\Services\VMTools'                         = 'VMware'
    'HKLM:\SYSTEM\ControlSet001\Services\VMMEMCTL'                        = 'VMware'
    'HKLM:\SYSTEM\ControlSet001\Services\vmci'                            = 'VMware'
    'HKLM:\SYSTEM\ControlSet001\Services\vmx86'                           = 'VMware'
    'HKLM:\HARDWARE\ACPI\DSDT\VMWARE__'                                   = 'VMware'
    'HKLM:\HARDWARE\ACPI\FADT\VMWARE__'                                   = 'VMware'
    'HKLM:\HARDWARE\ACPI\DSDT\Xen'                                        = 'Xen'
    'HKLM:\SYSTEM\ControlSet001\Services\xenevtchn'                       = 'Xen'
    'HKLM:\SYSTEM\ControlSet001\Services\xennet'                          = 'Xen'
    'HKLM:\SYSTEM\ControlSet001\Services\xensvc'                          = 'Xen'
    'HKCU:\SOFTWARE\Wine'                                                 = 'Wine'
    'HKLM:\SOFTWARE\Wine'                                                 = 'Wine'
    'HKLM:\SYSTEM\CurrentControlSet\Services\SbieDrv'                     = 'Sandboxie'
    'HKLM:\SYSTEM\ControlSet001\Services\SbieDrv'                         = 'Sandboxie'
    'HKLM:\SYSTEM\ControlSet001\Control\Class\{4D36E96D-E325-11CE-BFC1-08002BE10318}\0000\CoInstallers32' = 'Xen (net class coinstaller)'
}

# Files/directories whose mere presence identifies a hypervisor guest or a
# sandbox, independent of any registry/CIM data.
$Script:ArtifactFilePaths = @{
    "$env:WINDIR\System32\drivers\VBoxMouse.sys"                         = 'VirtualBox'
    "$env:WINDIR\System32\drivers\VBoxGuest.sys"                         = 'VirtualBox'
    "$env:WINDIR\System32\drivers\VBoxSF.sys"                            = 'VirtualBox'
    "$env:WINDIR\System32\drivers\VBoxVideo.sys"                         = 'VirtualBox'
    "$env:WINDIR\System32\vboxdisp.dll"                                  = 'VirtualBox'
    "${env:ProgramFiles}\Oracle\VirtualBox Guest Additions"              = 'VirtualBox'
    "$env:WINDIR\System32\drivers\vmmouse.sys"                           = 'VMware'
    "$env:WINDIR\System32\drivers\vmhgfs.sys"                            = 'VMware'
    "$env:WINDIR\System32\drivers\vm3dmp.sys"                            = 'VMware'
    "$env:WINDIR\System32\vm3dgl.dll"                                    = 'VMware'
    "${env:ProgramFiles}\VMware\VMware Tools"                            = 'VMware'
    "$env:WINDIR\System32\drivers\xenevtchn.sys"                         = 'Xen'
    "$env:WINDIR\System32\drivers\xennet.sys"                            = 'Xen'
}

# Well-known cloud-provider instance-metadata endpoint. See the Linux
# signatures module for why this is worth checking at all.
$Script:CloudMetadataUrl = 'http://169.254.169.254/latest/meta-data/'
