# Check coverage

How much of each upstream suite, rule set and taxonomy Perdedor tests, item by item. Every technique
in every tracked upstream is in one of four states:

- **Covered:** an implemented check names it in its `equivalents`, spelt as upstream spells it.
- **Planned:** a catalogued check will test it but is not implemented yet; its `reason` says why.
- **Not feasible:** either a catalogued check explains why it cannot be done safely from user mode
  (for example "needs a kernel driver" or "can crash a Xen guest"), or the item is out of scope
  because it describes the sample rather than the environment (packers, obfuscators, anti-forensic
  actions). Out-of-scope items are listed below with the reason.
- **Missing:** none of the above. These are the real gaps, listed by name below, and the weekly
  upstream watcher flags any new one.

*Of feasible* is the covered share once the not-feasible items are set aside. The tables are produced
by `perdedor coverage --markdown`; regenerate this page after changing the catalog:

```bash
perdedor coverage --markdown    # replace everything below "Generated coverage"
```

Mobile and Apple suites (freeRASP, RootBeer, IOSSecuritySuite, anti-emulator) cover what an app sees
on a device; Perdedor drives the device from the analyst host instead, see
[Android](notes/android.md) and [Apple](notes/apple.md). The scoring does not depend on these
percentages: a check counts once per technique however many upstream items it covers
([Scoring](SCORING.md)).

## Generated coverage

Generated 2026-11-09 from the inventories in `catalog/inventory/` and the `equivalents` of 1009 implemented checks (1034 catalogued). A technique is covered when an implemented check lists it; not feasible techniques are documented as such; everything else is missing. *Feasible* excludes the not feasible ones.

| Source | Revision | Techniques | Covered | Planned | Not feasible | Missing | Covered | Of feasible |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| VMAware (`vmaware`) | v2.8.2 | 81 | 62 | 5 | 3 | 11 | 76.5% | 79.5% |
| al-khaser (`al-khaser`) | v1.1.0 | 177 | 132 | 5 | 7 | 33 | 74.6% | 77.6% |
| Pafish (`pafish`) | v0.6 | 58 | 56 | 0 | 0 | 2 | 96.6% | 96.6% |
| InviZzzible (`invizzzible`) | d6fa72cb4d51 | 162 | 139 | 0 | 0 | 23 | 85.8% | 85.8% |
| Check Point Evasions encyclopedia (`checkpoint-evasions`) | 4cda4b058641 | 110 | 74 | 2 | 8 | 26 | 67.3% | 72.5% |
| MITRE ATT&CK STIX data (`attack`) | v20.1 | 7 | 7 | 0 | 0 | 0 | 100.0% | 100.0% |
| Malware Behavior Catalog (`mbc`) | v3.2 | 9 | 5 | 0 | 0 | 4 | 55.6% | 55.6% |
| anti-emulator (Android) (`anti-emulator`) | f2b669a54980 | 13 | 10 | 0 | 0 | 3 | 76.9% | 76.9% |
| freeRASP for Android (`freerasp-android`) | v19.3.0 | 22 | 14 | 0 | 2 | 6 | 63.6% | 70.0% |
| freeRASP for Flutter (`freerasp-flutter`) | v8.2.4 | 22 | 14 | 0 | 3 | 5 | 63.6% | 73.7% |
| IOSSecuritySuite (`iossecuritysuite`) | 2.3.0 | 12 | 10 | 0 | 2 | 0 | 83.3% | 100.0% |
| RootBeer (`rootbeer`) | 0.1.2 | 17 | 12 | 0 | 0 | 5 | 70.6% | 70.6% |
| systemd (systemd-detect-virt) (`systemd`) | v262.2 | 30 | 30 | 0 | 0 | 0 | 100.0% | 100.0% |
| capa rules (anti-analysis) (`capa-rules`) | v10.0.0 | 91 | 31 | 1 | 52 | 7 | 34.1% | 79.5% |
| CAPE community signatures (`cape-community`) | 9d9156384fd4 | 73 | 61 | 1 | 4 | 7 | 83.6% | 88.4% |

### VMAware: missing (11)

`AMD_SEV_MSR`, `AZURE`, `CLOCK`, `DBVM`, `GAMARUE`, `MEASURED_BOOT`, `MSR`, `NVRAM`, `SVM_EXCEPTIONS`, `THREAD_MISMATCH`, `UD`

### al-khaser: missing (33)

`AntiDisassmAsmJmpSameTarget`, `AntiDisassmConstantCondition`, `AntiDisassmFunctionPointer`, `AntiDisassmImpossibleDiasassm`, `AntiDisassmReturnPointerAbuse`, `AntiDisassmSEHMisuse`, `CreateRemoteThread_Injection`, `ErasePEHeaderFromMemory`, `GetSetThreadContext_Injection`, `NtCreateThreadEx_Injection`, `NtQueryObject_ObjectTypeInformation`, `NtYieldExecutionAPI`, `PageExceptionBreakpointCheck`, `ProcessJob`, `QueueUserAPC_Injection`, `RtlCreateUserThread_Injection`, `ScanForModules_DotNetModuleStructures`, `ScanForModules_EnumProcessModulesEx_32bit`, `ScanForModules_EnumProcessModulesEx_64bit`, `ScanForModules_LDR_Direct`, `ScanForModules_LdrEnumerateLoadedModules`, `ScanForModules_MemoryWalk_GMI`, `ScanForModules_MemoryWalk_Hidden`, `SetWindowsHooksEx_Injection`, `SizeOfImage`, `hosting_check`, `timing_CreateTimerQueueTimer`, `timing_CreateWaitableTimer`, `timing_IcmpSendEcho`, `timing_SetTimer`, `timing_WaitForMultipleObjects`, `timing_sleep_loop`, `timing_timeSetEvent`

### Pafish: missing (2)

`cuckoo_check_tls`, `rtt_confirm_dialog`

### InviZzzible: missing (23)

`cuckoo/AgentArtifacts`, `cuckoo/AgentListener`, `cuckoo/CuckoomonConfiguration`, `cuckoo/DeadAnalyzer`, `cuckoo/DelayInterval`, `cuckoo/DelaysAccumulation`, `cuckoo/FunctionHooks`, `cuckoo/InfiniteDelay`, `cuckoo/InvalidHook`, `cuckoo/LackOfArgumentChecks`, `cuckoo/PidReuse`, `cuckoo/RaisedExceptions`, `cuckoo/SocketTimeout`, `cuckoo/SuspendedThread`, `cuckoo/TaskSchedulerProcess`, `cuckoo/TickCount`, `cuckoo/UnbalancedStack`, `cuckoo/WMIProcess`, `cuckoo/WhitelistedProcess`, `generic/BigRamAlloc`, `generic/SleepDummyPatch`, `generic/TimeTampering`, `vmware/HypervisorPortEnum`

### Check Point Evasions encyclopedia: missing (26)

`anti-debug/assembly/instruction-counting`, `anti-debug/assembly/instruction_prefixes`, `anti-debug/assembly/popf_and_cpuid`, `anti-debug/assembly/ss_register`, `anti-debug/exceptions/raiseexception`, `anti-debug/interactive/generateconsolectrlevent`, `anti-debug/interactive/processsuspensiondetection`, `anti-debug/interactive/self-debugging`, `anti-debug/interactive/suspendthread`, `anti-debug/misc/dbgprint`, `anti-debug/misc/dbgsetdebugfilterstate`, `anti-debug/misc/selectors`, `anti-debug/misc/switchtothread`, `anti-debug/object-handles/createfile`, `anti-debug/object-handles/loadlibrary`, `anti-debug/timing/getlocaltime`, `anti-debug/timing/getsystemtime`, `anti-debug/timing/gettickcount`, `anti-debug/timing/kernel-timing`, `anti-debug/timing/timegettime`, `evasions/network/check-if-network-belongs-to-security-perimeter`, `evasions/network/netvalidatename-result-based-anti-emulation-technique`, `evasions/os-features/using-unbalanced-stack`, `evasions/timing/call-hooked-function-with-invalid-arguments`, `evasions/timing/get-time-ntp`, `evasions/wmi/check-network-adapter-reset-time`

### Check Point Evasions encyclopedia: out of scope (8)

- APK and manifest malformations aimed at analysis tools; a property of the sample file, not of the device under test. `android/anti-analysis/long-filenames`, `android/anti-analysis/wrong-values-manifest`, `android/anti-analysis/wrong-zip-header-values`
- Describes how the sample itself is built (packing, obfuscation, disassembly tricks), not anything the analysis environment shows; nothing to test in a sandbox. `anti-debug/exceptions/hiding-cf-with-eh`
- Blocks keyboard and mouse input to hinder an interactive debugger; changes system state and says nothing about the environment. `anti-debug/interactive/blockinput`
- Moves the sample to another desktop to hide from an interactive debugger; changes system state. `anti-debug/interactive/switchdesktop`
- An action the sample takes against monitoring or forensics (tampering, hiding, cleaning up), not a check of the environment; a sandbox records it as behaviour, and there is nothing read-only to test. `anti-debug/misc/ifeo-removal`, `evasions/wmi/escape-from-tracking`

### Malware Behavior Catalog: missing (4)

`B0002`, `B0005`, `B0006`, `B0036`

### anti-emulator (Android): missing (3)

`checkQemuBreakpoint`, `hasEmulatorAdb`, `qemuBkpt`

### freeRASP for Android: missing (6)

`onMalware`, `onObfuscationIssues`, `onScreenRecording`, `onScreenshot`, `onTimeSpoofing`, `onUnsecureWifi`

### freeRASP for Flutter: missing (5)

`obfuscationIssues`, `screenRecording`, `screenshot`, `timeSpoofing`, `unsecureWiFi`

### RootBeer: missing (5)

`canLoadNativeLibrary`, `checkForNativeLibraryReadAccess`, `isRooted`, `isRootedWithBusyBoxCheck`, `isRootedWithoutBusyBoxCheck`

### capa rules (anti-analysis): missing (7)

`capa/anti-analysis/anti-debugging/check-for-time-delay-in-dotnet`, `capa/anti-analysis/anti-debugging/debugger-detection/check-for-time-delay-via-gettickcount`, `capa/anti-analysis/anti-debugging/debugger-detection/check-for-time-delay-via-queryperformancecounter`, `capa/anti-analysis/anti-debugging/debugger-detection/check-process-job-object`, `capa/anti-analysis/anti-vm/vm-detection/check-for-microsoft-office-emulation`, `capa/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-device`, `capa/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-dns-suffix`

### capa rules (anti-analysis): out of scope (52)

- An action the sample takes against monitoring or forensics (tampering, hiding, cleaning up), not a check of the environment; a sandbox records it as behaviour, and there is nothing read-only to test. `capa/anti-analysis/anti-av/block-operations-on-executable-memory-pages-using-arbitrary-code-guard`, `capa/anti-analysis/anti-av/patch-antimalware-scan-interface-function`, `capa/anti-analysis/anti-av/patch-bitdefender-hooking-dll-function`, `capa/anti-analysis/anti-av/patch-event-tracing-for-windows-function`, `capa/anti-analysis/anti-av/protect-spawned-processes-with-mitigation-policies`, `capa/anti-analysis/anti-forensic/clear-logs/clear-windows-event-logs`, `capa/anti-analysis/anti-forensic/clear-logs/clear-windows-event-logs-remotely`, `capa/anti-analysis/anti-forensic/crash-the-windows-event-logging-service`, `capa/anti-analysis/anti-forensic/disable-powershell-transcription`, `capa/anti-analysis/anti-forensic/impersonate-file-version-information`, `capa/anti-analysis/anti-forensic/patch-process-command-line`, `capa/anti-analysis/anti-forensic/self-deletion/self-delete`, `capa/anti-analysis/anti-forensic/self-deletion/self-delete-using-alternate-data-streams`, `capa/anti-analysis/anti-forensic/spoof-parent-pid`, `capa/anti-analysis/anti-forensic/timestomp/timestomp-file`, `capa/anti-analysis/anti-forensic/unload-sysmon`
- An action the sample takes against monitoring or forensics (tampering, hiding, cleaning up), not a check of the environment; a sandbox records it as behaviour, and there is nothing read-only to test. Whether there are in-guest hooks to remove is what win.design.system_module_text_integrity tests. `capa/anti-analysis/anti-av/overwrite-dll-text-section-to-remove-hooks`
- Describes how the sample itself is built (packing, obfuscation, disassembly tricks), not anything the analysis environment shows; nothing to test in a sandbox. `capa/anti-analysis/anti-disasm/64-bit-execution-via-heavens-gate`, `capa/anti-analysis/anti-disasm/contain-anti-disasm-techniques`, `capa/anti-analysis/obfuscation/obfuscated-with-advobfuscator`, `capa/anti-analysis/obfuscation/obfuscated-with-babel-obfuscator`, `capa/anti-analysis/obfuscation/obfuscated-with-callobfuscator`, `capa/anti-analysis/obfuscation/obfuscated-with-deepsea-obfuscator`, `capa/anti-analysis/obfuscation/obfuscated-with-dotfuscator`, `capa/anti-analysis/obfuscation/obfuscated-with-smartassembly`, `capa/anti-analysis/obfuscation/obfuscated-with-spicesdotnet-obfuscator`, `capa/anti-analysis/obfuscation/obfuscated-with-vs-obfuscation`, `capa/anti-analysis/obfuscation/obfuscated-with-yano`, `capa/anti-analysis/obfuscation/string/stackstring/contain-obfuscated-stackstrings`, `capa/anti-analysis/packer/amber/packed-with-amber`, `capa/anti-analysis/packer/aspack/packed-with-aspack`, `capa/anti-analysis/packer/confuser/packed-with-confuser`, `capa/anti-analysis/packer/dxpack/packed-with-dxpack`, `capa/anti-analysis/packer/generic/packed-with-generic-packer`, `capa/anti-analysis/packer/gopacker/packed-with-gopacker`, `capa/anti-analysis/packer/huan/packed-with-huan`, `capa/anti-analysis/packer/kkrunchy/packed-with-kkrunchy`, `capa/anti-analysis/packer/nmm-protect/packed-with-nmm-protect`, `capa/anti-analysis/packer/nspack/packed-with-nspack`, `capa/anti-analysis/packer/pebundle/packed-with-pebundle`, `capa/anti-analysis/packer/pecompact/packed-with-pecompact`, `capa/anti-analysis/packer/pelocknt/packed-with-pelocknt`, `capa/anti-analysis/packer/peshield/packed-with-peshield`, `capa/anti-analysis/packer/pespin/packed-with-pespin`, `capa/anti-analysis/packer/petite/packed-with-petite`, `capa/anti-analysis/packer/rlpack/packed-with-rlpack`, `capa/anti-analysis/packer/themida/packed-with-themida`, `capa/anti-analysis/packer/upack/packed-with-upack`, `capa/anti-analysis/packer/upx/packed-with-upx`, `capa/anti-analysis/packer/vmprotect/packed-with-vmprotect`, `capa/anti-analysis/packer/y0da/packed-with-y0da-crypter`
- Targets language-model assisted analysis, not the sandbox environment. `capa/anti-analysis/anti-llm/terminate-anthropic-session-via-magic-strings`

### CAPE community signatures: missing (7)

`cape/modules/signatures/windows/antidebug_debugactiveprocess`, `cape/modules/signatures/windows/antidebug_devices`, `cape/modules/signatures/windows/antidebug_gettickcount`, `cape/modules/signatures/windows/antiemu_windefend`, `cape/modules/signatures/windows/antisandbox_systemparams`, `cape/modules/signatures/windows/antisandbox_volumeserial`, `cape/modules/signatures/windows/antivm_vmware_mutexes`

### CAPE community signatures: out of scope (4)

- An action the sample takes against monitoring or forensics (tampering, hiding, cleaning up), not a check of the environment; a sandbox records it as behaviour, and there is nothing read-only to test. `cape/modules/signatures/windows/antisandbox_cuckoocrash`, `cape/modules/signatures/windows/antisandbox_suspend`
- Reboots the machine to outlast the analysis; behaviour, not an environment check. Long analyses (CHIMERA) are the countermeasure. `cape/modules/signatures/windows/antisandbox_restart`
- An action the sample takes against monitoring or forensics (tampering, hiding, cleaning up), not a check of the environment; a sandbox records it as behaviour, and there is nothing read-only to test. Whether there are in-guest hooks to remove is what win.design.system_module_text_integrity tests. `cape/modules/signatures/windows/antisandbox_unhook`
