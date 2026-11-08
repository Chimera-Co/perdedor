	/* Debuggers detection tricks */
	print_check_group("Debuggers detection");
	exec_check("Using IsDebuggerPresent()", &debug_isdebuggerpresent,
		   "Debugger traced using IsDebuggerPresent()",
		   "hi_debugger_isdebuggerpresent");
	exec_check("Using BeingDebugged via PEB access", &debug_beingdebugged_peb,
		   "Debugger traced using PEB BeingDebugged",
		   "hi_debugger_beingdebugged_PEB");
	/* This is only working on MS Windows systems prior to Vista */
	if (winver.dwMajorVersion < 6) {
		exec_check("Using OutputDebugString()",
			   &debug_outputdebugstring,
			   "Debugger traced using OutputDebugString()",
			   "hi_debugger_outputdebugstring");
	}

	/* CPU information based detection tricks */
	print_check_group("CPU information based detections");
	exec_check
	    ("Checking the difference between CPU timestamp counters (rdtsc)",
	     &cpu_rdtsc,
	     "CPU VM traced by checking the difference between CPU timestamp counters (rdtsc)",
	     "hi_CPU_VM_rdtsc");
	exec_check
	    ("Checking the difference between CPU timestamp counters (rdtsc) forcing VM exit",
	     &cpu_rdtsc_force_vmexit,
	     "CPU VM traced by checking the difference between CPU timestamp counters (rdtsc) forcing VM exit",
	     "hi_CPU_VM_rdtsc_force_vm_exit");
	exec_check("Checking hypervisor bit in cpuid feature bits", &cpu_hv,
		   "CPU VM traced by checking hypervisor bit in cpuid feature bits",
		   "hi_CPU_VM_hypervisor_bit");
	exec_check("Checking cpuid hypervisor vendor for known VM vendors",
		   &cpu_known_vm_vendors,
		   "CPU VM traced by checking cpuid hypervisor vendor for known VM vendors",
		   "hi_CPU_VM_hv_vendor_name");

        /* Generic reverse turing tests */
