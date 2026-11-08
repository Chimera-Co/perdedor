
	/* Display general informations */
	_tprintf(_T("[al-khaser version 0.82]"));

	print_category(TEXT("Initialisation"));
	API::Init();
	print_os();
	API::PrintAvailabilityReport();
	/* Generic sandbox detection */
	if (ENABLE_GEN_SANDBOX_CHECKS) {
		print_category(TEXT("Generic Sandboxe/VM Detection"));
		loaded_dlls();
		known_file_names();
		known_usernames();
		known_hostnames();
		other_known_sandbox_environment_checks();
		looking_glass_vdd_processes();
		exec_check(&NumberOfProcessors, TEXT("Checking Number of processors in machine "));
		exec_check(&idt_trick, TEXT("Checking Interupt Descriptor Table location "));
	/* VirtualBox Detection */
	if (ENABLE_VBOX_CHECKS) {
		print_category(TEXT("VirtualBox Detection"));
		vbox_reg_key_value();
		exec_check(&vbox_dir, TEXT("Checking VirtualBox Guest Additions directory "));
		vbox_files();
		vbox_reg_keys();
		exec_check(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27 "));
		exec_check(&hybridanalysismacdetect, TEXT("Checking MAC address (Hybrid Analysis) "));
		vbox_devices();
		exec_check(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd "));
		exec_check(timing_CreateWaitableTimer, delayInMillis, TEXT("Delaying execution using CreateWaitableTimer ..."));
		exec_check(timing_CreateTimerQueueTimer, delayInMillis, TEXT("Delaying execution using CreateTimerQueueTimer ..."));

		exec_check(&rdtsc_diff_locky, TEXT("Checking RDTSC Locky trick "));
		exec_check(&rdtsc_diff_vmexit, TEXT("Checking RDTSC which force a VM Exit (cpuid) "));
	}
