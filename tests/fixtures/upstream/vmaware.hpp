class VM {
public:
    enum enum_flags : u8 {
        /* Windows */
        GPU_CAPABILITIES = 0,
        ACPI_SIGNATURE,
        /* Linux */
        SMBIOS_VM_BIT,
        DMIDECODE,
        /* Linux and MacOS */
        THREAD_COUNT,
        /* Cross-platform */
        HYPERVISOR_BIT,
        TIMER,
        /*
         * ADD NEW TECHNIQUE ENUM NAME HERE
         */
        DEFAULT,
        ALL,
        HIGH_THRESHOLD
    };
}
    const VM::core::technique_entry entries[] = {
        {VM::GPU_CAPABILITIES, {20, VM::gpu_capabilities}},
        {VM::ACPI_SIGNATURE, {100, VM::acpi_signature}},
        {VM::DMIDECODE, {100, VM::dmidecode}},
        {VM::TIMER, {45, VM::timer}},
    };
