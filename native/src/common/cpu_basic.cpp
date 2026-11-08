// CPUID hypervisor bit and vendor leaf: the two most widely used VM checks
// (Pafish cpu_hv / cpu_known_vm_vendors, al-khaser cpuid_is_hypervisor /
// cpuid_hypervisor_vendor, VMAware HYPERVISOR_BIT / HYPERVISOR_STR).
#include <map>

#include "../core/perdedor.hpp"
#include "x86.hpp"
#include "lowlevel.hpp"

namespace perdedor {
namespace {

const std::map<std::string, std::string>& known_vendors() {
    static const std::map<std::string, std::string> m = {
        {"KVMKVMKVM", "KVM"},          {"Linux KVM Hv", "KVM (Hyper-V enlightenments)"},
        {"Microsoft Hv", "Hyper-V"},   {"VMwareVMware", "VMware"},
        {"XenVMMXenVMM", "Xen"},       {"VBoxVBoxVBox", "VirtualBox"},
        {"prl hyperv", "Parallels"},   {" lrpepyh  vr", "Parallels"},
        {"bhyve bhyve", "bhyve"},      {"TCGTCGTCGTCG", "QEMU TCG"},
        {"ACRNACRNACRN", "ACRN"},      {"QNXQVMBSQG", "QNX"},
        {"HAXMHAXMHAXM", "Intel HAXM"}, {"UnisysSpar64", "Unisys s-Par"},
        {"SRESRESRESRE", "Lockheed SRE"}, {"Jailhouse", "Jailhouse"},
        {"EVMMEVMMEVMM", "Intel KGT"}, {"OpenBSDVMM58", "OpenBSD vmm"},
        {"VirtualApple", "Apple Rosetta / Virtualization"},
    };
    return m;
}

std::vector<Finding> hypervisor_bit(Context&) {
    const char* id = "env.cpuid_hypervisor_bit";
    const char* name = "CPUID hypervisor-present bit";
    const char* desc = "CPUID leaf 1, ECX bit 31 -- set by every mainstream hypervisor to advertise itself to the guest.";
    if (!x86::available()) return {skipped(id, name, desc, Severity::Critical, "CPUID unavailable or blocked")};
    x86::Regs r = x86::cpuid(1);
    bool present = (r.ecx >> 31) & 1u;
    char ev[64];
    std::snprintf(ev, sizeof ev, "ecx=0x%08x bit31=%d", r.ecx, present ? 1 : 0);
    return {lowlevel::measured(id, name, desc, Severity::Critical, present, ev,
                              lowlevel::numbers({{"leaf1_ecx", r.ecx}, {"hypervisor_bit", present}}), 0.98)};
}

std::vector<Finding> hypervisor_vendor(Context&) {
    const char* id = "env.cpuid_hypervisor_vendor";
    const char* name = "CPUID hypervisor vendor string";
    const char* desc = "CPUID leaf 0x40000000 -- the hypervisor vendor ID string (e.g. 'KVMKVMKVM', 'XenVMMXenVMM').";
    if (!x86::available()) return {skipped(id, name, desc, Severity::Critical, "CPUID unavailable or blocked")};
    x86::Regs r = x86::cpuid(0x40000000);
    std::string vendor = x86::hv_vendor(r);
    auto it = known_vendors().find(vendor);
    Json ev = Json::object();
    ev.set("vendor", vendor);
    char max[16];
    std::snprintf(max, sizeof max, "0x%08x", r.eax);
    ev.set("max_leaf", max);
    if (it != known_vendors().end()) ev.set("hypervisor", it->second);
    return {lowlevel::measured(id, name, desc, Severity::Critical, it != known_vendors().end(), ev,
                              lowlevel::numbers({{"max_leaf", r.eax}, {"known_vendor", it != known_vendors().end()}}), 0.98)};
}

}  // namespace

PERDEDOR_REGISTER(hypervisor_bit, "cpu.hypervisor_bit", "fast", false, "env.cpuid_hypervisor_bit");
PERDEDOR_REGISTER(hypervisor_vendor, "cpu.hypervisor_vendor_leaf", "fast", false, "env.cpuid_hypervisor_vendor");

}  // namespace perdedor
