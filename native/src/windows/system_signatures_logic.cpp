#include "system_logic.hpp"
namespace perdedor {
namespace winlogic {
// Signature facts: v1 Signatures.ps1; al-khaser AntiAnalysis/process.cpp and AntiVM/Generic.cpp.
const std::vector<std::string> &analysis_processes() {
    static const std::vector<std::string> v = {
        "apimonitor-x64.exe",
        "apimonitor-x86.exe",
        "apimonitor.exe",
        "autoruns.exe",
        "autorunsc.exe",
        "cape.exe",
        "cheatengine-i386.exe",
        "cheatengine-x86_64-sse4-avx2.exe",
        "cheatengine-x86_64.exe",
        "cuckoo.exe",
        "cuckoomon.exe",
        "cutter.exe",
        "detectiteasy.exe",
        "dnspy.exe",
        "dnspyex.exe",
        "drakrun.exe",
        "drakvuf.exe",
        "dumpcap.exe",
        "fakenet.exe",
        "fiddler.exe",
        "filemon.exe",
        "frida-helper-32.exe",
        "frida-helper-64.exe",
        "frida-server.exe",
        "ghidra.exe",
        "hollows_hunter.exe",
        "hookexplorer.exe",
        "httpdebugger.exe",
        "httpdebuggerui.exe",
        "hxd.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "ilspy.exe",
        "immunitydebugger.exe",
        "importrec.exe",
        "injector.exe",
        "joeboxcontrol.exe",
        "joeboxserver.exe",
        "ksdumperclient.exe",
        "lordpe.exe",
        "ollydbg.exe",
        "ollyice.exe",
        "pe-sieve.exe",
        "pestudio.exe",
        "petools.exe",
        "proc_analyzer.exe",
        "processhacker.exe",
        "procexp.exe",
        "procexp64.exe",
        "procmon.exe",
        "procmon64.exe",
        "r2.exe",
        "radare2.exe",
        "regmon.exe",
        "resourcehacker.exe",
        "sniff_hit.exe",
        "sysanalyzer.exe",
        "sysinspector.exe",
        "systeminformer.exe",
        "tcpview.exe",
        "vboxservice.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "windbg.exe",
        "wireshark.exe",
        "x32dbg.exe",
        "x64dbg.exe",
    };
    return v;
}
const std::vector<std::string> &guest_processes() {
    static const std::vector<std::string> v = {
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe",   "vmwaretray.exe", "vmwareuser.exe",
        "vmacthlp.exe",    "qemu-ga.exe",  "xenservice.exe", "xensvc.exe",     "prl_tools.exe",
        "prl_cc.exe",      "vmsrvc.exe",   "vmusrvc.exe",
    };
    return v;
}
const std::vector<std::string> &guest_services() {
    static const std::vector<std::string> v = {
        "VBoxGuest",     "VBoxMouse",    "VBoxSF",       "VBoxService", "VBoxVideo",     "VBoxWddm",
        "VMMEMCTL",      "VMTools",      "balloon",      "msvmmouf",    "netkvm",        "prl_cc",
        "prl_fs",        "prl_tg",       "prl_tools",    "qemu-ga",     "tpautoconnsvc", "viorng",
        "vioscsi",       "viostor",      "vm3dservice",  "vmci",        "vmhgfs",        "vmicexchange",
        "vmicheartbeat", "vmicshutdown", "vmictimesync", "vmicvss",     "vmmouse",       "vmusb",
        "vmusbmouse",    "vmvss",        "vmx86",        "vmx_svga",    "vmxnet",        "vpc-s3",
        "vpcuhub",       "xenagent",     "xenbus",       "xenevtchn",   "xenfilt",       "xeniface",
        "xennet",        "xensvc",       "xenvbd",
    };
    return v;
}
const std::vector<std::string> &modules() {
    static const std::vector<std::string> v = {
        "api_log.dll",  "avghooka.dll",  "avghookx.dll",   "capemon.dll",   "cmdvrt32.dll",
        "cmdvrt64.dll", "cuckoomon.dll", "dbghelp.dll",    "dir_watch.dll", "frida-agent.dll",
        "guard32.dll",  "guard64.dll",   "pstorec.dll",    "sbiedll.dll",   "sf2.dll",
        "snxhk.dll",    "sxin.dll",      "vboxhook.dll",   "vboxmrxnp.dll", "vboxservice.dll",
        "vboxtray.dll", "vmcheck.dll",   "vmguestlib.dll", "vmhgfs.dll",    "wpespy.dll",
    };
    return v;
}
const std::vector<std::string> &monitor_vendors() {
    // QEMU's generated EDID: vendor "RHT", name "QEMU Monitor"
    // https://github.com/qemu/qemu/blob/master/hw/display/edid-generate.c
    static const std::vector<std::string> v = {"RHT"};
    return v;
}
} // namespace winlogic
} // namespace perdedor
