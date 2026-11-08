#include <winsock2.h>
#include <ws2tcpip.h>
#include "system_checks.hpp"
#include <iphlpapi.h>
#include <netioapi.h>
#include <windns.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstring>
#include <set>
namespace perdedor {
namespace {
using namespace winsys;
// Operational caps, not detection thresholds: DESIGN-V2.md network/safety contract.
constexpr DWORD kHttpBudgetMs = 6500, kHttpBodyBytes = 1024;
struct Adapter {
    std::string description;
    std::vector<BYTE> mac;
    std::vector<uint32_t> addresses, gateways;
    ULONG type = 0;
    bool up = false;
};
win::Result<std::vector<Adapter>> adapters() {
    win::Result<std::vector<Adapter>> r;
    ULONG n = 16384;
    std::vector<BYTE> bytes(n);
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        auto *p = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(bytes.data());
        ULONG e = GetAdaptersAddresses(
            AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
            p, &n);
        if (e == ERROR_BUFFER_OVERFLOW) {
            if (n > winlogic::kMaxBlob) {
                r.error = "adapter buffer limit exceeded";
                return r;
            }
            bytes.resize(n);
            continue;
        }
        if (e == ERROR_NO_DATA)
            return r;
        if (e) {
            r.error = win::last_error_message(e);
            return r;
        }
        for (; p; p = p->Next) {
            if (r.value.size() >= winlogic::kMaxRows) {
                r.error = "adapter count limit exceeded";
                return r;
            }
            if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                continue;
            Adapter a;
            a.type = p->IfType;
            a.up = p->OperStatus == IfOperStatusUp;
            if (p->Description)
                a.description = win::narrow(p->Description);
            if (p->PhysicalAddressLength <= MAX_ADAPTER_ADDRESS_LENGTH)
                a.mac.assign(p->PhysicalAddress, p->PhysicalAddress + p->PhysicalAddressLength);
            for (auto u = p->FirstUnicastAddress; u; u = u->Next)
                if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_INET)
                    a.addresses.push_back(
                        ntohl(reinterpret_cast<sockaddr_in *>(u->Address.lpSockaddr)->sin_addr.s_addr));
            for (auto g = p->FirstGatewayAddress; g; g = g->Next)
                if (g->Address.lpSockaddr && g->Address.lpSockaddr->sa_family == AF_INET)
                    a.gateways.push_back(
                        ntohl(reinterpret_cast<sockaddr_in *>(g->Address.lpSockaddr)->sin_addr.s_addr));
            r.value.push_back(std::move(a));
        }
        return r;
    }
    r.error = "adapter buffer changed repeatedly";
    return r;
}
std::vector<Finding> adapter_check(Context &ctx, int kind) {
    const char *ids[] = {"design.mac_oui",         "design.adapter_count",    "design.no_wifi_adapter",
                         "design.default_subnets", "design.default_gateways", "design.adapter_descriptions"};
    const char *names[] = {"Virtual MAC address prefixes",
                           "Physical adapter count",
                           "No wireless adapter",
                           "Default virtual network subnets",
                           "Default virtual network gateways",
                           "Virtual adapter descriptions"};
    const char *id = ids[kind], *name = names[kind];
    auto r = adapters(); // local configuration query; sends no traffic
    if (!r.ok())
        return {fail(id, name, r.error, Severity::Medium)};
    unsigned wifi = 0, up = 0;
    std::vector<std::string> hits;
    for (const auto &a : r.value) {
        wifi += a.type == IF_TYPE_IEEE80211;
        up += a.up;
        std::string s;
        if (kind == 0)
            s = winlogic::oui(a.mac);
        if (kind == 5)
            s = winlogic::match(a.description, winlogic::vendors());
        if (!s.empty())
            hits.push_back(s);
        if (kind == 3 || kind == 4)
            for (auto address : kind == 3 ? a.addresses : a.gateways) {
                s = winlogic::subnet(address);
                if (!s.empty())
                    hits.push_back(s);
            }
    }
    bool hit = kind == 1 ? r.value.size() <= 1 : kind == 2 ? wifi == 0 : !hits.empty();
    auto ev = matched(hits, r.value.size());
    ev.set("wireless", wifi).set("up", up);
    return {result(id, name, hit, ev, Severity::Medium, kind == 0 ? 0.85 : 0.35)};
}
std::vector<Finding> arp_cache(Context &ctx) {
    const char *id = "behavioural.arp_cache", *name = "ARP neighbor cache count";
    PMIB_IPNET_TABLE2 table = nullptr;
    DWORD e = GetIpNetTable2(AF_INET, &table);
    if (e == ERROR_NOT_FOUND)
        return {result(id, name, true, counts(0))};
    if (e)
        return {fail(id, name, win::last_error_message(e))};
    unsigned count = 0;
    if (table->NumEntries > winlogic::kMaxEntries) {
        FreeMibTable(table);
        return {fail(id, name, "ARP table limit exceeded")};
    }
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        auto &row = table->Table[i];
        auto addr = ntohl(row.Address.Ipv4.sin_addr.s_addr);
        if (row.State != NlnsUnreachable && row.State != NlnsIncomplete && (addr >> 24) != 127 &&
            addr < 0xe0000000U && row.PhysicalAddressLength)
            ++count;
    }
    FreeMibTable(table);
    return {result(id, name, count == 0, counts(count))};
}
// Export and allocation contract documented by ReactOS ipconfig DisplayDns:
// https://github.com/reactos/reactos/blob/master/base/applications/network/ipconfig/ipconfig.c
std::vector<Finding> dns_cache(Context& ctx) {
    const char* id="behavioural.dns_cache",*name="DNS cache entry count";
    static volatile LONG stalled=0;
    auto value=win::bounded<uint64_t>([]{
        struct Entry {Entry* next;PWSTR name;};
        using Query=BOOL(WINAPI*)(Entry**);
        HMODULE lib=win::system_library(L"dnsapi.dll");
        if(!lib)return win::Result<uint64_t>{0,"",true};
        struct Lib {HMODULE h;~Lib(){FreeLibrary(h);}} cleanup{lib};
        auto query=win::proc<Query>(lib,"DnsGetCacheDataTable");
        if(!query)return win::Result<uint64_t>{0,"",true};
        Entry* p=nullptr;
        SetLastError(ERROR_SUCCESS);
        if(!query(&p)) {
            DWORD e=GetLastError();
            // An empty resolver cache returns FALSE without an error code.
            if(!p&&e==ERROR_SUCCESS)return win::Result<uint64_t>{0};
            return win::Result<uint64_t>{0,"DnsGetCacheDataTable failed: "+win::last_error_message(e)};
        }
        std::set<Entry*> seen;
        while(p) {
            if(seen.size()>=winlogic::kMaxEntries||!seen.insert(p).second)
                return win::Result<uint64_t>{0,"DNS cache enumeration limit or cycle"};
            Entry entry{};SIZE_T got=0;
            if(!ReadProcessMemory(GetCurrentProcess(),p,&entry,sizeof entry,&got)||got!=sizeof entry)
                return win::Result<uint64_t>{0,"unsupported DNS cache structure"};
            // Cache contents and domain names are never dereferenced or reported.
            // Release exactly as ReactOS ipconfig does (DnsFree with DnsFreeFlat).
            if(entry.name)DnsFree(entry.name,DnsFreeFlat);
            DnsFree(p,DnsFreeFlat);p=entry.next;
        }
        return win::Result<uint64_t>{static_cast<uint64_t>(seen.size())};
    },winlogic::kQueryMs,stalled);
    if(!value.ok())return{fail(id,name,value.error)};
    if(value.absent)return{absent(id,name,"DNS cache export unavailable")};
    return{result(id,name,value.value==0,counts(value.value))};
}
std::vector<Finding> listening_ports(Context &ctx) {
    const char *id = "design.agent_listening_ports", *name = "Local analysis agent listening ports";
    // Cuckoo agent default, Frida server defaults. A port alone is not attribution.
    // https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/data/agent/agent.py
    // https://frida.re/docs/modes/
    const std::set<unsigned> signatures = {8000, 27042, 27043};
    std::set<unsigned> hits;
    size_t examined = 0;
    for (ULONG family : {static_cast<ULONG>(AF_INET), static_cast<ULONG>(AF_INET6)}) {
        DWORD size = 0;
        DWORD e = GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (e != ERROR_INSUFFICIENT_BUFFER && e != NO_ERROR)
            return {fail(id, name, win::last_error_message(e))};
        if (size > winlogic::kMaxBlob)
            return {fail(id, name, "TCP table exceeds size limit")};
        std::vector<BYTE> bytes(size);
        e = GetExtendedTcpTable(bytes.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (e)
            return {fail(id, name, win::last_error_message(e))};
        if (family == AF_INET) {
            auto *t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(bytes.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                unsigned port = ntohs(static_cast<u_short>(t->table[i].dwLocalPort));
                ++examined;
                if (signatures.count(port))
                    hits.insert(port);
            }
        } else {
            auto *t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID *>(bytes.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                unsigned port = ntohs(static_cast<u_short>(t->table[i].dwLocalPort));
                ++examined;
                if (signatures.count(port))
                    hits.insert(port);
            }
        }
    }
    Json ports = Json::array();
    for (auto port : hits)
        ports.push(port);
    return {
        result(id, name, !hits.empty(),
               Ev().set("listeners", static_cast<unsigned long long>(examined)).set("ports", ports),
               Severity::Medium, 0.5)};
}
win::Result<std::wstring> random_host() {
    BYTE entropy[16];
    auto rc = BCryptGenRandom(nullptr, entropy, sizeof entropy, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (rc < 0)
        return {{}, "BCryptGenRandom failed: " + std::to_string(rc)};
    const wchar_t *hex = L"0123456789abcdef";
    std::wstring host = L"perdedor-";
    for (auto b : entropy) {
        host += hex[b >> 4];
        host += hex[b & 15];
    }
    host += L".invalid"; // RFC 2606 reserved non-existent TLD
    return {host};
}
win::Result<unsigned> resolve_random(const std::wstring &host) {
    static volatile LONG stalled = 0;
    return win::bounded<unsigned>(
        [host] {
            PDNS_RECORD records = nullptr;
            DNS_STATUS e = DnsQuery_W(host.c_str(), DNS_TYPE_A,
                                      DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE |
                                          DNS_QUERY_TREAT_AS_FQDN | DNS_QUERY_WIRE_ONLY,
                                      nullptr, &records, nullptr);
            struct Records {
                PDNS_RECORD p;
                ~Records() {
                    if (p)
                        DnsRecordListFree(p, DnsFreeRecordList);
                }
            } cleanup{records};
            if (e == DNS_ERROR_RCODE_NAME_ERROR || e == DNS_INFO_NO_RECORDS)
                return win::Result<unsigned>{0};
            if (e)
                return win::Result<unsigned>{0, win::last_error_message(e)};
            unsigned count = 0, visited = 0;
            for (auto p = records; p; p = p->pNext) {
                if (++visited > winlogic::kMaxRows)
                    return win::Result<unsigned>{0, "DNS record limit exceeded"};
                if (p->wType == DNS_TYPE_A)
                    ++count;
            }
            return win::Result<unsigned>{count};
        },
        winlogic::kQueryMs, stalled);
}
std::vector<Finding> dns_sinkhole(Context &ctx) {
    const char *id = "design.dns_sinkhole", *name = "DNS answers for two random invalid domains";
    if (!ctx.network)
        return {absent(id, name, "network checks disabled")};
    unsigned answered = 0;
    for (unsigned i = 0; i < 2; ++i) {
        auto host = random_host();
        if (!host.ok())
            return {fail(id, name, host.error)};
        auto r = resolve_random(host.value);
        if (!r.ok())
            return {fail(id, name, r.error)};
        answered += r.value > 0;
    }
    return {result(id, name, answered == 2, Ev().set("queried", 2).set("answered", answered),
                   Severity::High, 0.9)};
}
struct Internet {
    HINTERNET h = nullptr;
    ~Internet() {
        if (h)
            WinHttpCloseHandle(h);
    }
    explicit operator bool() const { return h != nullptr; }
};
struct Http {
    DWORD status = 0;
    std::string banner;
};
win::Result<Http> http(const std::wstring &host, const std::wstring &path, bool inspect_banner) {
    static volatile LONG stalled = 0;
    return win::bounded<Http>(
        [host, path, inspect_banner] {
            win::Result<Http> r;
            Internet session{WinHttpOpen(L"Perdedor/2", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                         WINHTTP_NO_PROXY_BYPASS, 0)};
            if (!session) {
                r.error = win::last_error_message();
                return r;
            }
            if (!WinHttpSetTimeouts(session.h, winlogic::kIoMs, winlogic::kIoMs, winlogic::kIoMs,
                                    winlogic::kIoMs)) {
                r.error = win::last_error_message();
                return r;
            }
            Internet connection{WinHttpConnect(session.h, host.c_str(), INTERNET_DEFAULT_HTTP_PORT, 0)};
            if (!connection) {
                r.error = win::last_error_message();
                return r;
            }
            Internet request{WinHttpOpenRequest(connection.h, L"GET", path.c_str(), nullptr,
                                                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0)};
            if (!request) {
                r.error = win::last_error_message();
                return r;
            }
            DWORD disabled =
                WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION | WINHTTP_DISABLE_COOKIES;
            if (!WinHttpSetOption(request.h, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof disabled)) {
                r.error = win::last_error_message();
                return r;
            }
            if (!WinHttpSendRequest(request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0,
                                    0, 0) ||
                !WinHttpReceiveResponse(request.h, nullptr)) {
                DWORD e = GetLastError();
                // NXDOMAIN is expected for .invalid. Timeouts and connection failures are inconclusive.
                r.absent = e == ERROR_WINHTTP_NAME_NOT_RESOLVED;
                if (!r.absent)
                    r.error = win::last_error_message(e);
                return r;
            }
            DWORD n = sizeof(r.value.status);
            if (!WinHttpQueryHeaders(request.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                     WINHTTP_HEADER_NAME_BY_INDEX, &r.value.status, &n,
                                     WINHTTP_NO_HEADER_INDEX)) {
                r.error = win::last_error_message();
                return r;
            }
            if (inspect_banner) {
                char body[kHttpBodyBytes];
                DWORD read = 0;
                if (!WinHttpReadData(request.h, body, sizeof body, &read)) {
                    r.error = win::last_error_message();
                    return r;
                }
                r.value.banner = winlogic::match(std::string(body, read), {"inetsim", "fakenet"});
            }
            return r;
        },
        kHttpBudgetMs, stalled);
}
std::vector<Finding> http_probe(Context &ctx, bool metadata) {
    const char *id = metadata ? "env.cloud_metadata_reachable" : "design.simulated_internet";
    const char *name = metadata ? "Cloud metadata endpoint response"
                                : "HTTP success or simulator banner for an invalid host";
    if (!ctx.network)
        return {absent(id, name, "network checks disabled")};
    auto host = metadata ? win::Result<std::wstring>{L"169.254.169.254"} : random_host();
    if (!host.ok())
        return {fail(id, name, host.error)};
    auto r = http(host.value, metadata ? L"/latest/meta-data/" : L"/", !metadata);
    if (!r.ok())
        return {fail(id, name, r.error, Severity::Medium)};
    return {result(id, name,
                   !r.absent &&
                       (metadata ? (r.value.status == 200 || r.value.status == 401 || r.value.status == 403)
                                 : (r.value.status == 200 || !r.value.banner.empty())),
                   Ev()
                       .set("status", r.value.status)
                       .set("nxdomain", r.absent)
                       .set("banner_signature", r.value.banner),
                   Severity::Medium, metadata ? 0.5 : 0.9)};
}
std::vector<Finding> proxy(Context &ctx, bool ie) {
    const char *id = ie ? "design.ie_proxy" : "design.winhttp_proxy",
               *name = ie ? "User proxy configuration" : "WinHTTP proxy configuration";
    bool configured = false, pac = false, auto_detect = false;
    if (ie) {
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG p{};
        if (!WinHttpGetIEProxyConfigForCurrentUser(&p))
            return {fail(id, name, win::last_error_message())};
        configured = p.lpszProxy && *p.lpszProxy;
        pac = p.lpszAutoConfigUrl && *p.lpszAutoConfigUrl;
        auto_detect = p.fAutoDetect;
        if (p.lpszProxy)
            GlobalFree(p.lpszProxy);
        if (p.lpszProxyBypass)
            GlobalFree(p.lpszProxyBypass);
        if (p.lpszAutoConfigUrl)
            GlobalFree(p.lpszAutoConfigUrl);
    } else {
        WINHTTP_PROXY_INFO p{};
        if (!WinHttpGetDefaultProxyConfiguration(&p))
            return {fail(id, name, win::last_error_message())};
        configured = p.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        if (p.lpszProxy)
            GlobalFree(p.lpszProxy);
        if (p.lpszProxyBypass)
            GlobalFree(p.lpszProxyBypass);
    }
    return {result(id, name, configured || pac,
                   Ev()
                       .set("explicit_proxy", configured)
                       .set("pac_configured", pac)
                       .set("auto_detect", auto_detect))};
}
std::vector<Finding> certificates(Context &ctx) {
    const char *id = "design.mitm_root_certificates", *name = "Interception root certificate labels";
    std::vector<std::string> hits;
    size_t examined = 0;
    for (DWORD location : {CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE}) {
        HCERTSTORE store =
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                          location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"ROOT");
        if (!store) {
            // CERT_STORE_OPEN_EXISTING_FLAG: a store that was never created holds no certificates.
            if (GetLastError() == ERROR_FILE_NOT_FOUND)
                continue;
            return {fail(id, name, win::last_error_message())};
        }
        struct Store {
            HCERTSTORE h;
            ~Store() { CertCloseStore(h, 0); }
        } cleanup{store};
        PCCERT_CONTEXT cert = nullptr;
        while ((cert = CertEnumCertificatesInStore(store, cert)) != nullptr) {
            if (++examined > winlogic::kMaxEntries) {
                CertFreeCertificateContext(cert);
                return {fail(id, name, "certificate enumeration limit exceeded")};
            }
            wchar_t label[1024];
            DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, label, 1024);
            if (n <= 1 || n > 1024)
                continue;
            auto s = winlogic::match(win::narrow(label), {"fiddler", "charles", "mitmproxy", "port swigger",
                                                          "portswigger", "burp", "inetsim", "fakenet"});
            if (!s.empty())
                hits.push_back(s);
        }
        if (GetLastError() != static_cast<DWORD>(CRYPT_E_NOT_FOUND))
            return {fail(id, name, win::last_error_message())};
    }
    return {result(id, name, !hits.empty(), matched(hits, examined), Severity::Medium, 0.75)};
}

// InviZzzible "mac" checks: vendor-specific OUI lists (vbox.conf / vmware.conf).
std::vector<Finding> mac_vendor(const char *id, const char *name, const std::vector<uint32_t> &ouis) {
    auto r = adapters();
    if (!r.ok())
        return {fail(id, name, r.error, Severity::Medium)};
    std::vector<std::string> hits;
    for (const auto &a : r.value) {
        if (a.mac.size() < 3)
            continue;
        uint32_t prefix = (uint32_t(a.mac[0]) << 16) | (uint32_t(a.mac[1]) << 8) | a.mac[2];
        if (std::find(ouis.begin(), ouis.end(), prefix) != ouis.end())
            hits.push_back(winlogic::oui(a.mac));
    }
    return {result(id, name, !hits.empty(), matched(hits, r.value.size()), Severity::Medium, 0.85,
                   "Assign MAC addresses from a physical vendor's OUI to the guest NICs.")};
}
std::vector<Finding> vbox_macs(Context &) {
    return mac_vendor("env.vbox_forbidden_macs", "vbox: Forbidden MACs", {0x080027});
}
std::vector<Finding> vmware_macs(Context &) {
    return mac_vendor("env.vmware_forbidden_macs", "vmware: Forbidden MACs", {0x000569, 0x000c29, 0x001c14, 0x005056});
}
std::vector<Finding> xen_macs(Context &) {
    // al-khaser xen_check_mac: 00:16:3E (Xen default OUI, also used by xl for generated MACs).
    return mac_vendor("env.xen_forbidden_macs", "xen: Forbidden MACs", {0x00163e});
}
std::vector<Finding> vmware_adapter(Context &) {
    const char *id = "env.vmware_adapter", *name = "vmware: Adapter";
    auto r = adapters();
    if (!r.ok())
        return {fail(id, name, r.error, Severity::Medium)};
    std::vector<std::string> hits;
    for (const auto &a : r.value)
        if (winlogic::contains(a.description, "VMware"))
            hits.push_back("VMware");
    return {result(id, name, !hits.empty(), matched(hits, r.value.size()), Severity::Medium, 0.85)};
}
// Cuckoo/CAPE result server: the in-guest analyzer streams results to TCP 2042
// (InviZzzible ResultserverConnection; Check Point network #4).
// https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/private/cwd/conf/cuckoo.conf
std::vector<Finding> resultserver(Context &ctx) {
    const char *id = "env.cuckoo_resultserver_connection", *name = "Cuckoo ResultServer connection";
    constexpr long long kResultServerPort = 2042;
    const auto port = ctx.param_int("analysis.resultserver_port", kResultServerPort);
    DWORD size = 0;
    DWORD e = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (e != ERROR_INSUFFICIENT_BUFFER && e != NO_ERROR)
        return {fail(id, name, win::last_error_message(e))};
    if (size > winlogic::kMaxBlob)
        return {fail(id, name, "TCP table exceeds size limit")};
    std::vector<BYTE> bytes(size + 4096);
    size = static_cast<DWORD>(bytes.size());
    e = GetExtendedTcpTable(bytes.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (e)
        return {fail(id, name, win::last_error_message(e))};
    auto *t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(bytes.data());
    unsigned hits = 0;
    for (DWORD i = 0; i < t->dwNumEntries; ++i)
        if (t->table[i].dwState == MIB_TCP_STATE_ESTAB &&
            ntohs(static_cast<u_short>(t->table[i].dwRemotePort)) == port)
            ++hits;
    return {result(id, name, hits > 0,
                   Ev().set("connections", static_cast<unsigned long long>(t->dwNumEntries))
                       .set("to_port", hits).set("port", port),
                   Severity::High, 0.8, "Move the result channel out of the guest network stack (agentless VMI).")};
}
// Provider name of the VirtualBox shared-folder redirector (pafish vbox_network_share,
// al-khaser vbox_network_share). mpr.dll is loaded at run time; no extra link dependency.
std::vector<Finding> vbox_shared_folders(Context &) {
    const char *id = "env.vbox_vbox_shared_folders", *name = "vbox: VBox Shared Folders";
    using Provider = DWORD(WINAPI *)(DWORD, LPWSTR, LPDWORD);
    HMODULE lib = win::system_library(L"mpr.dll");
    if (!lib)
        return {absent(id, name, "mpr.dll unavailable")};
    struct Lib {
        HMODULE h;
        ~Lib() { FreeLibrary(h); }
    } cleanup{lib};
    auto fn = win::proc<Provider>(lib, "WNetGetProviderNameW");
    if (!fn)
        return {absent(id, name, "WNetGetProviderNameW unavailable")};
    constexpr DWORD kWnncNetRdr2Sample = 0x00250000; // WNNC_NET_RDR2SAMPLE (winnetwk.h)
    wchar_t provider[256]{};
    DWORD n = 256;
    DWORD e = fn(kWnncNetRdr2Sample, provider, &n);
    if (e == ERROR_NO_NETWORK || e == ERROR_NOT_SUPPORTED || e == ERROR_BAD_PROVIDER)
        return {result(id, name, false, Ev().set("provider", ""))};
    if (e != NO_ERROR)
        return {fail(id, name, win::last_error_message(e))};
    auto text = win::narrow(provider);
    return {result(id, name, winlogic::contains(text, "VirtualBox Shared Folders"),
                   Ev().set("provider", text), Severity::High, 0.95)};
}

std::vector<Finding> adapter_0(Context &ctx) { return adapter_check(ctx, 0); }

std::vector<Finding> adapter_1(Context &ctx) { return adapter_check(ctx, 1); }

std::vector<Finding> adapter_2(Context &ctx) { return adapter_check(ctx, 2); }

std::vector<Finding> adapter_3(Context &ctx) { return adapter_check(ctx, 3); }

std::vector<Finding> adapter_4(Context &ctx) { return adapter_check(ctx, 4); }

std::vector<Finding> adapter_5(Context &ctx) { return adapter_check(ctx, 5); }
std::vector<Finding> metadata(Context &ctx) { return http_probe(ctx, true); }
std::vector<Finding> simulated(Context &ctx) { return http_probe(ctx, false); }
std::vector<Finding> ie_proxy(Context &ctx) { return proxy(ctx, true); }
std::vector<Finding> winhttp_proxy(Context &ctx) { return proxy(ctx, false); }
} // namespace
PERDEDOR_REGISTER(adapter_0, "network.mac_oui", "fast", false, "design.mac_oui");
PERDEDOR_REGISTER(adapter_1, "network.adapter_count", "fast", false, "design.adapter_count");
PERDEDOR_REGISTER(adapter_2, "network.adapter_count", "fast", false, "design.no_wifi_adapter");
PERDEDOR_REGISTER(adapter_3, "network.default_subnets", "fast", false, "design.default_subnets");
PERDEDOR_REGISTER(adapter_4, "network.default_subnets", "fast", false, "design.default_gateways");
PERDEDOR_REGISTER(adapter_5, "network.adapter_count", "fast", false, "design.adapter_descriptions");
PERDEDOR_REGISTER(dns_cache, "wear_and_tear.network_history", "medium", false, "behavioural.dns_cache");
PERDEDOR_REGISTER(arp_cache, "wear_and_tear.network_history", "fast", false, "behavioural.arp_cache");
PERDEDOR_REGISTER(listening_ports, "analysis_tools.listening_ports", "fast", false,
                  "design.agent_listening_ports");
PERDEDOR_REGISTER(certificates, "network.proxy_mitm", "medium", false, "design.mitm_root_certificates");
PERDEDOR_REGISTER(ie_proxy, "network.proxy_mitm", "fast", false, "design.ie_proxy");
PERDEDOR_REGISTER(winhttp_proxy, "network.proxy_mitm", "fast", false, "design.winhttp_proxy");
PERDEDOR_REGISTER(vbox_macs, "network.mac_oui", "fast", false, "env.vbox_forbidden_macs");
PERDEDOR_REGISTER(vmware_macs, "network.mac_oui", "fast", false, "env.vmware_forbidden_macs");
PERDEDOR_REGISTER(xen_macs, "network.mac_oui", "fast", false, "env.xen_forbidden_macs");
PERDEDOR_REGISTER(vmware_adapter, "hardware.nic_identity", "fast", false, "env.vmware_adapter");
PERDEDOR_REGISTER(resultserver, "analysis_tools.listening_ports", "fast", false, "env.cuckoo_resultserver_connection");
PERDEDOR_REGISTER(vbox_shared_folders, "guest_tools.services", "fast", false, "env.vbox_vbox_shared_folders");
PERDEDOR_REGISTER(dns_sinkhole, "network.dns_sinkhole", "medium", true, "design.dns_sinkhole");
PERDEDOR_REGISTER(metadata, "network.cloud_metadata", "medium", true, "env.cloud_metadata_reachable");
PERDEDOR_REGISTER(simulated, "network.simulated_internet", "medium", true, "design.simulated_internet");
} // namespace perdedor
