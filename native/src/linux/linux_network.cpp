// Network tells on Linux: MAC OUIs, default sandbox subnets and resolvers,
// isolation, DNS sinkholes, simulated internet, cloud metadata, adapters,
// proxies and interception CAs.
//
// Probes that send packets are registered with network=true and only contact
// the configured resolver (for random non-existent names), the address such a
// name resolves to, 169.254.169.254, or hosts the operator passes.
//
// Sources: v1 Linux agent (MAC_OUI_SIGNATURES, CLOUD_METADATA_URL); VMAware
// v2.8.2 MAC; al-khaser check_mac_addr; QEMU networking documentation (user
// mode 10.0.2.0/24, gateway 10.0.2.2, DNS 10.0.2.3); libvirt default network
// 192.168.122.0/24; VirtualBox host-only 192.168.56.0/24; Docker bridge
// 172.17.0.0/16 and embedded DNS 127.0.0.11; Azure 168.63.129.16; AWS
// 169.254.169.253; RFC 1035 message format.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>

#include "linux_util.hpp"

namespace perdedor {
namespace {
using namespace linuxutil;

constexpr int kDnsTimeoutMs = 2000;    // per query; resolvers answer NXDOMAIN in well under a second
constexpr int kTcpTimeoutMs = 2000;    // connect + response; v1 used 1 s for the metadata service
constexpr size_t kRandomLabel = 16;    // 26^16 names: a random .com label is unregistered
constexpr int kDnsPort = 53, kHttpPort = 80;

struct Subnet {
    const char* net;
    int bits;
    const char* what;
};
const std::vector<Subnet>& sandbox_subnets() {
    static const std::vector<Subnet> s = {{"10.0.2.0", 24, "QEMU user-mode networking (slirp)"},
        {"192.168.122.0", 24, "libvirt default network"}, {"192.168.56.0", 24, "VirtualBox host-only / Cuckoo default"},
        {"172.17.0.0", 16, "Docker default bridge"}};
    return s;
}

std::vector<Finding> mac_oui(Context& ctx) {
    const char* id = "design.mac_oui";
    const char* name = "NIC MAC address OUI";
    const char* desc = "Compares the first 3 octets of each NIC's MAC against virtual-NIC vendor prefixes (and "
                       "Docker's locally administered 02:42 prefix).";
    // v1 MAC_OUI_SIGNATURES plus Parallels 00:1c:42 (VMAware MAC).
    static const std::map<std::string, std::string> ouis = {{"52:54:00", "QEMU/KVM"}, {"08:00:27", "VirtualBox"},
        {"0a:00:27", "VirtualBox host-only"}, {"00:0c:29", "VMware"}, {"00:50:56", "VMware"}, {"00:1c:14", "VMware"},
        {"00:05:69", "VMware"}, {"00:16:3e", "Xen"}, {"00:03:ff", "Microsoft Virtual PC/Hyper-V"},
        {"00:15:5d", "Microsoft Hyper-V"}, {"00:1c:42", "Parallels"}};
    Root root(ctx);
    auto l = root.list("/sys/class/net");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Medium, l.err, "/sys/class/net")};
    Evidence e;
    for (const auto& n : l.names) {
        if (n == "lo") continue;
        bool ok;
        std::string mac = lower(read_value(root, "/sys/class/net/" + n + "/address", ok));
        if (!ok || mac.size() != 17) continue;
        ++e.observed;
        auto it = ouis.find(mac.substr(0, 8));
        if (it != ouis.end()) e.add(n + "=" + mac.substr(0, 8) + ":xx:xx:xx (" + it->second + ")");
        else if (mac.rfind("02:42:", 0) == 0) e.add(n + "=02:42:xx (Docker)");
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no network interfaces with a MAC")};
    return {e.finding(id, name, desc, Severity::Medium,
                      "Assign a MAC from a real NIC vendor's OUI (Xen: vif=['mac=...'] in xl.cfg).")};
}

struct Route {
    std::string iface;
    uint32_t dest = 0, gw = 0, mask = 0;
};
std::vector<Route> routes(const Root& root, bool& ok) {
    std::vector<Route> out;
    auto r = root.read("/proc/net/route");
    ok = r.ok;
    if (!r.ok) return out;
    auto ls = lines(r.value);
    for (size_t i = 1; i < ls.size(); ++i) {
        auto f = split(trim(ls[i]), '\t');
        std::vector<std::string> g;
        for (auto& x : f)
            if (!trim(x).empty()) g.push_back(trim(x));
        long long d, gw, m;
        if (g.size() < 8 || !number(g[1], d, 16) || !number(g[2], gw, 16) || !number(g[7], m, 16)) continue;
        // /proc/net/route prints addresses in host byte order of a network-order u32 (little-endian on x86).
        out.push_back({g[0], static_cast<uint32_t>(d), static_cast<uint32_t>(gw), static_cast<uint32_t>(m)});
    }
    return out;
}
std::string ip4(uint32_t raw) {
    char b[INET_ADDRSTRLEN];
    in_addr a{raw};
    inet_ntop(AF_INET, &a, b, sizeof b);
    return b;
}
bool in_subnet(uint32_t raw, const Subnet& s) {
    in_addr n{};
    inet_pton(AF_INET, s.net, &n);
    uint32_t mask = s.bits ? htonl(~0u << (32 - s.bits)) : 0;
    return (raw & mask) == (n.s_addr & mask);
}

std::vector<Finding> default_subnet(Context& ctx) {
    const char* id = "design.default_subnet";
    const char* name = "Default sandbox subnet";
    const char* desc = "The network behind the default route is a well-known emulator/sandbox default (QEMU slirp "
                       "10.0.2.0/24 with gateway 10.0.2.2, libvirt 192.168.122.0/24, VirtualBox/Cuckoo "
                       "192.168.56.0/24, Docker 172.17.0.0/16). Host-side bridges are ignored.";
    Root root(ctx);
    bool ok;
    auto rs = routes(root, ok);
    if (!ok) return {unreadable(id, name, desc, Severity::Medium, ENOENT, "/proc/net/route")};
    std::vector<std::string> ifaces;
    Evidence e;
    for (const auto& r : rs)
        if (r.dest == 0 && r.mask == 0) {
            ifaces.push_back(r.iface);
            ++e.observed;
            for (const auto& s : sandbox_subnets())
                if (in_subnet(r.gw, s)) e.add("gateway " + ip4(r.gw) + " (" + s.what + ")");
        }
    for (const auto& r : rs)
        for (const auto& i : ifaces)
            if (r.iface == i && r.mask != 0)
                for (const auto& s : sandbox_subnets())
                    if (in_subnet(r.dest, s)) e.add(i + " " + ip4(r.dest) + " (" + s.what + ")");
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no IPv4 default route")};
    return {e.finding(id, name, desc, Severity::Medium,
                      "Address the analysis network like an office or home LAN (CHIMERA: choose a non-default "
                      "subnet for the INetSim bridge).")};
}

std::vector<std::string> nameservers(const Root& root, bool& ok) {
    std::vector<std::string> out;
    auto r = root.read("/etc/resolv.conf");
    ok = r.ok;
    if (!r.ok) return out;
    for (const auto& l : lines(r.value)) {
        auto t = trim(l);
        if (t.rfind("nameserver", 0) != 0) continue;
        auto parts = split(t, ' ');
        for (size_t i = 1; i < parts.size(); ++i)
            if (!trim(parts[i]).empty()) { out.push_back(trim(parts[i])); break; }
    }
    return out;
}

std::vector<Finding> dns_resolver(Context& ctx) {
    const char* id = "design.dns_resolver_address";
    const char* name = "Sandbox or cloud DNS resolver";
    const char* desc = "/etc/resolv.conf points at a well-known emulator, container or cloud resolver address.";
    static const std::map<std::string, std::string> known = {{"10.0.2.3", "QEMU slirp DNS"},
        {"192.168.122.1", "libvirt dnsmasq"}, {"127.0.0.11", "Docker embedded DNS"},
        {"168.63.129.16", "Azure platform DNS"}, {"169.254.169.253", "AWS VPC resolver"},
        {"169.254.169.254", "GCE metadata resolver"}, {"192.168.56.1", "VirtualBox host-only host"}};
    Root root(ctx);
    bool ok;
    auto ns = nameservers(root, ok);
    if (!ok) return {skipped(id, name, desc, Severity::Medium, "no /etc/resolv.conf")};
    Evidence e;
    e.observed = ns.size() + 1;
    for (const auto& n : ns) {
        auto it = known.find(n);
        if (it != known.end()) e.add(n + " (" + it->second + ")");
    }
    return {e.finding(id, name, desc, Severity::Medium, "Serve DNS from an address that fits the simulated LAN.")};
}

std::vector<Finding> default_route(Context& ctx) {
    const char* id = "design.no_default_route";
    const char* name = "No default route";
    const char* desc = "Neither /proc/net/route nor /proc/net/ipv6_route has a default route: the machine is cut off, "
                       "as isolated analysis guests often are.";
    Root root(ctx);
    bool ok;
    auto rs = routes(root, ok);
    if (!ok) return {unreadable(id, name, desc, Severity::Medium, ENOENT, "/proc/net/route")};
    bool def = false;
    for (const auto& r : rs)
        if (r.dest == 0 && r.mask == 0) def = true;
    auto v6 = root.read("/proc/net/ipv6_route");
    if (v6.ok)
        for (const auto& l : lines(v6.value))
            if (l.rfind("00000000000000000000000000000000 00 ", 0) == 0 && l.find(" lo") == std::string::npos) def = true;
    return {bool_check(id, name, desc, Severity::Medium, !def, def ? "default route present" : "no default route",
                       "Give the guest a default route to the simulated internet (INetSim gateway).")};
}

// ---- minimal DNS client (RFC 1035) ----

std::string random_name(const std::string& tld) {
    unsigned char b[kRandomLabel];
    if (getrandom(b, sizeof b, 0) != static_cast<ssize_t>(sizeof b))
        for (size_t i = 0; i < sizeof b; ++i) b[i] = static_cast<unsigned char>(std::rand());
    std::string s;
    for (unsigned char c : b) s += static_cast<char>('a' + c % 26);
    return s + "." + tld;
}

bool sockaddr_for(const std::string& ip, int port, sockaddr_storage& ss, socklen_t& len) {
    std::memset(&ss, 0, sizeof ss);
    auto* a4 = reinterpret_cast<sockaddr_in*>(&ss);
    auto* a6 = reinterpret_cast<sockaddr_in6*>(&ss);
    std::string host = ip.substr(0, ip.find('%'));
    if (inet_pton(AF_INET, host.c_str(), &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons(static_cast<uint16_t>(port));
        len = sizeof *a4;
        return true;
    }
    if (inet_pton(AF_INET6, host.c_str(), &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(static_cast<uint16_t>(port));
        len = sizeof *a6;
        return true;
    }
    return false;
}

struct DnsAnswer {
    bool replied = false;
    int rcode = -1;
    int answers = 0;
    std::string first_a;
    std::string error;
};

size_t skip_name(const std::string& m, size_t p) {
    while (p < m.size()) {
        unsigned char l = static_cast<unsigned char>(m[p]);
        if (l == 0) return p + 1;
        if ((l & 0xc0) == 0xc0) return p + 2;
        p += l + 1;
    }
    return std::string::npos;
}

DnsAnswer dns_query(const std::string& server, const std::string& qname, int timeout_ms) {
    DnsAnswer out;
    sockaddr_storage ss;
    socklen_t len;
    if (!sockaddr_for(server, kDnsPort, ss, len)) { out.error = "unusable nameserver address"; return out; }
    uint16_t qid;
    if (getrandom(&qid, sizeof qid, 0) != sizeof qid) qid = static_cast<uint16_t>(std::rand());
    std::string q;
    q += static_cast<char>(qid >> 8);
    q += static_cast<char>(qid & 0xff);
    q += std::string("\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);  // RD, QDCOUNT=1
    for (const auto& label : split(qname, '.')) {
        q += static_cast<char>(label.size());
        q += label;
    }
    q += std::string("\x00\x00\x01\x00\x01", 5);  // root, QTYPE=A, QCLASS=IN
    int fd = socket(ss.ss_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { out.error = std::strerror(errno); return out; }
    if (connect(fd, reinterpret_cast<sockaddr*>(&ss), len) != 0 || send(fd, q.data(), q.size(), 0) < 0) {
        out.error = std::strerror(errno);
        close(fd);
        return out;
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    std::string m;
    while (std::chrono::steady_clock::now() < deadline) {
        int left = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
        pollfd p{fd, POLLIN, 0};
        if (poll(&p, 1, left > 0 ? left : 0) <= 0) break;
        char buf[1500];
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n < 12) {
            if (n < 0 && errno != EAGAIN) { out.error = std::strerror(errno); break; }
            continue;
        }
        if (static_cast<uint8_t>(buf[0]) != (qid >> 8) || static_cast<uint8_t>(buf[1]) != (qid & 0xff)) continue;
        m.assign(buf, static_cast<size_t>(n));
        break;
    }
    close(fd);
    if (m.empty()) {
        if (out.error.empty()) out.error = "no reply";
        return out;
    }
    out.replied = true;
    out.rcode = static_cast<uint8_t>(m[3]) & 0x0f;
    out.answers = (static_cast<uint8_t>(m[6]) << 8) | static_cast<uint8_t>(m[7]);
    size_t p = skip_name(m, 12);
    if (p != std::string::npos) p += 4;
    for (int i = 0; i < out.answers && p != std::string::npos && p < m.size(); ++i) {
        p = skip_name(m, p);
        if (p == std::string::npos || p + 10 > m.size()) break;
        unsigned type = (static_cast<uint8_t>(m[p]) << 8) | static_cast<uint8_t>(m[p + 1]);
        unsigned rdlen = (static_cast<uint8_t>(m[p + 8]) << 8) | static_cast<uint8_t>(m[p + 9]);
        p += 10;
        if (p + rdlen > m.size()) break;
        if (type == 1 && rdlen == 4 && out.first_a.empty()) {
            uint32_t raw;
            std::memcpy(&raw, m.data() + p, 4);
            out.first_a = ip4(raw);
        }
        p += rdlen;
    }
    return out;
}

// One short HTTP exchange; returns the status line and Server header, or an error.
struct Http {
    bool answered = false;
    std::string status, server, error;
};
Http http_probe(const std::string& ip, int port, const std::string& host, const std::string& path, int timeout_ms) {
    Http h;
    sockaddr_storage ss;
    socklen_t len;
    if (!sockaddr_for(ip, port, ss, len)) { h.error = "bad address"; return h; }
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { h.error = std::strerror(errno); return h; }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    auto left = [&]() {
        long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        return static_cast<int>(ms > 0 ? ms : 0);
    };
    if (connect(fd, reinterpret_cast<sockaddr*>(&ss), len) != 0 && errno != EINPROGRESS) {
        h.error = std::strerror(errno);
        close(fd);
        return h;
    }
    pollfd p{fd, POLLOUT, 0};
    int err = 0;
    socklen_t el = sizeof err;
    if (poll(&p, 1, left()) <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
        h.error = err ? std::strerror(err) : "connect timeout";
        close(fd);
        return h;
    }
    std::string req = "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
    if (send(fd, req.data(), req.size(), MSG_NOSIGNAL) < 0) {
        h.error = std::strerror(errno);
        close(fd);
        return h;
    }
    std::string resp;
    while (resp.size() < 2048) {
        pollfd r{fd, POLLIN, 0};
        if (poll(&r, 1, left()) <= 0) break;
        char buf[1024];
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) break;
        resp.append(buf, static_cast<size_t>(n));
        if (resp.find("\r\n\r\n") != std::string::npos) break;
    }
    close(fd);
    if (resp.rfind("HTTP/", 0) != 0) { h.error = resp.empty() ? "no response" : "non-HTTP response"; return h; }
    h.answered = true;
    auto ls = lines(resp);
    h.status = trim(ls[0]).substr(0, 60);
    for (const auto& l : ls)
        if (lower(l).rfind("server:", 0) == 0) h.server = trim(l.substr(7)).substr(0, 60);
    return h;
}

std::vector<Finding> dns_sinkhole(Context& ctx) {
    const char* id = "design.dns_sinkhole";
    const char* name = "DNS answers non-existent names";
    const char* desc = "Two random, unregistered names are resolved through the configured resolver; a real "
                       "resolver returns NXDOMAIN, a sinkhole (INetSim, FakeNet) returns an address.";
    Root root(ctx);
    if (root.fixture()) return {skipped(id, name, desc, Severity::High, "network probes are not run against an alternate root")};
    bool ok;
    auto ns = nameservers(root, ok);
    std::string server = ctx.param("network.dns_server", ns.empty() ? "" : ns[0]);
    if (server.empty()) return {skipped(id, name, desc, Severity::High, "no nameserver configured")};
    std::string tld = ctx.param("network.random_tld", "com");
    int timeout = static_cast<int>(ctx.param_int("network.dns_timeout_ms", kDnsTimeoutMs));
    int answered = 0, replied = 0;
    Json probes = Json::array();
    for (int i = 0; i < 2; ++i) {
        std::string n = random_name(tld);
        auto a = dns_query(server, n, timeout);
        Json p = Json::object();
        p.set("rcode", a.rcode);
        p.set("answers", a.answers);
        if (!a.error.empty()) p.set("error", a.error);
        probes.push(p);
        if (a.replied) ++replied;
        if (a.replied && a.rcode == 0 && a.answers > 0) ++answered;
    }
    Json ev = Json::object();
    ev.set("server", server);
    ev.set("probes", probes);
    if (!replied) return {skipped(id, name, desc, Severity::High, "resolver did not reply")};
    return {bool_check(id, name, desc, Severity::High, answered == 2, ev,
                       "Make the fake DNS return NXDOMAIN for names it does not simulate (INetSim: "
                       "dns_default_ip only for listed zones; or forward unknown names to a real resolver).")};
}

std::vector<Finding> simulated_internet(Context& ctx) {
    const char* id = "design.simulated_internet";
    const char* name = "Simulated internet answers random hosts";
    const char* desc = "A random unregistered name is resolved and, if it resolves, HTTP is requested from it: an "
                       "answer means a simulated internet (INetSim/FakeNet banner in Server).";
    Root root(ctx);
    if (root.fixture()) return {skipped(id, name, desc, Severity::High, "network probes are not run against an alternate root")};
    bool ok;
    auto ns = nameservers(root, ok);
    std::string server = ctx.param("network.dns_server", ns.empty() ? "" : ns[0]);
    if (server.empty()) return {skipped(id, name, desc, Severity::High, "no nameserver configured")};
    std::string host = random_name(ctx.param("network.random_tld", "com"));
    auto a = dns_query(server, host, static_cast<int>(ctx.param_int("network.dns_timeout_ms", kDnsTimeoutMs)));
    Json ev = Json::object();
    ev.set("rcode", a.rcode);
    if (!a.replied) return {skipped(id, name, desc, Severity::High, "resolver did not reply")};
    if (a.first_a.empty()) {
        ev.set("resolved", false);
        return {clean(id, name, desc, Severity::High, ev)};
    }
    ev.set("resolved", a.first_a);
    auto h = http_probe(a.first_a, kHttpPort, host, "/", static_cast<int>(ctx.param_int("network.tcp_timeout_ms", kTcpTimeoutMs)));
    ev.set("http", h.answered ? h.status : h.error);
    if (!h.server.empty()) ev.set("server_header", h.server);
    return {bool_check(id, name, desc, Severity::High, h.answered, ev,
                       "Answer only for simulated hosts; return connection errors for random names, and replace the "
                       "INetSim default banner.")};
}

std::vector<Finding> cloud_metadata(Context& ctx) {
    const char* id = "env.cloud_metadata_reachable";
    const char* name = "Cloud instance-metadata endpoint";
    const char* desc = "A short-timeout HTTP request to http://169.254.169.254/latest/meta-data/ -- reachability "
                       "alone identifies a cloud VM.";
    Root root(ctx);
    if (root.fixture()) return {skipped(id, name, desc, Severity::Medium, "network probes are not run against an alternate root")};
    auto h = http_probe("169.254.169.254", kHttpPort, "169.254.169.254", "/latest/meta-data/",
                        static_cast<int>(ctx.param_int("network.tcp_timeout_ms", kTcpTimeoutMs)));
    Json ev = Json::object();
    ev.set("result", h.answered ? h.status : h.error);
    return {bool_check(id, name, desc, Severity::Medium, h.answered, ev,
                       "Block 169.254.169.254 from the analysis guest.")};
}

std::vector<Finding> adapters(Context& ctx) {
    const char* id = "design.network_adapters";
    const char* name = "Single wired adapter, no Wi-Fi";
    const char* desc = "Exactly one hardware network adapter and no wireless interface (/sys/class/net/*/wireless, "
                       "phy80211): VMs get one virtual NIC, laptops have Wi-Fi.";
    Root root(ctx);
    auto l = root.list("/sys/class/net");
    if (!l.ok) return {unreadable(id, name, desc, Severity::Low, l.err, "/sys/class/net")};
    long long hw = 0, wifi = 0;
    for (const auto& n : l.names) {
        if (n == "lo" || !root.exists("/sys/class/net/" + n + "/device")) continue;
        ++hw;
        if (root.exists("/sys/class/net/" + n + "/wireless") || root.exists("/sys/class/net/" + n + "/phy80211")) ++wifi;
    }
    Json ev = Json::object();
    ev.set("hardware_adapters", hw);
    ev.set("wireless", wifi);
    auto f = bool_check(id, name, desc, Severity::Low, hw <= 1 && wifi == 0, ev,
                        "Add a second (e.g. Wi-Fi-named) adapter to match a laptop identity.");
    f.confidence = 0.3;
    return {f};
}

std::vector<Finding> proxy_env(Context& ctx) {
    const char* id = "design.proxy_environment";
    const char* name = "Proxy configured";
    const char* desc = "http(s)_proxy/ALL_PROXY in the environment or /etc/environment, or an APT proxy: traffic "
                       "may be routed through an interception proxy. Only variable names and host:port are kept.";
    Root root(ctx);
    Evidence e;
    e.observed = 1;
    auto strip = [](std::string v) {
        auto at = v.rfind('@');
        if (at != std::string::npos) v = v.substr(at + 1);
        auto scheme = v.find("://");
        if (scheme != std::string::npos && at == std::string::npos) v = v.substr(scheme + 3);
        return v.substr(0, v.find('/')).substr(0, 60);
    };
    auto env = root.environment();
    for (const char* k : {"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"})
        if (env.count(k) && !env[k].empty()) e.add(std::string(k) + "=" + strip(env[k]));
    auto etc = root.read("/etc/environment");
    if (etc.ok)
        for (const auto& l : lines(etc.value))
            if (lower(l).find("_proxy=") != std::string::npos) e.add("/etc/environment " + lower(trim(l)).substr(0, l.find('=')));
    auto apt = root.list("/etc/apt/apt.conf.d");
    for (const auto& n : apt.names) {
        auto r = root.read("/etc/apt/apt.conf.d/" + n);
        if (r.ok && r.value.find("::Proxy") != std::string::npos) e.add("apt proxy in " + n);
    }
    return {e.finding(id, name, desc, Severity::Low, "Route traffic transparently instead of through a configured proxy.")};
}

std::vector<Finding> mitm_ca(Context& ctx) {
    const char* id = "design.mitm_ca_certificates";
    const char* name = "Interception proxy CA installed";
    const char* desc = "Locally added CA certificates named after interception tools (mitmproxy, Burp/PortSwigger, "
                       "Charles, Fiddler, OWASP ZAP, INetSim, FakeNet). File names only.";
    static const std::vector<std::string> sigs = {"mitmproxy", "burp", "portswigger", "charles", "fiddler", "zap",
        "owasp", "inetsim", "fakenet", "telerik"};
    Root root(ctx);
    Evidence e;
    for (const char* d : {"/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors",
                          "/etc/ca-certificates/trust-source/anchors"}) {
        auto w = root.walk(d, 2);
        if (!root.exists(d)) continue;
        ++e.observed;
        for (const auto& f : w.names)
            if (!match(basename(f), sigs).empty()) e.add(f);
    }
    if (!e.observed) return {skipped(id, name, desc, Severity::Medium, "no local CA directories")};
    return {e.finding(id, name, desc, Severity::Medium, "Use a CA named like a corporate inspection CA, or none.")};
}

}  // namespace

PERDEDOR_REGISTER(mac_oui, "network.mac_oui", "fast", false, "design.mac_oui");
PERDEDOR_REGISTER(default_subnet, "network.default_subnets", "fast", false, "design.default_subnet");
PERDEDOR_REGISTER(dns_resolver, "network.default_subnets", "fast", false, "design.dns_resolver_address");
PERDEDOR_REGISTER(default_route, "network.connectivity", "fast", false, "design.no_default_route");
PERDEDOR_REGISTER(dns_sinkhole, "network.dns_sinkhole", "medium", true, "design.dns_sinkhole");
PERDEDOR_REGISTER(simulated_internet, "network.simulated_internet", "medium", true, "design.simulated_internet");
PERDEDOR_REGISTER(cloud_metadata, "network.cloud_metadata", "medium", true, "env.cloud_metadata_reachable");
PERDEDOR_REGISTER(adapters, "network.adapter_count", "fast", false, "design.network_adapters");
PERDEDOR_REGISTER(proxy_env, "network.proxy_mitm", "fast", false, "design.proxy_environment");
PERDEDOR_REGISTER(mitm_ca, "network.proxy_mitm", "fast", false, "design.mitm_ca_certificates");

}  // namespace perdedor
