"""Network tells: emulator addressing, hypervisor MAC OUIs, interception
proxies and CAs, VPNs, connectivity, DNS sinkholes and simulated internet.

The only network probes (network=True) resolve and contact random,
non-existent domain names, so they reach nothing on the real internet; on a
sandbox with INetSim-style DNS/HTTP they reach the simulator, which is the
point.
"""

from __future__ import annotations

import re
import secrets

from perdedor_common.models import Severity
from perdedor_common.registry import RunContext

from .. import signatures as sig
from ..adb import Device, shell_quote
from ._base import Checks, ProbeError, Skip, Verdict, need, props, settings, substr_hits

REG = Checks()

PROBE_TIMEOUT_S = 3  # per DNS/HTTP probe on the device; DESIGN-V2 asks for short network timeouts
# A system CA whose file is newer than the build by more than this was added
# after the image was built (AOSP stamps all cacerts files at build time).
CA_ADDED_AFTER_BUILD_S = 86400


def _random_domain() -> str:
    return f"{secrets.token_hex(8)}.invalid"


def _addresses(dev: Device) -> str:
    return need(dev.sh("ip addr show") or dev.sh("ifconfig"), "interface addresses")


@REG.check(
    "android.design.emulator_gateway_dns",
    "network.default_subnets",
    name="Emulator gateway and DNS (10.0.2.2 / 10.0.2.3)",
    description="Default route via 10.0.2.2 or DNS 10.0.2.3 - the emulator's user-mode NAT router and DNS "
    "forwarder (developer.android.com, emulator networking).",
    severity=Severity.HIGH,
    remediation="Use an analysis network with its own addressing instead of the emulator's slirp NAT.",
)
def check_emulator_gateway_dns(dev: Device, ctx: RunContext) -> Verdict:
    routes = dev.sh("ip route show table all", any_rc=True) or dev.sh("ip route", any_rc=True) or ""
    values = props(dev)
    dns = [values.get(f"net.dns{i}", "") for i in (1, 2)] + [values.get("net.eth0.dns1", "")]
    gw_hit = f"via {sig.AVD_GATEWAY} " in routes or f"via {sig.AVD_GATEWAY}\n" in routes
    dns_hit = [d for d in dns if d in sig.AVD_DNS]
    return Verdict(
        gw_hit or bool(dns_hit), {"gateway_10_0_2_2": gw_hit, "dns": [d for d in dns if d] or None}
    )


@REG.check(
    "android.design.vm_default_subnets",
    "network.default_subnets",
    name="Virtualisation default subnets",
    description="Addresses in VirtualBox NAT/host-only (10.0.3.0/24, 192.168.56.0/24), libvirt "
    "(192.168.122.0/24), Waydroid (192.168.240.0/24) or Docker (172.17.0.0/16) default ranges.",
    severity=Severity.MEDIUM,
    remediation="Address the analysis network from a range home and mobile networks use (e.g. 192.168.1.0/24).",
)
def check_vm_default_subnets(dev: Device, ctx: RunContext) -> Verdict:
    text = _addresses(dev)
    addrs = re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", text)
    hits = {a: name for a in addrs for prefix, name in sig.VM_DEFAULT_SUBNETS.items() if a.startswith(prefix)}
    return Verdict(
        bool(hits), {"addresses": [a for a in addrs if not a.startswith("127.")], "matched": hits or None}
    )


@REG.check(
    "android.design.mac_oui",
    "network.mac_oui",
    name="Hypervisor MAC address OUI",
    description="Interface MAC prefixes of virtual NICs: 52:54:00 QEMU/KVM, 08:00:27 VirtualBox, 00:16:3e Xen, "
    "00:0c:29/00:50:56 VMware, 00:15:5d Hyper-V.",
    severity=Severity.HIGH,
    remediation="Assign the guest NIC a MAC from a phone vendor OUI (or a locally administered random MAC, "
    "as Android uses for Wi-Fi).",
)
def check_mac_oui(dev: Device, ctx: RunContext) -> Verdict:
    text = dev.sh("cat /sys/class/net/*/address 2>/dev/null", any_rc=True)
    if not text:
        text = _addresses(dev)
    macs = sorted({m.lower() for m in re.findall(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", text)})
    macs = [m for m in macs if m not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")]
    if not macs:
        raise ProbeError("no MAC addresses readable")
    hits = {m: sig.VM_MAC_OUIS[m[:8]] for m in macs if m[:8] in sig.VM_MAC_OUIS}
    return Verdict(bool(hits), {"macs": len(macs), "matched": hits or None})


@REG.check(
    "android.design.http_proxy",
    "network.proxy_mitm",
    name="Global HTTP proxy",
    description="settings global http_proxy / global_http_proxy_host set: traffic goes through an interception "
    "proxy (MobSF sets http_proxy to its mitmproxy).",
    severity=Severity.HIGH,
    remediation="Intercept transparently at the network layer (routing/iptables on the analysis bridge) "
    "instead of configuring a device proxy.",
)
def check_http_proxy(dev: Device, ctx: RunContext) -> Verdict:
    glob = settings(dev, "global")
    values = {k: glob.get(k, "") for k in ("http_proxy", "global_http_proxy_host", "global_http_proxy_port")}
    values["net.gprs.http-proxy"] = props(dev).get("net.gprs.http-proxy", "")
    set_values = {k: v for k, v in values.items() if v and v not in ("null", ":0", "0", "")}
    return Verdict(bool(set_values), set_values or None)


@REG.check(
    "android.design.mitm_ca_certificates",
    "network.proxy_mitm",
    name="Interception CA certificates",
    description="CA files in the system store named after interception proxies (mitmproxy, PortSwigger, "
    "Charles, Fiddler, ZAP, HTTP Toolkit). A PEM header or recent update alone is not interception evidence.",
    severity=Severity.HIGH,
    remediation="Do not install the interception CA on the device; decrypt with app-level instrumentation "
    "only when needed, and remove it before snapshots.",
    cost="medium",
)
def check_mitm_ca(dev: Device, ctx: RunContext) -> Verdict:
    stores = ("/system/etc/security/cacerts", "/apex/com.android.conscrypt/cacerts")
    hits = []
    readable = False
    for store in stores:
        listing = dev.listdir(store)
        if listing is None:
            continue
        readable = True
        result = dev.run(f"grep -l -i -E {shell_quote('|'.join(sig.MITM_CA_TOKENS))} {store}/* 2>/dev/null")
        if result is None or result.returncode not in (0, 1):
            continue
        hits.extend(result.stdout.splitlines())
    if not readable:
        raise Skip("system CA store is not readable")
    return Verdict(bool(hits), {"matching_certificates": hits}, confidence=0.7)


@REG.check(
    "android.design.vpn_active",
    "network.proxy_mitm",
    name="VPN active",
    description="A VPN (tun/ppp interface, or a VPN network in dumpsys connectivity) - freeRASP onSystemVpn; "
    "on analysis devices it is usually a capture VPN (PCAPdroid, HTTP Toolkit, NetGuard).",
    severity=Severity.MEDIUM,
    remediation="Capture traffic on the host bridge rather than with an on-device VPN app.",
)
def check_vpn_active(dev: Device, ctx: RunContext) -> Verdict:
    names = need(dev.listdir("/sys/class/net"), "network interfaces")
    tun = [n for n in names if n.startswith(("tun", "ppp", "tap", "ipsec", "wg"))]
    conn = need(dev.dumpsys("connectivity"), "connectivity service")
    vpn_net = bool(re.search(r"(?m)^\s*NetworkAgentInfo.*\bVPN\b", conn)) or "Transports: VPN" in conn
    return Verdict(bool(tun) or vpn_net, {"interfaces": tun or None, "vpn_network": vpn_net})


@REG.check(
    "android.design.network_validation",
    "network.connectivity",
    name="Validated internet connectivity",
    description="dumpsys connectivity: the default network lacks the VALIDATED capability (Android's own "
    "connectivity check failed) or there is no default network - an offline or captive analysis network.",
    severity=Severity.LOW,
    remediation="Let the device's captive-portal check succeed (simulated generate_204 endpoint) or provide "
    "filtered real connectivity.",
)
def check_network_validation(dev: Device, ctx: RunContext) -> Verdict:
    text = need(dev.dumpsys("connectivity"), "dumpsys connectivity")
    no_default = bool(re.search(r"Active default network:\s*none", text))
    validated = "VALIDATED" in text
    return Verdict(no_default or not validated, {"default_network": not no_default, "validated": validated})


@REG.check(
    "android.design.dns_sinkhole",
    "network.dns_sinkhole",
    name="DNS answers for non-existent domains",
    description="Resolves a random non-existent .invalid name on the device (ping -c1). An answer means a "
    "sinkhole/fake DNS such as INetSim; the real DNS returns NXDOMAIN.",
    severity=Severity.HIGH,
    remediation="Answer NXDOMAIN for names the simulator has no reason to know (INetSim: dns_default_ip only "
    "for whitelisted names), or forward unknown names to a real resolver through a filter.",
    cost="medium",
    network=True,
)
def check_dns_sinkhole(dev: Device, ctx: RunContext) -> Verdict:
    host = _random_domain()
    result = dev.run(f"ping -c 1 -W {PROBE_TIMEOUT_S} {host} 2>&1", timeout=PROBE_TIMEOUT_S + 10)
    if result is None:
        raise ProbeError("ping could not be run")
    out = result.stdout
    resolved = re.search(r"PING \S+ \((\d+\.\d+\.\d+\.\d+)\)", out)
    if resolved:
        return Verdict(True, {"domain": host, "answer": resolved.group(1)})
    if re.search(r"(?i)unknown host|no address associated|name or service not known|bad address", out):
        return Verdict(False, {"domain": host, "answer": None})
    raise Skip(f"inconclusive ping output: {out.strip()[:120]!r}")


@REG.check(
    "android.design.simulated_internet",
    "network.simulated_internet",
    name="HTTP answers from a non-existent domain",
    description="Sends one HTTP GET to a random non-existent domain with toybox nc. Any HTTP reply (INetSim "
    "serves 200 with its default page) means a simulated internet.",
    severity=Severity.HIGH,
    remediation="Have the simulator refuse or 404 hosts it does not emulate, and hide simulator banners.",
    cost="medium",
    network=True,
)
def check_simulated_internet(dev: Device, ctx: RunContext) -> Verdict:
    host = _random_domain()
    request = f"GET / HTTP/1.0\\r\\nHost: {host}\\r\\nUser-Agent: Mozilla/5.0\\r\\n\\r\\n"
    result = dev.run(
        f"printf '{request}' | nc -w {PROBE_TIMEOUT_S} {host} 80 2>&1 | head -c 2048",
        timeout=PROBE_TIMEOUT_S + 10,
    )
    if result is None:
        raise ProbeError("nc could not be run")
    out = result.stdout
    if re.search(r"(?i)not found|applet|inaccessible or not found", out) and "HTTP/" not in out:
        raise Skip("nc not available on this build")
    status = re.search(r"HTTP/1\.[01] (\d{3})", out)
    banners = substr_hits(out, ("INetSim", "FakeNet", "fakenet"))
    if not status:
        raise Skip("no HTTP response; connectivity or DNS may be unavailable")
    return Verdict(
        bool(status),
        {"domain": host, "status": int(status.group(1)) if status else None, "banners": banners or None},
    )


CHECKS = REG.specs
