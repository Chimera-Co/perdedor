"""Pure parsers for the output of standard macOS / iOS commands.

Everything here is platform-independent and side-effect free so it can be
unit-tested on any host against recorded output.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# sys/proc.h (XNU): process is being traced (ptrace / debugger attached).
# https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc.h
P_TRACED = 0x00000800


def parse_sysctl(text: str) -> dict[str, str]:
    """``sysctl name ...`` prints ``name: value`` per line (``name = value`` on
    some older builds). Unknown names are reported on stderr and skipped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^([a-z][\w.]*)\s*(?::|=)\s?(.*)$", line)
        if match:
            out[match.group(1)] = match.group(2).strip()
    return out


def as_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_boottime(value: str | None) -> int | None:
    """``kern.boottime: { sec = 1730000000, usec = 123 } Fri Oct 27 ...``"""
    if not value:
        return None
    match = re.search(r"sec\s*=\s*(\d+)", value)
    return int(match.group(1)) if match else None


def parse_ioreg_properties(text: str) -> dict[str, str]:
    """Flatten ``ioreg -rd1 -c X`` / ``ioreg -l`` property lines
    (``"key" = value``) into ``key -> raw value`` (first occurrence wins).
    Data values such as ``<"Mac-xxxx">`` keep their angle-bracket form; use
    :func:`ioreg_string` to get the text inside."""
    out: dict[str, str] = {}
    for match in re.finditer(r'^[\s|+-]*"([^"]+)"\s*=\s*(.+?)\s*$', text, re.MULTILINE):
        out.setdefault(match.group(1), match.group(2))
    return out


def ioreg_string(raw: str | None) -> str | None:
    """``"abc"`` -> abc, ``<"abc">`` -> abc, ``<"a","b">`` -> a b, ``<616263>``
    -> abc (hex data that decodes to printable ASCII)."""
    if raw is None:
        return None
    raw = raw.strip()
    quoted = re.findall(r'"([^"]*)"', raw)
    if quoted:
        return " ".join(q.strip("\x00") for q in quoted)
    hex_match = re.fullmatch(r"<([0-9a-fA-F]*)>", raw)
    if hex_match:
        try:
            decoded = bytes.fromhex(hex_match.group(1)).rstrip(b"\x00").decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return raw
        if decoded.isprintable():
            return decoded
    return raw


def ioreg_count(text: str, key: str, value: str | None = None) -> int:
    """Number of property lines ``"key" = value`` in ioreg output."""
    pattern = rf'"{re.escape(key)}"\s*=\s*' + (re.escape(value) + r"\b" if value is not None else "")
    return len(re.findall(pattern, text))


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    flags: int
    command: str

    @property
    def executable(self) -> str:
        """Last path component of argv[0]."""
        first = self.command.split(" ", 1)[0]
        return first.rsplit("/", 1)[-1]


def parse_ps(text: str) -> list[Process]:
    """``ps -axo pid=,ppid=,flags=,command=`` (BSD ps prints flags in hex)."""
    procs = []
    for line in text.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        pid, ppid = as_int(parts[0]), as_int(parts[1])
        try:
            flags = int(parts[2], 16)
        except ValueError:
            continue
        if pid is None or ppid is None:
            continue
        procs.append(Process(pid, ppid, flags, parts[3]))
    return procs


def traced(procs: Iterable[Process]) -> list[Process]:
    return [p for p in procs if p.flags & P_TRACED]


def find_tokens(text: str | None, tokens: Iterable[str]) -> list[str]:
    """Case-insensitive substring hits, in token order."""
    if not text:
        return []
    lowered = text.lower()
    return [t for t in tokens if t.lower() in lowered]


def match_names(names: Iterable[str], wanted: Iterable[str]) -> list[str]:
    """Case-insensitive exact matches of ``names`` against ``wanted``."""
    wanted_l = {w.lower() for w in wanted}
    return sorted({n for n in names if n.lower() in wanted_l})


def matching_processes(procs: Iterable[Process], names: Iterable[str]) -> list[str]:
    """Processes whose executable name equals one of ``names`` (case-insensitive),
    or whose command line contains a name that has a path separator or a
    space in it (``Little Snitch``, ``/frida-server``)."""
    exact = {n.lower() for n in names if "/" not in n and " " not in n}
    loose = [n.lower() for n in names if "/" in n or " " in n]
    hits = []
    for proc in procs:
        exe = proc.executable.lower()
        cmd = proc.command.lower()
        if exe in exact or any(s in cmd for s in loose):
            hits.append(f"{proc.pid} {proc.command[:160]}")
    return hits


def parse_ifconfig_macs(text: str) -> dict[str, str]:
    """``ifconfig`` -> interface -> MAC (``ether xx:xx:...``)."""
    out: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        header = re.match(r"^([a-zA-Z0-9]+):\s+flags=", line)
        if header:
            current = header.group(1)
            continue
        ether = re.match(r"^\s+ether\s+([0-9a-fA-F:]{17})", line)
        if ether and current:
            out[current] = ether.group(1).lower()
    return out


def parse_ifconfig_inet(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        header = re.match(r"^([a-zA-Z0-9]+):\s+flags=", line)
        if header:
            current = header.group(1)
            continue
        inet = re.match(r"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)", line)
        if inet and current:
            out.setdefault(current, []).append(inet.group(1))
    return out


def mac_is_locally_administered(mac: str) -> bool:
    """IEEE 802: bit 1 of the first octet marks a locally administered address."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def parse_hardware_ports(text: str) -> list[dict[str, str]]:
    """``networksetup -listallhardwareports`` blocks of Hardware Port / Device /
    Ethernet Address."""
    ports: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            if current:
                ports.append(current)
                current = {}
            continue
        key = key.strip()
        if key == "Hardware Port" and current:
            ports.append(current)
            current = {}
        current[key] = value.strip()
    if current:
        ports.append(current)
    return [p for p in ports if "Hardware Port" in p]


def load_json(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def profiler_items(doc: Any, data_type: str) -> list[dict]:
    """``system_profiler -json SPxxxDataType`` -> list of top-level items."""
    if not isinstance(doc, Mapping):
        return []
    items = doc.get(data_type)
    return [i for i in items if isinstance(i, Mapping)] if isinstance(items, list) else []


def walk_items(items: Sequence[Any]) -> Iterable[Mapping]:
    """Depth-first over system_profiler ``_items`` trees (USB, Bluetooth)."""
    stack = list(items)
    while stack:
        item = stack.pop(0)
        if isinstance(item, Mapping):
            yield item
            children = item.get("_items")
            if isinstance(children, list):
                stack[0:0] = children


def flatten_strings(value: Any, limit: int = 20000) -> str:
    """All string leaves of a JSON document joined by newlines (for vendor
    string scans), bounded to ``limit`` characters."""
    out: list[str] = []
    stack = [value]
    size = 0
    while stack and size < limit:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
            size += len(item)
        elif isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return "\n".join(out)[:limit]


def parse_resolution(text: str | None) -> tuple[int, int] | None:
    """``"2560 x 1600 Retina"`` / ``"1920 x 1080 (1080p FHD...)"`` -> (w, h)."""
    if not text:
        return None
    match = re.search(r"(\d{3,5})\s*x\s*(\d{3,5})", text)
    return (int(match.group(1)), int(match.group(2))) if match else None


def parse_df_kbytes(text: str) -> int | None:
    """``df -k /`` second line, column 2 = 1K-blocks."""
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return None
    parts = lines[-1].split()
    return as_int(parts[1]) if len(parts) > 1 else None


def parse_csrutil(text: str) -> dict[str, Any]:
    """``csrutil status``: overall state plus the per-protection lines of a
    custom configuration (``Kext Signing: disabled``)."""
    lowered = text.lower()
    state = "unknown"
    match = re.search(r"system integrity protection status:\s*([a-z ]+?)[.(\n]", lowered + "\n")
    if match:
        state = match.group(1).strip()
    parts = {}
    for line in text.splitlines():
        sub = re.match(r"^\s*([A-Za-z][A-Za-z /]+):\s*(enabled|disabled)", line)
        if sub and "status" not in sub.group(1).lower():
            parts[sub.group(1).strip()] = sub.group(2)
    return {"state": state, "custom": "custom configuration" in lowered, "protections": parts}


def parse_scutil_proxy(text: str) -> dict[str, str]:
    """``scutil --proxy`` prints a ``<dictionary> { Key : Value }`` block."""
    out = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([A-Za-z]+)\s*:\s*(.+?)\s*$", line)
        if match:
            out[match.group(1)] = match.group(2)
    return out


def parse_launchctl_list(text: str) -> list[str]:
    """``launchctl list``: ``PID\\tStatus\\tLabel`` rows -> labels."""
    labels = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2] != "Label":
            labels.append(parts[2].strip())
    return labels


def parse_kext_bundles(text: str) -> list[str]:
    """Bundle ids from ``kmutil showloaded`` / ``kextstat`` rows (the column
    that looks like a reverse-DNS id)."""
    ids = []
    for line in text.splitlines():
        for token in line.split():
            if re.fullmatch(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){2,}", token):
                ids.append(token)
                break
    return ids


def parse_listen_ports(text: str) -> set[int]:
    """Listening TCP ports from ``netstat -an`` or ``lsof -nP -iTCP -sTCP:LISTEN``."""
    ports: set[int] = set()
    for line in text.splitlines():
        if "LISTEN" not in line:
            continue
        for match in re.finditer(r"[.:](\d{1,5})(?:\s|\)|$)", line):
            port = int(match.group(1))
            if 0 < port < 65536:
                ports.add(port)
                break
    return ports


def count_history_lines(text: str | None) -> int:
    if not text:
        return 0
    return sum(1 for line in text.splitlines() if line.strip())


def strings_of(blob: str | None) -> str:
    """Printable runs of 4+ characters (``strings``-like) from a decoded file;
    used for binary plists and sqlite files read through a text pipe."""
    if not blob:
        return ""
    return "\n".join(re.findall(r"[\x20-\x7e]{4,}", blob))
