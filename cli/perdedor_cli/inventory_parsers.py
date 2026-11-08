"""Parsers that extract an upstream project's technique list from its own sources.

Every parser is a pure function. Text parsers take ``(files, source)``: ``files`` maps a repository path
to the file's text and ``source`` is the entry of ``catalog/upstreams.json``. The ATT&CK parser takes an
iterator of STIX objects instead, so a bundle of tens of megabytes is never held in memory (see
``iter_json_array``). Each parser returns a list of items::

    {"name": str, "detail": str, "platforms": [str], "score": number | None}

``name`` is the identifier that ``equivalents`` in the check catalog is matched against; it is spelt the way
the upstream project spells it (an enum member, a function name, a technique id, an anchor).
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import defaultdict
from typing import Any, Callable, Iterable, Iterator, Mapping

Item = dict[str, Any]
Files = Mapping[str, str]


def _item(
    name: str, detail: str = "", platforms: Iterable[str] = (), score: float | int | None = None
) -> Item:
    return {"name": name, "detail": detail, "platforms": sorted(set(platforms)), "score": score}


def _dedupe(items: list[Item]) -> list[Item]:
    """Keep the first item of each name (upstreams repeat a name when one check is built per platform)."""
    seen: set[str] = set()
    out = []
    for it in items:
        if it["name"] not in seen:
            seen.add(it["name"])
            out.append(it)
    return out


# --------------------------------------------------------------------------------------------- VMAware

_VMAWARE_SECTION_PLATFORMS = {"windows": "windows", "linux": "linux", "macos": "macos", "mac": "macos"}
_VMAWARE_ALL = ("windows", "linux", "macos")


def _vmaware_section_platforms(label: str) -> list[str]:
    label = label.strip().lower()
    if label.startswith("cross"):
        return list(_VMAWARE_ALL)
    found = [p for word, p in _VMAWARE_SECTION_PLATFORMS.items() if re.search(rf"\b{word}\b", label)]
    return sorted(set(found)) or list(_VMAWARE_ALL)


def parse_vmaware_enum(files: Files, source: Mapping | None = None) -> list[Item]:
    """VMAware: the ``enum_flags`` technique enum of src/vmaware.hpp, the platform of each member (the
    ``/* Windows */``-style section comments) and its points from ``technique_table``."""
    text = next(iter(files.values()), "") if len(files) == 1 else "\n".join(files.values())
    m = re.search(r"enum\s+enum_flags\s*:\s*\w+\s*\{(.*?)\n\s*\};", text, re.S)
    if not m:
        return []
    points = {name: int(p) for name, p in re.findall(r"\{\s*VM::([A-Z0-9_]+)\s*,\s*\{\s*(\d+)\s*,", text)}
    items: list[Item] = []
    platforms = list(_VMAWARE_ALL)
    for raw in m.group(1).splitlines():
        line = raw.strip()
        if line.startswith("/*") or line.startswith("//"):
            comment = line.strip("/* ").strip()
            # A section label is a short comment made only of platform words; other comments (such as
            # "ADD NEW TECHNIQUE ENUM NAME HERE") are skipped.
            if comment and re.fullmatch(r"[A-Za-z\- ]+", comment) and len(comment) < 40:
                lowered = comment.lower()
                if lowered.startswith("cross") or any(
                    re.search(rf"\b{w}\b", lowered) for w in _VMAWARE_SECTION_PLATFORMS
                ):
                    platforms = _vmaware_section_platforms(comment)
            continue
        member = re.match(r"([A-Z][A-Z0-9_]*)\s*(?:=\s*[^,]+)?,?\s*(?:/\*.*)?$", line)
        if not member:
            continue
        name = member.group(1)
        if name in {"DEFAULT", "ALL", "NULL_ARG"}:
            break  # special flags and settings follow
        items.append(_item(name, f"VMAware technique ({', '.join(platforms)})", platforms, points.get(name)))
    return _dedupe(items)


# ------------------------------------------------------------------------------------------- al-khaser

# Calls in main() that are not checks.
_ALKHASER_NOT_CHECKS = {
    "EnableDefaultChecks",
    "resize_console_window",
    "print_os",
    "getchar",
    "print_category",
    "exec_check",
}


def parse_alkhaser_checks(files: Files, source: Mapping | None = None) -> list[Item]:
    """al-khaser: every ``exec_check(&name, TEXT("..."))`` and every bare ``name();`` check call in
    al-khaser/Al-khaser.cpp, with the ``print_category`` it runs under as the detail."""
    text = "\n".join(files.values())
    start = text.find("print_category(")
    if start < 0:
        return []
    items: list[Item] = []
    category = ""
    for line in text[start:].splitlines():
        stripped = line.strip()
        cat = re.search(r'print_category\(\s*TEXT\("([^"]*)"\)', stripped)
        if cat:
            category = cat.group(1).strip()
            continue
        call = re.match(r'exec_check\(\s*&?(\w+)\s*,(?:[^,]*,)?\s*TEXT\("([^"]*)"\)', stripped)
        if call:
            name, desc = call.group(1), call.group(2).strip()
            items.append(_item(name, f"{category}: {desc}", ["windows"]))
            continue
        bare = re.match(r"([A-Za-z_]\w*)\(\);", stripped)
        if bare and bare.group(1) not in _ALKHASER_NOT_CHECKS and category:
            items.append(_item(bare.group(1), f"{category}: grouped checks", ["windows"]))
    return _dedupe(items)


# --------------------------------------------------------------------------------------------- Pafish


def parse_pafish_checks(files: Files, source: Mapping | None = None) -> list[Item]:
    """Pafish: ``exec_check("description", &function, ...)`` calls in pafish/main.c, grouped by the
    ``print_check_group`` they follow. The function name is the technique name."""
    text = "\n".join(files.values())
    items: list[Item] = []
    group = ""
    pattern = re.compile(
        r'print_check_group\(\s*"([^"]*)"\s*\)|exec_check\s*\(\s*"([^"]*)"\s*,\s*&(\w+)', re.S
    )
    for m in pattern.finditer(text):
        if m.group(1) is not None:
            group = m.group(1)
        else:
            items.append(_item(m.group(3), f"{group}: {m.group(2)}", ["windows"]))
    return _dedupe(items)


# -------------------------------------------------------------------------------- Check Point Evasions

_CP_HEADING = re.compile(r'<h3>\s*<a[^>]*\bname="([^"]+)"[^>]*>\s*(\d+)\.\s*(.*?)\s*</a>\s*</h3>', re.S)


def _checkpoint_chapter(path: str) -> tuple[str, str]:
    """('evasions/cpu', 'windows') from '_src/Evasions/techniques/cpu.md'."""
    parts = path.replace("\\", "/").split("/")
    stem = parts[-1].rsplit(".", 1)[0]
    area = parts[parts.index("_src") + 1] if "_src" in parts and len(parts) > parts.index("_src") + 1 else ""
    area_key = area.lower()
    platform = "android" if area_key == "android" else "windows"
    return f"{area_key}/{stem}" if area_key else stem, platform


def parse_checkpoint_evasions(files: Files, source: Mapping | None = None) -> list[Item]:
    """Check Point Evasions encyclopedia: the numbered technique headings of each chapter. A name is
    ``<area>/<chapter>/<anchor>``, e.g. ``evasions/cpu/check-vendor-id-via-cpuid``."""
    items: list[Item] = []
    for path in sorted(files):
        chapter, platform = _checkpoint_chapter(path)
        for anchor, _num, title in _CP_HEADING.findall(files[path]):
            title = re.sub(r"<[^>]+>", "", title)
            title = re.sub(r"\s+", " ", title).strip()
            items.append(_item(f"{chapter}/{anchor}", title, [platform]))
    return _dedupe(items)


# ------------------------------------------------------------------------------------------ InviZzzible


def parse_invizzzible(files: Files, source: Mapping | None = None) -> list[Item]:
    """InviZzzible: every top-level key of the config/*.conf JSON files is one check. The name is
    ``<config>/<key>``, e.g. ``generic/RAM``; the score is the file's own ``score``."""
    items: list[Item] = []
    for path in sorted(files):
        if not path.endswith(".conf"):
            continue
        try:
            doc = json.loads(files[path])
        except json.JSONDecodeError:
            continue
        if not isinstance(doc, dict):
            continue
        stem = path.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        for key, body in doc.items():
            if not isinstance(body, dict):
                continue
            score = body.get("score")
            items.append(
                _item(
                    f"{stem}/{key}",
                    str(body.get("description", "")),
                    ["windows"],
                    score if isinstance(score, (int, float)) else None,
                )
            )
    return _dedupe(items)


# ------------------------------------------------------------------------------------------------- MBC

_MBC_ID = re.compile(r"<b>ID</b></td>\s*<td><b>(B\d{4})</b>", re.S)
_MBC_ATTACK = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def parse_mbc(files: Files, source: Mapping | None = None) -> list[Item]:
    """MBC: one item per anti-analysis behaviour page (``B0009``), with its methods counted in the detail
    and the related ATT&CK ids it lists."""
    items: list[Item] = []
    for path in sorted(files):
        text = files[path]
        ident = _MBC_ID.search(text)
        if not ident:
            continue  # objective index pages carry an OB id
        title = re.search(r"^#\s+(.+?)\s*$", text, re.M)
        methods = re.findall(r"^\|\*\*(.+?)\*\*\|(B\d{4}\.\d{3})\|", text, re.M)
        related = re.search(r"Related ATT&amp;CK Techniques|Related ATT&CK Techniques.*?</tr>", text, re.S)
        attack = sorted(set(_MBC_ATTACK.findall(related.group(0)))) if related else []
        detail = f"{title.group(1) if title else path}; {len(methods)} methods"
        if attack:
            detail += f"; ATT&CK {', '.join(attack)}"
        items.append(_item(ident.group(1), detail, []))
    return _dedupe(items)


# -------------------------------------------------------------------------------------------- ATT&CK

WANTED_ATTACK_PREFIXES = ("T1497", "T1622", "T1633")


def iter_json_array(stream, key: str = "objects", chunk_size: int = 1 << 20) -> Iterator[Any]:
    """Yield the elements of the top-level array ``key`` of a large JSON document read from ``stream``
    (a binary or text file object) without loading the document: the buffer holds one chunk plus the
    element being decoded."""
    decoder = json.JSONDecoder()
    buf = ""
    needle = f'"{key}"'
    state = "seek"  # seek key -> seek '[' -> elements
    while True:
        data = stream.read(chunk_size)
        eof = not data
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        buf += data
        pos = 0
        while True:
            if state == "seek":
                at = buf.find(needle, pos)
                if at < 0:
                    # Keep a tail so a key split across chunks is still found.
                    buf = buf[max(0, len(buf) - len(needle)) :]
                    pos = 0
                    break
                pos = at + len(needle)
                state = "open"
            if state == "open":
                at = buf.find("[", pos)
                if at < 0:
                    buf = buf[pos:]
                    pos = 0
                    break
                pos = at + 1
                state = "items"
            # state == "items"
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos >= len(buf):
                break
            if buf[pos] == "]":
                return
            try:
                obj, end = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                break  # element continues in the next chunk
            yield obj
            pos = end
        buf = buf[pos:]
        if eof:
            return


def _attack_id(obj: Mapping) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return ref.get("external_id")
    return None


def parse_attack_techniques(objects: Iterable[Mapping], source: Mapping | None = None) -> list[Item]:
    """ATT&CK: the T1497 family, T1622 and T1633 family, with the platforms and the software and groups
    that use each (procedure examples) from the STIX ``uses`` relationships. Revoked and deprecated
    techniques are dropped."""
    wanted: dict[str, tuple[str, Mapping]] = {}  # stix id -> (attack id, object)
    names: dict[str, str] = {}  # stix id -> software / group name
    uses: dict[str, list[str]] = defaultdict(list)  # technique stix id -> user stix ids
    for obj in objects:
        kind = obj.get("type")
        if kind == "attack-pattern":
            tid = _attack_id(obj)
            if (
                tid
                and tid.startswith(WANTED_ATTACK_PREFIXES)
                and not (obj.get("revoked") or obj.get("x_mitre_deprecated"))
            ):
                wanted[obj["id"]] = (tid, obj)
        elif kind in ("malware", "tool", "intrusion-set", "campaign"):
            if not (obj.get("revoked") or obj.get("x_mitre_deprecated")):
                names[obj["id"]] = obj.get("name", obj["id"])
        elif kind == "relationship" and obj.get("relationship_type") == "uses":
            if not (obj.get("revoked") or obj.get("x_mitre_deprecated")):
                uses[obj.get("target_ref", "")].append(obj.get("source_ref", ""))
    items: list[Item] = []
    for stix_id, (tid, obj) in wanted.items():
        users = sorted({names[u] for u in uses.get(stix_id, []) if u in names})
        platforms = [p.lower() for p in obj.get("x_mitre_platforms", [])]
        detail = f"{obj.get('name', '')}; {len(users)} procedure examples"
        item = _item(tid, detail, platforms)
        item["procedure_examples"] = users
        items.append(item)
    items.sort(key=lambda i: i["name"])
    return _dedupe(items)


# --------------------------------------------------------------------------- mobile and Linux helpers

_JAVA_DETECTOR = re.compile(r"public\s+(?:(?:static|native|final)\s+)*(?:boolean|int)\s+(\w+)\s*\(")


def parse_java_detectors(files: Files, source: Mapping | None = None) -> list[Item]:
    """anti-emulator and RootBeer: public boolean (or native int) detector methods. Overloads count once."""
    platform = "android"
    items: list[Item] = []
    for path in sorted(files):
        cls = path.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0]
        for name in _JAVA_DETECTOR.findall(files[path]):
            items.append(_item(name, cls, [platform]))
    return _dedupe(items)


_FREERASP_CALLBACK = re.compile(r"override\s+fun\s+(on(?!Activity|Create|AllChecksFinished)[A-Z]\w*)\s*\(")
_FREERASP_DART_ENUM = re.compile(r"enum\s+Threat\s*\{(.*?)\}", re.S)


def parse_freerasp(files: Files, source: Mapping | None = None) -> list[Item]:
    """freeRASP: the threat callbacks of the Android listener (``onPrivilegedAccess``, ``onSimulator``,
    ...) and the members of the Dart ``Threat`` enum (``privilegedAccess``, ``simulator``, ...)."""
    items: list[Item] = []
    for path in sorted(files):
        text = files[path]
        if path.endswith(".kt") or path.endswith(".java"):
            for name in _FREERASP_CALLBACK.findall(text):
                items.append(_item(name, "ThreatListener callback", ["android"]))
        elif path.endswith(".dart"):
            enum = _FREERASP_DART_ENUM.search(text)
            if enum:
                body = re.sub(r"//.*", "", enum.group(1))
                for name in re.findall(r"\b([a-zA-Z]\w*)\s*,", body + ","):
                    items.append(_item(name, "Threat enum", ["android", "ios"]))
    return _dedupe(items)


def parse_ios_security_suite(files: Files, source: Mapping | None = None) -> list[Item]:
    """IOSSecuritySuite: the public ``amI...`` / ``is...`` check functions of IOSSecuritySuite.swift."""
    items: list[Item] = []
    for path in sorted(files):
        for name in re.findall(r"public\s+(?:static|class)\s+func\s+((?:amI|is)\w*)\s*[(<]", files[path]):
            items.append(_item(name, "IOSSecuritySuite public API", ["ios"]))
    return _dedupe(items)


def parse_systemd_virt(files: Files, source: Mapping | None = None) -> list[Item]:
    """systemd-detect-virt: the ``VIRTUALIZATION_*`` ids of src/basic/virt.h (without range markers)."""
    text = "\n".join(files.values())
    m = re.search(r"enum\s+Virtualization\s*\{(.*?)\n\s*\}", text, re.S)
    if not m:
        return []
    items: list[Item] = []
    kind = "vm"
    for line in m.group(1).splitlines():
        ident = re.match(r"\s*(_?VIRTUALIZATION_[A-Z0-9_]+)\s*(?:=\s*([^,]+))?,", line)
        if not ident:
            continue
        name, value = ident.group(1), (ident.group(2) or "").strip()
        if name.endswith("CONTAINER_FIRST") or value.endswith("CONTAINER_FIRST"):
            kind = "container"
        if name.startswith("_") or name == "VIRTUALIZATION_NONE" or name.endswith(("_FIRST", "_LAST")):
            continue  # range markers, not techniques
        items.append(_item(name, f"{kind}: {name.removeprefix('VIRTUALIZATION_').lower()}", ["linux"]))
    return _dedupe(items)


# -------------------------------------------------------------------------------------- directory lists


def parse_generic_list(files: Files, source: Mapping | None = None) -> list[Item]:
    """A directory listing as an inventory: one item per file under the tracked directories (``paths``
    entries ending in ``/``), named by its path without extension. ``name_filter`` (a regular expression
    on the file name) and ``name_prefix`` in the source entry narrow and label the list. The values of
    ``files`` are not used; only the paths."""
    source = source or {}
    prefixes = [p for p in source.get("paths", []) if p.endswith("/")]
    name_filter = re.compile(source["name_filter"]) if source.get("name_filter") else None
    label = source.get("name_prefix", "")
    items: list[Item] = []
    for path in sorted(files):
        if prefixes and not any(path.startswith(p) for p in prefixes):
            continue
        base = path.rsplit("/", 1)[-1]
        if name_filter and not name_filter.search(base):
            continue
        stem = path.rsplit(".", 1)[0] if "." in base else path
        items.append(_item(f"{label}{stem}", path, []))
    return _dedupe(items)


# ----------------------------------------------------------------------------------------------- table


def parse_none(files: Files, source: Mapping | None = None) -> list[Item]:
    return []


TEXT_PARSERS: dict[str, Callable[[Files, Mapping | None], list[Item]]] = {
    "vmaware_enum": parse_vmaware_enum,
    "alkhaser_checks": parse_alkhaser_checks,
    "pafish_checks": parse_pafish_checks,
    "checkpoint_evasions": parse_checkpoint_evasions,
    "invizzzible_configs": parse_invizzzible,
    "mbc": parse_mbc,
    "anti_emulator": parse_java_detectors,
    "rootbeer": parse_java_detectors,
    "freerasp": parse_freerasp,
    "ios_security_suite": parse_ios_security_suite,
    "systemd_virt": parse_systemd_virt,
    "generic_list": parse_generic_list,
    "none": parse_none,
}

# Parsers that read a STIX bundle as a stream of objects rather than text files.
STIX_PARSERS: dict[str, Callable[[Iterable[Mapping], Mapping | None], list[Item]]] = {
    "attack_techniques": parse_attack_techniques,
}

# Parsers that only need the repository's file list, not the file contents.
LISTING_PARSERS = {"generic_list"}

PARSER_NAMES = tuple(sorted({*TEXT_PARSERS, *STIX_PARSERS}))


def glob_match(pattern: str, name: str) -> bool:
    """Case-insensitive glob used for ``equivalents`` patterns (``*_reg_keys``, ``cpu_*``)."""
    return fnmatch.fnmatchcase(name.casefold(), pattern.casefold())
