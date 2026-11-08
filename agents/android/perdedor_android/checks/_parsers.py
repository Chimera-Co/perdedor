"""Parsers for dumpsys / service-call output shared by several check modules."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Android 7+ `dumpsys sensorservice`:
#   0x00000001) BMI160 Accelerometer | Bosch | ver: 1 | type: android.sensor.accelerometer(1) | perm: n/a ...
_SENSOR_NEW = re.compile(
    r"^\s*0x[0-9a-fA-F]+\)\s*(?P<name>[^|]+?)\s*\|\s*(?P<vendor>[^|]+?)\s*\|.*?type:\s*(?P<type>[\w.]+)"
)
# Android 4-6: "Goldfish 3-axis Accelerometer| The Android Open Source Project| version=1 |android.sensor.accelerometer| 0x..."
_SENSOR_OLD = re.compile(
    r"^\s*(?P<name>[^|]+?)\s*\|\s*(?P<vendor>[^|]+?)\s*\|\s*version=\d+\s*\|\s*(?P<type>[\w.]+)\s*\|"
)


@dataclass(frozen=True)
class Sensor:
    name: str
    vendor: str
    type: str


def parse_sensors(text: str) -> list[Sensor]:
    sensors: list[Sensor] = []
    in_list = False
    for line in text.splitlines():
        if line.strip().lower().startswith("sensor list"):
            in_list = True
            continue
        match = _SENSOR_NEW.match(line) or (
            _SENSOR_OLD.match(line) if in_list or "version=" in line else None
        )
        if match:
            sensors.append(
                Sensor(match.group("name").strip(), match.group("vendor").strip(), match.group("type"))
            )
    if not sensors:
        # Very old builds: one "handle=" line per sensor (the v1 parser).
        for line in text.splitlines():
            if "handle=" in line.lower():
                sensors.append(Sensor(line.strip()[:60], "", ""))
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for s in sensors:
        key = (s.name, s.vendor, s.type)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


_EVENT_HEADER = re.compile(r"^\s*(?P<name>.+?):\s*last\s+\d+\s+events", re.IGNORECASE)
_EVENT_LINE = re.compile(r"\(ts=[^)]*\)\s*(?P<values>[-0-9.,\s]+)")


def parse_recent_events(text: str) -> dict[str, list[tuple[float, ...]]]:
    """``Recent Sensor events`` section: sensor name -> list of value tuples."""
    events: dict[str, list[tuple[float, ...]]] = {}
    current: str | None = None
    for line in text.splitlines():
        header = _EVENT_HEADER.match(line)
        if header:
            current = header.group("name").strip()
            events.setdefault(current, [])
            continue
        if current is None:
            continue
        match = _EVENT_LINE.search(line)
        if match:
            values = []
            for part in match.group("values").replace(",", " ").split():
                try:
                    values.append(float(part))
                except ValueError:
                    pass
            if values:
                events[current].append(tuple(values))
        elif line.strip() and not line.startswith((" ", "\t")):
            current = None
    return events


def parse_battery(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep and key and value.strip():
            out.setdefault(key.strip().lower(), value.strip())
    return out


_PARCEL_WORDS = re.compile(r"0x[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{8}\s+){1,4})")


def parse_parcel_string(text: str) -> str | None:
    """Decode the String16 reply of ``service call <svc> <code> ...``.

    Reply layout: int32 exception code (0 = success), int32 length in UTF-16
    units (-1 = null), then the UTF-16LE characters. ``service call`` prints
    the parcel as 32-bit words in host order (little-endian).
    """
    words: list[int] = []
    for match in _PARCEL_WORDS.finditer(text):
        words += [int(w, 16) for w in match.group(1).split()]
    if len(words) < 2 or words[0] != 0:
        return None
    length = words[1]
    if length == 0xFFFFFFFF or length > 512:
        return None
    raw = b"".join(w.to_bytes(4, "little") for w in words[2:])
    value = raw[: 2 * length].decode("utf-16-le", errors="replace")
    return value if len(value) == length else None


def luhn_valid(number: str) -> bool:
    if not number.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
