"""Find every ``CHECKS`` list in an agent's ``checks`` package.

New check modules are picked up by dropping a file into the package; nothing
else needs editing. Works from a directory or from a zipapp (zipimport), which
is how the Linux agent is staged into guests.
"""

from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

from .registry import CheckSpec


def discover(package: ModuleType) -> list[CheckSpec]:
    specs: list[CheckSpec] = []
    seen: set[str] = set()
    names = sorted(m.name for m in pkgutil.iter_modules(package.__path__) if not m.name.startswith("_"))
    for name in names:
        module = importlib.import_module(f"{package.__name__}.{name}")
        for check in getattr(module, "CHECKS", ()):
            for finding_id in check.ids:
                if finding_id in seen:
                    raise ValueError(f"check id {finding_id} registered twice ({module.__name__})")
                seen.add(finding_id)
            specs.append(check)
    return specs
