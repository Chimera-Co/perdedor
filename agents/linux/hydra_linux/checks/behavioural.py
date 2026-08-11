"""Category 3 (Ch.3.2.3): behavioural / interaction-based detection.

Modelled on Miramirkhani et al.'s "wear-and-tear" result: a sandbox that is
artifact-free and correctly timed is still detectable if it is obviously
new -- no shell history, no aged files, nothing installed. Also covers
al-khaser's "Human Interface" section (process/font count as a proxy for a
genuinely-used desktop).
"""

from __future__ import annotations

import time
from pathlib import Path

from hydra_common import FindingFactory
from hydra_common.models import Category, Finding, Platform, Severity

from .. import utils

_PLATFORM = Platform.LINUX
_CATEGORY = Category.BEHAVIOURAL_INTERACTION
_f = FindingFactory(category=_CATEGORY, platform=_PLATFORM)

_MIN_SHELL_HISTORY_LINES = 20
_MIN_AGED_FILES = 5
_AGED_FILE_THRESHOLD_SECONDS = 7 * 24 * 3600  # a file older than a week counts as "wear"
_MIN_INSTALLED_PACKAGES = 50
_MIN_FONT_COUNT = 30
_MIN_RUNNING_PROCESSES = 40


def check_shell_history() -> Finding:
    check_id, name = "linux.behavioural.shell_history", "Shell history depth"
    description = (
        "A near-empty ~/.bash_history/.zsh_history is implausible for a machine with real usage history."
    )
    home = Path.home()
    history_files = [home / ".bash_history", home / ".zsh_history"]
    line_count = 0
    found_any = False
    for history_file in history_files:
        text = utils.read_text(str(history_file))
        if text is not None:
            found_any = True
            line_count += len([line for line in text.splitlines() if line.strip()])
    remediation = "Seed the golden image with realistic shell history before freezing it."
    if not found_any:
        return _f.detected(
            check_id, name, description, Severity.LOW, "no shell history file found", remediation
        )
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=line_count < _MIN_SHELL_HISTORY_LINES,
        evidence=f"{line_count} history lines",
        remediation=remediation,
    )


def check_aged_files() -> Finding:
    check_id, name = "linux.behavioural.aged_files", "Filesystem 'wear and tear' age"
    description = (
        "Counts files under $HOME older than a week; a home directory that is all brand-new is a tell."
    )
    home = Path.home()
    now = time.time()
    aged = 0
    try:
        for entry in home.rglob("*"):
            try:
                if entry.is_file() and (now - entry.stat().st_mtime) > _AGED_FILE_THRESHOLD_SECONDS:
                    aged += 1
                    if aged >= _MIN_AGED_FILES:
                        break
            except OSError:
                continue
    except OSError as exc:
        return _f.error(check_id, name, description, Severity.LOW, str(exc))
    evidence = (
        f"{aged} files older than a week" if aged < _MIN_AGED_FILES else f">= {aged} files older than a week"
    )
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=aged < _MIN_AGED_FILES,
        evidence=evidence,
        remediation="Populate the golden image with realistic aged documents/downloads before freezing it.",
    )


def check_installed_package_count() -> Finding:
    check_id, name = "linux.behavioural.installed_packages", "Installed package count"
    description = "A machine with very few installed packages beyond the base OS looks freshly provisioned."
    dpkg_out = utils.run(["dpkg-query", "-f", ".\n", "-W"])
    rpm_out = None if dpkg_out is not None else utils.run(["rpm", "-qa"])
    output = dpkg_out or rpm_out
    if output is None:
        return _f.skipped(
            check_id, name, description, Severity.LOW, "neither dpkg-query nor rpm is available on this host"
        )
    count = len([line for line in output.splitlines() if line.strip()])
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.LOW,
        is_detected=count < _MIN_INSTALLED_PACKAGES,
        evidence=f"{count} packages",
        remediation="Install a realistic mix of everyday software (browsers, office tools, media players) on the golden image.",
    )


def check_font_count() -> Finding:
    check_id, name = "linux.behavioural.font_count", "Installed font count"
    description = f"A machine with fewer than {_MIN_FONT_COUNT} fonts installed looks like a minimal/headless provisioning rather than a real desktop."
    output = utils.run(["fc-list"])
    if output is None:
        return _f.skipped(check_id, name, description, Severity.INFO, "fc-list not available on this host")
    count = len([line for line in output.splitlines() if line.strip()])
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.INFO,
        is_detected=count < _MIN_FONT_COUNT,
        evidence=f"{count} fonts",
        remediation="Install a normal desktop font set on the golden image.",
    )


def check_running_process_count() -> Finding:
    check_id, name = "linux.behavioural.running_process_count", "Running process count"
    description = f"A machine running fewer than {_MIN_RUNNING_PROCESSES} processes looks like a minimal sandbox rather than a real desktop session."
    output = utils.run(["ps", "-e"])
    if output is None:
        return _f.error(check_id, name, description, Severity.INFO, "`ps -e` failed or is unavailable")
    count = len([line for line in output.splitlines() if line.strip()]) - 1  # minus header row
    return _f.bool_check(
        check_id,
        name,
        description,
        Severity.INFO,
        is_detected=count < _MIN_RUNNING_PROCESSES,
        evidence=f"{count} processes",
        remediation="A minimal process list is expected right after boot; re-run this check after normal desktop session startup.",
    )


def run_all() -> list[Finding]:
    return [
        check_shell_history(),
        check_aged_files(),
        check_installed_package_count(),
        check_font_count(),
        check_running_process_count(),
    ]
