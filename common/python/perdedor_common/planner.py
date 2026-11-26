"""Hardening planner (issue #5 section 6): turn ``exposure.plan`` into a reviewable change list.

``exposure.plan`` orders the detected techniques by score gain per unit of effort. This module adds what
an operator needs to act on it:

* each step names its layer in the operator's terms (hypervisor, firmware, device model, guest OS, user
  profile, monitor, network, host hardware) and where the recipe goes (``xl.cfg``, SMBIOS/ACPI tables, the
  QEMU device model, the Windows registry and policy, Linux DMI and udev rules ...);
* given a previous report of the same environment, it says what improved and what regressed since;
* it renders the plan as Markdown with a checkbox per change, and as JSON.

Perdedor never applies a fix. The plan is a list for a person to review, apply and re-scan.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# catalog fix.layer -> the planner's layer name
LAYERS = {
    "hypervisor": "hypervisor",
    "firmware": "firmware",
    "vm-config": "device model",
    "analysis-engine": "monitor",
    "network": "network",
    "host-hardware": "host hardware",
    # guest-image splits into guest OS and user profile by technique class (see layer_for)
}

# technique-class prefixes whose guest-image fixes are about a lived-in user profile, not the OS image
_USER_PROFILE = ("wear_and_tear.", "human.")

# where the recipe for a layer is applied, per platform ("*" = any platform)
TARGETS = {
    (
        "hypervisor",
        "*",
    ): "Xen hypervisor and domain options (xl.cfg: cpuid=, viridian=, HAP/altp2m; Xen boot options)",
    ("firmware", "*"): "SMBIOS and ACPI tables (xl.cfg smbios_firmware= / acpi_firmware=, hvmloader build)",
    (
        "device model",
        "*",
    ): "VM config and QEMU device model (xl.cfg vga=, nic model, disk vendor, usb, device_model_args)",
    ("guest OS", "windows"): "Windows registry and policy (reg.exe / Group Policy in the golden image)",
    (
        "guest OS",
        "linux",
    ): "Linux guest image (DMI-facing files, udev rules in /etc/udev/rules.d, packages, services)",
    ("guest OS", "*"): "Guest operating system image",
    (
        "user profile",
        "*",
    ): "User profile in the golden image (documents, history, recent files, installed apps)",
    ("monitor", "*"): "Analysis monitor (out-of-guest introspection plugins, in-guest agent, hooks)",
    ("network", "*"): "Analysis network (DNS, simulated internet, routing, addresses)",
    ("host hardware", "*"): "Physical host (CPU, memory, devices passed to the guest)",
}


def layer_for(step: Mapping) -> str:
    """The planner layer of one plan step."""
    layer = step.get("layer")
    if layer == "guest-image":
        technique = str(step.get("technique") or "")
        return "user profile" if technique.startswith(_USER_PROFILE) else "guest OS"
    return LAYERS.get(layer, layer or "unknown")


def target_for(layer: str, platform: str) -> str | None:
    return TARGETS.get((layer, platform)) or TARGETS.get((layer, "*"))


def _statuses(findings: Iterable[Any]) -> dict:
    out = {}
    for f in findings:
        f = f if isinstance(f, Mapping) else f.to_dict()
        if f.get("id") and f.get("status"):
            out[f["id"]] = f["status"]
    return out


def changes_since(previous: Iterable[Any], current: Iterable[Any]) -> dict:
    """Checks that stopped firing (improved), started firing (regressed), and checks only one run has."""
    before, now = _statuses(previous), _statuses(current)
    improved = sorted(k for k, s in now.items() if s == "clean" and before.get(k) == "detected")
    regressed = sorted(k for k, s in now.items() if s == "detected" and before.get(k) == "clean")
    return {
        "improved": improved,
        "regressed": regressed,
        "new_checks": sorted(set(now) - set(before)),
        "dropped_checks": sorted(set(before) - set(now)),
    }


def hardening_plan(
    findings: Iterable[Any],
    platform: str,
    catalog: Any = None,
    *,
    previous: Iterable[Any] | None = None,
    max_steps: int = 25,
    baseline: Any = None,
    baseline_store: Any = None,
) -> dict:
    """``exposure.plan`` with layers, recipe targets and, when ``previous`` is given, the changes since."""
    from .exposure import assess, plan

    findings = list(findings)
    p = plan(
        findings,
        platform,
        catalog,
        max_steps=max_steps,
        baseline=baseline,
        baseline_store=baseline_store,
    )
    for step in p.get("steps", []):
        step["layer_group"] = layer_for(step)
        step["target"] = target_for(step["layer_group"], platform)
    p["applies_fixes"] = False
    if previous is not None:
        previous = list(previous)
        delta = changes_since(previous, findings)
        try:
            before = assess(previous, platform, catalog).get("score")
        except Exception:  # noqa: BLE001 - an unscorable old report still gives the check-level delta
            before = None
        delta["score_before"] = round(before, 2) if isinstance(before, (int, float)) else None
        delta["score_now"] = p.get("start")
        p["since_previous"] = delta
    return p


def render_markdown(p: Mapping, title: str | None = None) -> str:
    """The plan as a reviewable change list: one checkbox per change, in the order to apply them."""
    L = [f"# {title or 'Hardening plan'} ({p.get('platform')})", ""]
    L.append(
        "Perdedor never applies these changes. Review each one, apply it in the layer named, re-scan, and "
        "compare the new report with this one (`perdedor compare`)."
    )
    L.append("")
    if p.get("start") is None:
        L.append("Nothing to plan: the report has no applicable findings.")
        return "\n".join(L) + "\n"
    L.append(
        f"Exposure now **{p['start']:.1f}**; **{p['end']:.1f}** if every change below is applied "
        f"(model {p.get('model')})."
    )
    since = p.get("since_previous")
    if since:
        L += ["", "## Since the previous report", ""]
        if since.get("score_before") is not None:
            L.append(f"- Exposure {since['score_before']:.1f} -> {since['score_now']:.1f}")
        L.append(f"- Improved (stopped firing): {len(since['improved'])}")
        for k in since["improved"][:30]:
            L.append(f"  - `{k}`")
        L.append(f"- Regressed (started firing): {len(since['regressed'])}")
        for k in since["regressed"][:30]:
            L.append(f"  - `{k}`")
        if since["new_checks"] or since["dropped_checks"]:
            L.append(
                f"- Checks only in this report: {len(since['new_checks'])}; only in the previous one: "
                f"{len(since['dropped_checks'])} (catalog or selection changed)"
            )
    L += ["", "## Changes, in order", ""]
    L.append("| # | Gain | Score after | Effort | Layer | Technique |")
    L.append("|---|---|---|---|---|---|")
    for s in p["steps"]:
        L.append(
            f"| {s['step']} | +{s['gain']:.1f} | {s['score_after']:.1f} | {s['effort']} | "
            f"{s.get('layer_group')} | {s['title']} |"
        )
    for s in p["steps"]:
        L += ["", f"### {s['step']}. {s['title']}", ""]
        L.append("- [ ] Applied and re-scanned")
        L.append(f"- Layer: **{s.get('layer_group')}**. Where: {s.get('target') or 'see the recipe'}")
        if s.get("how"):
            L.append(f"- Recipe: {s['how']}")
        if s.get("chimera"):
            L.append(f"- On CHIMERA: {s['chimera']}")
        if s.get("checks"):
            L.append("- Checks that fire: " + ", ".join(f"`{c}`" for c in s["checks"][:12]))
    if p.get("measure_next"):
        L += ["", "## Measure next", ""]
        L.append("No check ran for these techniques; their rate is estimated from similar ones.")
        for m in p["measure_next"]:
            have = ", ".join(f"`{c}`" for c in m["implemented_checks"][:5]) or "no implemented check yet"
            L.append(f"- {m['title']} (est. {m['expected_rate']:.0%}): {have}")
    return "\n".join(L) + "\n"
