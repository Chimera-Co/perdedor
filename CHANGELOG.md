# Changelog

Releases follow [docs/RELEASING.md](docs/RELEASING.md): patch releases keep the report format, minor releases
may add checks and fields, major releases change the format or the score's meaning.

## v2.0.1 (2026-11-09)

- Every agent, `perdedor test`, `perdedor report` and the HTML report now headline the exposure score
  (`perdedor-exposure-2`) instead of v1's severity-weighted pass rate. The weighted score stays in the JSON
  for older consumers.
- `win.env.enclosure_serial` no longer counts a blank chassis asset tag as a detection. Consumer firmware
  often leaves it empty (the Acer laptop CHIMERA runs on does), so bare metal failed the check too. A
  placeholder or vendor string in either field is still a detection.
- Releases include `perdedor-deploy-vX.Y.Z.tar.gz`: the tagged tree with the native agents in
  `native/build/`, for hosts that run scans from a checkout. See [docs/RELEASING.md](docs/RELEASING.md).
- Docs site: top navigation tabs (the menu is visible on every page), formulas rendered with MathJax,
  list formatting fixed. New READMEs for the native agents and the Android, macOS and iOS drivers. The v1
  PowerShell and shell agents are marked as legacy fallbacks.

## v2.0.0 (2026-11-09)

- Native C++17 agents for Windows (x64, x86) and Linux; Python drivers for Android, macOS and iOS.
- A catalog of 1,034 checks (1,009 implemented) mapped to 131 techniques and 91 malware families, with
  equivalents for al-khaser, Pafish, VMAware, InviZzzible, Check Point, capa and CAPE.
- The exposure score: the share of documented evasive families expected to run normally, with an interval,
  a trust grade, per-class detail and a hardening plan ordered by gain.
- `perdedor coverage` and the upstream watcher report what each upstream project checks that Perdedor does not.
