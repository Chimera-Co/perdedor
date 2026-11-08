# Staying current with upstream

Perdedor claims to cover what the best evasion suites check. That claim only holds if somebody notices when
those suites change. `perdedor upstream` does the noticing and `perdedor coverage` keeps the claim honest.

## How it works

```
catalog/upstreams.json        tracked sources, the revision each was last reviewed at (`pinned`)
catalog/inventory/<id>.json   the technique list extracted from that revision by a parser
catalog/checks/*.json         `equivalents` of every check: upstream technique names it covers
```

* `perdedor upstream check` asks GitHub (REST, unauthenticated unless `--token-env VAR` names an
  environment variable that holds a token) for the newest release, tag or commit of every source and
  compares it with the pin. A source that moved is an **update**. For each update the parser runs on the new
  files and the result is diffed against the committed inventory: techniques that appeared upstream, techniques
  that disappeared, and which of the new ones **no check maps** (`equivalents` does not mention them).
* Source kinds: `github-release` (latest release), `github-tag` (highest version tag, optionally narrowed by
  `tag_prefix` / `tag_regex`), `github-commits` (newest commit touching any tracked path), `attack-stix`
  (a release whose STIX bundles are stream-parsed), `web-page` (SHA-256 of the page; a change means "go and look").
* Network behaviour: standard library `urllib`, 25 s timeout, up to 3 retries with 2/4/8 s backoff on 5xx and
  network errors, `Retry-After` and `X-RateLimit-Reset` honoured up to 30 s (a longer wait stops the run and the
  remaining sources are reported as skipped), `If-None-Match` revalidation through the ETags stored in the state
  file (a 304 does not count against the rate limit), proxies from the usual environment variables. The token is
  sent only to `api.github.com`, never printed and not forwarded on redirects to other hosts.
* The state file (default `$XDG_STATE_HOME/perdedor/upstream-state.json`, `--state` to override) holds the ETag
  cache, the revisions seen by the last run and the last result. `perdedor upstream status` prints that result.
* Exit codes of `check`: **0** nothing new, **10** updates available, **1** error (a source could not be
  checked, or the catalog is invalid). Updates win over errors: when both occur the exit code is 10 and the errors
  are listed in the result.
* `check --offline` does no network access: it validates `upstreams.json` and the inventories, prints the pins
  and the coverage figures.

Updates are measured against the **pin**, not against the last run, so an unreviewed update stays reported until
somebody pins it (`new_since_last_check` in the JSON tells a first sighting from a repeat).

## Tracked sources

| id | project | kind | why |
|---|---|---|---|
| `vmaware` | VMAware | github-release | Largest actively maintained VM/sandbox detection library; its technique enum is the broadest list of tells Perdedor should be able to reproduce. Renamed from kernelwernel/VMAware. |
| `al-khaser` | al-khaser | github-release | The reference Windows anti-VM, anti-debug and anti-sandbox check suite that malware authors copy from. Moved from LordNoteworthy/al-khaser. |
| `pafish` | Pafish | github-release | The original sandbox-detection demonstrator. The repository is archived, so a change here is unexpected. |
| `invizzzible` | InviZzzible | github-commits | Configurable evasion test tool from Check Point; its config/*.conf files list the checks with scores and countermeasures. |
| `checkpoint-evasions` | Check Point Evasions encyclopedia | github-commits | The most complete public catalogue of sandbox, VM and debugger evasion techniques with signature recommendations (evasions.checkpoint.com). |
| `unprotect` | Unprotect Project | web-page | Community database of malware evasion techniques mapped to ATT&CK and MBC; no public repository, so the technique index page is hashed and a change is a prompt to review the site. |
| `attack` | MITRE ATT&CK STIX data | attack-stix | Authoritative technique and procedure-example data for T1497 (virtualization/sandbox evasion), T1622 (debugger evasion) and T1633 (mobile sandbox evasion); the check catalog maps its techniques to these ids. |
| `mitre-cti` | MITRE CTI repository | github-release | The original ATT&CK STIX repository; it still publishes a release for each ATT&CK version, so it is a second signal for a new matrix version. |
| `mbc` | Malware Behavior Catalog | github-release | MBC behaviours B0001-B0037 (debugger and VM detection, sandbox detection, emulator detection) are referenced from the technique catalog. |
| `mbc-stix` | MBC STIX 2.1 data | github-tag | Machine-readable MBC; a new tag means new or renumbered behaviours. |
| `anti-emulator` | anti-emulator (Android) | github-commits | The classic Android emulator detection checks (QEMU files and drivers, telephony defaults, build properties) that the Android agent must pass. |
| `freerasp-android` | freeRASP for Android | github-release | Widely deployed Android app-protection SDK; its threat callbacks list what apps check (root, hooks, emulator, debugger, developer mode). |
| `freerasp-ios` | freeRASP for iOS | github-release | iOS counterpart of freeRASP; the checks are in a binary framework, so only releases are watched. |
| `freerasp-flutter` | freeRASP for Flutter | github-release | The Threat enum is the cross-platform list of freeRASP detections (Android and iOS). |
| `iossecuritysuite` | IOSSecuritySuite | github-release | Open-source iOS jailbreak, emulator, debugger and reverse-engineering detection; defines the iOS checks the future iOS agent should resist. |
| `rootbeer` | RootBeer | github-release | The most used open-source Android root detection library; its checks are what apps run on a rooted analysis device. |
| `android-native-root-detector` | Android Native Root Detector | github-release | Native-code root and hook detection for Android; watched for new detection ideas, no parser. |
| `owasp-mastg` | OWASP MASTG | github-release | Mobile security testing guide: the tests for root, emulator and tamper detection that app developers are told to implement. Renamed from OWASP/owasp-mastg. |
| `drakvuf` | DRAKVUF | github-commits | The introspection engine CHIMERA runs; new plugins and options (cpuidmon, hidsim, altp2m changes) change what the sandbox can hide. |
| `drakvuf-sandbox` | DRAKVUF Sandbox | github-release | The analysis pipeline built on DRAKVUF; its releases show how other deployments handle evasion and VM hardening. |
| `libvmi` | LibVMI | github-commits | VM introspection library under DRAKVUF; its last release is from 2020, so the master branch is tracked. |
| `xen` | Xen 4.19 releases | github-tag | The hypervisor CHIMERA runs (4.19 branch): new point releases carry security fixes and hypercall or CPUID behaviour changes. Tags RELEASE-4.19.N on the GitHub mirror. |
| `xen-xsa` | Xen security advisories | web-page | The advisory index at xenbits.xen.org; a changed page means a new XSA to assess against the pinned Xen build. |
| `qemu` | QEMU | github-tag | The device model behind Xen HVM guests: new releases change emulated devices, ACPI and SMBIOS strings that guests can fingerprint. |
| `systemd` | systemd (systemd-detect-virt) | github-release | systemd-detect-virt is what many Linux samples and tools call; virt.h lists the hypervisors and container runtimes it recognises. |
| `virt-what` | virt-what | web-page | Shell tool that detects virtualization from CPUID, DMI and /proc; the release page is hashed (no public git mirror). |
| `capa-rules` | capa rules (anti-analysis) | github-release | Mandiant capa's anti-analysis rules (anti-vm, anti-debugging, anti-emulation) describe the evasion behaviours found in real samples. |
| `cape-community` | CAPE community signatures | github-commits | CAPE's antisandbox, antivm, antidebug and antiemu signatures list evasions seen in malware that a sandbox reports. Directory-wide commit tracking is noisy; the technique list is the useful part. |
| `vmware-hardened-loader` | VmwareHardenedLoader | github-release | Open-source VMware hardening against detection; its patch list shows which tells defenders consider worth hiding. |
| `vmde` | VMDE (Virtual Machine Detection Engine) | github-release | Early VM detection engine; archived, kept as a historical reference. |

Sources with a parser have an inventory. Pins record `version`, `commit`, the `date` the pin was made and
`released`, the date upstream published that revision. Several repositories have been renamed (VMAware, al-khaser,
the OWASP MASTG, CAPE community); the catalog uses the current names, GitHub also answers for the old ones.

## Parsers

| parser | reads | technique name |
|---|---|---|
| `vmaware_enum` | `enum_flags` and `technique_table` in `src/vmaware.hpp` | enum member (`HYPERVISOR_BIT`), platforms from the section comments, points from the table |
| `alkhaser_checks` | `exec_check(&name, ...)` and grouped calls in `Al-khaser.cpp` | function name (`rdtsc_diff_vmexit`, `vbox_reg_keys`) |
| `pafish_checks` | `exec_check("...", &fn, ...)` in `pafish/main.c` | function name (`cpu_rdtsc_force_vmexit`) |
| `invizzzible_configs` | top-level keys of `config/*.conf` | `<config>/<key>` (`generic/RAM`), score from the file |
| `checkpoint_evasions` | numbered `<h3>` headings of the technique chapters | `<area>/<chapter>/<anchor>` (`evasions/cpu/check-vendor-id-via-cpuid`) |
| `attack_techniques` | STIX bundles, streamed: T1497*, T1622, T1633* and the software/groups that use them | ATT&CK id |
| `mbc` | behaviour pages of `anti-behavioral-analysis/` | MBC behaviour id (`B0009`) |
| `anti_emulator`, `rootbeer` | public boolean detector methods | method name |
| `freerasp` | `ThreatListener` callbacks and the Dart `Threat` enum | `onSimulator`, `simulator` |
| `ios_security_suite` | public `amI...` functions | function name |
| `systemd_virt` | `VIRTUALIZATION_*` in `src/basic/virt.h` | enum member |
| `generic_list` | a directory listing (capa rules, CAPE signatures) | path without extension, with `name_prefix` |

Parsers are pure functions in `cli/perdedor_cli/inventory_parsers.py` and are tested on trimmed excerpts in
`tests/fixtures/upstream/`. The ATT&CK parser reads the bundle with a chunked JSON array scanner, so the
50 MB enterprise bundle never sits in memory.

## Coverage

`perdedor coverage [--tool vmaware|al-khaser|...] [--json|--markdown]` joins an inventory with the check
catalog. An upstream technique is

* **covered** when an `implemented` check lists it in `equivalents[<tool>]` (glob patterns such as `*_reg_keys`
  allowed, case-insensitive; for ATT&CK and MBC through the `attack` / `mbc` ids of the technique a check
  implements, a parent technique counting as covered when a sub-technique is),
* **planned** when only a `planned` check lists it,
* **not_feasible** when a check with that status lists it (the reason is in that entry),
* **missing** otherwise.

Two percentages are printed: covered of all, and covered of the feasible (all minus not feasible). Quote these
figures, not impressions, when claiming coverage. They count names, so a pattern that is too broad over-claims;
review new `equivalents` patterns as carefully as new checks. The tool key of a source is `equivalents_key` in
`upstreams.json` (default: the source id).

## Reviewing an update and turning it into checks

1. `perdedor upstream check` (or open the issue "Upstream updates to review" that the weekly workflow keeps).
2. Read the upstream change log or diff for the moved sources (the URL is printed).
3. For each new unmapped technique decide: **already covered** (add its name to `equivalents` of the existing
   check), **new check** (add an entry to the right `catalog/checks/*.json` with `equivalents`, `fix` and
   `references`, implement it in an agent, propose a technique key in `research/proposed-techniques-*.json` if
   none fits), or **not feasible from user mode** (add a `not_feasible` entry with the reason).
4. `perdedor coverage --tool <tool>`: the technique must no longer be missing.
5. `perdedor upstream pin <id> --inventory` records the reviewed revision and rewrites the inventory from it
   (`pin --all` pins everything that is pending; run it only after the review is done).
6. Commit `catalog/upstreams.json`, `catalog/inventory/` and the new checks together.

`perdedor upstream refresh [ID...] [--at pinned|latest]` rebuilds inventories without touching the pins, which is
what to run after a parser fix.

## Running it

* **GitHub Actions**: `.github/workflows/upstream-watch.yml` runs weekly (and on demand), passes the workflow
  token with `--token-env GITHUB_TOKEN` and, on exit code 10, creates or updates one open issue titled
  "Upstream updates to review".
* **systemd**: `contrib/systemd/perdedor-upstream.{service,timer}` run `perdedor upstream check --json` weekly
  and keep the state in `/var/lib/perdedor/upstream-state.json`. Install with
  `cp contrib/systemd/perdedor-upstream.* /etc/systemd/system/ && systemctl enable --now perdedor-upstream.timer`;
  the service runs as user `perdedor` and reads an optional token from `/etc/perdedor/upstream.env`
  (`GITHUB_TOKEN=...`, mode 0600). Exit status 10 is treated as success by the unit.
* **Reading the result from a console**: the state file is plain JSON; `last_result` is the document that
  `check --json` prints (`summary`, `sources[]` with `status`, `pinned`, `latest`, `new_techniques`,
  `unmapped_upstream_techniques`). A dashboard only needs read access, for example
  `jq '.last_result.summary' /var/lib/perdedor/upstream-state.json` or
  `perdedor upstream status --json --state /var/lib/perdedor/upstream-state.json`. Do not write to it; the timer owns it.
