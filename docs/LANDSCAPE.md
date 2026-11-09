# Landscape: tools, research and patents

Perdedor answers one question for a sandbox operator: **what would evasive malware notice here, how much
would it cost us, and what do we fix first?** Many tools and papers answer part of that question. This
page lists them, says what each does well, what Perdedor took from it, and where Perdedor still falls
short. It was reviewed in November 2026; check the linked sources for anything newer.

- [Open-source evasion test suites](#open-source-evasion-test-suites)
- [Detection rule sets and catalogues](#detection-rule-sets-and-catalogues)
- [Commercial sandboxes and their anti-evasion approach](#commercial-sandboxes-and-their-anti-evasion-approach)
- [Research](#research)
- [Patents](#patents)
- [What Perdedor does that the others do not](#what-perdedor-does-that-the-others-do-not)
- [Where Perdedor is still behind](#where-perdedor-is-still-behind)

## Open-source evasion test suites

These tools run inside an analysis environment and print what they detect. They are the closest
relatives of Perdedor, and Perdedor's catalog maps their techniques (see
[CHECK_COVERAGE.md](CHECK_COVERAGE.md); `perdedor coverage` prints the live figures).

| Tool | Platforms | What it is best at | Score | Fix guidance | Perdedor coverage |
|---|---|---|---|---|---|
| [al-khaser](https://github.com/ayoubfaouzi/al-khaser) | Windows | Breadth: anti-debug, anti-VM, anti-dump, timing, code-injection demos | none (pass/fail list) | none | 74.6 % (77.6 % of feasible) |
| [Pafish](https://github.com/a0rtega/pafish) | Windows | The classic, compact VM and sandbox checks, often copied by real malware | none | none | 96.6 % |
| [VMAware](https://github.com/NotRequiem/VMAware) | Windows, Linux, macOS | Deep VM-brand detection with a certainty percentage, about 100 techniques | points towards a "VM certain" threshold | none | 76.5 % (79.5 % of feasible) |
| [InviZzzible](https://github.com/CheckPointSW/InviZzzible) | Windows | Cuckoo-specific and generic sandbox checks from Check Point | none | none | 85.8 % |
| systemd-detect-virt | Linux | The reference Linux virtualisation detector | none | none | 100 % |
| [anti-emulator](https://github.com/strazzere/anti-emulator) | Android | Emulator properties, files and QEMU pipes | none | none | 76.9 % |
| [RootBeer](https://github.com/scottyab/rootbeer) | Android | Root detection used by banking apps | none | none | 70.6 % |
| [freeRASP](https://github.com/talsec/Free-RASP-Android) | Android, iOS, Flutter | App self-protection: root, hooks, emulators, debuggers | none | none | 63.6 % (70 % of feasible) |
| [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) | iOS | Jailbreak, debugger, reverse-engineering and simulator checks | none | none | 83.3 % (100 % of feasible) |

**What Perdedor took from them:** the technique list itself, the exact upstream names (so coverage is
measurable), and VMAware's idea that some tells are far more decisive than others.

**Why they are not enough on their own:** each covers one or two platforms, none shares a report format
with another, none says which detection to fix first, and only VMAware produces a number, which answers
"is this a VM?" rather than "how much evasive malware would still run here?". Their technique lists also
change; al-khaser and VMAware add checks every few months, which is why Perdedor tracks them
([UPSTREAM.md](UPSTREAM.md)).

Real malware copies these tools. AT&T Alien Labs traced public anti-VM code from Pafish and al-khaser
into malware families
([Alien Labs](https://cybersecurity.att.com/blogs/labs-research/how-public-tools-are-used-by-malware-developers-the-antivm-tale)),
so covering them is a floor, not a ceiling.

## Detection rule sets and catalogues

These are not test suites but descriptions of evasion behaviour. Perdedor uses them as vocabularies and
as evidence of what malware does in practice.

| Source | What it is | How Perdedor uses it |
|---|---|---|
| [Check Point Evasions encyclopedia](https://evasions.checkpoint.com/) | The largest public catalogue of sandbox, VM and anti-debug techniques, with code and countermeasures | Tracked upstream; each technique mapped to the Perdedor check that tests it: 74 of 110 covered (72.5 % of feasible) |
| [capa rules](https://github.com/mandiant/capa-rules) (anti-analysis) | Mandiant's rules for recognising anti-VM, anti-debug and anti-emulation code in binaries | Tracked upstream and mapped, so a capa hit on a sample leads to the Perdedor check that measures the same tell: 31 of 91 covered, 52 out of scope (packers, obfuscators, anti-forensics), 79.5 % of feasible |
| [CAPE community signatures](https://github.com/CAPESandbox/community) | Behavioural signatures that flag evasion attempts during detonation | Tracked upstream and mapped the same way: 61 of 73 covered (88.4 % of feasible) |
| [MITRE ATT&CK T1497](https://attack.mitre.org/techniques/T1497/) | Virtualization/Sandbox Evasion and its sub-techniques | Every technique carries its ATT&CK id |
| [MBC](https://github.com/MBCProject/mbc-markdown) | The Malware Behavior Catalog's anti-behavioural-analysis objective | MBC ids where they exist |
| [Unprotect Project](https://unprotect.it/) | A community database of evasion techniques with code snippets | Tracked; used as a reference while writing checks |

## Commercial sandboxes and their anti-evasion approach

Commercial products do not publish their check lists, so this section describes their stated approach
and what an operator of each should measure. Perdedor has not been run against any of these products;
the claims in the middle column are the vendors' own.

| Product | Stated approach to evasion | What Perdedor would measure on it |
|---|---|---|
| [VMRay](https://www.vmray.com/resources/vmray-technology-whitepaper/) | Monitoring from the hypervisor with no in-guest component, so "there is nothing for malware to detect" | Whether the guest itself still leaks: firmware strings, devices, CPUID, timing, wear and tear. Agentless monitoring hides the monitor, not the VM. |
| [Joe Sandbox](https://www.joesecurity.org/joe-sandbox-hypervisor) | Its own hypervisor for inspection, plus detonation on bare-metal machines | On bare metal only wear-and-tear, identity and network tells remain; Perdedor's human, wear_and_tear, identity and network classes cover exactly those. |
| ANY.RUN, Hybrid Analysis, Recorded Future Triage | Interactive or automated VM detonation at scale, with configurable environments | The full catalog. Public services like these are what SandPrint-style probes fingerprint (see Research). |
| CAPE, Cuckoo 3, DRAKVUF Sandbox (open source) | In-guest monitor (CAPE, Cuckoo) or agentless introspection (DRAKVUF) | The full catalog, plus the instrumentation class for in-guest monitors. CHIMERA, which Perdedor was built for, is DRAKVUF-based. |

The common thread: hiding the analysis engine is necessary but not sufficient. A sandbox whose monitor
leaks nothing can still be given away by its firmware, its hardware, its network, or the fact that nobody
ever used it. Perdedor scores all of these together.

## Research

| Work | Finding | What Perdedor took from it |
|---|---|---|
| Kirat, Vigna, Kruegel, **BareCloud** (USENIX Security 2014) [link](https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/kirat) | Running samples on bare metal and on emulated and virtualised systems and comparing behaviour flagged 5,835 evasive samples among 110,005. | The ground truth is "does the sample behave differently here?". The exposure score estimates exactly that share. |
| Miramirkhani, Appini, Nikiforakis, Polychronakis, **Spotless Sandboxes** (IEEE S&P 2017) [link](https://www.ieee-security.org/TC/SP2017/papers/429.pdf) | Wear-and-tear artifacts (browser history, recent files, event logs, DNS cache) tell sandboxes from real machines with 92.86 % accuracy, even on bare metal. | The wear_and_tear class (41 Windows checks) and its "aged files" style thresholds. |
| Yokoyama et al., **SandPrint** (RAID 2016) [link](https://christian-rossow.de/publications/sandprint-raid2016.pdf) | A probe submitted to 20 public services clustered 2,666 reports into 76 sandboxes; similar probes detected commercial appliances. | Identity and configuration checks (user and computer names, uptime, screen size, hardware counts), and the lesson that defaults shared across a fleet are themselves a fingerprint. |
| Blackthorne et al., **AVLeak** (WOOT 2016) [link](https://www.usenix.org/conference/woot16/workshop-program/presentation/blackthorne) | Antivirus emulators leak hundreds of fingerprints: environment artifacts, API inconsistencies, emulated networking, timing and CPU "red pills". | The emulator and instruction-behaviour checks in the low-level catalog. |
| Galloro, Polino, Carminati, Continella, Zanero, **A systematical and longitudinal study of evasive behaviors in Windows malware** (Computers & Security 2022) [link](https://research.utwente.nl/en/publications/a-systematical-and-longitudinal-study-of-evasive-behaviors-in-win/) | 92 techniques across 45,375 samples from 2010–2019: evasive samples rose by about 12 % and the techniques used shifted over time. | Technique prevalence as an input to the score, and the upstream watcher: the technique mix moves, so the catalog must too. |
| Maffia et al., **Longitudinal Study of the Prevalence of Malware Evasive Techniques** (2021) [link](https://arxiv.org/abs/2112.11289) | Over 40 % of 2020 samples used at least one evasive technique, against about 30 % in 2016. | Base rates for the scoring lab ([SCORING.md](SCORING.md)). |
| Zhang et al., **Scarecrow** (DSN 2020) | Making a real machine look like an analysis environment deactivated 89.56 % of evasive samples. | The same evasive logic read the other way: every tell Perdedor finds is one a sample would act on. |

## Patents

Patents were read for ideas only. Perdedor implements no claimed method, and this is not legal advice.

| Patent | Idea | Relevance to Perdedor |
|---|---|---|
| [US10546128B2](https://patents.google.com/patent/US10546128) and US11144642, "Deactivating evasive malware" (IBM) | Present analysis-environment indicators on end hosts so evasive malware stays dormant (the method behind Scarecrow). | Confirms that the indicators Perdedor measures are the ones malware branches on. |
| [US9917855B1](https://patents.google.com/patent/US9917855B1/en), "Mixed analysis-based virtual machine sandbox" | Interrupt a suspect process inside the VM and score its behaviour, to catch samples that hide through exception handlers. | Motivates the debugger and exception-based checks in the low-level catalog. |
| [US11416611](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11416611), "Countering malware detection evasion techniques" | Catch samples that restrict themselves to benign behaviour once they see a sandbox, using a sandbox separate from the bare-metal target. | The same quantity Perdedor's score expresses: what share of samples would hold back here. |

## What Perdedor does that the others do not

1. **One catalog across five platforms.** 1,009 implemented checks (Windows 432, Android 197, Linux 191,
   macOS 116, iOS 73) share 131 techniques, 19 classes, one report schema and one score.
2. **A score that means something.** The exposure score is the expected share of known evasive malware
   that would run normally, with a 90 % interval, per-class and per-category detail, and four
   trustworthiness grades. It was chosen in a scoring lab against the alternatives, including the
   VMAware-style points model and the old pass rate ([SCORING.md](SCORING.md)).
3. **Fix order, not just findings.** Every check carries how to fix it, the layer it lives in and the
   effort. `perdedor plan` orders the fixes by score gain per unit of effort.
4. **Who cares about each tell.** 91 malware families, tools and actors are mapped to the techniques
   they use, with sources ([THREATS.md](THREATS.md)).
5. **It notices when the world moves.** A weekly job checks 30 upstream sources and keeps one issue open
   listing new techniques that no check covers yet ([UPSTREAM.md](UPSTREAM.md)).
6. **Native, dependency-free agents.** Windows and Linux run one static C++ binary (no PowerShell, .NET
   or Python in the guest); Android, macOS and iOS are driven from the host over adb or ssh.
7. **Operator control.** The same selectors (profile, id globs, class, technique, cost, tag, network
   off) work in the CLI, in every agent and in the CHIMERA console.

## Where Perdedor is still behind

- **Kernel-level probes.** VMAware and al-khaser include checks that need a kernel driver (some MSR and
  exception probes). Perdedor stays in user mode on purpose and lists these as not feasible.
- **Anti-disassembly and code-injection demonstrations** in al-khaser test an analyst's tools, not the
  sandbox, and are not implemented.
- **Validation on real targets.** Windows and Linux have run on real CHIMERA guests and on GitHub's
  Windows runners, and the macOS agent runs on GitHub's macOS runner. Android devices, iOS devices and
  macOS virtual machines have only been tested against recorded fixtures so far.
- **Prevalence data is public data.** Family weights come from published reports and vendor statistics
  ([THREATS.md](THREATS.md#limitations)); a private sample corpus would sharpen them.
