# Notes: threat-model work (v2-threats)

## What was done

* `catalog/threats.json`: 120 families (Windows 91, Linux 11, macOS 9, Android 13,
  iOS 0), 302 evidence items, 75 distinct technique keys, 75 distinct source URLs
  (128 items cite an ATT&CK technique page plus its underlying reference).
* `research/prevalence.json`: estimate, interval and basis for all 131 technique keys.
* `research/proposed-techniques-threats.json`: 5 proposed keys.
* `docs/THREATS.md`: method, coverage tables, notable cases, limitations.
* `tests/test_threats.py`: schema and sourcing tests (keys valid via
  `load_catalog`, every technique has evidence with a URL, no duplicate names, sane
  years and date formats, weights 0.2-3.0, types and platforms valid, at least 10
  families on Windows, Linux and Android, prevalence file complete and ordered,
  proposals not already in the catalog).

## Decisions

* Accuracy over volume: a technique is listed only when the source names the check.
  Left out for that reason: SharkBot's emulator test (Cleafy), Rotexy's emulator
  test, Octo2, Hook, Crocodilus, Brokewell, and the vague ATT&CK mobile procedures
  (Dendroid, FakeSpy, Ginp, HenBox, WolfRAT, BRATA, KoSpy, SpyC23, TERRACOTTA).
  Perfctl (pauses on user login), XorDDoS, Kinsing, TeamTNT, BPFDoor and Outlaw had no
  documented sandbox check in the reports read.
* LockBit, REvil, Clop and GoldMax are Windows-only entries because their documented
  checks are Windows API calls; LockBit's Linux-ESXi locker is a separate entry.
* Target-country guards (SIM ISO, GeoID, operator country) map to `identity.locale`,
  whose title includes region. A sandbox fails them mainly because it has no SIM or a
  default region.
* Mapping rules are listed in `docs/THREATS.md` (Method, point 3).
* Weight bases state only figures that were read in the cited source; where no
  figure exists the basis says "judgement weight".

## Requests for other areas

* **Scoring.** With this catalog the Windows score switches to the family form, and
  `tests/test_exposure.py::test_one_strong_detection_outweighs_five_weak_ones` fails
  (`score(one) == 94.86`, expected `< 90`). Cause: `cpu.hypervisor_bit` is sourced for
  only GuLoader and Raspberry Robin (3.2 of 59.1 Windows weight, 5.4%). Reports rarely
  name this check even though crypters and loaders use it widely, so the family form
  under-counts it. Not changed here (`exposure.py` and its tests belong to the scoring
  area). Options: blend the family form with the tier form, or add an "unattributed"
  pseudo-family weighted by the tier priors.
* **Catalog.** `hardware.memory_modules` should list `macos`: Atomic macOS Stealer reads
  `system_profiler SPMemoryDataType` for QEMU and VMware strings
  (knowyouradversary.ru, 19 Mar 2025). Recorded as a known gap in
  `tests/test_threats.py::PLATFORM_GAPS`.

## Main sources

ANY.RUN annual reports 2024 and 2025, CISA AA22-216A, Europol Operation Endgame (May
2024), Unit 42 (macOS stealers, Kazuar), MITRE ATT&CK technique pages listed in the
brief, Zscaler, Outpost24, Fortinet, Elastic, Trellix, Check Point Research, Securelist,
FireEye and Sophos (SUNBURST), Trend Micro, ThreatFabric, Group-IB, Cleafy, Bitdefender,
Cyble, PT ESC (Decoy Dog), MalwareTech (WannaCry, Necurs), Cyberbit (Locky), Splunk
(Meduza). Papers: Chen et al. 2008 (DSN), Galloro et al. 2022 (Computers & Security),
Kedrowitsch et al. 2017 (Amnesia's DMI check).

## Verification

* `.venv/bin/python -m pytest -q tests`: all new tests pass; the one failure is the
  scoring test above.
* `python3 -c "import json;json.load(open('catalog/threats.json'))"` succeeds.
* No sample was downloaded and no malware infrastructure was contacted; only public
  pages were read.

## Limitations and open points

* Some evidence comes from secondary write-ups that quote the primary vendor
  (SecurityWeek for Amnesia, Infosecurity Magazine for Doctor Web's SpinOk finding,
  an ORKL archive copy for Mars Stealer, RansomLook for the Payload ESXi locker, an
  independent analyst's blog for LockBit Linux and Hydra). They are marked by URL.
* No iOS family with a concrete simulator or sandbox check was found.
* The other studies named in the brief (Maffia, Yokoyama, Miramirkhani, Vidas and
  Christin, Petsas, Jing, Costamagna, Cozzi) were not used for figures because their
  numbers were not checked against the papers during this work.
