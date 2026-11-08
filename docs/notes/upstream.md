# Notes: upstream watcher and coverage inventories

## What was implemented

* `perdedor upstream check|status|pin|refresh` and `perdedor coverage` (`cli/perdedor_cli/upstream.py`,
  registered through `upstream.register(subparsers)`; four lines added to `__main__.py`).
* Thirteen text parsers and one streaming STIX parser (`cli/perdedor_cli/inventory_parsers.py`).
* `catalog/upstreams.json`: 30 sources, each verified with `gh api repos/OWNER/NAME` and pinned on 2026-11-08
  (the two web pages are pinned by content hash).
* `catalog/inventory/<id>.json` for every source with a parser (counts in docs/UPSTREAM.md and the final report).
* `contrib/systemd/perdedor-upstream.{service,timer}`, `.github/workflows/upstream-watch.yml` (validated with
  actionlint, actions pinned to the same commit SHAs as ci.yml), `docs/UPSTREAM.md`, `tests/test_upstream.py` with
  fixtures in `tests/fixtures/upstream/`.

## Design decisions

* Updates are measured against the pin, so the weekly job keeps reporting until a human pins; the state file
  only adds `new_since_last_check` and the ETag cache.
* Standard library only; the token goes only to api.github.com and is re-attached on same-host redirects (renamed
  repositories answer 301) but never to other hosts.
* Exit code 10 wins over 1 so that a partial outage never hides real updates.
* Parsers beyond the list in the brief (`invizzzible_configs`, `anti_emulator`, `rootbeer`, `freerasp`,
  `ios_security_suite`, `systemd_virt`) were added because those projects need name extraction too.
* MBC is inventoried at behaviour level (B0009), because `catalog/techniques.json` references behaviours, not
  methods. ATT&CK covers T1497*, T1622, T1633* from both the enterprise and the mobile bundle.
* Coverage counts names; glob patterns in `equivalents` can over-claim, and the figures are only as good as those
  patterns.

## Sources used

The upstream repositories listed in `catalog/upstreams.json`, read through the GitHub REST API and
raw.githubusercontent.com at the pinned revisions.

## Verification

* `pytest -q tests` (whole suite), ruff, black and isort over the tree.
* `perdedor upstream check --offline` and one real `perdedor upstream check` against GitHub.
* Parsers run on the complete upstream files (not only the trimmed fixtures) to build the inventories.

## Known limitations

* The pins of `github-commits` sources point at the newest commit touching the tracked paths; directory-wide
  paths (CAPE signatures, DRAKVUF plugins, LibVMI) change often, so those sources report updates frequently.
* Web-page sources (Unprotect, Xen advisories, virt-what) detect any byte change, including cosmetic ones.
* Al-khaser grouped calls (`vbox_files()`, `known_usernames()`) are one technique each, although each hides many
  individual probes; its Anti-Debug sources are reached only through the exec_check list in `Al-khaser.cpp`.
* The Check Point chapters are parsed from numbered headings; a chapter that changes its heading format yields no
  techniques (the diff would show them as removed).
* The first inventory run was done at the pinned revisions; the weekly job has never run on GitHub yet.
* Needs validation on a real deployment: the systemd unit (user `perdedor`, state directory permissions) and the
  workflow's issue creation (needs `issues: write` on the repository).
