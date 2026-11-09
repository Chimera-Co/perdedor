# Releases and deployments

Perdedor is developed on `main` and used from tagged releases. A host that runs scans, such as a sandbox's
golden-image check, installs a release and stays on it until someone decides to move it. Work on `main` never
reaches such a host by accident.

## What a release contains

Pushing a tag `vX.Y.Z` runs the full CI, then the release job publishes these assets. Each one has a signed
build-provenance attestation.

| Asset | For |
|---|---|
| `perdedor-windows-x64.exe`, `perdedor-windows-x86.exe` | the native Windows agents, copied into a guest |
| `perdedor-linux-x86_64` | the native Linux agent (static, also pushed to x86 Android devices) |
| `perdedor-X.Y.Z-py3-none-any.whl`, `perdedor-X.Y.Z.tar.gz` | the analyst CLI and the Python agents (`pip install`) |
| `perdedor-windows-ps7-agent-vX.Y.Z.zip` | the v1 PowerShell agent, kept as a fallback |
| `perdedor-deploy-vX.Y.Z.tar.gz` | the whole tagged tree with the three native agents already in `native/build/` |
| `SHA256SUMS` | checksums of every asset above |

The deploy bundle is for hosts that run scans from a checkout. It contains the catalog, the schema, every
agent and the native sources. The agents in `native/build/` are newer than their sources, so
`perdedor_common.host.native_binary` uses them as they are and never rebuilds on the host.

## Verifying a download

```bash
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify perdedor-deploy-v2.0.1.tar.gz --repo Chimera-Co/perdedor
```

The attestation shows that the file was built by this repository's release workflow from the tagged
commit. The checksum shows only that the file matches the list published with it.

## Cutting a release

1. Every version string must agree: `python scripts/check_version.py`. Bump them together (`pyproject.toml`,
   `perdedor_common/__init__.py`, `perdedor_common/models.py`, `native/src/core/perdedor.hpp`,
   `Perdedor.Common.psm1`).
2. Add the release to `CHANGELOG.md`.
3. Merge to `main` with CI green. Then tag and push: `git tag -a vX.Y.Z -m "Perdedor vX.Y.Z" && git push origin vX.Y.Z`.
4. The release job checks the tag against the version strings. It refuses to publish if they differ.

Patch releases (`X.Y.Z+1`) fix checks, scoring data or documentation and keep the report format. Minor releases
may add checks, classes or report fields; consumers must ignore fields they do not know. A major release
changes the report format or the score's meaning.

## Updating a deployment

A deployment moves from one release to the next as one step, with the previous copy kept for rollback:

1. Read the changelog between the two releases, and the release notes.
2. Verify the deploy bundle (above). Unpack it next to the current copy, not over it.
3. Import the new tree once before switching (load the catalog, run the Linux agent with `--version`).
4. Stop whatever runs scans, swap the directories, start them again, and run one scan.
5. Keep the previous tree, or an archive of it, until that scan looks right.

CHIMERA does all of this with one command: `sudo scripts/chimera/perdedor-update.sh vX.Y.Z`. To go back,
run `--rollback`. Its operator guide is `docs/chimera/perdedor-production.md` in the CHIMERA repository.
