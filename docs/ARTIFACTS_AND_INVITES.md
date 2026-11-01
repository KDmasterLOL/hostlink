# Raw Agent artifact packaging and invitation contract

Only private `KDmasterLOL/hostlink` GitHub Releases supply production binaries.
The exact four names and credential policy are in [GitHub Releases](GITHUB_RELEASES.md).
These scripts operate locally: they never create tags, upload or deploy.

## Source-exact packaging

Run from a clean source worktree at the selected full lowercase Git SHA.
The binary must be a current-user-owned regular file, nonempty and bounded.
The command preserves the existing packaging CLI:

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
cargo build --offline --locked --release -p hostlink-agent
python3 scripts/package-hostlink-agent.py \
  --source-sha "$SOURCE_SHA" \
  --target x86_64-unknown-linux-gnu \
  --version 0.1.0 \
  --binary target/release/hostlink-agent \
  --output-dir target/agent-package-linux-x64
```

Output is a new private directory containing exactly the raw named executable
and `artifact-receipt.json`. Receipt format 2 records source SHA, target,
version, asset name, size, SHA-256 and optional build receipt provenance.
The copied asset is rehashed against the selected source binary; the source
HEAD and clean-worktree checks run before and after staging. No transformations
are applied to binary bytes. Source provenance identifies the selected clean
worktree and exact input hash; it is not a reproducible-build attestation.

For both Win7 targets supply `--build-receipt` from
`scripts/build-win7-candidate.sh`. It must bind the exact source, target and
binary digest to `PE_BUILD_AND_INSPECTION_PASS`, the matching PE machine,
subsystem 6.0 and successful static CRT import check. Packaging also checks the
actual PE machine. A receipt never substitutes for native Windows execution.

## Stage a complete release locally

```sh
python3 scripts/stage-hostlink-github-release.py \
  --package-dir target/agent-package-linux-x64 \
  --package-dir target/agent-package-win11-x64 \
  --package-dir target/agent-package-win7-x64 \
  --package-dir target/agent-package-win7-x86 \
  --output-dir target/hostlink-release-v0.1.0 \
  --require-all-targets
```

Staging requires matching source/version, unique supported targets, exact
raw asset paths, sizes and SHA-256, and rejects symlinks, hardlinks and extra
legacy files. It rechecks copied bytes before publishing the output directory.
`--require-all-targets` requires all four; partial staging remains available
for local checks. Output contains raw assets plus `.release-receipt.json`.
The hidden receipt is local provenance and **must not be uploaded**. There is
no ZIP, release manifest, archive hash sidecar or installer script output.

A separately authorized publication must upload the unchanged raw assets and
expose GitHub-published SHA-256 digests. This source task does not publish.

## Invite and bootstrap

```sh
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc --version 0.1.0
```

Controller-generated disposable PS2/POSIX bootstrap replaces released and
installed scripts. Default hidden target PAT prompt and explicit
`--embed-github-token` are distinct choices. Download and verify the single
raw executable before consuming the one-use Hub invite. Rust Agent install
owns enrollment and executable publication; no Git/default tools are installed.
An uncertain enrollment must be reconciled rather than automatically replayed.

See [installation](AGENT_INSTALLATION.md), [enrollment](ENROLLMENT.md) and
[Win7 build/native gates](WIN7_REWRITE_ACCEPTANCE.md).
