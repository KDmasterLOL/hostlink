# Agent artifacts and invitations

Release packaging and inviting a machine are separate operations. Packaging does not create a Git tag, publish a release, enroll a host, or install an Agent.

## Build and package

Build from an exact, clean source revision:

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

The packaging script copies one raw executable and produces a local `artifact-receipt.json` recording its source revision, target, version, size and SHA-256. It checks source consistency and file ownership, size and content. Win7 assets additionally require a build inspection receipt from `scripts/build-win7-candidate.sh`.

## Stage a release

```sh
python3 scripts/stage-hostlink-github-release.py \
  --package-dir target/agent-package-linux-x64 \
  --package-dir target/agent-package-win11-x64 \
  --package-dir target/agent-package-win7-x64 \
  --package-dir target/agent-package-win7-x86 \
  --output-dir target/hostlink-release-v0.1.0 \
  --require-all-targets
```

All four packages must represent the same source revision and version. Staging verifies unique targets, binary sizes and hashes. Only the raw executable assets are uploaded to GitHub; local packaging and staging receipts remain local.

See [GitHub Releases](GITHUB_RELEASES.md) for exact asset names and the current private-source policy.

## Invite a machine

```sh
hostlink invite --name lab-host --target x86_64-pc-windows-msvc
```

The Controller checks the selected GitHub release before creating a one-use Hub invitation. The target verifies downloaded executable bytes before enrolling with that invitation. The default bootstrap requests a target-owned GitHub PAT; `--embed-github-token` is an explicit secret-bearing alternative.

Use `hostlink invite --help` for optional version, gateway and token-only controls. See [enrollment](ENROLLMENT.md) for reconciliation after an ambiguous enrollment attempt.
