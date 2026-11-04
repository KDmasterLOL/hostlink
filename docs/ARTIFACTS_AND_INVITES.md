# Agent artifacts and invitations

Release packaging and inviting a machine are separate operations. Packaging does not create a Git tag, publish a release, enroll a host, or install an Agent.

## Build and verify raw assets

Build each target from the same clean, committed revision and record the full Git SHA, toolchain, target and version. For Linux:

```sh
git status --porcelain=v1
git rev-parse HEAD
cargo build --locked --release -p hostlink-agent --target x86_64-unknown-linux-gnu
sha256sum target/x86_64-unknown-linux-gnu/release/hostlink-agent
```

The status must be empty before and after building. For Windows build on the corresponding MSVC environment; for Win7 follow [Win7 build and inspection](WIN7_REWRITE_ACCEPTANCE.md). Copy each executable to its exact asset name listed in [GitHub Releases](GITHUB_RELEASES.md), then calculate SHA-256 on the copied bytes and compare it with the source. Record the four target names, sizes, digests, version and source SHA together. Verify all four are unique, nonempty and built from the same revision before release. Compare the published GitHub digests with those recorded locally.

There is currently no automated source-bound packaging or staging receipt gate; these checks require independent review before publication. A digest confirms byte identity, not publisher authenticity.

## Invite a machine

```sh
hostlink invite --name lab-host --target x86_64-pc-windows-msvc
```

The Controller checks the selected GitHub release before creating a one-use Hub invitation. The target verifies downloaded executable bytes before enrolling with that invitation. The default bootstrap requests a target-owned GitHub PAT; `--embed-github-token` is an explicit secret-bearing alternative.

Use `hostlink invite --help` for optional version, gateway and token-only controls. See [enrollment](ENROLLMENT.md) for reconciliation after an ambiguous enrollment attempt.
