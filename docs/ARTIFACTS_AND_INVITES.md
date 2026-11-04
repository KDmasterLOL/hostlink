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

For a release candidate, dispatch `Source checks and release candidate` on the intended commit. All four builds and the aggregate job must succeed in that run. The retained `release-candidate-<source SHA>` artifact contains the four raw executables, `SOURCE_SHA`, and `SHA256SUMS`; check the source SHA, version and digests before publication and compare each published GitHub digest with the candidate. The workflow does not publish or enforce release permissions, so release operators must not substitute a push/PR source-check result for the successful dispatch. A digest confirms byte identity, not publisher authenticity.

The Win7 jobs cross-compile and inspect both PE files, including static CRT imports; they do not execute `binary-info` on Windows 7. Native identity and compatibility acceptance on each Windows version remain separate. The source SHA is workflow provenance, not embedded in the executable.

## Invite a machine

```sh
hostlink invite --name lab-host --target x86_64-pc-windows-msvc
```

The Controller checks the selected GitHub release before creating a one-use Hub invitation. The target verifies downloaded executable bytes before enrolling with that invitation. The controller embeds the one-use Hub invite in a single target-side command; public Release downloads do not require a GitHub PAT or a separate install script.

Use `hostlink invite --help` for optional version, gateway and token-only controls. See [enrollment](ENROLLMENT.md) for reconciliation after an ambiguous enrollment attempt.
