# Agent artifacts and invitations

Release packaging and inviting a machine are separate operations. Packaging does not create a Git tag, publish a release, enroll a host, or install an Agent.

## Build and verify raw assets

Build all four targets locally from the same clean, committed revision. Record the full Git SHA before and after the build and require `git status --porcelain=v1 --untracked-files=all` to be empty at both points. Record the version, target, toolchain, size and SHA-256 of each executable. Compare staged bytes with their build outputs; verify the exact four nonempty, unique asset names in [GitHub Releases](GITHUB_RELEASES.md). A digest confirms byte identity, not publisher authenticity.

The root `Justfile` provides `just check`, `just build-linux`, `just build-windows`, `just build-win7-x64`, `just build-win7-x86`, `just build-all`, `just stage`, `just verify-candidate`, and `just publish`. Build all targets, stage the candidate, and verify it locally. Consult `just --list` and the Justfile for prerequisites.

`stage` checks all four build outputs, their checksums and toolchain records before creating the candidate directory. A later staging or verification failure can still leave an incomplete candidate at `target/release-candidate/<source-sha>`; inspect and remove that local directory before retrying. Run the preflight regression with `python3 tests/release/test_stage.py`.

An operator explicitly invokes `just publish` to publish: it verifies the candidate, requires the version tag to already point to the source commit and no existing release for that tag, then runs `gh release create` to upload exactly the four raw Agent executables. It checks the published asset inventory and SHA-256 digests against the local candidate. Keep the source-bound receipt and verification records private and local; never upload them as release assets. GitHub Actions does not build or upload release candidates.

For Win7, retain the pinned cross-build and PE inspections in [Win7 build and inspection](WIN7_REWRITE_ACCEPTANCE.md). These checks do not execute `binary-info` on Windows 7. Native identity and compatibility acceptance on each Windows version remain separate; the source SHA in the local record is not embedded in the executable.

## Invite a machine

```sh
hostlink invite --name lab-host --target x86_64-pc-windows-msvc
```

The Controller checks the selected GitHub release before creating a one-use Hub invitation. Each selected raw executable must be uniquely named, uploaded, nonempty, at most 256 MiB, and have a published SHA-256 digest. The target verifies downloaded executable bytes before enrolling with that invitation. The controller embeds the one-use Hub invite in a single target-side command; public Release downloads do not require a GitHub PAT or a separate install script. Linux bootstrap requires curl 8.4 or newer to enforce the download limit while streaming.

Use `hostlink invite --help` for optional version, gateway and token-only controls. See [enrollment](ENROLLMENT.md) for reconciliation after an ambiguous enrollment attempt.
