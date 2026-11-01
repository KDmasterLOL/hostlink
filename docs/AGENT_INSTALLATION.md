# Installed Agent and first-install verification — current 1C-1159 contract

**Only** GitHub Releases in the private `KDmasterLOL/hostlink` repository
are supported as production artifact sources. No external artifact site,
operator-selected URL, mirror, or env token override remains. For the release
and target-side bootstrap contracts see [GitHub Releases](GITHUB_RELEASES.md).

## Installed Agent

```sh
hostlink-agent update                     # latest published stable release
hostlink-agent update --version 1.2.3     # explicitly selected release, downgrade permitted
hostlink-agent update --root ROOT         # installed-root override
```

The public library interface is
`update_from_github(root: &Path, version: Option<&semver::Version>) -> io::Result<bool>`.
The installed Agent reads its own private user credential from
`~/.config/hostlink/credentials/github-token` on Linux (honouring an absolute
`XDG_CONFIG_HOME`) or `%APPDATA%\HostLink\credentials\github-token` on
Windows. It never obtains a PAT from CLI arguments, `GH_TOKEN`, `GITHUB_TOKEN`,
the Hub, or the release package. Absent or unsafe credentials fail closed.

GitHub's pinned upstream `self_update::github` backend discovers latest
published stable release or exact `vX.Y.Z` (also accepts unprefixed exact
tags). The selected release must contain exactly one
`hostlink-agent-TARGET.zip` with a valid GitHub API-published
`sha256:<hex>` digest. Release metadata and asset URLs must come from the
fixed authenticated GitHub API origin. The checksum verifies bytes against
GitHub's metadata; it is **not** an independent publisher signature.

The sole publisher remains upstream `self_update::backends::custom::Update`:
it verifies the complete ZIP SHA-256, archive members, manifest target/version
and extracted executable and scripts; writes canonical `archive.sha256`;
publishes the verified bundle under `ROOT/bin`; and reads back the installed
identity. Both `ROOT/update.lock` and `ROOT/jobs/runner.lock` remain held
throughout. Apalis SQLite state and keys are never modified by the updater.
GitHub asset downloads support bounded HTTPS-only CDN redirects, with
authentication sent only to the initial `api.github.com` request.

`true` means installed, `false` means already current. Without
`--version` the updater cannot downgrade or silently reinstall the same
version. A supplied older version is allowed. If there is no published
release, missing target asset, missing digest, token or network access, the
command errors without claiming an update.

On Linux the default `ROOT` is derived from the actual installed executable
at `ROOT/bin/hostlink-agent` (the installer uses randomized private parents).
A development binary must pass `--root`. On Windows the install root is the
current user's OS-resolved LocalAppData/HostLink/Agent, but update must still be
performed by a **verified separate executable outside the installed bin**.
Windows requires the Agent stopped, current-user Task Scheduler registration
removed, and no running installed Agent image. No part of `update`
automatically stops/restarts/registers a service.

## ZIP package identity

`scripts/package-hostlink-agent.py` creates target-specific packages with
the exact interior path `hostlink-agent-TARGET/`, `manifest.json`, executable
and helper scripts. The source manifest is retained byte-for-byte in
`ROOT/bin` and records `format=2`, `component=agent`, target, version and
per-file SHA-256. `archive.sha256` is added **after** ZIP verification (an
archive cannot self-hash). There is no `install.json` compatibility layer.

`scripts/stage-hostlink-github-release.py` verifies package source/version
receipts and creates one flat uniquely-named multi-target GitHub upload
directory without publishing a tag or release. See
[artifact build and staging](ARTIFACTS_AND_INVITES.md).

## Fresh bootstrap

`hostlink invite` resolves GitHub Release metadata, validates all required
assets and downloads/checks the selected installer **before** requesting a
one-use Hub invitation. The copyable target bootstrap does NOT contain the PAT:
it prompts locally without echoing (or verifies an existing private credential)
and stores it in the target user's private credential file. The signed-by-hash
installer, target-specific sidecar executable, and ZIP are then fetched via
GitHub release-asset API with target-side credential and bounded manual HTTPS
redirects; their SHA-256 hashes are checked before `bootstrap-verify`.

The verifier checks ZIP inventory, file digests, target and source-sidecar
identity, stages a fresh private bundle, and writes a separate
`bootstrap-receipt.json`. Only after source verification does bootstrap
prompt for the **different, one-use Hub invitation token** and enroll. The
one-use token is never reused automatically after an uncertain outcome.
`bootstrap-finalize` checks installed files, receipt, private state and
pending marker before completing.

The target's GitHub token remains outside the Agent install root/ZIP. It is
not an enrollment or Hub registration secret.

## Known acceptance gates

- No verified live private GitHub Release existed as of 2026-11-01. Do not
  confuse synthetic API/HTTPS fixtures with a published-release download.
- Windows 7 x86/x64 and Windows 11 PowerShell 2/ACL/Task Scheduler native
  acceptance has **not** run for this revision.
- Power-loss during the upstream directory renames can leave `bin` missing;
  upstream rollback handles ordinary in-process publication errors only.
- ZIP network download is bounded by a read cap; ZIP declared expansion sizes
  are not an independent streaming quota against malicious false size headers.

[Windows offline updater](AGENT_UPDATE_WINDOWS.md) ·
[Source layout](SOURCE_LAYOUT.md) ·
[Historical self-update decisions](SELF_UPDATE_REWRITE.md)
