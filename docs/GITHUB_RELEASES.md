# GitHub Releases

HostLink currently resolves production Agent binaries from GitHub Releases in `KDmasterLOL/hostlink`. The repository is **private at the time of this documentation update**. Making the repository public does not, by itself, remove the current Client and Agent code's credential-file requirements; those require a separate implementation change.

## Release assets

A release contains four raw Agent executables:

| Target | Asset |
| --- | --- |
| Linux x64 (glibc) | `hostlink-agent-x86_64-unknown-linux-gnu` |
| Windows x64 | `hostlink-agent-x86_64-pc-windows-msvc.exe` |
| Windows 7 x64 | `hostlink-agent-x86_64-win7-windows-msvc.exe` |
| Windows 7 x86 | `hostlink-agent-i686-win7-windows-msvc.exe` |

Each asset requires a GitHub-published SHA-256 digest. No installer archives, scripts, manifests, or checksums are published as separate release assets. `state/manifest.json` is unrelated private enrollment metadata and must remain installed.

An explicit version selects `vX.Y.Z`; otherwise the Client uses the latest published stable release. Only an authenticated, exact match for the requested target and its digest is eligible for installation or update.

## Credentials

The current implementation reads a fine-grained GitHub PAT with repository `Contents: Read` permission:

| System | User-owned credential path |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/hostlink/credentials/github-token` or `$HOME/.config/hostlink/credentials/github-token` |
| Windows | `%APPDATA%\HostLink\credentials\github-token` |

Controller and target credentials are independent. Files must be owner-only (Unix directories `0700` and token `0600`; Windows protected current-user-only ACLs). The PAT is never needed by the Hub to register a host.

By default, the target bootstrap requests its own PAT without echo. `--embed-github-token` explicitly puts the Controller PAT into its generated bootstrap; that output is secret material. Do not commit, share, or retain it.

## Installation

```sh
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc
hostlink invite --name lab-linux --target x86_64-unknown-linux-gnu --version 0.1.0
```

The current Controller prints a disposable POSIX or PowerShell 2 bootstrap rather than a short URL. It validates the release metadata before issuing a one-use Hub invitation. The target downloads the selected raw executable, checks its SHA-256, and invokes Rust `hostlink-agent install`. The one-use invitation is consumed during enrollment, not during the download.

The current Windows helper must be saved to a private temporary file and executed explicitly. See [artifact packaging](ARTIFACTS_AND_INVITES.md), [enrollment](ENROLLMENT.md), and [installation](AGENT_INSTALLATION.md).

## Updating

`hostlink-agent update` currently uses the `self_update` GitHub RAW backend and a target-owned PAT. Update admission is serialized and Windows replacement requires the Agent stopped with its owned task unregistered. See [Windows offline update](AGENT_UPDATE_WINDOWS.md).

The release digest ties the downloaded bytes to GitHub metadata. It is not an independent publisher signature.
