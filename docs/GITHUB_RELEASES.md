# GitHub Releases

HostLink currently resolves production Agent binaries from GitHub Releases in `KDmasterLOL/hostlink`. The repository and all release assets are public. Bootstrap and Agent updates download them without GitHub credentials.

## Release assets

A release contains four raw Agent executables:

| Target | Asset |
| --- | --- |
| Linux x64 (glibc) | `hostlink-agent-x86_64-unknown-linux-gnu` |
| Windows x64 | `hostlink-agent-x86_64-pc-windows-msvc.exe` |
| Windows 7 x64 | `hostlink-agent-x86_64-win7-windows-msvc.exe` |
| Windows 7 x86 | `hostlink-agent-i686-win7-windows-msvc.exe` |

Each asset requires a GitHub-published SHA-256 digest. The Controller fails before issuing an invitation if the required metadata or digest is unavailable. No installer archives, scripts, manifests, or checksums are published as separate release assets. `state/manifest.json` is unrelated private enrollment metadata and must remain installed.

An explicit version selects `vX.Y.Z`; otherwise the Client uses the latest published stable release. Only an exact match for the requested target and its digest is eligible for installation or update.

## Local release preparation

Build and verify a candidate locally from one clean, committed source revision as described in [artifact packaging](ARTIFACTS_AND_INVITES.md). An operator explicitly invokes `just publish`; it verifies the candidate and uses `gh release create` to upload the four raw assets above, then checks the published inventory and SHA-256 digests. Keep the source-bound receipt private and local. GitHub hosts the public release; GitHub Actions does not build or upload it.

## Installation

```sh
hostlink invite lab-win7 --os windows
hostlink invite lab-linux --os linux --version 0.1.0
```

The current Controller prints a disposable POSIX or PowerShell 2 bootstrap rather than a short URL. It validates the release metadata before issuing a one-use Hub invitation. The target selects its platform and downloads the raw executable from `https://github.com/KDmasterLOL/hostlink/releases/download/vTAG/FILENAME`, checks its SHA-256, and invokes `hostlink-agent install`. Neither the Controller nor the target needs a GitHub PAT for this flow; no separate installer script is downloaded. The one-use invitation is consumed during enrollment, not during the download.

The output is one paste-ready command containing the one-use invitation. The Windows command is intended for pasting into cmd.exe or PowerShell; native shell acceptance remains unverified. Treat it as a secret, including terminal history and clipboard. Windows selects NT 6.1 x86/x64 or NT 10 x64 from build 10240 (the initial Windows 10 release); native acceptance remains separate. On NT 6.1 the interactive bootstrap uses WinINet with redirects, authentication, cookies and caching disabled, explicitly allowing one HTTPS redirect to GitHub asset hosts. Certificate validation is not disabled; successful TLS still depends on system configuration. The bootstrap registers and starts the current-user service after installation. See [artifact packaging](ARTIFACTS_AND_INVITES.md), [enrollment](ENROLLMENT.md), and [installation](AGENT_INSTALLATION.md).

The Linux bootstrap allows at most 600 seconds for its bounded raw Agent download (maximum 256 MiB). The default invitation lifetime is 900 seconds; keep the TTL longer than the expected download and enrollment time, especially on very slow links. A failed or timed-out download is removed before the one-use invitation token is written or enrollment starts.

## Updating

`hostlink-agent update` currently uses the `self_update` GitHub RAW backend and a public GitHub release, without a PAT. Update admission is serialized and Windows replacement requires the Agent stopped with its owned task unregistered. See [Windows offline update](AGENT_UPDATE_WINDOWS.md).

The release digest ties the downloaded bytes to GitHub metadata. It is not an independent publisher signature.
