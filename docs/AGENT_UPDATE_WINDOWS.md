# Windows Agent: GitHub-only offline update (1C-1159)

The current user must **stop** the installed Agent and remove its
current-user Task Scheduler task, then run a verified, separate
`hostlink-agent.exe` updater from beneath the private Agent root but
**outside** `bin`. Running the updater or replacement of a live Agent
image is not supported. The updater never kills processes or manipulates
Task Scheduler registrations by itself.

```text
hostlink-agent.exe update                 # GitHub's latest stable release
hostlink-agent.exe update --version 1.2.3 # exact published GitHub release
```

`--root ROOT` is optional on Windows: the OS resolves the exact
current-user LocalAppData/HostLink/Agent root. The Agent checks the private
root and exclusive `update.lock` and `jobs/runner.lock`, requires no
registered Task Scheduler task or running installed executable, and fails
before publication when any admission check fails.

The private GitHub credential is stored in **the target user's**
`%APPDATA%\HostLink\credentials\github-token`, created by the target-side
bootstrap prompt with an owner-only protected DACL. Updates read it via
native Win7-compatible APIs and do **not** accept raw artifact URLs,
command-line tokens or token environment variables. The credential must
provide repository-scoped GitHub `Contents:Read`. An inaccessible or
unpublished GitHub Release is an error, not a reason to retry a different
publisher.

The fixed private `KDmasterLOL/hostlink` GitHub API yields an exact
version and target asset with a SHA-256 digest. `self_update 1.3.1`
verifies SHA/ZIP/manifest and extracted file inventory before swapping
the complete Agent `bin` directory. The publisher preserves the source
`manifest.json`, writes canonical `archive.sha256`, and rereads the
installed identity. HTTPS-only CDN redirects do not forward Authorization.
There is no independent publisher signature, no general release engine,
no durable crash journal and no automatic task restart. A power loss
between renames can require manual `bin` recovery.

The bundle contains the PowerShell 2-compatible
`Update-HostLink-Agent.ps1` wrapper. Pass
`-Updater` pointing at the **separate verified executable**; optionally
pass `-Version 1.2.3`. It determines `ROOT` from the bundle location and
calls the same GitHub-only Agent updater. No `-Url` or `-Sha256` flags.

For fresh Windows installation, `hostlink invite` supplies an installer
bootstrap in two steps when the safe PowerShell code exceeds the 8191
character `cmd.exe` command-line limit. The helper contains **no PAT**.
The target user saves the helper as a local .ps1 and runs it unelevated;
its hidden prompt securely provisions the GitHub token before fetching
the release-asset installer, sidecar, and archive. Files are SHA-pinned,
then `bootstrap-verify` is run **before** asking for the one-use
HostLink enrollment token.

Native Windows 7 (x86/x64), Windows 11, PowerShell 2, file ACL and
Task Scheduler concurrency acceptance is still outstanding; Linux
static/source checks do not establish native correctness. No live
machines, tasks, registrations or production data were modified.

See [GitHub release lifecycle](GITHUB_RELEASES.md),
[Agent install/identity](AGENT_INSTALLATION.md) and
[historical self-update record](SELF_UPDATE_REWRITE.md).
