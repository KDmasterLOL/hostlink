# HostLink: GitHub Releases as the only distribution channel

Status: implementation on `dev` under Huly 1C-1159. **No release has been
published or installed by this change**. Native Windows 7/11 and PowerShell 2
acceptance is a release gate, not a substituted static test.

## Artifact source and format

Source: **private** `KDmasterLOL/hostlink` GitHub Releases; do not mirror an
artifact website. The command `hostlink invite --name HOST --target TARGET`
chooses GitHub's latest published stable Release. `--version X.Y.Z`
requests an exact published version. No other publisher URL is accepted by
the managed installation/update flow.

Build the existing source-exact target packages using
`scripts/package-hostlink-agent.py` and native required checks. To turn
separate packages into **one flat release asset directory**, run (examples):

```sh
python3 scripts/stage-hostlink-github-release.py \
  --package-dir target/package-linux-x64 \
  --package-dir target/package-win11-x64 \
  --package-dir target/package-win7-x64 \
  --package-dir target/package-win7-x86 \
  --output-dir target/hostlink-release-vX.Y.Z \
  --require-all-targets
```

The stage command **does not contact GitHub, create tags, or publish**. Its
output uses unique asset names and is checked against the package receipts:

- `hostlink-agent-x86_64-unknown-linux-gnu.zip` and
  `hostlink-agent-x86_64-unknown-linux-gnu` (standalone verifier).
- `hostlink-agent-x86_64-pc-windows-msvc.zip` and
  `hostlink-agent-x86_64-pc-windows-msvc.exe`.
- `hostlink-agent-x86_64-win7-windows-msvc.zip` and
  `hostlink-agent-x86_64-win7-windows-msvc.exe`.
- `hostlink-agent-i686-win7-windows-msvc.zip` and
  `hostlink-agent-i686-win7-windows-msvc.exe`.
- Shared `install-hostlink-agent.sh` (Linux) and
  `Install-HostLink-Agent.ps1` (Windows).

`.release-receipt.json` is the **local** staging receipt, not an Agent
download. Each published GitHub asset must have a `sha256:<hex>` digest,
and its contents must match that receipt. Version tags use `vX.Y.Z` and
`manifest.json` within each ZIP retains `version=X.Y.Z`. Prefer immutable
GitHub Releases; require OS- and source-exact acceptance before actual release.

## GitHub credential on the target (user-approved)

A repository-scoped, **read-only** GitHub credential is read from:

- Linux: `$XDG_CONFIG_HOME/hostlink/credentials/github-token` where
  `XDG_CONFIG_HOME` is an **absolute** path; otherwise
  `~/.config/hostlink/credentials/github-token`.
- Windows: `%APPDATA%\HostLink\credentials\github-token` in the
  **current user's** profile, not the system/service profile.

By default bootstrap prompts locally without echoing and creates the
user-owned credential file (or reuses a validated existing one).
With explicit `hostlink invite --embed-github-token`, the bootstrap instead
provisions the Controller credential automatically. Different existing
credentials are not overwritten. Invalid files fail closed.
The Agent subsequently reads the same file for update. The Controller also
needs its own credential file under its own user profile to resolve Releases
and verify the installer **before issuing a one-use invitation**.

Create the GitHub fine-grained personal access token with access only to this
repository and `Contents: Read`. This permission includes **the source
repository**, not solely release binaries. On untrusted/customer machines
consider an independently owned private repository containing only binary
Releases, or separate credentials per machine to reduce blast radius. Shared
permanent PATs are simpler but are revocable at the cost of coordinated
rotation of every machine. The explicit opt-in prints a PAT-bearing
bootstrap command. Treat that output, copied shell commands and saved
Windows helper files as sensitive; delete temporary helpers after use.
Without this opt-in the generated invitation contains no GitHub PAT.
Never embed PAT bytes in committed programs, releases or Hub records.
A file with restrictive permissions protects against **other local users**,
not against compromise of the Agent's own user account.

## Initial installation and future update

1. A trusted Controller authenticated to GitHub resolves the exact published
   Release, checks target-specific ZIP, sidecar, installer names and full
   GitHub-provided SHA-256 digests, downloads and preflights the installer
   **before** creating the one-use Hub invitation.
2. The copyable bootstrap command runs on the **target**. By default it
   provisions the credential through a hidden local prompt; with explicit
   `--embed-github-token`, it uses the Controller-supplied value instead.
   It downloads the chosen installer and checks SHA-256 before executing it.
3. The installer downloads the exact target-specific executable verifier and
   ZIP using the same credential, checks their independently selected hashes,
   runs `bootstrap-verify`, and only then prompts for the one-use Hub invite
   token and performs secure enrollment/finalization.
4. An already installed Agent uses `hostlink-agent update` (latest) or
   `hostlink-agent update --version X.Y.Z` (exact). It reads the target's
   private credential, verifies release metadata/digest and the ZIP package,
   and updates only when the stopped-Agent/offline gate permits publication.

GitHub asset APIs may return HTTP 200 binary data or HTTP 302 to its
content-delivery network. The authenticated request is sent **only** to the
pinned GitHub API host; a separate HTTPS redirect download must **never**
forward Authorization. All downloads must be bounded by timeout and file size,
and all files verified by SHA-256 and format before enrollment/installation.

For Windows, stopping/removing the current-user Task Scheduler registration
and running a separately verified updater outside installed `bin` are still
required. Updating the executable while the Agent is running is prohibited.
This change does not deploy Agents, revoke/replace existing registrations,
or silently restart services.

## Acceptance and limitations

No GitHub Release was present in the private repository on 2026-11-01.
A real private-release download requires a subsequently **approved immutable
release** and authorized credentials; offline fixtures cannot prove it.
Windows 7 x86/x64, Windows 11, PowerShell 2 target profile/ACLs and native
Task Scheduler offline update require explicitly approved disposable targets.

Source contracts: [Agent installation](AGENT_INSTALLATION.md),
[Agent enrollment](ENROLLMENT.md), [Artifact and invites](ARTIFACTS_AND_INVITES.md).
