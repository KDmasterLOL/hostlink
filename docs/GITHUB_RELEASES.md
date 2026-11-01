# HostLink binary-only GitHub Releases (1C-1164)

The sole production artifact source is the private `KDmasterLOL/hostlink`
GitHub Releases repository. Latest means published stable; explicit versions
select exact `vX.Y.Z` tags. No arbitrary URL, mirror or alternate publisher.
This is a source contract; no release or deployment is authorized by this change.

## Release assets

Exactly four raw executables are eligible for publication:

- `hostlink-agent-x86_64-unknown-linux-gnu`
- `hostlink-agent-x86_64-pc-windows-msvc.exe`
- `hostlink-agent-x86_64-win7-windows-msvc.exe`
- `hostlink-agent-i686-win7-windows-msvc.exe`

Each asset needs a GitHub API-published `sha256:<hex>` digest. The updater
uses the upstream `self_update` GitHub backend in RAW mode with the exact
named target asset, version and published digest. A digest authenticates
bytes relative to GitHub metadata; it is not an independent publisher signature.

The Client library's `ArtifactSelection` is issued by the authenticated
GitHub release resolver, not constructed or mutated by library callers;
the rendered bootstrap consumes that validated selection and exposes only
the read-only selected SHA-256 to the CLI.

No ZIP, release manifest, checksum sidecar, installer PS1 or shell asset is
published. Packaging produces one raw executable and a **local**
`artifact-receipt.json`; staging emits only the selected raw assets and a
hidden `.release-receipt.json`. Both receipts stay on the build machine.
Neither is a runtime installation format. See [local packaging](ARTIFACTS_AND_INVITES.md).

## Credentials and invitation

Controller and target each own a separate private credential file:

| Platform | Credential |
| --- | --- |
| Linux | absolute `$XDG_CONFIG_HOME/hostlink/credentials/github-token`, otherwise `$HOME/.config/hostlink/credentials/github-token` |
| Windows | `%APPDATA%\HostLink\credentials\github-token` |

The target bootstrap prompts without echo by default, or reuses its validated
private credential. `hostlink invite --embed-github-token` explicitly embeds
the Controller PAT in the printed bootstrap. Treat stdout, shell history,
clipboard and saved helpers as secret material and dispose of them after use.
Different existing credentials must not be silently overwritten. Without
this opt-in no PAT is included in the generated invitation.

Use repository-scoped `Contents: Read`; this grants source access as well as
binary access. Target credentials require Unix `0600` and private directories,
or a protected current-user-only Windows DACL. A PAT never enters Hub records,
release assets, binaries, download URLs or logs. Tests use synthetic credentials
and temporary roots; never read or copy the real HOME PAT.

The Controller's fixed `credentials/github-token` is HostLink-managed private
state: the `hostlink/credentials` directory must be `0700` and its token
exactly `0600` on Unix, or use the single-current-user protected ACL required
by `private-fs` on Windows. Existing `0400` Controller PAT files are not
silently changed; explicitly set `0600` only after reviewing ownership and
path safety. Credential and directory symlinks, hardlinks and unexpected ACLs
are rejected. User-supplied Hub/SSH input paths are a separate contract.

The Controller resolves the exact raw asset and digest before creating a
Hub invite, then generates disposable POSIX or Windows 7 PowerShell 2 bootstrap
text. Bootstrap downloads **one** executable and verifies SHA-256 before
consuming the separate one-use Hub invitation. It invokes Rust Agent install
for enrollment and executable publication at the stable per-user root.
No Git or other default command installation is part of this flow.

Windows output always contains a disposable PowerShell 2 helper between
`# BEGIN TARGET HELPER` and `# END TARGET HELPER` markers. On the target,
protect the temporary file so only the current user can read or modify it,
then save only the text between the markers as
`%TEMP%\hostlink-bootstrap.ps1`, encoded as UTF-8 with BOM. Review it and
explicitly execute the printed `powershell -NoProfile -ExecutionPolicy Bypass
-File "%TEMP%\hostlink-bootstrap.ps1"` command in an unelevated `cmd.exe`;
optionally append `-NoRun` to install without starting the Agent. Delete the
helper after installation, including on failure. The helper is never installed.
With `--embed-github-token`, its PAT is cleartext and the output warns about it;
without that opt-in it contains no GitHub credential. The helper is not encoded
in a command line: the full script exceeds the `cmd.exe` limit of 8191 characters.
Linux keeps the disposable POSIX bootstrap flow.

Authenticated requests go only to the fixed GitHub API origin. A bounded
HTTPS CDN redirect must not receive Authorization. Missing assets, digests,
private credentials or inaccessible releases fail closed.

## Runtime and acceptance boundaries

See [installation](AGENT_INSTALLATION.md) for stable paths, identity and locks,
and [Windows offline update](AGENT_UPDATE_WINDOWS.md) for the stopped-task gate.
No durable crash journal or automatic crash recovery is promised. Native Win7
x86/x64, Win11, PowerShell 2, ACLs and Task Scheduler acceptance remain separate
release gates. Cross-builds and offline fixtures do not establish them.

The binary-only source is integrated across Agent, Controller and packaging,
with Linux workspace and synthetic fixture checks. No actual GitHub Release
or native Windows installation/update has been accepted yet.
