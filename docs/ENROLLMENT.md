# Fresh Agent enrollment

`hostlink-agent enroll` is an explicit one-shot operation for a new, current-user
installation root. It does not adopt an existing Agent root. The enrollment
module sends the shared `hostlink-hub` v2 DTO to `POST /v2/enroll` using HTTPS
with rustls, redirects disabled, bounded timeouts, and a bounded JSON response.
For an operator-managed private CA, pass `--hub-ca-cert /private/hub-ca.pem`.
This adds that PEM certificate to the normal trust roots while preserving
certificate and hostname verification; there is no HTTP or insecure TLS mode.

## Direct CLI

Place the one-use token in a private file (`0600` on Unix; a current-user-only
protected DACL on Windows), then run:

```text
hostlink-agent enroll \
  --hub-url https://hub.example \
  --token-file /private/path/invite-token \
  --root /private/path/new-agent-root \
  --name lab-win7 \
  --user hostlink
```

If Hub returns more than one approved gateway, enrollment stops. Select an
entry from that exact response with `--gateway-index N`; the Agent does not
guess a route. A successful enrollment writes a private `state/agent.json`,
`machine.json`, `manifest.json`, host and reverse-tunnel keys, approved gateway
pin, Controller `authorized_keys`, and a private jobs directory. The machine ID
is generated before the request and kept in the private attempt record. The
configuration binds only to loopback. `run --config state/agent.json` serves
the embedded SSH endpoint and maintains the configured pinned reverse russh
tunnel in the current user session.

If a pending marker remains, do not submit the invite again. The marker means
Hub enrollment may have committed or local publication did not finish. Check
the Hub's secret-free inventory and reconcile the record before creating a new
invite. A rerun against an existing root fails before sending another request.

On Windows the direct `enroll` command validates the current user's private
files and parent directory rather than testing whether its token is elevated.
The published PowerShell bootstrap still requires a non-elevated interactive
session and creates each directory with one protected current-user
`OICI` ACE required by vendored `private-fs`. This owner-only inheritance
also protects SQLite's DB/WAL/SHM files created without an explicit DACL.
Private files instead receive noninheritable ACLs.
Even if enrollment is performed elevated by a separate operator
workflow, Agent runtime refuses elevated tokens before serving remote commands
or Apalis jobs.

## Bootstrap scripts — GitHub-only source

The `hostlink invite --name NAME --target TARGET [--version X.Y.Z]`
Controller command resolves **published** GitHub Release metadata from the
fixed private `KDmasterLOL/hostlink` repository. Controller credentials live
in that controller user's private `hostlink/credentials/github-token`
file. Before requesting an invitation from Hub, Client checks the exact
installer, verifier and ZIP names, their published SHA-256 digests, and
downloads/validates the selected installer. Arbitrary
`--installer-url`/`--agent-url`/`--archive-url` parameters are no longer
accepted. `--token-only` remains for manual enrollment without a runnable
bootstrap command.

Both target bootstrap scripts
(`crates/agent/assets/install-hostlink-agent.sh` on Linux x86_64 and
`Install-HostLink-Agent.ps1` on Windows) use **the target user's own
credential**, not the Controller's token file. Before the first asset fetch,
the target bootstrap checks or securely prompts for a GitHub read-only PAT,
creating `~/.config/hostlink/credentials/github-token` on Linux
(`XDG_CONFIG_HOME` if absolute) or
`%APPDATA%\HostLink\credentials\github-token` on Windows. Owner-only
permissions and no symlink/reparse alias are required. The secret never
appears in the generated command, argv, Hub request, release ZIP or logs.
An already provisioned private credential is reused without modification.

Initial files are always fetched from the fixed GitHub Release asset
API `https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/ID`
and verified against the Release's published SHA-256 pins. The authenticated
API request supports HTTP 200 or a single bounded HTTPS redirect to an
approved GitHub CDN hostname **without forwarding Authorization**; there is
no unrelated website fallback. The installer requires matching sidecar
target/version and independently verifies the downloaded ZIP and extracted
file identities. The verifier creates a private stage with the exact original
`manifest.json`, `archive.sha256`, and `bootstrap-receipt.json`.

Only **after** these byte and manifest checks does the installer prompt
for the separate **one-use HostLink enrollment token**, invoke
`enroll --retain-pending`, publish the verified bundle, and run
`bootstrap-finalize`. That command rechecks installed file identities,
receipts, private state and pending marker; an uncertain enrollment is
not retried automatically. No background service is registered as a side
effect of enrollment; the user can start it explicitly.

On Windows 7, `PowerShell 2` lacks `Expand-Archive`. The target-specific
Rust sidecar remains the ZIP verifier; the installer does not implement a
duplicate ZIP parser. An inline `-EncodedCommand` exceeds the 8191-character
Windows `cmd.exe` limit with credential provisioning; the Client instead
emits a **two-step local helper** (text without a PAT) to save and run
unelevated on the target. The PAT is prompted locally, and the one-use Hub
invite token is prompted only after the downloads are verified.

Native Windows 7 x86/x64 and Windows 11 PowerShell 2/ACL/Task Scheduler
acceptance still requires an authorized disposable target and an immutable
source candidate. Linux source/fixture evidence does not establish those
gates. For release packaging and target credential security see
[GitHub Releases](GITHUB_RELEASES.md) and
[Artifact publication and invites](ARTIFACTS_AND_INVITES.md).
