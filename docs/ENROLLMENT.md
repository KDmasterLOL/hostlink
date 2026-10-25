# Fresh Agent enrollment

`hostlink-agent enroll` is an explicit one-shot operation for a new, current-user
installation root. It does not adopt an existing Agent root. The enrollment
module sends the shared `hostlink-hub` v2 DTO to `POST /v2/enroll` using HTTPS
with rustls, redirects disabled, bounded timeouts, and a bounded JSON response.

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

## Bootstrap scripts

`crates/agent/assets/Install-HostLink-Agent.ps1` supports Windows PowerShell 2
syntax and requires exact same-origin HTTPS URLs and independent lowercase
SHA-256 pins for the target-specific executable sidecar and
`hostlink-agent-TARGET.zip`, plus exact semantic version and target from the
trusted artifact selection. It rejects elevated
or service sessions, uses a new owner-only `%LOCALAPPDATA%` parent, reads the
token with `Read-Host -AsSecureString`, and invokes enrollment without putting
the token in argv. It checks the selected Windows target against OS version and
architecture, including rejecting x86-on-WOW64 as proof of Win7 x86. It starts
the Agent in the foreground by default; `-NoRun` prints the same-user command.

`crates/agent/assets/install-hostlink-agent.sh` supports x86_64 Linux and
requires curl, sha256sum, stat, mktemp, and standard shell tools. It requires
same-origin HTTPS package URLs, downloads without following redirects, checks
both source digests and the sidecar version, then asks the sidecar to run
`bootstrap-verify` before it reads the token. The sidecar shares the updater's
ZIP parser, package inventory, manifest and member hash checks, size bounds,
target checks, and safe member staging. It also proves its own executable bytes
match the ZIP's `hostlink-agent` member. Verification creates only a new private
staging directory and writes matching `install.json` metadata plus a finite
`bootstrap-receipt.json` containing the selected source digest and validated
manifest file identities. The installer publishes the binary extracted from the
ZIP, never the sidecar copy, then enrolls into a fresh private root and starts
the Agent in the foreground.

Installer enrollment uses a hidden `--retain-pending` mode. After copying the
ZIP executable and source receipt into the new root, it invokes
`bootstrap-finalize --root ...`; that command revalidates the exact installed
inventory, file digests, metadata, receipt, private state directory, and pending
marker before removing the marker. A failure after the one-use token was sent
therefore leaves private reconciliation state and cannot trigger automatic
reenrollment.

PowerShell 2 uses the same Rust ZIP verifier sidecar because it has no
`Expand-Archive` and the installer does not implement a second ZIP parser. Any
archive, member, target, version, output-path, or sidecar mismatch fails before
the token prompt, so it cannot issue an enrollment request. Once `enroll` is
invoked, any uncertain outcome retains the pending marker; the one-use token is
never retried automatically.

The source-selection caller must pass the chosen immutable artifact tuple. For
PowerShell this is `AgentUri`, `AgentSha256`, `ArchiveUri`, `ArchiveSha256`,
`AgentVersion`, and `Target`; for Linux these map to `--agent-url`,
`--agent-sha256`, `--archive-url`, `--archive-sha256`, `--agent-version`, and
`--target`. `ArchiveUri` must name `hostlink-agent-TARGET.zip`; the sidecar and
ZIP digests are separate lowercase SHA-256 values. The `hostlink invite` caller
is a separate Client owner and is not implemented in this Agent worktree, so
it must emit these exact values before the generated command can be considered
runnable.

Win7 x64/x86 native PowerShell 2 acceptance and Win11 acceptance must be run on
an immutable source candidate. Linux source tests do not establish those
platform gates. Enrollment is not a service install and creates no background
process on its own; `run` belongs to the logged-in user session.
