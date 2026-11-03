# Fresh Agent enrollment

`hostlink-agent enroll` is an explicit one-shot operation for a new, current-user
installation root. It does not adopt an existing Agent root. The enrollment
module sends the shared `hostlink-hub` v2 DTO to `POST /v2/enroll` using HTTPS
with rustls, redirects disabled, bounded timeouts, and a bounded JSON response.
For an operator-managed private CA, pass `--hub-ca-cert /private/hub-ca.pem`.
This adds that PEM certificate to the normal trust roots while preserving
certificate and hostname verification; there is no HTTP or insecure TLS mode.

## Stable root and install owner

The Rust Agent install operation owns enrollment and executable publication at
one stable per-user root: absolute `$XDG_DATA_HOME/hostlink/Agent`, otherwise
`$HOME/.local/share/hostlink/Agent` on Linux; current-user OS-resolved
`%LOCALAPPDATA%\HostLink\Agent` on Windows. No random installation roots.
See [installation](AGENT_INSTALLATION.md). Manual `enroll` is a low-level
operation, not a replacement installer or an alternate managed root policy.

If Hub returns more than one approved gateway, enrollment stops unless an
explicit zero-based `--gateway-index N` selects an entry in the enrollment
response. Pass it to `hostlink-agent install`, or to `hostlink invite` to
include it in the generated bootstrap. The Agent does not guess a route.
Selection is validated after the Hub enrollment request: a missing or
out-of-range index may consume the one-use invite and leaves a pending marker.
Reconcile the Hub record before creating a new invite; do not retry the old one.
A successful enrollment writes a private `state/agent.json`,
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
The Controller-generated disposable PowerShell bootstrap requires a non-elevated interactive
session and creates each directory with one protected current-user
`OICI` ACE required by vendored `private-fs`. This owner-only inheritance
also protects SQLite's DB/WAL/SHM files created without an explicit DACL.
Private files instead receive noninheritable ACLs.
Even if enrollment is performed elevated by a separate operator
workflow, Agent runtime refuses elevated tokens before serving remote commands
or Apalis jobs.

## Disposable bootstrap — GitHub-only source

`hostlink invite --name NAME --target TARGET [--version X.Y.Z]` resolves
published metadata from private `KDmasterLOL/hostlink`. The Controller checks
the exact raw executable asset and published digest before creating a Hub
invitation and renders disposable Win7 PowerShell 2 or POSIX bootstrap.
There are no published/installed installer, run or update scripts.

Default target bootstrap prompts without echo for a read-only GitHub PAT or
reuses a validated target-owned credential. Explicit `--embed-github-token`
prints the Controller PAT in the bootstrap; treat that output and saved helper
as secret and dispose of them after use. Without opt-in no PAT is embedded.
The target credential is `0600` on Unix or protected current-user-only Windows
DACL, stored separately from enrollment state. See [GitHub credentials](GITHUB_RELEASES.md).

The bootstrap downloads one exact raw binary via the fixed GitHub API, follows
only a bounded approved HTTPS CDN redirect without Authorization, and checks
SHA-256 **before consuming** the separate one-use Hub invitation. Rust Agent
install owns enrollment and executable publication. No Git/default tools are
installed. No release manifest, archive hash or bootstrap receipt is created.
`state/manifest.json` remains the private enrollment-key manifest and must be
preserved. Native Win7/11 PS2/ACL/lifecycle acceptance remains a separate gate;
packaging tests alone do not validate it.
