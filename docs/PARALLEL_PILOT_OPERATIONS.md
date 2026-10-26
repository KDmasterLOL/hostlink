# HostLink v2 isolated HOME pilot

This Linux-only operator tool runs an isolated v2 Hub, Caddy HTTPS endpoint,
OpenSSH gateway and freshly enrolled Agent below one private user-owned root.
It does not change the installed ONEC Agent, port 22, user SSH configuration,
global Caddy, FRP, system services or login lingering. All listeners bind only
to `127.0.0.1`; this pilot is not externally reachable and is not a deployment.

## Requirements and source pin

Run as the intended non-root user from an exact clean Git commit. Required local
tools are Rust/Cargo with cached locked dependencies, Python 3, OpenSSH server
and client, Caddy, and OpenSSL. The first `up` builds the Hub,
Agent and Controller in release mode and creates the immutable Linux Agent
package using `scripts/package-hostlink-agent.py`. The package receipt and
binary digests are retained in the private root and tied to its marker SHA.

The root must be a normalized absolute path, with no symlink in any existing
component, and the parent must belong to the current user. The root is created
with mode `0700`; private files use `0600`. Do not prepare inside the source
worktree or reuse an existing Agent/Hub root.

```sh
PILOT="$HOME/.local/share/hostlink-v2-pilot"
scripts/hostlink-v2-pilot.sh prepare --root "$PILOT" --source-sha "$(git rev-parse HEAD)"
scripts/hostlink-v2-pilot.sh up --root "$PILOT"
scripts/hostlink-v2-pilot.sh status --root "$PILOT"
scripts/hostlink-v2-pilot.sh check --root "$PILOT"
scripts/hostlink-v2-pilot.sh logs --root "$PILOT"
scripts/hostlink-v2-pilot.sh down --root "$PILOT"
scripts/hostlink-v2-pilot.sh up --root "$PILOT"  # restart with the same identity and state
scripts/hostlink-v2-pilot.sh down --root "$PILOT"
scripts/hostlink-v2-pilot.sh purge --root "$PILOT" # explicit irreversible deletion
```

`prepare` records the current source commit and is idempotent only for the same
source. `up` rejects a changed/dirty source and never overwrites existing
artifacts. It creates independent controller and gateway Ed25519 identities,
a private CA and `localhost` leaf, private Hub tokens and state, then starts
Hub, Caddy, alternate-port sshd, creates a one-use Hub invitation through the
real Controller CLI, enrolls the Agent through its real HTTPS CLI, and starts
the exact built Agent binary. The invite token is captured internally and
written to an owner-only one-use file; it is not shown or logged. The Hub owns
the v2 `gateway/hostlink-v2-authorized_keys` projection, which isolated sshd
loads directly. It does not change `~/.ssh/authorized_keys`.

The process ledger records PID, `/proc` start time, executable SHA-256, path,
device/inode and full argv/config identity before any later signal. Commands refuse
unknown, reused or changed process identities. Partial startup rolls back only
children whose identities were captured; uncertain state remains for manual
reconciliation. The tool never escalates to `SIGKILL`.

## What the commands prove

- `status` reports the owned process ledger state. It does not infer Agent
  availability from Hub inventory.
- `check` makes separate checks: authenticated Hub management API, sshd host
  key response against the generated pin, and Controller `verify` over the
  Hub-approved gateway route to the Agent's pinned SSH identity.
- `logs` reads only bounded regular files from the private pilot log directory.
- `down` refuses Prepared, Running, Interrupted or malformed durable job
  records and refuses to stop sshd while an established session remains after
  the Agent closes its reverse connection. It stops only verified pilot
  processes and preserves enrollment keys, Hub registry, artifacts and job
  history for a later `up`.
- `purge` requires a stopped ledger, safe job state and a tree with no symlinks,
  foreign ownership, special files or filesystem crossings.

No `.env` file is read or evaluated. Caddy TLS uses normal hostname and
certificate validation; the Controller and Agent trust only the private CA
alongside normal system roots. Credentials do not appear in process arguments,
URLs, user-visible output or service logs. Hub process tokens are supplied in
its private child environment and stored in private token files.

## Verification boundaries

This local pilot does not prove external DNS/VPS/firewall access, legacy/new
Agent coexistence on another installed host, Windows 11 or Windows 7 behavior,
safe Windows update, source release readiness, or production suitability.
The CLI invitation here is an explicit local token-only invitation followed by
the real Agent enrollment API; the source-pinned installer/package artifacts
are built and served, but the installer UX is not exercised by this lifecycle
command. The full invitation/installer acceptance remains covered separately
by `scripts/hostlink-managed-gateway-fixture.sh`.

If loopback sockets are denied by the execution environment, do not report
`up`/`check` as passed. Keep the private root and process evidence intact for
an authorized HOME run with local sockets enabled. Never remove an unknown
process or job record to make `down` or `purge` pass.
