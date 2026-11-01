# HostLink v2 isolated HOME pilot

This Linux-only operator tool runs an isolated v2 Hub, Caddy HTTPS endpoint,
OpenSSH gateway and freshly enrolled Agent below one private user-owned root.
It does not change the installed ONEC Agent, port 22, user SSH configuration,
global Caddy, FRP, system services or login lingering. All listeners bind only
to `127.0.0.1`; this pilot is not externally reachable and is not a deployment.

## Requirements and source pin

Run as the intended non-root user from an exact clean Git commit. Required local
tools are Rust/Cargo with cached locked dependencies, Python 3.11+, OpenSSH server
and client, Caddy, and OpenSSL. The first `up` builds the Hub,
Agent and Controller in release mode and creates the immutable Linux Agent
package using `scripts/package-hostlink-agent.py`. The package contains exactly
`hostlink-agent-x86_64-unknown-linux-gnu` and a private
`artifact-receipt.json` in raw format 2. The receipt binds the source SHA,
Linux target, Cargo workspace version, exact asset name, byte size and SHA-256;
its `build_receipt` is `null`. The executable is bounded to 256 MiB and the
receipt to 64 KiB. Both fresh and retained packages reject unexpected members,
symlinks, foreign ownership, unsafe permissions, or changed bytes.

Hub, Agent and Controller copies have a separate private `build-receipt.json`
with source SHA and all three binary digests. Creating copies runs Cargo for
that source even if release binaries already exist in the target cache; the
Agent copy must also match the packaged raw executable. Retained copies are
verified against their receipt before reuse. These local provenance receipts
stay in the private pilot root and are not production release assets.

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
- `down` verifies the exact running Agent's private Apalis job directory and
  queries the **loopback-only upstream Board API** for zero pending, running,
  active, stale-running and queued jobs. A missing, malformed or unavailable
  Board response blocks shutdown; it does not inspect or modify SQLite tables.
  It also refuses to stop sshd with an established gateway session after the
  Agent closes its reverse connection. It signals only source- and PID-pinned
  pilot processes, retaining Hub/Agent identities, Apalis SQLite history and
  raw build artifacts for a later `up`.
- `purge` requires a stopped ledger, known owner-scoped Apalis files and no
  symlinks,
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
the real Agent enrollment API. The pilot builds a source-pinned raw Agent
package and serves its local artifact directory through loopback Caddy, but
does not exercise the private GitHub production bootstrap, PAT provisioning,
release download or installer UX. Production bootstrap acceptance requires an
explicitly approved GitHub Release and separate source-exact native checks;
see [Agent installation](AGENT_INSTALLATION.md) and
[packaging and invites](ARTIFACTS_AND_INVITES.md). Local artifact tests are not
production bootstrap evidence.

Focused artifact verification uses disposable synthetic fixtures, the real
packager and a tiny offline Cargo workspace; it does not build HostLink or
start pilot services:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_hostlink_v2_pilot_artifacts.py' -v
```

If loopback sockets are denied by the execution environment, do not report
`up`/`check` as passed. Keep the private root and process evidence intact for
an authorized HOME run with local sockets enabled. Never remove an unknown
process or job record to make `down` or `purge` pass.
