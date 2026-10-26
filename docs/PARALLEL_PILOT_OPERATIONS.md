# Parallel HostLink HOME pilot lifecycle foundation

This first lifecycle slice prepares and safely owns a private, source-pinned
pilot directory. It does not start Hub, Agent, Caddy, or sshd. The persistent
Caddy/sshd `up` and `check` flow and interactive invitation/enrollment remain
later implementation slices; no command here reports the pilot online or
claims a successful managed-fleet check.

## Requirements

- Run as the intended unprivileged user, never as root.
- Use a normalized absolute root path with no symbolic link in any path
  component. The root must be private (mode `0700`) and owned by the current
  user.
- Prepare from the exact clean Git HEAD. The requested source SHA must be the
  current 40-character Git commit SHA, and the worktree must have no tracked,
  staged, or untracked changes.
- Python 3 and Git must be available.

## Commands

```sh
scripts/hostlink-v2-pilot.sh prepare \
  --root "$HOME/.local/share/hostlink-v2-pilot" \
  --source-sha "$(git rev-parse HEAD)"
scripts/hostlink-v2-pilot.sh status --root "$HOME/.local/share/hostlink-v2-pilot"
scripts/hostlink-v2-pilot.sh logs --root "$HOME/.local/share/hostlink-v2-pilot"
scripts/hostlink-v2-pilot.sh down --root "$HOME/.local/share/hostlink-v2-pilot"
scripts/hostlink-v2-pilot.sh purge --root "$HOME/.local/share/hostlink-v2-pilot"
```

`prepare` writes a versioned owner/source marker atomically and creates an
owner-only `logs/` directory. Repeating it for the same source is safe. A
different source, malformed marker, wrong owner, unsafe path, or changed root
permissions fails closed. `status` reports `PREPARED` only when no process
ledger exists; any present process ledger is conservatively reported as
`OWNED-PROCESS-UNKNOWN`. `logs` reads only regular files owned by the current
user directly inside the owned logs directory, with a maximum of 32 files and
1 MiB per file per invocation. `down` is idempotent for a
stopped root and never signals a PID. Unknown process or job state blocks it.
`purge` requires the exact valid marker, no process or job ledger, and a tree
containing only current-user-owned regular files/directories with no links,
special files, or filesystem crossings.

## Limits and troubleshooting

This is lifecycle foundation only. It does not build or pin binaries, issue
Hub invitations, enroll an Agent, manage service startup, prove job state from
Hub inventory, or provide persistent Caddy/sshd `up`/`check`. The fixture at
`scripts/hostlink-managed-gateway-fixture.sh` remains a temporary integration
test reference and is not changed by this pilot tool. Preserve a root whenever
process or job ownership is uncertain; inspect its marker and state files
manually before deciding on cleanup. Never remove an unknown PID or job record
to make `purge` pass.
