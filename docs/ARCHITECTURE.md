# HostLink architecture — Agent-local jobs

Development architecture for Huly 1C-1098. This replaces the old SSH jobs
design; earlier source snapshots and rollout notes are historical, not a
description of current `dev`.

## Components

- **HostLink Hub:** fleet registry, invitations, revocation, route and SSH
  identity. Hub does not run commands or store Agent job data.
- **HostLink Client:** selects a managed or explicitly configured host and
  uses pinned `russh` for short SSH `exec`, private SFTP transfers, and
  loopback TCP forwarding. There is no Client jobs API or command uploader.
- **HostLink Agent:** an unprivileged user process with an embedded `russh`
  server and optional outbound pinned reverse SSH tunnel. Separately, one
  Apalis SQLite `commands` queue and `WorkerBuilder` execute `CommandJob`
  entries and retain native state and results.
- **Apalis Board:** the upstream `apalis-board-api 1.0.0` Axum router and
  embedded UI on an independently configured **loopback-only** listener. A
  tiny `/new` form submits JSON directly to the upstream Board task API;
  `/` serves the upstream board for listing tasks/workers.

```text
Browser ── loopback HTTP/SSH TCP forward ──> Agent Apalis Board
                                               │ native TaskSink
                                            SQLite Jobs
                                               │ Apalis WorkerBuilder
                                        CommandJob -> ProcessKit

HostLink Client ── pinned SSH exec/SFTP/forward ──> Agent SSH
Hub ── inventory/enroll/route/revoke ──> Client + Agent
```

## Job execution contract

The typed payload is `CommandJob { program, args, cwd? }`. There is no
automatic shell interpretation: calling `sh -c` or
`powershell.exe -Command` is an explicit command choice. The handler
returns the real process exit code (`Ok(i32)`, including nonzero) or an
execution error (`Err`); Apalis owns queue state, orphan retry and result
storage. After Agent/worker failure an already-started task may be retried
and its side effects repeated. No exactly-once guarantee.

The Agent uses ProcessKit OS group containment and refuses weak POSIX
fallback to avoid orphaned child trees on normal shutdown. Durable state
does **not** mean an OS process lives through an Agent crash. Process
output is not a separate HostLink durable stdout/stderr store; Board
displays upstream task/worker state and tracing information.

The Board's HTTP endpoint can execute arbitrary code as the Agent user.
Only loopback binding is permitted, with exact Host and Origin checks.
Remote browser use must go through trusted pinned SSH TCP forwarding
using the **same local port** as `board_listen`. Never publish this service
on an unauthenticated network listener.

Fresh enrollment allocates distinct loopback SSH and Board listener
addresses and writes them to the private Agent configuration. Legacy
configs without `board_listen` remain valid but do not serve the UI.
No automatic migration is provided for old jobs data: schema v5 is
fresh-only and rejects v4/older/torn state without modifying it.

The Agent updater still requires a private update lock and read-only
inspection of Apalis native pending/queued/running tasks before replacing
an Agent. Unknown or incompatible jobs roots block an update; a finished
job is not an active process.

See [Agent jobs](../crates/agent/src/jobs/README.md),
[Agent jobs contract](AGENT_MINIMAL_JOBS.md),
[Client/Hub](CLIENT_HUB.md),
[Source layout](SOURCE_LAYOUT.md), and
[verification evidence](AGENT_MINIMAL_JOBS_EVIDENCE.md).
