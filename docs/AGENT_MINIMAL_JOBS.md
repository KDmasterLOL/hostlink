# Agent-local jobs

HostLink uses Apalis SQLite and the upstream Apalis Board for durable Agent-local jobs. Detached shell commands use `hostlink exec --host NAME --board-port PORT --detach --command '...'`; native state is read with `hostlink job status --host NAME --board-port PORT JOB_ID`. Both use the upstream Board HTTP API over authenticated, pinned SSH direct-tcpip to `127.0.0.1:PORT`; no separate queue or transport is added. The Board port is randomly selected during Agent enrollment and is absent from the Hub registry, so the caller must supply the exact port. For named Hub targets, detached execution selects the shell from the registered target OS; direct `--config` targets must also pass `--os linux` or `--os windows`, and unknown OS values fail closed. HostLink never scans or guesses ports. Normal `exec` remains session-bound.

## Execution

Jobs contain a program, argv and optional working directory, represented as `CommandJob { program, args, cwd }`. They execute directly as the Agent's OS user through ProcessKit, without implicit shell expansion. Apalis owns SQLite persistence, queue delivery, retries, statuses and results.

The Board exposes `PUT /api/v1/queues/commands/tasks` and upstream task/worker listing endpoints. The Agent also supplies a small `/new` task form.

After a crash, Apalis may run a task that had already started. Applications must tolerate repeated side effects; job execution is not exactly once.

The upstream task endpoint reports status but not shell stdout, stderr, or exit code; `job status` marks these unavailable. Use the Board UI or have the command write its own result file when output is needed. A timeout or lost connection during submit leaves the outcome unknown, so do not blindly resubmit side-effectful work. Controller generates a ULID accepted by Apalis `TaskId` and sends it via upstream `x-task-id`.

## Access and lifecycle

The Board listens only on the configured loopback `board_listen` address. Use pinned SSH TCP forwarding to view it remotely. The Board can execute programs with the Agent user's privileges; it is not a public API.

ProcessKit limits concurrent child-process groups and uses platform-supported containment. On Linux the Agent requires cgroup v2; Windows uses Job Objects. Updates require the Agent stopped and the jobs runner lock free. The updater does not read or modify Apalis tables.

Fresh jobs databases are initialized with upstream migrations. Existing databases are preserved and are not silently converted from unrelated old layouts.

See [Agent jobs source](../crates/agent/src/jobs/README.md), [architecture](ARCHITECTURE.md), and [Agent lifecycle](AGENT_LIFECYCLE.md).
