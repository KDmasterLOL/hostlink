# Agent-local jobs

HostLink uses Apalis SQLite and the upstream Apalis Board for durable Agent-local jobs. Detached shell commands use `hostlink exec --host NAME --board-port PORT --detach --command '...'`; native state is read with `hostlink job status --host NAME --board-port PORT JOB_ID`. Both use the upstream Board HTTP API over authenticated, pinned SSH direct-tcpip to `127.0.0.1:PORT`; no separate queue or transport is added. The Board port is randomly selected during Agent enrollment and is absent from the Hub registry, so the caller must supply the exact port. For named Hub targets, detached execution selects the shell from the registered target OS; direct `--config` targets must also pass `--os linux` or `--os windows`, and unknown OS values fail closed. HostLink never scans or guesses ports. Normal `exec` remains session-bound.

## Execution

Jobs contain a program, argv and optional working directory, represented as `CommandJob { program, args, cwd }`. They execute directly as the Agent's OS user through ProcessKit, without implicit shell expansion. `hostlink exec --detach --board-port PORT --timeout-seconds N --command ...` optionally adds `timeout_seconds` to the job, bounded to 1..=14400 seconds. Before submitting an explicit timeout, the Controller opens a pinned SSH direct-tcpip channel and makes a bounded, side-effect-free `GET /new` request. It requires HTTP 200 and exactly one valid `x-hostlink-command-timeout-max` response header whose value covers the requested timeout and does not exceed 14400. Older Agents without this capability are rejected before job submission when the flag is used. Omitting the flag skips the preflight and omits the JSON field, preserving compatibility with older Agents. The option is valid only with `--detach`; it configures Agent command runtime, not the Controller's SSH/Board request timeout. Apalis owns SQLite persistence, queue delivery, retries, statuses and results.

The Board exposes `PUT /api/v1/queues/commands/tasks` and upstream task/worker listing endpoints. The Agent also supplies a small `/new` task form. A command exit code of zero completes as `Done`; a nonzero exit is an execution error and is recorded by Apalis as `Failed`. Apalis SQLite can retry failed tasks while `attempts < max_attempts`. A direct Board API submission that omits `x-task-max-attempts` uses Apalis's default maximum of 25, so side-effectful work can run repeatedly after nonzero exits. Callers that require a terminal failure after one execution must set the upstream task's maximum attempts to one. Neither this failure status nor the attempt limit provides exactly-once execution; crashes can still leave side effects uncertain.

After a crash, Apalis may run a task that had already started. Applications must tolerate repeated side effects; job execution is not exactly once.

The upstream task endpoint reports status and may include a serialized result under `ctx.runs`; `job status` displays that upstream value when present, without treating it as a process exit code. When no upstream run result is present, result and exit code remain unavailable. Shell stdout/stderr are not exposed; use the Board UI or have the command write its own result file when output is needed. A timeout or lost connection during submit leaves the outcome unknown, so do not blindly resubmit side-effectful work. Controller generates a ULID accepted by Apalis `TaskId` and sends it via upstream `x-task-id`.

## Access and lifecycle

The Board listens only on the configured loopback `board_listen` address. Use pinned SSH TCP forwarding to view it remotely. The Board can execute programs with the Agent user's privileges; it is not a public API.

ProcessKit limits concurrent child-process groups and uses platform-supported containment. On Linux the Agent requires cgroup v2; Windows uses Job Objects. Updates require the Agent stopped and the jobs runner lock free. The updater does not read or modify Apalis tables.

Fresh jobs databases are initialized with upstream migrations. Existing databases are preserved and are not silently converted from unrelated old layouts.

See [Agent jobs source](../crates/agent/src/jobs/README.md), [architecture](ARCHITECTURE.md), and [Agent lifecycle](AGENT_LIFECYCLE.md).
