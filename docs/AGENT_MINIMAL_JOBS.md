# Agent-local jobs

HostLink uses Apalis SQLite and the upstream Apalis Board for durable Agent-local jobs. The Controller has no `hostlink jobs` command or separate jobs-over-SSH protocol.

## Execution

Jobs contain a program, argv and optional working directory, represented as `CommandJob { program, args, cwd }`. They execute directly as the Agent's OS user through ProcessKit, without implicit shell expansion. Apalis owns SQLite persistence, queue delivery, retries, statuses and results.

The Board exposes `PUT /api/v1/queues/commands/tasks` and upstream task/worker listing endpoints. The Agent also supplies a small `/new` task form.

After a crash, Apalis may run a task that had already started. Applications must tolerate repeated side effects; job execution is not exactly once.

## Access and lifecycle

The Board listens only on the configured loopback `board_listen` address. Use pinned SSH TCP forwarding to view it remotely. The Board can execute programs with the Agent user's privileges; it is not a public API.

ProcessKit limits concurrent child-process groups and uses platform-supported containment. On Linux the Agent requires cgroup v2; Windows uses Job Objects. Updates require the Agent stopped and the jobs runner lock free. The updater does not read or modify Apalis tables.

Fresh jobs databases are initialized with upstream migrations. Existing databases are preserved and are not silently converted from unrelated old layouts.

See [Agent jobs source](../crates/agent/src/jobs/README.md), [architecture](ARCHITECTURE.md), and [Agent lifecycle](AGENT_LIFECYCLE.md).
