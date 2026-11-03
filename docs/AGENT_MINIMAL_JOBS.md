# Agent-local Apalis jobs — contract

Huly 1C-1098 supersedes the SSH `hostlink-jobs` protocol, Client jobs
CLI, SFTP binary sealing and HostLink's custom jobs lifecycle.

## Upstream ownership

`apalis-core` and `apalis-sqlite` **1.0.0** own the `commands`
queue, delivery, locking, native task status and result, worker heartbeat
and orphan recovery. `apalis-board-api` **1.0.0** provides the stock
HTTP tasks/queues/workers API and embedded browser UI. No parallel queue,
job listing SQL, custom result model, or job-specific SSH transport.

Commands are `CommandJob { program: String, args: Vec<String>,
cwd: Option<String> }`. They execute directly as the unprivileged
Agent OS user using ProcessKit. No implicit shell. Task outcomes are
recorded by Apalis: `Done + Ok(exit_code)` or `Failed + Err(error)`.
The Board's own API at `PUT /api/v1/queues/commands/tasks` accepts
JSON payloads, and `GET /api/v1/queues/commands/tasks` lists tasks.
`/new` is a tiny form which calls the upstream API; `/` is the
upstream Board app. No separate endpoint or custom tasks service.

Apalis may replay a task that was already started after worker/Agent
failure. This can repeat side effects. The result is **not** proof of
exactly-once execution; a crashed OS process cannot be recovered.

## Security and lifecycle

A loopback-only `board_listen: Option<SocketAddr>` is explicitly
configured. Non-loopback or zero-port addresses are refused. Fresh
enrollment writes an allocated Board loopback port distinct from SSH.
Existing configs with a missing/null field keep serving SSH without
Board until configured. HTTP requests require the expected Host and
same-origin Origin header when present. This is a local code-execution
service, not authenticated HTTP for public deployment. Remote access
is via pinned SSH local TCP forwarding **on the same port**.

At most 16 ProcessKit processes execute concurrently. Linux requires
CgroupV2, Windows requires JobObject, and FreeBSD requires ProcessReaper;
weak POSIX fallback is refused. Worker shutdown stops active jobs and
waits for ProcessKit to confirm the process tree emptied; unconfirmed
teardown remains a failure. Program and argv inputs are bounded.
The worker persists native results, not separate HostLink stdout/stderr
spools. Upstream event and trace monitoring is distinct from capture of
arbitrary raw command output.

The SQLite database is a persistent local `jobs/jobs.db`, owned by Apalis
through SQLx. Fresh enrollment runs the upstream Apalis SQLite migrations.
Existing databases open without creating or migrating missing/legacy state;
HostLink no longer manages its own `DurableMeta`, SQLx checksum inspection,
WAL/SHM permission sweeps, or directory-entry allowlist. Existing v5 data is
left untouched; an older layout is not imported or deleted automatically.
SQLx/Apalis errors surface when they open or use incompatible state.

The Board passes native task lifecycle headers, attempt limits and scheduling
parameters directly to Apalis, without HostLink-specific restrictions.
Neither service nor updater reads Apalis's Jobs table or blocks process
shutdown on queued tasks. `runtime::serve_on` holds the process-lifetime
`jobs/runner.lock` on Linux and Windows; the updater requires the **same**
canonical lock to be free and serializes update invocations via `update.lock`.
On Windows, updates are **offline only**: the operator explicitly stops and
removes the verified current-user Task Scheduler registration, then runs a
separate verified updater executable under the stable Agent root but outside
`bin`. The updater refuses registered or running Agents; it neither invokes
a control pipe nor restarts the Agent. The sole raw publisher is upstream
`self_update` with published SHA-256 and installed-binary identity readback.
Normal publication errors have best-effort rollback, not durable power-loss
recovery. Pending tasks remain in Apalis for later delivery; an interrupted
task may run again after restart. Shutdown/process-tree safety and source-
exact native Windows 7/11 updater acceptance remain separate release gates.

SFTP is independent of jobs and stays within private
`transfers/<controller-fingerprint>` directories. The `hostlink` CLI
retains SSH exec and forwarding, but provides no `hostlink jobs`
commands. The SSH channel lifetime has no special relationship to
Agent-local Apalis jobs.

## Acceptance

Before any release: format, workspace check, strict Clippy and tests;
actual board HTTP task creation/execution and native stored result;
SSH exec/SFTP/TCP forwarding and updater regressions; native Windows 11
and Windows 7 x86/x64; process-tree shutdown, launch/cancel and
deployment/migration gates. Never infer native Windows acceptance from
Linux tests.

For the source module map see [jobs README](../crates/agent/src/jobs/README.md);
for executed checks see [evidence](AGENT_MINIMAL_JOBS_EVIDENCE.md).
