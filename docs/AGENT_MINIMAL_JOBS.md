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

The SQLite database is an Agent-owned private local file (`jobs/jobs.db`).
New Agent installations use fresh-only schema marker **v5**. Prior v4,
legacy `record.json`, unknown output files and torn/corrupt roots are
rejected and **never automatically erased or migrated**. Installed-root
migration needs a separate explicit user authorization.

The Board passes native task lifecycle headers, attempt limits and scheduling
parameters directly to Apalis, without HostLink-specific restrictions.
The updater still holds `update.lock` and refuses replacement when the
native database already contains Pending/Queued/Running jobs or retryable
Failed tasks. **The Board no longer uses this lock for task creation.**
Consequently, an updater checking an otherwise empty queue may race with
a new Board submission. Updating a running Agent requires separate HTTP/worker
quiescence before relying on an empty-queue check; this must be addressed
before live release acceptance. Read-only jobs inspection fails closed for
unknown/corrupt roots.

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
