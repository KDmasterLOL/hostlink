# HostLink Agent jobs — Apalis SQLite 1.0.0 PoC (1C-1064)

Status: **implemented and verified as an isolated experiment, NOT a production Agent replacement.**

## Goal and baseline

Check whether the existing Agent job store can be replaced by Apalis
with less total code while preserving: canonical caller-generated UUID,
controller SSH-key ownership, immutable request+source hash, idempotent admission,
no accidental replay of started commands, persisted state, raw output, Agent
update interlock, private filesystem ownership and Windows 7 compatibility.

HostLink baseline: dev 0a78f729d34b692bd527bcdd2838634701bcb6f9.
Tested library: apalis-core 1.0.0, apalis-sqlite 1.0.0, sqlx 0.9.0.
Upstream sources: https://github.com/apalis-dev/apalis-sqlite/tree/v1.0.0
(especially src/lib.rs, src/persist.rs, src/sink.rs, task/sink.sql,
backend/reenqueue_orphaned.sql and backend/fetch_next.sql).

## Actual implementation

The standalone experiments/agent-apalis-poc Cargo workspace calls the genuine
SqliteStorage, TaskBuilder and public Apalis orphan-recovery query against
temporary SQLite files. It includes a minimal adapter for HostLink UUID,
owner/payload conflict checking, durable SQLite settings and a persistent
at-most-once start marker (StartedClaims). It does NOT launch OS commands,
install an Agent, run live workers or migrate existing job records. The job
model is representative, not the complete current Agent JobRecord schema.

Run from the repository root:

    cargo test --locked --manifest-path experiments/agent-apalis-poc/Cargo.toml
    cargo clippy --locked --manifest-path experiments/agent-apalis-poc/Cargo.toml --all-targets -- -D warnings
    cargo run --locked --manifest-path experiments/agent-apalis-poc/Cargo.toml

On **Windows 11 GNU with Rust 1.99.0 (2026-10-27)**:
Initial PoC: 6/6 tests passed, zero failed; format passed; Clippy -D warnings passed;
executable smoke passed: one stored job, FULL SQLite synchronous mode,
no command executed. No native Windows 7 or Linux run has been performed.

Tests cover identical and conflicting UUID replay, controller ownership
mismatch, SHA tampering, concurrent admission, reopen/readback, actual Apalis
orphan recovery, and a durable at-most-once claim including reopen.

## Critical observed differences

| HostLink requirement | Apalis SQLite 1.0 behavior | Needed custom code |
| --- | --- | --- |
| JobId must be canonical caller UUID | Backend TaskId is ULID | Map UUID via unique idempotency key and fetch payload by key |
| Same UUID with different command/owner must fail | INSERT ON CONFLICT DO NOTHING, silently retains original even with different payload | Re-read and compare full owner+request+digest; return conflict |
| A started remote command must NEVER run again after lost ACK/restart | Orphan recovery resets Running to Pending, increments attempts; verified even with max_attempts=1 | Separate durable once-only execution claim and Interrupted handling |
| Explicit Prepared, Running, Exited(code), Failed, Interrupted | Apalis has its own queue/worker states | Custom transition mapping, source/owner CAS, durable exit status |
| Durable accepted-task receipt | setup sets PRAGMA synchronous=OFF | Reset and verify FULL on every SQLite connection; production power-loss tests |
| Private owner-only paths, output, update exclusion | Generic SQLite persistence | Retain ACL/symlink checks, output store and update locking |
| Synchronous JobStore API for service/update commands | Apalis SQLx methods are async | Update call sites and lock/process model |

The actual Apalis public orphan-recovery query was called by the test:
a task with status Running, attempts 1 and max_attempts 1 became Pending
with attempts 2. The upstream fetch_next SQL selects Pending tasks without
checking attempts. Thus setting one permitted attempt does NOT provide
no-replay semantics.

On connection setup, SqliteStorage::setup explicitly sets
PRAGMA synchronous=OFF. The PoC uses a single pooled connection and
restores FULL afterwards; that is NOT a safe general multi-connection
configuration without a per-connection check.

## Size and dependencies

Current production file sizes (physical lines):
- jobs/store.rs: 225
- jobs/private_fs.rs: 226
- jobs/artifacts.rs: 203, remains necessary
- jobs/output.rs: 42, remains necessary

The PoC src/lib.rs already exceeds 300 lines including its tests,
but covers only a subset of production behavior. A real migration would
also require secure storage ownership, output and updater integration,
complete record/exit-state mapping, crash-safe migration and service/SSH
API changes. private_fs.rs protects artifacts and the updater, so it
cannot be deleted by changing the job record backend alone.

The isolated experiment lockfile resolves 189 package versions.
Compared with the baseline HostLink workspace lockfile, 56 non-experiment
package versions are absent from the baseline. This is a rough upper
bound of possible new resolved dependencies, not an exact merged tree.
SQLx introduces bundled native SQLite compilation. Windows 7 compatibility
must be verified separately before any adoption.

## Scheduling extension (1C-1065)

The same isolated experiment now exercises two scheduling modes:

- **One-time deferred launch:** an optional immutable UTC Unix timestamp on the synthetic JobRecord. TaskBuilder::run_at_timestamp persists it in the Apalis SQLite Jobs.run_at column. Duplicate UUID with the same timestamp is idempotent; changing the timestamp for the same UUID is rejected, even after reopening. Upstream queries/backend/fetch_next.sql selects Pending only when run_at <= now.
- **Recurring ticks:** apalis-cron 1.0.0 generates the next UTC tick from a cron expression. The PoC converts each tick to deterministic UUID v5 derived from an example schedule identifier and the tick timestamp, and persists the occurrence with Apalis SQLite. No OS command or real Agent worker is started. Re-adding that occurrence after restarting is idempotent.

This validates scheduled occurrences, not a complete recurring schedule service. CronScheduler computes upcoming ticks from current time. It does NOT persist the schedule definition itself nor backfill ticks missed while the scheduler was offline. pipe_to(SqliteStorage) persists ticks that were actually emitted, not retroactive ticks. A future production design needs an explicit owner-bound schedule definition, immutable command digest, timezone and daylight saving policies, missed-run policy, and schedule cancellation/updates. The one-time execution claim is still required: durable scheduling must not silently replay interrupted remote commands.

If HostLink introduces delayed jobs, Apalis run_at is useful and substantially cheaper than implementing a home-grown scheduler. Keep apalis-cron optional until recurring tasks are part of the product; its presence does not resolve the orphan-requeue contract.

The isolated extension adds apalis-cron 1.0.0, cron 0.17.0 and UUID v5 to the PoC only, NOT the root HostLink workspace. Cargo added 23 versions to this experiment's resolved dependencies. New regression tests check persisted delays, restart, conflict on changed timestamp, and real cron tick -> deduplicated persisted occurrence. On Windows 11, the extended suite passed 8/8 tests (0 failed), strict Clippy, format check and an isolated smoke executable; mcp-job tests b9979a5b-39ac-4d6e-ae49-d19d85d604c9 and QA 1925e585-9052-4b7b-88eb-086f33d8009e. No real command executed.

## Decision

**Keep existing HostLink Agent JobStore for now.**

Apalis works and persists tasks, but we have not demonstrated lower TOTAL
production code or preservation of no-replay/owner/state contracts without
custom SQL and guards. The ordinary Apalis orphan retry behavior conflicts
with unrepeatable HostLink commands. Do not silently reinterpret those
commands as safe to retry, and do not change live installed Agents.

This PoC remains in a separate task branch. If automatic job retries become
an explicitly supported product feature later, Apalis is a plausible engine
but needs production-equivalent crash/replay, migration and Win7 testing.
