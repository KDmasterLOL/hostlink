# Agent jobs

HostLink jobs are **durable remote process requests**, not OS services. They
survive SSH disconnection, and Apalis SQLite preserves the queue, worker state
and result. After an Agent/worker crash, **Apalis may execute a previously
started job again**. The user explicitly accepted this on 2026-10-29.
A job must therefore tolerate duplicate side effects; no exactly-once
execution guarantee exists.

For the detailed contract see
[Agent jobs behavior](../../../../docs/AGENT_MINIMAL_JOBS.md) and
[verification evidence](../../../../docs/AGENT_MINIMAL_JOBS_EVIDENCE.md).

## Architecture

```text
HostLink Client
  ├─ SFTP upload → Agent-owned per-controller artifact
  └─ authenticated SSH "hostlink-jobs" → frame.rs / protocol.rs
                                                │
                                  JobStore / Apalis TaskSink
                                                │
                                   SQLite Jobs (schema v4)
                                                │
                                    Apalis WorkerBuilder
                                     native lock / result
                                                │
                                       ProcessKit group
                                      stdout / stderr
```

**Apalis** owns task delivery, native status, attempts, result publication,
and crashed-worker requeue. There is no `StartedClaims` table, custom
`claim_dequeued`, manual result transition, or HostLink restart ledger.
`JobStore` is only the bridge to private storage, authenticated owner-filtered
reads, artifact admission and updater safety.

**ProcessKit** starts/terminates the OS process group and captures raw output.
The Agent does not implement a second queue. **SSH/SFTP** carry commands and
files; the accepted task is not tied to its SSH channel. Separate
[service/](../service/) manages Agent's systemd/Windows service, not
individual jobs.

## Job lifecycle

1. **Fresh enrollment** provisions an empty private `jobs` directory with
   `JobStore::initialize_fresh`. Normal startup uses `JobRuntime::open`
   against an already-existing database. Existing schema-v3 roots are
   rejected rather than automatically migrated or erased.
2. **Upload and seal:** `HostConnection::job_run` uploads the exact binary
   using SFTP. The Agent places a SHA-verified copy in the authenticated
   controller's private `artifacts` directory.
3. **Admit:** the Client-generated canonical ULID is the Apalis task ID and
   idempotency key. `JobStore::admit` calls the native Apalis task sink.
   Resubmitting the **same** ID/spec is idempotent; this does **not** disable
   Apalis's independent automatic retry after a worker crash.
4. **Run:** Apalis's `WorkerBuilder` locks/dequeues the task and invokes the
   handler. The handler checks the source, runs a ProcessKit group and
   returns `Ok(exit_code)` (including nonzero exit codes), or `Err`.
   Apalis stores the resulting native `Done`/`Failed` state and result.
5. **Observe:** `list`, `status` and offset-based `logs` are authenticated
   by controller identity. `cancel` stops a running process or cancels a
   pending task. The request acknowledgement is not proof that OS teardown
   is complete.

On a crash, Apalis can make a Running/Queued task Pending again. An already
started program can therefore run again. Existing raw output files are
appended across attempts with a shared per-stream size cap; logs can contain
data from multiple attempts. A crash can leave partial output, and side
effects may have occurred before Apalis recorded a result.

## State and private files

```text
<install_root>/
├── update.lock
├── jobs/
│   ├── jobs.db                 # Apalis native Jobs/Workers, format marker v4
│   ├── jobs.db-wal, jobs.db-shm # SQLite sidecars, when present
│   ├── runner.lock            # exclusive Agent runtime
│   └── outputs/<ULID>/{stdout.bin,stderr.bin}
└── artifacts/<controller-key-sha256>/
    ├── uploads/<sha256>.upload
    └── sealed/<sha256>.program
```

| Apalis state | HostLink view |
| --- | --- |
| Pending / Queued | Prepared |
| Running | Running |
| Done with `Ok(exit_code)` | Exited { code } |
| Failed with `Err` | Failed |
| Killed before any attempt | Failed (queued cancellation) |
| Killed after an attempt | Interrupted (uncertain) |

`JobState` and `JobView` are projections, **not separate persistent states**.
Owner-filtered `query.rs` SQL remains because Apalis 1.0.0 does not expose one
atomic authenticated payload/status/result query or owner-aware pagination.
`lifecycle.rs` contains only a guarded native-row cancellation for queued
jobs; it is not a general lifecycle engine. Native Apalis event handling
publishes normal completions.

`runner.lock` prevents simultaneous Agent runtimes from owning the same
store. `update.lock` and `active_ids` prevent replacing an Agent while
jobs are pending/running or its persisted state is unsafe. Job admission
and process start are coordinated with shutdown/cancel. The worker and
ProcessKit each own their respective concurrency/process-lifetime limits.

The managed root is private and Agent-owned, with bounded payloads, output
and artifacts. The sealed source must belong to the authenticated
controller and pass source SHA, ACL and symlink checks. Updater and
service operations still validate their own installation/integrity rules.

## Files to read

| File | Purpose |
| --- | --- |
| [mod.rs](mod.rs) | Runtime, limits and exports |
| [model.rs](model.rs) | Job ID, payload, status projection |
| [persistence.rs](persistence.rs) | Apalis storage and task sink |
| [database.rs](database.rs) | SQLite connection, fresh v4 schema and ownership |
| [query.rs](query.rs) | Native status/result and owner-scoped reads |
| [lifecycle.rs](lifecycle.rs) | Guarded pending-task cancellation only |
| [inventory.rs](inventory.rs) | Update/service safety scan |
| [engine.rs](engine.rs) | Apalis WorkerBuilder and execution callback |
| [worker.rs](worker.rs) | ProcessKit execution and tree teardown |
| [spool.rs](spool.rs), [output.rs](output.rs) | Bounded binary stdout/stderr |
| [artifacts.rs](artifacts.rs), [source.rs](source.rs), [private_fs.rs](private_fs.rs) | Private binary/paths |
| [frame.rs](frame.rs), [protocol.rs](protocol.rs) | SSH frame and operations |

All nine jobs unit-test source files are in [tests/](tests/), rather than
mixed with the implementation. They retain their original Rust module
paths so existing test filters and private fixture access still work.
Agent/Client end-to-end tests remain under their respective crate-level
`tests/` directories.
See [SOURCE_LAYOUT](../../../../docs/SOURCE_LAYOUT.md) for module conventions.

## Validation

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace -- --test-threads=1
```

An ordinary test PASS is not native Windows 7 acceptance. Positive OS process
tests require the actual supported ProcessKit group mechanism: Linux cgroup v2,
Windows Job Object or FreeBSD process reaper. Native/production deployment
is separately authorized. Old schema-v3 `jobs.db` migration is a separate task
(Huly 1C-1080).
