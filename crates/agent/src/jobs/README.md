# Agent jobs

This module is the **Agent-owned durable execution subsystem**. It accepts an
authenticated controller's source-pinned program, queues it in Apalis SQLite,
executes it through ProcessKit, and lets the controller reconnect for status,
logs, or cancellation.

**Durable does not mean that a process survives an Agent crash.** Jobs survive
SSH disconnections; after an Agent restart, work that never started can still
run, but a job whose execution may have started is **not replayed**.

Start with [the runtime](mod.rs), [queue consumer](engine.rs),
[process execution](worker.rs), and [SSH request dispatch](protocol.rs).
For the detailed security contract and its acceptance limitations, see
[Minimal Agent jobs](../../../../docs/AGENT_MINIMAL_JOBS.md) and
[verification evidence](../../../../docs/AGENT_MINIMAL_JOBS_EVIDENCE.md).

## Ownership and dependencies

```text
Controller / hostlink CLI
  ├─ SFTP upload ───────────────────────────> Agent SFTP
  │                                           └─ per-controller artifacts/
  └─ authenticated russh "hostlink-jobs" ───> frame.rs → protocol.rs
                                                  │
                                               JobRuntime
                                                  │
                                    JobStore / Apalis SQLite Jobs
                                                  │
                                        Apalis WorkerBuilder
                                                  │
                                          one-use start claim
                                                  │
                                       ProcessKit ProcessGroup
                                                  │
                                 stdout/stderr files + native result
```

- **Apalis SQLite** owns the queue, the persisted task payload, native
  `Jobs.status`/`attempts`/`last_result`, and the worker dequeue.
- **HostLink jobs** adds authorization, a one-use *process-start fence*, recovery
  policy, and the checks needed before publishing a terminal result. It
  deliberately writes some native Apalis fields transactionally; Apalis is
  **not** the only code that changes a job's status.
- **ProcessKit** owns the OS process group, cancellation, and output pumps.
- **SSH and SFTP** provide authenticated transport, not another execution
  engine. The SSH server starts one Agent-lifetime `JobWorker` and forwards
  job channels. It does not construct the jobs runtime internally.
- **Agent service registration** is a different subsystem under
  [service](../service/). Jobs are *not* individual systemd/Windows services.

An SSH channel may close without cancelling an accepted job. A short-lived SSH
`exec` command has different, channel-owned lifetime semantics.
The current [SSH server](../ssh/server.rs) still supervises worker startup,
shutdown, and process-slot draining; these are remaining cross-module
lifecycle details, **not** a second queue.

## One job, step by step

1. **Provision**: fresh enrollment explicitly calls
   `JobStore::initialize_fresh()` on an empty private jobs root. Ordinary
   startup uses `JobRuntime::open()` to validate an **existing** database,
   acquire the exclusive runner lease, and recover its previous state. It never
   silently creates or upgrades an old database.
2. **Stage**: `HostConnection::job_run()` receives a canonical caller-generated
   ULID, uploads binary bytes using SFTP, verifies their SHA-256 by `seal`,
   then sends one `run` request over the authenticated `hostlink-jobs` SSH
   subsystem. The Client prints the ID *before* network submission.
3. **Admit**: `JobStore::admit()` checks controller ownership, the exact
   executable/specification digest, capacity, and the update interlock; then
   it sends a task through the Apalis SQLite task sink. The same ULID is used
   as the public ID, Apalis task ID, idempotency key, and output directory
   name. An identical ID/request is idempotent; an ID with different ownership
   or content is rejected.
4. **Dequeue and fence**: `WorkerBuilder` polls SQLite. Before any OS process
   starts, `claim_dequeued()` atomically inserts a unique `StartedClaims` row
   and changes the native task to Running in a transaction. This is **not** a
   second lifecycle database: it is evidence that an execution attempt was
   already spent, even if Apalis later requeues an orphan.
5. **Execute**: `worker.rs` re-verifies the sealed source, starts a ProcessKit
   group with supported OS-backed containment, and writes bounded raw
   stdout/stderr to private files. Exit/cancel/timeout is terminal only after
   the process tree is confirmed empty, the output pumps completed, and both
   files were synced. Otherwise the job is **Interrupted / UNKNOWN**, not
   falsely successful.
6. **Observe**: `status`, owner-filtered `list`, and offset-based `logs` read
   the persisted result without rerunning anything. `cancel` requests process
   cancellation; the acknowledged request is not proof of completed teardown.

The public CLI is `hostlink jobs run/list/status/logs/cancel`; `seal` is a
private step in the upload/run workflow. The old `hostlink-jobs-v1` subsystem
is rejected, not emulated.

## Persistent state and recovery

```text
<install_root>/
├── update.lock
├── jobs/
│   ├── jobs.db                 # Apalis Jobs + StartedClaims + schema metadata
│   ├── jobs.db-wal             # SQLite sidecar, when present
│   ├── jobs.db-shm             # SQLite sidecar, when present
│   ├── runner.lock            # one owning Agent runtime
│   └── outputs/
│       └── <ULID>/
│           ├── stdout.bin
│           └── stderr.bin
└── artifacts/
    └── <controller-key-sha256>/
        ├── uploads/<sha256>.upload
        ├── sealed/<sha256>.program
        └── seal.lock
```

The task's **immutable** `JobPayload` contains its ID, controller fingerprint,
request digest, and `JobSpec` (program, arguments, optional working directory,
source hash). Its lifecycle is *not* separately serialized. `JobState` and
`JobView` are validated projections of Apalis's native columns and the claim:

| Apalis state | Operator view | Meaning |
| --- | --- | --- |
| Pending / Queued with no spent claim | Prepared | May execute normally |
| Running with matching claim | Running | Execution attempt is spent |
| Done with confirmed exit code | Exited(code) | Completed, including nonzero exit |
| Failed | Failed | Known failure or confirmed cancellation |
| Killed / unsafe requeued state | Interrupted | Outcome unknown; never replay |

On restart, **unclaimed** Pending/Queued tasks remain eligible. Previously
claimed/ambiguous work fails closed as Interrupted. A claimed job is not
silently retried, even when Apalis's orphan recovery makes it pending again.
`JobStore::recover_nonterminal()` implements this policy under `runner.lock`.

`JobStore::list()` / `lookup()` use bounded, authenticated native SQL queries
because Apalis's general `ListTasks`/`FetchById` interfaces do not supply the
single owner-filtered status/result/claim snapshot this protocol requires.
There is **one** persisted lifecycle source, not a shadow status store.

## Concurrency, updates, and failure rules

- `runner.lock`: ensures only one Agent runtime owns and recovers this root.
- `update.lock`: excludes job admission/start from an Agent update. The updater
  and OS service lifecycle call `active_ids()` to inspect the database and
  output inventory via a read-only pool. Prepared, Running, Interrupted, or
  corrupt state prevents claiming safe replacement.
- `start_lock`: an in-process boundary between admission, cancellation,
  process start, and shutdown.
- Apalis/Tower concurrency limit (**16**) bounds simultaneous dequeue
  handlers. A separate process semaphore (**16**) keeps capacity occupied
  until process-tree teardown *and* result publication; UNKNOWN retains its
  permit instead of silently releasing capacity. These are different
  lifetimes, not redundant limiters.
- SSH jobs channels have a separate bound (**32**). A failure in the durable
  worker stops new admission instead of silently running a second engine.

Limits include 4,096 persisted jobs, 64 MiB per uploaded artifact, 8 MiB per
stdout/stderr stream, and 24 KiB per log read. Source ownership, link/reparse
checks, SHA-256, private ACLs, SQLite WAL/FULL durability, and strong process
containment are intentional costs of running binaries on another machine.
Source hashing followed by path-based execution is **not** an atomic
exec-by-file-descriptor guarantee against same-user replacement.

## Source map

| File | Responsibility |
| --- | --- |
| [mod.rs](mod.rs) | Limits, module exports, runtime/runner ownership |
| [model.rs](model.rs) | ULID, immutable spec/payload, operator state/view |
| [persistence.rs](persistence.rs) | Apalis storage, fresh/open distinction, admission |
| [database.rs](database.rs) | SQLite configuration, migrations, lock and layout checks |
| [query.rs](query.rs) | Authenticated native-row decoding, lookup and paging |
| [lifecycle.rs](lifecycle.rs) | One-use start claim, result publication and recovery |
| [inventory.rs](inventory.rs) | Full corruption/output scan and updater safety |
| [engine.rs](engine.rs) | Apalis worker, dequeue, active-task supervision |
| [worker.rs](worker.rs) | ProcessKit launch, teardown, timeout, durable completion |
| [spool.rs](spool.rs) | Bounded raw writer and output-completion markers |
| [output.rs](output.rs) | Private binary logs, offsets, EOF checks |
| [artifacts.rs](artifacts.rs) | Per-controller SFTP upload sealing |
| [source.rs](source.rs) | Executable source and launch-context verification |
| [private_fs.rs](private_fs.rs) | Private paths, ACL/owner/link checks and file locks |
| [frame.rs](frame.rs) | One bounded request/reply frame over an SSH channel |
| [protocol.rs](protocol.rs) | Authenticated run/list/status/logs/cancel/seal dispatch |

The other nine Rust files in this directory are regression suites (including
Linux/Windows process and filesystem fixtures), **not** additional job engines.
Useful starting points are `tests.rs` (storage and recovery),
`engine_tests.rs` (queue/claims), `worker_tests.rs` (execution), and
`protocol_tests.rs` (commands).

## Why is this module large?

Source snapshot after the library-first refinement based on `dev@a144f57`
(physical lines, including comments and
blank lines; not a measure of runtime cost):

Before 1C-1081, the separate `ssh/jobs` + `durable` modules contained
**2,577 implementation lines and 1,454 test lines**. The current replacement has
**87 more implementation lines**, but **1,962 more test lines**. This explains
why the new consolidated directory looks much larger despite eliminating
the duplicate module boundaries and legacy protocol.

| Responsibility | Implementation lines |
| --- | ---: |
| Database, durable claims, queries, models, recovery | 1,032 |
| Filesystem ownership, executable verification, sealed artifacts | 574 |
| Apalis consumer, ProcessKit execution, bounded streaming | 602 |
| SSH frame and operation dispatch | 189 |
| Output reading | 117 |
| Module root and runtime assembly | 150 |
| **Total implementation** | **2,664** |
| **Regression tests (9 files)** | **3,416** |

Most lines are **not scheduling logic**. They implement security and failure
guarantees not provided by a generic queue: authenticated ownership, immutable
artifacts, one-time execution, native process-tree termination, output
completeness, and safe Agent update/restart. In particular, Apalis can requeue
orphaned work, which is unsafe for already-started, non-idempotent programs.
The custom `StartedClaims` fence prevents replay but deliberately permits an
UNKNOWN result after a crash. This is **at-most-once start after the claim**,
not an exactly-once effect guarantee.

The main maintenance cost is the coupling to Apalis's native SQLite schema
(including explicit result publication) and ProcessKit's process/pump
completion semantics. Treat upgrades to either library as contract changes
requiring negative crash, cancellation, and output tests; merely moving these
checks into another module will not reduce the responsibilities.

Possible **future** simplification boundaries, not changes already made:
hide worker shutdown/slot supervision from SSH, reduce the public `JobStore`
surface used by enrollment/tests, or obtain stronger upstream ProcessKit
completion guarantees so fewer custom output markers are needed. Each requires
a specific caller/safety review; deleting `StartedClaims` or the UNKNOWN
quarantine is **not** an equivalent simplification.

## Verification and further reading

For focused tests, start with:

```sh
cargo test --locked -p hostlink-agent --lib jobs::
cargo test --locked -p hostlink-agent --lib ssh::server::wire_tests
cargo test --locked -p hostlink --lib run::
```

These are *not* release/native acceptance. Positive source/OS-process tests
require trusted filesystem ancestry, authorized loopback sockets, and strong
ProcessKit containment. Do not bypass a rejected security check merely to
make a test pass.

See [the detailed contract](../../../../docs/AGENT_MINIMAL_JOBS.md),
[source layout](../../../../docs/SOURCE_LAYOUT.md), and
[verification evidence](../../../../docs/AGENT_MINIMAL_JOBS_EVIDENCE.md).
The old `record.json` to SQLite cutover is a separate, explicit migration
(Huly 1C-1080), not part of runtime startup.
