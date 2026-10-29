# Agent jobs contract (Huly 1C-1081)

Source: `crates/agent/src/jobs/`. For architecture and the file map, see the
[module README](../crates/agent/src/jobs/README.md). For exact test receipts,
see [verification evidence](AGENT_MINIMAL_JOBS_EVIDENCE.md).

## Queue and recovery

The Agent uses the **pinned Apalis SQLite 1.0.0** backend, its native
`TaskSink`, `WorkerBuilder`, task locks, and persisted results. No
HostLink-specific `StartedClaims` table, one-shot execution fence,
manual completion ACK or custom restart replay blocker exists.

**Approved behavior (2026-10-29): Apalis may repeat a task that already
started if its worker/Agent crashes.** Retrying may duplicate side effects.
Do not advertise at-most-once or exactly-once execution. Explicit admission
of an identical ULID/spec is idempotent; Apalis automatic crash recovery is
independent from a second admission request.

Apalis's `reenqueue_orphaned.sql` changes stale Running/Queued tasks to
Pending, increments attempts and can enqueue them even with
`max_attempts(1)`. That setting limits ordinary failed-attempt retries;
it does **not** prevent orphan replay. The worker handler returns
`io::Result<i32>`: `Ok(exit_code)` (including nonzero codes) becomes
native `Done` + `Ok(code)`, and `Err` becomes native `Failed` + error.
Normal job errors are not fatal to the entire Agent.

There is one canonical uppercase caller-generated ULID for the Apalis ID,
idempotency key, and filesystem output path; no UUID compatibility.
`JobPayload` stores immutable owner fingerprint/request digest/program/argv/
cwd/source digest. Native Apalis `Jobs.status`, `attempts`, and
`last_result` are the durable lifecycle source, not a copied JobState.

`JobStore::lookup` and `list` use bounded authenticated native-row queries.
`FetchById` / `ListTasks` in pinned Apalis do not expose the combination
of owner-filtered payload/status/result and paginated all-status listing.
These queries do not manage state. A tiny guarded pending-cancel SQL update
remains because the pinned backend has no public atomic cancel-by-ID API.

| Native Apalis | Operator state | Updater |
| --- | --- | --- |
| Pending / Queued | prepared | defer |
| Running | running | defer |
| Done + `Ok(i32)` | exited(code) | may proceed after output checks |
| Failed + `Err` | failed | may proceed after output checks |
| Killed with zero attempts | failed (cancelled before start) | may proceed |
| Killed after an attempt | interrupted / unknown | defer |
| Missing/torn/invalid data | error | reject |

## SSH, binaries and process handling

The authenticated SSH subsystem is `hostlink-jobs` (no jobs-v1 adapter).
Each bounded channel carries one length-prefixed JSON request and response.
The operations are `seal` (internal), `run`, `list`, `status`, `logs`,
and `cancel`. Closing an SSH jobs channel does **not** cancel the job.
Ordinary short SSH `exec` is channel-owned, not durable.

The Client's `HostConnection::job_run(id, bytes, args)` uploads a binary via
SFTP, verifies/seals its SHA-256 within the authenticated controller's
private artifact root, then admits its ULID/spec via Apalis. Only the
managed exact sealed source can be executed; no arbitrary remote program
path is accepted through jobs. A lost ACK should be resolved by querying
the same ULID, not by inventing a new identity.

`ProcessKit` starts, stops and drains a real OS-backed process group.
Only Linux CgroupV2, Windows JobObject and FreeBSD ProcessReaper are
accepted for durable execution; the POSIX process-group fallback is
rejected. The Agent must not assert successful completion until the process
tree is empty, both raw output pumps reached EOF and the spools synced.
Cancelled/failed processes return native errors; unconfirmed tree teardown
stops admission until the Agent is recovered. Linux parent-death cleanup
on abrupt Agent termination is not a guarantee for every descendant:
the service supervisor and OS containment remain relevant. Duplicate
effects after crash are an accepted consequence of native Apalis replay.

stdout/stderr are private raw byte files. Reattempts append existing
output and the per-stream size limit covers all attempts combined. The
output may contain partial data or multiple attempts. EOF is reported
only once a terminal native status and the captured file bounds permit
it; a lost output file is not silently interpreted as complete empty
output after a started attempt.

## Storage, service and migration policy

- `JobStore::initialize_fresh` is explicit fresh provisioning only.
  Native Apalis migrations initialize the new store once.
- The private database schema marker is **version 4**; no
  `StartedClaims`. Version 3, legacy `record.json` or torn/unknown roots
  are **rejected without modification**. Import/migration stays Huly
  1C-1080 and requires separate authorization for existing installations.
- `JobRuntime::open` opens only an existing root and holds the exclusive
  `runner.lock` for the serving lifetime. Never create replacement state
  on recovery.
- SQLite remains WAL with verified synchronous FULL and bounded
  owner-only paths; updater scanning opens a read-only pool. Corruption
  fails closed.
- `update.lock` excludes admission/start during an update. The updater
  and OS service lifecycle use `jobs::active_ids` and refuse replacement
  when native tasks are Pending/Queued/Running or state cannot be
  validated. A server crash does **not** establish that a task has completed.
- `start_lock` coordinates cancellation and spawn; Apalis's own
  ConcurrencyLimit bounds dequeue handlers and the OS-process semaphore
  bounds actual tree lifetimes. A delayed Apalis lock publication must not
  cause a cancelled task to execute.

Resource limits: 16 concurrent job processes, 32 jobs SSH channels,
4,096 jobs per store, 64 MiB per uploaded artifact, 128 artifacts per
controller, 8 MiB per output stream, 24 KiB per log chunk and 64 KiB per
job frame. No service may silently expand these bounds.

This is a development-only breaking source change. **Do not deploy to
installed Agents with schema-v3 jobs roots or reset their state** to
work around the version gate. Native Windows 11 and Windows 7 x86/x64
acceptance must be recorded separately before release.

## Verification

```sh
cargo fmt --all -- --check
cargo check --offline --locked --workspace --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo test --offline --locked --workspace -- --test-threads=1
```

Focused regressions: native orphan reenqueue/handler retry, ordinary
nonzero exit code, pending cancellation vs dequeued/locked task,
update.lock vs run, SSH disconnect/reconnect, SFTP artifact scope,
ProcessKit cancellation/output EOF, updater/service active-job deferral,
old schema preservation, and native Windows containment.
