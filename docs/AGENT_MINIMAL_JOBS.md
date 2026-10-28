# Minimal Agent jobs (1C-1081)

Owner: `crates/agent/src/jobs/`. Update this contract when changing job storage,
execution, framing or Client commands. This is development integration only.

## Queue and execution

One `SqliteStorage<JobPayload>` sink and one Agent-owned `WorkerBuilder` handle
admission and processing. The worker polls every 100 ms in batches of 16;
concurrency is bounded to 16 processes, with no retry middleware or alternate
backend. ProcessKit owns execution, raw output and tree teardown. Local cancellation
uses the Agent's active token to stop the explicit group concurrently with child
drain; jobs do not wire `Command::cancel_on`. In pinned 3.3.4 that finisher's
Cancelled result masks a pump read error. An error-free drain plus both stream-end
flushes, spool sync and confirmed empty group permits clean user cancel to become
Failed. Any drain error (including Io with a cancelled active token) stays UNKNOWN.
The final pre-spawn cancel check and ProcessKit start hold `start_lock`, shared
with authenticated Cancel, so an acknowledged pre-start cancel cannot execute.
Before any OS spawn, the Agent inspects the **actual created group's**
`ProcessGroup::mechanism()`. Only Linux `CgroupV2`, Windows `JobObject` and
FreeBSD `ProcessReaper` are trusted; POSIX `ProcessGroup`, other platforms and
future enum variants are rejected. Linux therefore requires delegated cgroup v2.
Pinned ProcessKit 3.3.4 can fall back when cgroup creation fails, even if its
`host_containment()` prediction said cgroup. It has no other strong Linux backend;
parent-death cleanup protects only the direct child. An unsupported backend never
reaches `start()`: its claimed job becomes Failed only after both fresh empty
spools sync. Sync/publication uncertainty stays UNKNOWN and blocks updates.
The Agent retains an explicit ProcessGroup owner through child drain and always
requires `group.stop(Duration::ZERO, true).members_after() == Some(0)` before
result publication and permit release. The job deadline is enforced against
this owned group rather than via `Command::timeout`: in ProcessKit 3.3.4
the shared-group command timeout kills only its direct child, potentially
leaving a grandchild's inherited stdout/stderr open until `join_pumps`
aborts without an EOF flush. On deadline the Agent cancels the active token,
stops the entire group concurrently with `drain()`, then confirms group
emptiness, both stream-end flushes and durable sync before recording Failed.
The stop/reap/drain phase has a ten-second upper bound; if OS termination,
reaping or pipe drainage cannot be confirmed, the worker publishes UNKNOWN,
closes admission and retains its permit instead of hanging indefinitely
or reporting a false terminal result. A successful kill call alone is insufficient.
After the direct child is drained/reaped, the Agent repeats the OS-backed stop/count
query every 25 ms for at most five seconds, retaining group ownership. This includes
descendants that close stdio and outlive their parent. Cancellation issues group
stop concurrently with drain/reap, then confirms zero membership. Unknown counts,
query errors or a nonempty group at the deadline yield UNKNOWN, no output EOF,
and an error that retains the permit and blocks updates. Failed starts also require
empty-group confirmation before a proven pre-spawn failure can become Failed.
SSH authenticates the controller and carries requests; closing a jobs channel
cannot cancel a process. Ordinary SSH exec retains its channel-owned lifetime.

The immutable payload contains only ULID, controller fingerprint, request digest
and exact executable/argv/cwd/source SHA. Lifecycle is **never serialized into
that payload**. Apalis `Jobs.status`, `attempts` and `last_result` are authoritative.
`JobView`/wire `JobState` are read-only projections:

| Native Apalis | Operator view | Update |
| --- | --- | --- |
| Pending / Queued, pristine or exact native requeue result, no claim | prepared | deferred |
| Running with matching claim | running | deferred |
| Done + `Ok(exit_code)` with matching claim | exited, exact code (including nonzero) | allowed |
| Failed + `Err(...)`, attempts=1 | failed | allowed after required output validation |
| Killed + `Err(...)` | interrupted / UNKNOWN | deferred |
| Pending / Queued with prior claim or consumed eligibility | interrupted / UNKNOWN | deferred |
| Invalid identity, schema, attempt/result or files | error | blocked |

`ListTasks` and `FetchById` exist in pinned apalis-sqlite 1.0.0. Neither
returns an atomic owner-filtered payload/status/result/claim snapshot; `ListTasks`
also defaults to Pending. The small SQL projection in `jobs/query.rs` replaces
both. `WaitForCompletion` cannot join the one-use fence and is not used.

The caller's canonical uppercase ULID is **also** `Jobs.id` (Apalis TaskId) and
`idempotency_key`; there is no second generated identity or UUID compatibility.
The Client generates and prints it before resolving/connecting to the host.
The pinned `ulid = 3.0.0` dependency was already in Cargo.lock through Apalis;
parse plus canonical round-trip rejects lowercase, aliases and 130-bit overflow.

`StartedClaims(task_id PRIMARY KEY, owner, request_sha256)` is an immutable
one-use **execution fence**, not another lifecycle engine. Only WorkerBuilder's
dequeue can reach the production `claim_dequeued` method. Under `update.lock`
and `BEGIN IMMEDIATE`, `INSERT … SELECT` matches the exact payload, same task ID,
worker lock, due time, unclaimed eligibility and Queued status, then sets native
Running/attempts=1 before ProcessKit launches. A spent or stale claim is an error.
Upstream orphan requeue ignores max_attempts; neither it nor restart grants a
second process attempt. On restart, pristine unclaimed Pending/Queued work is
preserved. The worker heartbeat is expired so actual Apalis registration can
reenqueue Queued work. Pinned Apalis increments attempts and stores one of two
exact requeue Err strings (heartbeat timeout / worker shutdown); only those
unclaimed rows remain eligible. Claim atomically sets attempts=1 and clears that
bookkeeping result. Spent claims and uncertain native state become Killed/UNKNOWN;
corrupt status/result fails closed. Restart never grants a second process attempt.

Admission holds `update.lock`: indexed ID lookup with owner/spec/digest check,
capacity count, then the standard Apalis task sink. It does not enumerate jobs
or output files. Status uses one indexed SELECT; list uses one owner-filtered
SELECT, claim join, deterministic ID order, LIMIT 32 and OFFSET in one SQLite
snapshot. Result/payload/claim bytes are bounded and validated. Logs reuse their
single authenticated record snapshot. Deep database/filesystem inventory is
reserved for startup/recovery and updater safety checks; output reads still
validate private paths and file bounds. Corrupt unrelated files do not trigger
an O(N) admission scan, but still block updater/startup and fail on direct read.

## Breaking transport and CLI

The only jobs subsystem is **`hostlink-jobs`**. There is no v1 adapter. Each SSH
channel carries exactly one UTF-8 JSON request with a four-byte big-endian length,
then EOF; replies have the same framing. Frames are bounded to 64 KiB and requests
time out after 15 seconds. Unknown fields (including the old `version`) fail.
Operations are `run`, `list`, `status`, `logs`, `cancel`, `seal`.

```sh
hostlink jobs run --config HOST.json --binary ./local-binary --id ULID -- exact argv
hostlink jobs run --config HOST.json --binary ./local-binary --wait -- exact argv
hostlink jobs list --config HOST.json --page 1
hostlink jobs list --config HOST.json --status Done --page 1
hostlink jobs status --config HOST.json --id ULID
hostlink jobs logs --config HOST.json --id ULID --stream stdout --offset 0
hostlink jobs cancel --config HOST.json --id ULID
```

`--host NAME` may replace `--config`. The single `jobs run` uploads via SFTP,
seals and enqueues using private Client `job_seal`/`job_start`. By default it
prints admission ID/status and returns promptly; `--wait` streams exact raw
stdout/stderr and returns the process exit code, with at most three reconnects across a single total status/stdout/stderr failure
budget. Successful reads never replenish that budget.
`HostConnection::job_run(id, bytes, args)` is the same upload/seal/enqueue pipeline
used by CLI and integration callers. No start retry occurs on transport failure.
Top-level `hostlink run`, low-level `--program/--source-sha256/--cwd`, and former
`job start/output` commands are removed with no alias. IDs print before connection;
a lost ACK means UNKNOWN: query that ULID before further action. Repeated identical
IDs/specs return the existing view; conflicting specs/keys fail.

`list` returns only this controller's summaries, ULID-sorted, 32 per page
(pages 1..128). Omit status to list across all six native statuses. Concurrent
changes can move entries between filtered pages; listing does not claim a stable
snapshot across requests. Logs are raw bytes, at most 24 KiB per chunk; continue
using the returned offset. Cancel acknowledges the request; status confirms
terminal teardown. Seal retains digest-bound per-controller SFTP ownership.

New authenticated run admission accepts only this controller's exact canonical
`artifacts/<controller-sha>/sealed/<source-sha>.program` returned by Seal.
The Agent validates the install/artifact/controller/sealed parents and file using
the existing private owner/permissions or Windows SID/protected-DACL checks, then
verifies executable permissions, single-link identity and SHA. An arbitrary owned
read-only executable, writable parent, symlink alias, traversal or another
controller's source is insufficient, even with identical bytes/basename.
The worker repeats source authorization, digest and optional remote cwd validation
after dequeue, immediately before ProcessKit start. A source rejected after claim
cannot be retried/replayed; its synced empty spools permit definite Failed.
Exact same-ID/owner/spec retries return the immutable record even if the source
was subsequently removed or changed; they never enqueue another attempt.
Hashing an opened descriptor followed by pathname exec does **not** guarantee
execution of that descriptor against same-UID replacement between check and exec.

On Unix, ArtifactStore opening, Seal and source authorization also walk every
directory ancestor from `/`, before canonicalization can erase symlinks. Every
component must be a directory owned by root or the Agent. Group/world-writable
non-sticky directories are rejected. A writable sticky parent is allowed only
when its next directory entry is also root/Agent-owned. This permits standard
protected `/home` installations and root-owned sticky `/tmp` with an Agent-owned
child, while rejecting unknown owners (including unmapped namespace UIDs),
symlink ancestors and a writable ancestor above the install root. Checking only
`0755` is insufficient for a foreign-owned directory: its owner can chmod it.
Existing install/sealed private permissions and Windows ACL checks still apply.
The worker repeats the ancestor policy through the existing source verifier;
these are pathname checks, not an atomic guarantee against root/same-UID mutation.

## Private roots and durability

Schema version 3 is fresh-root-only. Explicit enrollment calls
`JobStore::initialize_fresh` on a private empty directory. Runtime opening never
creates/migrates a database or repairs missing files. Old SQLite schemas,
record.json roots, unknown entries and torn stores are preserved and rejected.
Cutover/import belongs to 1C-1080; do not reset IDs or delete state to pass checks.

Keep private owner/permissions, Windows SID/DACL, hardlink/reparse checks,
WAL and verified FULL on every connection. Limits remain 4096 jobs, 64 KiB per
payload, 8 MiB per raw stream, 64 MiB per artifact and 128 artifacts/controller.
Both spools must be durable for exited and claimed failed jobs. ProcessKit 3.3.4
can silently abort output pumps after its five-second join grace; fsync alone
therefore cannot prove complete output. Both private raw tee writers must report
a successful stream-end flush, drain must be error-free, and both spool fsyncs
must succeed before terminal complete logs. Missing markers mean UNKNOWN,
updater deferral and `eof=false`. At overflow,
the writer cancels the tree and discards excess bytes while draining to EOF;
the bounded captured prefix remains a Failed result after confirmed teardown.

The marker relies on pinned `pump.rs` calling raw tee flush only at stream end,
including read error. Flush alone is not proof of clean EOF: without `cancel_on`,
`child.drain` preserves the sink read error as Io, even during user cancellation.
`AsyncWrite::poll_flush` is not intrinsically an EOF API: an upstream early flush would invalidate this
proof; later writes clear the marker, but a future ProcessKit upgrade must recheck
this contract. No marker is needed when no pumps existed: pre-spawn
rejection/cancel or Spawn/NotFound yield Failed only after spool fsync.
Other launch/teardown errors remain UNKNOWN. Lost spool files are
errors rather than empty EOF. Service/updater scans use a read-only connection;
admission and dequeue claim share `update.lock` and use a nonblocking try-lock.
Admission returns Busy without enqueue; an explicit same-ID retry is idempotent.
The consumer retains the exact dequeue-bound task on WouldBlock, releases its
permit and `start_lock`, and retries after async 10/20/40/80/100 ms backoff (capped
at 100 ms) until the lock is available or Agent shutdown cancels the wait. Each
attempt re-reads cancellation/terminal state under `start_lock`. It never returns
success merely for Busy, never blocks Tokio, and never retries a committed claim.
On shutdown it leaves unclaimed Queued work for native Apalis recovery during
restart; spent claims remain fenced as UNKNOWN. Other handler/backend errors
still fail closed and stop admission/process trees. Both lock APIs explicitly
unlock before FD close (a concurrent fork may inherit a descriptor until exec).
Fresh initialization/updater retain their blocking lock APIs. Installed Agent
publication defers for prepared, running, UNKNOWN or invalid state. No new Windows API is introduced;
Win7 runtime and disposable native Windows acceptance remain separate gates.

Native positive process tests probe the actual created group's mechanism and emit
`NOT RUN` when strong containment is unavailable. They never bypass the production
gate. On fallback hosts, separate regressions run real admission/Apalis consumption
and verify no launch marker, spent claims, Failed, synced empty output and no replay.
Optional runs still count early-return skips as libtest `ok`; inspect the named
`NOT RUN` diagnostics rather than treating the harness total as native passes.
Use a host with provable filesystem ownership, strong containment and permitted
loopback sockets for mandatory positive acceptance:

```sh
HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1 CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR="$PWD/target" TMPDIR="$PWD/target/test-tmp" \
  cargo test --locked --workspace -- --nocapture --test-threads=1
```

All jobs/internal, encrypted SSH wire and shared Agent/Client integration
capability checks use one test-only helper. In required mode an unavailable
actual CgroupV2/JobObject/ProcessReaper backend panics with its name and the test
name before any skip. The native ancestor fixture likewise fails in this mode
when root ownership or the root-owned sticky `/tmp` case cannot be proved.
The mode regression uses isolated current-test-binary subprocesses; its helper
test is explicitly ignored outside those subprocesses. No production bypass or
new dependency is involved. A nonzero required-mode run is **not** native acceptance.
Verification and exact limitations: [1C-1081 evidence](AGENT_MINIMAL_JOBS_EVIDENCE.md).

On Windows, SFTP hardens only a successful CREATE_NEW upload: check regular file,
reparse/owner/SID/allow ACEs (permitting safe inheritance), then reject hardlinks,
then protect the DACL and validate it. No existing file is repaired and Seal's
protected-DACL/source checks are unchanged.
