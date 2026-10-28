# Agent Apalis WorkerBuilder consumer (1C-1073)

Originally developed in `task/1c-1073-apalis-worker`, then integrated into
`task/1c-1073-apalis-production`. This is development code for review,
with no deployment or release authority.

## Execution and ownership

The jobs-v1 start handler only admits the immutable request through the real
SqliteStorage sink, validates the source and returns Prepared. Existing IDs
return their persisted state and reject a foreign controller or changed spec.
It has no spawn or direct worker dispatch. The existing Client parser already
accepts Prepared; framing and start/status/output/cancel/seal schemas are frozen.

One Agent-owned WorkerBuilder uses the same SqliteStorage<JobRecord>, with
100 ms polling, 16-task batches, tower ConcurrencyLimitLayer(16), and
run_until tied to Agent shutdown. There is no retry layer, alternate backend
or execution transport. russh/russh-sftp remain the sole execution/file carrier.
The existing maximum of 4096 durable records also bounds the pending backlog.

Apalis owns Pending -> Queued and its Workers registration/heartbeat rows.
HostLink owns the StartedClaims fence, Running, terminal payloads, attempts and
output. Config disables lock_tasks and persist_results: asynchronous Lock or
Complete events must never rewrite HostLink's payload/state transaction.
Before ProcessKit, claim_dequeued holds update.lock and BEGIN IMMEDIATE,
re-reads the payload/claim, and verifies all of:

- exact UUID, task ID, controller, request digest and complete fetched snapshot;
- Prepared payload, Queued status, expected worker's lock and non-null lock time;
- due run_at, attempts=0 and no StartedClaim.

The claim commits with Running before process creation. An uncertain commit
never grants execution. Lifecycle writes seal attempts to at least one, including
pre-launch Failed, because Apalis also fetches Failed with attempts below the
limit. Startup recovery seals historical Failed/attempts=0 rows from the previous
storage-only Agent; it preserves their identity/payload/output. It turns prior
Prepared/Running, including Queued and orphan-requeued claims, into Interrupted
under the exclusive runner lease before starting the consumer. No schema change
or runtime migration is introduced. Under that same exclusive runner lease,
recovery expires only the named HostLink worker's old heartbeat after reconciling
all nonterminal tasks. Apalis can then re-register immediately, even inside its
30-second duplicate-registration window; the Workers table remains bounded to
one runtime worker row across repeated restarts.

StartedClaims is never deleted by ACK, cancellation, orphan requeue or restart.
If an already-started task is requeued during the current lifetime, the service
refuses its mismatched queue/payload or spent claim, stops admission and cancels
all trees. Corrupt or ambiguous state remains blocking; recovery never replays it.
Prepared cancellation commits Failed without spawning. Running cancellation
returns Running until ProcessKit confirms tree teardown. Interrupted remains
UNKNOWN and blocks update.

## Shutdown and failures

The serving lifetime supervises the worker JoinHandle. Unexpected worker exit
fails SSH serving. Normal shutdown stops admission under start_lock and cancels
trees. Before allowing run_until to stop polling, the shutdown future waits for
all process permits. This ordering matters: upstream CallAll drains handlers
before poll_close, so stopping with a pending SQLite Fetch can park a transaction
which a handler needs to persist its final state. Polling continues while the
cancelled process tasks write their outcomes; no new process can pass admission.

A process task is spawned only inside the Apalis service after the fenced claim.
The service awaits it. The task independently retains its permit and runtime
through ProcessKit drain and durable publication. This is required because
upstream Worker::run returns on backend error and drops in-flight service futures.
The supervisor cancels and waits for every retained process permit on that path,
including decode/SQL failures. Service errors also stop admission, cancel trees
and return an explicit failure. The serving shutdown wait is bounded to five
seconds. On timeout it returns an error and signals cancellation without aborting
cleanup or releasing the runner lease while retained tasks remain alive.

A dequeued task prepares and syncs stdout/stderr spool files before rechecking
its source SHA. Missing/changing source may then be recorded as Failed with
valid empty output. Failure to prepare or sync either spool is UNKNOWN and
remains Interrupted, blocking updates. An unconfirmed ProcessKit teardown
or failed outcome publication quarantines the permit in the Agent runtime,
closes admission and forces worker/shutdown failure; no new task receives that
capacity slot. The bounded shutdown waits are per stage, not a guarantee
that the entire operation finishes within a single five-second deadline.

ProcessKit, exact source SHA checks, tree termination, raw capped/synced output,
private paths, sealed artifacts and updater admission retain their existing
owners. No installed Agent, normal profile, service or production data is used.

## Source audit

The pinned upstream local 1.0.0 sources were inspected, specifically SQLite
persist.rs/register/heartbeat/fetch_next, queries/backend/fetch_next.sql,
reenqueue_orphaned.sql and reenqueue_abandoned.sql; core worker/builder.rs,
worker/mod.rs/run_until, worker/call_all.rs, worker/lifecycle.rs and
backend/persistence/{mod.rs,service.rs}. These establish the actual builder and
extractor signatures, automatic ACK behavior, orphan retry despite max_attempts=1,
and the shutdown transaction hazard described above. No upstream patch/vendor
fork or guessed API is used. Tower 0.5.3 is an existing dependency; only its
`limit` feature and the Agent dependency entry were enabled.

## Verification

Environment: Linux, rustc 1.99.1 (58cf8f9c3 2026-10-13), offline cached pinned
dependencies. The aggregate SHA-256 over 185 workspace Rust/manifests/lock files
(sorted compact JSON path-to-SHA map) is:

`d77c64ba0ce0f82620570b3a671cbc95741a4dafd60dac0166514dd65461e7c4`

The exact source map, logs and complete patch are retained in ignored
`target/1c1073-worker-evidence/`. Documentation is excluded from that source hash.

| Executed check | Actual result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --offline --locked --workspace --all-targets` | PASS |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked -p hostlink-agent --lib ssh::` | 17 PASS, including nine new engine regressions and real encrypted/authenticated production-handler SSH over duplex streams |
| `cargo test --offline --locked --workspace --no-fail-fast` | NOT PASS: 174 passed, 22 failed in 12 targets because sandbox denies disposable socket binds, 2 pre-existing ignored tests |
| Agent updater / Linux lifecycle integration in workspace run | 26 / 2 PASS |
| Durable store tests in workspace run | 20 PASS |
| Client run/protocol tests in workspace run | 14 PASS |
| Independent read-only diff/upstream review, including final bounded shutdown adjustment | No concrete defects reported; reviewer made no edits and ran no tests |
| `cargo check --offline --locked -p hostlink-agent --tests --target x86_64-pc-windows-msvc` | BLOCKED in dependency build: missing lib.exe; no Windows compile/runtime PASS |
| `git diff --check`; isolated experiments workspace comparison to base | PASS; experiments unchanged |

The regressions use real SQLite queries and OS processes, including no-worker
Prepared/repeated-ID behavior followed by actual database polling; dequeue/claim
crash recovery; exact worker/task/owner/command rejection; StartedClaim orphan
reenqueue; terminal retry suppression and historical Failed/0 sealing without
rewriting the result; immediate restart with one worker registration row;
16-process backpressure; raw output/ACK loss/reconnect; explicit and shutdown
tree cancellation; backend decode failure during a running tree; runner-lease
retention and Interrupted update barriers.

Linux checks cannot establish Windows 7/11 runtime acceptance, power-loss
behavior or release approval. TCP sockets cannot be bound in this sandbox;
duplex SSH is useful protocol evidence but not TCP or deployed-service evidence.
The earlier storage-only receipt remains historical. Promotion/deployment
acceptance remains NO-GO until real TCP and native Windows gates are executed.

Git staging was attempted only on this task worktree. It failed creating
`index.lock` in its Git administrative directory with `Read-only file system`.
There is no commit: task HEAD and the parent production branch remain
`2c8c32d60f1e611e475fd8cf5fe988f210eff787`; all implementation files remain in
the local task diff. No dev/main/tag/service changes or merge were performed.
