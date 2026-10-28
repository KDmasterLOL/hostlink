# 1C-1081 simplification and P1 follow-up evidence

## 2026-10-28 — Apalis-first deletion pass (post-a144f57)

The user requested **maximum removal** of bespoke jobs machinery, prioritizing
upstream libraries and asking before adding any new guarantee. Baseline
`dev@a144f57d974e4af6f1aed021f63970f9b4c6c898`: 2,859 production lines
and 3,504 test lines under `agent/src/jobs`. This isolated candidate combines
the Agent-owned source refactor and storage micro-cleanup:

- Remove the bespoke Unix walk from `/` through every ancestor's UID/mode/sticky
  bits, and delete `ancestor_tests.rs`. Use `std::fs::canonicalize` to reject
  path aliases; rely on private, Agent-owned **managed roots**, SSH key trust,
  and the OS user boundary instead of a global host-filesystem policy.
- Reduce `source.rs` from 180 to 75 lines by reusing
  `ArtifactStore::authorize_source` (private file/link/ACL/owner checks), then
  verifying the sealed source SHA at admission and dequeue and its execute/read-only
  mode. Do not claim this atomically pins pathname execution against same-UID
  replacement.
- Remove the second hand-coded digest-copy loop in `artifacts.rs`. Use
  `std::io::copy` with an explicit size cap, and reuse the existing
  `verify_artifact` on the **finished sealed file**.
- Remove duplicate `JobStore::from_pool` construction path and one redundant
  owner digest check; keep the database read-only inspector and one-shot claim.
- Preserve public `jobs run/list/status/logs/cancel`, per-controller sealed
  artifacts, immutable ULIDs/idempotency, bounded output, OS-tree shutdown,
  updater locks, and no replay of started commands.

The pinned **apalis-sqlite 1.0.0** source was examined: `FetchById` and
`ListTasks` cannot atomically provide the required owner+native result+claim
projection. In particular, upstream `reenqueue_orphaned.sql` changes
Running/Queued to Pending **without** filtering `max_attempts`; `fetch_next.sql`
selects Pending unconditionally on attempts. Thus `max_attempts(1)` alone
does not preserve the root `AGENTS.md` rule against silent replay of started
programs. Apalis `TaskSink`, `WorkerBuilder` and `ack_tasks` are already used;
do not invent another infrastructure layer to work around their limits.
Additional major removal of `StartedClaims`/native SQL requires a user-approved
change in no-replay guarantees and deliberate migration review; neither was
silently performed.

| Current source-scoped verification | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --offline --locked --workspace --all-targets` | PASS |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| Agent `cargo test --offline --locked -p hostlink-agent --lib jobs:: -- --test-threads=1` | **69 PASS, 0 failed, 1 ignored subprocess helper** |
| Encrypted authenticated in-memory SSH wire scenario | 1 PASS, **weak-containment rejection branch**; full positive process execution not reached |
| SFTP library tests | 4 PASS |
| Client run/protocol tests | 16 PASS |
| Client binary CLI tests | 10 PASS |
| `cargo test --offline --locked --workspace -- --test-threads=1` with shared Cargo target and private HOME TMPDIR | **PASS, exit 0** across Client/Agent/Hub and their integration targets; two external HTTPS/gateway fixtures and subprocess helper explicitly ignored |

This candidate has **2,664 production lines** and **3,416 test lines** in
`agent/src/jobs`: production **−195 lines (−6.8%)**, ten test files reduced
to nine, and tests **−88 lines** (mostly removed obsolete ancestor tests).
The result is a *limited*, proven code reduction, not a claim that HostLink
is now a one-file vanilla Apalis worker. Native Windows 11/Win7 acceptance of
this source and mandatory strong Linux process-tree containment have **not**
been shown. Older verification below is historical to its documented SHAs.
No installed Agent, production host, database, job state or migration was
modified.

## Integration review of runtime ownership and updater scan

Verified code candidate: `3d376121a20c186fbfcde47404183a48bac2f2bb`
(subsequent edits to this file/documentation do not change Rust behavior).
Starting from `dev@ea17116c6551a1ccab80452f28773d3eafd3662f`, the task
deletes `agent/src/ssh/jobs` and `agent/src/durable`, and replaces the
old jobs-v1 commands with `jobs run/list/status/logs/cancel` over
`hostlink-jobs`. Apalis SQLite holds native status/results, with only one
immutable per-start execution claim; ProcessKit owns OS process trees.
No production jobs-v1 adapter, second UUID, or alternate `claim_start`
remains.

Last refinement: `JobRuntime::open` now holds existing-store opening,
exclusive runner lock, recovery and runtime construction within the jobs
owner, rather than SSH manually assembling the mechanism. The updater's
`active_ids` safety scan now reads directly through the validated read-only
SQLite pool; it no longer instantiates a write-capable Apalis queue for a
read-only inspection. Pinned Apalis `ConcurrencyLimitLayer` must remain
distinct from retained OS-tree `slots`: the former bounds dequeue consumer
futures, while the latter quarantines UNKNOWN process capacity beyond worker
completion. Eliminating it would weaken an actual safety invariant.

| Source-scoped code validation at 3d37612 | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --offline --locked --workspace --all-targets` | PASS |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| Agent: exclusive runner lease, missing store, orphan no-replay, updater-locked recovery, tampered native claim | 5 focused tests PASS |
| Client: `cargo test --offline --locked -p hostlink --lib run::` | 16 PASS |
| Client: `cargo test --offline --locked -p hostlink --bin hostlink` | 10 PASS |
| Agent full Linux `jobs::tests::` scan with Btrfs TMPDIR | 25 PASS, 1 source-ancestor fixture FAIL (the HOME connector maps `/` to foreign UID 65534; no ACL bypass) |

The identical **production-file** line-count method (all `*.rs` under
Agent job directories, excluding files with `test` in the name) gives
`dev` legacy 2577 lines and this candidate 2859 lines (**+282**).
The accepted simplification is ownership/API/state correctness, **not**
a net decrease in Agent LOC. The extra ProcessKit cancellation, output
proof and security checks remain necessary under the current no-replay
contract. Previous intermediate LOC snapshots further below are
historical, not the final count. Earlier native Windows 11 evidence was
for **8bbaf21 only**; Windows 11/Win7 native acceptance on the final
integrated source, and full Linux workspace runtime with strong
containment, are **not proven**. No client/production deployment.

## 2026-10-28 — owned ProcessKit deadline and Windows 11 acceptance

Latest source-exact **task-branch** candidate:
`8bbaf21cb62d49b04771cb8f6ee957cc522ed58d`.
Only the isolated task branch was committed/pushed. Neither `dev`,
`main`, release tags, installed Agents, customer machines, services nor databases
were changed by this continuation.

Pinned ProcessKit 3.3.4 kills only the direct child on a shared-group
`Command::timeout`. A descendant that inherits stdout/stderr can therefore
hold the pipes open until `join_pumps` silently aborts after five seconds,
leaving neither raw tee with a confirmed EOF flush. The earlier Windows
fixture repeatedly reproduced that truthful UNKNOWN error on
`98e6c22` and `dff64e8`. Commit `bfd9991` moved the deadline into the
owned `ProcessGroup`: timeout or explicit cancellation stops the entire
group before the joined output pumps are finalized. Commit `8bbaf21`
bounds that stop-and-drain phase to ten seconds and propagates any stop,
reap or pipe failure as UNKNOWN. The separate five-second group membership
confirmation, both stream-end flush markers and spool fsync still gate
`Failed`/EOF. Unknown or unconfirmed results retain the non-replay fence,
stop admission and quarantine capacity; there is no silent retry.

| Source-exact verification | Result |
| --- | --- |
| HOME `cargo fmt --all -- --check` | PASS |
| HOME `cargo check --offline --locked --workspace --all-targets` | PASS |
| HOME `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| HOME `jobs::worker::tests::stalled_process_reap_is_bounded_and_never_reports_completion` | 1 PASS, real ProcessKit empty group and intentionally pending drain |
| HOME `jobs::tests::actual_apalis_orphan_requeue_cannot_replay_started_command_even_after_restart` | 1 PASS, real Apalis SQL and immutable claim |
| HOME Client binary CLI tests | 10 PASS |
| WORK Windows 11 `bfd9991`, compact test profile, native timeout/tree/EOF | **1 PASS**, source-exact `mcp-job 765dd840-42c9-4260-b824-ef5213cf298e` |
| WORK Windows 11 `8bbaf21`, compact test profile, `cargo test --locked -p hostlink-agent --lib jobs:: -- --nocapture --test-threads=1` | **27 PASS, 0 failed, 2 ignored fixture helpers**, source-exact `mcp-job 2dd3be2b-5dce-45b5-bf9c-ae5b7d037294` |
| WORK Windows 11 `8bbaf21`, Client `cargo test --locked -p hostlink --lib run::` and `--bin hostlink` | **16 protocol and 9 CLI PASS**, 0 failed, `mcp-job 9017c239-68cd-4c8c-8525-9fa2fe8d324f` |
| Independent read-only ProcessKit 3.3.4 review of `bfd9991..8bbaf21` | No P0/P1 findings |

On WORK the native test runs with `CARGO_PROFILE_TEST_DEBUG=0` and
`CARGO_INCREMENTAL=0`; this produces a test binary within the immutable
64 MiB artifact seal limit. Without the compact profile, the ordinary
debug test binary was about 275 MiB and Seal correctly refused it
**before execution**. The test now fails with an actionable profile diagnostic
instead of an opaque artifact-size error. No production limit was weakened.
The Windows fixture verifies the descendant exits, the terminal state is
`Failed`, and both output streams report EOF only after confirmed teardown.

On HOME, 25 of 26 jobs storage tests passed; the remaining Seal test was
rejected because the connector's UID namespace reports `/` as UID 65534.
This is expected fail-closed ancestor ownership enforcement, **not** a passing
source-authorization runtime test. A full Linux workspace PASS for the
`8bbaf21` source is **not established**. A full WORK Windows workspace run
and real Windows 7 x64/x86 acceptance have also **not** been established.
The candidate is **not release/deployment certified**; the evidence above
is confined to the branch, native Windows 11 jobs, Linux static checks and
selected regressions. No existing jobs-root database was migrated.

Current follow-up is based on `task/1c-1081-minimal-apalis-jobs` at
`a60b7b3f1069cfb03406bd15e97760ca39b7779b`, 2026-10-28.
No release, deployment, dev/main merge, installed Agent, customer data or services
were touched. The original Windows 11 run of a60b7b3 is historical evidence
and failed one process-tree timeout test; retest the corrected source separately.
Contract: [minimal jobs](AGENT_MINIMAL_JOBS.md).

## Updater Busy and cancellation/read-error P1 fixes

- Consumer retries only WouldBlock on the exact dequeue-bound claim, releasing
  `start_lock` and permit during cancellable 10–100 ms async backoff. It re-reads
  terminal/cancel state each attempt. Shutdown leaves unclaimed Queued work for
  native Apalis restart recovery; spent claims cannot replay. Other errors still
  stop admission and process trees. Admission still returns Busy without enqueue.
- Local cancel no longer configures ProcessKit `cancel_on`: explicit group stop
  runs alongside drain, preserving Io. The final cancel check/start share
  `start_lock` with authenticated Cancel. Clean drain + both stream-end flushes +
  spool fsync + full group-empty confirmation allow Failed; any drain error stays
  UNKNOWN and follows existing permit quarantine. Global shutdown may stay UNKNOWN.
- Pinned source checked locally: ProcessKit 3.3.4 `pump.rs` flushes before setting
  read-error; `running/mod.rs` checks Cancelled before read-error in finish_lines.
  Apalis SQLite/core 1.0.0 native fetch/register/requeue and disabled Lock/Complete
  persistence retain task identity and at-most-once execution. No dependency added.

Files changed by this P1 task: `jobs/{engine.rs,busy_tests.rs,worker.rs,worker_tests.rs,
tests.rs}` under `crates/agent/src/`; `README.md`; and
`docs/{AGENT_MINIMAL_JOBS.md,AGENT_MINIMAL_JOBS_EVIDENCE.md,SOURCE_LAYOUT.md}`.
`tests.rs` only exposes existing fixture helpers to sibling tests. Strong backend,
ancestor/source checks, CLI/SSH exec and Windows JobObject implementation are
unchanged by this task. During final verification, concurrent edits appeared in
`jobs/private_fs.rs` and `jobs/database.rs` (FileLease ownership flag and consuming
unlock). They were preserved, are not authored by this task and are outside the
two independent reviews. An additional concurrent `busy_tests.rs` edit adds an
optional source-ancestor capability skip (required mode still fails); it is not
authored by this task. The Busy reviewer checked this guard separately and found
no production bypass; its NOT RUN is not native evidence. Build checks and focused regressions were repeated on the
combined FileLease tree; the broad-suite result precedes those concurrent edits.
Two separate read-only reviewers inspected Busy against pinned Apalis
and cancellation against pinned ProcessKit; both reported no findings. The
cancellation reviewer also checked the added deterministic Cancel/spawn FIFO test.

The Windows 11 baseline test also logged repeated `ERROR_NOT_LOCKED (158)`.
`FileLease::unlock(self)` now consumes its guard, sets the held flag to false
after an explicit successful unlock, and `Drop` only unlocks still-held leases.
This removes duplicate unlock attempts while retaining fail-closed explicit
unlock errors and fork-safe release on unwinding. Native Windows recheck is
required; this source change by itself is not evidence of Windows success.

### Executed verification

Common environment: `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=$PWD/target
TMPDIR=$PWD/target/test-tmp MISE_STATE_DIR=/tmp/hostlink-1c1081-mise`.
Cargo commands used `--offline --locked`; tests used `-p hostlink-agent --lib`.

| Check | Observed result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo check --offline --locked --workspace --all-targets` | exit 0, includes final test source and concurrent FileLease edits |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | exit 0, includes final test source and concurrent FileLease edits |
| `cargo test … jobs::engine::busy_tests -- --nocapture --test-threads=1` | exit 0: 3 fully exercised SQLite/Apalis tests; running+queued native scenario NOT RUN (`process_group`) |
| `cargo test … jobs::worker::tests::cancelled_signal_and_flushed_spools_do_not_mask_io_read_error -- --exact --nocapture` | exit 0: real finish_job/SQLite/filesystem; Err(Io)+cancel+flushed spools gives UNKNOWN/eof=false/error; clean signalled outcome+cancel gives Failed/eof=true |
| `cargo test … jobs:: -- --nocapture --test-threads=1` | exit 101: libtest 50 passed, 19 failed, 1 ignored; 17 NOT RUN diagnostics (16 early returns plus a partial positive-ancestor skip); before the final FIFO test was added, P1 production code identical |
| `cargo test … jobs::worker::tests::authenticated_cancel_waiting_at_spawn_gate_prevents_execution -- --exact --nocapture` | exit 0 with NOT RUN (`process_group`); no native acceptance |
| `HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1 cargo test … jobs::worker::tests::clean_user_cancel_confirms_failed_and_worker_continues -- --exact --nocapture` | exit 101: required backend unavailable (`process_group`), before fixture/spawn; no native acceptance |
| `git diff --check` | exit 0 |

All 19 broad-suite failures occurred at existing sealed-source fixture setup with
`PermissionDenied: source ancestor permits foreign entry replacement`. This
sandbox exposes `/` and `/home` as UID 65534 (`uid_map: 1000 0 1`); the ancestor
gate remains intact. The SQLite Busy tests deliberately use an unauthorized
storage-only source, exercising actual dequeue/claim/recovery then the real
pre-spawn rejection with synced empty spools; they do not prove successful spawn.
The read-error regression injects public Err(Io) at the real finisher boundary;
it does not reproduce a faulty OS pipe. Native clean cancel, authenticated
Cancel/spawn ordering, running+queued updater contention and all Windows/Win7
execution remain NOT RUN here. Final runtime acceptance remains **NO-GO** until
verified on a host with provable ancestors and an actual strong backend.

The sections below retain historical evidence from earlier snapshots, including
`ea17116c6551a1ccab80452f28773d3eafd3662f`; their scope/results do not describe
this P1 follow-up.

## Final ancestor-security P1 and required-native P2 follow-up

Status: **source complete; runtime security acceptance remains NO-GO** in this
sandbox. The coordinator reports a full Linux workspace PASS before this
follow-up using `CARGO_TARGET_DIR=target` and `TMPDIR=target/test-tmp`; that is
historical user-provided evidence, not a final-source PASS from this run.

Only production `jobs/private_fs.rs` and `jobs/artifacts.rs` change here.
The reusable Unix walk examines each ancestor from `/` without first resolving
away symlinks. It requires directory type and root/Agent owner at every step;
a foreign owner could chmod even a 0755 directory. Group/world-writable
non-sticky ancestors are rejected. Writable sticky parents need both trusted
parent and trusted next-entry owners; an unknown child is rejected. The terminal
install/sealed directory must itself be protected, with existing private-file
checks retained. ArtifactStore open, source authorization and Seal invoke the
walk. Existing admission and immediately-pre-spawn source checks therefore
repeat it. Windows ACL behavior, SHA/identity checks, ProcessKit mechanism gate,
claim/no-replay and UNKNOWN handling remain unchanged. These pathname checks
are not atomic exec-by-FD protection against same-UID/root mutation.

Source tests add an ancestor **above** nested install, cached-store Seal refusal,
ancestor symlink and post-admission writable-ancestor rejection. The queued test
also checks no new admission, durable empty Failed spools and no replay after
permissions are restored. The UID/mode policy table covers root/Agent sticky
parents with root/Agent children, foreign sticky children, unknown children,
non-sticky 0777/0775/0757 and foreign-owned 0755. Separate tests use real chmod,
symlink and metadata functions. Actual foreign-UID chown/race execution is not
claimed; foreign-child ownership is covered at the production policy predicate.

One test-only containment helper now serves internal jobs, encrypted SSH wire,
Agent integration and Client Agent E2E tests. Optional mode emits named NOT RUN;
`HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1` panics on the actual weak backend before
returning a skip. The wire check runs before fixture initialization in required
mode. The isolated current-test-binary subprocess regression checks default
success/NOT RUN and required failure on the actual backend, without globally
mutating environment variables. Its child-only helper is explicitly ignored in
ordinary runs. No dependency or production bypass was added.

Independent read-only review found no findings; runtime limitations below were
explicitly retained. `Cargo.toml`, `Cargo.lock`, `jobs/{mod,persistence,worker,
protocol,source}.rs` are byte-identical to this follow-up's starting snapshot,
including both coordinator unlock fixes. No commit/stage/push/integration.

### Executed checks and blocked runtime

All build/test commands used `CARGO_INCREMENTAL=0`,
`CARGO_TARGET_DIR=$PWD/target`, `TMPDIR=$PWD/target/test-tmp`,
`MISE_STATE_DIR=/tmp/hostlink-1c1081-mise`, and locked offline dependencies.

| Command (after common environment) | Exact result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo check --offline --locked --workspace --all-targets` | exit 0 |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | exit 0 |
| `cargo test --offline --locked -p hostlink-agent --lib ancestor_tests -- --nocapture --test-threads=1` | exit 0; 3 libtest successes: 2 fully exercised tests, 1 real unknown-root rejection with positive /home and root-owned sticky /tmp segment NOT RUN |
| `cargo test --offline --locked -p hostlink-agent --lib jobs::process_tests::containment_mode_tests -- --nocapture` | exit 0; 1 passed, 1 subprocess-only helper ignored; parent asserts real child failure in required mode |
| `HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1 cargo test --offline --locked -p hostlink-agent --lib jobs::process_tests::agent_shutdown_cancels_the_owned_process_tree -- --exact --nocapture` | exit 101, 1 FAILED: expected negative proof of required-mode failure, actual backend `process_group`; NOT native positive acceptance |
| `HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1 cargo test --offline --locked -p hostlink-agent --lib ssh::server::wire_tests -- --nocapture` | exit 101, 1 FAILED before filesystem fixture: expected missing-containment diagnostic; NOT native positive acceptance |
| `cargo test --offline --locked -p hostlink-agent --lib jobs::source_tests::unsafe_ancestor_above_install_rejects_source_open_and_seal -- --exact --nocapture` | exit 101, 1 FAILED at fixture setup: root owner cannot be proved; intended source/Seal assertions NOT REACHED |
| `git diff --check` | exit 0 |

The sandbox maps only UID 1000 (`/proc/self/uid_map`: `1000 0 1`). Stat of `/`
and `/home` exposes UID **65534**, not provable root or Agent. `/tmp` here is
Agent-owned 0700, not native root-owned 01777. The new security policy correctly
rejects the full absolute source path; there is no insecure test exception.
The policy unit run checks that rejection, but does **not** prove positive native
ancestor behavior. The source/queued fixtures and final full workspace must be
rerun where root ownership is visible. Full workspace runtime was not attempted
here after the confirmed fixture blocker; no final full-suite PASS or skip count
is invented. Native Windows/Win7/FreeBSD remains NOT RUN.

The HOME connector rejected a read-only `stat` attempt because it requires
approval while the session policy is `never`; no HOME command executed.

Run mandatory positive acceptance on a socket-capable host with provable ancestor
owners and strong containment (Linux delegated cgroup v2, Windows JobObject,
FreeBSD ProcessReaper):

```sh
HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1 CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR="$PWD/target" TMPDIR="$PWD/target/test-tmp" \
  cargo test --locked --workspace -- --nocapture --test-threads=1
```

Zero exit is required. Named NOT RUN markers in optional logs identify skipped
positive segments; libtest `ok` alone is not native acceptance. On this weak host
the mandatory command must fail, as the focused required-mode run demonstrates.

### Source-exact local receipt

Local ignored artifacts: `target/ancestor-native-{fmt,check,clippy,policy,modes,
required,wire-required,source-runtime}.log`, `target/ancestor-native-verification.json`,
`target/ancestor-native-source.sha256`, `target/ancestor-native-followup.patch`.
Exact follow-up files:

```text
README.md
crates/agent/src/jobs/ancestor_tests.rs
crates/agent/src/jobs/artifacts.rs
crates/agent/src/jobs/containment_mode_tests.rs
crates/agent/src/jobs/engine_tests.rs
crates/agent/src/jobs/private_fs.rs
crates/agent/src/jobs/process_tests.rs
crates/agent/src/jobs/source_tests.rs
crates/agent/src/ssh/tests/wire/mod.rs
crates/agent/tests/support/containment.rs
docs/AGENT_MINIMAL_JOBS.md
docs/AGENT_MINIMAL_JOBS_EVIDENCE.md
docs/SOURCE_LAYOUT.md
```

Starting dirty files are preserved in
`/tmp/hostlink-1c1081-before-ancestor-native.tar` and their hashes in
`target/ancestor-native-before.json`.

The final source/build manifest contains **197** inputs; manifest SHA-256:
`cb9a5c0ab3efd7f8bfc7ed1690bf3278d038664fb05577d753438a0ef3824699`.

```text
eaa50eee6fae24937a577035a36fba52f710cc0a343ccca5a4ec6d563ada35a2  crates/agent/src/jobs/private_fs.rs
b3eda2189f082a15845c7de9b9dd6aaeae077996931fc54e005e2b9ebec1f483  crates/agent/src/jobs/artifacts.rs
```

## Earlier two-job-security P1 follow-up (historical)

Source owner remains `crates/agent/src/jobs/`; no v1 execution path is added.
This follow-up starts from the coordinator's existing dirty diff, including
explicit unlocks in `JobStore::initialize_fresh` and `JobRuntime::drop`. Both
are preserved byte-for-byte. The actual production job-source count at this
follow-up's start was **2577**, now **2655** (+78 lines); the older counts below
are historical snapshots, not the current tree.

A. `worker.rs` creates a ProcessKit group and inspects that **same instance's**
`mechanism()` before the only `group.start`. The stable non-exhaustive enum is
matched against Linux CgroupV2 / Windows JobObject / FreeBSD ProcessReaper;
every other backend, including POSIX and future variants, fails before spawn.
Fresh empty stdout/stderr are synced before Failed is published. Sync or
publication uncertainty remains UNKNOWN; the execution claim is never renewed.
Existing post-spawn empty-group, pump EOF, spool fsync, permit quarantine and
update exclusion stay in force.

Pinned source inspected in `processkit-3.3.4/src`: `mechanism.rs:18-40`
(non-exhaustive enum), `group.rs:148-160,1436-1438` (empty group/actual backend),
`sys/linux.rs:79-139,613-617` (only cgroup or POSIX fallback), and
`runner.rs:716-738` (start in the same existing group). `host_containment()` is
only a prediction (`mechanism.rs:85-108`). There is no alternate strong Linux
backend or require-cgroup option; resource-limit-induced failure adds unrelated
caps. Linux parent-death cleanup is direct-child-only (`parent_death.rs:29-47`).
No custom process tracker or test-only production gate was introduced.

B. `ArtifactStore::authorize_source` validates install/artifact/controller/sealed
parents and the expected file with existing private owner/permission/SID/DACL
and link checks. The requested program's exact OS string must equal the expected
`sealed/<sha>.program` canonical path, not just its basename or resolved alias.
`verify_job_source(store, owner, spec)` then retains executable identity, digest,
read-only Unix file and optional remote cwd checks. New authenticated admissions
validate this before enqueue; the worker repeats it after queue delay immediately
before start. An exact already-recorded ID/owner/spec returns its old state even
if the source was changed/deleted, preserving lost-ACK lookup without replay.
The existing pathname-exec same-UID replacement caveat remains explicit.

Unit regressions write real private upload files and call actual Seal. Linux TCP
fixtures use SFTP→Seal (compiled here, TCP runtime blocked). The Windows
crash-injection fixture constructs the private sealed layout before server
startup and later verifies it through real Seal; Windows-specific source was
adapted but not compiled or executed here. The regressions cover another controller with
identical artifact bytes, arbitrary readonly paths in writable parents, writable
sealed parents/files, file/directory symlink aliases, traversal/dot aliases,
corrupt digest, unsafe cwd, changed source/parent after admission, source removal
and exact lost-ACK retries. The fallback regression runs real Apalis processing
twice: no parent or setsid-descendant launch marker, Failed with both durable
empty spool EOFs, one claim/attempt per ID, no quarantine, healthy admission and
no replay. The encrypted russh duplex scenario checks authenticated rejection
without enqueue, then real fallback failure, lost ACK/reconnect, both empty
output streams and cross-controller denial. Positive native process assertions
remain in the tests and require an actual capable ProcessGroup.

Only test code adds direct `processkit.workspace` under Client dev-dependencies;
it uses the already-pinned 3.3.4 package. No resolved package version changes.

Independent read-only review of the four production files and pinned ProcessKit
found no findings. It checked the actual-instance launch gate, exact owner-bound
canonical source, prelaunch sync, no replay and preservation of both unlocks.
This is source review, not native runtime acceptance.

### Latest verification

Rust build/test commands ran in this isolated worktree using
`MISE_STATE_DIR=/tmp/hostlink-1c1081-mise`,
`CARGO_TARGET_DIR=/tmp/hostlink-1c1081-target`, and
`TMPDIR=$PWD/target/test-tmp` (Btrfs; not quota-limited `/tmp`).

| Executed command | Final result |
| --- | --- |
| `cargo fmt --all`, `cargo fmt --all -- --check` | exit 0 |
| `cargo check --offline --locked --workspace --all-targets` | exit 0 |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | exit 0 |
| `cargo test --offline --locked -p hostlink-agent --lib jobs:: -- --nocapture --test-threads=1` | 56 libtest successes, 0 failed: 42 exercised bodies, 14 positive bodies NOT RUN |
| `cargo test --offline --locked -p hostlink-agent --lib ssh::server::wire_tests -- --nocapture` | 1 exercised test, 0 failed; authenticated negative/fallback branch |
| `cargo test --offline --locked -p hostlink --lib run::tests_protocol -- --nocapture` | 7 passed, 0 failed |
| `git diff --check` | exit 0 |

Native positive process tests are **NOT RUN** on this host: actual ProcessKit
backend is `ProcessGroup` because cgroup v2 is not delegated. libtest reports
14 early-return positive test bodies as `ok`; they are excluded from positive
runtime proof here. The uncertain-native-state regression also reports a
NOT RUN marker for its positive branch but executes its negative/fallback branch.
The encrypted-duplex test executes real SSH authentication, framing, Seal,
source-rejection and fallback consumption/reconnect assertions; its native exit,
raw child output and tree-cancellation segment is NOT RUN. The first fallback
wire attempt exposed a fixture race between unconsumed Run ACK and Status; the
fixture now waits for bounded authenticated List visibility without consuming ACK.
The unchanged lifecycle/status assertions then pass.

Local logs and structured receipt (ignored build artifacts):
`target/two-p1-{fmt,fmt-check,check,clippy,jobs,wire,client-protocol,artifact}.log`,
`target/two-p1-verification.json`, `target/two-p1-source.sha256`, and
`target/two-p1-followup.patch`. The manifest hashes all **195** source/build inputs
under crates plus workspace manifests/config. Its SHA-256 is
`4138d3ad3d71989f931c56f8e6411702a97f29b3802dc3b6552871ee3b53088d`.

Exact reviewed production SHA-256:

```text
10b9b9d170ffebae5b4f5b47eb2bd3b2206e88115378b6db67dc89d396593bee  crates/agent/src/jobs/artifacts.rs
2a68e45f47f25d3ce5b0390cce98a567380556ac982b1b52f24cff6c5689dea7  crates/agent/src/jobs/protocol.rs
82fef5202ec307f555199dce2cf81d2474b6d4f9e6a2b529275a42e439dac3e9  crates/agent/src/jobs/source.rs
7ca2c4e7cd0b561511984103d3d03fc8a9e7ada4f94f7b10358db3187f6ccbf7  crates/agent/src/jobs/worker.rs
```

Exact follow-up files (relative to the pre-follow-up dirty snapshot):

```text
Cargo.lock
README.md
crates/agent/src/jobs/artifacts.rs
crates/agent/src/jobs/engine_tests.rs
crates/agent/src/jobs/process_tests.rs
crates/agent/src/jobs/protocol.rs
crates/agent/src/jobs/protocol_tests.rs
crates/agent/src/jobs/source.rs
crates/agent/src/jobs/source_tests.rs
crates/agent/src/jobs/windows_process_tests.rs
crates/agent/src/jobs/worker.rs
crates/agent/src/jobs/worker_tests.rs
crates/agent/src/ssh/tests/wire/mod.rs
crates/agent/tests/artifact_seal_loopback.rs
crates/agent/tests/ssh_loopback.rs
crates/agent/tests/support/containment.rs
crates/agent/tests/windows_durable_jobs.rs
crates/client/Cargo.toml
crates/client/tests/agent_jobs_interop.rs
crates/client/tests/cli_run_interop.rs
crates/client/tests/e2e_steps/gateway_jobs.rs
crates/client/tests/managed_https_gateway_e2e.rs
docs/AGENT_MINIMAL_JOBS.md
docs/AGENT_MINIMAL_JOBS_EVIDENCE.md
```

The tracked dirty baseline is preserved in
`/tmp/hostlink-1c1081-before-two-p1.patch`; jobs/support/docs untracked baseline
in `/tmp/hostlink-1c1081-before-two-p1-untracked.tar`. This is not a clean-HEAD
comparison: inherited task changes and coordinator lock fixes are retained.

The local TCP artifact integration attempt compiled but failed at listener bind
with `EPERM` before assertions. The HOME connector then rejected a read-only
source-identity command because it requires approval while policy is `never`;
no HOME command executed. Neither result is a TCP integration PASS.
Windows/Win7 and FreeBSD native execution remain **NOT RUN**. Full workspace
runtime has not been rerun after these two security fixes. The coordinator's
pre-fix full-suite PASS is historical and does not cover this final source.

## Earlier simplification snapshot (historical)

Physical production Rust lines, excluding filenames containing `test`, including
comments, imports and blank lines. First-pass snapshot: local
`/tmp/hostlink-1c1081-pass1.tar`; base count uses tracked HEAD source.

| Scope | First pass | Second pass before P1 | Current P1 |
| --- | ---: | ---: | ---: |
| Agent `src/jobs/*.rs` | 2546 | 2373 | 2558 |
| Client CLI `args.rs`, `commands/{job,run,mod}.rs` | 855 | 651 | 664 |
| Client `src/run/*.rs` | 637 | 685 | 685 |
| Same combined scope | 4038 | 3709 | 3907 |

Original Agent `durable/*.rs` + `ssh/jobs/*.rs`: **2577 → 2558**, -19 lines.
All scoped P1 fixes together add 185 Agent and 13 CLI lines over the second pass;
these safety mechanisms are included rather than hidden from the reduction. The Client library includes the
shared upload/seal/enqueue pipeline moved from CLI. Pre-P1 source is preserved
in `/tmp/hostlink-1c1081-pass2.patch`.

Mechanisms deleted in this pass:

- UUID-to-different-ULID resolution: one canonical caller ULID is native TaskId,
  idempotency key, payload ID, output-directory name and claim primary key.
  `StartedClaims` loses its second ID column; fresh-only schema is now 3.
- Full inventory per admission, list's inventory + ListTasks + per-row reads,
  FetchById + secondary status/claim lookup, and duplicate logs status lookup.
  One bounded SQL row decoder joins native lifecycle/result and the fence.
  List executes one owner-aware SELECT with deterministic pagination. Deep file
  inventory remains startup/recovery/updater only. SQL query-plan regression
  proves indexed ID and claim lookup; corrupt unrelated state still blocks updates.
- Public production `claim_start` and its optional alternate eligibility path.
  Only `claim_dequeued` remains: worker/snapshot-bound INSERT SELECT under
  BEGIN IMMEDIATE, then native Running in the same transaction. Spent claims
  fail, including after real upstream orphan requeue. Test crash injection is
  confined to cfg(test) code and integration-test SQL fixtures.
- Top-level run, low-level run CLI, PreparedJob command hierarchy, duplicate CLI
  spec/ID validation, duplicated SFTP orchestration, and a sealed-result DTO.
  Only `jobs run --binary [--id ULID] [--wait]` remains; default enqueues promptly.
  `HostConnection::job_run` shares the pipeline; low-level seal/start are private.
- Separate list/wire modules and the optional-field JobResponse hierarchy.
  One framing/dispatch path handles typed serde requests and bounded JSON replies.

One standard Apalis sink/WorkerBuilder remains. Native lifecycle/result is the
only state engine; the immutable claim is an execution fence. ProcessKit tree
ownership, raw spool limits/continuity, artifact/ACL checks, verified WAL/FULL,
Agent-owned lifetime and UNKNOWN update exclusion remain. No compatibility adapter.
The only dependency addition is direct use of already-locked `ulid = 3.0.0`;
no resolved package version changed.

## Four scoped P1 correctness fixes

1. Both raw tee writers expose an EOF-flush marker. `finish_job` observes both
   markers **before** syncing cloned spool FDs; a late pump write cannot race an
   earlier fsync and manufacture durable completion. Missing markers, sync
   failure or ambiguous teardown publish native Killed/UNKNOWN, block updates,
   retain partial bytes and never report EOF. Pinned ProcessKit 3.3.4
   `running/mod.rs::join_pumps` may abort after five seconds without returning an
   error. `pump.rs:1806` flushes raw tees at EOF (also after read error, surfaced
   by drain). AsyncWrite flush is not intrinsically EOF: an upstream early-flush
   change would invalidate this proof; later writes clear the marker, and upgrades
   must recheck this contract. Overflow cancels the tree and discards excess
   bytes while draining to EOF, retaining the bounded Failed-prefix semantics.
   The deterministic regression uses real child exit, real fsynced partial files
   and missing markers at the post-drain fault boundary; it does not claim to
   reproduce the library's five-second hang itself.
2. Recovery preserves unclaimed pristine Pending and Queued work and expires the
   named worker heartbeat. Actual Apalis registration reenqueues Queued rows;
   pinned orphan/abandoned queries increment attempts and write two exact Err
   strings. Only those known native bookkeeping results without any claim remain
   eligible. Claim atomically sets attempts=1 and clears the bookkeeping result.
   Spent claims and uncertain bookkeeping become Killed; malformed status/result
   still fails closed. Restart before dequeue and after real dequeue both execute
   once. Existing committed-claim/orphan/restart regressions still prohibit replay.
3. Pinned `runner.rs:914` proves Cancelled from Command.start short-circuits before
   spawn. It now publishes Failed only after both empty spools sync, returns Ok
   to the consumer and does not quarantine a permit or shut down admission.
   Source failures retain their sync checks; ambiguous errors remain UNKNOWN.
   A pre-cancelled post-claim job and a subsequent real WorkerBuilder job prove
   no first launch, successful second execution and no unknown permits.
4. CLI --wait keeps one total transport failure budget: at most three reconnects,
   error on the fourth failure. Successful status or one successful output stream
   never replenishes it. The unchanged wait loop was extracted locally for a real
   scripted SSH transport test: each connection succeeds on status/stdout, rejects
   the stderr channel, and must stop after four failures/eight successful reads.
   This test compiled but could not reach its assertions here because TCP bind is
   denied; it is explicitly not a runtime PASS.

## Earlier empty-group confirmation P1

`shutdown_ref()`/successful kill issuance is insufficient. The worker now retains
its ProcessGroup and calls `stop(Duration::ZERO, true)` repeatedly, with 25 ms
between reports and a five-second hard timeout. Only `members_after() == Some(0)`
authorizes terminal publication. `None`, positive counts at the deadline, and
query/stop failures yield native Killed/UNKNOWN and an error, preventing output
EOF, retaining the worker permit and blocking updater admission. There is no
custom PID enumeration or leader-only `members()` check. Cancellation issues stop
concurrently with child drain/reap, then uses the same confirmation; failed starts
also require empty-group confirmation. EOF-flush markers and spool fsync checks
remain required. Prior Windows secure-new-upload and nonblocking update-lock fixes
are preserved.

Source contract: pinned ProcessKit 3.3.4 `group.rs:1127-1210`,
`ShutdownReport::members_after`, backend `GracefulTarget::alive_count` (Windows Job
Object, Linux cgroup or POSIX tracked process-group probe). Direct-child drain/reap
precedes final confirmation, avoiding unreaped direct-child zombie false positives.
The real Linux regression starts a descendant that installs SIGTERM ignore before
the parent exits, closes stdio and runs `sleep 300`. It checks the descendant is
no longer running before Exited(7) and updater eligibility become visible. Existing
cancellation/tree and overflow tests also execute this confirmation path.
No synthetic unknown-count/query-failure backend was introduced; those OS failure
paths are fail-closed in source but were not induced on this host.

## Earlier executed verification (before the two-security-fix follow-up)

Linux builds use `/tmp/hostlink-1c1081-target` and
`MISE_STATE_DIR=/tmp/hostlink-1c1081-mise`.

- `cargo fmt --all`, then `cargo fmt --all -- --check`: PASS.
- `cargo check --locked --workspace --all-targets`: PASS.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: PASS.
- `cargo test --locked -p hostlink-agent --lib jobs::`: **51 passed, 0 failed**.
  Includes the SIGTERM-ignoring closed-stdio descendant regression, process-tree
  cancellation, overflow, pump-end/fsync, pre-spawn cancellation/healthy second job,
  no-replay/restart, update-lock Busy/shutdown, native Apalis and UNKNOWN fences.
- `cargo test --locked -p hostlink-agent --lib ssh::server::wire_tests`:
  **1 passed, 0 failed**, real encrypted russh over duplex streams.
- `git diff --check`: PASS.

Logs: `/tmp/p1-empty-group-{fmt,check,clippy,jobs-final,wire}.log`.
No full workspace test was run for this final P1, as requested.

Separately, the coordinator reports an independently executed HOME full Linux
workspace run on the second-pass draft **before this P1**: **exit 0, 205 passed,
0 failed, 2 ignored**, including real TCP. Its external log is
`/tmp/hostlink-1c1081-external-workspace.log` in HOME's separate `/tmp`, not visible
in this sandbox. This records the coordinator's evidence, not a local inspection
or a full-workspace PASS of the final P1. Earlier sandbox TCP EPERM results are
not an outstanding Linux capability gate; the coordinator's final-P1 full-suite
rerun remains pending.

## Remaining gates and commit status

Native Windows 11 / Windows 7: **NOT RUN**. The preceding i686 MSVC cross-check
stopped in ring at missing SDK/CRT `assert.h`; it was not a Windows compilation
pass. No native Windows claim is made for membership polling or upload ACLs.

No staging or commit was attempted, per instruction. HEAD remains
`ea17116c6551a1ccab80452f28773d3eafd3662f`. All edits remain in the same dirty
isolated task worktree; no dev/main, deployed Agent, customer or release writes.
