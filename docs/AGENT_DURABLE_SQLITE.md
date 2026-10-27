# Agent durable SQLite contract (1C-1073)

`durable/` owns the real Apalis SQLite Jobs payload, canonical caller UUID,
controller key fingerprint, immutable spec/request SHA, state, one-use started
claim, bounded private output and sealed artifacts. `ssh/jobs/` owns the frozen
jobs-v1 subsystem, four-byte big-endian JSON framing and processkit execution.
The old jobs namespace and filesystem record backend have been deleted. Client
production code and the isolated PoC workspace are unchanged.

## Admission and recovery

- Admission uses `SqliteStorage::send`, one allowed attempt and the UUID as its
  idempotency key. Full record readback checks owner, exact spec and source hash.
  Conflicting requests fail; Existing never creates a process.
- `claim_start` validates eligibility and commits StartedClaims plus Running in
  one `BEGIN IMMEDIATE` transaction before processkit may start. The claim binds
  the UUID, Apalis task ID, owner and request digest. Any uncertain commit fails
  closed. Neither restart nor a lost ACK grants another attempt.
- The Agent holds an exclusive runner lease through all retained worker/session
  references. Restart recovery turns Prepared/Running into Interrupted and
  disables their Apalis queue eligibility, preserving the claim. Interrupted
  has no automatic reconciliation transition and always blocks update.
- The normal Apalis worker/orphan retry loop is deliberately not enabled:
  upstream orphan recovery requeues Running even with max_attempts=1. Tests
  exercise that actual query and prove it cannot authorize a second claim.
- jobs-v1 has no scheduling fields. It rejects unknown input; no cron or hidden
  retry scheduler has been introduced. Native Apalis run_at eligibility is
  checked when claiming, without exposing an untrusted new protocol field.

## Filesystem and durability

Provisioned `jobs_root` is private and contains `jobs.db`, optional SQLite WAL
and shared-memory sidecars, `runner.lock`, and `outputs/<UUID>/{stdout,stderr}.bin`.
There are at most 4096 records, 64 KiB per record (largest terminal representation
must fit), 8 MiB per raw output stream and 24 KiB per output response. Exited
output must exist; missing output is an error, never fabricated EOF. Unknown
output directories, FIFO/symlink files, Unix hardlinks or oversized streams fail
the safety scan. Windows paths retain SID/DACL and reparse checks. Artifacts remain a sibling under the same install root and retain
per-controller ownership, exact seal size/SHA and private read-only execution.

Every connection uses WAL and FULL, verified after connect and before acquire;
the pool has one connection, finite SQLite busy/acquire timeouts and replacement
connection tests. Apalis public migrations run directly: its setup routine that
sets synchronous OFF is never called. Sidecars created by SQLite inherit only
the private directory's access and receive protected private Windows DACLs.
Output file names and bytes are synced before terminal publication.

Lock order is shared install-root update.lock, then SQLite transaction. Async
admission acquires the filesystem lock on a blocking worker, so a single-thread
Tokio executor can still finish SQL. Service and updater retain synchronous
safety checks using a read-only SQLite connection on a scoped runtime thread;
they do not reacquire the updater's already-held lock. Active and Interrupted
states defer replacement, and invalid/unknown state returns an error.
Processkit cancellation/timeout waits for tree teardown. Uncertain teardown,
shutdown or failed output synchronization stays Interrupted.

## Existing filesystem records

This change intentionally implements the task's fail-closed migration option,
not an automatic importer. Any legacy UUID directory or unknown root entry
aborts Agent opening and updater scans with its path and a migration diagnostic.
The scan never reads, rewrites or deletes legacy records or output. It does not
initialize jobs.db around them. Torn/empty databases and orphan output are also
preserved and rejected. A missing database cannot prove update safety: even an
empty uninitialized root blocks service/update scans. Only explicit fresh enrollment/provisioning calls
`DurableStore::initialize_fresh` on a new private EMPTY root. Ordinary
`DurableStore::open` (including SSH runtime startup) never creates a database,
repairs missing output directories or runs migrations. Even empty and
runner-only roots fail runtime opening if jobs.db is absent. Existing migration
versions, success flags and checksums must match this Agent. An incompatible
schema requires a separately verified migration; opening never repairs its
ledger. Existing connections verify WAL without converting an unknown mode.

For an existing install, retain a complete private backup and its exact legacy
Agent binary/config. Reconcile active and UNKNOWN IDs with their controller;
keep the original root for the legacy Agent's status/output inspection. A
verified importer must establish identity/state/output equivalence before that
root can be reused. Until such an importer exists, upgrading a nonempty legacy
jobs root is blocked. A separate fresh enrollment/private root can exercise the
new backend without altering the old root or replaying any legacy UUID.
Do not delete records or reset IDs to make preflight pass.

## Evidence boundary

Linux source checks and focused SQLite/process tests do not establish Windows
7 or Windows 11 runtime acceptance or power-loss durability on real hardware.
See the task evidence receipt for exact executed checks and sandbox blockers.
