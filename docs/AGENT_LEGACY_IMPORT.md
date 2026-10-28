# Legacy snapshot staging (1C-1075): publication BLOCKED

This is the non-destructive inspector/staging fallback, **not a completed
cutover importer**. Existing installations remain unmigrated. It is an explicit
operator CLI only; Agent startup, enrollment, updater and WorkerBuilder never
call it. No new dependencies, service commands, process execution or network
operations are used.

## Scope and invocation

Use a separately obtained, complete **offline private copy**, not an installed
Agent's live jobs directory. Retain the original install, configuration, binary,
artifacts and jobs as the only authoritative source. Obtaining that copy and
proving the original process is stopped are outside this command. This task
does not authorize stopping or modifying any installed Agent.

The copied parent must be private and contain the copied original `update.lock`
and `jobs/`. The separate stage parent must already exist and be private. Use
absolute paths without links, junctions, parent traversal or unverified aliases.
On Windows ordinary drive-letter and verbatim paths are accepted after ancestor
reparse checks; source/stage overlap is compared using canonical paths.
Windows execution is not yet validated.

```text
hostlink-agent durable import-legacy --root /private/snapshot/jobs --stage /private/stages/import-1075
```

The command **always exits 1**. On a fully verified candidate its diagnostic
says `verified snapshot stage ...; publication blocked` and explains the
missing cutover fence. Other diagnostics mean preparation/verification failed.
No successful migration result is emitted. Do not change Agent configuration
to either the stage or its `store/` child. Do not rename/copy the staged DB
into an install, change its schema version, or remove the quarantine.

## Validation and retained data

The legacy reader is pinned to
`4570a45c5ba53f5440a8265906393cbcf629c033:crates/agent/src/jobs/`:
`model.rs`, `store.rs`, `output.rs`, `private_fs.rs`, `mod.rs`, `tests.rs`.
It validates schema 1, canonical lowercase UUID directory and record identity,
private owner UID/SID/DACL, regular files, no symlinks/reparse ancestors or
hardlinks, lowercase owner digest, spec validation and exact serialized-spec
request SHA. An owner fingerprint is preserved and checked for format and
identity; legacy JSON contains no signature proving that controller's trust.
Trusted offline snapshot provenance remains an operator prerequisite.

Unknown entries, torn/oversized records and output, missing Exited spools,
unsafe paths and mixed legacy/new layouts are rejected. Limits are 4096 jobs,
64 KiB per record, 8 MiB per stream, and 512 MiB total record/output snapshot
bytes. The staging bound deliberately refuses larger archives without deleting
or truncating them. There is no override that bypasses validation.

Only existing source `update.lock` and any existing per-job `state.lock` are
opened and locked nonblocking. Missing state locks are valid for an old
Prepared record; none are created. Contention refuses staging. A `runner.lock`
is probed and then always rejected as a non-legacy layout. Source files and
their permissions are never rewritten, hardened, renamed or deleted. As with
ordinary reads, filesystem access-time accounting may occur.

The separate stage holds `import.json`, `stage.lock`, `store/`, and completion
markers `built`/`verified`. The journal records the pinned legacy SHA, full
snapshot digest, count, `publication: blocked` and the blocker. In `store/`:

- Real Apalis public migrations create `jobs.db`; SQLx connections require
  WAL and FULL. Tasks enter through the real `SqliteStorage` sink. No setup
  routine that disables synchronous is used.
- `DurableMeta.version = -1075` quarantines the DB **before the first imported
  task**. Normal `DurableStore::open` refuses it. This is not a runtime schema.
- Each UUID preserves owner, exact spec/source SHA and request SHA. Old
  Prepared/Running/Interrupted become Interrupted UNKNOWN, `Killed` in Apalis.
  Exited preserves its actual signed exit code and becomes `Done`; Failed
  stays Failed. All tasks have one allowed attempt and attempts sealed to 1.
- `LegacyImportSources` is a tombstone for every UUID. It retains the complete
  original JSON bytes (including whitespace), record SHA, and the exact
  presence, length and SHA of both raw output streams. No source data is erased.
- Only original Running/Exited establish a prior process reservation and get
  StartedClaims. Failed/Interrupted cannot establish whether execution occurred;
  their tombstones preserve that uncertainty without inventing a process claim.
  Failed can have zero, one or two spools; missing streams remain missing.
- Existing spools copy as raw binary bytes. There is no text decoding,
  concatenation or offset translation. Exited requires both spools. Readback
  checks full records, claims per UUID, original bytes/digests, absent streams,
  output lengths/SHA, terminal queue sealing, migration checksums, SQLite
  integrity and foreign keys. Production record/output inventory is reused.
  Source inventory is repeated to detect observed changes.

## Restart, failure and recovery policy

Directory creation reserves a new stage exclusively; an existing stage is
never overwritten. The stage lease excludes concurrent verification/writers.
Source and stage locks are not acquired in a blocking wait.

`built` is synced after all copied streams and SQLite commits/connection close;
`verified` is synced only after readback and source recheck. A retry after a lost
CLI acknowledgement fully revalidates a completed stage against the source,
including the quarantine, without inserting tasks again. Partial/missing/torn
journals or completion markers are refused and preserved. Do not delete an
incomplete stage to make a retry succeed: retain it for diagnosis and choose a
different new stage path against a trustworthy unchanged copy. ENOSPC and sync
errors propagate; they never authorize publication. There is no automatic
cleanup, publication, backup rotation, restore or resume of an uncertain write.
Crash-boundary tests construct interrupted durable states; they do not certify
physical power-loss behavior or Windows directory-flush durability.

## Why publication and rollback are blocked

In the pinned old Agent, `JobStore::admit`/`recover_nonterminal` hold
`update.lock`, while `transition` holds `state.lock` only during record
replacement. Neither is a lifetime runner lease. A previously started OS
process can continue writing spools while an importer holds every available
lock. Even two equal source scans cannot prove quiescence. New `runner.lock`
does not fence an old binary that never opens it.

This bounded implementation therefore cannot prove exclusive ownership of an
installed legacy root or safely coordinate its service/configuration and
rollback to the old executable. It never renames an authoritative root, so no
mixed authoritative state is created and the original remains intact. The
new runtime refuses the original legacy layout and the staged quarantine.
There is no claim that old-Agent rollback has been made safe after cutover:
**cutover never happens**. A future publication implementation needs an
independently verified offline process/service fence, durable backup/journal
recovery, trusted install identity and a forward-only old-binary admission
fence, plus Linux/Windows native acceptance. Do not simulate that proof by
removing records, changing IDs or reporting fresh-root tests as migration.

Windows 11 and source-exact NT6.1 acceptance remain separate, unexecuted gates.
