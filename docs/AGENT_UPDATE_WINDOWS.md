# Windows Agent stopped-runtime updater

## Current implementation status

`update::apply` supports only an offline, stopped-Agent transaction launched by
a separate updater executable. The caller must not be the installed EXE, the
current-user lifecycle marker must be absent, and process enumeration must prove
that no process is running the installed image. Active durable jobs defer before
publication. No Agent restart is required or attempted in this unregistered
case. This does not support updates from a live Agent or a registered service.

The offline transaction stages the verified executable and new metadata plus
private old executable/metadata backups under `.updates` on the install volume.
It flushes the journal file and commits each journal rename with
`MoveFileExW(MOVEFILE_WRITE_THROUGH)` before publication, uses `ReplaceFileW` with zero
flags so ACL merging must succeed, advances the journal after each replacement,
and verifies the installed metadata and complete inventory hashes before
returning `Installed`. On an in-process publication or readback error it restores
the verified backups and verifies the old bytes. Before a subsequent update stages
a new archive, it runs bounded recovery under the shared update lock after job,
service, and caller preflight. An unpublished transaction is discarded only when
installed files and both backups match the recorded old identities. A partially
published or rolling-back transaction is restored from verified backups. A fully
published transaction is committed only after exact metadata and the complete
installed manifest are revalidated. Unknown or damaged state preserves the
journal and candidates and returns an error. Startup still refuses an unresolved
journal; recovery is performed only by a separately invoked offline updater.
The Windows transaction currently requires packaged PowerShell support files to
match the installed copies byte-for-byte; packages that change them are rejected
before publication.

The user-scope lifecycle owner now exists in `service.rs`: its private marker
binds the current SID, install root, executable digest, named pipe, and login
registration. Its `stop` path authenticates the owner pipe, verifies the
reported process SID, image path and SHA, requests cooperative stop, waits on
the actual process handle, and rechecks durable jobs. That API has not yet been
bound to an updater transaction or tested in an update-specific disposable
Windows profile. The update path rejects a root while this lifecycle marker is
present.

`update_handoff.rs` adds a persisted transaction substrate: a deterministic
transaction hash over old/new target, version, package, executable and metadata
digests; atomic bounded journal writes; strict readback; exact file-hash evidence
for staged, installed and backup executable plus metadata; and a side-effect-free
recovery planner. Readback recomputes the transaction hash so edited journal
identities are rejected. The journal parent must be a private, current-user-owned,
non-reparse directory validated by its caller.

Windows service start and managed login now refuse to launch when
`.updates/handoff.json` exists or is malformed. Windows update preflight also
refuses such a journal. This prevents login startup from bypassing maintenance
after an interrupted transaction. The offline transaction itself creates,
advances, reads back, and removes the journal around the actual file changes.

## Current implementation boundary

`service.rs` now owns a crate-private maintenance receipt and coordinator
primitives. The caller must hold the existing `jobs::acquire_update_lock` for
the full transaction. Entry verifies the current SID/root, marker, exact Run
command, executable digest, and durable job state, then records maintenance in
the owner marker. Managed login startup refuses that marker before it can start
a listener. The exact current-user Run value is removed, the Agent is asked to
stop over its owner-authenticated pipe, and the updater waits on the verified
process handle. No PID is accepted from an argument and no process is
force-terminated.

The opaque receipt supports updating only the marker executable digest after
the coordinator has verified the new file, restoring the exact Run command
after marker/file readback, and restoring the old marker and registration only
when the old executable digest is present. The marker retains the prior digest
across interruption, so a later coordinator can restore old registration only
after observing those exact old bytes. These primitives do not launch or
health-check an Agent; the coordinator must keep the update journal and lock
authoritative, then use the existing authenticated `service::start` before
reporting success. If restart fails, it must re-enter maintenance, restore and
verify the old file inventory, then restore the old marker/Run entry. Foreign
Run values and ambiguous marker states fail closed.

This does not enable a registered-service `update::apply` path. The disposable
Windows lifecycle test remains ignored and requires the documented separately
verified standard-user profile harness. Marker checks and cross-target builds
do not prove actual HKCU, process-handle, concurrent login, restart, or rollback
behavior. No native maintenance transaction was run in the current profile.

## Required helper protocol

The installed executable cannot replace its own loaded image. The updater must
be a separate, private, verified process on the install volume. It must use the
existing owner-bound stop path and shared job lock, prove that no durable job
is Prepared, Running, Interrupted, corrupt, or unknown, and wait for the
authenticated Agent process handle to signal before publication. Reconnect
must never replay a started job.

The managed-live helper must validate archive SHA, target, semantic version, complete
manifest and old installed inventory before mutation. It must durably record
`STAGED`, `BACKED_UP`, `PUBLISHED`, `VERIFIED`, and `RESTARTED`, with exact old
and new package, executable and metadata identities. Every journal transition
must be atomic and recoverable; transaction IDs must be recomputed from the
validated journal contents. It must verify the backup before publication,
verify the full new installed inventory before restart, and verify the new
Agent's authenticated lifecycle response before reporting `Installed`. A
failed publication or bounded restart must restore and verify the old
executable and metadata. Ambiguous states preserve all candidates and the
journal and return an error.

The recovery planner maps validated journal phases plus observed old/new/backup
executable and metadata hashes to one action. File-level tests exercise exact
hash observations and fail-closed recovery decisions, but the planner must not
be treated as having performed filesystem publication. Active, interrupted,
unreadable, or unknown durable jobs must defer
before staging, journal recovery, or publication. The update lock must remain
held across the full operation and startup must not race login registration.

## Windows filesystem and wait constraints

Microsoft documents that [`ReplaceFile`](https://learn.microsoft.com/en-us/windows/win32/fileio/moving-and-replacing-files)
can create a backup and preserve original attributes including ACLs, and that
the source file must be closed before copy or move. `WaitForSingleObject` can
wait on a process handle with `SYNCHRONIZE` and is supported by Windows 7
([Microsoft API reference](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)).
Do not infer process exit from a missing pipe. A plain new-file rename inherits
security from the destination directory only when creating a new file, so
preserving the installed executable's ACL must be explicit; see Microsoft's
[file security guidance](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).
Reject reparse points in the root, stage, backup, metadata, and journal paths.
The staged executable and backup must be on the same volume as the installed
binary. Reboot-delayed replacement, admin/SYSTEM elevation, guessed PID
termination, and a second execution transport are forbidden.

## Acceptance still required

Run source-exact, disposable-profile tests on Windows 11 and Windows 7 x64 and
x86 separately. The tests must cover owner/SID/path/hash mismatch, foreign or
stale PID, active/Interrupted/unknown jobs with no preceding mutation, reparse
paths, backup hash mismatch, locked file, every journal transition and crash
recovery, failed restart and rollback, idempotent recovery, and no login
auto-run race or job replay. Windows update tests must never use the real WORK
profile or an installed service. Cross-compilation and Linux recovery-planner
tests do not prove Windows publication behavior.
