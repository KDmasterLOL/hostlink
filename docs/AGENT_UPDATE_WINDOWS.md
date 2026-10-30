# Windows Agent offline update (1C-1114)

Windows updates require a fully stopped, unregistered Agent. Live update,
maintenance mode, one-use candidate admission, automatic restart and health
handoff have been removed. The updater never changes Task Scheduler or HKCU.
An installed task (even stopped) or an old root-derived HKCU Run registration
is an error. Historical marker/VBS files alone do not block an offline update.
Remove the owned task before updating and explicitly reinstall/start it
afterwards. Existing active legacy installations require stopping and removing
their old autorun registration with the matching old executable.
Service status does not attest the installed binary SHA or probe SSH. Package
integrity is checked by this updater's exact manifest and journal verification.

The supported updater root remains the exact OS-resolved LocalAppData/HostLink/Agent
with protected owner-only ACLs on Agent and its immediate parent.
Vendored `private-fs` opens and verifies these directories without following
symlink/reparse components. Its strict Windows DACL policy is described in
[`VENDOR.md`](../Vendor/private-fs/VENDOR.md); directories use protected
owner-only `OICI` inheritance and regular files use noninheritable
owner-only ACLs. Archive staging files are created privately at birth,
the recovery journal uses the crate's durable atomic publication, and the
same update/runner locks remain mandatory.
Run the update command from a separate private executable beneath that root
on the same volume, not from the executable being replaced. Keep the existing
CLI syntax: `update --root ROOT --archive ZIP --sha256 SHA --target TARGET
--version VERSION`. No package lookup, implicit download or version guessing.
The archive must be beneath ROOT.

The updater holds the exclusive update lock and the existing Agent process
lifetime lock for the entire transaction. The latter is an OS file lock, not
an Apalis lock/table or a custom PID ownership record. It refuses a running
Agent and conservatively checks the installed image against the OS process
snapshot; an unreadable matching image is an error. Registration absence and
stopped state are checked again before publication. Concurrent official Agent
startup cannot acquire the runtime lock. Service install/start are serialized
against update, and foreground/logon startup rejects any pending journal.

Archive SHA-256, exact version/target, bounded ZIP structure and member digests,
installed inventory, private staging/ACLs and hardlink/reparse defenses remain.
`self_update` Extract/MoveAll remains the publication implementation. Existing
support scripts must match both old and new manifests; changing package support
files in this transaction is still unsupported and fails closed.

Before publication, the updater durably records exact old/new executable and
metadata hashes plus verified private backups under `.updates`. It reads back
the full published inventory before success. Failed publication restores and
verifies the old inventory. On interruption, retrying offline uses the journal
and hashes to finish a fully published installation, restore a partial one, or
preserve ambiguous state with an error. Recovery never starts an Agent.
Retired `RESTARTED` live-handoff journals are rejected for manual investigation;
legacy maintenance state is never silently converted. Unknown artifacts,
untrusted backups and changed metadata remain errors. Enrollment, credentials
and Apalis jobs are retained and no SQLite tables are inspected.

`service stop` delegates to Task Scheduler termination and does **not** guarantee
graceful shutdown or descendant cleanup. Interrupted Apalis commands may replay
with repeated side effects. Prefer foreground Ctrl+C when a cooperative shutdown
is required; offline update still requires task removal and stopped evidence.

Native Windows 11 and Win7 SP1 x64/x86 offline update/recovery, task logon,
termination, concurrency and rollback acceptance is **NOT RUN** for this change.
Linux tests and generic MSVC check/clippy only establish their stated evidence.
No installed Agent, real profile or production machine is a permitted test target.
