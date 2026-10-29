# HostLink redundant-guard and library-first audit

Review: 2026-10-29. Scope: Agent, Client, Hub, tests and installation/update
contracts. Development work only; no deployed Agent, Hub, customer host, or
production data was modified. Root instructions: [AGENTS.md](../AGENTS.md).

## Rule for deletion

Remove HostLink code when an already-used library or a single typed boundary
owns the same invariant. Preserve validations that protect a different trust
boundary, process lifecycle, installer source identity, or crash recovery.
A reduction in line count alone is not evidence of correctness.

## Implemented in this change

| Previously redundant | Simplification and remaining invariant |
| --- | --- |
| `agent/jobs/database.rs`: private SQL scans, `DurableMeta`, migration-ledger checksum reimplementation, WAL/SHM sweeps, repeated PRAGMA and directory validation | SQLx creates/opens one pool; only **fresh enrollment** runs upstream `SqliteStorage::migrations()`. Existing stores are not created or rewritten on open. SQLite still uses WAL and `synchronous=FULL`. |
| `agent/jobs/store.rs::active_ids`: direct SQL against Apalis's `Jobs` table, synchronous thread/runtime bridge and dependencies in service/updater | Deleted. Apalis alone owns task statuses and retry policy. Queued tasks persist; cancellation may replay previously started commands. |
| `jobs/worker.rs` extra worker lock and update lock coupled to jobs | Agent SSH/jobs/tunnel supervisor owns one process-lifetime `jobs/runner.lock`, used by the Linux updater to require the process stopped. `install_root/update.lock` belongs solely to the updater, serializing publication/recovery. Both are **OS process** locks, not extra SQLite locks. |
| Duplicate enrollment manifest structs; Linux service expected a different schema from enrollment's producer | Shared `EnrollmentManifest` + `EnrollmentIdentity` typed Serde in Agent enrollment, consumed by Linux and Windows service. Still compare identity, allowlisted file names and SHA-256 contents. |
| Three Agent config loaders manually resolved only primary gateway paths; Client loader omitted alternate identity | One `AgentConfig::resolve_relative_paths` handles primary and all alternates. Client loader also resolves alternate identities. |
| Client bootstrap's custom SemVer grammar | Existing workspace `semver::Version::parse`; accepts prerelease/build and rejects integer overflow consistently with Agent. |
| Duplicate base64/algorithm parsers for OpenSSH pins in Client connect/migration | `russh::keys::PublicKey::from_openssh`; keep single-line boundary and byte-exact SSH host key pin. |
| SSH host-key input read twice; Hub info validated each gateway twice; enrollment validated Ed25519 keys before canonical parser; Hub reparsed typed MachineId | One validation per typed boundary. Distinct-source input validation and authentication retained. |

The updater no longer checks whether `jobs.db` exists: it knows only whether
the **process** has stopped. It never creates, deletes or migrates Apalis data.
This has a deliberate consequence on Linux: an updater can publish a correct
binary while an independently missing/corrupt Apalis store causes a subsequent
Agent startup error. Windows managed updates additionally require authenticated
health after restart. Do not describe Linux package publication as proof of
runtime health.

## Further opportunities, not implemented

| Priority | Source | Library-first / smaller approach | Why separate |
| --- | --- | --- | --- |
| P2 | `agent/exec.rs`, `agent/enrollment/platform.rs`, `agent/service/windows/private_fs.rs` | Consolidate duplicate Windows current-user/SYSTEM/elevation checks using existing `windows-permissions` SID APIs. | Requires native Windows token/ACL tests, including NT6.1. Do not remove owner or elevation restrictions. |
| P2 | `agent/update/private_fs.rs`, `hub/state.rs`, `hub/ssh_authorization.rs` | Use same-directory `tempfile::NamedTempFile` instead of custom PID-named temporary publishers and manual naming/cleanup. | Must preserve file and directory fsync, private ACL and recovery-on-error semantics. |
| P2 | `client/hub/client.rs::read_config` and `cli/commands/hub.rs::configured_hub_client` | Avoid creating/dropping a reqwest client, reading secrets, and then constructing another client. | Public `from_config` remains an independent validated entrypoint. |
| P2 | `client/cli/commands/hosts.rs` | Replace `JoinSet` + `Arc<Semaphore>` per inventory entry with `futures::stream::buffer_unordered(4)` (existing workspace crate). | Preserve per-host timeouts, all status results and stable sorted output. |
| P3 | `agent/update/windows/fs.rs` | Use `std::os::windows::fs::OpenOptionsExt` + `File` rather than manual CreateFileW handle machinery for opening a directory. | Preserve share, backup-semantics, reparse and file identity flags; native Windows tests needed. |
| P3 | `agent/update/private_fs.rs` | Investigate replacing small `HashWriter` adapter with standard digest I/O facilities, if type-level contract matches. | Must match streamed hash and length checks. |
| P3 | `agent/update_handoff/recovery.rs` | Remove duplicate branch producing the same recovery action after confirming truth table. | Journal state transitions must retain error and power-loss recovery cases. |

## Guarantees that are not redundant

* **SSH host-key pinning, Ed25519 operator authorization, trusted enrollment
  origin and browser Host/Origin checks:** libraries parse/transport keys; they
  do not determine which remote party is trusted. The local Board can execute
  arbitrary commands with Agent privileges.
* **ProcessKit cancellation, containment and bounded worker concurrency:**
  Apalis schedules jobs but does not contain the OS child process tree.
* **Raw ZIP central-directory and duplicate-entry validation:**
  `agent/update/archive/zip_index.rs` protects against contradictory package
  identities that are not safely represented by a filename-keyed map.
* **Updater SHA/target/installed-inventory verification, journal, rollback,
  maintenance one-use admission and Windows PID/SID/image checks:**
  `self_update::MoveAll` does not provide crash-durable multi-file
  publication or an authenticated restart.
* **Hub JSON state writer lock / commit admission:** concurrency and cancelled
  HTTP request futures must not lose or duplicate authoritative invitations,
  enrollments or revocations. SQLite queue locks cannot replace these.
* **Reverse SSH reconnect policy:** `russh` supplies the SSH transport but
  not HostLink's gateway rotation, permanent key/auth failure boundary or
  transient-backoff behavior.

## Acceptance boundaries

Verified on the isolated integration branch before merging to dev:

* `cargo fmt --all -- --check` — PASS.
* `cargo check --offline --locked --workspace --all-targets` — PASS.
* `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` — PASS.
* `cargo test --offline --locked --workspace -- --test-threads=1` — PASS,
  including 41 Agent unit, 27 updater, 18 Hub tests and Client/SSH/SFTP.
* `cargo xwin check` and `cargo xwin clippy -- -D warnings` for Agent
  `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` — PASS.

Cross-compilation does **not** prove Windows ACL, HKCU, process-handle or
Windows 7 runtime behavior. The native disposable-profile Windows lifecycle
fixture and two optional external Caddy/OpenSSH HTTPS E2E fixtures remain
out of scope. Installed-Agent updates and v4 data migration have not been
authorized or exercised; no live migration or release should be claimed.

The Linux updater currently expects an enrolled `install_root/jobs`
layout for its process-lifetime lock, which fresh enrollment supplies.
Manually configured nonstandard `jobs_root` values have not been accepted
as safe update targets; managed update acceptance must verify the exact
lock path and ownership before deploying this policy.
