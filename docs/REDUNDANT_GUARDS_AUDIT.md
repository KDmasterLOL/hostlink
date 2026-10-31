# HostLink redundant-guard and library-first audit

> 1C-1147 supersedes prior updater staging, CLI and journal guarantees. See
> [the current updater contract](SELF_UPDATE_REWRITE.md); historical evidence below
> does not attest this source revision.

> 1C-1114 supersedes the historical Windows maintenance/live-handoff details below:
> Windows now uses a current-user Task Scheduler logon task and offline stopped-only
> update after task removal. See [lifecycle](AGENT_LIFECYCLE.md) and
> [updater](AGENT_UPDATE_WINDOWS.md). Native Win7/11 acceptance remains NOT RUN.

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

## Follow-up: 1C-1102 (2026-10-29) — implemented

Every P2/P3 candidate below has been replaced with an existing library or
standard library feature, preserving the remaining trust-boundary checks:

| Area | Change | Remaining invariant |
| --- | --- | --- |
| Windows Agent exec, enrollment and service | One `private_fs::windows::is_non_elevated_user` using `windows-permissions` SID and `std::os::windows::io::OwnedHandle` for the token; removed three separate token/elevation implementations and unsafe `TOKEN_USER` buffer decoding | SYSTEM or elevated users are rejected; Windows token errors propagate rather than permitting execution |
| Agent updater + Hub state + authorized_keys projection | Same-directory `tempfile::NamedTempFile` replaces PID/nonce-generated names and manual temporary-file cleanup | Still sync the written file and parent directory; preserve Hub uncertain-commit readback; retain private directory/file ownership checks |
| Client `list --check` | `futures::stream::buffer_unordered(4)` replaces `JoinSet` + `Semaphore` and spawns no per-host tasks | At most four simultaneous checks, same per-host timeout and status classification, stable sorted output |
| Client Hub config | `HubClient::from_file` returns parsed config and its single constructed client | The public `read_config` and `from_config` boundaries remain independently validated |
| Windows updater file identity | `std::os::windows::fs::OpenOptionsExt` replaces custom UTF-16 `CreateFileW` and handle-drop code | Explicit access/share/reparse/backup flags and file-index identity checks preserved |
| SHA-256 | `std::io::copy` writes directly into the `digest`-provided `Write` impl for SHA-256 | Streamed hashing and size limits remain in place |
| Windows rollback planner | Removed duplicate `BackedUp → CancelUnpublished` match branch with identical result | Other journal transitions and evidence validation unchanged |

This follow-up adds a direct Hub temporary-file cleanup/private-mode
assertion, Linux updater idempotent-publication cleanup test and a
Windows-only file/directory identity regression. The last test compiles for
both Windows architectures; its runtime check still requires native Windows.

The Hub's `tempfile` dependency is optional under `server`; Client's
`futures` was already used elsewhere in the workspace. We did **not**
replace persistent journals, recorded backups or updater transaction locks
with temporary objects.

## Remaining work and testing caveats

* Native Windows 11 and Windows 7 (x64 and x86) execution still must
  validate token/elevation handling, protected DACLs, directory identity,
  authentication and installed-Agent update/recovery in a disposable user
  profile. Cross-compilation and strict Clippy cannot prove Win32 runtime.
* Linux installed-Agent update admission still assumes the enrolled
  `install_root/jobs/runner.lock` identity; arbitrary custom jobs roots
  require explicit acceptance before deployment.
* Windows identity opening now uses standard Rust handle construction; its
  `FILE_READ_ATTRIBUTES | SYNCHRONIZE`, sharing and
  `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` flags match
  the previous native call, but must be tested live on NT6.1.
* There may be further simplification opportunities, but no remaining
  P2/P3 candidate in the earlier list is left unimplemented.

## Guarantees that are not redundant

* **SSH host-key pinning, Ed25519 operator authorization, trusted enrollment
  origin and browser Host/Origin checks:** libraries parse/transport keys; they
  do not determine which remote party is trusted. The local Board can execute
  arbitrary commands with Agent privileges.
* **ProcessKit cancellation, containment and bounded worker concurrency:**
  Apalis schedules jobs but does not contain the OS child process tree.
* **Agent package identity and safe extraction:** the 2026-10-31 1C-1149
  reduction removed the bespoke ZIP central parser. The patched `zip` crate
  handles header consistency, while the pinned archive digest, required-file
  inventory and post-extraction identity validation protect installation.
* **Updater SHA/target/installed-inventory verification, stopped-runtime
  locks and exact Windows task XML/image checks:** `self_update` handles the
  bundle swap and in-process rollback, but does not stop the Agent or manage
  Scheduler registrations. Durable crash recovery was explicitly retired in
  1C-1147; automatic restart is not part of the updater.
* **Hub JSON state writer lock / commit admission:** concurrency and cancelled
  HTTP request futures must not lose or duplicate authoritative invitations,
  enrollments or revocations. SQLite queue locks cannot replace these.
* **Reverse SSH reconnect policy:** `russh` supplies the SSH transport but
  not HostLink's gateway rotation, permanent key/auth failure boundary or
  transient-backoff behavior.

## Acceptance boundaries

Historical evidence before 1C-1114 on the earlier isolated integration branch:

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
