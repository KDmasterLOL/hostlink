# HostLink russh execution rewrite: staged integration and managed-fleet migration

Status date: 2026-10-26. Parent Huly: 1C-987.
Latest cross-platform runtime evidence baseline: `rewrite/russh-minimal@4bc0ef681ce23cc9fb20cd7cd668afc3879ae26c`.
Experimental development only. No changes to installed agents, HostLink dev/main/tags, legacy OneC Toolkit, gateways or 1C databases without a separate explicit cutover decision.

## Current implementation and verified acceptance (2026-10-26)

This is the current status; the A/B/C sections below document the *original*
implementation contracts, not the current missing-feature list. Do not assign
work based on their historical "current issue" wording without checking code.

| Functional gate / owner | Verified source and evidence | Remaining acceptance |
| --- | --- | --- |
| russh Agent + Client, SFTP, source-bound Seal/run, durable jobs/cancel | Present in experimental rewrite; Linux workspace fmt/check/strict Clippy/full tests PASS; real pinned SSH loopback E2E | Exact immutable final-candidate retest, Win7 native |
| Authoritative Hub v2 registry/invite/enroll/list/revoke | Hub 1C-1019 + Controller 1C-1020 + Agent bootstrap 1C-1021 integrated; actual Hub-issued identity used for nested russh gateway SSH and binary exec/SFTP; one-use invite replay rejected (1C-1011) | Real HTTPS-to-Hub/installer workflow, safe side-by-side fleet cutover/revoke, Win7 PS2 |
| Source-pinned Windows/Linux Agent installer | Verified ZIP, manifest, target/version and independent executable sidecar, private fresh root; 18 Linux update lifecycle checks PASS | Native install on Windows11/Win7 x64 and true Win7 x86 |
| User-facing TCP forwarding/RDP/probe | Current named/unmanaged CLI integrated, 4/4 Linux and 4/4 native Win11 GNU tests PASS | Win7 and exact MSVC/Win7 target acceptance |
| Agent-approved multiple reverse gateway routes | Exact pinned Agent alternate routes and fail-closed errors; 3/3 Linux and 3/3 native Win11 GNU tests PASS on 4bc0ef6 | Controller Hub multiple-gateway selector/initial-connection retry: 1C-1025 follow-up; Win7 native |
| Windows11 native GNU | 4bc0ef6: Agent russh E2E, reverse gateway, TCP forwarding and 3 multi-edge tests PASS with Rust 1.99.1 GNU | Full workspace Windows11 test receipt and native MSVC source-exact candidate |
| Windows self-update (1C-1004) | Linux package/active-jobs/rollback 18+ tests PASS; Windows staging integrity exists in task worktree | Cooperative same-owner stopped-runtime handoff, bounded restart/rollback, native verification; do NOT claim Installed while Unsupported |
| Win7 x64 + x86 (1C-1008) | Source-locked Tier 3 builder script, both PE inspections specified; bash -n and ShellCheck PASS | **No verified cross-built PE hashes or NT6.1 native smoke yet**. Never transfer prior old-dev evidence |
| Final migration/replacement (1C-1011) | Explicit side-by-side runbook and read-only legacy preflight implemented | Complete final-source acceptance, source receipts and separate release/cutover authorization |

On HOME Linux and WORK Windows the tests above used only disposable owned
fixtures. Windows GNU tests are **not** proof of the Win7/MSVC target. On the
current Agent update code, unsupported Windows publication is an intentional
safety gate, not a successful completed update. Original `dev`, `main`,
production services, releases and tags remain separate and unchanged.

## Historical evidence and original task contracts

- Verified initial rewrite is a two-crate russh Agent+Client execution milestone without legacy Agent JSONL RPC, external OpenSSH subprocess or Nextest attestation engine; a focused **Hub management crate is REQUIRED** for final fleet inventory/invite/enrollment/revocation (1C-1019/1020/1021).
- HOME Linux actual pinned Agent-to-Client TCP/SSH: short exec, binary stdin/stdout/stderr, exit 7, SFTP, authenticated durable start once, drop SSH, reattach, binary output offsets, unchanged effects, wrong-key rejection. Fmt/check/strict Clippy/tests PASS.
- WORK Windows11 clean source at rewrite/28370a5: fmt/check/strict Clippy/workspace tests PASS, including actual short exec and Agent/Client SFTP; 4b34e31 only changes Rust stable toolchain and docs. Source-exact final candidate retest is mandatory.
- Old, supported HostLink dev has actual NT6.1.7601 PS2 x64 and x86/WOW64 native SSH/exec/SFTP PASS. This is NOT proof for the rewrite.
- Rewrite c64619e produced a Windows7 x64 PE, but no current source x64+x86 hash-matched Win7 native receipts.
- Linux Agent-only updater: package version/target/SHA, private staging, shared job lock, active-job deferral and rollback tests PASS. Windows updater still explicitly refuses publication without a stopped-runtime handoff.

## A. Remote test artifact execution (priority critical)

A1. Agent-owned staging and SFTP isolation (new child).
Current issue: SFTP is rooted in jobs_root shared by ALL authorized controller keys, and open/read/write/stat/remove do not provide chmod/seal. Unix source verification refuses a writable uploaded file. A naive hostlink run command cannot function safely.
- Bind SFTP access to the server-derived authenticated key fingerprint. Stage files in private artifacts/<key-fingerprint>, as a SIBLING of jobs_root under the same user-owned install root. Never store artifact directories inside the UUID-only jobs root, because jobs::active_ids assumes every entry is a job UUID.
- Reject traversal, symlinks/reparse, cross-key access, unbounded files, overwriting a candidate, modified or partially uploaded contents, wrong SHA and unsafe owner/ACL.
- Add one bounded versioned Seal request over the EXISTING hostlink-jobs-v1 SSH subsystem. Seal checks exact SHA/length, transforms the user-owned candidate to a non-writable executable (Unix 0500 / protected Windows user ACL), returns the Agent-resolved canonical absolute path. Repeated exact seal may be idempotent; mismatches fail. No new TCP/HTTP listener.
- Preserve existing start/status/output wire schema and negative tests. Prove same user with two separate authorized keys cannot read/overwrite another key's upload.

A2. Typed Controller run (new child, based on A1 Seal contract).
- CLI run --config HOST --binary LOCAL [--id UUID] -- [typed libtest/Nextest args...] hashes a bounded regular local file, prints UUID before connecting, opens pinned SSH, uploads create-new via SFTP, seals via jobs-v1 and runs the exact server-returned path with SHA-pinned JobSpec. No shell string or guessed path.
- Lost start acknowledgement is UNKNOWN: show status/output reattach commands; never blindly resubmit. Binary stdout/stderr read by monotonic offsets, exact exit including 7 and timeout, no fabricated success.
- Owner-only cleanup of known terminal task artifacts, preserve unresolved jobs for readback. Unit protocol/error tests plus real SSH fixture with source-pinned executable, --list, disconnect, same ID without duplicate effect.

## B. Windows + Windows7 acceptance (priority release-blocking)

B1. Windows11 durable worker (existing 1C-1003).
- Private user-scoped root, exact binary SHA, protected ACL/owner, actual non-elevated/non-LocalSystem token. Start durable job with typed args, drop SSH, reattach/read logs and code, reject different key and duplicate effects.
- Overflow, agent shutdown, timeout and cancellations must kill the complete Windows Job Object process tree, not merely the direct child. Wrong hash/reparse/elevated identity refuse.
- Source SHA and disposable cleanup receipt required; Windows compile alone is NOT enough.

B2. Windows7 x64 + x86 current source (new child).
- From final source SHA compile both x86_64-win7-windows-msvc and i686-win7-windows-msvc using the separately pinned nightly, cargo-xwin, build-std and static CRT; no fallback to ordinary MSVC targets.
- Record toolchain/source/package digests, machine 0x8664/0x14c, subsystem 6.0, UCRT/VCRuntime import set, exact source identity.
- On authorized disposable NT6.1 PS2 x64 and x86/WOW64: hash-match binary, --version, config, SSH keys, binary stdin/stderr/exit7, SFTP, gateway, durable start/drop/reconnect, bounded process cleanup. Source-exact and ownership-verified TEMP cleanup.
- x86 on WOW64 is NOT direct proof of Windows7 x86 32-bit OS; distinguish it. Report BLOCKED if the required target is unavailable.

B3. Windows self-update handoff (existing 1C-1004/1C-991).
- Preflight exact version, package and installed binary digests/ACL/target/owner under the shared JobStore lock. Prepared/Running/Interrupted/unknown state defers.
- Running EXE cannot simply be overwritten: use a small separate verified updater helper, stop Agent only after no active job and correct owner, stage/publish/journal/relaunch or rollback. No Windows Service takeover and no legacy Toolkit updater.
- Windows11 and Win7 native success/recovery/failure matrices required. If handoff unproven, remain Unsupported; do not claim migration complete.

## C. Gateway, migration, completion

C1. Reverse gateway (new child).
- Disposable real SSH gateway, known Ed25519 host pins, remote loopback forwarding and nested Controller->Gateway->Agent connection.
- Port refusal/duplicate mapping, missing trust, wrong user, network interruption and reconnect/backoff. No silent fallback or public listener, tests must observe authenticated target host identity.

C2. Dry-run migration inventory (new child).
- Old HostLink Hub Controller and Agent JSON config, managed RPC tokens/keys and directory layout differ from the rewrite. Inspect only read-only and redact all secrets.
- Produce per-host compatibility report: authentication key, target host public-key pin, assigned gateway/port, executable/architecture, user-owned install root, old control consumers, target-side process owner, installer/update compatibility. Missing identity => explicit blocker, never a fabricated fallback.
- Run new Agent side-by-side with old on an isolated port and separate owned root. Demonstrate one-host new Controller success and proved fallback to old. Do not deploy or alter a live service in this issue.

Implemented locally by 1C-1010: `hostlink migration preflight` reads bounded old Hub/Controller/Agent JSON snapshots plus explicit new Agent/HostSpec files and emits a redacted static per-host report. It performs no SSH/network operations or writes. See [MIGRATION_RUNBOOK.md](MIGRATION_RUNBOOK.md) for invocation, manual side-by-side verification and rollback. A passing static report does not satisfy the disposable gateway/Windows/runtime gates above.

C3. Final source-exact release acceptance (new child).
- On one exact SHA: cargo fmt, check, strict Clippy, workspace tests on Linux and Windows11; both Win7 PE targets plus actual NT6.1 smoke; user-scope Windows durable reconnect, updater active-job deferral/rollback, SFTP seal + typed run, gateway mode and SSH reconnect; negative authorization and cleanup.
- Huly status Todo -> In Progress -> Merging -> Done only when matching SHA evidence is attached. Gate: explicit user authorization before dev promotion, main/tag/release, switching installed Agents or modifying production networks.

## D. Mandatory Hub-backed managed fleet (new, required for replacement)

- 1C-1019: restore one authoritative Hub control-plane owner: secret-free fleet inventory, canonical host identities, one-use expiring invites, fresh Agent registration and exact gateway/SSH trust projection, truthful revocation. No second Agent command transport, no legacy per-Agent JSONL control secret. Separate new state root and versioned API; do not alter currently deployed old Hub.
- 1C-1020: `hostlink list/info/verify/invite/display-name/remove`, named-host `check/exec/upload/download/run/job` through newly resolved/pinned existing russh HostSpec. Fast inventory by default; optional bounded per-host live probe with honest timestamps/status. Manual HostSpec mode stays explicit.
- 1C-1021: digest-pinned Win7/Win11/Linux user-scope bootstrap, one-use token, locally generated Ed25519 Agent identities, Hub enrollment, exact approved gateway route, private Agent configuration and side-by-side rollback. No silent adoption of running Agents.
- All Hub APIs, anti-goals, ownership and canonical caller expectations are defined in [MANAGED_FLEET_ARCHITECTURE.md](MANAGED_FLEET_ARCHITECTURE.md). No release/replacement acceptance while these mandatory features are absent. Existing 1C-1010 offline preflight is not a Hub replacement.

## Order, ownership, no conflicts

A1, B3 and B2 are independent initial Codex lanes in separate task worktrees.
A2 can begin with the frozen A1 wire contract, with Client files exclusive to its lane.
B1 native Windows tests and C1 gateway run against the combined candidate; C2 migration audit before any install; C3 release after all mandatory gates.
Codex does scoped code implementation, max three concurrent execution sessions; coordinator owns issue semantics, review, integration, test receipts and source-exact release decision.
