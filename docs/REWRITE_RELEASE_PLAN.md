# HostLink russh execution rewrite: staged integration and managed-fleet migration

> 1C-1164 supersedes historical ZIP/installer/release-manifest guarantees below.
> The binary-only contract is [GitHub Releases](GITHUB_RELEASES.md) and
> [installation](AGENT_INSTALLATION.md). Keep private `state/manifest.json`.
> Historical test counts do not validate this source or native raw installation.

> 1C-1147 supersedes prior updater staging, CLI and journal guarantees. See
> [the current updater contract](SELF_UPDATE_REWRITE.md); historical evidence below
> does not attest this source revision.

> 1C-1114 supersedes the historical Windows maintenance/live-handoff details below:
> Windows now uses a current-user Task Scheduler logon task and offline stopped-only
> update after task removal. See [lifecycle](AGENT_LIFECYCLE.md) and
> [updater](AGENT_UPDATE_WINDOWS.md). Native Win7/11 acceptance remains NOT RUN.

Status date: 2026-10-27. Parent Huly: 1C-987.
Code-verified source SHA: `37fd3663f91dad0ceefd933862a4ec595e4765ce`.
The source at this SHA is authorized for development integration into HostLink `dev`
for testing. This document's commit is documentation-only and has a different SHA;
it does not identify a separately tested executable. Main, tags, releases, deployment,
installed agents, gateways and 1C databases remain outside this authorization.

## Historical implementation and evidence (2026-10-27, superseded for Windows)

The workspace has three crates: Agent, Client and the required HostLink Hub.
The table records implementation and the source-exact evidence available for
`37fd366`; implementation status does not by itself satisfy release acceptance.

| Functional gate / owner | Verified source and evidence | Remaining acceptance |
| --- | --- | --- |
| Required russh Agent/Client and Hub v2 management architecture | Three-crate workspace: Agent, Client and required Hub; `russh`/`russh-sftp` remain the only Agent/Controller execution and transfer carrier | Full release and cutover acceptance remains separate |
| Agent-only updater (1C-1004) | Linux updater tests 23/23 plus recovery tests 4/4 PASS. Windows 11 native unit tests 9/9 PASS with strict Clippy. Windows ZIP updater uses `self_update 1.3.1` Extract/MoveAll, private crash recovery and one-use maintenance-candidate admission | Windows 11 registered/live update, authenticated health and rollback have not been run end-to-end |
| Windows 7 runtime and bootstrap | On real NT6.1.7601 x64, Agent+Client `--version` on x64 and x86 under WOW64: 4/4 PASS. ZIP bootstrap x64/x86: 2/2 PASS | Native 32-bit Windows 7 OS has not been tested. WOW64 is not a substitute |
| Windows 7 maintenance/update primitives | On each x64 and x86-WOW64 architecture: native maintenance 6/6 plus MoveAll/recovery/ACL 3/3, 9/9 PASS | Full registered/live Agent update and health/rollback not run on either architecture |
| Original OneC Agent and OneC Toolkit | Confirmed untouched by this task | No old Agent, Toolkit, production service, gateway or database was changed |
| Release/cutover | Not performed; this task prepares only a documentation commit for controlled dev testing integration | Independent tests and coordinator fast-forward to dev; main/tags/release/deployment need separate explicit authorization |

These receipts are source-exact for code SHA `37fd3663f91dad0ceefd933862a4ec595e4765ce`.
They do not assert native outcomes for the later documentation commit SHA, which changes
no Rust source. They do not establish full release acceptance, native 32-bit Windows 7
support, or a successful registered/live update. Do not transfer old OneC Agent evidence.

## Historical evidence and original task contracts

The following dated records describe earlier source snapshots and are not current status.
Sections A, B and D retain their original implementation requirements; check the
current table and source before treating any historical issue wording as open work.

- The initial rewrite was a two-crate russh Agent+Client execution milestone without legacy Agent JSONL RPC, external OpenSSH subprocess or Nextest attestation engine; a focused **Hub management crate was REQUIRED** for final fleet inventory/invite/enrollment/revocation (1C-1019/1020/1021). That Hub is now integrated.
- HOME Linux actual pinned Agent-to-Client TCP/SSH: short exec, binary stdin/stdout/stderr, exit 7, SFTP, authenticated durable start once, drop SSH, reattach, binary output offsets, unchanged effects, wrong-key rejection. Fmt/check/strict Clippy/tests PASS.
- WORK Windows11 clean source at rewrite/28370a5: fmt/check/strict Clippy/workspace tests PASS, including actual short exec and Agent/Client SFTP; 4b34e31 only changes Rust stable toolchain and docs. Source-exact final candidate retest is mandatory.
- Old, supported HostLink dev has actual NT6.1.7601 PS2 x64 and x86/WOW64 native SSH/exec/SFTP PASS. This is NOT proof for the rewrite.
- Rewrite c64619e produced a Windows7 x64 PE, but no current source x64+x86 hash-matched Win7 native receipts.
- Historical Linux updater evidence and Windows pre-handoff status refer to earlier snapshots; current Windows updater status is in the table above.

## A. Remote test artifact execution (priority critical)

A1. Agent-owned staging and SFTP isolation are implemented in the current
[jobs contract](AGENT_MINIMAL_JOBS.md): private per-controller artifacts beside
the SQLite jobs root, bounded create-new uploads, exact SHA/size sealing,
read-only executables, and strict owner/path/ACL checks over the existing SSH
transport. The breaking subsystem is `hostlink-jobs`; there is no v1 adapter.

A2. The single Controller flow is `hostlink jobs run --binary LOCAL
[--id ULID] [--wait] --config HOST -- [argv...]`. It prints the canonical ULID
before connecting, uploads/seals/enqueues, and returns admission promptly.
`--wait` reads raw offset-based output and returns the process code. A lost ACK
requires status lookup; no automatic start resend. See the
[current evidence](AGENT_MINIMAL_JOBS_EVIDENCE.md) for executed core/SSH tests
and remaining TCP/native Windows gates. Artifact cleanup policy and broader
native/Nextest evidence remain separate work.

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
- Preflight exact version, package and installed binary digests/ACL/target/owner under the shared durable admission/update lock. Prepared/Running/Interrupted/unknown state defers.
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
- Huly status Todo -> In Progress -> Merging -> Done only when matching SHA evidence is attached. Dev testing integration is explicitly authorized for this task. Main/tag/release promotion, switching installed Agents and modifying production networks require separate explicit authorization.

## D. Mandatory Hub-backed managed fleet (original implementation contract)

- 1C-1019: restore one authoritative Hub control-plane owner: secret-free fleet inventory, canonical host identities, one-use expiring invites, fresh Agent registration and exact gateway/SSH trust projection, truthful revocation. No second Agent command transport, no legacy per-Agent JSONL control secret. Separate new state root and versioned API; do not alter currently deployed old Hub.
- 1C-1020: `hostlink list/info/verify/invite/display-name/remove`, named-host `check/exec/upload/download/run/job` through newly resolved/pinned existing russh HostSpec. Fast inventory by default; optional bounded per-host live probe with honest timestamps/status. Manual HostSpec mode stays explicit.
- 1C-1021: digest-pinned Win7/Win11/Linux user-scope bootstrap, one-use token, locally generated Ed25519 Agent identities, Hub enrollment, exact approved gateway route, private Agent configuration and side-by-side rollback. No silent adoption of running Agents.
- Hub APIs, anti-goals, ownership and canonical caller expectations are described in [MANAGED_FLEET_ARCHITECTURE.md](MANAGED_FLEET_ARCHITECTURE.md). The required Hub crate and Hub v2 registry are now integrated; full release/replacement acceptance remains subject to the current evidence table and source-exact release gates. The 1C-1010 offline preflight is not a Hub replacement.

## Order, ownership, no conflicts

A1, B3 and B2 are independent initial Codex lanes in separate task worktrees.
A2 can begin with the frozen A1 wire contract, with Client files exclusive to its lane.
B1 native Windows tests and C1 gateway run against the combined candidate; C2 migration audit before any install; C3 release after all mandatory gates.
Codex does scoped code implementation, max three concurrent execution sessions; coordinator owns issue semantics, review, integration, test receipts and source-exact release decision.
