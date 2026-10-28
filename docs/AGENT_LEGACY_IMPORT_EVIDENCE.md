# 1C-1075 snapshot staging evidence — cutover NOT IMPLEMENTED

Date: 2026-10-28. Branch: `task/1c-1075-legacy-cutover`.
Verified clean starting HEAD:
`ea17116c6551a1ccab80452f28773d3eafd3662f`
(`task/1c-1073-apalis-production` baseline).
Pinned old source: `4570a45c5ba53f5440a8265906393cbcf629c033`.
Compiler: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.

## Delivered scope

Explicit copied-snapshot inspector plus real Apalis SQLite/output staging,
permanent runtime quarantine, immutable original JSON/spool manifests,
state mapping and per-UUID claim verification, idempotent completed-stage
readback and fail-closed partial stages. There is no publication function,
installed-root swap, service action or runtime legacy backend. The command
always returns nonzero. See [the runbook](AGENT_LEGACY_IMPORT.md).

The complete 1C-1075 cutover objective is **not achieved**. The old Agent's
update/state locks cannot establish process/output quiescence; no old-binary
rollback/admission fence has been verified. The user-authorized fallback is
therefore delivered instead of a falsely successful importer. Two equal source
inventories are observation checks, not proof that a legacy Agent is stopped.

## Executed checks

Cached offline dependencies; build products in `/tmp/hostlink-1c1075-target`.
No manifest or lockfile dependency changes.

| Check | Actual result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |
| `cargo check --offline --locked --workspace --all-targets` | PASS |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked -p hostlink-agent --lib durable::legacy_import` | 10 PASS |
| `cargo test --offline --locked -p hostlink-agent --lib durable::` | 31 PASS, includes the 10 above |
| `cargo test --offline --locked -p hostlink-agent --test legacy_import_cli` | 1 PASS, actual binary, two invocations, exit 1 with blocked-publication diagnostic |
| `RUST_TEST_THREADS=2 cargo test --offline --locked --workspace --all-targets -q` outside delegated sandbox | PASS, 0 failures, 2 intentionally ignored |
| Existing updater / Linux lifecycle integration in full run | 26 / 2 PASS on disposable fixtures; no installed services changed |
| `cargo check --offline --locked -p hostlink-agent --all-targets --target x86_64-pc-windows-msvc` | BLOCKED in dependency C build: `lib.exe` absent; not a Windows compile PASS |
| WORK Windows 11 GNU, `ce9963b74278f8ae0b89f1ed926023fe685cc071`: fmt, workspace all-targets check, strict Clippy | PASS |
| WORK Windows 11 GNU, same SHA: `cargo test -p hostlink-agent --lib durable::legacy_import` | 10/10 PASS |
| WORK Windows 11 GNU, same SHA: `cargo test -p hostlink-agent --test legacy_import_cli` | 1/1 PASS; CLI correctly refuses publication |
| Independent read-only review | Per-UUID claim-presence finding fixed and regression tested; follow-up found no further blocking staging findings |

New tests cover every old state, signed nonzero exit, exact original JSON,
all-byte binary streams across 24 KiB chunks and offset/EOF bounds, Failed with
zero/one/two spools, foreign-controller access rejection, malformed schema/UUID/
digest/spec, duplicate canonical UUID aliases, missing Exited output, oversized
output, unknown entries, permissions, symlinks/ancestor links/hardlinks/FIFO,
update/state/runner/stage lock contention, complete-stage lost-ACK retries,
interrupted reservation/journal/database/sink/build/verification boundaries,
and readback corruption of output, claims, tombstones, attempt budget,
quarantine and journal. No mock execution/store functions were introduced.

Windows 11 GNU staging branch now passed native fixture tests for private paths
and raw outputs. It does not cover installed-root cutover or true NT6.1.
Foreign filesystem UID ownership was not
fabricated in Linux fixtures; public permissions and foreign controller digests
are tested separately. Fault-boundary construction is not hardware power-loss
proof. Actual disk exhaustion, source-exact NT6.1 execution,
installed-root cutover/recovery and old-Agent rollback remain NOT RUN.

The delegated sandbox's earlier full run suffered loopback `EPERM` errors;
the independent HOME run outside that sandbox completed successfully with two
test threads. An initial unrestricted HOME run had one intermittent SSH
overflow-termination timeout; two dedicated SSH reruns passed, followed by
the successful full workspace run above. This does not prove a deterministic
timing guarantee under unlimited parallel load.
Logs: `/tmp/hostlink-1c1075-{check,clippy,tests,durable-tests,cli-tests,workspace-tests,windows-check}.log`.

## Git ownership

Delegated Codex could not stage Git metadata from its restricted sandbox.
The coordinator performs task-branch-only commit and remote SHA verification.
Earlier source-map receipts predate the Windows path adjustment and must not
be presented as authoritative evidence for the final commit. No dev/main/tag
or installed-agent action is authorized by this snapshot stage.
