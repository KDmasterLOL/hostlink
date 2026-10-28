# 1C-1073 strict runtime-open follow-up receipt

Historical 1C-1073 record. Current implementation and acceptance are described
in [1C-1081 minimal jobs](AGENT_MINIMAL_JOBS.md).

Scope: the runtime-open fail-open correction, explicit fresh provisioning,
related call sites/fixtures and documentation. This receipt does **not** certify
completion of the whole Apalis migration or its separately owned worker,
output, Windows handoff and legacy-cutover gates.

Branch: `task/1c-1073-apalis-production`.
Original dev baseline: `4570a45c5ba53f5440a8265906393cbcf629c033`.
This focused receipt precedes coordinator task-branch publication and native
acceptance; it is not a release acceptance report.

## Implemented behavior

`DurableStore::open` opens existing state only. It rejects missing jobs.db in
empty and runner-only roots, zero-byte/torn databases, missing output roots and
incompatible migration ledgers. It never invokes migrations, creates jobs.db,
repairs output directories or converts a stored journal mode to WAL.

`DurableStore::initialize_fresh` explicitly provisions a new private EMPTY
root. It rejects existing database, runner, output and unknown entries. Its
new connection establishes and verifies WAL/FULL; every pooled connection
continues to verify WAL/FULL after connect and before acquire. All ordinary
connections explicitly disable create_if_missing. Failed initialization is
preserved instead of being reset on retry.

Enrollment and fresh test provisioning use initialize_fresh; runtime SSH and
reopening use open. The coordinator's strict missing-database active_ids guard
is unchanged. Existing records, output bytes, UUID/spec identity and migration
ledger entries are preserved on rejected opens. Existing ledger versions,
success flags and checksums are validated without automatic repair.

## Executed checks

Linux: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`; cached offline dependencies.

| Command/check | Actual result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --offline --locked --workspace --all-targets` | PASS |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked -p hostlink-agent --lib durable::` | 19 PASS |
| `cargo test --offline --locked -p hostlink-agent --lib ssh::` | 8 PASS, includes real production-handler SSH over duplex |
| `cargo test --offline --locked -p hostlink --lib run::` | 14 PASS |
| Agent updater / Linux lifecycle integration | 26 / 2 PASS |
| Changed Agent/Client TCP integration fixtures | 11 blocked by sandbox bind EPERM; 2 static tests PASS |
| `git diff --check`; unchanged isolated PoC | PASS |

Negative tests cover absent DB in empty/runner-only roots, removal of a closed
DB and its sidecars while preserving raw output, no recreated DB, refusal to
initialize an existing store, immutable UUID/spec after reopening, a torn empty
file and a missing migration-ledger entry without reapplying migrations.
The Windows cfg call site uses the retained public open API.

Windows target tests check was attempted with
`cargo check --offline --locked -p hostlink-agent --tests --target
x86_64-pc-windows-msvc`; dependency setup failed because lib.exe is unavailable.
This is not Windows compilation/runtime proof. Native Windows/Win7 acceptance
was not run. No real service or client database was modified.

## Source binding and review

Independent focused read-only review has no remaining Required findings for
this open/fresh scope. All 105 Rust/manifest hashes were verified against
aggregate SHA-256:

`762784a2ce9077e61db3b8585c9727d2a88de601f88e27d06c64fe81c376792e`

The aggregate is SHA-256 of UTF-8
`json.dumps(files, sort_keys=True, separators=(',', ':'))`, where files maps
paths to content SHA-256 values. Documentation is outside that source hash.

The source map, logs, and reviewed patch at that point are in ignored
`target/1c1073-evidence/open-split/`. Git staging failed inside the delegated
sandbox, so the coordinator is responsible for a task-branch commit and
source-exact native validation. This does not authorize dev promotion.
