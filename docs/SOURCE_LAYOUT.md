# HostLink source layout and module boundaries

Source decomposition for Huly 1C-987 (2026-10-27). The codebase uses three
crates: Agent, Client, and Hub; this describes the **development** branch and
does not certify production or registered Windows updater deployment.

## Convention

- For a module with children, use `name/mod.rs` and `name/*.rs`. **Never**
  create both `name.rs` and `name/mod.rs` at the same Rust module path.
  Windows layouts use `service/windows/mod.rs`, not `windows.rs`.
- Aim for roughly **200 physical lines per new module**. Larger cohesive files
  (protocol handlers, Windows state transitions, or single end-to-end tests)
  are allowed when splitting introduces more coupling than clarity.
- Keep the smallest visibility needed (`pub(super)`/`pub(in ...)`) and preserve
  existing public entrypoints through root re-exports.
- Prefer private `#[cfg(test)]` sibling modules for unit tests needing private
  implementation access. Integration tests stay in `crates/*/tests` and may
  use nested fixture/scenario modules in the same test target.
- This is a source-layout rule, **not** authorization to change behavior,
  security policy, network transports, service registration or deployed agents.

## Where to look

| Concern | Module |
| --- | --- |
| Controller CLI and operator command dispatch | `crates/client/src/cli/{mod.rs,args.rs,commands/}`; `main.rs` is the binary entrypoint |
| Managed Hub HTTP client, routes and trusted SSH pins | `crates/client/src/hub/{mod.rs,client.rs,config.rs,routes.rs}` |
| Direct and gateway SSH | `crates/client/src/connect/`; `crates/agent/src/ssh/`; `crates/agent/src/tunnel/` |
| Source-pinned tests / durable jobs | `crates/client/src/run/`; `crates/agent/src/durable/`; `crates/agent/src/ssh/jobs/` |
| Hub v2 endpoints and authoritative registry | `crates/hub/src/server/`; `crates/hub/src/state.rs` |
| Fresh enrollment and source-pinned installation | `crates/agent/src/enrollment/`; `crates/client/src/bootstrap/` |
| Linux service lifecycle | `crates/agent/src/service/linux/` (systemd --user) |
| Windows user-owned service and maintenance | `crates/agent/src/service/windows/`, with admission, rollback and process ownership |
| Agent update and ZIP security | `crates/agent/src/update/`, including `archive/`, `windows/` and `update_handoff/` for recovery |

`durable/database.rs` keeps the cohesive private initialization, connection
and immutable migration-ledger validation contract together; its extra lines
are a security-contract exception. `durable/persistence.rs` keeps the cohesive
Apalis payload, immutable claim
validation and SQL row decoding together. `durable/tests.rs` and
`ssh/jobs/tests.rs` are larger security/lifecycle regression suites; their
scenarios exercise real SQLite and processes rather than mock backends.
`ssh/jobs/engine_tests.rs` is likewise a cohesive worker security/lifecycle
regression suite covering real dequeue, forged claims, crash windows, retry
suppression, process limits and failure-driven tree teardown.
`durable/legacy_import/snapshot.rs` keeps the bounded old-format inventory and
private file access contract together. Its sibling `tests.rs` is a cohesive
security regression suite for quarantined staging, byte-preserving output,
lock contention, interrupted stages and source/readback corruption; their
extra lines are security-contract/test exceptions to the size guideline.

## Verification

Use `cargo fmt --all -- --check`, `cargo check --locked --workspace
--all-targets`, `cargo clippy --locked --workspace --all-targets -- -D
warnings`, and `cargo test --locked --workspace`. Run on both Linux and
Windows after platform-dependent moves. Windows 7 source-exact execution
and managed live updater handoff remain separately recorded acceptance gates
under Huly 1C-1004/1008; a Windows 11 compile is not a Win7 native pass.
