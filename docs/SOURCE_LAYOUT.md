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
| Agent CLI, commands and shared configuration loading | `crates/agent/src/cli.rs`, `crates/agent/src/commands/`, `crates/agent/src/shared.rs`; `main.rs` only initializes the CLI and reports errors |
| Managed Hub HTTP client, routes and trusted SSH pins | `crates/client/src/hub/{mod.rs,client.rs,config.rs,routes.rs}` |
| Direct and gateway SSH | `crates/client/src/connect/`; `crates/agent/src/ssh/`; `crates/agent/src/tunnel/` |
| Agent process supervision (SSH, Apalis, tunnel, updater lifetime lock) | `crates/agent/src/runtime.rs` |
| Agent-local Apalis command queue and Board UI/API | `crates/agent/src/jobs/` (no Client jobs subsystem) |
| Shared Agent-private files, locks and Windows DACL | `crates/agent/src/private_fs/` |
| Hub v2 endpoints and authoritative registry | `crates/hub/src/server/`; `crates/hub/src/state.rs` |
| Fresh enrollment and source-pinned installation | `crates/agent/src/enrollment/`; `crates/client/src/bootstrap/` |
| Linux service lifecycle | `crates/agent/src/service/linux/` (systemd --user) |
| Windows current-user Task Scheduler | `crates/agent/src/service/windows/`, with COM adapter, exact task XML and read-only legacy rejection |
| Agent update and ZIP security | `crates/agent/src/update/`, including `archive/`, `windows/` and `update_handoff/` for recovery |

`jobs/mod.rs` exposes only the typed `CommandJob`, local queue and private
updater contract. `jobs/store.rs` configures the native Apalis SQLite
`commands` queue; `jobs/worker.rs` uses `WorkerBuilder` to execute it
through ProcessKit. `jobs/board.rs` mounts the upstream Apalis Board
Axum API and embedded UI; `jobs/new.html` is a small form calling the
upstream task API. `jobs/database.rs` preserves private fresh-only SQLite
schema using upstream Apalis migrations only. Shared `private_fs/mod.rs`
enforces owned paths and uses
standard `File::lock` / `File::unlock`; `private_fs/windows.rs`
centralizes DACL checks for jobs, SSH, SFTP, service and updater while
preserving their different allowed-principal policies.
`jobs/tests/` contains the focused API and worker tests. There are no
SSH jobs frames, SFTP binary artifacts, custom lifecycle or Client jobs
module. `runtime.rs` supervises the independent SSH server, Apalis worker
and outbound tunnel and owns the Linux updater process-lifetime lock.
`ssh/server.rs` only runs the `russh` server and handles authenticated
exec, SFTP and TCP-forward channels. `ssh/config.rs` uses shared
`private_fs` for key-file validation. `ssh::serve` and `ssh::serve_on`
remain public re-exports of the runtime functions for existing callers.
`russh` advertises only public-key authentication; channel tracking
requires no shared mutex because the handler owns its session map.
`sftp/` owns controller-scoped generic transfers.
Agent CLI command argument definitions and execution live together in
individual modules under `commands/`, including separate service actions.
The `cli.rs` module only parses and dispatches Clap commands, while
`shared.rs` owns the bounded Agent configuration loader. Public command syntax and status fields are retained; retired Windows hidden
`--managed-service` and `--maintenance-start` flags are removed.
See [jobs README](../crates/agent/src/jobs/README.md) and
[jobs contract](AGENT_MINIMAL_JOBS.md).

## Verification

Use `cargo fmt --all -- --check`, `cargo check --locked --workspace
--all-targets`, `cargo clippy --locked --workspace --all-targets -- -D
warnings`, and `cargo test --locked --workspace`. Run on both Linux and
Windows after platform-dependent moves. Windows 7 source-exact execution
and offline update/recovery remain separately recorded acceptance gates
under Huly 1C-1004/1008; a Windows 11 compile is not a Win7 native pass.
