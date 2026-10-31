# HostLink source layout and module boundaries

Source decomposition for Huly 1C-987 (2026-10-27). The codebase uses three
crates: Agent, Client, and Hub; this describes the **development** branch and
does not certify production or registered Windows updater deployment.

## Convention

- For a module with children, use `name/mod.rs` and `name/*.rs`. **Never**
  create both `name.rs` and `name/mod.rs` at the same Rust module path.
  The Agent service has `service/mod.rs` plus sibling platform modules
  `service/linux.rs` and `service/windows.rs`; these do not have children.
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
| Owner-only private files and Windows ACL | `Vendor/private-fs/` (pinned upstream + Win7 fallback) |
| Verified-handle → standard `File` conversion for OS locks and Tokio | `crates/agent/src/private_fs.rs` (one extension trait) |
| Windows 7 LocalAppData lookup for exact updater root | `crates/agent/src/update/private_fs.rs` |
| Hub v2 endpoints and authoritative registry | `crates/hub/src/server/`; `crates/hub/src/state.rs` |
| Fresh enrollment and source-pinned installation | `crates/agent/src/enrollment/`; `crates/client/src/bootstrap/` |
| Linux service lifecycle | `crates/agent/src/service/linux.rs` (`service-manager` + systemd --user) |
| Windows current-user Task Scheduler | `crates/agent/src/service/windows.rs` (direct COM, owned task action, legacy collision rejection) |
| Exact Agent URL update and ZIP security | `crates/agent/src/update/{artifact.rs,admission.rs,publication.rs,installed.rs,archive/}`; `windows/` owns offline admission only |

`update/publication.rs` calls high-level `self_update::backends::custom::Update`.
`artifact.rs` supplies one pinned release; `installed.rs` owns validated format-2
bin metadata with format-1 root fallback. `archive/contents.rs` is the one bounded
ZIP/manifest validator shared by the updater and fresh bootstrap. Bootstrap-only
private copying/extraction remains in `archive/mod.rs` and `staging/mod.rs` to
preserve the existing installer output contract. There is no installed-update
fallback, private staging backend, platform publisher or update_handoff journal.
The cohesive bootstrap/profile filesystem file and end-to-end HTTP test module
are permitted to exceed the approximate 200-line target. See
[SELF_UPDATE_REWRITE.md](SELF_UPDATE_REWRITE.md) for the authorized durability change.

`jobs/mod.rs` exposes only the typed `CommandJob`, local queue and private
updater contract. `jobs/store.rs` configures the native Apalis SQLite
`commands` queue; `jobs/worker.rs` uses `WorkerBuilder` to execute it
through ProcessKit. `jobs/board.rs` mounts the upstream Apalis Board
Axum API and embedded UI; `jobs/new.html` is a small form calling the
upstream task API. `jobs/database.rs` preserves private fresh-only SQLite
schema using upstream Apalis migrations only. `Vendor/private-fs/` supplies
`PrivateDir`, `PrivateFile`, owner-only permissions, Windows protected DACL,
nofollow/reparse and hardlink checks, and durable atomic publication.
Its pinned upstream revision and compatibility deviations are recorded in
[`Vendor/private-fs/VENDOR.md`](../Vendor/private-fs/VENDOR.md).
`private_fs.rs` defines a single `PrivateFileExt::try_clone_std` method:
it verifies a private file, then clones the already-acquired OS handle for
standard `File` locking or Tokio (without reopening a path). Lock owners
open via `PrivateDir` directly; there is no generic `open_lock` wrapper.
The updater owns Win7-compatible OS profile lookup in `update/private_fs.rs`.
Converting to `File` does not retain vendored per-I/O revalidation; SFTP
must treat this as an explicit verification boundary. There is no separate
Agent ACL/parser implementation or root/elevation validator. Service install/start
validate the private Agent root and its immediate parent; runtime privilege
policy belongs to `runtime.rs`. Read-only Task Scheduler status does not
inspect filesystem permissions. Win7 compatibility uses a local-NTFS legacy
identity fallback, but native Win7 reparse/ACL/rename tests remain a separate
acceptance gate.
`jobs/tests/` contains the focused API and worker tests. There are no
SSH jobs frames, SFTP binary artifacts, custom lifecycle or Client jobs
module. `runtime.rs` supervises the independent SSH server, Apalis worker
and outbound tunnel and owns the Linux updater process-lifetime lock.
`ssh/server.rs` only runs the `russh` server and handles authenticated
exec, SFTP and TCP-forward channels. `ssh/config.rs` uses vendored
`private-fs` file capabilities for key access. `ssh::serve` and `ssh::serve_on`
remain public re-exports of the runtime functions for existing callers.
`russh` advertises only public-key authentication; channel tracking
requires no shared mutex because the handler owns its session map.
`sftp/` owns controller-scoped generic transfers.
Agent CLI command argument definitions and execution live together in
individual modules under `commands/`, including separate service actions.
The `cli.rs` module only parses and dispatches Clap commands, while
`shared.rs` owns the bounded Agent configuration loader. Service status
exposes OS registration/running state only; SSH/Hub readiness and enrollment
health have separate owners. Retired Windows hidden
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
