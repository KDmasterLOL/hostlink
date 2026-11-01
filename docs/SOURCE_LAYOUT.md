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
| Managed registered Host identity, explicit pending invitation and fresh pinned connect | `crates/client/src/host/` (public `Host::create/connect`) |
| Direct and gateway SSH | `crates/client/src/connect/`; `crates/agent/src/ssh/`; `crates/agent/src/tunnel/` |
| Agent process supervision (SSH, Apalis, tunnel, updater lifetime lock) | `crates/agent/src/runtime.rs` |
| Agent-local Apalis command queue and Board UI/API | `crates/agent/src/jobs/` (no Client jobs subsystem) |
| Owner-only private files and Windows ACL | `Vendor/private-fs/` (pinned upstream + Win7 fallback) |
| Verified-handle → standard `File` conversion for OS locks and Tokio | `crates/agent/src/private_fs.rs` (one extension trait) |
| Windows 7 LocalAppData lookup for exact updater root | `crates/agent/src/agent_files.rs` |
| Hub v2 endpoints and authoritative registry | `crates/hub/src/server/`; `crates/hub/src/state.rs` |
| Fresh enrollment and source-pinned installation | `crates/agent/src/enrollment/`; `crates/client/src/bootstrap/` |
| Linux service lifecycle | `crates/agent/src/service/linux.rs` (`service-manager` + systemd --user) |
| Windows current-user Task Scheduler | `crates/agent/src/service/windows.rs` (direct COM, owned task action) |
| Installed Agent update | `crates/agent/src/update.rs`: exact artifact, offline admission and upstream `self_update` |
| Initial Agent installation and receipt | `crates/agent/src/bootstrap.rs` |
| Shared package identity and ZIP preflight | `crates/agent/src/package/` |
| Shared private root/path and file identities | `crates/agent/src/agent_files.rs` |
| Windows offline process identity admission | `crates/agent/src/service/offline.rs` |

`update.rs` exposes the GitHub-only `update_from_github(root, version)`
entrypoint and uses upstream `self_update::github` for release discovery,
then the single `self_update::custom::Update` for ZIP/manifest-checked
publication. No public arbitrary URL/pin update mode remains. Agent
credentials are read through the private `agent_files.rs` helpers from the
target's user-owned `hostlink/credentials/github-token` file. Controller's
GitHub-only invitation selects and verifies assets in
`crates/client/src/bootstrap/github.rs` before issuing a Hub invite; the
target bootstrap securely prompts/creates its own PAT before downloading
the fixed GitHub asset URLs. `bootstrap.rs` still owns the original
first-install verifier/finalization, with source `manifest.json` and
separate installed `archive.sha256`. Both paths preserve locks, the
stopped-Agent gate and private state. See
[GitHub Releases](GITHUB_RELEASES.md) and
[Agent installation](AGENT_INSTALLATION.md).

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
Win7-compatible OS profile lookup belongs to `agent_files.rs`.
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
