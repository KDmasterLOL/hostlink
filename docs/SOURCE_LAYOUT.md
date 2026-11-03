# Source layout

HostLink is a Rust workspace with three components and one vendored filesystem dependency.

| Concern | Location |
| --- | --- |
| Controller CLI and dispatch | `crates/client/src/cli/` |
| Controller Hub client, registry and routes | `crates/client/src/hub/`, `host/` |
| SSH connections, commands and SFTP | `crates/client/src/connect/`, `exec/`, `sftp.rs` |
| Release selection and bootstrap | `crates/client/src/bootstrap/`, `crates/client/assets/` |
| Agent CLI and runtime | `crates/agent/src/cli.rs`, `commands/`, `runtime.rs` |
| Agent SSH and reverse tunnel | `crates/agent/src/ssh/`, `tunnel/`, `sftp/` |
| Agent enrollment, installation and update | `crates/agent/src/enrollment/`, `installation.rs`, `update.rs` |
| Agent user services | `crates/agent/src/service/` |
| Agent-local jobs and Board | `crates/agent/src/jobs/` |
| Hub HTTPS endpoints and state | `crates/hub/src/server/`, `state.rs` |
| Private filesystem support | `Vendor/private-fs/`, `crates/agent/src/private_fs.rs` |
| Build/package scripts and tests | `scripts/`, `scripts/tests/` |

Modules with children use `name/mod.rs` and sibling files, not both `name.rs` and `name/mod.rs`. Keep visibility narrow, write focused unit/integration tests, and avoid duplicating ownership across components.

Apalis owns its SQLite job state; HostLink does not implement a separate queue schema. `russh` is the only remote execution transport; the Hub provides control-plane APIs, not an alternate RPC engine. Filesystem publication and identity checks use existing owner-verified abstractions.

See [architecture](ARCHITECTURE.md), [jobs](AGENT_MINIMAL_JOBS.md), and [release packaging](ARTIFACTS_AND_INVITES.md).
