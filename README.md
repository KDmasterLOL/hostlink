# HostLink — managed fleet with russh remote execution

Experimental parallel rewrite. The current two-crate SSH milestone is not a drop-in
replacement, release, deployment or installed fleet cutover. The final product MUST also
include Hub-backed inventory, invitations, enrollment, host discovery and revocation. Source baseline: dev 5a1f80b4c44c393dd8cc83faacf0a3ebc49de342.

Target packages:
- hostlink-agent: embedded SSH server, outbound reverse tunnel, SFTP,
  short exec, durable jobs, secure fresh enrollment and Agent-only updater.
- hostlink: Hub-managed host selection/invite/list/revoke plus pinned SSH
  client, exec, transfer, forwarding and resumable test execution.
- hostlink-hub: authoritative identity, route/gateway registry, invitations,
  enrollment, SSH authorization and revocation; **no execution RPC**. See
  [crates/hub/README.md](crates/hub/README.md) for server configuration/API.

Updates must pin the exact Agent artifact SHA-256/version/target, defer active
jobs and reject unsafe roots. Managed-live Windows handoff and restart remain
required gates, not currently supported. Windows supports
offline publication only when a separate updater invokes it with no active Agent
process, service marker, or durable jobs. It stages and hashes the exact old/new
inventory, records a journal, atomically replaces files with ACL preservation,
and rolls back in-process failures. Registered/live Agent handoff and automatic
recovery after interruption remain unsupported. See
[docs/AGENT_UPDATE_WINDOWS.md](docs/AGENT_UPDATE_WINDOWS.md). The opt-in native
Windows 11 registered-Agent acceptance harness is
[`scripts/verify-windows-agent-updater-native.ps1`](scripts/verify-windows-agent-updater-native.ps1);
it requires a separately verified disposable user profile and source-exact
build/package receipts.

The original HostLink `dev` tree remains unchanged. This experimental branch
has runnable CLI binaries; it is **not ready for deployment or fleet migration**.
The managed-fleet target and acceptance gates are in
[docs/MANAGED_FLEET_ARCHITECTURE.md](docs/MANAGED_FLEET_ARCHITECTURE.md)
and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

The isolated Linux HOME pilot lifecycle (private Hub v2, HTTPS, OpenSSH
gateway, enrollment, health checks and reversible stop/restart) is documented
in [docs/PARALLEL_PILOT_OPERATIONS.md](docs/PARALLEL_PILOT_OPERATIONS.md).

## Rust compiler policy

The rewrite follows the installed Rust stable toolchain (currently 1.99.1)
for local Linux/modern Windows checks. The workspace MSRV remains 1.98.1:
raising the minimum is not required just to use a newer compiler. `stable`
is intentionally rolling, not a byte-for-byte reproducible compiler pin;
run `rustc --version` when recording acceptance. The Windows 7 Tier 3 MSVC
targets have no precompiled Rust standard library. Build both Agent and Client
targets with the separately pinned `nightly-2026-08-22`, `cargo-xwin`, and
`build-std`; ordinary Windows MSVC targets are not substitutes. The
source-exact build and PE evidence workflow is documented in
[docs/WIN7_REWRITE_ACCEPTANCE.md](docs/WIN7_REWRITE_ACCEPTANCE.md).

For disposable Windows bootstrap checks, `scripts/verify-win7-bootstrap-native.ps1`
validates the matching x64/x86 build and package receipts, runs the actual
`bootstrap-verify` binaries, checks their output receipts, and exercises digest,
target, and overwrite rejection. It requires Windows PowerShell 2, an
unelevated interactive user, and an explicitly supplied empty private staging
root. Windows 11 x86 execution is WoW64 evidence only, not native NT6.1
acceptance. See the acceptance document for package preparation and invocation.

## Development commands

```sh
cargo test --offline --locked --workspace
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo run --offline --locked -p hostlink-agent -- check --config agent.json
cargo run --offline --locked -p hostlink-agent -- run --config agent.json
cargo run --offline --locked -p hostlink-hub -- check --config hub.json
cargo run --offline --locked -p hostlink-hub -- serve --config hub.json
cargo run --offline --locked -p hostlink -- check --config host.json
cargo run --offline --locked -p hostlink -- exec --config host.json --command 'echo hello'
cargo run --offline --locked -p hostlink -- migration preflight --help
```

```sh
scripts/build-win7-candidate.sh \
  --source-sha "$(git rev-parse HEAD)" \
  --output-dir "target/win7-candidate-$(git rev-parse HEAD)"
```

The Win7 builder requires a clean task worktree and a new output directory
inside ignored `target/`. It builds both exact Win7 target triples and writes
PE inspection reports plus a source-bound JSON receipt. A successful cross
build is not native Windows 7 acceptance.

`hostlink migration preflight` inspects bounded local legacy Hub/Controller/Agent snapshots and explicit new Agent/HostSpec configs. It emits a redacted per-host READY/REVIEW/BLOCKED report without SSH, network access, credential conversion, or file writes. See [docs/MIGRATION_RUNBOOK.md](docs/MIGRATION_RUNBOOK.md) for required inputs and manual side-by-side verification/rollback; static readiness is not deployment acceptance.

The Agent listens on loopback and requires an Ed25519 host key and authorized
controller keys. The controller pins the Agent host public key and requires a
private Ed25519 identity. Neither component silently creates or enrolls keys.
Only use disposable current-user fixtures until the native acceptance matrix
passes.

Fresh user enrollment is available as `hostlink-agent enroll`; it uses the Hub
v2 `/v2/enroll` DTO, creates distinct machine and SSH host Ed25519 keys, and
publishes a private config only after validating the Hub response. The Win7
PowerShell 2 and Linux bootstrap scripts require independent exact source pins
for the package ZIP and target-specific verifier sidecar. The sidecar shares the
updater's strict ZIP/member manifest validator, verifies its own bytes match the
ZIP executable, and writes install integrity metadata plus a source-bound
bootstrap receipt before the token prompt. See
[docs/ENROLLMENT.md](docs/ENROLLMENT.md) for the full bootstrap contract and
native acceptance limits.

Durable jobs use the same authenticated SSH connection, with
`hostlink job start`, `hostlink job status` and `hostlink job output`. The job
UUID is printed **before** the first start request; on a lost acknowledgement,
query status by UUID instead of resubmitting. Ordinary SSH `exec` remains
channel-owned and does **not** survive a disconnect.

The client also supports Hub v2 inventory and named host selection while
keeping explicit `--config PATH` as a mutually exclusive option. Start with
`hostlink hub configure`, then use `hostlink list` for registry data or
`hostlink list --check` for bounded pinned SSH probes. See
[docs/CLIENT_HUB.md](docs/CLIENT_HUB.md) for operator commands, private token
requirements, gateway routing and truthful revocation behavior.

The pinned SSH client also supports loopback-only TCP forwarding, local RDP
mapping and target-side TCP probes through `russh` direct-tcpip. See
[docs/TCP_FORWARDING.md](docs/TCP_FORWARDING.md) for commands, deadlines,
concurrency limits and security behavior.

The opt-in process-level managed gateway fixture runs a real child Hub over
trusted local HTTPS, enrolls an Agent, and uses a temporary OpenSSH gateway
whose `AuthorizedKeysFile` includes the Hub-owned v2 projection. It exercises
managed exec, SFTP, durable jobs, forwarding and revocation without touching
user SSH configuration or system services. See
[docs/ISOLATED_GATEWAY.md](docs/ISOLATED_GATEWAY.md) for prerequisites and
limits.

Fresh Agent enrollment can retain an explicitly selected Hub-approved primary
gateway and ordered, independently pinned alternates. Transient transport
failure rotates through those routes with bounded backoff; pin, authentication
and reverse-port authorization failures stop without fallback. See
[docs/MULTI_GATEWAY.md](docs/MULTI_GATEWAY.md) for the route and gateway
authorization contract.

A real Linux HOME Agent↔Client SSH test verifies accepted-once execution,
disconnect/reconnect, binary stdout/stderr and exit code `7`. Native Win7
x64/x86 and Windows Agent-owned durable execution/updater handoff remain
explicit acceptance gates. The Agent-only updater is not removed.

## Local Agent artifact packages

Use [docs/ARTIFACTS_AND_INVITES.md](docs/ARTIFACTS_AND_INVITES.md) and
`scripts/package-hostlink-agent.py` to create a deterministic, source-SHA-bound
Agent ZIP, sidecar, installer pin, and invite-input hashes. Packaging is local
only; operators select and verify their own immutable HTTPS artifact origin.
The `hostlink-managed-gateway-fixture.sh` opt-in HOME fixture also packages from
its clean committed SHA and exercises the real CLI invite, HTTPS installer,
one-use prompt, and managed Agent lifecycle against temporary Caddy/sshd
instances. Native Windows 11 and Win7 PowerShell 2 acceptance remain separate.

## Agent lifecycle

The Hub registry and local Agent process are managed separately. `hostlink remove`
revokes Hub access; it does not uninstall the local Agent. Linux uses a
root-bound `systemd --user` unit; Windows 7 and Windows 11 use a current-user
HKCU login-startup entry with an authenticated local control pipe. Both expose
`hostlink-agent service install/start/stop/status/remove`, preserve enrollment
data, keys and jobs, and refuse shutdown while durable jobs are unresolved.
Linux does not enable login lingering. Windows startup requires the interactive
user to sign in and rejects HKCU Run commands over the 260-character limit.
Windows roots must be protected descendants of the current user's OS-resolved
LocalAppData folder. Every intermediate directory must have a protected
owner-only ACL; the control token remains out of launcher arguments.
See [docs/AGENT_LIFECYCLE.md](docs/AGENT_LIFECYCLE.md) for commands, platform
limits and safety behavior. Windows native acceptance remains unrun.
