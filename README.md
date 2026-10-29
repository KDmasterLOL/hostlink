# HostLink — managed fleet with russh remote execution

Managed HostLink rewrite for development integration testing under Huly 1C-987.
The workspace contains three crates: Agent, Client and the required Hub. This
integration is not a release, deployment or installed fleet cutover. The source
code evidence documented in [the release plan](docs/REWRITE_RELEASE_PLAN.md) is
for `37fd3663f91dad0ceefd933862a4ec595e4765ce`; a documentation-only commit has
a different SHA and does not change the tested executable source.

Target packages:
- hostlink-agent: embedded SSH server, outbound reverse tunnel, SFTP,
  short exec, Agent-local Apalis jobs/Board, fresh enrollment and Agent-only updater.
- hostlink: Hub-managed host selection/invite/list/revoke plus pinned SSH
  client, exec, transfer and forwarding. Jobs are Agent-local.
- hostlink-hub: authoritative identity, route/gateway registry, invitations,
  enrollment, SSH authorization and revocation; **no execution RPC**. See
  [crates/hub/README.md](crates/hub/README.md) for server configuration/API.

Updates pin the exact Agent archive SHA-256/version/target and reject unsafe
roots. Windows uses `self_update 1.3.1` extraction/MoveAll and private durable
crash recovery, **offline only**: stop/remove its Task Scheduler task, run the
separate private updater, then explicitly install/start the task again.
Archive/manifest/inventory verification and rollback remain required. Native
Windows 11/Win7 acceptance for this replacement remains unrun. See
[docs/AGENT_UPDATE_WINDOWS.md](docs/AGENT_UPDATE_WINDOWS.md).

The rewrite is being integrated into HostLink `dev` for testing. It is **not
ready for release, deployment or fleet migration**.
The source-directory convention and module ownership are in
[docs/SOURCE_LAYOUT.md](docs/SOURCE_LAYOUT.md).
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

Agent-local commands use **Apalis SQLite 1.0.0** for queue/state/results and
the official **apalis-board-api 1.0.0** (Axum) for the browser UI and HTTP API.
The Agent accepts direct program + argv jobs, not a shell string by default.
The old SSH `hostlink-jobs` subsystem, Client `hostlink jobs` CLI, binary
upload/seal, bespoke state/protocol and raw spool log files are removed.

**For a freshly enrolled Agent**, its private `agent.json` includes an independent
`board_listen` (loopback-only) port; older manual configs may leave this
`null`, disabling the UI until a separately authorized config update. On
the Agent computer open `http://127.0.0.1:BOARD_PORT/new` to enqueue a command,
or `http://127.0.0.1:BOARD_PORT/` for the stock Apalis Board. The native API
accepts JSON at `PUT /api/v1/queues/commands/tasks` and exposes tasks/workers
under `/api/v1`. There is no separate jobs connection or job-specific Client API.

To open the Board from another trusted computer use **pinned authenticated
SSH TCP forwarding**, keeping the same local port number as the Agent:
```sh
hostlink forward --host lab-win7   --listen 127.0.0.1:BOARD_PORT --target 127.0.0.1:BOARD_PORT
```
The Board intentionally checks the exact HTTP Host/Origin, and **does not
bind publicly**. Anyone with local access to the Board can execute commands
as the Agent user; do not publish this HTTP port through a public proxy.

Apalis may re-enqueue a task after a crash, including one that had already
started; the command must tolerate duplicate side effects. ProcessKit controls
the OS process tree and requires an OS-backed containment mechanism. Standard
Apalis results contain the actual exit code; this design does not promise full
raw stdout/stderr replay. New stores use upstream Apalis SQLite migrations;
existing databases are reused without HostLink SQL schema inspection and
older layouts are not automatically imported or deleted. See the
[jobs module guide](crates/agent/src/jobs/README.md),
[Agent jobs contract](docs/AGENT_MINIMAL_JOBS.md) and
[verification evidence](docs/AGENT_MINIMAL_JOBS_EVIDENCE.md).

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
managed exec, SFTP, forwarding and revocation without touching
user SSH configuration or system services. See
[docs/ISOLATED_GATEWAY.md](docs/ISOLATED_GATEWAY.md) for prerequisites and
limits.

Fresh Agent enrollment can retain an explicitly selected Hub-approved primary
gateway and ordered, independently pinned alternates. Transient transport
failure rotates through those routes with bounded backoff; pin, authentication
and reverse-port authorization failures stop without fallback. See
[docs/MULTI_GATEWAY.md](docs/MULTI_GATEWAY.md) for the route and gateway
authorization contract.

A real Linux HOME Agent↔Client SSH test verifies channel-owned exec,
binary stdout/stderr and exact nonzero exit codes; the separate Apalis Board
integration tests cover persistent Agent-local commands. The Win7 evidence
and remaining gates are recorded in [the release plan](docs/REWRITE_RELEASE_PLAN.md):
WOW64 does not substitute for a native 32-bit Windows 7 OS. The replacement
Task Scheduler lifecycle and offline update/recovery require fresh native acceptance.

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
Task Scheduler logon task using limited interactive-user rights and no password.
Both expose `hostlink-agent service install/start/stop/status/remove`, preserving
enrollment, keys and Apalis jobs. Windows stop uses Scheduler termination;
graceful shutdown and descendant cleanup are not guaranteed. Interrupted
commands may replay after restart, repeating side effects.
Linux does not enable login lingering. Windows requires interactive sign-in.
Roots must be protected descendants of OS-resolved LocalAppData with private
ancestors. Legacy Run/VBS/pipe/maintenance registrations are rejected, not adopted.
See [docs/AGENT_LIFECYCLE.md](docs/AGENT_LIFECYCLE.md) for commands, platform
limits and safety behavior. Windows native acceptance remains unrun.
