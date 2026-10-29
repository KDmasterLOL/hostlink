# HostLink — managed fleet with russh remote execution

Managed HostLink rewrite for development integration testing under Huly 1C-987.
The workspace contains three crates: Agent, Client and the required Hub. This
integration is not a release, deployment or installed fleet cutover. The source
code evidence documented in [the release plan](docs/REWRITE_RELEASE_PLAN.md) is
for `37fd3663f91dad0ceefd933862a4ec595e4765ce`; a documentation-only commit has
a different SHA and does not change the tested executable source.

Target packages:
- hostlink-agent: embedded SSH server, outbound reverse tunnel, SFTP,
  short exec, durable jobs, secure fresh enrollment and Agent-only updater.
- hostlink: Hub-managed host selection/invite/list/revoke plus pinned SSH
  client, exec, transfer, forwarding and resumable test execution.
- hostlink-hub: authoritative identity, route/gateway registry, invitations,
  enrollment, SSH authorization and revocation; **no execution RPC**. See
  [crates/hub/README.md](crates/hub/README.md) for server configuration/API.

Updates must pin the exact Agent artifact SHA-256/version/target, defer active
jobs and reject unsafe roots. The Agent-only local ZIP updater is integrated:
Windows uses `self_update 1.3.1` extraction and `MoveAll`, private durable crash
recovery, and single-use maintenance-candidate admission. The registered/live
Windows update, health and rollback flow has not yet passed a real managed-live
acceptance run; this code status is not release acceptance. See
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

Durable jobs use `hostlink jobs run/list/status/logs/cancel` over the authenticated
`hostlink-jobs` SSH subsystem. `hostlink jobs run --binary ./runner --config
host.json -- [argv...]` uploads, seals and enqueues; `--wait` streams raw output
and returns the exact exit code. The canonical ULID prints before connecting
and is also the Apalis TaskId. After a lost acknowledgement, query that same
ULID. Top-level `hostlink run` and low-level run flags are removed. Ordinary SSH
exec is channel-owned.

One Agent-owned Apalis SQLite 1.0.0 WorkerBuilder polls the queue and runs at
most 16 ProcessKit trees. Apalis owns worker locks, native status, persisted
results and automatic recovery. **After Agent/worker failure an already-started
job may execute again**; repeated side effects are an accepted trade-off,
not an exactly-once guarantee. An explicit duplicate ULID admission is still
idempotent. The old custom start-claim ledger and manual completion/recovery
engine were removed. Cancelled or failed jobs do not stop an otherwise healthy
worker. Private output can append across crash-recovered attempts. SHA checks
and per-controller sealed artifacts retain their bounds. Fresh private roots
use jobs schema v4; older schemas/record.json are rejected, not migrated.
New runs require the authenticated controller's exact canonical sealed source,
with private-parent and digest checks repeated immediately before launch.
On Unix, the managed install/artifact roots must be Agent-owned and private.
Source paths must be canonical (no ancestor symlink aliases), but we no longer
walk the host filesystem enforcing owner/mode policy on every ancestor above
the managed install root. This assumes trusted SSH controllers and the
non-privileged Agent's filesystem boundary.
Job execution requires actual cgroup v2 containment on Linux (delegation required),
Job Objects on Windows, or a process reaper on FreeBSD. POSIX fallback is rejected
before spawn; after empty spool sync this is a definite Failed job, not a
successful process execution.
Native-positive acceptance uses `HOSTLINK_REQUIRE_NATIVE_CONTAINMENT=1`; missing
strong containment then fails tests instead of reporting an optional skip.
The CLI/protocol change is breaking, with no v1 compatibility. See the
[jobs module guide](crates/agent/src/jobs/README.md),
[minimal jobs contract](docs/AGENT_MINIMAL_JOBS.md) and
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
disconnect/reconnect, binary stdout/stderr and exit code `7`. The Win7 evidence
and remaining gates are recorded in [the release plan](docs/REWRITE_RELEASE_PLAN.md):
WOW64 does not substitute for a native 32-bit Windows 7 OS, and a full registered
Agent live-update run remains untested.

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
