# HostLink — managed fleet with russh remote execution

Managed HostLink rewrite for development integration testing under Huly 1C-987.
The workspace contains three crates: Agent, Client and the required Hub. This
integration is not a release, deployment or installed fleet cutover.
See the [documentation index](docs/index.md) for maintained contracts.
Huly 1C-1164 defines binary-only distribution. Agent, Controller and
packaging changes are integrated and pass the Linux workspace tests; native
Windows and real private-release acceptance remain separate release gates.

Target packages:

- hostlink-agent: embedded SSH server, outbound reverse tunnel, SFTP,
  short exec, Agent-local Apalis jobs/Board, fresh enrollment and Agent-only updater.
- hostlink: Hub-managed host selection/invite/list/revoke plus pinned SSH
  client, exec, transfer and forwarding. Jobs are Agent-local.
- hostlink-hub: authoritative identity, route/gateway registry, invitations,
  enrollment, SSH authorization and revocation; **no execution RPC**. See
  [crates/hub/README.md](crates/hub/README.md) for server configuration/API.

Fresh installation and updates use **only the private**
`KDmasterLOL/hostlink` **GitHub Releases** repository. The target's GitHub
read-only credential is entered during bootstrap by default and stored in a
private current-user file (`~/.config/hostlink/credentials/github-token`
on Linux, `%APPDATA%\HostLink\credentials\github-token` on Windows).
`hostlink invite --embed-github-token` explicitly embeds the Controller's
existing PAT in the printed bootstrap command, so the target provisions it
without another prompt. This opt-in **exposes the PAT in stdout, copied
commands and potentially shell history or saved PowerShell scripts**;
otherwise the token never appears in the generated invitation. Controller uses its own
corresponding user-local credential to resolve the release metadata and
published binary digest **before issuing an invitation**. The target verifies
downloaded bytes before consuming the one-use Hub token. The updater supports
`hostlink-agent update [--version X.Y.Z] [--root ROOT]` and no arbitrary
`--url`, `--sha256` or `--target` flags. Distribution contains exactly four
raw Agent executables, with GitHub-published SHA-256; see
[GitHub Releases](docs/GITHUB_RELEASES.md) for exact asset names.
The updater uses the `self_update` GitHub RAW backend for one exact target
asset and version, with exclusive offline locks and Windows stopped-task gate.

Install at one stable per-user root: absolute `$XDG_DATA_HOME/hostlink/Agent`
or `$HOME/.local/share/hostlink/Agent` on Linux, current-user OS-resolved
`%LOCALAPPDATA%\HostLink\Agent` on Windows. Controller-generated disposable
PS2/POSIX bootstrap verifies one downloaded binary before consuming the Hub
invite. Rust Agent install owns enrollment and executable publication; no Git
or default tools are installed. No ZIP, installed PS1/shell wrappers, release
manifest, `archive.sha256` or bootstrap receipt. **Keep `state/manifest.json`**:
it owns private enrollment-key identity, separate from release metadata.

Both `update.lock` and `jobs/runner.lock` remain mandatory. Stop the Agent
before publication; on Windows remove its current-user Task Scheduler task
and use a verified separate updater outside installed `bin`. Upstream handles
ordinary in-process rollback, but sudden kill/power loss may require manual
recovery; no durable crash journal. See [installation](docs/AGENT_INSTALLATION.md)
and [Windows offline update](docs/AGENT_UPDATE_WINDOWS.md). Native Win7/11
acceptance and separately approved publication remain release gates.

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

The old `scripts/verify-win7-bootstrap-native.ps1` ZIP harness is retired
and fails explicitly without executing candidates. It cannot validate the raw
installation flow. Native Windows 7 x86/x64, Windows 11 and PowerShell 2
acceptance must be recorded anew; see the acceptance document.

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

Fresh enrollment uses the Hub v2 `/v2/enroll` DTO, distinct machine and SSH
host Ed25519 keys, and private config publication after validating the reply.
Controller-generated bootstrap downloads and SHA-256-checks a single raw
executable before invoking Rust install and consuming the one-use invite.
See [enrollment](docs/ENROLLMENT.md) for identity and reconciliation boundaries.

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

The isolated Hub/OpenSSH gateway pilot uses only disposable user-owned
processes. Its procedures and limitations are in
[docs/PARALLEL_PILOT_OPERATIONS.md](docs/PARALLEL_PILOT_OPERATIONS.md).

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

Use [the GitHub-only publication contract](docs/ARTIFACTS_AND_INVITES.md):
`scripts/package-hostlink-agent.py` copies one source-bound raw executable
and writes local provenance; `scripts/stage-hostlink-github-release.py`
verifies receipts and emits only raw assets plus a hidden local receipt.
Receipts must not be published. These tools do not upload, tag or deploy.
Run `python3 -m unittest discover -s scripts/tests -v` for local script checks.
The old asset-sourced bootstrap credential/download tests were deleted with
the installers; Controller-generated bootstrap has its own tests.

## Agent lifecycle

The Hub registry and local Agent process are managed separately. `hostlink remove`
revokes Hub access; it does not uninstall the local Agent. Linux uses a
root-bound `service-manager` systemd user unit; Windows 7 and Windows 11 use a current-user
Task Scheduler logon task using limited interactive-user rights and no password.
Both expose `hostlink-agent service install/start/stop/status/remove`, preserving
enrollment, keys and Apalis jobs. Windows stop uses Scheduler termination;
graceful shutdown and descendant cleanup are not guaranteed. Interrupted
commands may replay after restart, repeating side effects.
Linux handles systemd SIGTERM gracefully and does not enable login lingering. Windows requires interactive sign-in.
Windows service roots and their immediate parents must be private to their
current owner; read-only profile ancestors are allowed. The offline Windows
updater still requires the exact OS-resolved LocalAppData/HostLink/Agent root.
Agent-private file security now uses a pinned vendored `private-fs` crate
(`Vendor/private-fs/VENDOR.md`), including a Windows 7 local-NTFS fallback.
On Windows, private directories have one protected current-user `OICI` ACE
to protect SQLite-created DB/WAL/SHM files through inheritance. Private
regular files use one protected, noninheritable current-user ACE. Existing
nonconforming ACLs are never silently repaired.
Stale legacy markers do not block service installation, but an existing
legacy HKCU Run autorun must be safely removed before Task Scheduler startup.
See [docs/AGENT_LIFECYCLE.md](docs/AGENT_LIFECYCLE.md) for commands, platform
limits and safety behavior. Windows native acceptance remains unrun.

## Project Structure

```text
crates/agent/    Agent runtime, enrollment, install/update and local jobs
crates/client/   Controller CLI and generated bootstrap
crates/hub/      Fleet management API and state
scripts/        Local packaging, evidence and disposable pilot tools
docs/           Source contracts and acceptance history
Vendor/         Pinned dependencies with local compatibility changes
```

| Directory | Responsibility |
| --- | --- |
| `crates/` | Agent, Controller and Hub implementations |
| `scripts/` | Local build/package checks; no implicit publication |
| `docs/` | Architecture, installation and evidence boundaries |
| `Vendor/` | Pinned dependency sources and provenance |

### Adding New Code

| Concern | Owner |
| --- | --- |
| Install/update and enrollment | Agent Rust modules; [source map](docs/SOURCE_LAYOUT.md) |
| Generated bootstrap and invite | Controller `bootstrap/` and Hub command modules |
| Artifact packaging and staging | Existing Python scripts and `scripts/tests/` |
