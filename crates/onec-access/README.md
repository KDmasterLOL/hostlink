# onec-access

`onec-access` is the controller-side managed-machine access product for `onec-hub` /
`onec-agent` fleets. It owns controller-local hub configuration, authoritative inventory
selection, generated SSH projection, embedded russh/russh-sftp transport, structured exec/jobs,
verified file transfer, probes, forwarding, RDP and enrollment invitation rendering.

It does **not** own hub persistence/enrollment state or caller-specific project/update policy. Server-side
authority remains in `onec-hub`; target-local operations are composed by `onec-cli` over
`onec-infobase`, `onec-project`, and the other focused domain owners.

## Display-only managed machine labels

An enrolled host may have an optional Unicode display label independent of its stable
Hub name. The operator can update or clear it without reenrollment or key rotation:

```text
onec-access display-name server-a "Тестовый сервер"
onec-access display-name server-a --clear
```

The stable Hub `name` remains the only human-readable SSH/exec/remove selector and
authenticated Hello identity. `display_name` is never a selector; duplicate labels are
allowed. `onec-access list` presents both name and label, while `list --json` and
`info` expose `display_name` separately without changing existing fields.

The Hub persists `display_name` as an optional field in the current durable state,
retains it during same-machine reenrollment, and supports operator-only
`PATCH /v1/agents/{machine_id}/display-name` with a string label or JSON null
to clear. Legacy records lacking `display_name` remain valid. The Hub and controller
must both support this endpoint; deploying a controller alone does not activate it.

The controller runs one Tokio runtime at the binary boundary. Hub HTTP, embedded SSH/SFTP, agent
control RPC, bulk transfers, loopback forwarding and job polling use async I/O and timers. Explicit
async channel finish reports SSH/SFTP shutdown failures; dropping a channel does not block or create
a runtime. After a mutating request is written to a managed target, canceling its controller future
leaves the controller unable to know whether the target applied it; `target-state-unknown` is
returned only when the future remains alive to observe a transport failure. Cancellation does not
cancel target work. Callers needing reconnect/no-replay semantics should use durable jobs and
persisted job IDs rather than canceling an in-flight mutating RPC. Transfer cancellation owns local
temporary files and schedules cleanup of unique remote SFTP staging names on the live application
runtime; that drop-path cleanup is best effort and is not guaranteed after abrupt runtime shutdown.
Cancellation before the remote publication request leaves the destination untouched. Once the
mutating `PathRename` publication request is in flight, cancellation cannot determine whether the
target applied it; destination state is unknown and callers must not replay blindly. The wire
protocol and CLI behavior are unchanged.

TargetSsh uploads use the existing 180-second total transfer budget and bound each SFTP request
to the configured 30-second SSH inactivity interval, capped by the remaining total budget. The
per-request bound covers SFTP connection establishment, destination checks, staging-file
open/write/sync/close and metadata. Atomic publication uses authenticated Agent
`PathRename`, not SFTP, and remains under the overall TargetSsh 180-second deadline.
Remote SHA-256 is also an authenticated Agent control-channel request with a
separate 180-second bound for staging,
post-publication verification and ambiguous-publication reconciliation (and remains under the
TargetSsh 180-second overall upload ceiling). A slow but valid Agent digest must not fail merely
because it exceeds the 30-second SFTP operation budget. If final verification cannot be observed,
the upload is not reported as successful or retried blindly. A timeout cancels the in-flight
request and reports only its stage, elapsed time, acknowledged/total bytes, and whether
publication may have committed. A cancelled run-owned staging path receives bounded
best-effort cleanup; unconfirmed cleanup or
publication remains unknown. Publication is never blindly retried after its request may have been
sent. The large multi-stage SFTP upload future is heap-backed so it does not consume the default
controller thread stack; a regression test bounds the enclosing future's layout. The nested
Agent `PathSha256` control-channel futures at SFTP staging and final verification are also
heap-backed, preventing stack overflow when an SSH handshake runs deep inside the upload
state machine. The complete loopback SFTP upload/download regression runs at default stack size.

Immediate execution and durable job start each expose one async `bon`-generated builder, beginning
with `exec(program)` and `start_job(program)`. This is an intentional source API break for Rust
callers of this crate: `onec-access` is an internal controller product, and its former
`exec_with_*` / `job_start_with_*` wrapper families were removed. No synchronous compatibility
facade remains. The builder migration changes neither the CLI contract nor agent wire semantics.

## Controller access setup

Configure the hub once on the operator machine. For a durable workstation, keep the operator token in a private file beside the toolkit config rather than requiring every shell to export it:

```bash
onec-access configure \
  --url https://ops.example.com \
  --gateway gateway.example.com \
  --gateway-user operator \
  --identity ~/.ssh/onec-operator \
  --known-hosts ~/.ssh/known_hosts \
  --token-file secrets/operator.token

onec-access check
```

Relative token-file paths resolve beside the OS-native `onec-access` ProjectDirs controller config (`~/.config/onec-access/controller.json` on ordinary Linux, `%APPDATA%\onec-access\config\controller.json` on Windows). `--token-env` remains available for ephemeral/operator-managed environments. The token value itself is never stored in `controller.json`, and there is no per-server local registry entry.

The local configuration is written canonically with an ordered `gateways` array. Older
single-gateway `gateway_host` / `gateway_user` / `gateway_port` files are read and migrated on the
next write. Authenticated hub `/v1/info` topology takes precedence; the local list is used only when
an older hub omits `gateways`. Hub-supplied host keys are checked as exact Ed25519 pins. Legacy
fallback endpoints use the configured `known_hosts` file with strict checking.

Per-target effect ceilings and the `target-effect` subcommands are retired. Every
authenticated enrolled host uses the same controller authorization model.
`run-local --required-effect` still labels an invocation's effect for
correct lease and owned-resource handling; it is not a separate host privilege.
Legacy `target_max_effects` config is validated on read but omitted on write.
Production infobase restrictions, scoped cleanup, active-job deferral and exact
artifact verification remain independent of this controller setting.

Embedded controller operations use the approved gateway list in order during SSH and channel
establishment. Each connection phase is bounded: gateway SSH connect/authentication, gateway
`direct-tcpip`, target SSH handshake/authentication, and the target agent-control channel each have
a five-second limit. Failures identify the phase and elapsed milliseconds without returning route
addresses, usernames, or key material. SFTP channel/subsystem initialization has a separate
ten-second bound; an explicit SFTP rejection keeps its typed unsupported outcome. A failed route
is closed before the next approved route is tried. The interactive SSH gateway-admission probe
keeps one ten-second deadline per route across
gateway connect/authentication, reverse-channel open/shutdown, and session disconnect confirmation.
If cleanup cannot be confirmed inside that deadline, admission fails without trying another route.
Once a channel is returned, controller protocol operations are sent once and are not
replayed through another edge. Generated `sync-ssh` configuration creates a separate alias for each
approved gateway. Manually invoked OpenSSH still uses the configured primary `ProxyJump`. The
`onec-access ssh` command first probes the target reverse listener through approved gateways in
order, then starts one interactive OpenSSH session through the selected gateway. It does not retry
the target session after launch. Fleet and automation access uses embedded multi-edge transport.

## Enrollment and legacy migration mechanisms

Server installation and recovery runbooks follow the [source and infrastructure boundary](../../docs/remote-agent-testing.md#source-and-infrastructure-ownership). The contracts here describe the maintained source mechanisms and their test obligations.

`invite` requires six direct artifact pins: `--direct-installer-url`, `--direct-installer-sha256`, `--direct-package-url`, `--direct-package-sha256`, `--direct-package-version`, and `--direct-package-target`. There is no default or `latest` lookup. Script and ZIP URLs must be credential-free, immutable HTTPS URLs on the same origin with no redirects, and the ZIP filename must match the explicit supported Windows triple. The controller checks the normalized installer SHA-256 against both the supplied pin and its embedded script before creating the one-use token. The ZIP SHA-256 is trusted input rather than a downloaded sidecar. The generated PowerShell command prompts for the token separately, keeping it out of `-EncodedCommand` and process argv. The verified candidate handles enrollment. `user-session` uses per-user persistence; `windows-service` requires elevation and executes under LocalSystem. The optional embedded-SSH candidate switch selects the existing carrier preflight; it does not relax package or identity checks.

`migrate-runtime` preserves the enrolled config, secret and known-hosts rather than minting an invite or re-enrolling. It requires the same six direct pins and supports only already-enrolled online Windows user-session targets; a known persistence mismatch or `windows-service` migration fails closed. Old `--release-id` and `--release-manifest-sha256` flags are rejected. A pre-unified agent may advertise `exec.argv-v1` without `exec.bounded-v1`; only this migration bridge can use the private legacy-compatible Exec request with a controller deadline. Ordinary Exec still requires `exec.bounded-v1`. The target verifies the normalized installer hash before staging and uses WMI `Win32_Process.Create` for the detached existing-config installer. Active-job deferral, writer locks, exact candidate checks and rollback remain updater-owned.

The migration receipt binds the selected package version/digest and positive detached PID. It proves accepted process launch only; installation, reconnection and exact installed executable identity need independent observations. An ambiguous request outcome must not be replayed. A detached installer failure may create the exclusive, reparse-safe `agent/migration-last-failure.json` with only `phase`, allowlisted `error_type`, and installer `line`; it excludes exception text and arguments and preserves an existing diagnostic. Its `finally` block owns migration temporary-file cleanup.

`migration-report` is read-only. It classifies a live agent from its complete current capabilities, retains unreachable/incomplete inventory as unknown, and reports whether the supported persistence/Windows migration preconditions hold. It never invokes migration. This compatibility implementation remains available for source development and regression tests; it does not define a fleet rollout policy.

`onec-access list` and `migration-report` resolve Hub routes for up to eight enrolled agents concurrently, while authenticated agent `Hello` probes remain limited to two simultaneous connections. Both commands preserve sorted output. In `list`, `status=online` means an authenticated agent `Hello` responded at the reported `observed_at_unix_ms`; `status_scope=point_in_time` makes clear this does not guarantee that a later SSH channel or `exec` will succeed. A failed Hello is reported as `status=unknown`, because transport failure cannot establish that the agent itself is offline. `persistence_mode_source=hub_enrollment` identifies Hub-provided enrollment metadata separately from the live Hello observation. Failure rows retain the existing `error` key but its text is a bounded, sanitized diagnostic; `failure_phase` identifies the route stage. Both commands remain read-only with respect to managed targets and do not execute a probe command.

```bash
onec-access list
onec-access info accounting-01
onec-access verify accounting-01 --json
onec-access sync-ssh
onec-access ssh accounting-01 -- hostname
onec-access exec accounting-01 -- cmd.exe /c whoami
onec-access exec accounting-01 --secret-env ONEC_OPS_IB_PASSWORD=ONEC_ACCOUNTING_PASSWORD -- onec doctor
onec-access exec accounting-01 --stdin-file request.bin -- tool.exe --consume-stdin
onec-access exec accounting-01 --result report.json=1048576 --result-dir ./results -- tool.exe --write-result
ONEC_ACCESS_TARGET=accounting-01 onec-access run-local --required-effect run-owned --map-file-env NEXTEST_BIN_EXE_onec -- ./native_run_owned.exe --list
ONEC_ACCESS_TARGET=accounting-01 onec-access run-local --required-effect read-only --map-file-env NEXTEST_BIN_EXE_onec -- ./native_readonly.exe --list
ONEC_ACCESS_TARGET=accounting-01 onec-access run-local --required-effect disposable --map-file-env NEXTEST_BIN_EXE_onec -- ./native_disposable.exe --list
onec-access exec accounting-01 --secret-env TOOL_PASSWORD=ONEC_ACCOUNTING_PASSWORD --stdin-file request.json --result report.json=1048576 --result-dir ./results -- tool.exe --consume-stdin --write-result
onec-access job start accounting-01 -- onec doctor
onec-access job start accounting-01 --secret-env ONEC_OPS_IB_PASSWORD=ONEC_ACCOUNTING_PASSWORD -- onec doctor
onec-access job start accounting-01 --stdin-file request.bin -- tool.exe --consume-stdin
onec-access job start accounting-01 --result report.json=1048576 -- tool.exe --write-result
onec-access job start accounting-01 --secret-env TOOL_PASSWORD=ONEC_ACCOUNTING_PASSWORD --stdin-file request.json --result report.json=1048576 -- tool.exe --consume-stdin --write-result
onec-access job result accounting-01 <job-id> ./results --cleanup
onec-access upload accounting-01 ./payload.bin 'C:\\Temp\\payload.bin'
onec-access download accounting-01 'C:\\Temp\\result.dt' ./result.dt
onec-access probe accounting-01 127.0.0.1 1545
onec-access rdp accounting-01
```

`onec-access exec` and `onec-access job start` accept repeatable `--secret-env KEY=SOURCE_ENV`. The CLI never accepts plaintext secret values: the controller validates all mappings, reads the named local process environment variables, and sends resolved values only through authenticated `SecretEnvironment`. Ordinary `--env` and secret mappings for the same target variable are rejected before host lookup; missing, non-Unicode, or empty source variables fail locally. Agents must advertise `exec.secret-env-v1` / `jobs.secret-env-v1`; immediate output and durable logs redact exact secret bytes, and durable job state/request metadata never persist the reusable value.

`onec-access exec` and `onec-access job start` also accept optional `--stdin-file PATH`; use `--stdin-file -` to read one payload from controller stdin. Input is exact binary data, limited to 256 KiB before any remote request. Agents advertise `exec.stdin-v1` / `jobs.stdin-v1`; controllers fail closed before execution when the matching capability is absent. Stdin is non-secret operation data, not a credential channel.

For interactive `onec-access ssh` commands targeting Windows, the controller checks the complete final encoded command before gateway probing and rejects commands longer than 8000 encoded bytes. This is a conservative supported-route limit that reserves space within the default 8191-character `cmd.exe` command-line envelope; the configured OpenSSH server shell can differ, and this limit does not assert or inspect a remote shell registry setting. Use `onec-access upload` for a file or script. Use `onec-access exec --stdin-file` only when the selected program is verified to consume stdin. The diagnostic reports encoded length only and never includes command arguments. POSIX interactive commands are not subject to this Windows limit.

Do not send PowerShell 2 scripts through stdin with `-Command -` or `-File -`; native NT 6.1 runs returned exit 0 without the required completion marker. Stdin remains suitable for exact binary payloads to consumers verified to read it, such as `sort.exe`. For short, non-secret PowerShell scripts up to 4096 UTF-16LE source bytes, use `-EncodedCommand` with a completion marker after the caller-specific postcondition. Base64 is encoding, not secrecy, and the command is visible in process arguments. Longer or secret scripts must use an explicitly uploaded, owned `.ps1` path with `-File <path>` and an independent postcondition check. See the [legacy Windows PowerShell execution contract](../../docs/legacy-windows-compatibility.md#powershell-script-execution-and-stdin).

`onec-access exec` and `onec-access job start` accept repeatable `--result NAME=MAX_BYTES` declarations. Immediate Exec requires `--result-dir DIR` for controller-local publication; durable results are retrieved after terminal completion with `onec-access job result NAME JOB_ID DIR [--cleanup]`. Result retrieval binds to the original Exec/JobStatus metadata and verifies exact name, byte count, SHA-256 and media type before publication.

`exec` and `job start` are trusted arbitrary process execution under the authenticated Agent
account. They send a program and argv without controller-side shell interpolation, but they do not
sandbox the process: callers can invoke interpreters, scripts, or encoded commands. Policy for
arbitrary commands belongs to the authenticated caller; no general shell parser or command
denylist constrains filesystem effects. Interactive OpenSSH is a separate boundary that encodes
the remote command as one shell string for the selected target OS; this does not guarantee the
semantics of arbitrary caller-authored shell scripts. Toolkit-owned recursive cleanup must use the
typed `filesystem.scoped-remove-v1` / `PathRemoveScoped` operation, which requires the target to
be a strict child of an explicitly declared root and validates path components on the Agent. If
ownership cannot be proven, preserve the staging path for inspection.

`onec-access run-local` is the generic Cargo/Nextest target-runner boundary. It resolves the
managed target from `--target` or `ONEC_ACCESS_TARGET`, validates every controller-local file
before target resolution, then resolves its canonical machine identity through the authenticated
hub and checks `--required-effect` against that machine's controller-local ceiling before creating
an agent client, checking agent capabilities, preparing a run, staging files, or executing. The
`--required-effect` is mandatory; the accepted values are `read-only`, `run-owned`, and `disposable`.
Only the selected target's ceiling is consulted. Run-owned and disposable execution acquires a
controller-local cross-process lease keyed by the exact Hub machine identity, so independent
Nextest invocations cannot execute mutable tests against the same managed target concurrently.
Canonical Nextest inventory argv (`--list --format terse`, optionally followed by `--ignored`)
receives a bounded wait matching the run-local staging ceiling (currently 540 seconds) for that
same lease, so concurrent Nextest controllers queue
instead of failing on the ordinary 100-millisecond contention timeout. Inventory still holds the
lease for its complete mutable run-local execution and is rejected when a durable reservation is
active; argv never bypasses admission, regardless of the selected executable. Other mutable argv
uses the ordinary bounded wait. Target identity resolution and the required-effect ceiling check
still happen before admission and before remote agent contact. Read-only execution remains
concurrent. It stages the
executable and each repeatable `--map-file-env KEY` value
into an agent-owned immutable SHA-256 cache, and executes the verified staged executable with the
remaining argv unchanged. A cache entry is reusable only after the remote byte count and SHA-256
match; publication never overwrites a claimed digest, so concurrent publishers converge on the
same verified object. Staging receives 180 seconds per selected artifact, up to a 540-second
wall-clock ceiling for the complete sequential stage. Cache admission, transfer, and verification
share that deadline; no phase can extend it or trigger an automatic retry after timeout. The
opt-in run-local timing line reports selected artifact count, aggregate bytes, and the allocated
deadline. `run-local-job start` uses the same per-artifact allocation and hard ceiling for its
executable and mapped files. Each invocation receives a unique agent-owned working directory that is
removed with scoped cleanup; the immutable cache is not part of per-run cleanup.
For a durable start that must not upload a candidate, `run-local-job start --require-cached-candidate`
checks the exact candidate path in the Agent-owned cache with `PathSha256`, verifies byte count and
SHA-256, and checks the identity again immediately before job submission. Missing, unreadable, or
mismatched entries fail without opening an upload; `--map-file-env` is rejected because mapped
files require transfer. Without this flag, existing cache reuse and upload-on-miss behavior is
unchanged. The option does not change durable job ownership or execution effects.
A `PathRemoveScoped` request (including the general `remove-scoped` API)
gets at most one additional approved-route pass only when typed transport
evidence proves that no Agent request was submitted. The Agent still enforces
the supplied owner-root containment and `missing_ok` value. This is
bounded by the 30-second cleanup deadline; ambiguous post-submission failures
never replay deletion and leave cleanup unconfirmed for explicit recovery.
Cache admission permits one fresh SSH route pass for a read-only `PathSha256` probe only
when **every** approved route failed in a typed transient pre-request establishment phase.
A host-key rejection, opaque route failure, or transport failure after possible request
submission does not trigger this retry. The second probe must independently return the
exact remote byte count and SHA-256 before cache reuse; all unknown identities still fail
closed, skip upload, and are never reported as a cache miss.
Cache admission failures remain fail-closed and skip upload. Diagnostics name only the safe cause
category (for example, an opaque legacy Agent response, unavailable or denied TargetSftp, timeout,
or transport failure). A gateway-control-only carrier cannot provide independent TargetSftp
absence evidence for old untyped Agent replies and reports that prerequisite explicitly,
without retrying upload. When an old Agent's opaque `PathSha256` response cannot be resolved because
pinned TargetSsh `lstat` is unavailable or fails, upgrade the Agent to a version that returns typed
`PathNotFound`, or restore working pinned TargetSsh SFTP before retrying. Authenticated `exec` is not
used to infer absence: it cannot provide the Agent-side structural path and reparse checks needed
for this proof. Diagnostics do not print upstream error text, credentials, or remote paths.

Runner stdout contains only the remote child's bounded, secret-redacted stdout bytes; child stderr
is forwarded to stderr and the `onec-access` process returns the remote exit code. Setup/transport
diagnostics are written to stderr. Immediate execution remains bounded by the agent's existing
256 KiB-per-stream safety ceiling; exceeding it fails the run rather than returning truncated test
listing output. Ordinary `onec-access exec` keeps its 60-second default, while `run-local` uses
the Agent protocol's 10-minute maximum only as an outer emergency ceiling. Repository Nextest
configuration owns the earlier native per-test timeout. Exec control channels remain write-open
until the response so controller/runner termination is observable by the Agent; connection
EOF/reset cancels and reaps the owned process tree instead of leaving a detached remote test.
`run-local` therefore reuses the existing immediate-exec raw-output/process-tree and secret
redaction invariants instead of defining another remote runner protocol.

For source-exact commands that may outlive their controller connection, use
`onec-access run-local-job start|status|logs|cancel|results|attest|cleanup`. `start` requires the
`jobs.local-candidate-v1` Agent capability before remote preparation or upload and prints a
controller-generated run ID for reconnecting. Mapped files are verified and retained in that
job's prepared workspace; the executable may use the immutable content cache. Mutable run
reservations survive controller exit and block competing mutable immediate or durable run-local
execution on the exact managed machine until terminal results and scoped workspace cleanup
complete. Disconnect does not cancel; `cancel` explicitly requests Agent-owned process-tree
cancellation. If start failed before a job was recorded, `cleanup --abandon-unstarted` asks the
Agent to prove no job owns the run ID before removing its prepared workspace. Use
`run-local-job list-reservations <managed-target>` to recover pending run IDs or inspect the
Agent-job binding when controller output was interrupted. See [durable local-candidate lifecycle evidence](../../docs/incidents/native-testing-records.md#durable-local-candidate-lifecycle)
for the operator sequence.

The explicit `run-local-job start --native-effect run-owned|disposable` option selects the
Agent-native invocation-observation mode. It independently checks the selected effect against the
managed-target ceiling, requires `native-invocation-observation-v1`, rejects secret environment
bindings, computes the shared protocol `NativeInvocationIdentity::sha256()`, and persists that
commitment in the private durable reservation before `NativeRunLocalJobStart`. It never falls back
to ordinary `JobStart`. Read-only durable jobs remain prohibited by the durable mutable reservation
contract. The standard `start` flow without `--native-effect` is unchanged.

An additional explicit opt-in, `--native-suite-policy <JSON>`, sends a typed
`NativeSuitePolicy` with that same native start request. It requires
`--native-effect`, and the client checks the policy's runner SHA, exact argv,
ordinary environment and effect against the candidate launch before staging.
Mapped environment and result artifacts are not supported with this policy
because they are outside its approved launch fields. The canonical policy SHA
is included in the durable invocation identity, and the Agent independently
admits the request only when its configured administrator pin matches. A
missing pin or rejected/unsupported policy is an error; there is no policy-free
retry. The client requires the `native-suite-policy-admission-v1` capability
from Agent Hello before sending the policy request; Agents that only advertise
`native-invocation-observation-v1` are rejected before job start. The Agent
then independently checks its pin and exact launch fields. This authorization
does not prove that listed tests ran or passed and does not grant native suite
or release acceptance.

```sh
onec-access run-local-job start --target <managed-target> \
  --required-effect run-owned --native-effect run-owned \
  --native-suite-policy approved-suite-policy.json \
  -- ./native-runner.exe run --exact suite::case_a suite::case_b
```

The JSON file uses protocol type `NativeSuitePolicy`: `version`,
`runner_sha256`, `args`, `env`, sorted complete `expected_tests`, and `effect`.
Its canonical digest must already be pinned in the Agent's administrator-owned
configuration.

The signed protocol-v1 invocation observation retains the Agent binary's `host_os` and
`host_arch`. Windows Agents additionally sign live kernel version/build, process architecture,
native machine architecture, and `IsWow64Process` outcome. Those facts distinguish an NT 6.1
kernel and x86-on-x64 execution, and the controller rejects facts inconsistent with the signed
host identity. Older signatures remain verifiable when this optional field is absent. This is
observation evidence only; it does not select a release lane or classify a host as a release pass.

Example explicit opt-in (the durable target authorization and the Agent-declared effect are
checked independently):

```text
onec-access run-local-job start --target <managed-target> \
  --required-effect run-owned --native-effect run-owned -- ./candidate.exe --exact suite::test
```

For the standard `JobStart` flow without `--native-effect`, after terminal success retrieve results
(which also cleans the remote result set), then collect its one-time terminal attestation:

```text
onec-access run-local-job results <managed-target> <run-id> <local-results-dir>
onec-access run-local-job attest <managed-target> <run-id> --challenge <fresh-challenge> \
  --trusted-public-key <independently-pinned-ed25519-key.hex>
# Only after an interrupted attest request, with the exact same challenge and pinned key:
onec-access run-local-job recover-attest <managed-target> <run-id> --challenge <fresh-challenge> \
  --trusted-public-key <independently-pinned-ed25519-key.hex>
```

The pinned key file contains exactly 32 Ed25519 public-key bytes as 64 hexadecimal digits. The
controller compares it to the Agent's separately returned public key, checks its SHA-256 signer
ID, binds the record to the controller reservation's exact machine/run/job and candidate digest,
and verifies the protocol's `agent-native:v1` canonical signing bytes. After the read-only pinned-key
check and before the one-shot cleanup/sign request, the controller creates a private empty pending
marker. The Agent request removes the owned run workspace and is single-use. If its response is
lost, never retry `attest`; run `recover-attest`
with the original challenge and pinned key. Recovery only fetches an already-created signed
record for the exact job. Missing/corrupt remote data, a changed challenge, or a network error
preserves the pending marker and durable reservation. A verified receipt is atomically published
create-new with private permissions under the controller's OS-native `onec-access` data directory
before reservation release; an existing non-empty receipt is never overwritten. It is a process
observation only; it does not represent release-native test results or a managed acceptance receipt.

Native invocation mode uses a separate signed record and commands:

```text
onec-access run-local-job results <managed-target> <run-id> <local-results-dir>
onec-access run-local-job observe-invocation <managed-target> <run-id> \
  --challenge <fresh-challenge> --trusted-public-key <independently-pinned-key.hex>
# Only after an interrupted observe request, using its exact challenge and pinned key:
onec-access run-local-job recover-invocation <managed-target> <run-id> \
  --challenge <fresh-challenge> --trusted-public-key <independently-pinned-key.hex>
```

Observation verifies the pinned Ed25519 signature and the reserved machine/run/job, candidate and
canonical invocation SHA-256, declared effect, challenge, terminal success with exit code zero,
completed local result cleanup, and Agent-owned run-root cleanup. New protocol-v1 records also sign
the SHA-256 and exact byte length of each complete Agent-owned redacted stdout/stderr log; the Agent
worker records an immutable completion commitment before successful terminal publication, and the
Agent rechecks the files against it during signing and read-only recovery. The controller rejects malformed or
oversized signed commitments. These digests identify retained output bytes only: they do not prove
that Nextest or another runner executed test cases or that any test passed. Older signatures without
the optional output commitment remain verifiable with their original canonical bytes. The receipt
keeps its explicit `observation_only` label and is never converted to release v2. It creates a
private one-use pending marker before the signing request and never retries that request after an ambiguous outcome;
recovery sends only the Agent's read-only fetch operation. Its receipt is explicitly observation-only,
is an Agent process observation only and cannot produce a managed acceptance receipt.

To check two complete log files that were already copied to the controller, use the offline verifier
with the stable Hub machine ID from the operator's independently pinned target inventory, the exact
run ID and challenge, and the same independently pinned public key. It reads the durable job binding
from the controller's private local state; it does not resolve the
machine through the Hub or contact a managed host. The key is never taken from the receipt, and a
receipt from an older record without signed output-log hashes is rejected.

```text
onec-access run-local-job verify-invocation-logs <run-id> \
  --machine-id <independently-pinned-machine-id> \
  --challenge <original-challenge> \
  --trusted-public-key <independently-pinned-key.hex> \
  --stdout-log ./agent-stdout.log --stderr-log ./agent-stderr.log
```

Each local log must be a private regular file no larger than 8 MiB. The verifier opens without
following links, reads each file twice through the same verified file identity, and checks path
metadata around those reads before comparing exact lengths and SHA-256 values with the signed
record. The copied files may be untrusted; an exact match cryptographically binds their bytes to the
Agent-signed hashes. It does not prove that libtest executed or that tests passed. The command reports
`observation_only`; it cannot create an accepted release receipt or report a release PASS.

To verify a local copy of one result artifact against the Agent-published result metadata signed in
that same invocation record, use the offline result verifier. It reads the durable machine/run/job
reservation and invocation candidate/digest/effect from controller-local private state, then checks
the Agent Ed25519 signature with the separately supplied key. It does not contact the Hub or Agent,
download files, interpret JUnit, or treat the artifact as a test result. Older signed v1 records
without a result set are rejected for this command.

```text
onec-access run-local-job verify-invocation-result <run-id> \
  --machine-id <independently-pinned-machine-id> \
  --challenge <original-challenge> \
  --trusted-public-key <independently-pinned-key.hex> \
  --artifact-name <exact-portable-name> \
  --artifact-file ./local-result-file
```

The requested exact name must occur once in the signed typed result set, whose owner must match the
reserved job. The private regular local file must have the signed byte length and SHA-256; the
verifier streams and repeats its digest while checking file identity and path metadata, with the
protocol's 512 MiB per-artifact ceiling. Successful output says `observation_only` and
`authenticated_result_bytes:true`; it authenticates the bytes only and does not produce a release
acceptance receipt or release PASS.

The new machine appears because `onec-access list` asks the hub; no `remote add` is necessary. New enrollment records also retain the selected managed persistence mode (`user-session` or `windows-service`) as non-secret inventory metadata, so controller diagnostics can explain an offline logon-scoped host without contacting the missing agent. Older records remain readable and simply have no persistence value until compatible re-enrollment. To decommission a machine, use `onec-access remove accounting-01`; hub-backed removal deletes the fleet record and removes that machine's restricted gateway SSH key.
