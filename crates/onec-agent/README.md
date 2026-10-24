# HostLink Agent

`onec-agent` is the extracted runtime-side component of HostLink for managed Windows and Unix
hosts. Its package and executable names remain historical compatibility identifiers because the
workspace lockfile and installed service/process contracts are owned outside this crate slice.
They are not HostLink domain APIs.

It is intentionally separate from the `onec` controller:

- `onec-agent` owns connectivity and a minimal remote-control protocol.
- `onec` owns the controller/orchestration CLI and composes the focused domain/backend crates.
- the customer server does not need the toolkit repository or Rust toolchain.
- the control listener is loopback-only.
- connectivity is outbound: the agent maintains an SSH reverse tunnel to a gateway.
- individual TCP endpoints can be proxied on demand; RAS/RAC or whole port ranges are not exposed by default.

## Compatibility and extraction status

This extracted source still carries the legacy pinned `onec-toolkit-<target>.zip` installer and
updater. That path is retained for migration compatibility and still expects the historical
`onec.exe` bundle member. It is not an independent HostLink Agent bootstrap/update package, and
must not be used as the HostLink package contract. A separate exact-digest Agent-only bootstrap
and updater is pending. Do not infer existing-host migration or service takeover from generic CLI
wording.

The embedded SSH server currently supports SFTP and direct TCP forwarding. SSH `exec` and `shell`
requests remain rejected. Safe generic command execution still needs an owned process-tree
lifecycle with exact exit status, stdout/stderr handling, stdin policy, and timeout/cancellation
coverage before SSH hooks can use it.

The neutral `hostlink-core` crate is being supplied by the sibling extraction slice. The Agent
still depends on `onec-core` until that API is available. The Agent requires neutral equivalents
for bounded file/JSON/line reads; private file and directory validation/creation; atomic file
publication and scoped removal; exclusive file locking; SHA-256 and digest parsing; retained and
redacting log writers; owned process/background command setup; Windows command-line encoding;
constant-time string comparison; hostname lookup; and Unix timestamps. Core API integration and
its compatibility tests remain pending.

## Current MVP

The agent supports:

- `hello` / `status`;
- exact executable + argv/cwd/non-secret environment execution without implicit shell interpolation;
- typed file upload/download/hash/scoped-remove/rename operations, so structured Windows paths never need `cmd.exe` quoting;
- persistent `jobs-v1` execution with durable state/logs, reconnectable status, explicit argv/cwd/environment, and process-tree cancellation;
- TCP reachability probes;
- raw TCP stream forwarding for one explicitly requested target;
- exact-length file upload/download, with staged overwrite publication;
- one pinned in-process `russh` reverse-tunnel transport;
- automatic reconnect after the SSH session closes or fails;
- bounded ownership of forwarded SSH channels; shutdown cancels and drains every active bridge;
- bind-before-tunnel startup, so a duplicate agent cannot create a competing reverse forward;
- native Windows Service installation/removal without NSSM or WinSW.

The control protocol is JSON-lines for control messages, then switches to raw bytes after a successful `tcp_connect`.

### Native terminal attestation building block

The authenticated control operations `native_attestation_public_key`, `run_local_attest`, and
`run_local_attestation_fetch` expose a dedicated Ed25519 signer, separate from SSH host identity.
The key is
stored below the private agent jobs directory as a create-once file restricted to the current
user (Unix mode `0600`; Windows protected user ACL); export returns only
the verifying key and its SHA-256-derived signer ID. Pin that public key out of band. The signer
accepts only a durable `run-local` job ID and a bounded challenge: it reads the agent's persisted
terminal state, requires `succeeded` with exit code zero, requires declared result artifacts to
have been retrieved and cleaned, removes the exact owned run workspace, and then creates one
durable signed receipt per job. `run_local_attestation_fetch` reads only that existing bounded
private record, checks exact job/run/executable ownership and the stored signature, and never
creates a key or signs again. Failed, canceled, interrupted, non-run-local, nonterminal, or
uncleaned jobs cannot produce a success signature. This terminal receipt contains no stdout or
caller-supplied PASS field.

This is a bounded agent-owned process observation, not a managed release acceptance receipt. It binds the run ID,
agent job ID, candidate executable SHA-256, fresh verifier challenge, observed terminal success,
owned cleanup, and signer ID. A separate `native-invocation-observation-v1` capability is available
for jobs started through `native_run_local_job_start` with a closed `native_effect` value. Agent stores a SHA-256
commitment to the exact structured invocation (program, argv, cwd, non-secret environment, stdin,
declared results, run-local identity, and declared effect) before worker spawn. The worker
recomputes it from the persisted request before launching and rechecks the staged candidate bytes.
The observation request supplies a fresh challenge and the expected invocation digest; signing
requires the exact durable job, exit code zero, non-truncated bounded logs, cleaned declared
results, the unchanged invocation commitment, the candidate digest still matching the cache file,
and successful scoped run-root removal. The signed record binds the invocation digest, candidate
digest, declared effect, Agent build architecture/OS, terminal exit, cleanup, challenge, job/run IDs,
signer, and stdout/stderr byte SHA-256 commitments with exact retained lengths. After ProcessKit has
drained and finalized both Agent output sinks and `ResultWorkspace::finalize_into` has published
the declared result bytes, the worker stores one private create-new completion commitment before
publishing successful terminal state. It binds the exact run-local job identity, complete output
log commitments, and optional canonical `ResultSetInfo`. The signer checks that the result owner
and ordered artifact declarations match the immutable pre-spawn invocation commitment, that the
worker-sealed manifest equals terminal job state, and that the controller retrieved and cleaned
the published result files. The signed protocol-v1 invocation record includes this optional
manifest; old records omit it and retain their original canonical signing bytes. A missing worker
seal or any result-manifest mismatch fails closed. Read-only recovery revalidates the worker seal,
terminal manifest, and signature after result bytes have been cleaned; it never signs again.
The signer compares each complete private regular log (up to the existing 8 MiB durable-log
ceiling) with that worker commitment and checks the same bytes again around signing. Missing,
changed, unsafe, or storage-truncated logs fail closed.
The log reader uses a no-follow file handle and verifies the opened file still matches its
pathname before and after hashing (Unix device/inode, Windows volume/file ID). The Windows reader
also denies concurrent write/delete sharing while its handle is open. Equal-size pathname swaps
are not evidence of the same signed log; the record is never issued when ownership changes.
Read-only recovery verifies the stored signature and rechecks the on-disk files without signing
again. Older protocol-v1 records without output commitments retain their original canonical
signature bytes.

When immutable argv contains exactly one canonical libtest `--exact <name>` pair, the Agent also
places that bounded requested filter in the signed `requested_exact_testcase` field. The Agent
derives it while creating the pre-spawn commitment; the worker recomputes the invocation digest
and filter from the persisted request before launch, and read-only recovery checks the signed value
against that commitment. The record binds the requested filter to the process exit and cleanup
observation. A zero exit does not prove that a matching test existed or ran. A verifier still needs
an independently approved inventory and the pinned test-binary identity to compare the request
with policy. Missing, ambiguous, listing, and skip selectors are omitted. This does not prove a
complete suite run: Nextest still runs on the initiating host, so the Agent does not own the
scheduler or observe its complete inventory and terminal summary. No stdout/JUnit test claims are
signed.

The administrator-pinned `NativeSuitePolicy` currently gates only admission of an exact
candidate SHA, argv, environment, effect, and expected-test inventory. The Agent reconstructs the
canonical policy from its durable request and checks the digest again before any executable launch;
missing fields, a changed candidate identity, or a tampered inventory fail the owned job. This is
launch-policy integrity only: the Agent does not claim that test cases ran, and stdout or a libtest
summary is not suite evidence. Existing v1 attestation still covers only process completion and
scoped workspace cleanup. No suite-result RPC or capability is exposed, and this policy path is not
the managed release acceptance receipt required for promotion.

The result digest proves only which bytes the Agent published. It does not prove tests executed or
that a test report represents a passing run. The effect is caller-declared and must be checked
against independently pinned policy. The
architecture/OS identify the Agent build/runtime category and do not prove Windows release class,
source commit, toolchain, 1C platform, or test behavior. This protocol intentionally carries no
suite inventory, aggregate test count, or suite outcome: it observes one exact structured
invocation and does not turn stdout, output digests, or a caller's suite label into test evidence.
Output digests identify only the bounded redacted bytes retained by the Agent; they do not prove
test-case execution, outcomes, or release success. This is an Agent process observation only and
cannot produce a managed release acceptance receipt. Current `onec-access run-local-job attest`
still collects the older `agent-native:v1` receipt. Recovery fetch verifies and returns only an
already persisted signed observation; it never creates a key or signs again. Both Agent record
formats use distinct versioned domains and length-prefixed JSON, with no claim of byte compatibility
with managed-release acceptance receipts.

The agent control secret is read from an environment variable/secret file on the target and immediately wrapped in `secrecy::SecretString`; Debug is redacted and plaintext access is explicit only at the constant-time protocol-authentication boundary. It is supplied ephemerally by `onec-access` after authenticated retrieval from `onec-hub` and is never persisted in project topology or job state. A normal job launch request briefly stages its exact executable/argv/cwd/non-secret environment in the private job directory until the detached worker claims it, then deletes that request file. `onec-access exec/job --env` remains non-secret operation context and must not carry credentials.

The wire protocol retains a separate internal `secret_env` field for trusted controller integrations that need secret process environment without serializing it as ordinary job context. The public `onec-access --env` surface does not expose credential mapping through this field. Immediate exec applies secret values only to the child and redacts exact secret bytes from stdout/stderr. Persistent jobs never serialize `secret_env` into `request.json` or state: the serving agent passes it only in the detached worker process environment, the worker removes its internal carrier variable before launching the child, and stdout/stderr are streamed through exact-byte redaction before durable logs are written. Agents advertise `exec.secret-env-v1` / `jobs.secret-env-v1`; consumers fail closed rather than downgrading a reusable secret to ordinary environment.

`jobs-v1` remains the target-side durability boundary rather than a controller-timeout convenience. The detached worker owns transient secret injection, bounded/redacted durable logs and terminal state across controller disconnects and serving-agent restarts. The actual job child process tree is delegated to ProcessKit, which confirms owned-tree exit and drains/finalizes durable output before terminal publication; jobs no longer maintain a second SIGTERM/`taskkill /T` tree-kill implementation. Windows Task Scheduler was prototyped as a replacement owner: it can detach, reattach, expose registered-task state/last result and stop/delete the registered task instance, but native Windows acceptance proved that a descendant process can survive successful task stop/delete. Its ExecAction contract also has no per-run secret environment or stdout/stderr stream ownership. Adopting it would therefore keep a worker/process-tree owner and add scheduler COM lifecycle code rather than remove the proven durability machinery. Controller-side MCP background jobs solve a different lifetime boundary and do not replace target-side reattach/no-replay semantics.

Toolkit-owned child process trees do **not** inherit the complete resident-agent environment. The optional TLS proxy helper, user-mode sshd host/direct sshd process, immediate `Exec`, and durable `JobStart` all start from the same safe OS/user base: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `TMPDIR`, `TEMP`, `TMP`, `LANG`, `LANGUAGE`, `TZ`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `LC_*`, the XDG config/cache/data/state/runtime roots, and on Windows the standard system/user/profile/program roots plus `COMSPEC`, `PATHEXT`, processor identity/count, `PSModulePath`, and related account/machine names. Proxy/auth/tool-specific variables, arbitrary service configuration, and the agent control secret are not ambient inputs. Structured Exec/JobStart may then layer authenticated non-secret request `env` and trusted `secret_env`; TLS-proxy/sshd children receive no request-specific environment layer. The configured control-secret env name cannot be supplied as ordinary request `env`; a trusted integration may intentionally pass a value under that name only through `secret_env`. Toolkit-internal job-secret/SSH-askpass carrier names are never caller-settable. Immediate Exec overwrites the reserved `ONEC_EXEC_DEADLINE_UNIX_MS` with its absolute deadline; callers cannot set it through either request environment. This lets `onec-1cv8` finish Designer timeout and owned-tree cleanup before the agent's outer Exec cancellation. Durable jobs write `ONEC_JOB_SYSTEM` / `ONEC_JOB_ID` after both request layers, so spoofed values cannot win. `ONEC_PARENT_RUN_ID` remains caller-owned correlation context.

The former generic `EnvironmentGet` / `environment.read-v1` control surface was retired once repository usage was removed. The safe-base contract is the single resident-agent child-process input policy for the optional TLS proxy/sshd helpers, `Exec`, and durable jobs. The installer-owned `path_prepend` contract remains effective because it updates the resident `PATH` before serving and that final PATH is copied into the safe base.

## Commands

```text
onec-agent check --config agent.json
onec-agent serve --config agent.json
onec-agent run          --config agent.json
onec-agent probe-tunnel --config agent.json --seconds 10
onec-agent install-service --config agent.json [--start]
onec-agent start-service
onec-agent stop-service
onec-agent service-status
onec-agent uninstall-service [--stop]
```

`agent.json` is a toolkit-owned versioned schema and rejects unknown fields at the root and nested SSH/TLS objects. Supported omitted fields continue to use documented defaults; misspelled or retired keys fail instead of being silently ignored.

`serve` starts only the loopback control endpoint. `run` additionally supervises the configured SSH reverse tunnel. `probe-tunnel` starts the same tunnel (and user-mode sshd when configured), verifies that both stay alive for a bounded interval, then terminates its owned children and exits; it is intended for deployment diagnostics. Windows service lifecycle is implemented with the `windows-service` crate rather than hand-written SCM FFI/`sc.exe`: `install-service` creates or validates the toolkit-owned auto-start service, configures restart-on-failure actions, and can start it; `start-service`, `stop-service`, and `service-status` expose typed lifecycle/status operations. Mutating service commands require administrator/service-control rights.

## Embedded target SSH candidate backend

`agent.json` may explicitly select the library-owned embedded target server with
`embedded_ssh_server`. It is mutually exclusive with the existing external `ssh_server` owner:

```json
"embedded_ssh_server": {
  "user": "managed-user",
  "host_key": "ssh_host_ed25519_key",
  "authorized_keys": "sshd_authorized_keys",
  "port": 27392
}
```

Relative key paths resolve next to `agent.json`. The host private key must pass the same
toolkit private-file policy and both host/operator keys must be Ed25519. The server binds only an
already-owned loopback listener, authenticates the exact configured username against the enrolled
controller keys, provides SFTP for generic file bytes, and preserves authenticated TargetSsh
`direct-tcpip` forwarding with bounded connection/concurrency policy.

This backend is currently **opt-in candidate runtime** for 1C-373 validation. Ordinary managed
enrollment still emits the existing external `ssh_server` configuration and the proven NT 6.1
GatewayControl fallback remains unchanged. An explicit installer `-EmbeddedSshCandidate` switch
instead preflights the exact downloaded `onec-agent.exe` with real host-key verification,
public-key authentication, SFTP byte round-trip and `direct-tcpip` half-close forwarding before
`ssh_host_public_key` is advertised to the hub. The self-test uses its own ephemeral loopback
listener so an existing managed sshd can keep the final target port until cutover; normal agent
startup owns the final configured port and triggers the install rollback path if that bind fails.
That candidate path does not provision target
`sshd.exe`; it reuses PortableGit `ssh-keygen` only to create the same persistent
`ssh_host_ed25519_key`, then publishes final operator keys through `sshd_authorized_keys`. Candidate
failure is fatal rather than silently falling back. Universal promotion remains blocked on native
legacy-Windows acceptance.

## Reverse SSH configuration

The resident reverse tunnel is owned in-process by `russh`; `onec-agent` does not spawn
`ssh.exe` to keep the gateway connection alive.

```json
{
  "version": 1,
  "name": "example-target",
  "listen": "127.0.0.1:27391",
  "secret_env": "ONEC_AGENT_SECRET",
  "ssh": {
    "gateways": [
      { "host": "gateway-a.example.test", "user": "onec-agent", "port": 22 },
      { "host": "gateway-b.example.test", "user": "onec-agent", "port": 22 }
    ],
    "remote_port": 41001,
    "identity": "C:\\ProgramData\\onec-agent\\id_ed25519",
    "known_hosts": "C:\\ProgramData\\onec-agent\\known_hosts",
    "reconnect_seconds": 5
  }
}
```

The tunnel fails closed:

- the configured private identity must be an Ed25519 OpenSSH key;
- each gateway host key must match a line in the explicit shared `known_hosts` file; certificates are not accepted
  by this managed route;
- the server-side forward request binds only `127.0.0.1:<remote_port>`;
- incoming forwarded channels are accepted only for that exact loopback binding and only after the
  target loopback connection succeeds;
- forwarded-channel concurrency is bounded and all bridge tasks are owned, cancelled and drained
  with the SSH session;
- `russh` keepalives detect dead transports and the supervisor independently reconnects each
  gateway after `reconnect_seconds`. Every edge exposes the same stable `remote_port` on its own
  gateway host, so a failed edge does not interrupt a healthy edge.

Old `agent.json` files may still contain `ssh.program`. It is accepted only as legacy
deserialize-only residue and is not serialized or used to launch a client. Fresh enrollment omits
it. PortableGit/OpenSSH remains installed for interactive operator tooling, key generation and the
separate target-side `sshd` compatibility path.

When direct SSH egress is unavailable but an edge intentionally exposes raw SSH behind TLS, the
optional `tls_proxy` keeps the established byte-stream contract:

```json
{
  "host": "ssh-edge.example.test",
  "user": "onec-agent",
  "port": 443,
  "tls_proxy": {
    "program": "C:\\Tools\\OpenSSL\\bin\\openssl.exe",
    "server_name": "ssh-edge.example.test",
    "alpn": "http/1.1"
  }
}
```

The agent owns `openssl s_client -quiet` as a bounded helper process and passes its stdin/stdout
directly to `russh::client::connect_stream`. SSH host-key pinning and Ed25519 client
authentication remain authoritative. This helper preserves the historical raw-TLS transport
semantics; it is not an HTTPS tunnel and does not turn the TLS wrapper into a second SSH client.

## Tunnel reliability and diagnostics

The no-admin Windows installation uses a hidden per-user PowerShell supervisor started from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. It restarts `onec-agent` after an agent exit, while `onec-agent` itself reconnects a failed SSH reverse tunnel every `reconnect_seconds`. `russh` keepalives detect a dead transport, and connection/forward-request failures are retried in-process rather than terminating the resident agent.

The supervisor must not self-update the toolkit while a durable `jobs-v1` worker is `queued` or `running`. The installed supervisor no longer parses durable-job JSON itself: the lifecycle wrapper asks the resident Rust agent for a read-only `__self-update --preflight` result before any process/service quiescence, and the actual Rust updater repeats the same job-state check after acquiring `update.lock`. A deferred result is retried after five minutes. This keeps job-state/update policy in one Rust owner and prevents a routine toolkit update from tearing down the control channel in the middle of a long 1C maintenance operation.

Managed installed-runtime updates replace the complete immutable `bin/` bundle: `onec-agent.exe`, `onec.exe`, `Run-OnecAgent.ps1`, `Update-OnecToolkit.ps1`, and `onec-toolkit-update.cmd`. The unified `onec.exe` provides the controller command surface, including project orchestration and metadata operations, on the managed host. A previously installer-owned `onec-ops.exe` is backed up with the other managed files, removed as part of successful publication, and restored if publication rolls back. If the old file cannot be removed, publication fails and restores the prior managed files. Mutable enrollment/config/SSH/jobs/log/lock state stays outside that bundle. `self_update` owns exact archive digest verification, extraction, candidate verification, same-parent directory replacement and rollback-on-swap-failure. `Update-OnecToolkit.ps1` is only the Windows lifecycle handoff around that Rust operation. Existing user-session persistence still executes `scripts/Run-OnecAgent.ps1`; after a successful bundle replacement the lifecycle wrapper refreshes that compatibility projection from the new immutable bundle.

The hidden `__self-update` mechanism accepts an exact archive through `--archive-url` or `--archive-file`, together with `--archive-sha256`, `--package-version`, `--target` and the installed `--root`. These flags are an implementation contract for infrastructure and regression tests. Operational installation follows the [source and infrastructure boundary](../../docs/remote-agent-testing.md#source-and-infrastructure-ownership).

Exactly one archive source is required: HTTPS URL, or an absolute ZIP path staged under the toolkit root. Local archives must be regular files with no symlink/reparse path components. Exactly one archive source and all three package identity values are required. The target must match `install.json`; the archive digest, package version and target are recorded for digest-based idempotence. On repeat install, the verified archive digest and per-file runtime checks remain mandatory; the plain operator-selected semver (for example `0.3.2`) matches the same installed release even when the Windows bootstrap records an executable `+src...` build fingerprint in `installed_version`. Different major/minor/patch or prerelease values still fail closed. The archive filename and extraction directory are derived from the target, and the same five-file staged-candidate check, writer lock, active-job deferral, exact digest verification and rollback-capable `self_update` replacement apply. A local archive is digest-checked before entering `self_update`, which independently verifies the streamed bytes before extraction. Calling `__self-update` without an exact archive selection now fails with guidance; it never contacts a moving `latest` pointer.


The direct installer and `Update-OnecToolkit.ps1` receive an exact ZIP with its trusted SHA-256, package version and target. Installed v2 agents and their older lifecycle scripts may still contain the previous latest/manifest updater until that installation is replaced. This source change does not migrate installed hosts. Require native acceptance of the old-install-to-direct-update transition before claiming that fleet migration is safe. The `Install-OnecToolkit.ps1` legacy v2 branch remains only to transition existing installations. Direct package installation records package digest identity; it does not authorize or report managed-release acceptance.

SHA-256 values enter the Rust package updater as `onec_core::Sha256Digest`. Input accepts uppercase or lowercase hexadecimal and serializes the recorded digest in lowercase.

Persistent diagnostics live next to the agent configuration:

- `agent/supervisor.log`: supervisor start, agent start/exit/restart, self-update start/result/defer;
- `agent/agent-events.log`: schema-versioned JSONL for control listener, user-mode sshd, reverse tunnel, agent/service lifecycle. It persists only typed lifecycle fields (for example ports/exit code), not arbitrary exception text or paths.

When the gateway reports `Connection refused` for an allocated reverse port while other agents on the same gateway remain online, the reverse listener is absent. Check these two logs first. A normal SSH transport loss should reconnect automatically; an absent listener with no reconnect events indicates that the resident agent/supervisor is no longer running.

Managed enrollment has two explicit persistence profiles. `user-session` is the default: it keeps the existing no-admin HKCU Run supervisor and therefore shares the logged-in user-session boundary. `windows-service` is opt-in through `onec-access invite --persistence windows-service`; it requires an elevated PowerShell session before download/enrollment, installs the same agent as an auto-start SCM service, removes the competing HKCU autostart, and persists `persistence_mode` in `install.json`. Both profiles now require a fresh structured `tunnel.started` event before install success; user-session additionally proves the supervisor lock is held. The one-use enrollment token is not embedded in the generated PowerShell argv. After the exact release archive is hash-verified and extracted, the verified candidate `onec-agent __enroll-http` performs the HTTPS-only, zero-redirect enrollment using a private token file. The updater preserves the selected persistence profile and restores the previous running/stopped service state on failure.

`windows-service` is deliberately a **privileged machine-level profile**: SCM runs it as LocalSystem, target-side `sshd` is owned by that service process, and structured `Exec`/`JobStart` children therefore run in the service security context rather than the interactive user context. Do not select it merely to avoid logon; use it only on hosts where that privilege model is acceptable. Sensitive managed files are ACL-restricted to the installing user plus SYSTEM. Current native acceptance proves Windows PowerShell 5.1 parsing and non-mutating SCM status queries, but an isolated elevated Windows test target is still required to claim service creation/start and tunnel persistence as live-tested.

## Controller

Configure controller-side machine access in `onec-access`. The agent protocol is intentionally machine-only: it owns enrollment, identity/status, structured execution, durable jobs, filesystem transfer, probes, and forwarding, but no 1C discovery/update/project policy.

Persistence profile selection and enrollment are governed by the [infrastructure boundary](../../docs/remote-agent-testing.md#source-and-infrastructure-ownership). The following access examples assume an already prepared test target:

```bash
onec-access list
onec-access info customer-a
onec-access verify customer-a --json
onec-access sync-ssh
onec-access ssh customer-a -- whoami
onec-access exec customer-a -- whoami
onec-access probe customer-a 127.0.0.1 1541
onec-access upload customer-a ./payload.bin 'C:\Temp\payload.bin'
onec-access download customer-a 'C:\Temp\backup.dt' ./backup.dt
onec-access rdp customer-a
onec-access forward customer-a --listen-port 21541 --target-host 127.0.0.1 --target-port 1541
```

1C discovery was removed from the agent wire protocol. Reach the machine first, then execute local `onec` inspection or mutation on the target, for example `onec-access exec customer-a -- onec doctor`. Likewise, configuration updates, project deployment, template installation, and storage-provider policy are target-local/domain workflows and are not agent RPCs.

### Persistent jobs

Use a persistent job when the operation may outlive the controller request, SSH session, or serving agent process:

```bash
onec-access job start customer-a -- onec configuration fetch SmallBusiness30@3.0.14.123 --source 'C:\Temp\1Cv8.cf' --output 'C:\Temp\unf-xml'
# prints a stable job-... ID

onec-access job status customer-a job-...
onec-access job logs customer-a job-... --tail-bytes 65536
onec-access job wait customer-a job-...
onec-access job cancel customer-a job-...
```

`onec-access exec` and `onec-access job start` pass the program, every argv element, optional cwd, and optional non-secret environment entries as structured protocol fields. No command shell or code-page switch is inserted by the controller. `JobStart` returns immediately after the agent creates a private durable job directory and starts its worker. The worker owns the child process, immutable state snapshots, and bounded/redacted stdout/stderr logs, so the job survives controller disconnects and remains queryable after an agent restart.

`jobs-v1` also owns durable job correlation. The worker injects `ONEC_JOB_SYSTEM=onec_agent_job` and the actual `ONEC_JOB_ID=job-...` before child launch. This is a mandatory part of the durable-job contract, not a separately negotiated optional capability. Terminal states are `succeeded`, `failed`, `canceled`, and `interrupted`; `interrupted` never implies success. Controller-side wait timeout does not cancel a job; cancellation is explicit and process-tree-aware.

Generic `onec-access forward` and `onec-access rdp` listeners bind on the controller loopback. If an already-running RAS endpoint must be reached, forward that endpoint explicitly; `onec-hub` does not start RAS or infer 1C cluster topology. A Configurator connection can be redirected to working-process ports, so forwarding only 1541/1545 is not a substitute for target-local 1C operations.

## Windows compatibility builds

The main Windows bundle uses `x86_64-pc-windows-msvc` for current Windows/Server releases.

The complete remote toolkit is also built for Rust's Win7-compatible targets:

```text
x86_64-win7-windows-msvc   compatibility x64: onec-agent + onec
i686-win7-windows-msvc     compatibility x86: onec-agent + onec
```

That compatibility line is intended for Windows 7 / Windows Server 2008 R2 (6.1), Windows Server 2012/2012 R2, and newer systems. Original Windows Server 2008 (6.0, non-R2) is below the Rust `win7` target baseline and is intentionally outside the supported compatibility scope.
The managed runtime itself keeps the 6.1 compatibility baseline, but toolkit-managed TargetSsh requires nested Windows Job Objects because onec-agent owns resident `sshd` in a kill-on-close Job while Win32-OpenSSH creates its own Job for remote commands/subsystems. Nested jobs begin with NT 6.2 (Windows 8 / Windows Server 2012), so Windows 7 / Server 2008 R2 enrollment deliberately omits target `sshd` and uses the direct onec-agent GatewayControl carrier. On NT 6.2+ TargetSsh remains optional: before advertising it to `onec-hub`, the installer runs the exact portable `sshd` on an ephemeral loopback port and proves public-key authentication with a toolkit-owned key/`authorized_keys` file. If that account/ACL/OpenSSH preflight fails, enrollment likewise continues through GatewayControl instead of accepting a broken SSH-ready host. Existing NT 6.1 records that still advertise a target host key must be re-enrolled with a current invite so hub inventory and the resident carrier change atomically; ordinary self-update does not rewrite enrollment transport metadata.
On legacy systems the pinned PortableGit self-extractor is judged by both its allowlisted exit status and the extracted OpenSSH postcondition. Exit code `1` is accepted only after a fresh verified extraction contains runnable `git.exe`, `ssh.exe`, `ssh-keygen.exe`, and compatibility `curl.exe` in a supported layout; incomplete roots, missing files, and other non-zero exit codes remain fatal. This lets a fresh invite repair a partially damaged user-session install without manual file surgery.


Local agent-only build helper:

```bash
just validate-compat
```

Compatibility cross-builds are checked by `just validate-compat`; actual
Windows loader/service/1C compatibility requires native TEST target execution.
No separate Wine smoke wrapper is maintained.

The compatibility targets require nightly Rust with `rust-src`, `cargo-xwin`, `-Z build-std=std,panic_abort`, and an x86+x64 xwin SDK cache.

For service mode, prefer `secret_file` over `secret_env`, because a Windows service normally runs outside the interactive user's environment. Restrict the secret file ACL to the service identity/administrators.

Example:

```json
{
  "version": 1,
  "name": "customer-a",
  "listen": "127.0.0.1:27391",
  "secret_env": "",
  "secret_file": "C:\\ProgramData\\onec-agent\\control.secret",
  "ssh": {
    "program": "C:\\ProgramData\\Git\\usr\\bin\\ssh.exe",
    "gateways": [
      { "host": "gateway.example.test", "user": "onec-agent", "port": 22 }
    ],
    "remote_port": 41001,
    "identity": "C:\\ProgramData\\onec-agent\\id_ed25519",
    "known_hosts": "C:\\ProgramData\\onec-agent\\known_hosts",
    "reconnect_seconds": 5
  }
}
```

## Security boundary

The MVP is an administrative agent and therefore intentionally powerful. Production deployment still needs:

- one SSH identity per customer/agent;
- gateway-side ACLs that prevent an agent account from accessing other agents;
- enrollment and key rotation;
- audit logging;
- Windows DPAPI-backed local secret/key storage;
- an operation policy/capability allowlist for environments where unrestricted `exec` is not appropriate.

No production customer server should run the MVP with a shared SSH key or a shared control secret.
