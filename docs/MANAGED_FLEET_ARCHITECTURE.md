# HostLink managed fleet — mandatory control plane

> 1C-1114 supersedes the historical Windows maintenance/live-handoff details below:
> Windows now uses a current-user Task Scheduler logon task and offline stopped-only
> update after task removal. See [lifecycle](AGENT_LIFECYCLE.md) and
> [updater](AGENT_UPDATE_WINDOWS.md). Native Win7/11 acceptance remains NOT RUN.

**Current source note (Huly 1C-1098):** The sections below were originally the 1C-987 managed-fleet target, but the user replaced the old SSH jobs subsystem with Agent-local Apalis/Board on 2026-10-29. Jobs now use the Agent's separate loopback Board and native SQLite queue; Client jobs CLI and remote binary execution have been removed. See [current architecture](ARCHITECTURE.md). Fleet management and SSH exec/SFTP/forward remain.

Source audit: original independent `dev@5a1f80b4c44c393dd8cc83faacf0a3ebc49de342`; experimental rewrite inspected at `2e95835bf12066368a8a1ae471aaba76387ae5e5`. Follow current Git HEAD and source if either moves. References below are **verified existing** unless explicitly labelled *proposed*.

## What "one SSH transport" means

```text
                           management plane (HTTPS, not Agent RPC)
hostlink CLI / HubClient  <---------------------------------->  hostlink-hub
      |                        list, invite, enroll, revoke       |
      |                                                            | authoritative
      | (resolve fresh machine ID, target and gateway key pins)    | inventory,
      |                                                            | names, routes,
      |                                                            | SSH authorizations
      |       execution/data plane: russh only                      |
      +------------------ pinned gateway hop ----------------------+-- SSH gateway
                                    |
                                    +----- reverse loopback SSH ----- hostlink-agent
                                             exec | SFTP | TCP forward
```

Hub owns **fleet identity/topology/lifecycle** only. It does not run shell commands, proxy arbitrary Agent RPC, store per-Agent command secrets, own user jobs, or become a second execution transport. The Agent stays an unprivileged `russh` server with an outbound reverse SSH tunnel. The Controller uses `russh` with *independently pinned* gateway and target host keys. A static, explicit `HostSpec` remains a supported unmanaged mode, not the default replacement for Hub-managed hosts.

### Crate/module ownership

| Owner | Existing | Required destination |
| --- | --- | --- |
| Client/CLI | `crates/client/src/{lib,main,connect,exec,sftp,run,forward,migration}.rs` | **Proposed** `crates/client/src/hub.rs`: thin HTTPS `HubClient`, managed host lookup and routing into **existing** `HostSpec`/ `HostConnection::connect`; management CLI entries |
| Hub | No crate in experimental workspace | **Proposed** `crates/hub/` with library exposing a narrow stable management DTO/domain contract and a separate `hostlink-hub check/serve` server feature. Hub owns persistent registry, invitations, enrollment, revocation and gateway SSH key authorization |
| Agent | `crates/agent/src/{lib,main,ssh,tunnel,jobs,sftp,update}/` | Fresh enrollment and source-pinned installer; independent Apalis Board listener on loopback only, no legacy Agent JSONL or SSH jobs RPC |
| Prior implementation (READ-ONLY) | `dev:crates/onec-hub/src/{state,server,allocation,authorized_keys,enrollment/*}.rs`, `dev:crates/onec-access/src/hub/*`, `dev:crates/onec-agent/src/{bootstrap_enrollment,enrollment_http}.rs` and `dev:crates/onec-agent/assets/Install-HostLink-Agent.ps1` | Reuse validated semantics and mature primitives selectively. Do **not** clone the old control-secret/JSONL execution stack or depend on old Toolkit |

Hub's stable value types may be consumed by Client with the Hub **server feature disabled**; the Win7 Client must not link Axum/HTTP server runtime. No catch-all `core` or duplicate identity/protocol parsers merely to break a dependency cycle.

### Proposed versioned management contract

These are the required new management capabilities, not claims about implemented endpoints. A new **/v2** HTTP contract prevents old /v1 control-secret clients from incorrectly appearing compatible; the existing deployed Hub retains its /v1 endpoints and state untouched during migration.

| API | Meaning |
| --- | --- |
| `GET /v2/info`, `GET /healthz` | Management capabilities/topology; health only does not assert Agent availability |
| `GET /v2/hosts`, `GET /v2/hosts/{machine_id}` | Authoritative **secret-free** enrolled host inventory and exact lookup |
| `POST /v2/invites` | Authenticated operator obtains a short-lived, one-use enrollment token; Hub state stores its digest only |
| `POST /v2/enroll` | Agent presents token and generated Ed25519 reverse identity and target SSH host key; Hub registers stable machine identity, assigns one restricted reverse loopback port, returns approved pinned gateway routes and operator public keys |
| `PATCH /v2/hosts/{machine_id}/display-name` | Change display-only label; never change the stable machine identity |
| `DELETE /v2/hosts/{machine_id}` | Revoke fleet membership/new gateway authorization, return a truthful commit/reconciliation receipt; **does not claim uninstall or forcibly terminate established channels** |
| `POST /internal/v2/ssh/authorized-key` | Authenticated gateway authorization lookup restricted to enrolled Agent Ed25519 key and its assigned `127.0.0.1:port` |

The old `GET /v1/agents/{id}/control-credential`, `control_secret` and legacy Agent JSONL commands are **not** part of the new management contract. Maintain the old Hub as read-only existing infrastructure until separately authorized cutover.

Hub must reject ambiguous or re-used `machine_id`, a new invitation claiming an already enrolled identity without an explicitly approved rotation token, malformed/duplicate names, reused reverse ports, invalid keys and untrusted routes. Persistent Hub writes are atomic under a writer lock, with source-exact readback and explicit commit-uncertain/reconciliation outcomes. Reconcile only new Hub-owned SSH authorization entries, never overwrite unmanaged keys or the old Hub's `onec-agent:*` namespace. For an in-use reverse SSH connection, Hub revocation alone cannot establish that the channel is closed: report **revoked_new_connections** separately from **confirmed_session_terminated** and any **remote_uninstall**.

### Controller user experience

Preserve old useful commands from `dev:crates/onec-access/src/cli/commands/mod.rs` and the present SSH-only core:

```text
hostlink configure --hub-url https://hub.example --token-file /private/token
hostlink list                 # fast Hub snapshot; no live SSH probe by default
hostlink list --check         # explicit bounded per-host SSH probe
hostlink info lab-win7
hostlink verify lab-win7      # actual target SSH identity/check; nonzero if failed
hostlink invite --name lab-win7 --ttl-seconds 900   # source-pinned bootstrap
hostlink exec --host lab-win7 --command "..."
hostlink forward --host lab-win7 --listen 127.0.0.1:25431 --target 127.0.0.1:25431
hostlink display-name lab-win7 "Lab machine"
hostlink remove lab-win7     # Hub revocation, NOT remote uninstall
```

The Board-forward port above is illustrative; use `board_listen` from the Agent's private configuration on both sides of the forwarding command. The stock Board UI is at `/`, and the command form at `/new`. Preserve existing `--config PATH` unmanaged `HostSpec` operations as an explicit mutually exclusive selection. `HubClient::list_hosts` and `resolve_host` handle HTTPS/auth/bounded JSON. `resolve_host_spec` maps an eligible host to the existing `HostSpec` using a **controller-local SSH private key**, Hub-projected *public* Agent HostKey, and separately pinned gateway key. Hostnames/display labels are not identities.

`list` reports every enrolled host even when offline; it never silently probes all hosts. `--check` explicitly connects with bounded concurrency and per-host timeout, classifying `online`, `unknown`, `unreachable`, and `identity_mismatch` plus observation time. Enrollment is **not** online status. Slow/broken hosts must not block the rest of the listing; known-host operations must not make a global live fanout. Missing pins, conflicting multiple gateway candidates, expired/revoked host records, Hub failure and SSH transport failure must produce distinct actionable errors; **no trust-on-first-use or old GatewayControl fallback**.

### Fresh Agent bootstrap

`hostlink invite` first validates exact installer/package target/version/SHA-256 from an independently trusted source. The generated Windows PowerShell 2/Win7-compatible or Linux bootstrap is run **on the target by its authorized non-elevated user**. A separate one-use secret is entered interactively or read from an owner-only token file, **never embedded in the command line, URL or logs**. The installer rejects an existing/foreign Agent root, symlink/reparse/unsafe ACL, wrong digest/target/version, ZIP traversal and package member mismatch. The Agent then:
1. Creates fresh private machine identity and distinct Ed25519 gateway and embedded SSH host keys.
2. Explicitly enrolls using pinned HTTPS and a one-use token, validating the complete reply and gateway pins. An uncertain enrollment result requires reconciliation, not blind token replay.
3. Atomically publishes its own private Agent configuration, authorized controller public keys and job/storage roots, all outside the old installation.
4. Runs as the owning user, listens on loopback only and maintains the outbound pinned reverse SSH route.

For the existing `AgentConfig.gateway: Option<ReverseGateway>`, a multiple-edge Hub inventory **cannot** be silently collapsed to an arbitrary gateway. Select one explicitly trusted route or report that the approved multi-edge contract is not yet implemented.

### Functional parity and intentionally retired mechanisms

| Existing useful user capability | New disposition |
| --- | --- |
| Hub config/show, list/info/verify/check, invite/enroll, display-name, remove/revoke | **Required**; currently missing in rewrite (1C-1019/1020/1021) |
| Explicit selected-host exec, private SFTP upload/download, TCP forward | Existing `russh` implementation retained; no Client jobs protocol |
| Durable command queue, native status/results and web monitoring | Agent-local Apalis SQLite plus stock Apalis Board on loopback, with `/new` form over its native API |
| Gateway TCP/RDP forwarding, target TCP probe, scoped owned-artifact cleanup, wait/log convenience | Valuable operator parity; evaluate bounded call sites and restore through existing `russh`/SFTP primitives without generic Agent filesystem RPC |
| Interactive OpenSSH process / `sync-ssh`, Hub Agent JSONL control secret, entire Nextest attestation and Toolkit release engine | Do **not** reintroduce a second transport or policy engine. Interactive/PTTY only if separately accepted; testing/effect policy remains caller-owned |
| Agent-only update | **Mandatory**, but Windows offline update/recovery after task removal and Win7 target proof remain separate acceptance gates |

### Acceptance and migration gates

- In isolated task worktrees: Hub invitation/enrollment/list/revoke state and key projection regression + Client fast list/named SSH + Agent secure bootstrap on disposable fixtures; fmt, check, strict Clippy and focused tests. Verify public APIs and negative absence of old runtime imports.
- In the experimental rewrite integration branch: a real local **Hub → invite → Agent enrollment → gateway authorization → pinned Client by name → SSH exec/SFTP/forward → revoke** scenario, plus a separate Board HTTP command enqueue/execute/result test. Revoked targets become unavailable for new managed SSH sessions with truthful reporting about existing sessions.
- On one authorized immutable source SHA: current Windows11, actual NT6.1 Win7 x64/x86 and required Linux runtimes, including PowerShell2 bootstrap, Windows Job Object cleanup, update deferral/rollback, gateway reconnect and cleanup. Prior old `dev` Win7 receipts do not prove the rewrite.
- Current old Hub, old agents, original HostLink `dev`, `main`, tags, production routes and 1C databases **must not change** without separate explicit user authorization. Test new Hub/Agent only on isolated user-owned roots, ports and gateway fixtures.
