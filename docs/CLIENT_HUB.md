# Hub-managed HostLink client

The Client uses Hub v2 for inventory and current host routing, then uses pinned `russh` for short SSH exec, SFTP and local TCP forwarding. Hub does not execute commands or proxy Agent RPC. **Agent-local Apalis jobs are managed through the Agent's loopback-only Board UI/API, not via a Client jobs command.**

## Configure the controller

Create an operator bearer token file with owner-only permissions, and keep the controller and gateway Ed25519 private keys in separate owner-only files. Configure the controller once:

```sh
hostlink hub configure \
  --hub-url https://hub.example \
  --hub-ca-cert /private/hub-ca.pem \
  --token-file ~/.config/hostlink/operator.token \
  --ssh-user hostlink \
  --identity ~/.ssh/hostlink_ed25519 \
  --gateway-identity ~/.ssh/hostlink_gateway_ed25519
hostlink hub show
hostlink hub check
```

The configuration is written to `~/.config/hostlink/hub.json` (Windows: `%APPDATA%\HostLink\hub.json`). The Hub URL must be an HTTPS origin. `hub check` checks operator API access and does not probe an Agent. `--hub-ca-cert` is optional and adds one PEM CA to normal TLS trust; certificate and hostname validation remain enabled.

## Inventory and host operations

```sh
hostlink list                 # one Hub inventory request, no SSH probes
hostlink list --check         # explicit bounded (four concurrent) pinned SSH checks
hostlink info lab-win7        # registry data only
hostlink verify lab-win7      # open and close a pinned russh connection
hostlink display-name lab-win7 "Windows lab"
hostlink remove lab-win7 --yes
```

`list --check` prints `online`, `unreachable`, `unknown`, or `identity_mismatch` with an observation timestamp. A registry record alone never means that the Agent is online. `remove` revokes new managed connections; its receipt reports that existing sessions were not confirmed terminated and that no remote uninstall occurred.

Names and stable machine IDs are exact selectors; a unique machine-ID prefix is also accepted. Display labels are not identities. If Hub advertises multiple gateway routes, connection resolution fails until an explicit route-selection policy is available. DNS is resolved with a deadline and is never treated as an SSH identity; the gateway and target keys are independently pinned.

## Execution

Existing operations accept exactly one target source:

```sh
hostlink check --host lab-win7
hostlink exec --host lab-win7 --command 'hostname'
hostlink upload --host lab-win7 --local ./input.bin --remote input.bin
hostlink download --host lab-win7 --remote output.bin --local ./output.bin
```

The existing `--config PATH` form remains available and cannot be combined with `--host`. Managed selection uses `Host::connect` to resolve a fresh Hub identity and independently pinned gateway/Agent keys before establishing `russh`. Explicit unmanaged configuration continues to use `HostSpec` and `HostConnection::connect` directly.

## Rust managed Host API

`Host` represents the stable machine identity of an **already enrolled** host. Its asynchronous operations make the network boundary explicit:

```rust
use hostlink::{
    host::Host,
    hub::HubClient,
};

// Loading owner-only configuration does not contact Hub.
let (hub, config) = HubClient::from_file(config_path)?;

// Only after validating the authenticated release selection:
let pending = Host::create(&hub, Some("lab-win7".into()), 900).await?;
let invitation = pending.into_invitation();
// Deliver the one-use invitation at an explicitly controlled secret boundary.
// No Host identity or SSH session exists yet: the target must enroll first.

// After enrollment, resolve a fresh authoritative identity and connect to it.
let (host, mut ssh) = Host::connect(&hub, &config, "lab-win7").await?;
let response = ssh.exec("hostname", &[]).await?;
ssh.close().await?;
```

`Host::create` does **not** upload artifacts, install an Agent, wait for enrollment or imply that a host is online. The high-level CLI validates the private GitHub release metadata and target binary digest before requesting an invitation; the target downloads and verifies the actual executable **before consuming** the one-use token. Library callers must establish equivalent artifact trust themselves. The `PendingHost` holds the invitation, not an SSH identity. `Host::connect` resolves a current Hub record and approved gateway list for every call, returns the registered `Host` identity with the existing authenticated `HostConnection`, and never falls back to a cached or unmanaged route when Hub is unavailable. Neither operation creates another SSH engine.

The Linux process-level domain regressions require Caddy, OpenSSL and available
disposable loopback ports, so they are intentionally opt-in rather than a
dependency of ordinary CI unit tests:

```sh
cargo test --offline --locked -p hostlink --lib -- --ignored --test-threads=1
```

These cases exercise the actual HTTPS Hub and pinned nested `russh` flow,
including fresh name/ID resolution, revoked hosts, ambiguous selectors and
key mismatches. They do not replace Windows 7/11 native acceptance.

## Agent-local jobs through Apalis Board

Freshly enrolled Agents have a private `board_listen` such as
`127.0.0.1:25431` in their `agent.json`. On that computer, open
`http://127.0.0.1:25431/new` to submit a program and argv, or
`http://127.0.0.1:25431/` for the built-in Apalis Board. The port shown
here is an illustration; use the exact configured port.

From an authorized controller, forward the **same local port** over pinned
SSH (example port 25431):

```sh
hostlink forward --host lab-win7 --listen 127.0.0.1:25431 --target 127.0.0.1:25431
```

Use the forwarded localhost URL in a browser. The stock Board API accepts
`PUT /api/v1/queues/commands/tasks` with a JSON command payload and
provides task/worker listing endpoints. Board HTTP is not published to a
public network; local access grants code execution under the Agent user.
Apalis can retry a previously started command after a worker crash, so
side effects may repeat. The old `hostlink jobs` CLI and SSH jobs
subsystem were intentionally removed.

## Invitations (private GitHub Releases only)

The Controller must first have a private read-only GitHub token stored in
its own `~/.config/hostlink/credentials/github-token`
(`%APPDATA%\HostLink\credentials\github-token` on Windows). It must
grant `Contents: Read` to the fixed private `KDmasterLOL/hostlink`
repository. This does not grant access to a private release unless the
token is valid, and also grants read access to repository source.

```sh
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc
hostlink invite --name lab-win7 --target x86_64-win7-windows-msvc --version 0.1.0
```

Without a version, Client chooses GitHub's latest published stable release;
otherwise exact `vX.Y.Z`. Under 1C-1164 it resolves the exact raw target
executable and GitHub-published SHA-256 before issuing a one-use Hub invite.
Controller renders disposable Windows 7 PowerShell 2 or POSIX bootstrap;
there is no released/installed installer asset. Target bootstrap downloads one
binary and checks its digest before consuming the separate Hub invite, then
invokes Rust Agent install at the stable per-user root.

Default bootstrap prompts for the target's own PAT without echo and creates
or reads private `hostlink/credentials/github-token`. Explicit
`--embed-github-token` prints the Controller PAT in the helper instead; protect
stdout/history/clipboard and delete saved helpers after use. No PAT is embedded
without opt-in. Unix credentials require `0600`; Windows requires protected
current-user-only ACL. No Git/default command installation is performed.
`state/manifest.json` remains private enrollment metadata.

`--token-only` remains for manual enrollment. No arbitrary-site installer,
agent or archive URL flags or alternate publisher fallback. Missing private
credentials, assets or digests fail closed. Controller unit tests verify
rendered bootstraps; native Windows PowerShell 2 execution is still untested.

See [GitHub Releases](GITHUB_RELEASES.md),
[Artifact publication](ARTIFACTS_AND_INVITES.md), and
[Fresh enrollment](ENROLLMENT.md).

## Multi-gateway Client routing

Hub-managed `--host` operations resolve the host and the current `/v2/info`
gateway list before opening SSH. With one approved gateway, the client keeps
the existing behavior. With multiple gateways, configure an exact primary
route in the owner-only controller Hub config using `preferred_gateway` with
the exact `host:port` value from `/v2/info`; the client never chooses an array
index or guesses a preferred edge. All listed routes are bounded to sixteen,
validated for unique identities and Ed25519 pins, and resolved before SSH.

The chosen route is tried first. The remaining Hub-approved routes are tried
in Hub order only when establishing the gateway SSH connection fails with a
transient connect refusal, reset, timeout, or disconnect. Pin mismatch,
public-key authentication failure, reverse-port channel refusal, and nested
Agent host-key mismatch stop immediately. A failed gateway is cleaned up
before the next route is attempted. Once the nested Agent session has started,
short SSH operations are not retried on another route after connection setup.
Agent-local Apalis jobs do not use these Client routes.

The old manual `HostSpec` JSON with one `gateway` remains valid. Its optional
`alternates` field defaults to an empty list. Direct unmanaged configs remain
separate from Hub route selection.

CLI command callers use `--host` for managed routing: `check`, `exec`,
`upload`, `download`, `forward`, `rdp`, and `probe`. `--config PATH`
continues to load a manual `HostSpec` and does not consult Hub settings.
