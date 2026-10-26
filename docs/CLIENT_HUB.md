# Hub-managed HostLink client

The Client uses Hub v2 for inventory and current host routing, then uses the same pinned `russh` transport for SSH exec, SFTP and durable jobs. Hub does not execute commands or proxy Agent RPC.

## Configure the controller

Create an operator bearer token file with owner-only permissions, and keep the controller and gateway Ed25519 private keys in separate owner-only files. Configure the controller once:

```sh
hostlink hub configure \
  --hub-url https://hub.example \
  --token-file ~/.config/hostlink/operator.token \
  --ssh-user hostlink \
  --identity ~/.ssh/hostlink_ed25519 \
  --gateway-identity ~/.ssh/hostlink_gateway_ed25519
hostlink hub show
hostlink hub check
```

The configuration is written to `~/.config/hostlink/hub.json` (Windows: `%APPDATA%\HostLink\hub.json`). The Hub URL must be an HTTPS origin. `hub check` checks operator API access and does not probe an Agent.

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
hostlink run --host lab-win7 --binary ./tests -- --list
hostlink job start --host lab-win7 --program /opt/tests --source-sha256 <sha256> -- --list
hostlink job status --host lab-win7 --id <uuid>
```

The existing `--config PATH` form remains available and cannot be combined with `--host`. Managed selection fetches fresh Hub records and builds the existing `HostSpec`; all execution remains on `HostConnection::connect`. A lost job-start acknowledgement remains `UNKNOWN`; query its printed UUID and do not repeat the start request.

## Invitations

```sh
hostlink invite --name lab-win7 --ssh-user hostlink --ttl-seconds 900 \
  --target x86_64-win7-windows-msvc \
  --version 0.2.0 \
  --installer-url https://artifacts.example/Install-HostLink-Agent.ps1 \
  --installer-sha256 <independently-verified-script-sha256> \
  --agent-url https://artifacts.example/v0.2.0/x86_64-win7-windows-msvc/hostlink-agent.exe \
  --agent-sha256 <independently-verified-agent-sha256> \
  --archive-url https://artifacts.example/v0.2.0/hostlink-agent-x86_64-win7-windows-msvc.zip \
  --archive-sha256 <independently-verified-zip-sha256>
```

The default invite flow requires an exact target (`i686-win7-windows-msvc`, `x86_64-win7-windows-msvc`, `x86_64-pc-windows-msvc`, or `x86_64-unknown-linux-gnu`), semantic version, canonical name, SSH user (`--ssh-user`, or the configured Hub default), the installer URL and SHA-256, Agent sidecar URL and SHA-256, and exact target-named ZIP URL and SHA-256. Installer, sidecar, and ZIP URLs must be credential-free HTTPS links on one origin. The sidecar and ZIP paths must bind the selected version (`VERSION` or `vVERSION` segment); the sidecar must also contain the exact target as a path segment and end in `hostlink-agent.exe` on Windows or `hostlink-agent` on Linux. The ZIP URL must end in `hostlink-agent-TARGET.zip`.

Before `POST /v2/invites`, the client fetches the installer with redirects disabled, TLS certificate verification enabled, a 1 MiB bound and a 30 second deadline. It checks the independently supplied script digest and the expected platform installer interface. Any missing pin, malformed or swapped source, redirect, download error, digest mismatch, invalid UTF-8 or installer contract mismatch fails before an invitation is issued. The generated Windows PowerShell 2 or POSIX command repeats the bounded HTTPS download and exact installer SHA-256 verification on the target before executing the verified bytes. Installer arguments are shell-quoted, and the installer itself checks the sidecar and ZIP pins, target and version before prompting for the invitation token.

The one-use token is displayed separately from the copyable command. It is never embedded in the command, script, URL or environment; the installed bootstrap securely prompts for it. Manual enrollment is available only through explicit `hostlink invite --token-only` and does not print a runnable command.

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
operations are never replayed on another route; in particular, a job start
whose acknowledgement is lost remains an unknown outcome for the caller.

The old manual `HostSpec` JSON with one `gateway` remains valid. Its optional
`alternates` field defaults to an empty list. Direct unmanaged configs remain
separate from Hub route selection.

CLI command callers use `--host` for managed routing: `check`, `exec`, `run`,
`job start/status/cancel/output`, `forward`, `rdp`, and `probe`. `--config PATH`
continues to load a manual `HostSpec` and does not consult Hub settings.
