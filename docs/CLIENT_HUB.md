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
hostlink invite --name lab-win7 --ttl-seconds 900
```

The one-use token is shown only by this explicit command. The client currently reports `artifact_binding: missing`; it does not invent a runnable install command because a source-verified Agent artifact/install binding is not available in this client task.
