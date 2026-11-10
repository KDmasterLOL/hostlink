# Controller and Hub

The `hostlink` Controller uses the Hub for live inventory, machine identity, approved gateways and revocation. It then opens pinned `russh` sessions for remote commands, SFTP and TCP forwarding. The Hub is not a remote-command proxy.

Authenticated Hub GET requests retry transient connection failures and timeouts up to four attempts, with 250 ms, 500 ms and 1 s delays and a 45 s total budget. HTTP errors, invalid responses and TLS validation failures are not retried. Mutating Hub requests are sent once, since their outcome may be unknown after a transport failure.

## Configure the Controller

Create a private Hub operator-token file and separate Ed25519 identities, then configure the Controller:

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

An optional `--hub-ca-cert /private/hub-ca.pem` adds a trusted CA. On Linux, the managed Hub config is `~/.config/hostlink/hub.json`; on Windows it is `%APPDATA%\HostLink\hub.json`. Credential files and managed configuration require user-only permissions. An alternate `HOSTLINK_HUB_CONFIG` path can be specified explicitly.

## Managed hosts

```sh
hostlink list
hostlink list --check
hostlink info lab-host
hostlink verify lab-host
hostlink display-name lab-host "Development host"
hostlink remove lab-host --yes
```

`list` queries the registry without SSH; `list --check` performs explicit bounded connectivity probes. `remove` revokes new connections but does not uninstall the Agent or forcibly terminate an existing session.

## Remote operations

```sh
hostlink check --host lab-host
hostlink exec --host lab-host --command 'hostname'
hostlink upload --host lab-host --local ./input.bin --remote input.bin
hostlink download --host lab-host --remote output.bin --local ./output.bin
hostlink forward --host lab-host --listen 127.0.0.1:25431 --target 127.0.0.1:25431
```

For unmanaged configurations, use `--config PATH` instead of `--host`.

## Invitations

```sh
hostlink invite lab-host --os windows
hostlink invite lab-linux --os linux --version 0.1.0
```

The CLI resolves all required raw executables for the OS from one fixed GitHub release before issuing a one-use invitation. The output is one command containing that invitation; protect the command as a secret. The public release needs no GitHub credential. The Windows command is intended for pasting into cmd.exe or PowerShell; paste the Linux command into a POSIX shell. Native Windows shell acceptance remains unverified.

See [GitHub Releases](GITHUB_RELEASES.md) and [enrollment](ENROLLMENT.md) for prerequisites and credential handling.

## Agent-local jobs

Durable tasks belong to the Agent's Apalis SQLite queue, exposed through its loopback-only Board. The Board can be accessed from a Controller through `hostlink forward`; use the configured Agent `board_listen` port on both ends. The Board can execute programs under the Agent user's permissions and must not be exposed publicly.

## Gateway routing

With more than one Hub-approved gateway, configure `preferred_gateway` as an exact `host:port` from the Hub's `/v2/info` response. The Controller may try another approved route only for transient gateway connection failures; SSH identity or authorization failures do not trigger a fallback. See [multi-gateway routing](MULTI_GATEWAY.md).
