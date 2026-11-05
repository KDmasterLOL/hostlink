# HostLink

HostLink manages remote Windows and Linux machines through pinned SSH connections. It consists of a Controller CLI, a user-scoped Agent, and a Hub for enrollment, inventory, routing, and revocation.

The Agent provides SSH execution, SFTP, TCP forwarding, and local persistent jobs using Apalis SQLite. HostLink does not require OpenSSH Server on managed machines.

## Components

| Package | Purpose |
| --- | --- |
| `hostlink` | Controller CLI: inventory, invites, SSH execution, file transfer, forwarding |
| `hostlink-agent` | Managed SSH Agent, enrollment, local jobs, user service, self-update |
| `hostlink-hub` | HTTPS control plane: hosts, invitations, enrollment, revocation, gateway authorization |

The Hub does not execute remote commands or host the Agent's jobs database. The Agent's Apalis Board is available only on its loopback interface and can be reached remotely through authenticated SSH forwarding.

## Supported Agent builds

| Platform | Release target |
| --- | --- |
| Linux x86-64 (glibc) | `x86_64-unknown-linux-gnu` |
| Windows 10 / 11 x86-64 | `x86_64-pc-windows-msvc` |
| Windows 7 / Server 2008 R2 x86-64 | `x86_64-win7-windows-msvc` |
| Windows 7 x86 | `i686-win7-windows-msvc` |

The bootstrap selects NT 10 x86-64 from build 10240; native acceptance remains separate. macOS is not implemented. The exact native acceptance criteria are in [Windows 7 compatibility](docs/WIN7_REWRITE_ACCEPTANCE.md).

## Build and test

Build and verification run locally through the root `Justfile`; GitHub Actions is not used. Run `just check` for the workspace check, and `just test` and `just clippy` for the corresponding local tests and lint. Use `just --list` for available recipes.

See [local artifact preparation](docs/ARTIFACTS_AND_INVITES.md) for builds, candidate verification, and explicitly invoked publication, and [Windows 7 compatibility](docs/WIN7_REWRITE_ACCEPTANCE.md) for cross-build and native acceptance requirements.

## Controller examples

Configure the Hub first, as shown in [Controller setup](docs/CLIENT_HUB.md).

```sh
hostlink hub check
hostlink list
hostlink list --check
hostlink verify lab-host
hostlink exec --host lab-host --command 'hostname'

# Detached shell command (supply the Agent's exact loopback Board port)
hostlink exec --host lab-host --board-port 39123 --detach --command 'long-running-command'
# Optional Agent execution timeout (1..=14400 seconds)
hostlink exec --host lab-host --board-port 39123 --detach --timeout-seconds 3600 --command 'long-running-command'
# Explicit timeouts require an Agent advertising its supported maximum; without the flag, older Agents remain compatible.
# Direct --config targets must specify --os linux or --os windows
hostlink job status --host lab-host --board-port 39123 JOB_ID
hostlink upload --host lab-host --local ./input.bin --remote input.bin
```

A new machine requires a one-use Hub invitation:

```sh
hostlink invite lab-win7 --os windows
```

The command prints one paste-ready bootstrap containing a one-use invitation. Protect it as a secret. Before issuing it, the Controller selects the sole Hub-approved gateway or the configured `preferred_gateway`; use `--gateway-index N` to explicitly select another approved route. Public release downloads require no GitHub PAT; see [Releases and bootstrap](docs/GITHUB_RELEASES.md) for target shell and platform requirements.

The Agent's SSH protocol login defaults to the Controller Hub configuration's `ssh_user`, independently of the target OS account. If `--ssh-user` is supplied, it must match that configured login.

## Documentation

Start with the [documentation index](docs/index.md) for installation, upgrades, managed routing, Agent lifecycle, and development.

The opt-in pinned SSH/SFTP smoke harness and its safety limits are documented in [tests/support](tests/support/README.md).

## License

[MIT](LICENSE).
