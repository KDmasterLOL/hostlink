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
| Windows 11 x86-64 | `x86_64-pc-windows-msvc` |
| Windows 7 / Server 2008 R2 x86-64 | `x86_64-win7-windows-msvc` |
| Windows 7 x86 | `i686-win7-windows-msvc` |

Windows 10 is not currently enabled in the bootstrap compatibility check; macOS is not implemented. The exact native acceptance criteria are in [Windows 7 compatibility](docs/WIN7_REWRITE_ACCEPTANCE.md).

## Build and test

Requirements: Rust and Cargo, the toolchain specified in `rust-toolchain.toml`, and platform build dependencies.

```sh
cargo build --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Windows 7 targets use an additional cross-compilation workflow; see [Windows 7 compatibility](docs/WIN7_REWRITE_ACCEPTANCE.md).

## Controller examples

Configure the Hub first, as shown in [Controller setup](docs/CLIENT_HUB.md).

```sh
hostlink hub check
hostlink list
hostlink list --check
hostlink verify lab-host
hostlink exec --host lab-host --command 'hostname'
hostlink upload --host lab-host --local ./input.bin --remote input.bin
```

A new machine requires a one-use Hub invitation:

```sh
hostlink invite lab-win7 --os windows
```

The command prints one paste-ready bootstrap containing a one-use invitation. Protect it as a secret. Public release downloads require no GitHub PAT; see [Releases and bootstrap](docs/GITHUB_RELEASES.md) for target shell and platform requirements.

## Documentation

Start with the [documentation index](docs/index.md) for installation, upgrades, managed routing, Agent lifecycle, and development.

## License

[MIT](LICENSE).
