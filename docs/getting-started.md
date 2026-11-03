# Getting started

HostLink is a Rust workspace with three packages: `hostlink` (Controller), `hostlink-agent` (Agent) and `hostlink-hub` (Hub).

## Development

```sh
rustc --version
cargo build --locked --workspace
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
python3 -m unittest discover -s scripts/tests
```

Check the command-line interfaces without connecting to any host:

```sh
cargo run --locked -p hostlink -- --help
cargo run --locked -p hostlink-agent -- --help
cargo run --locked -p hostlink-hub -- --help
```

## Next steps

- [Architecture](ARCHITECTURE.md) describes the transport and control plane.
- [Controller and Hub](CLIENT_HUB.md) describes Hub configuration and managed host operations.
- [GitHub Releases](GITHUB_RELEASES.md) describes the current release and bootstrap contract.
- [Agent installation](AGENT_INSTALLATION.md) explains stable roots and updates.

Use disposable development machines for first-time enrollment and lifecycle testing.
