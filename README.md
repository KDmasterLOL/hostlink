# HostLink

A standalone, generic managed-machine access product: a controller, a Hub/gateway,
an outbound reverse-SSH Agent, SFTP, process execution and port forwarding.

Status: additive extraction in progress. The independent workspace contains
neutral Rust packages `hostlink-access`, `hostlink-agent`, `hostlink-hub`,
`hostlink-protocol`, and `hostlink-core`; the three binaries and standalone
Agent-only package contract are separate from OneC Toolkit. Embedded SSH exec
has Linux loopback regression coverage. External Windows/Win7 acceptance is
still pending. Legacy wire and config identities remain preserved; no standalone
release has yet passed native acceptance.

- No dependency on 1C domain concepts in the target architecture.
- Existing installed Agent configurations, protocol fields, SSH keys and signed
  observations must not be silently renamed or invalidated.
- Source extraction does not authorize installation, service takeover, release,
  deployment or modifications to the upstream OneC Toolkit checkout.
- Windows 7 compatibility and Cargo/Nextest target runner parity are release
  requirements, not assumptions.

Tracking: Huly 1C-944. See docs/extraction.md for baseline and gates.

## Development and verification

The workspace pins Rust 1.98.1. From the repository root:

```shell
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

Source CI also compiles and packages independent Linux and current-Windows
binaries without publishing them. This does not establish native compatibility
or fleet-rollout acceptance. Windows 7 x64/x86 require separate source-exact
Tier-3 toolchain and NT6.1 runtime testing; see
[compatibility gates](docs/compatibility.md).
