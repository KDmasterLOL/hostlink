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

The hidden `__embedded-ssh-preflight` command keeps its existing auth, SFTP and
forwarding checks by default. Windows operators may explicitly add `--check-exec`
to validate the fixed local PowerShell exec probe; it requires a verified
non-elevated, non-LocalSystem process context and reports
`EMBEDDED_SSH_EXEC_PROBE_PASS` on success.

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

The Agent-only Windows installer supports either a manually prepared `-ConfigFile` or a fresh
user-scope Hub enrollment using `-HubUrl` and `-EnrollmentTokenFile` together. Manual configs
must explicitly set `jobs_dir` to the new `%LOCALAPPDATA%\HostLink\Agent\jobs` directory;
otherwise installation fails before publishing because the updater could miss active work. Enrollment creates
new private SSH identities and pinned Hub-provided keys before publishing config into a fresh
`%LOCALAPPDATA%\HostLink\Agent` root. It never installs a service or starts the Agent. The script
uses PowerShell 2-compatible syntax, but ZIP extraction requires the .NET Framework 4.5
`ZipArchive` type. PowerShell 2 on stock Windows 7/CLR 2 is unverified and may not load that type;
the installer fails closed when `ZipArchive` is unavailable. Native Win7 acceptance remains
blocked until tested on an owned Win7 environment.
Controller invites accept the optional paired flags `--direct-agent-executable-url` and
`--direct-agent-executable-sha256` for a trusted `hostlink-agent.exe` sidecar. Both are
required when the selected package target is `x86_64-win7-windows-msvc` or
`i686-win7-windows-msvc`; the current `x86_64-pc-windows-msvc` package keeps the ZIP-only
path unless the pair is supplied. The controller pins the sidecar digest from the operator,
preflights its same-origin HTTPS URL before creating the one-use invite, and the generated
PowerShell 2 bootstrap verifies the downloaded bytes before passing the sidecar to the
existing installer. The sidecar URL must end in `/<package-target>/hostlink-agent.exe`,
which binds the executable path to the selected ZIP target. A current-Windows executable is
not a Win7-compatible substitute.
The embedded SSH login is the fixed logical `hostlink` account; SSH commands run as the Agent
process user and do not impersonate a Windows account. Durable jobs live in a current-user-only
`jobs` directory shared by the Agent config and updater's active-job guard.
