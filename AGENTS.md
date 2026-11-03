# HostLink engineering guide

HostLink comprises `hostlink` (Controller), `hostlink-agent` (managed Agent), and `hostlink-hub` (HTTPS control plane). Read [architecture](docs/ARCHITECTURE.md), [source layout](docs/SOURCE_LAYOUT.md), and the relevant subsystem document before changing behavior.

## Ownership and invariants

- Use `russh` and `russh-sftp` as the only remote execution/file-transfer transport. The Hub owns enrollment, inventory, revocation and gateway SSH authorization; it does not execute commands.
- Agent-local durable jobs belong to Apalis SQLite and the upstream Apalis Board, available only on loopback. Do not reintroduce a custom SSH jobs protocol, queue engine, or unauthenticated public Board listener.
- Preserve Ed25519 identity pins, bounded I/O and concurrency, private files, and one-use enrollment semantics. Do not print, commit, or propagate private credentials in tests or logs.
- `hostlink-agent install` owns stable-root enrollment and executable publication. Updates use a single verified raw Agent executable; Windows publication is stopped-only and requires removal of the owned Task Scheduler task first.
- Keep `state/manifest.json` (enrollment-key identity) distinct from any release metadata. Do not restore legacy installer archives, ZIP-based updater, or installed bootstrap scripts.
- Use `module/mod.rs` for multi-file Rust modules, not a mixture of `module.rs` and `module/mod.rs`. Prefer focused modules and tests.

## Workflow

- Inspect existing code, tests, docs and Git state; make scoped changes on task branches and run the relevant Rust/Python checks.
- Verify actual native behavior before claiming Windows 7/11 or service-lifecycle acceptance. Cross-compilation alone is insufficient.
- Do not mutate customer databases, production services, running legacy Agents, Hub state, tags or releases without the corresponding explicit authorization.
- Never publish real credentials, machine-specific configuration, private infrastructure addresses, or raw logs in repository files.
- Release artifacts are published only through an explicitly reviewed, source-bound workflow; see [GitHub Releases](docs/GITHUB_RELEASES.md).
