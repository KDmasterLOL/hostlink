# Compatibility and migration gates

The initial repository is ADDITIVE. The original OneC Toolkit checkout, its
original release ZIPs, installed services and infra deployment mechanisms
remain the authority until a separately authorized, tested cutover.

## Immutable/externally consumed contracts

- Agent JSONL protocol v1; response fields, capability negotiation, bounded
  framing, complete stdio bytes, signed record canonical serialization.
- Hub enrollment state versions and machine_id, stable hub name, alternate
  display-only labels, gateway keys, endpoint identity, port allocation,
  known_hosts and authorized_keys projections.
- Legacy serialized onec_ops_executable, already published signed domain
  strings, existing config roots and SSH host aliases must NOT be silently
  renamed by the extraction; future data migration may introduce neutral
  names with explicit dual-read and fixtures.
- Old Agent runtime ZIP and its five required files, managed update lock and
  durable jobs keep running until an approved cutover proves a standalone Agent
  installer with no competing service or key ownership.
- Hub/controller/Agent version mismatch is a supported condition to test,
  not a reason for automatic upgrade/re-enrollment or key rotation.

## Required before any installed-host transition

1. New independently built Hub/Agent/Controller, Cargo tests, strict Clippy,
   formatting, and copy-source provenance audit.
2. Generic operations: authenticated reverse SSH, SFTP, TCP forwarding,
   control RPC, run-local (including Nextest --list), durable jobs, disconnect
   and cancellation/unknown-state tests.
3. Compare old/new controller with old/new Agent and Hub identities; verify
   current state and signed historical receipts with byte-exact fixtures.
4. Windows latest x64 native acceptance and Windows 7 x64/x86 source-exact
   loader/transport matrix on isolated fixtures. Linux cross-build alone
   cannot prove legacy Windows runtime behavior.
5. Verified separate Agent ZIP with version/hash, independent rollback and
   health readback, along with a tested migration from the old bundled ZIP.
6. Only after the new release and infra orchestration are separately accepted
   may source ownership be removed from OneC Toolkit in a further task.

## Local build and native acceptance evidence

GitHub Actions is no longer the HostLink build/test executor. Run locked Rust
checks, strict Clippy, focused loopback regressions, negative architecture
guards and packaging validation locally on HOME/approved disposable fixtures.

For **HostLink `f573bd1a12d3be3865af860d77d6442cd9f903d8`** HOME produced
`x86_64-win7-windows-msvc` and `i686-win7-windows-msvc` Agent candidates
using `nightly-2026-08-22`, `cargo-xwin 0.23.1`,
`-Z build-std=std,panic_abort` and static CRT. Both builds and PE/ZIP checks
passed: target machine x64 `0x8664`, x86 `0x14C`, no dynamic UCRT/VCRuntime
imports, exact four-file Agent-only ZIP with SHA-256 sidecars. The archived
build receipt is local to HOME at
`~/.cache/hostlink/win7-builds/f573bd1/candidate-verification.json`.

**Neither source-exact f573 Win7 candidate has passed an actual NT6.1 loader,
SSH exec, installer or enrollment acceptance test.** An earlier Win7 candidate
passed version/config and SSH auth/SFTP/TCP on a controlled NT6.1 user session,
but its opt-in PowerShell 2 exec binary-stdin probe failed; its earlier evidence
cannot be reused as proof for f573. Native access to the owned Win7 fixture must
be restored before further acceptance. Tier-3 images are not ordinary
`*-pc-windows-msvc` builds. See the
[Rust platform documentation](https://doc.rust-lang.org/rustc/platform-support/win7-windows-msvc.html).

The Agent-only PowerShell 2 installer can bypass CLR4 `ZipArchive` only when
both `-AgentExecutableFile` and `-AgentExecutableSha256` are supplied. It
checks the staged candidate and ZIP against caller-provided SHA-256 pins, then
uses that candidate's existing `__self-update --agent-only` command to verify
and install the ZIP. Win7 targets require this pair; there is no alternate
extractor. Current Windows MSVC artifacts are not Win7 candidates. Dedicated
Tier-3 Win7 x64/x86 binaries have been locally built and PE-inspected, but
**native bootstrap and end-to-end enrollment acceptance are still missing**.

Embedded SSH exec on Windows requires a verified non-elevated, non-LocalSystem
process token; elevated contexts receive an explicit SSH request denial.

## Outside this phase

No changes to installed hosts, infra Ansible, server config, secrets, GitHub
release/Latest, main/tag, or the original Toolkit repositories.
