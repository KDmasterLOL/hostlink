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

## Outside this phase

No changes to installed hosts, infra Ansible, server config, secrets, GitHub
release/Latest, main/tag, or the original Toolkit repositories.
