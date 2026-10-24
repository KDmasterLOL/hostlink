# Extraction baseline / acceptance plan

- Source: OneC Toolkit branch dev
- Frozen source commit: cad7883c281216350ce2a461c0f9a011faef8b3f
- Huly: 1C-944
- Tracked files copied without semantic edits: 490.
- Original worktree verified clean. Do not modify, remove or deprecate it in this phase.
- Generated build directories, private secrets and customer topology not copied.

## Staged acceptance

1. Preserve wire-compatible four-crate code and source-file digests.
2. Rename new Rust packages/binaries to HostLink names without changing persisted wire IDs
   or data signing bytes. Keep migration mapping explicit.
3. Remove onec-core path dependency using minimal neutral and independently licensed
   primitives; no 1C domain models.
4. Independently compile/test Hub, controller, Agent and protocol.
5. Preserve run-local/Cargo/Nextest runner behavior, argv/output/cleanup and Windows 7 support.
6. Define independent installation/release assets; no onec.exe in the new package.
7. Add SSH exec for embedded target SSH; preserve RPC path until native parity. Implement
   caller-supplied PowerShell scripts through SSH, not a dependency manager or Hub executor.
8. In a separate authorized phase, migrate consumers and installations; only then remove
   old access crate ownership from Toolkit.

## Baseline reference

See upstream-files.sha256 for a complete source snapshot digest map.
