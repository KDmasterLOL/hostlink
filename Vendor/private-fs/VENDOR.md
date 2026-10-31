# Vendored private-fs

- Upstream: https://github.com/orielhaim/private-fs
- Version: `v0.2.1`, source commit `07d542518b76d4eef6200523b6a7a57dd401b0e7`.
- Licenses: MIT OR Apache-2.0 (tracked `LICENSE-MIT` and `LICENSE-APACHE`).
- HostLink integration: `Vendor/private-fs` as a Cargo path dependency.
  Only the upstream nested `[workspace]` declaration was removed for workspace integration.
- Scope: private Agent enrollment, credentials, SFTP, locks, updater and Apalis
  storage. Existing `PrivateDir`/`PrivateFile` public APIs remain unchanged.

## Intentional downstream changes

- **Win7 file identity:** use `GetFileInformationByHandleEx(FileIdInfo)` for modern
  128-bit file IDs; on known unsupported-class errors only, use the full
  64-bit `GetFileInformationByHandle` index/volume ID, restricted to **local
  NTFS with persistent ACL support**. Never truncate ReFS identities, accept
  remote volumes or equate legacy/extended identity representations.
- **Win7 no-reparse opens:** `NtCreateFile` first requests `OBJ_DONT_REPARSE`;
  only `STATUS_INVALID_PARAMETER`/`STATUS_INVALID_INFO_CLASS` permit the
  one-time retry without it. The retry retains `FILE_OPEN_REPARSE_POINT`,
  handle-relative single-component traversal and post-open type/reparse
  checks. Drive acquisition uses the current `QueryDosDeviceW` mapping of
  a drive letter to an exact local `\Device\HarddiskVolumeN` root, then
  retains that handle. Arbitrary namespace targets, SUBST, UNC and unsafe
  devices fail closed.
- **Windows owner-only ACL inheritance:** a protected user-only directory
  DACL uses `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` so SQLite's VFS
  creates `jobs.db`, `jobs.db-wal`, and `jobs.db-shm` with owner-only
  rights. Private regular files retain a noninheritable protected owner-only
  DACL. Foreign principals and existing non-conforming directories are not
  silently adopted or repaired. See
  `crates/agent/tests/private_fs_windows_sqlite.rs`.
- **Unix test fixture:** POSIX ACL tests use an available effective UID to
  support user namespaces rather than requiring unmapped UID 12345. Only a
  minimal default ACL probe is skipped on mounts rejecting that ACL with
  `EINVAL`/`EOPNOTSUPP`; production file policy is unchanged.

## Binding reproducibility

Win32 bindings use an isolated `windows-bindgen = 0.100` Cargo workspace.
Its build dependencies are not part of the Agent runtime graph. Generated
`FILE_DEVICE_DISK` and `FILE_REMOTE_DEVICE` constants have type `i32`;
the native backend casts them when comparing to Win32 `u32` device fields.

```sh
cargo run --locked --manifest-path Vendor/private-fs/tools/windows-bindings/Cargo.toml -- --check
```

## Verification and remaining compatibility gate

For source-level checks run formatter, Linux `private-fs` and Agent tests,
strict Clippy, the bindings parity command above, and Windows x64/i686
cross-checks. Tests in `src/windows/tests.rs` cover the legacy ID and
`OBJ_DONT_REPARSE` fallback, root/component restrictions, identity/reparse,
ACL inheritance and classic rename, including negative cases.

**Native Win7 SP1 x86/x64 and Win11 runs remain required** to establish
actual filesystem, Windows API, protected ACL/SQLite and reparse behavior.
An xwin check or successful PE build does not prove Win7 loadability or
runtime compatibility. Full Agent Win7 i686 source-exact build/import checks
are also separately gated. See Huly `1C-1141` for acceptance evidence.
Keep the fork minimal; preserve these invariants when rebasing upstream.
