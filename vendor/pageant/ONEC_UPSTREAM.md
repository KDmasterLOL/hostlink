# Vendored Pageant

Upstream: https://github.com/warp-tech/russh
Crates.io version: `0.2.3`
Upstream VCS base: `8a51a0dca4f6fbdcc3ce98c627254026b25b3252` (`pageant`)
Crates.io checksum: `6d8eab09a361a4afe0b1668be978cd97e4f052e927a92b0b608cf902965d49ce`

The vendored tree is based on the published crates.io 0.2.3 source snapshot.
The published crate archive SHA-256 was verified against its crates.io checksum;
all local deltas are listed below. The published library `Cargo.lock` is omitted:
the workspace root `Cargo.lock` is the authoritative reviewed lock for this path
override, matching the existing vendored-library convention.

Local compatibility deltas for Windows 7 builds:

- Pin the existing `windows` dependency to exactly `0.61.3`, retaining its
  upstream `Win32_Security` feature.
- Pin optional `windows-strings` to exactly `0.4.2` for the `namedpipes`
  feature, matching windows-core 0.61.2 and the workspace Windows bindings.
- In `src/error.rs`, use `windows::core::Error::from_win32()` in Pageant's
  existing `Error::from_win32()` helper, as exposed by windows-result 0.61.

No Pageant features or functionality are removed. The security-fixed 0.2.3
implementation is otherwise unchanged.

Verification for this patch: locked checks for `onec-agent` and `onec-cli`,
strict Clippy and tests for those owners, pinned xwin release builds for the
current x64 and both Win7 targets, import inspection of both Win7 `onec.exe`
binaries, and an unchanged passing `just managed-binaries` forbidden-import
gate.

Remove this local patch when an upstream Pageant release supports the workspace
Windows 0.61.3 / windows-strings 0.4.2 dependency generation and its
`Error::from_win32()` API. Verify the Pageant APIs and all listed compatibility
gates before removal.
