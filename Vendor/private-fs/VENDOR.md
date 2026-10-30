# Vendored private-fs

- Upstream: https://github.com/orielhaim/private-fs
- Release: `v0.2.1`
- Pinned source commit: `07d542518b76d4eef6200523b6a7a57dd401b0e7`
- License: MIT OR Apache-2.0 (see `LICENSE-MIT` and `LICENSE-APACHE`)
- Use: HostLink Agent private filesystem capabilities, including Win7 x86/x64.

Source files were copied from the exact upstream Git revision, excluding the
inner `.git` repository. The nested `[workspace]` block was removed from
`Cargo.toml` so Cargo can include this path dependency in the HostLink
workspace. Local Windows 7 compatibility changes should be restricted to
the native Windows backend and documented in this file.

When updating, review upstream diffs and preserve all HostLink-specific
compatibility changes. Do not blindly replace this directory with `main`.
