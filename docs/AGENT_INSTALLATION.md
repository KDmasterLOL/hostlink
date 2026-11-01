# Agent update and bootstrap — current contract (1C-1155 / 1C-1156)

HostLink uses upstream `self_update 1.3.1` to download, SHA-verify and swap
installed Agent bundles. Fresh enrollment is distinct because it must verify
an independently pinned executable sidecar and ZIP before using an invitation.

## Installed Agent: `crates/agent/src/update.rs`

`hostlink-agent update --root ROOT --url URL --sha256 SHA --target TARGET --version VERSION`

The Rust interface is one public function:
`update(root, url, sha256, target, version) -> io::Result<bool>`.
`true` means installed; `false` means already current.

1. Require a parsed credential-free HTTPS URL (no fragment), a supported
   runtime target, an exact semantic version and an independently supplied
   lowercase archive SHA-256. The URL may contain ordinary percent encoding,
   a query string or an arbitrary CDN asset name; its path is **not** proof
   of the archive's version, platform or publisher.
2. Validate the private root and acquire both `update.lock` and
   `jobs/runner.lock`. On Windows the Task Scheduler registration must be
   absent, a verified separate updater must run outside `bin/`, and the
   installed Agent executable must not be running.
3. Read the existing `bin/manifest.json` and `bin/archive.sha256`, validate
   exact file identities, and skip the download only if **both** version and
   archive digest already match. Different content at the same version
   remains an explicit reinstallation; a matching SHA with conflicting
   version is an error.
4. Configure one `self_update::backends::custom::Update` with the selected
   version/URL, expected archive checksum, ZIP preflight and extracted
   bundle verification. The upstream library downloads/extracts/swaps the
   bundle, with only best-effort in-process rollback.
5. Retain the **verbatim** source `manifest.json` in the new `bin/`, append
   `archive.sha256` containing the verified ZIP digest, and verify the
   installed manifest and files after publication.

A tiny private `ReleaseSource` adapter remains because the library's
custom backend requires this trait even when the caller already selected
exactly one download URL. Replacing it with the built-in GitHub backend
would change how exact independently pinned sources are selected.

The updater consumes an artifact selected by the local operator/caller; it
does not authenticate an otherwise arbitrary URL/hash pair or implement a
trusted-publisher allowlist. The expected SHA-256 must therefore be obtained
**independently from an authorized, trusted source**. `ureq` explicitly
disables redirects and environment proxies and retains a 30-second global
timeout. These are intentional deviations from `ureq 3.4.2` defaults.
`self_update 1.3.1` already defaults to zero retries; it is not separately
configured. An explicitly selected older version remains an allowed
downgrade under the current exact-artifact contract; there is no implicit
`latest` selection or anti-rollback policy.

The updater does not read or modify the Apalis database, state, keys,
registration or service lifetime. The root remains private; the nonsecret
`bin/` may use upstream native file permissions.

## Package format

The release ZIP is produced by `scripts/package-hostlink-agent.py` and
contains a `hostlink-agent-TARGET/` directory with the executable,
Windows helper scripts (for Windows targets) and **one** `manifest.json`.
The manifest contains `format` (2), `component` (`agent`), `target`,
`version` and the exact file size/SHA-256 map (`files`).

This **same manifest** is retained verbatim after extraction; no
`install.json` or duplicated installed-metadata schema is created.
The ZIP's SHA-256 cannot appear inside itself without a self-reference,
so the updater or fresh bootstrap adds `archive.sha256` alongside the
manifest **after verification**. Both files travel together in the
published `bin/` bundle, preserving source digest/version identity and
same-version reissue detection.

## Fresh installation: `crates/agent/src/bootstrap.rs`

1. Linux shell/PowerShell 2 scripts independently pin the ZIP and verifier
   sidecar, invoking `bootstrap-verify` before asking for the invite token.
2. The verifier checks source SHA, complete safe ZIP member inventory,
   extracted file digests, target/version, and its own executable against
   the package member. A newly created private staging folder contains
   the actual verified member files, **verbatim `manifest.json`**,
   `archive.sha256` and a separate `bootstrap-receipt.json`.
3. After enrollment, the installer copies member files, `manifest.json`
   and `archive.sha256` to `ROOT/bin/` and the bootstrap receipt to the
   private root. No archive-pinned secret is placed in the bundle.
4. `bootstrap-finalize --root ROOT` rechecks installed source and file
   digests, receipt, private state and pending marker. It clears the marker
   only on success. Unknown legacy formats are not adopted.

| Ownership | Location |
| --- | --- |
| Single installed-update API and upstream call | `crates/agent/src/update.rs` |
| Source-pinned fresh enrollment | `crates/agent/src/bootstrap.rs` |
| Shared ZIP preflight and manifest/installed identity | `crates/agent/src/package/` |
| Private path/file helpers | `crates/agent/src/agent_files.rs` |
| Windows stopped-image check | `crates/agent/src/service/offline.rs` |
| Disposable update and bootstrap regressions | `crates/agent/src/update_tests/`, `crates/agent/tests/bootstrap_lifecycle.rs` |

## Boundaries

- SHA-256 must come from an independently trusted artifact publisher.
- Installed-Agent updates do not enforce a release filename or version
  segment in the download URL. The ZIP manifest and extracted file hashes
  enforce the requested target/version **after** the archive checksum gate.
  Fresh enrollment/sidecar bootstrap has a separate source-validation
  contract and is not changed by this updater-only simplification.
- The ZIP compressed-size bound is checked **after** the upstream download.
  Declared expanded sizes are not a strict streaming quota against
  deliberately false ZIP headers.
- Power loss between upstream directory renames can leave `bin/` absent;
  there is no durable crash recovery or automatic service restart.
- Windows 7/11, PowerShell 2, Task Scheduler and actual running-process
  behavior require native acceptance, not just cross-compilation.

See [source layout](SOURCE_LAYOUT.md), [Windows offline update](AGENT_UPDATE_WINDOWS.md),
[artifact packaging](ARTIFACTS_AND_INVITES.md), and
[historical integration evidence](SELF_UPDATE_REWRITE.md).
