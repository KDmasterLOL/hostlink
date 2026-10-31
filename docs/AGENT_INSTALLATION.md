# Agent update and bootstrap (current pre-release contract)

HostLink does **not** implement a second updater. Installed updates use the
upstream `self_update 1.3.1` high-level bundle transaction. Initial enrollment
is a separate workflow: there is no prior installation and the independently
pinned sidecar executable must be verified **before** consuming an invitation.

## Installed Agent: `crates/agent/src/update.rs`

`hostlink-agent update --root ROOT --url URL --sha256 SHA --target TARGET --version VERSION`

1. Validate the exact independently approved HTTPS URL, runtime target,
   semantic version and SHA-256. `ReleaseSource` exposes one release, not
   `latest` or discovery.
2. Verify the private install root; hold `update.lock` and
   `jobs/runner.lock`. On Windows require the current-user Scheduler task
   to be unregistered, a distinct updater executable under the root but
   **outside** `bin/` and no running process using the installed executable.
3. Read **only** `bin/install.json` (format **2**) and verify its exact
   installed-file SHA-256 inventory. Missing or old metadata is an error.
4. Return `AlreadyCurrent` for matching version and pinned digest.
   Otherwise call `self_update::backends::custom::Update::update_extended()`
   exactly once. The library downloads the ZIP, verifies its SHA-256, extracts
   and swaps the whole bundle with best-effort in-process rollback.
5. The archive hook checks required ZIP members and manifest via
   `package/contents.rs`. The binary hook replaces `manifest.json` with
   `install.json` format 2 and verifies **extracted** file identities before
   publication. The returned bundle is also verified after publication.

There is no format-1 installed-metadata fallback/migration, retired-journal
compatibility guard, HKCU Run compatibility logic or custom publishing engine.
No updater operation writes into `state/`, `keys/` or the Apalis database.

## Fresh installation: `crates/agent/src/bootstrap.rs`

`hostlink-agent bootstrap-verify --archive ZIP --sha256 SHA --target TARGET --version VERSION --output DIR`

1. The shell/PowerShell 2 installer downloads independently SHA-pinned ZIP
   and target-specific verifier executable (sidecar), then runs
   `bootstrap-verify` **before asking for the invitation token**.
2. The sidecar checks archive SHA, manifest, required files, extracted hashes
   and that its own executable matches the ZIP member. It publishes a **new
   private directory** with binaries, `install.json` format 2 and
   `bootstrap-receipt.json`. Private Windows ACLs are set at creation.
3. After enrollment the installer copies the binaries to `ROOT/bin/`,
   copies metadata to **`ROOT/bin/install.json`** and the receipt to
   `ROOT/bootstrap-receipt.json`. It never creates `ROOT/install.json`.
4. `bootstrap-finalize --root ROOT` checks installed files, private
   `state/agent.json`, receipt and pending marker, removing the marker only
   on success.

Package manifest and bootstrap receipt use their own **current format 2**.
Other enrollment and Hub wire formats are independently versioned.

## Shared source map

| Location | Purpose |
| --- | --- |
| `update.rs` | One installed-update entry point, locks, artifact and upstream hooks |
| `bootstrap.rs` | Fresh sidecar/ZIP verification, protected staging and finalize |
| `package/mod.rs` | Current package and installed-metadata structures |
| `package/contents.rs` | Safe ZIP member set, declared limits and manifest |
| `package/installed.rs` | Exact installed `bin/` hashes and format-2 metadata |
| `agent_files.rs` | Private paths/root, file identities and Win7 profile lookup |
| `service/offline.rs` | Windows-only offline process identity guard |
| `service/windows.rs` | Windows Task Scheduler register/start/remove/status |
| `update_tests/` and `tests/bootstrap_lifecycle.rs` | Disposable regression tests |

See [source layout](SOURCE_LAYOUT.md),
[Windows offline update](AGENT_UPDATE_WINDOWS.md) and
[artifact packaging](ARTIFACTS_AND_INVITES.md).

## Limits

- Archive SHA-256 must be supplied from an independently trusted source.
- The compressed-size guard is applied **after** the upstream download;
  declared expanded ZIP sizes do not provide a strict streaming byte quota
  for a maliciously crafted archive.
- Power loss between upstream renames may leave `bin/` absent; no
  crash-durable recovery or automatic restart is promised.
- Windows 7/11, PowerShell 2, Task Scheduler and installed-process guards
  still need native source-exact acceptance. Cross-compilation is not a
  substitute for native execution.
