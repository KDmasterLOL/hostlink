# HostLink Agent: updates and first installation

This directory does **not** implement a second updater. The installed Agent is
updated by the upstream `self_update` crate. Most of the code here handles
HostLink's **installation policy**, **installed-file identity** and **fresh
enrollment bootstrap**. Those are different jobs that currently share this
module.

Start with [`mod.rs`](mod.rs) for the public `apply` entry point and
[`publication.rs`](publication.rs) for the actual `self_update` call.

## Installed Agent update

Entry point: `hostlink-agent update --root ROOT --url URL --sha256 SHA --target
TARGET --version VERSION` ([CLI](../commands/update.rs)).

1. `Artifact::new` ([`artifact.rs`](artifact.rs)) accepts one exact
   version, target, HTTPS URL and independently supplied SHA-256. Its
   `ReleaseSource` exposes that single artifact to `self_update`: it does not
   query GitHub releases or select `latest`.
2. `apply` ([`mod.rs`](mod.rs)) calls
   [`admission.rs`](admission.rs) to validate the private install root and
   acquire `update.lock` and `jobs/runner.lock`. Windows additionally
   requires an unregistered/stopped task, a separate updater executable outside
   `bin/`, and no running installed Agent image
   ([`windows/mod.rs`](windows/mod.rs)).
3. [`installed.rs`](installed.rs) reads and verifies the installed files.
   Format 2 stores `install.json` within `bin/`; format 1 in the private
   install root remains readable for migration. An already-current format-2
   install returns without downloading.
4. [`publication.rs`](publication.rs) configures
   `self_update::backends::custom::Update` and calls **`update_extended()`**.
   The library downloads the pinned archive, verifies its SHA-256, extracts the
   bundle and swaps the staged directory into `ROOT/bin`.
5. The `verify_archive` hook uses
   [`archive/contents.rs`](archive/contents.rs) for the minimal expected-file
   set, paths, declared size bounds and package manifest. The `verify_binary`
   hook checks the **extracted** files against that manifest, writes format-2
   `bin/install.json` and checks the bundle **before** the swap. The two hooks
   share verified manifest data via `OnceLock`.
6. The installed package identity is read back after the upstream operation.
   `apply` reports `Installed` or `AlreadyCurrent`; it does not restart the
   Agent or touch `state/`, `jobs/` or `keys/`.

There is **one** installed-update publishing mechanism: `self_update`.
The code above supplies the product-specific constraints around it, not a
replacement downloader, ZIP extractor, publisher or rollback engine.

## Fresh installation is a separate workflow

First installation is not `update`. The installer downloads an independently
SHA-256-pinned target-specific verifier executable (the *sidecar*) and package
ZIP **before requesting the enrollment token**.

- `bootstrap-verify` calls
  [`bootstrap.rs::verify_fresh_package`](bootstrap.rs). It checks the archive
  digest, target and version, and uses
  [`archive/mod.rs`](archive/mod.rs) plus `self_update::Extract` to stage the
  package. Extracted member hashes and the sidecar's executable hash must match
  the package manifest. A fresh private output is published only after those
  checks.
- [`staging/mod.rs`](staging/mod.rs) keeps fresh-install temporary directories
  private at creation, including on Windows. This is a bootstrap requirement,
  not a second installed-update staging engine.
- The installer performs enrollment and places the verified package in the
  new Agent root. `bootstrap-finalize` then checks the installed package,
  receipt, private state and pending marker before clearing that marker.
- [`manifest.rs`](manifest.rs) defines the package manifest, bootstrap
  receipt, installed metadata formats and required filenames.

The bootstrap checks cannot be replaced by the installed-update
`publication::update` path: at this point there is **no existing installation**,
and the verifier sidecar must match the package before an invitation is
consumed.

## Source map

| File | Responsibility |
| --- | --- |
| [`mod.rs`](mod.rs) | Public `apply`, idempotence, request/outcome and shared constants |
| [`publication.rs`](publication.rs) | Configures and invokes **upstream `self_update`**; verifies staged and published bundle |
| [`artifact.rs`](artifact.rs) | Exact caller-approved artifact and `self_update::ReleaseSource` adapter |
| [`admission.rs`](admission.rs) | Private-root checks, process locks and retired-journal refusal |
| [`windows/mod.rs`](windows/mod.rs) | Windows-only stopped-process and Task Scheduler admission |
| [`installed.rs`](installed.rs) | Installed inventory and format-1/format-2 readback |
| [`manifest.rs`](manifest.rs) | Package, receipt and installed-metadata types |
| [`archive/contents.rs`](archive/contents.rs) | Shared ZIP preflight using upstream `zip`, not a custom ZIP parser |
| [`bootstrap.rs`](bootstrap.rs) | Initial package verification and post-enrollment finalization |
| [`archive/mod.rs`](archive/mod.rs) | Private **bootstrap-only** package copy/extraction and file verification |
| [`staging/mod.rs`](staging/mod.rs) | Private temporary-directory lifetime for first installation |
| [`private_fs.rs`](private_fs.rs) | Shared file identities, private-path checks and Windows profile lookup |
| [`tests/`](tests/mod.rs) | Unit/HTTP integration fixtures; separate bootstrap lifecycle tests live under `crates/agent/tests/` |

## Why not just one `update()` call?

For an application that only replaces its own executable, a short
`self_update` builder call is often enough. HostLink additionally requires
independent artifact pins, stopped-Agent admission, preserving private
enrollment/jobs/keys, exact installed-file identity, legacy metadata migration
and an independent first-install protocol. Upstream `self_update` cannot infer
those HostLink requirements.

That does **not** mean all existing checks are permanently necessary:

- **Worth separating structurally:** move `bootstrap.rs`, private bootstrap
  staging and bootstrap-only filesystem code into an installation-owned module.
  This makes the updater smaller *to navigate* without deleting behavior.
- **Worth evaluating for removal:** format-1 fallback and bootstrap receipts
  once existing deployments are demonstrably migrated; overlapping
  filesystem/path wrappers when `private-fs` already guarantees the same
  invariant. These require source-exact regression tests, especially on Win7.
  Also review whether hashing the staged bundle in `prepare_bundle` and
  hashing it again after publication in `installed::read` is worth
  the additional I/O. The latter is a post-publication readback, not a
  second update implementation.
- **Keep while required by product policy:** exact archive hash, installed
  integrity, offline admission, state isolation, package-to-sidecar equality
  and bounded package processing. These are not supplied by a bare
  `self_update` invocation.
- **Already removed:** the handwritten ZIP central-directory parser, the
  experimental `rawzip` dependency, bespoke installed-update publishers,
  Windows handoff and durable recovery journal.

Do not reintroduce strict ZIP byte/layout canonicality merely to restore
historical tests. Upstream `zip` checks header consistency; HostLink checks
the expected member set and verifies the extracted files before publication.

## Limitations and references

- `self_update` currently bounds the **downloaded** archive only after the
  download. The archive preflight bounds **declared** uncompressed sizes, not a
  strict streaming decompression budget for deliberately false ZIP headers.
  Artifact SHA-256 must come from an independently trusted source.
- Upstream rollback covers ordinary in-process swap failures on a best-effort
  basis. An abrupt kill or power loss during rename may leave `bin/` missing.
  There is no automatic durable crash recovery.
- Windows 7/11 native Task Scheduler, PowerShell 2 and updater acceptance
  remain separate release gates; cross-compilation alone is insufficient.

See [`docs/SELF_UPDATE_REWRITE.md`](../../../../docs/SELF_UPDATE_REWRITE.md)
for the accepted updater contract,
[`docs/ARTIFACTS_AND_INVITES.md`](../../../../docs/ARTIFACTS_AND_INVITES.md)
for package construction and
[`AGENTS.md`](../../../../AGENTS.md) for repository-wide constraints.
