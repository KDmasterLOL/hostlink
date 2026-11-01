# History of the Agent self_update integration

> 1C-1164 supersedes historical ZIP/installer/release-manifest guarantees below.
> The binary-only contract is [GitHub Releases](GITHUB_RELEASES.md) and
> [installation](AGENT_INSTALLATION.md). Keep private `state/manifest.json`.
> Historical test counts do not validate this source or native raw installation.

**Current binary-only contract (1C-1164):** [GitHub-only release and credential contract](GITHUB_RELEASES.md) and [Agent installation](AGENT_INSTALLATION.md).
All specific versions and manual URL examples below are **historical** and not current CLI instructions.
The sections below record the **historical** source-exact 1C-1147/1149/1153
decisions and their own test evidence. Their `install.json` transformation,
`Artifact` constructor, `AgentUpdateRequest` and `AgentUpdateOutcome` refer to
superseded code and are **not** requirements of current `dev`.

## 1C-1155 — direct source manifest / minimal update interface

The 1C-1155 version of the Agent had one public
`update(root, url, sha256, target, version) -> io::Result<bool>`.
The high-level upstream `self_update::backends::custom::Update` remains the
only downloader, ZIP extractor and bundle publisher. The exact caller-selected
HTTPS URL, version, target and independently supplied full ZIP SHA-256 stay
pinned. A minimal one-`Release` adapter is required by upstream
`custom::Update::source`; GitHub auto-discovery would change that contract.

The source release `manifest.json`, containing file SHA-256 identities, is
copied **unchanged** into `bin/`. After the upstream checksum check the
staged bundle receives a 64-byte `bin/archive.sha256` file. This digest
cannot be embedded in its own archive without a cryptographic self-reference.
The two metadata files swap atomically with the executable and scripts.
The archive hook still checks ZIP safety/required member inventory; the
binary hook verifies the extracted files before publication. There is no
manifest-to-install conversion, duplicated installed metadata struct,
`OnceLock` sharing, bespoke rollback or installed-format migration.
The same-version/different-digest case still installs the selected exact
source; equal-version/equal-digest requests are idempotent.

Fresh bootstrap separately verifies the sidecar and ZIP before enrollment,
retains `manifest.json`, adds `archive.sha256` and checks the source receipt.
Private root, keys, jobs and state stay outside the published bundle. Windows
requires an unregistered task and an independent stopped Agent process.

### 1C-1157 — typed inputs and GitHub Release selection

The pinned Rust update API accepts parsed `Url`, exact `Version`, and a
32-byte SHA-256 decoded from CLI input by `hex`. The no-argument Agent
`update` selects the newest compatible stable release from the fixed
private GitHub repository; `--version X.Y.Z` selects that version explicitly.
Both use the existing `self_update` package and stopped-Agent checks.
GitHub's API-published SHA-256 is verified but is not an independent
publisher signature. Exact operator-pinned URL/SHA mode remains available.
Private repository access requires suitable GitHub credentials. No published
HostLink Releases existed at the 2026-11-01 baseline, so live latest
installation cannot be claimed until an approved release is published.

### 1C-1156 — updater URL policy and error semantics

The installed updater accepts a normal parsed credential-free HTTPS URL,
including percent-encoded paths, optional query strings and arbitrary asset
basenames. It does **not** infer publisher, target or version identity from
the textual URL. The caller/operator must independently trust the supplied
archive SHA-256; `self_update` verifies that digest before ZIP extraction,
and HostLink checks the manifest and extracted bundle against the selected
target/version and expected per-file hashes. The parsed canonical URL is used
for the actual fetch. The existing exact pinned release selection also permits
an explicit older-version install (no implicit anti-downgrade guarantee).

The upstream `self_update 1.3.1` default is already zero retries. The custom
`ureq 3.4.2` client **still** disables redirects and environment proxies,
because its defaults would allow both, and still enforces a 30-second timeout.
Runner-lock errors now preserve their original I/O kind unless the lock is
actually contended (`WouldBlock`); unexpected filesystem errors must not
masquerade as a running Agent. Bootstrap-side source URL/pin validation is a
different enrollment contract and remains unchanged.

**Acceptance caveat:** this entry is a design/implementation description;
the historical test matrix later in this document belongs to the older source
commit. New source-exact test results must be recorded separately.

---

## Historical 1C-1147 contract


Base: dev@b7f93f46150ab86780eec5bad643ee325462b483. Author worktree/branch:
`task/1c-1145-self-update-rewrite-20261031`. No dev/main/tag/release, installed
Agent, original checkout or production operation is part of this change.

## Authorized contract change

The user's 2026-10-31 instruction and Huly comment `6ae58513ccc4a30009b609f1`
explicitly replace bespoke updater staging protection with self_update's native
filesystem behavior. Temporary archive/bundle and bin are nonsecret. Persistent
root/state/jobs/keys remain private. AGENTS.md now records that contract.

Recovery on an ordinary publication error means upstream in-process best-effort
rollback, not durable recovery after process death. This is an authorized
reduction of the former journal guarantee. No automatic recovery is claimed:
**a kill/power loss between bundle renames may leave bin missing**, and a failed
rollback can also require manual reconciliation. Upstream logs a restoration
failure and returns the original publication error. There is no restart/health
handoff or higher-level journal recovery.

## One installed update path

`hostlink-agent update --root ROOT --url URL --sha256 SHA --target TARGET --version VERSION`
uses pinned self_update 1.3.1 custom::Update and checksums. The supplied immutable
artifact tuple is the trust input; there is no built-in discovery/allowlist. Only
credential-free HTTPS URLs with a literal nontraversing path, a version segment
(version or vVERSION), and hostlink-agent-TARGET.zip filename are accepted. No
percent-encoded/ambiguous path, fragment, embedded user information or zero port.
The public constructor never accepts HTTP; private unit fixtures use nonzero
127.0.0.1 HTTP ports with the same real pipeline. ureq 3.4.2 (already locked) is
used directly to disable redirects/proxies and set a 30-second timeout; retries
are zero. Each ReleaseSource returns exactly one asset and release_tag forces
that exact version even for equal/downgrade versions. Content identity remains
independent SHA-256, not a version-only decision.

The updater takes both exclusive update.lock and jobs/runner.lock for the entire
operation. It requires a real private root with no alias; Windows also validates
OS-resolved LocalAppData, absent Scheduler registration and a
separate updater outside bin, and checks matching installed-image processes.
`same-file 1.0.6`, already in Cargo.lock, owns Windows file identity comparison.
No job tables are read, no missing DB is initialized, and no service is restarted.

The archive hook uses the same patched `zip 9.1.3` crate as self_update. It
checks local-header consistency, duplicate names, safe required regular-file
inventory, declared size bounds and the manifest's exact target/version.
Physical central-record counts, comments, prefixes and member ordering are not
part of the trusted-package contract. Before publication the extracted files
are verified against the manifest, rather than hashing each ZIP member during
preflight. Limits: 512 MiB compressed/declared total expanded, 256 MiB per
entry and 64 KiB manifest/metadata. **The compressed cap is checked after
download**: self_update 1.3.1 does not forward low-level
Download::max_download_size. Declared expanded sizes are not a strict
streaming output quota for malformed archives. The timeout is not a byte cap.

The bundle hook verifies extracted identities, makes the Linux Agent executable,
replaces manifest.json with format-2 install.json and validates its exact inventory.
The library swaps the entire root hostlink-agent-TARGET bundle into ROOT/bin.
Executable, support scripts and metadata therefore publish together; state/jobs/keys
are outside the swapped tree. A returned success is read back against the pins.
Post-publication read-back failure returns an error; the library stash is already
released at that point, so there is no HostLink rollback for such an error.

The reader accepts **only** validated `bin/install.json` format 2. A missing
or old-format metadata file fails clearly; there is no root/install.json
fallback, legacy migration or republishing solely to migrate metadata.
Format-2 equal-version/equal-digest updates are idempotent and require no
download after root/lock/offline and installed-file validation.

## Deletion and bootstrap compatibility

The disabled probe, feature/example, platform publishers, update_handoff journal,
transaction backups/cleanup/replay and their obsolete tests are removed. There is
no second installed-update backend. Compatibility with retired journal files
is not implemented because no installed clients need migration. The minimal archive/manifest reader has
one owner shared by update and bootstrap; `rawzip` and handwritten ZIP parsing are absent.

Fresh bootstrap-verify/bootstrap-finalize retain their CLI and now emit only
format-2 install metadata, with source-sidecar hash and receipt checks, enrollment pending marker and private
state/output policy. PrivateTempDir and precreated private extraction files are
now **bootstrap-only**, preserving the existing first-install contract; they are
not another installed updater. Install scripts retain their first-install flow.
The PS2 Run wrapper and service registration accept nonsecret bin; the Update
wrapper invokes the URL CLI rather than returning Unsupported. Native PS2 runtime
proof is still required; static source/packaging tests do not establish it.


## 1C-1149: one ZIP reader, no handwritten central parser

The 2026-10-31 user decision makes independently pinned archive identity and
safe extraction the product requirement, **not** canonical physical ZIP bytes.
The direct Agent ZIP dependency and self_update both resolve to `zip 9.1.3`
(patched for GHSA-m665-v7pm-7grj). The old `zip 6.0.0`, extra `rawzip`
probe and `archive/zip_index.rs` are removed. Validation requires the expected
set of files but accepts their order and benign ZIP comments/prefixes.
Negative tests remain for wrong pin/target/version, extra or missing members,
unsafe paths/symlinks, duplicated names, malformed headers and extracted
file-identity mismatches. These checks protect against wrong installations,
not ZIP-format canonicality. Fresh bootstrap still requires its separately
pinned verifier executable before the invitation secret is entered.

## 1C-1153: one updater file, fresh-only bootstrap, no installed legacy schema

The pre-release Agent now has one installed-update source `crates/agent/src/update.rs`,
a separate `bootstrap.rs` and shared `package/` modules. Both initial
installation and updates publish only `bin/install.json` format 2.
Initial package manifest and bootstrap receipt are likewise current format 2.
There is **no** format-1 installed reader, root-install-metadata migration,
retired-update journal guard or old HKCU Run compatibility lookup.
Windows process and Task Scheduler stopped-only checks still apply.

The installed updater is still exactly the upstream high-level
`self_update::backends::custom::Update`; first-install private staging is
not a second installed updater. For the current implementation and ownership
see [Agent installation](AGENT_INSTALLATION.md).

## Verification

The following receipt records the original `1C-1147@ba0e34a` cutover; it is
not a claim of re-running the full matrix after `1C-1149`.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check`, `git diff --check` | PASS |
| `cargo check --offline --locked --workspace --all-targets` | PASS |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --offline --locked -p hostlink-agent --lib` | PASS: 50/50, including 9/9 high-level URL updater tests |
| `cargo test --offline --locked -p hostlink-agent --test update_lifecycle` | PASS: 8/8 bootstrap and strict ZIP regressions |
| `cargo test --offline --locked -p private-fs --lib` | PASS: 91/91 |
| Agent Windows x64/i686 MSVC `cargo xwin check` and strict Clippy `--all-targets` | PASS: both targets |
| Win7 x64/i686 MSVC `cargo +nightly-2026-08-22 xwin check` and strict Clippy with `-Z build-std=std,panic_abort` | PASS: both targets (compile only) |
| `python3 -m unittest discover -s scripts/tests -p 'test_win7_bootstrap_harness.py'` | PASS: 7/7 |
| `hostlink-agent update --help`, `bootstrap-verify --help` | PASS: URL update and unchanged local bootstrap arguments |
| Entire Python contract suite | NOT VERIFIED: remote execution timed out after 85 seconds |
| Native Win7/Win11, PowerShell 2, Task Scheduler update, power-loss injection | NOT RUN |

The nine high-level updater tests use real loopback HTTP and disposable
directories. They cover exact URL/digest/manifest, legacy-to-bundle metadata
migration, same-version new digest, idempotence, refusal of redirects/symlinks,
upstream in-process rollback and preservation of actual queued Apalis SQLite
jobs. No installed Agent, customer machines or deployed services were modified.

**Release limitation:** Windows cross-target compilation does not prove that
new HTTPS/TLS and bundle renames work natively on Win7/Win11. Power-loss recovery
was traded for upstream best-effort rollback. A crash or failed restoration may
require manual repair; callers must not interpret an ambiguous update as success.
