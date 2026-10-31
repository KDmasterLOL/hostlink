# 1C-1147: production self_update-first cutover

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
OS-resolved LocalAppData, absent Scheduler/legacy autorun registration and a
separate updater outside bin, and checks matching installed-image processes.
`same-file 1.0.6`, already in Cargo.lock, owns Windows file identity comparison.
No job tables are read, no missing DB is initialized, and no service is restarted.

The archive hook enforces the existing exact ZIP index/member order, no symlinks
or traversal, bounded compressed/expanded sizes, unique manifest entries,
version/target and all file hashes. Limits: 512 MiB compressed/total expanded,
256 MiB per entry and 64 KiB manifest/metadata. **The compressed cap is checked
after download**: high-level self_update 1.3.1 does not forward low-level
Download::max_download_size. The timeout is not a byte cap. No streaming bound
or custom download implementation is invented.

The bundle hook verifies extracted identities, makes the Linux Agent executable,
replaces manifest.json with format-2 install.json and validates its exact inventory.
The library swaps the entire root hostlink-agent-TARGET bundle into ROOT/bin.
Executable, support scripts and metadata therefore publish together; state/jobs/keys
are outside the swapped tree. A returned success is read back against the pins.
Post-publication read-back failure returns an error; the library stash is already
released at that point, so there is no HostLink rollback for such an error.

The reader prefers **validated** bin/install.json format 2. It falls back to
private legacy root/install.json format 1 only when bin metadata is absent, and
validates the old inventory too. Invalid new metadata never falls back. Legacy
root metadata is retained unchanged. A same-digest legacy installation is
republished once to migrate metadata; format-2 same version/SHA is idempotent and
requires no download, after root/locks/offline admission and integrity validation.

## Deletion and bootstrap compatibility

The disabled probe, feature/example, platform publishers, update_handoff journal,
transaction backups/cleanup/replay and their obsolete tests are removed. There is
no second installed-update backend. A small refusal for retired journal files is
retained; they are never interpreted/deleted. The bounded content validator has
one owner shared by update and bootstrap.

Fresh bootstrap-verify/bootstrap-finalize retain their CLI and format-1 output,
source-sidecar hash and receipt checks, enrollment pending marker and private
state/output policy. PrivateTempDir and precreated private extraction files are
now **bootstrap-only**, preserving the existing first-install contract; they are
not another installed updater. Install scripts retain their first-install flow.
The PS2 Run wrapper and service registration accept nonsecret bin; the Update
wrapper invokes the URL CLI rather than returning Unsupported. Native PS2 runtime
proof is still required; static source/packaging tests do not establish it.

## Verification

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
