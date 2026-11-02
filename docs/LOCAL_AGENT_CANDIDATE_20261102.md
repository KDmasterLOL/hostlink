# HostLink Agent local candidate — 2026-11-02

This is **local packaging and test evidence only**, associated with Huly
1C-1011 and the source revision
`0c195d760be295bc4b75952aa12e1f8a5834b923`
(workspace version `0.1.0`). The Git source used to build was a **clean,
detached exact-SHA** HOME Linux worktree under
`$HOME/.local/share/hostlink-v2-operational/source-0c195d760be2`.
Subsequent documentation-only commits on `dev` do not change this source
identity. No `main` update, tag, release, installed server Agent, or
production cutover has occurred.

## Local source-bound raw executables

The existing `scripts/package-hostlink-agent.py` created one owned raw
binary plus a private `artifact-receipt.json` per target. The existing
`scripts/stage-hostlink-github-release.py --require-all-targets` then
validated **exactly four** packages (no ZIP, sidecar or extra files) and
produced a local stage directory and hidden `.release-receipt.json`.

| Agent target | Bytes | SHA-256 |
| --- | ---: | --- |
| `x86_64-unknown-linux-gnu` | 26,376,704 | `915768f0b128c228c32250ce1f829ae828621a0ea4e4a68b7b7f1330d261699c` |
| `x86_64-pc-windows-msvc` | 20,604,416 | `e332350abe7ec128c2cace13334c57dcc65ebbae39f2a3be90c853c22b972fe0` |
| `x86_64-win7-windows-msvc` | 20,607,488 | `a45d892799123356d0b34db578270657bb421b11420488429312aabd2b847ace` |
| `i686-win7-windows-msvc` | 17,072,640 | `2beae5bdeb9984fb351d15f3b5f3478660da6595af6c468ef30d5af226f3a6ab` |

Local stage: `target/staged-agent-assets-0c195d/` in the pinned
worktree (ignored by Git). Source-bound package receipts:
`target/source-exact-agent-packages-0c195d/{target}/artifact-receipt.json`.
These locations are **not public release URLs**. The actual four binaries
and local receipt were independently rehashed from staged bytes, with
`FOUR_RAW_ASSETS_SOURCE_BOUND_PASS`; no extras.

## Build and native evidence

- Win7 x64 and i686: pinned `nightly-2026-08-22`,
  `cargo-xwin 0.23.1`, SDK `10.0.26100.0`,
  CRT `14.44.17.14`, `clang-cl` and
  `RUSTFLAGS=-C target-feature=+crt-static`, with
  `build-std=std,panic_abort`. The source-bound
  `target/win7-0c195d-20261102/receipt.json` reports
  `PE_BUILD_AND_INSPECTION_PASS`: machine `0x8664`/`0x14c`,
  subsystem 6.0 and static CRT import checks PASS. **Native Win7
  acceptance for this revision remains NOT RUN.**
- Windows 11 x64: local HOME `cargo-xwin` release build with static CRT,
  `llvm-readobj` machine `0x8664`, subsystem 6.0 and imported DLLs
  reviewed. On actual WORK Windows 11 `10.0.26100`, the raw exe was
  transferred to a disposable user TEMP file, its SHA-256 verified, then
  `hostlink-agent --version` printed `0.1.0` and
  `hostlink-agent binary-info` returned
  `{"version":"0.1.0","target":"x86_64-pc-windows-msvc"}`.
  Exit code 0 and scratch removal verified. **This is a binary/native
  loader smoke, not Agent installation or running SSH/Task Scheduler.**
- Linux x64: actual private HOME managed pilot Agent package at the same
  source SHA was independently hashed; the local Hub v2, Caddy and gateway
  authenticated `home-v2-pilot` via pinned SSH, and the HOME Client
  preserved remote `exit 7`. The independently installed HOME and WORK
  Clients share the binary source revision, but WORK is **not yet
  authorized as a second Hub operator**.

## Outstanding release and deployment gates

Source-exact tests of Windows Agent enrollment, private installed state,
Win7 PowerShell 2 bootstrap, stopped-only update/rollback, Windows
Job Object containment, real bare Win7 x86, and approved server coexistence
remain required. The external Hub v2 HTTPS address and restricted reverse
gateway routing have not been published: the old
`https://ops.bulzavr.ru/v2/info` returned HTTP 404 on 2026-11-02,
and the HOME edge FRP client reports `port not allowed` for existing
routes. Existing OneC Hub/Agent/services/databases were not touched.

The required next deployment gate is a **specific authorized test server**,
owning user, isolated Agent root, external Hub/gateway mapping, exact
artifact SHA, bounded native health check, and reversible rollback receipt.
The four files must not be presented as a published or production-accepted
release until those criteria and separate publication authorization hold.

See [HOME local pilot](HOME_PILOT_SERVICE.md),
[Win7 acceptance](WIN7_REWRITE_ACCEPTANCE.md) and
[Agent install](AGENT_INSTALLATION.md).
