# Win7 rewrite cross-build and acceptance evidence

This procedure builds only the current `hostlink-agent` and `hostlink` workspace
packages for both Windows 7 MSVC target triples. It does not run a binary on
Windows and cannot satisfy the NT6.1 acceptance gate.

## Why this uses build-std

Rust lists `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc` as Tier 3,
and does not ship precompiled standard-library artifacts for them. Building
therefore requires a nightly compiler with `rust-src` and `build-std`. The
workflow pins `nightly-2026-08-22`, `cargo-xwin` 0.23.1, xwin SDK
10.0.26100.0, MSVC CRT package 14.44.17.14, and `clang-cl`; it does not fall
back to `x86_64-pc-windows-msvc` or `i686-pc-windows-msvc`. Rust's [target
support page](https://doc.rust-lang.org/nightly/rustc/platform-support/win7-windows-msvc.html)
describes the target and cross-compilation prerequisites.

## Build a source-exact candidate

Run from any clean experimental rewrite worktree or detached immutable candidate,
after committing the exact source to be built. Select a new path below the ignored
`target/` directory each time:

```sh
export XWIN_CACHE_DIR="$HOME/.cache/hostlink/msvc-sdk-v17/mount"
export XWIN_ARCH="x86,x86_64"
SOURCE_SHA="$(git rev-parse HEAD)"
scripts/build-win7-candidate.sh \
  --source-sha "$SOURCE_SHA" \
  --output-dir "target/win7-candidate-$SOURCE_SHA"
```

The script accepts any clean source-exact integration/task worktree or detached HEAD.
The actual branch name (or `DETACHED_HEAD`) is recorded and checked again before
publishing artifacts, so final integrated release candidates are supported.
The script requires a clean Git worktree,
the full lowercase source SHA, Rust `nightly-2026-08-22` with `rust-src`,
`cargo-xwin` 0.23.1, and `llvm-readobj`. It builds each target using the
equivalent of:

```sh
RUSTFLAGS='-C target-feature=+crt-static' \
cargo +nightly-2026-08-22 xwin build \
  --cross-compiler clang-cl --xwin-version 17 \
  --xwin-sdk-version 10.0.26100.0 \
  --xwin-crt-version 14.44.17.14 \
  --locked --release --target TARGET \
  -Z build-std=std,panic_abort \
  -p hostlink-agent -p hostlink
```

The two values substituted for `TARGET` are exactly
`x86_64-win7-windows-msvc` and `i686-win7-windows-msvc`. Each result must contain
both `hostlink-agent.exe` and `hostlink.exe`. The script checks PE machine
`0x8664`/`0x14c`, PE subsystem version 6.0, imports, and rejects dynamic CRT
DLL imports despite the static CRT flag. It retains the complete
`llvm-readobj --file-headers --coff-imports` output and SHA-256 for each binary.

All cargo artifacts and unpublished output are staged below ignored `target/`.
The requested output path must not exist. A failed command removes its private
staging directory; the final evidence directory is published with one same-
filesystem rename only after both architectures pass inspection. The script
checks the exact HEAD and clean worktree before and after the build. Use a
different new output directory for each candidate rather than reusing old
artifacts.

`receipt.json` records the source SHA, branch, clean-worktree assertion, build
user and host, rustc/Cargo/cargo-xwin versions, pinned SDK/toolchain settings,
target triples, binary hashes, PE machine/subsystem, and imported DLL sets. Its
`status` is `PE_BUILD_AND_INSPECTION_PASS`; `native_acceptance.status` is always
`NOT_RUN`. The receipt is evidence for the source-bound build and static PE
inspection only. It does not claim runtime compatibility.

## Source-bound raw bootstrap parser fixtures (1C-1044)

On HOME, after committing the candidate and confirming a clean worktree, use a
new, empty owner-private directory outside all credentials and configuration.
The ignored test reads no token. It renders the six actual Windows helpers with
synthetic selection data and writes exact marker-delimited bytes plus nonsecret
`provenance.txt`. `private-fs` checks the directory, ownership, permissions and
path components; existing entries are refused. The receipt records HEAD and
checks the production renderer, selection and two script inputs against HEAD;
clean worktree also binds the test exporter itself to that commit.

```sh
git status --porcelain
git rev-parse HEAD
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hostlink-ps2-parse.XXXXXXXX")"
export HOSTLINK_PARSE_FIXTURE_DIR="$FIXTURE_DIR"
cargo test --offline --locked -p hostlink --lib \
  bootstrap::tests::export_raw_windows_parse_fixtures -- --ignored --exact
cat "$FIXTURE_DIR/provenance.txt"
sha256sum "$FIXTURE_DIR"/*.ps1
```

Transfer those six synthetic fixtures, their receipt, and
`scripts/verify-raw-windows-bootstrap-parse.ps1` from the same commit to a
private disposable directory on WORK or the authorized NT6.1 target. Compare
every filename/hash with the HOME receipt before parsing; record source SHA,
OS, architecture, actual `$PSVersionTable.PSVersion`, parser script hash and
exit code. Run from PowerShell with explicit paths, for example:

```powershell
$PSVersionTable.PSVersion
$files = @('C:\fixture\x86_64-win7-windows-msvc-prompt.ps1', 'C:\fixture\x86_64-win7-windows-msvc-embedded.ps1', 'C:\fixture\i686-win7-windows-msvc-prompt.ps1', 'C:\fixture\i686-win7-windows-msvc-embedded.ps1', 'C:\fixture\x86_64-pc-windows-msvc-prompt.ps1', 'C:\fixture\x86_64-pc-windows-msvc-embedded.ps1')
& 'C:\fixture\verify-raw-windows-bootstrap-parse.ps1' -Path $files
$LASTEXITCODE
```

Use Windows PowerShell 2 on native Win7 x64 and x86 for PS2 evidence; a newer
WORK parser is separate evidence. The script checks a malformed syntax case on
every run, reads only supplied files, and calls
[`PSParser.Tokenize`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.psparser.tokenize)
without executing their contents. Transfer only these generated synthetic
fixtures, never a real invitation or PAT. `PARSE_PASS` is **PARSE_ONLY**: it
does not establish GitHub download, enrollment, Task Scheduler, or full raw
release E2E.

**Native PS2 parse receipt (2026-11-03, Huly 1C-1044):** HOME clean
`dev@6930eb9d3c91aa5d834c8fc5f15087a429fbe6df` generated all six helpers
from the production renderer with only a synthetic GitHub credential. The
opt-in fixture test passed (1/1), its provenance reported
`production_render_inputs=match_HEAD`, and source SHA-256 matched for every
helper. The exact parser script SHA-256 was
`b531d508b5d60d92818bbda583477e815eeb482ad5e75c4ea0e6043f5ee3ea48`.
On the real SERVER-1C (Windows NT 6.1.7601, Windows PowerShell 2.0), all eight
transferred files (six helpers, parser, provenance) matched HOME SHA-256 in a
new owner-private disposable fixture directory. The parser reported
`MALFORMED_REJECTED` and **6/6 `PARSE_PASS`, exit 0**. Only the parser ran;
none of the bootstrap helpers was executed. This is native PowerShell 2
**syntax** evidence for the three target variants, not a Win7 x86 OS runtime
or actual binary download, invitation redemption, Agent install, service,
Task Scheduler, update, or private GitHub Release acceptance. Those gates
remain open under 1C-1044/1008/1011/1164.

## Raw artifact packaging and native harness retirement (1C-1164)

Package each exact Agent executable with the matching source SHA and
`receipt.json` from the builder:

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("crates/agent/Cargo.toml", "rb"))["package"]["version"])')"
for TARGET in x86_64-win7-windows-msvc i686-win7-windows-msvc; do
  scripts/package-hostlink-agent.py \
    --source-sha "$SOURCE_SHA" \
    --target "$TARGET" \
    --version "$VERSION" \
    --binary "target/win7-candidate-$SOURCE_SHA/$TARGET/hostlink-agent.exe" \
    --build-receipt "target/win7-candidate-$SOURCE_SHA/receipt.json" \
    --output-dir "target/win7-package-$SOURCE_SHA-$TARGET"
done
```

Output contains the exact raw `hostlink-agent-TARGET.exe` and a local
`artifact-receipt.json`. PE/build provenance remains required; no ZIP, SHA
sidecar, installer PS1, release manifest or bootstrap receipt is generated.

`scripts/verify-win7-bootstrap-native.ps1` is **RETIRED**: it throws before
reading inputs or executing any binary. Its archive-based `bootstrap-verify`
flow cannot validate the new binary-only install. The old ZIP harness and
asset-sourced bootstrap tests have been removed; no native replacement run is
claimed. Controller-generated bootstrap needs tests in its owning lane.

New native acceptance must use an independently verified disposable target
and source-exact raw assets after Agent/Controller integration. Exercise the
generated PS2 bootstrap with synthetic credentials, default hidden prompt and
explicit PAT opt-in; hash failure before Hub invite consumption; stable
LocalAppData/HostLink/Agent root; Rust install enrollment and executable
publication; no installed wrappers/default tools; protected target credential
ACL; preserved private `state/manifest.json`; and stopped-task/exclusive-lock
RAW update and ordinary rollback. Real release/network tests need separate
authorization; this source-only task uses no live machines or real PAT.

Record source/build/artifact digests, Windows OS/architecture, PowerShell
version, exit status and nonsecret results. Windows 11 x86/WoW64 is not a
native 32-bit Windows 7 or NT6.1 pass. **Native acceptance for 1C-1164: NOT RUN.**

## Builder guard cases

These deterministic negative checks can be run without compiling a candidate:

```sh
# Missing required arguments must fail.
! scripts/build-win7-candidate.sh

# A mismatched source identity must fail before invoking the compiler.
! scripts/build-win7-candidate.sh \
  --source-sha 0000000000000000000000000000000000000000 \
  --output-dir target/should-not-exist

# An uncommitted source edit must fail the clean-worktree preflight.
touch .win7-dirty-preflight.tmp
if scripts/build-win7-candidate.sh \
  --source-sha "$(git rev-parse HEAD)" \
  --output-dir target/should-not-exist; then
  rm -f .win7-dirty-preflight.tmp
  exit 1
fi
rm -f .win7-dirty-preflight.tmp
```

Missing-toolchain and x86 omission guards are also statically checkable without
building: the source must check the pinned rustup toolchain and `rust-src`,
declare both exact target triples, and reject any missing or empty executable.

```sh
rg -F 'pinned toolchain is missing: $TOOLCHAIN' scripts/build-win7-candidate.sh
rg -F 'rust-src is missing from $TOOLCHAIN' scripts/build-win7-candidate.sh
rg -F 'readonly TARGETS=(x86_64-win7-windows-msvc i686-win7-windows-msvc)' \
  scripts/build-win7-candidate.sh
rg -F '[[ -f "$built" && -s "$built" ]]' scripts/build-win7-candidate.sh
```

Missing pinned toolchain/component or inspection utilities fail in preflight
with a named diagnostic. Missing output for either architecture, wrong machine
or incompatible subsystem fails before publication. Do not infer a two-arch
build from a one-arch directory: both target entries and all four executable
hashes must be present in the receipt. `bash -n` checks script syntax; `git diff
--check` checks patch whitespace. Neither is a build or runtime test.

The live Visual Studio 17 component catalog does not currently expose SDK
10.0.22621.0 to `cargo-xwin`; the installer command fails before compilation.
The independently cached SDK 10.0.26100.0 includes both `x86` and `x86_64`
platform libraries and matching CRT. The builder now requires that exact
private cache and both target architectures rather than silently fetching a
newer SDK or falling back to a generic Windows target. Its newer SDK version
does not imply runtime support on Windows 7: only exact Win7 Rust target PE
inspection followed by native NT6.1 execution can establish that.

## Separate NT6.1 native acceptance gate

An operator/coordinator must run these artifacts on authorized, owner-marked,
disposable machines and retain source/package hash-matched receipts. This
builder does not connect to hosts, deploy packages, install services, or run
this matrix:

- Windows 7 SP1 x64 with PowerShell 2.
- Windows 7 SP1 x86 on a 32-bit OS; x86 under WOW64 on x64 is a separate result
  and does not prove the 32-bit OS target.
- Exact artifact SHA match and `--version`, user-owned configuration and SSH
  key setup, authenticated SSH exec with binary stdin/stdout/stderr and exit 7.
- Pinned SSH exec/SFTP/forward, local Apalis Board jobs and crash replay
  boundaries, reverse gateway operation, and owned temporary-file cleanup.
- Explicit evidence that no installed service, production host, gateway, or
  1C database was changed.

Until those independent runs exist, report native NT6.1 acceptance as **NOT
RUN** or **BLOCKED** with the missing machine/criterion. Old `dev@5a1f80b`
receipts and previous rewrite binaries such as `c64619e` do not prove this
candidate.
