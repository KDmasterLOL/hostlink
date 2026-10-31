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

## Run the source-bound bootstrap verifier on disposable Windows

After building one source SHA, package each exact Agent target separately with
the matching target binary and the build `receipt.json`. Keep both build
directories and package directories intact; each package directory contains
`artifact-receipt.json`, the target Agent sidecar and its `.sha256`, and the ZIP
with its `.zip.sha256` file.

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

Copy the shared build output directory, both package output directories, and
the harness script to a Windows test machine through the approved operator
channel. Create a new, empty disposable directory owned by the
interactive test user with a protected ACL granting access only to that user.
Run Windows PowerShell 2 unelevated and pass the exact paths and source SHA:

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\scripts\verify-win7-bootstrap-native.ps1 `
  -SourceSha 0123456789abcdef0123456789abcdef01234567 `
  -Version 1.2.3 `
  -BuildRoot C:\HostLinkEvidence\build `
  -X64PackageRoot C:\HostLinkEvidence\package-x64 `
  -X86PackageRoot C:\HostLinkEvidence\package-x86 `
  -DisposableRoot C:\HostLinkEvidence\empty-private-root
```

The harness rejects elevated/service identities, nonempty or unsafe disposable
roots, inherited or foreign ACL grants, reparse paths, foreign-owned inputs,
malformed or mismatched build/package receipts and SHA-256 sidecars, wrong
source/target/version, and pre-existing output. It then executes each actual
target `hostlink-agent.exe bootstrap-verify --archive ... --sha256 ... --target
... --version ... --output ...`, checks the published `bootstrap-receipt.json`
and extracted file identities, and runs negative checks for a wrong archive
digest, wrong target, and output overwrite. The Agent uses the patched ZIP reader to reject conflicting headers and
duplicate, missing, unexpected or unsafe files before publication. For each target the harness also creates a disposable ZIP
with a duplicated central-directory entry, recomputes its digest, and verifies
that the actual target binary rejects it without publishing output. The harness
accepts a candidate only when the real binary successfully validates the
packaged ZIP and its embedded manifest.

The disposable root must be empty and on a local filesystem. The harness retains
its unique private run directory and verified output receipts under that root;
use a new empty disposable root for each run. Preserve the builder receipt,
both package receipts, both `.zip.sha256` and executable `.sha256` files, exact
source SHA, Windows version/architecture, PowerShell version, exit status and
the verified bootstrap receipts as follow-up evidence. Do not copy token,
credential, enrollment, or public-key material into the evidence bundle. A
Windows 11 x86 run is **WoW64 evidence only**; it does not prove a 32-bit
Windows 7 OS or native NT6.1 acceptance. This bootstrap verification procedure
does not install or start the Agent and does not cover the broader NT6.1
acceptance matrix below.

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
- SFTP Seal/run, durable job start then disconnect/reconnect/cancel with full
  process-tree cleanup, reverse gateway operation, and owned temporary-file
  cleanup.
- Explicit evidence that no installed service, production host, gateway, or
  1C database was changed.

Until those independent runs exist, report native NT6.1 acceptance as **NOT
RUN** or **BLOCKED** with the missing machine/criterion. Old `dev@5a1f80b`
receipts and previous rewrite binaries such as `c64619e` do not prove this
candidate.
