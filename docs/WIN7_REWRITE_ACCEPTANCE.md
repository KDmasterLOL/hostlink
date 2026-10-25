# Win7 rewrite cross-build and acceptance evidence

This procedure builds only the current `hostlink-agent` and `hostlink` workspace
packages for both Windows 7 MSVC target triples. It does not run a binary on
Windows and cannot satisfy the NT6.1 acceptance gate.

## Why this uses build-std

Rust lists `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc` as Tier 3,
and does not ship precompiled standard-library artifacts for them. Building
therefore requires a nightly compiler with `rust-src` and `build-std`. The
workflow pins `nightly-2026-08-22`, `cargo-xwin` 0.23.1, xwin SDK
10.0.22621.0, MSVC CRT package 14.44.17.14, and `clang-cl`; it does not fall
back to `x86_64-pc-windows-msvc` or `i686-pc-windows-msvc`. Rust's [target
support page](https://doc.rust-lang.org/nightly/rustc/platform-support/win7-windows-msvc.html)
describes the target and cross-compilation prerequisites.

## Build a source-exact candidate

Run from the isolated task worktree, after committing the exact source to be
built. Select a new path below the ignored `target/` directory each time:

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
scripts/build-win7-candidate.sh \
  --source-sha "$SOURCE_SHA" \
  --output-dir "target/win7-candidate-$SOURCE_SHA"
```

The script requires branch `task/1c-1008-win7-source-v3`, a clean Git worktree,
the full lowercase source SHA, Rust `nightly-2026-08-22` with `rust-src`,
`cargo-xwin` 0.23.1, and `llvm-readobj`. It builds each target using the
equivalent of:

```sh
RUSTFLAGS='-C target-feature=+crt-static' \
cargo +nightly-2026-08-22 xwin build \
  --cross-compiler clang-cl --xwin-version 17 \
  --xwin-sdk-version 10.0.22621.0 \
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
