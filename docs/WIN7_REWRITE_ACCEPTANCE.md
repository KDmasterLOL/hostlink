# Windows 7 build and compatibility

Windows 7 uses the Tier 3 Rust targets `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc`. They require a nightly Rust toolchain with `rust-src` and `-Z build-std`; ordinary Windows MSVC builds are not substitutes. See [Rust platform support](https://doc.rust-lang.org/nightly/rustc/platform-support/win7-windows-msvc.html).

## Cross-compile

The repository provides `scripts/build-win7-candidate.sh`, which pins the toolchain, Windows SDK and MSVC CRT and performs PE inspection for both targets.

From a clean, committed worktree:

```sh
export XWIN_CACHE_DIR="$HOME/.cache/hostlink/msvc-sdk-v17/mount"
export XWIN_ARCH="x86,x86_64"
SOURCE_SHA="$(git rev-parse HEAD)"
scripts/build-win7-candidate.sh \
  --source-sha "$SOURCE_SHA" \
  --output-dir "target/win7-candidate-$SOURCE_SHA"
```

The builder requires `nightly-2026-08-22`, `cargo-xwin` 0.23.1, SDK 10.0.26100.0, CRT 14.44.17.14 and `clang-cl`. It checks the requested source SHA, clean working tree, PE machine types, subsystem and imports. The resulting `receipt.json` records binary hashes and build identity. A successful cross-build is not a native Windows 7 runtime test.

## Package the executables

```sh
SOURCE_SHA="$(git rev-parse HEAD)"
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("crates/agent/Cargo.toml", "rb"))["package"]["version"])')"
for TARGET in x86_64-win7-windows-msvc i686-win7-windows-msvc; do
  python3 scripts/package-hostlink-agent.py \
    --source-sha "$SOURCE_SHA" \
    --target "$TARGET" \
    --version "$VERSION" \
    --binary "target/win7-candidate-$SOURCE_SHA/$TARGET/hostlink-agent.exe" \
    --build-receipt "target/win7-candidate-$SOURCE_SHA/receipt.json" \
    --output-dir "target/win7-package-$SOURCE_SHA-$TARGET"
done
```

Packaging emits one raw Agent executable and local provenance. See [artifact packaging](ARTIFACTS_AND_INVITES.md).

## Test PowerShell 2 bootstrap syntax

The current Windows bootstrap supports Windows PowerShell 2. Generate synthetic, credential-free fixtures using a clean source worktree and a new private directory:

```sh
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hostlink-ps2-parse.XXXXXXXX")"
export HOSTLINK_PARSE_FIXTURE_DIR="$FIXTURE_DIR"
cargo test --offline --locked -p hostlink --lib \
  bootstrap::tests::export_raw_windows_parse_fixtures -- --ignored --exact
```

On a Windows test machine, verify transferred fixture hashes and run `scripts/verify-raw-windows-bootstrap-parse.ps1` using PowerShell 2. The parser only checks syntax; it does not execute the bootstrap, download assets or register an Agent. The retired `scripts/verify-win7-bootstrap-native.ps1` is not a replacement for these tests.

## Native acceptance

Validate separately on Windows 7 SP1 x64 and a genuine 32-bit Windows 7 SP1 system (WOW64 on x64 is not equivalent). Check exact binary identity, SHA-256, enrollment, permissions, SSH execution/SFTP, Apalis jobs, user Task Scheduler service, and stopped-only updates.

Record OS and PowerShell versions, artifact digests and exit statuses. A clean build, a PowerShell parser pass or a Windows 11 test does **not** establish Windows 7 native compatibility.
