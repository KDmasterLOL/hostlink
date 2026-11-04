# Windows 7 build and compatibility

Windows 7 uses the Tier 3 Rust targets `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc`. They require a nightly Rust toolchain with `rust-src` and `-Z build-std`; ordinary Windows MSVC builds are not substitutes. See [Rust platform support](https://doc.rust-lang.org/nightly/rustc/platform-support/win7-windows-msvc.html).

## Cross-compile and inspect

Use a clean, committed worktree and record `git rev-parse HEAD` before and after building. Both status checks (`git status --porcelain=v1`) must be empty. Provision `nightly-2026-08-22` with `rust-src`, cargo-xwin 0.23.1, clang-cl, and an xwin cache containing SDK 10.0.26100.0 and CRT 14.44.17.14 for both x86 and x86_64. Verify the cache provenance independently.

```sh
export XWIN_CACHE_DIR="$HOME/.cache/hostlink/msvc-sdk-v17/mount"
export XWIN_ARCH=x86,x86_64
for target in x86_64-win7-windows-msvc i686-win7-windows-msvc; do
  env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS='-C target-feature=+crt-static' \
    cargo +nightly-2026-08-22 xwin build --cross-compiler clang-cl \
    --xwin-version 17 --xwin-sdk-version 10.0.26100.0 --xwin-crt-version 14.44.17.14 \
    --locked --release --target "$target" -Z build-std=std,panic_abort \
    -p hostlink-agent -p hostlink || exit 1
  for exe in hostlink-agent.exe hostlink.exe; do
    binary="target/$target/release/$exe"
    test -s "$binary" || exit 1
    sha256sum "$binary"
    llvm-readobj --file-headers --coff-imports "$binary" > "$binary.pe.txt" || exit 1
  done
done
```

Review each PE report: machine must be `0x8664` for x64 or `0x14c` for x86; subsystem version must be 6.0. Imports must exclude dynamic CRT DLLs (`api-ms-win-crt*`, `ucrtbase.dll`, `msvcrt.dll`, `vcruntime*`, `msvcp*`, `concrt*`) and `combase.dll`. Record reports and hashes with the source SHA and tool versions. These checks are manual; no automated receipt or PE rejection gate currently exists. Cross-compilation does not establish native compatibility. Package the raw Agent executables as described in [artifact packaging](ARTIFACTS_AND_INVITES.md).

## PowerShell 2 syntax

The new inline bootstrap targets PowerShell 2, but its generated command and decompressed script require native parser and execution checks on Windows 7. The old saved-helper fixture exporter was deleted. Native GitHub TLS, download, SHA-256, enrollment and service startup remain separate acceptance gates; PowerShell syntax alone is not acceptance.

## Native acceptance

Validate separately on Windows 7 SP1 x64 and a genuine 32-bit Windows 7 SP1 system (WOW64 on x64 is not equivalent). Check exact binary identity, SHA-256, enrollment, permissions, SSH execution/SFTP, Apalis jobs, user Task Scheduler service, and stopped-only updates.

Record OS and PowerShell versions, artifact digests and exit statuses. A clean build, a PowerShell parser pass or a Windows 11 test does **not** establish Windows 7 native compatibility.
