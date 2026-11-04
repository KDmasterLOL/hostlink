# Local source-bound builds. Windows binaries still require native acceptance.
set shell := ["bash", "-euo", "pipefail", "-c"]

# Show available commands.
default:
    @just --list

fmt:
    cargo +1.99.1 fmt --all -- --check

check:
    cargo +1.99.1 check --workspace --locked

test:
    cargo +1.99.1 test --workspace --locked

clippy:
    cargo +1.99.1 clippy --workspace --all-targets --locked -- -D warnings

# Compile Controller, Agent and Hub for the HOME host.
build-workspace:
    cargo +1.99.1 build --locked --workspace

# Release: build all four Agent targets, no upload.
build: build-all

build-linux: (_build "x86_64-unknown-linux-gnu")
build-windows: (_build "x86_64-pc-windows-msvc")
build-win7-x64: (_build "x86_64-win7-windows-msvc")
build-win7-x86: (_build "i686-win7-windows-msvc")
build-all: build-linux build-windows build-win7-x64 build-win7-x86

# Build each target into a SHA-specific directory; receipts bind bytes to source.
[private]
_build target:
    #!/usr/bin/env bash
    set -euo pipefail
    test -z "$(git status --porcelain=v1 --untracked-files=all)" || { echo 'Commit all changes before building' >&2; exit 1; }
    sha=$(git rev-parse HEAD)
    target='{{target}}'
    export CARGO_TARGET_DIR="$PWD/target/local-build/$sha/$target"
    mkdir -p "$CARGO_TARGET_DIR"
    rm -f "$CARGO_TARGET_DIR/build.sha256"
    unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS
    test "$(rustc +1.99.1 -Vv | sed -n 's/^commit-hash: //p')" = 58cf8f9c35b355199727627d07ae34a4e2846d67
    if [[ "$target" == *windows* ]]; then
      test "$(cargo +1.99.1 xwin --version)" = 'cargo-xwin-xwin 0.23.1'
      export XWIN_CACHE_DIR="${XWIN_CACHE_DIR:-$HOME/.cache/hostlink/win7-xwin-current-14368fb}"
      done_file="$XWIN_CACHE_DIR/xwin/DONE"
      test -f "$done_file"
      grep -q 'Win11SDK_10\.0\.26100' "$done_file"
      for arch in x86 x64; do grep -q "Microsoft\.VC\.14\.44\.17\.14\.CRT\.$arch" "$done_file"; done
      test -s "$XWIN_CACHE_DIR/xwin/sdk/include/ucrt/assert.h"
      for arch in x86 x86_64; do
        test -s "$XWIN_CACHE_DIR/xwin/crt/lib/$arch/libcmt.lib"
        test -s "$XWIN_CACHE_DIR/xwin/sdk/lib/um/$arch/kernel32.lib"
        test -s "$XWIN_CACHE_DIR/xwin/sdk/lib/ucrt/$arch/libucrt.lib"
      done
    fi
    case "$target" in
      x86_64-unknown-linux-gnu) cargo +1.99.1 build --locked --release -p hostlink-agent --target "$target"; suffix= ;;
      x86_64-pc-windows-msvc)
        cargo +1.99.1 xwin build --cross-compiler clang-cl --xwin-version 17 --xwin-sdk-version 10.0.26100.0 --xwin-crt-version 14.44.17.14 --locked --release -p hostlink-agent --target "$target"; suffix=.exe ;;
      *)
        test "$(rustc +nightly-2026-08-22 -Vv | sed -n 's/^commit-hash: //p')" = c656540d6467dee1381f0cbd882412d6bd1cd5ae
        rustup component list --toolchain nightly-2026-08-22 --installed | grep -qx rust-src
        RUSTFLAGS='-C target-feature=+crt-static' cargo +nightly-2026-08-22 xwin build --cross-compiler clang-cl --xwin-version 17 --xwin-sdk-version 10.0.26100.0 --xwin-crt-version 14.44.17.14 --locked --release --target "$target" -Z build-std=std,panic_abort -p hostlink-agent
        suffix=.exe ;;
    esac
    test "$(git rev-parse HEAD)" = "$sha"
    test -z "$(git status --porcelain=v1 --untracked-files=all)"
    file="$CARGO_TARGET_DIR/$target/release/hostlink-agent$suffix"
    test -f "$file" && test ! -L "$file" && test -s "$file" && test "$(wc -c < "$file")" -le 268435456
    sha256sum "$file" > "$CARGO_TARGET_DIR/build.sha256"
    {
      cargo +1.99.1 --version
      rustc +1.99.1 -Vv
      if [[ "$target" == *windows* ]]; then cargo +1.99.1 xwin --version; fi
      if [[ "$target" == *win7* ]]; then cargo +nightly-2026-08-22 --version; rustc +nightly-2026-08-22 -Vv; fi
    } > "$CARGO_TARGET_DIR/toolchain"

# Copy and inspect the four previously built assets into a private candidate.
stage:
    #!/usr/bin/env bash
    set -euo pipefail
    umask 077
    test -z "$(git status --porcelain=v1 --untracked-files=all)"
    sha=$(git rev-parse HEAD)
    dir="$PWD/target/release-candidate/$sha"
    test ! -e "$dir" || { echo 'Candidate already exists' >&2; exit 1; }
    mkdir -p "$dir"
    for target in x86_64-unknown-linux-gnu x86_64-pc-windows-msvc x86_64-win7-windows-msvc i686-win7-windows-msvc; do
      root="$PWD/target/local-build/$sha/$target"
      suffix=.exe; test "$target" != x86_64-unknown-linux-gnu || suffix=
      src="$root/$target/release/hostlink-agent$suffix"
      test -f "$src" && test ! -L "$src" && test -s "$src" && test "$(wc -c < "$src")" -le 268435456
      sha256sum "$src" | cmp - "$root/build.sha256"
      cp "$src" "$dir/hostlink-agent-$target$suffix"
      cmp "$src" "$dir/hostlink-agent-$target$suffix"
      printf '[%s]\n' "$target" >> "$dir/TOOLCHAINS"
      cat "$root/toolchain" >> "$dir/TOOLCHAINS"
    done
    printf '%s\n' "$sha" > "$dir/SOURCE_SHA"
    cargo +1.99.1 metadata --locked --no-deps --format-version 1 | jq -er '.packages[] | select(.name == "hostlink-agent") | .version' > "$dir/VERSION"
    (cd "$dir" && sha256sum hostlink-agent-* > SHA256SUMS && wc -c hostlink-agent-* > SIZES && sha256sum SOURCE_SHA VERSION TOOLCHAINS SIZES SHA256SUMS > MANIFEST)
    test "$(git rev-parse HEAD)" = "$sha" && test -z "$(git status --porcelain=v1 --untracked-files=all)"
    just verify-candidate

# Verify inventory, receipt, identity and PE properties; no native Windows execution.
verify-candidate:
    #!/usr/bin/env bash
    set -euo pipefail
    test -z "$(git status --porcelain=v1 --untracked-files=all)"
    sha=$(git rev-parse HEAD)
    dir="$PWD/target/release-candidate/$sha"
    test "$(cat "$dir/SOURCE_SHA")" = "$sha"
    cd "$dir"
    shopt -s nullglob dotglob
    printf '%s\n' MANIFEST SHA256SUMS SIZES SOURCE_SHA TOOLCHAINS VERSION hostlink-agent-i686-win7-windows-msvc.exe hostlink-agent-x86_64-pc-windows-msvc.exe hostlink-agent-x86_64-unknown-linux-gnu hostlink-agent-x86_64-win7-windows-msvc.exe | LC_ALL=C sort | cmp - <(printf '%s\n' * | LC_ALL=C sort)
    for f in *; do test -f "$f" && test ! -L "$f"; done
    for f in hostlink-agent-*; do test -f "$f" && test ! -L "$f" && test -s "$f" && test "$(wc -c < "$f")" -le 268435456; done
    sha256sum --strict -c MANIFEST
    sha256sum SOURCE_SHA VERSION TOOLCHAINS SIZES SHA256SUMS | cmp - MANIFEST
    wc -c hostlink-agent-* | cmp - SIZES
    sha256sum --strict -c SHA256SUMS
    sha256sum hostlink-agent-* | cmp - SHA256SUMS
    version=$(cargo +1.99.1 metadata --manifest-path "$OLDPWD/Cargo.toml" --locked --no-deps --format-version 1 | jq -er '.packages[] | select(.name == "hostlink-agent") | .version')
    [[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
    test "$(cat VERSION)" = "$version"
    ./hostlink-agent-x86_64-unknown-linux-gnu binary-info | jq -e --arg version "$version" '. == {version: $version, target: "x86_64-unknown-linux-gnu"}'
    for f in *.exe; do
      pe=$(llvm-readobj --file-headers --coff-imports "$f")
      machine=0x8664; [[ "$f" != *i686* ]] || machine=0x14C
      grep -Eiq "Machine: .*\($machine\)" <<< "$pe"
      grep -Eq 'Subsystem: .*\(0x3\)' <<< "$pe"
      if [[ "$f" == *win7* ]]; then
        grep -Eq 'MajorSubsystemVersion: 6$' <<< "$pe"
        grep -Eq 'MinorSubsystemVersion: 0$' <<< "$pe"
        imports=$(awk '/^[[:space:]]*Name:/ {if ($NF ~ /\.[Dd][Ll][Ll]$/) print tolower($NF)}' <<< "$pe")
        test -n "$imports"
        if grep -Eqi '^(api-ms-win-crt.*|ucrtbase\.dll|msvcrt\.dll|msvcr[0-9]+\.dll|vcruntime.*\.dll|msvcp.*\.dll|concrt.*\.dll|combase\.dll)$' <<< "$imports"; then
          echo 'Forbidden Win7 DLL import' >&2
          exit 1
        fi
      fi
    done

# Explicit publication only: tag must already exist; never overwrite a release.
publish: verify-candidate
    #!/usr/bin/env bash
    set -euo pipefail
    sha=$(git rev-parse HEAD)
    version=$(cargo +1.99.1 metadata --locked --no-deps --format-version 1 | jq -er '.packages[] | select(.name == "hostlink-agent") | .version')
    tag="v$version"
    test "$(git rev-parse "refs/tags/$tag^{commit}")" = "$sha"
    # Resolve the exact remote tag, including annotated tag objects, without fetching refs.
    object=$(gh api "repos/KDmasterLOL/hostlink/git/ref/tags/$tag" | jq -ce '.object | {type, sha}')
    for _ in 1 2 3 4 5; do
      type=$(jq -er '.type' <<< "$object")
      remote_sha=$(jq -er '.sha' <<< "$object")
      [[ "$type" != tag ]] || { object=$(gh api "repos/KDmasterLOL/hostlink/git/tags/$remote_sha" | jq -ce '.object | {type, sha}'); continue; }
      break
    done
    test "$type" = commit && test "$remote_sha" = "$sha"
    gh api repos/KDmasterLOL/hostlink/immutable-releases | jq -e '.enabled == true' >/dev/null
    # API errors other than 404 also refuse publication.
    releases=$(gh api repos/KDmasterLOL/hostlink/releases --paginate --slurp)
    jq -e --arg tag "$tag" 'all(.[][]; .tag_name != $tag)' <<< "$releases" >/dev/null
    dir="target/release-candidate/$sha"
    gh release create "$tag" --repo KDmasterLOL/hostlink --verify-tag --notes-from-tag "$dir/hostlink-agent-x86_64-unknown-linux-gnu" "$dir/hostlink-agent-x86_64-pc-windows-msvc.exe" "$dir/hostlink-agent-x86_64-win7-windows-msvc.exe" "$dir/hostlink-agent-i686-win7-windows-msvc.exe"
    release=$(gh api "repos/KDmasterLOL/hostlink/releases/tags/$tag")
    jq -e '.immutable == true and (.assets | length == 4)' <<< "$release" >/dev/null
    while read -r digest name; do
      jq -e --arg name "$name" --arg digest "sha256:$digest" '[.assets[] | select(.name == $name and .digest == $digest)] | length == 1' <<< "$release" >/dev/null
    done < "$dir/SHA256SUMS"
