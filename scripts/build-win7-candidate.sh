#!/usr/bin/env bash
set -Eeuo pipefail

readonly TOOLCHAIN="nightly-2026-08-22"
readonly XWIN_VERSION="17"
# The active VS 17 catalog no longer exposes 10.0.22621.0. HOME has the
# explicitly source-checked Windows 11 SDK 10.0.26100.0 with x86 and x64 CRT
# 14.44.17.14. Win7 compatibility is determined by the Rust Win7 target and
# PE/native NT6.1 acceptance, NOT by the nominal SDK release version.
readonly XWIN_SDK_VERSION="10.0.26100.0"
readonly XWIN_CRT_VERSION="14.44.17.14"
readonly XWIN_CROSS_COMPILER="clang-cl"
readonly BUILD_STD="std,panic_abort"
readonly TARGETS=(x86_64-win7-windows-msvc i686-win7-windows-msvc)
readonly PACKAGES=(hostlink-agent hostlink)
readonly RUSTFLAGS_VALUE="-C target-feature=+crt-static"

usage() {
  cat <<'USAGE'
Usage: scripts/build-win7-candidate.sh --source-sha FULL_SHA --output-dir target/PATH

Build and inspect the Agent and Client for both Win7 MSVC target triples.
This is local PE evidence, not a release bundle or native acceptance.
Pass each Agent executable and receipt.json to package-hostlink-agent.py
to stage one raw release asset; Client executables are not Agent assets.
Use the pre-provisioned xwin SDK 10.0.26100.0 + CRT 14.44.17.14 in XWIN_CACHE_DIR.
Requires both x86 and x86_64 xwin components; set XWIN_ARCH=x86,x86_64.
The output directory must be new and inside this checkout's ignored target/.
USAGE
}

fail() {
  printf 'build-win7-candidate: ERROR: %s\n' "$*" >&2
  exit 1
}

source_sha=""
output_arg=""
while (($#)); do
  case "$1" in
    --source-sha)
      (($# >= 2)) || fail "--source-sha requires a value"
      source_sha="$2"
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || fail "--output-dir requires a value"
      output_arg="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1 (use --help)"
      ;;
  esac
done

[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "--source-sha must be a full lowercase 40-character Git SHA"
[[ -n "$output_arg" ]] || fail "--output-dir is required"

for tool in git rustup rustc cargo llvm-readobj clang-cl jq sha256sum realpath rg head; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool is missing: $tool"
done

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail "run from inside a Git worktree"
repo_root="$(realpath "$repo_root")"
source_branch="$(git -C "$repo_root" symbolic-ref --quiet --short HEAD || true)"
[[ -n "$source_branch" ]] || source_branch="DETACHED_HEAD"

assert_source_clean_and_exact() {
  local actual status branch
  actual="$(git -C "$repo_root" rev-parse HEAD)"
  [[ "$actual" == "$source_sha" ]] || fail "source HEAD changed or does not match --source-sha (expected $source_sha, got $actual)"
  branch="$(git -C "$repo_root" symbolic-ref --quiet --short HEAD || true)"
  [[ -n "$branch" ]] || branch="DETACHED_HEAD"
  [[ "$branch" == "$source_branch" ]] || fail "source branch or detached-HEAD state changed during build"
  status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"
  [[ -z "$status" ]] || fail "source worktree is dirty; commit or remove source changes before building"
}

assert_source_clean_and_exact

target_root="$repo_root/target"
mkdir -p "$target_root"
target_root="$(realpath "$target_root")"
if [[ "$output_arg" = /* ]]; then
  output_path="$(realpath -m "$output_arg")"
else
  output_path="$(realpath -m "$repo_root/$output_arg")"
fi
[[ "$output_path" == "$target_root/"* ]] || fail "--output-dir must resolve below ignored target/: $target_root"
[[ ! -e "$output_path" ]] || fail "output path already exists; choose a new output directory: $output_path"

installed_toolchains="$(rustup toolchain list)" || fail "cannot list installed Rust toolchains"
rg -q "^${TOOLCHAIN}-" <<<"$installed_toolchains" || fail "pinned toolchain is missing: $TOOLCHAIN"
rust_src_present="$(rustup component list --toolchain "$TOOLCHAIN" --installed)"
rg -q '^rust-src$' <<<"$rust_src_present" || fail "rust-src is missing from $TOOLCHAIN; install that component explicitly"
rustc_version="$(rustc "+$TOOLCHAIN" --version --verbose)" || fail "cannot run pinned rustc $TOOLCHAIN"
[[ -n "${XWIN_CACHE_DIR:-}" ]] || fail "set XWIN_CACHE_DIR to an owned pre-provisioned xwin SDK cache"
[[ -f "$XWIN_CACHE_DIR/xwin/DONE" ]] || fail "XWIN_CACHE_DIR is missing verified xwin/DONE; provision the pinned 26100 SDK before compiling"
[[ "${XWIN_ARCH:-}" == "x86,x86_64" || "${XWIN_ARCH:-}" == "x86_64,x86" ]] ||
  fail "set XWIN_ARCH=x86,x86_64 for true i686 and x86_64 Win7 builds"
if ! rg -q 'Win11SDK_10\.0\.26100' "$XWIN_CACHE_DIR/xwin/DONE"; then
  fail "xwin cache is not sourced from the required Windows SDK 10.0.26100.0"
fi
if ! rg -q 'Microsoft\.VC\.14\.44\.17\.14\.CRT\.x86' "$XWIN_CACHE_DIR/xwin/DONE"; then
  fail "xwin cache lacks required CRT 14.44.17.14 x86 components"
fi
cargo_version="$(cargo "+$TOOLCHAIN" --version)" || fail "cannot run pinned Cargo $TOOLCHAIN"
xwin_version="$(cargo "+$TOOLCHAIN" xwin --version)" || fail "cargo-xwin is missing or unusable for $TOOLCHAIN"
[[ "$xwin_version" == "cargo-xwin-xwin 0.23.1" ]] || fail "expected cargo-xwin 0.23.1, got: $xwin_version"
target_list="$(rustc "+$TOOLCHAIN" --print target-list)" || fail "cannot inspect target list from $TOOLCHAIN"
for target in "${TARGETS[@]}"; do
  rg -q "^${target}$" <<<"$target_list" || fail "$TOOLCHAIN does not list required target $target"
done
clang_version="$(clang-cl --version | head -n 1)" || fail "cannot run clang-cl"
llvm_readobj_version="$(llvm-readobj --version | head -n 1)" || fail "cannot run llvm-readobj"

mkdir -p "$(dirname "$output_path")"
stage="$(mktemp -d "$target_root/.win7-candidate-stage.XXXXXXXX")"
stage="$(realpath "$stage")"
[[ "$stage" == "$target_root/"* ]] || fail "internal staging path escaped target/"
cleanup() {
  local rc=$?
  trap - EXIT
  if [[ "$stage" == "$target_root/"* && -d "$stage" ]]; then
    rm -rf -- "$stage"
  fi
  exit "$rc"
}
trap cleanup EXIT
mkdir -p "$stage/payload" "$stage/cargo-target"

for target in "${TARGETS[@]}"; do
  printf 'Building target %s from %s\n' "$target" "$source_sha"
  env -u CARGO_ENCODED_RUSTFLAGS \
    RUSTFLAGS="$RUSTFLAGS_VALUE" \
    CARGO_TARGET_DIR="$stage/cargo-target" \
    cargo "+$TOOLCHAIN" xwin build \
      --cross-compiler "$XWIN_CROSS_COMPILER" \
      --xwin-version "$XWIN_VERSION" \
      --xwin-sdk-version "$XWIN_SDK_VERSION" \
      --xwin-crt-version "$XWIN_CRT_VERSION" \
      --locked --release --target "$target" \
      -Z "build-std=$BUILD_STD" \
      -p "${PACKAGES[0]}" -p "${PACKAGES[1]}"

  arch_dir="$stage/payload/$target"
  mkdir -p "$arch_dir"
  for exe in hostlink-agent.exe hostlink.exe; do
    built="$stage/cargo-target/$target/release/$exe"
    [[ -f "$built" && -s "$built" ]] || fail "missing or empty required artifact after $target build: $built"
    cp -- "$built" "$arch_dir/$exe"
  done
done

json_targets='[]'
for target in "${TARGETS[@]}"; do
  case "$target" in
    x86_64-win7-windows-msvc) expected_machine="0x8664" ;;
    i686-win7-windows-msvc) expected_machine="0x14c" ;;
    *) fail "internal unsupported target: $target" ;;
  esac
  arch_dir="$stage/payload/$target"
  json_binaries='[]'
  for exe in hostlink-agent.exe hostlink.exe; do
    binary="$arch_dir/$exe"
    report="$arch_dir/$exe.llvm-readobj.txt"
    llvm-readobj --file-headers --coff-imports "$binary" >"$report" || fail "llvm-readobj failed for $target/$exe"
    machine="$(awk '/^[[:space:]]*Machine:/ { if (match($0, /\(0x[[:xdigit:]]+\)/)) { value=substr($0, RSTART+1, RLENGTH-2); print tolower(value) } exit }' "$report")"
    subsystem_major="$(awk '/^[[:space:]]*MajorSubsystemVersion:/ { print $NF; exit }' "$report")"
    subsystem_minor="$(awk '/^[[:space:]]*MinorSubsystemVersion:/ { print $NF; exit }' "$report")"
    [[ "$machine" == "$expected_machine" ]] || fail "$target/$exe machine mismatch: expected $expected_machine, got ${machine:-missing}"
    [[ "$subsystem_major" == 6 && "$subsystem_minor" == 0 ]] || fail "$target/$exe subsystem must be 6.0 for Win7 compatibility, got ${subsystem_major:-missing}.${subsystem_minor:-missing}"
    imports_text="$(awk '/^[[:space:]]*Name:/ { name=$NF; if (name ~ /\.[Dd][Ll][Ll]$/) print tolower(name) }' "$report" | sort -u)"
    if rg -qi '(^|/)(api-ms-win-crt[^/]*|ucrtbase\.dll|msvcrt\.dll|vcruntime[^/]*\.dll|msvcp[^/]*\.dll|concrt[^/]*\.dll)$' <<<"$imports_text"; then
      fail "$target/$exe imports a dynamic CRT DLL despite +crt-static: $(tr '\n' ' ' <<<"$imports_text")"
    fi
    # Win7 has the documented CoTaskMemFree export in ole32.dll, but no
    # combase.dll. Static CRT and PE subsystem checks alone cannot catch an
    # unconditional loader dependency on a Windows 8+ DLL.
    if rg -qi '^combase\.dll$' <<<"$imports_text"; then
      fail "$target/$exe imports combase.dll, which is absent on Windows 7; bind Win7-compatible OLE APIs to ole32.dll"
    fi
    import_json="$(jq -Rn '[inputs | select(length > 0)]' <<<"$imports_text")"
    binary_sha="$(sha256sum "$binary" | awk '{print $1}')"
    json_binaries="$(jq -c --arg exe "$exe" --arg sha "$binary_sha" --arg machine "$machine" \
      --argjson subsystemMajor "$subsystem_major" --argjson subsystemMinor "$subsystem_minor" \
      --argjson imports "$import_json" \
      '. + [{file:$exe,sha256:$sha,pe_machine:$machine,subsystem:{major:$subsystemMajor,minor:$subsystemMinor},imports:$imports,static_crt_import_check:"passed"}]' \
      <<<"$json_binaries")"
  done
  json_targets="$(jq -c --arg target "$target" --argjson binaries "$json_binaries" '. + [{target:$target,binaries:$binaries}]' <<<"$json_targets")"
done

assert_source_clean_and_exact
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uid="$(id -u)"
user="$(id -un)"
host="$(uname -srm)"
jq -n \
  --arg status "PE_BUILD_AND_INSPECTION_PASS" \
  --arg source_sha "$source_sha" \
  --arg branch "$source_branch" \
  --arg built_at_utc "$timestamp" \
  --arg build_user "$user" \
  --arg build_uid "$uid" \
  --arg build_host "$host" \
  --arg toolchain "$TOOLCHAIN" \
  --arg rustc "$rustc_version" \
  --arg cargo "$cargo_version" \
  --arg xwin "$xwin_version" \
  --arg clang_cl "$clang_version" \
  --arg llvm_readobj "$llvm_readobj_version" \
  --arg xwin_version "$XWIN_VERSION" \
  --arg xwin_sdk_version "$XWIN_SDK_VERSION" \
  --arg xwin_crt_version "$XWIN_CRT_VERSION" \
  --arg cross_compiler "$XWIN_CROSS_COMPILER" \
  --arg build_std "$BUILD_STD" \
  --arg rustflags "$RUSTFLAGS_VALUE" \
  --argjson targets "$json_targets" \
  '{schema_version:1,status:$status,source:{git_sha:$source_sha,branch:$branch,worktree_clean:true},built_at_utc:$built_at_utc,build_environment:{user:$build_user,uid:$build_uid,host:$build_host,rust_toolchain:$toolchain,rustc:$rustc,cargo:$cargo,cargo_xwin:$xwin,clang_cl:$clang_cl,llvm_readobj:$llvm_readobj,xwin_component_version:$xwin_version,xwin_sdk_version:$xwin_sdk_version,xwin_crt_version:$xwin_crt_version,cross_compiler:$cross_compiler,build_std:$build_std,rustflags:$rustflags},targets:$targets,native_acceptance:{status:"NOT_RUN",windows_version:null,architecture:null,operator_receipt:null}}' \
  >"$stage/payload/receipt.json"

assert_source_clean_and_exact
[[ ! -e "$output_path" ]] || fail "output path appeared during build; refusing to overwrite: $output_path"
mv -- "$stage/payload" "$output_path"
printf 'PE build and inspection complete: %s\n' "$output_path"
printf 'Receipt: %s/receipt.json\n' "$output_path"
