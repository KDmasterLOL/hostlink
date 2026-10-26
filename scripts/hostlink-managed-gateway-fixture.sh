#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" == "0" ]]; then
  echo "Refusing root execution; this fixture must stay in the current user's scope." >&2
  exit 2
fi

for tool in cargo sshd caddy openssl ssh-keygen ssh pgrep ss; do
  command -v "$tool" >/dev/null || { echo "Required fixture tool is missing: $tool" >&2; exit 2; }
done

echo "Building exact worktree binaries for source $(git rev-parse HEAD)"
cargo build --offline --locked -p hostlink-hub -p hostlink-agent -p hostlink

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export HOSTLINK_HUB_BIN="$TARGET_DIR/debug/hostlink-hub"
export HOSTLINK_AGENT_BIN="$TARGET_DIR/debug/hostlink-agent"
export HOSTLINK_CLIENT_BIN="$TARGET_DIR/debug/hostlink"
HOSTLINK_SSHD_BIN="$(command -v sshd)"
HOSTLINK_CADDY_BIN="$(command -v caddy)"
HOSTLINK_SOURCE_SHA="$(git rev-parse HEAD)"
export HOSTLINK_SSHD_BIN HOSTLINK_CADDY_BIN HOSTLINK_SOURCE_SHA

for binary in "$HOSTLINK_HUB_BIN" "$HOSTLINK_AGENT_BIN" "$HOSTLINK_CLIENT_BIN"; do
  [[ -x "$binary" ]] || { echo "Built fixture binary is missing: $binary" >&2; exit 2; }
done

cargo test --offline --locked -p hostlink --test managed_https_gateway_e2e -- --ignored --nocapture
