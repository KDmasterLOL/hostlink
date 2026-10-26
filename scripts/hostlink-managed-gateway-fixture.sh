#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! git diff --quiet || ! git diff --cached --quiet || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "Fixture requires a committed, clean source revision before packaging." >&2
  exit 2
fi

if [[ "$(id -u)" == "0" ]]; then
  echo "Refusing root execution; this fixture must stay in the current user's scope." >&2
  exit 2
fi

for tool in cargo sshd caddy openssl ssh-keygen ssh pgrep ss script; do
  command -v "$tool" >/dev/null || { echo "Required fixture tool is missing: $tool" >&2; exit 2; }
done

echo "Building exact worktree binaries for source $(git rev-parse HEAD)"
cargo build --offline --locked -p hostlink-hub -p hostlink-agent -p hostlink
cargo build --offline --locked --release -p hostlink-agent

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export HOSTLINK_HUB_BIN="$TARGET_DIR/debug/hostlink-hub"
export HOSTLINK_AGENT_BIN="$TARGET_DIR/debug/hostlink-agent"
export HOSTLINK_CLIENT_BIN="$TARGET_DIR/debug/hostlink"
HOSTLINK_SSHD_BIN="$(command -v sshd)"
HOSTLINK_CADDY_BIN="$(command -v caddy)"
HOSTLINK_SOURCE_SHA="$(git rev-parse HEAD)"
HOSTLINK_ARTIFACT_TMP="$(mktemp -d "${TMPDIR:-/tmp}/hostlink-artifacts.XXXXXXXX")"
HOSTLINK_ARTIFACT_ROOT="$HOSTLINK_ARTIFACT_TMP/candidate"
trap 'rm -rf -- "$HOSTLINK_ARTIFACT_TMP"' EXIT
scripts/package-hostlink-agent.py \
  --source-sha "$HOSTLINK_SOURCE_SHA" \
  --target x86_64-unknown-linux-gnu \
  --version 0.1.0 \
  --binary "${CARGO_TARGET_DIR:-$ROOT/target}/release/hostlink-agent" \
  --output-dir "$HOSTLINK_ARTIFACT_ROOT"
export HOSTLINK_SSHD_BIN HOSTLINK_CADDY_BIN HOSTLINK_SOURCE_SHA HOSTLINK_ARTIFACT_ROOT

for binary in "$HOSTLINK_HUB_BIN" "$HOSTLINK_AGENT_BIN" "$HOSTLINK_CLIENT_BIN"; do
  [[ -x "$binary" ]] || { echo "Built fixture binary is missing: $binary" >&2; exit 2; }
done

# Both tests create independent sshd/Caddy servers, but each snapshots the
# preexisting sshd PID set; serialize them to avoid counting the other
# fixture as a preexisting service and to keep ownership receipts meaningful.
cargo test --offline --locked -p hostlink --test managed_https_gateway_e2e -- --ignored --nocapture --test-threads=1
