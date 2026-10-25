#!/bin/sh
set -eu

usage() {
    cat >&2 <<'EOF'
Usage: install-hostlink-agent.sh --hub-url HTTPS_ORIGIN --name CANONICAL --ssh-user USER \
  --agent-url HTTPS_URL --agent-sha256 LOWERCASE_SHA256 --archive-url HTTPS_URL \
  --archive-sha256 LOWERCASE_SHA256 --agent-version SEMVER --target x86_64-unknown-linux-gnu
EOF
    exit 2
}

hub_url=
name=
ssh_user=
agent_url=
agent_sha256=
agent_version=
archive_url=
archive_sha256=
target=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --hub-url) [ "$#" -ge 2 ] || usage; hub_url=$2; shift 2 ;;
        --name) [ "$#" -ge 2 ] || usage; name=$2; shift 2 ;;
        --ssh-user) [ "$#" -ge 2 ] || usage; ssh_user=$2; shift 2 ;;
        --agent-url) [ "$#" -ge 2 ] || usage; agent_url=$2; shift 2 ;;
        --agent-sha256) [ "$#" -ge 2 ] || usage; agent_sha256=$2; shift 2 ;;
        --agent-version) [ "$#" -ge 2 ] || usage; agent_version=$2; shift 2 ;;
        --archive-url) [ "$#" -ge 2 ] || usage; archive_url=$2; shift 2 ;;
        --archive-sha256) [ "$#" -ge 2 ] || usage; archive_sha256=$2; shift 2 ;;
        --target) [ "$#" -ge 2 ] || usage; target=$2; shift 2 ;;
        *) usage ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then
    echo 'Enrollment must run as a normal unprivileged user.' >&2
    exit 1
fi
case "$hub_url" in https://*) ;; *) echo 'Hub URL must use HTTPS.' >&2; exit 1 ;; esac
hub_authority=${hub_url#https://}
case "$hub_authority" in *@*|*/*|*\?*|*\#*|'') echo 'Hub URL must be an HTTPS origin without credentials, path, query or fragment.' >&2; exit 1 ;; esac
case "$agent_url" in https://*) ;; *) echo 'Agent URL must use HTTPS.' >&2; exit 1 ;; esac
case "$archive_url" in https://*) ;; *) echo 'Archive URL must use HTTPS.' >&2; exit 1 ;; esac
agent_authority=${agent_url#https://}
archive_authority=${archive_url#https://}
case "$agent_authority" in *@*|*\#*) echo 'Agent URL must not contain credentials or fragments.' >&2; exit 1 ;; esac
case "$archive_authority" in *@*|*\#*) echo 'Archive URL must not contain credentials or fragments.' >&2; exit 1 ;; esac
agent_origin=https://${agent_authority%%/*}
archive_origin=https://${archive_authority%%/*}
agent_origin=${agent_origin%%\?*}
archive_origin=${archive_origin%%\?*}
[ "$agent_origin" = "$archive_origin" ] || { echo 'ZIP and sidecar must use the same HTTPS origin.' >&2; exit 1; }
archive_path=${archive_authority%%\?*}
archive_name=${archive_path##*/}
[ "$archive_name" = "hostlink-agent-$target.zip" ] || { echo 'Archive URL must select the exact target-named Agent ZIP.' >&2; exit 1; }
case "$name" in ''|*[!a-z0-9._-]*|[!a-z0-9]*) echo 'Name must be canonical lowercase ASCII.' >&2; exit 1 ;; esac
case "$ssh_user" in ''|*[!A-Za-z0-9._-]*) echo 'SSH user is invalid.' >&2; exit 1 ;; esac
[ "${#name}" -le 128 ] || { echo 'Name is too long.' >&2; exit 1; }
case "$agent_sha256" in *[!0-9a-f]*|'') echo 'Agent SHA-256 must be lowercase hexadecimal.' >&2; exit 1 ;; esac
[ "${#agent_sha256}" -eq 64 ] || { echo 'Agent SHA-256 must contain 64 characters.' >&2; exit 1; }
case "$archive_sha256" in *[!0-9a-f]*|'') echo 'Archive SHA-256 must be lowercase hexadecimal.' >&2; exit 1 ;; esac
[ "${#archive_sha256}" -eq 64 ] || { echo 'Archive SHA-256 must contain 64 characters.' >&2; exit 1; }
[ "$target" = 'x86_64-unknown-linux-gnu' ] || { echo 'Unsupported Linux package target.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'This bootstrap supports x86_64 Linux only.' >&2; exit 1; }
printf '%s' "$agent_version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' || { echo 'Agent version must be exact semantic version.' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo 'curl is required.' >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo 'sha256sum is required.' >&2; exit 1; }

base=${XDG_DATA_HOME:-"$HOME/.local/share"}
[ -d "$base" ] || mkdir -p "$base"
[ ! -L "$base" ] || { echo 'Install parent must not be a symlink.' >&2; exit 1; }
base=$(cd "$base" && pwd -P)
[ "$(stat -c '%u' "$base")" = "$(id -u)" ] || { echo 'Install parent must be owned by the current user.' >&2; exit 1; }
base_mode=$((0$(stat -c '%a' "$base")))
[ $((base_mode & 18)) -eq 0 ] || { echo 'Install parent must not be writable by group or other users.' >&2; exit 1; }
stage=$(mktemp -d "${TMPDIR:-/tmp}/hostlink-agent-bootstrap.XXXXXXXX")
chmod 700 "$stage"
token_file="$stage/invite-token"
cleanup() {
    stty echo 2>/dev/null || true
    [ ! -f "$token_file" ] || rm -f "$token_file"
    [ ! -d "$stage" ] || rm -rf "$stage"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

agent="$stage/hostlink-agent"
archive="$stage/hostlink-agent.zip"
verified="$stage/verified-package"
# No redirect following; an HTTP 3xx is an error. Both the transfer and file size are bounded.
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-filesize 268435456 --connect-timeout 10 --max-time 120 -o "$agent" "$agent_url"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-filesize 536870912 --connect-timeout 10 --max-time 180 -o "$archive" "$archive_url"
actual_sha=$(sha256sum "$agent" | awk '{print $1}')
[ "$actual_sha" = "$agent_sha256" ] || { echo 'Agent executable SHA-256 mismatch.' >&2; exit 1; }
chmod 700 "$agent"
version_output=$("$agent" --version)
case "$version_output" in *"$agent_version"*) ;; *) echo 'Downloaded Agent version does not match the pinned version.' >&2; exit 1 ;; esac
"$agent" bootstrap-verify --archive "$archive" --sha256 "$archive_sha256" --target "$target" --version "$agent_version" --output "$verified"
[ -d "$verified" ] || { echo 'Exact Agent ZIP package verification failed; invite token was not requested.' >&2; exit 1; }
[ "$(sha256sum "$verified/hostlink-agent" | awk '{print $1}')" = "$agent_sha256" ] || { echo 'Verified ZIP executable differs from the independently pinned sidecar.' >&2; exit 1; }

printf 'One-use HostLink invite token: ' >&2
stty -echo
IFS= read -r token
stty echo
printf '\n' >&2
trap cleanup EXIT
printf '%s' "$token" | LC_ALL=C grep -Eq '^[0-9a-f]{64}$' || { unset token; echo 'Invite token format is invalid.' >&2; exit 1; }
umask 077
printf '%s' "$token" > "$token_file"
unset token

parent=$(mktemp -d "$base/hostlink-agent.XXXXXXXX")
chmod 700 "$parent"
root="$parent/Agent"
"$agent" enroll --hub-url "$hub_url" --token-file "$token_file" --root "$root" --name "$name" --user "$ssh_user" --retain-pending
install -d -m 700 "$root/bin"
[ ! -e "$root/bin/hostlink-agent" ] || { echo 'Agent executable already exists; refusing overwrite.' >&2; exit 1; }
cp "$verified/hostlink-agent" "$root/bin/hostlink-agent"
chmod 700 "$root/bin/hostlink-agent"
[ "$(sha256sum "$root/bin/hostlink-agent" | awk '{print $1}')" = "$(sha256sum "$verified/hostlink-agent" | awk '{print $1}')" ] || { echo 'Published Agent package member digest mismatch.' >&2; exit 1; }
cp "$verified/install.json" "$root/install.json"
chmod 600 "$root/install.json"
cp "$verified/bootstrap-receipt.json" "$root/bootstrap-receipt.json"
chmod 600 "$root/bootstrap-receipt.json"
"$agent" bootstrap-finalize --root "$root"
rm -f "$token_file"
rm -f "$agent" "$archive"
rm -rf "$verified"
rmdir "$stage"
printf 'Enrollment complete. Starting the embedded Agent in this user session. Press Ctrl-C to stop it.\n' >&2
exec "$root/bin/hostlink-agent" run --config "$root/state/agent.json"
