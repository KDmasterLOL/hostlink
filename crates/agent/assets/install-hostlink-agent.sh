#!/bin/sh
set -eu

# BEGIN GITHUB BOOTSTRAP HELPERS
# Shared verbatim with the Controller renderer. Never enable tracing around secrets.
set +x
umask 077
hl_fail() { echo "$1" >&2; exit 1; }
hl_asset_url() {
    case "$1" in
        https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/*)
            hl_id=${1#https://api.github.com/repos/KDmasterLOL/hostlink/releases/assets/} ;;
        *) hl_fail 'Expected a HostLink GitHub API release asset URL.' ;;
    esac
    case "$hl_id" in ''|*[!0-9]*|0*) hl_fail 'Expected a positive numeric GitHub asset ID.' ;; esac
}
hl_safe_chain() (
    case "$1" in /*) ;; *) hl_fail 'Credential path must be absolute.' ;; esac
    case "$1/" in *'/../'*|*'/./'*) hl_fail 'Credential path must not contain dot components.' ;; esac
    [ ! -L "$1" ] && [ -d "$1" ] || hl_fail 'Credential ancestor is missing or a symlink.'
    hl_owner=$(stat -c '%u' "$1")
    [ "$hl_owner" = "$(id -u)" ] || [ "$hl_owner" = 0 ] || hl_fail 'Unsafe credential ancestor owner.'
    hl_mode=$((0$(stat -c '%a' "$1")))
    [ $((hl_mode & 18)) -eq 0 ] || hl_fail 'Credential ancestor is writable by other users.'
    [ "$1" = / ] || hl_safe_chain "$(dirname "$1")"
)
hl_config_dir() (
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        hl_config_dir "$(dirname "$1")"
        mkdir -m 700 "$1" || hl_fail 'Cannot create credential ancestor.'
    fi
    hl_safe_chain "$1"
)
hl_private_dir() {
    hl_config_dir "$1"
    [ "$(stat -c '%u:%a' "$1")" = "$(id -u):700" ] || hl_fail 'Credential directory must be owned by this user with mode 0700.'
}
hl_credential_path() {
    case "${XDG_CONFIG_HOME:-}" in
        /*) hl_config=$XDG_CONFIG_HOME ;;
        *) hl_config="$HOME/.config" ;;
    esac
    hl_credential="$hl_config/hostlink/credentials/github-token"
}
hl_load_credential() {
    hl_credential_path
    hl_safe_chain "$(dirname "$hl_credential")"
    for hl_dir in "$hl_config/hostlink" "$hl_config/hostlink/credentials"; do
        [ "$(stat -c '%u:%a' "$hl_dir")" = "$(id -u):700" ] || hl_fail 'Unsafe credential directory permissions.'
    done
    [ -f "$hl_credential" ] && [ ! -L "$hl_credential" ] || hl_fail 'GitHub credential must be a regular file, not a symlink.'
    [ "$(stat -c '%u:%a:%h' "$hl_credential")" = "$(id -u):600:1" ] || hl_fail 'GitHub credential must be owner-only mode 0600 with one link.'
    [ "$(stat -c '%s' "$hl_credential")" -le 1024 ] || hl_fail 'Invalid GitHub credential size.'
    hl_github_token=$(cat "$hl_credential")
    case "$hl_github_token" in ''|*[!A-Za-z0-9_]*) unset hl_github_token; hl_fail 'Invalid GitHub credential format.' ;; esac
}
hl_provision_credential() {
    [ "$(id -u)" -ne 0 ] || hl_fail 'Bootstrap must run as a normal unprivileged user.'
    [ "$#" -le 1 ] || hl_fail 'Unexpected credential provision arguments.'
    hl_credential_path
    hl_config_dir "$hl_config"
    hl_private_dir "$hl_config/hostlink"
    hl_private_dir "$hl_config/hostlink/credentials"
    if [ -e "$hl_credential" ] || [ -L "$hl_credential" ]; then
        hl_load_credential
        if [ "$#" -eq 1 ] && [ "$1" != "$hl_github_token" ]; then
            unset hl_github_token
            hl_fail 'Existing GitHub credential differs; rotate it explicitly instead of overwriting.'
        fi
        unset hl_github_token
        return
    fi
    if [ "$#" -eq 1 ]; then
        # Explicit Controller opt-in: the generated bootstrap is itself a
        # secret. Never print this value or pass it to a child process as argv.
        hl_github_token=$1
    else
        hl_tty_state=$(stty -g </dev/tty) || hl_fail 'An interactive target terminal is required.'
        trap 'stty "$hl_tty_state" </dev/tty' EXIT
        trap 'exit 130' HUP INT TERM
        stty -echo </dev/tty
        printf 'GitHub fine-grained PAT (HostLink Contents:Read only): ' >/dev/tty
        hl_read_ok=0
        IFS= read -r hl_github_token </dev/tty || hl_read_ok=$?
        stty "$hl_tty_state" </dev/tty
        trap - EXIT HUP INT TERM
        printf '\n' >/dev/tty
        [ "$hl_read_ok" -eq 0 ] || hl_fail 'GitHub credential prompt failed.'
    fi
    case "$hl_github_token" in ''|*[!A-Za-z0-9_]*) unset hl_github_token; hl_fail 'Invalid GitHub credential format.' ;; esac
    [ "${#hl_github_token}" -le 1024 ] || hl_fail 'Invalid GitHub credential size.'
    (set -C; printf '%s' "$hl_github_token" > "$hl_credential") || hl_fail 'Credential creation failed; existing files are never overwritten.'
    unset hl_github_token
    hl_load_credential
    unset hl_github_token
}
hl_download() (
    # Subshell confines the PAT. curl >=8.4 bounds bodies even without Content-Length.
    hl_asset_url "$1"
    hl_curl_version=$(curl -q --version | awk 'NR == 1 {print $2}')
    hl_major=${hl_curl_version%%.*}; hl_minor=${hl_curl_version#*.}; hl_minor=${hl_minor%%.*}
    [ "$hl_major" -gt 8 ] || { [ "$hl_major" -eq 8 ] && [ "$hl_minor" -ge 4 ]; } || hl_fail 'curl 8.4 or newer is required for bounded streaming.'
    hl_load_credential
    hl_url=$1; hl_dest=$2; hl_max=$3; hl_deadline=$(($(date +%s) + $4)); hl_first=1
    trap 'rm -f "$hl_dest"' EXIT
    trap 'exit 130' HUP INT TERM
    while :; do
        hl_remaining=$((hl_deadline - $(date +%s)))
        [ "$hl_remaining" -gt 0 ] || hl_fail 'GitHub asset download deadline exceeded.'
        hl_result=$(
            if [ "$hl_first" -eq 1 ]; then
                printf 'header = "Authorization: Bearer %s"\n' "$hl_github_token"
            fi | curl -q -K - --silent --fail --globoff --proto '=https' --tlsv1.2 \
                --header 'Accept: application/octet-stream' --user-agent 'HostLink-bootstrap' \
                --max-filesize "$hl_max" --connect-timeout 10 --max-time "$hl_remaining" \
                --output "$hl_dest" --write-out '%{http_code}\n%{redirect_url}' "$hl_url"
        ) || hl_fail 'GitHub asset download failed.'
        hl_status=${hl_result%%'
'*}
        case "$hl_status" in
            200) [ "$(stat -c '%s' "$hl_dest")" -le "$hl_max" ] || hl_fail 'GitHub asset exceeds its size limit.'; break ;;
            302)
                [ "$hl_first" -eq 1 ] || hl_fail 'GitHub asset redirect limit exceeded.'
                hl_url=${hl_result#*'
'}
                case "$hl_url" in https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) ;; *) hl_fail 'GitHub asset redirect destination rejected.' ;; esac
                case "$hl_url" in *[[:space:][:cntrl:]]*|*'#'*|*\\*) hl_fail 'GitHub asset redirect URL rejected.' ;; esac
                hl_first=0
                unset hl_github_token ;;
            *) hl_fail 'GitHub asset response status rejected.' ;;
        esac
    done
    trap - EXIT HUP INT TERM
)
# END GITHUB BOOTSTRAP HELPERS

usage() {
    cat >&2 <<'EOF'
Usage: install-hostlink-agent.sh --hub-url HTTPS_ORIGIN --name CANONICAL --ssh-user USER \
  --agent-url HTTPS_URL --agent-sha256 LOWERCASE_SHA256 --archive-url HTTPS_URL \
  --archive-sha256 LOWERCASE_SHA256 --agent-version SEMVER --target x86_64-unknown-linux-gnu \
  [--hub-ca-cert PEM]
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
hub_ca_cert=
while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || usage
    case "$1" in
        --hub-url) hub_url=$2 ;;
        --name) name=$2 ;;
        --ssh-user) ssh_user=$2 ;;
        --agent-url) agent_url=$2 ;;
        --agent-sha256) agent_sha256=$2 ;;
        --agent-version) agent_version=$2 ;;
        --archive-url) archive_url=$2 ;;
        --archive-sha256) archive_sha256=$2 ;;
        --target) target=$2 ;;
        --hub-ca-cert) hub_ca_cert=$2 ;;
        *) usage ;;
    esac
    shift 2
done

[ "$(id -u)" -ne 0 ] || hl_fail 'Enrollment must run as a normal unprivileged user.'
case "$hub_url" in https://*) ;; *) hl_fail 'Hub URL must use HTTPS.' ;; esac
hub_authority=${hub_url#https://}
case "$hub_authority" in *@*|*/*|*\?*|*\#*|'') hl_fail 'Hub URL must be an HTTPS origin without credentials, path, query or fragment.' ;; esac
hl_asset_url "$agent_url"
hl_asset_url "$archive_url"
case "$name" in ''|*[!a-z0-9._-]*|[!a-z0-9]*) hl_fail 'Name must be canonical lowercase ASCII.' ;; esac
case "$ssh_user" in ''|*[!A-Za-z0-9._-]*) hl_fail 'SSH user is invalid.' ;; esac
[ "${#name}" -le 128 ] || hl_fail 'Name is too long.'
for digest in "$agent_sha256" "$archive_sha256"; do
    case "$digest" in *[!0-9a-f]*|'') hl_fail 'SHA-256 must be lowercase hexadecimal.' ;; esac
    [ "${#digest}" -eq 64 ] || hl_fail 'SHA-256 must contain 64 characters.'
done
[ "$target" = 'x86_64-unknown-linux-gnu' ] || hl_fail 'Unsupported Linux package target.'
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || hl_fail 'This bootstrap supports x86_64 Linux only.'
printf '%s' "$agent_version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$' || hl_fail 'Agent version must be exact semantic version.'
command -v curl >/dev/null 2>&1 || hl_fail 'curl is required.'
command -v sha256sum >/dev/null 2>&1 || hl_fail 'sha256sum is required.'
if [ -n "$hub_ca_cert" ]; then
    [ -f "$hub_ca_cert" ] && [ ! -L "$hub_ca_cert" ] && [ -r "$hub_ca_cert" ] || hl_fail 'Explicit Hub CA must be a readable regular file, not a symlink.'
fi

base=${XDG_DATA_HOME:-"$HOME/.local/share"}
[ -d "$base" ] || mkdir -p "$base"
[ ! -L "$base" ] || hl_fail 'Install parent must not be a symlink.'
base=$(cd "$base" && pwd -P)
[ "$(stat -c '%u' "$base")" = "$(id -u)" ] || hl_fail 'Install parent must be owned by the current user.'
base_mode=$((0$(stat -c '%a' "$base")))
[ $((base_mode & 18)) -eq 0 ] || hl_fail 'Install parent must not be writable by group or other users.'
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
# The invite renderer provisions the target credential before fetching this script.
# Direct script execution requires the same private credential; it never accepts a PAT argument.
hl_download "$agent_url" "$agent" 268435456 120
hl_download "$archive_url" "$archive" 536870912 180
actual_sha=$(sha256sum "$agent" | awk '{print $1}')
[ "$actual_sha" = "$agent_sha256" ] || hl_fail 'Agent executable SHA-256 mismatch.'
chmod 700 "$agent"
"$agent" bootstrap-verify --archive "$archive" --sha256 "$archive_sha256" --target "$target" --version "$agent_version" --output "$verified"
[ -d "$verified" ] || hl_fail 'Exact Agent ZIP package verification failed; invite token was not requested.'
[ "$(sha256sum "$verified/hostlink-agent" | awk '{print $1}')" = "$agent_sha256" ] || hl_fail 'Verified ZIP executable differs from the independently pinned sidecar.'

printf 'One-use HostLink invite token: ' >&2
stty -echo
IFS= read -r token
stty echo
printf '\n' >&2
printf '%s' "$token" | LC_ALL=C grep -Eq '^[0-9a-f]{64}$' || { unset token; hl_fail 'Invite token format is invalid.'; }
umask 077
printf '%s' "$token" > "$token_file"
unset token

parent=$(mktemp -d "$base/hostlink-agent.XXXXXXXX")
chmod 700 "$parent"
root="$parent/Agent"
set -- --hub-url "$hub_url" --token-file "$token_file" --root "$root" --name "$name" --user "$ssh_user" --retain-pending
if [ -n "$hub_ca_cert" ]; then set -- "$@" --hub-ca-cert "$hub_ca_cert"; fi
"$agent" enroll "$@"
install -d -m 700 "$root/bin"
for member in hostlink-agent manifest.json archive.sha256 bootstrap-receipt.json; do
    destination="$root/bin/$member"
    [ "$member" != bootstrap-receipt.json ] || destination="$root/$member"
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || hl_fail 'Agent package member already exists; refusing overwrite.'
    # Noclobber refuses existing files; finalize verifies the installed inventory and hashes.
    (set -C; cat "$verified/$member" > "$destination")
    chmod 600 "$destination"
done
chmod 700 "$root/bin/hostlink-agent"
"$agent" bootstrap-finalize --root "$root"
cleanup
printf 'Enrollment complete. Starting the embedded Agent in this user session. Press Ctrl-C to stop it.\n' >&2
exec "$root/bin/hostlink-agent" run --config "$root/state/agent.json"
