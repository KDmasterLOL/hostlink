# shellcheck shell=sh
# Inputs are quoted by the Controller renderer before this fragment.
: "${agent_url:?}" "${agent_sha256:?}" "${hub_url:?}" "${name:?}" "${ssh_user:?}" "${hub_ca_cert?}" "${gateway_index?}"
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || hl_fail 'This bootstrap supports x86_64 Linux only.'
case "${XDG_DATA_HOME:-}" in
    /*) hl_data=$XDG_DATA_HOME ;;
    *) hl_data="$HOME/.local/share" ;;
esac
case "$hl_data" in /*) ;; *) hl_fail 'An absolute per-user data directory is required.' ;; esac
root="$hl_data/hostlink/Agent"
stage=$(mktemp -d "${TMPDIR:-/tmp}/hostlink-bootstrap.XXXXXXXX")
token_file="$stage/invite-token"
agent="$stage/hostlink-agent"
cleanup() { rm -rf "$stage"; }
trap cleanup 0
trap 'exit 130' HUP INT TERM
hl_download "$agent_url" "$agent" 268435456 120
printf '%s  %s\n' "$agent_sha256" "$agent" | sha256sum -c -
chmod 700 "$agent"
# The stage is private; CreateNew prevents replacing an existing file.
(set -C; printf '%s' "$HL_INVITE" > "$token_file")
unset HL_INVITE
set -- install --hub-url "$hub_url" --token-file "$token_file" --name "$name" --user "$ssh_user"
if [ -n "$hub_ca_cert" ]; then set -- "$@" --hub-ca-cert "$hub_ca_cert"; fi
if [ -n "$gateway_index" ]; then set -- "$@" --gateway-index "$gateway_index"; fi
"$agent" "$@"
cleanup
trap - 0 HUP INT TERM
"$root/bin/hostlink-agent" service install --root "$root" --config "$root/state/agent.json"
"$root/bin/hostlink-agent" service start --root "$root"
