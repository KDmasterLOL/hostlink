# shellcheck shell=sh
# Inputs are quoted by the Controller renderer before this fragment.
: "${agent_url:?}" "${agent_sha256:?}" "${hub_url:?}" "${name:?}" "${ssh_user:?}" "${hub_ca_cert?}"
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
# A verified binary is required before even asking for the one-use Hub token.
hl_tty_state=$(stty -g </dev/tty) || hl_fail 'An interactive target terminal is required.'
trap 'stty "$hl_tty_state" </dev/tty; cleanup' 0
stty -echo </dev/tty
printf 'One-use HostLink invite token: ' >/dev/tty
IFS= read -r token </dev/tty
stty "$hl_tty_state" </dev/tty
trap cleanup 0
printf '\n' >/dev/tty
[ "${#token}" -eq 64 ] || hl_fail 'Invalid invite token size.'
case "$token" in *[!0-9a-f]*) unset token; hl_fail 'Invalid invite token format.' ;; esac
(set -C; printf '%s' "$token" > "$token_file")
unset token
set -- install --hub-url "$hub_url" --token-file "$token_file" --name "$name" --user "$ssh_user"
if [ -n "$hub_ca_cert" ]; then set -- "$@" --hub-ca-cert "$hub_ca_cert"; fi
"$agent" "$@"
cleanup
trap - 0 HUP INT TERM
exec "$root/bin/hostlink-agent" run --config "$root/state/agent.json"
