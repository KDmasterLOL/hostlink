# shellcheck shell=sh
# Target-local bootstrap helpers; never installed. Never enable tracing around secrets.
set +x
umask 077
hl_fail() { echo "$1" >&2; exit 1; }
hl_asset_url() {
    case "$1" in
        https://github.com/KDmasterLOL/hostlink/releases/download/*)
            hl_id=${1#https://github.com/KDmasterLOL/hostlink/releases/download/} ;;
        *) hl_fail 'Expected a public HostLink release asset URL.' ;;
    esac
    case "$hl_id" in v*/hostlink-agent-*) ;; *) hl_fail 'Invalid public release asset URL.' ;; esac
}
hl_download() (
    # curl >=8.4 bounds bodies even without Content-Length.
    hl_asset_url "$1"
    hl_curl_version=$(curl -q --version | awk 'NR == 1 {print $2}')
    hl_major=${hl_curl_version%%.*}; hl_minor=${hl_curl_version#*.}; hl_minor=${hl_minor%%.*}
    [ "$hl_major" -gt 8 ] || { [ "$hl_major" -eq 8 ] && [ "$hl_minor" -ge 4 ]; } || hl_fail 'curl 8.4 or newer is required for bounded streaming.'
    hl_url=$1; hl_dest=$2; hl_max=$3; hl_deadline=$(($(date +%s) + $4)); hl_first=1
    trap 'rm -f "$hl_dest"' EXIT
    trap 'exit 130' HUP INT TERM
    while :; do
        hl_remaining=$((hl_deadline - $(date +%s)))
        [ "$hl_remaining" -gt 0 ] || hl_fail 'GitHub asset download deadline exceeded.'
        hl_result=$(
            curl -q --silent --fail --globoff --proto '=https' --tlsv1.2 \
                --header 'Accept: application/octet-stream' --user-agent 'HostLink-bootstrap' \
                --max-filesize "$hl_max" --connect-timeout 10 --max-time "$hl_remaining" \
                --output "$hl_dest" --write-out '%{http_code}\n%{redirect_url}' "$hl_url"
        ) || hl_fail 'GitHub asset download failed.'
        hl_newline='
'
        hl_status=${hl_result%%"$hl_newline"*}
        case "$hl_status" in
            200) [ "$(stat -c '%s' "$hl_dest")" -le "$hl_max" ] || hl_fail 'GitHub asset exceeds its size limit.'; break ;;
            302)
                [ "$hl_first" -eq 1 ] || hl_fail 'GitHub asset redirect limit exceeded.'
                hl_url=${hl_result#*"$hl_newline"}
                case "$hl_url" in https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) ;; *) hl_fail 'GitHub asset redirect destination rejected.' ;; esac
                case "$hl_url" in *[[:space:][:cntrl:]]*|*'#'*|*\\*) hl_fail 'GitHub asset redirect URL rejected.' ;; esac
                hl_first=0
                ;;
            *) hl_fail 'GitHub asset response status rejected.' ;;
        esac
    done
    trap - EXIT HUP INT TERM
)
