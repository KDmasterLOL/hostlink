#!/usr/bin/env nu

def host-args [host: string] {
    ["--host" $host]
}

def remote-name [nonce: string] {
    $"qa-($nonce).bin"
}

def new-run-id [] {
    random uuid | str replace --all '-' ''
}

def remote-name-valid [name: string] {
    $name =~ '^qa-[0-9a-f]{32}\.bin$'
}

def checked-remote-name [name: string] {
    if not (remote-name-valid $name) {
        error make {msg: "SFTP --remote must be a generated relative basename"}
    }
    $name
}

def command-args [host: string, command: string] {
    ["--host" $host "--command" $command]
}

def job-id-valid [job_id: string] {
    $job_id =~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
}

def checked-job-id [job_id: string] {
    if not (job-id-valid $job_id) {
        error make {msg: "detached exec did not return one strict ULID job ID"}
    }
    $job_id
}

def parse-job-id [output: string] {
    let tokens = ($output | str replace --all --regex '[^0-9A-HJKMNP-TV-Z]+' ' ' | split row ' ')
    let matches = ($tokens | where {|token| job-id-valid $token})
    if ($matches | length) != 1 {
        error make {msg: "detached exec output must contain exactly one strict ULID job ID"}
    }
    $matches | first
}

def parse-state-line [line: string] {
    let states = ["Queued" "Pending" "Running" "Done" "Failed" "Killed"]
    let trimmed = ($line | str trim)
    let exact = ($states | where {|state| $trimmed == $state})
    if ($exact | length) == 1 {
        return $exact
    }
    let words = ($trimmed | str replace --all --regex '[^A-Za-z]+' ' ' | str trim | split row ' ')
    let keyed_values = ($words | enumerate | each {|entry|
        if (($entry.item | str lowercase) in ["state" "status"]) and (($entry.index + 1) < ($words | length)) {
            $words | get ($entry.index + 1)
        } else {
            ""
        }
    } | where {|value| not ($value | is-empty)})
    let matches = ($states | where {|state| $keyed_values | any {|value| $value == $state }})
    if ($matches | length) == 1 {
        return $matches
    }
    []
}

def parse-job-state [output: string] {
    let matches = ($output | lines | each {|line| parse-state-line $line} | flatten)
    if ($matches | length) != 1 {
        error make {msg: "job status output did not contain one unambiguous recognized state"}
    }
    $matches | first
}

def task-command [job_os: string] {
    match $job_os {
        "linux" => "sleep 8"
        "windows" => "Start-Sleep -Seconds 8"
        _ => { error make {msg: "--job-os must be linux or windows"} }
    }
}

def detached-job-args [host: string, command: string, board_port: int] {
    ["exec"] ++ (host-args $host) ++ ["--command" $command "--detach" "--board-port" ($board_port | into string)]
}

def job-status-args [host: string, board_port: int, job_id: string] {
    ["job" "status"] ++ (host-args $host) ++ ["--board-port" ($board_port | into string) (checked-job-id $job_id)]
}

def detached-cli-help-valid [exec_help: string, status_help: string] {
    (($exec_help | str contains "--host") and ($exec_help | str contains "--detach") and ($exec_help | str contains "--board-port") and ($status_help | str contains "--host") and ($status_help | str contains "--board-port") and ($status_help | str contains "JOB_ID"))
}

def require-detached-cli [binary: string] {
    let exec_help = (run-cli $binary ["exec" "--help"])
    let status_help = (run-cli $binary ["job" "status" "--help"])
    if not (detached-cli-help-valid $exec_help $status_help) {
        error make {msg: "Controller CLI help does not expose the required detached exec and job status flags"}
    }
}

def job-config [job: bool, board_port_arg: string, job_os: string] {
    let port_provided = not ($board_port_arg | is-empty)
    let os_provided = not ($job_os | is-empty)
    let any_provided = $job or $port_provided or $os_provided
    if not $any_provided {
        return {enabled: false, board_port: 0, job_os: ""}
    }
    if not ($job and $port_provided and $os_provided) {
        error make {msg: "detached smoke requires --job, --board-port INT, and --job-os linux|windows together"}
    }
    if not ($board_port_arg =~ '^[0-9]+$') {
        error make {msg: "--board-port must be an integer from 1 through 65535"}
    }
    let port = ($board_port_arg | into int)
    if $port < 1 or $port > 65535 {
        error make {msg: "--board-port must be an integer from 1 through 65535"}
    }
    if $job_os not-in ["linux" "windows"] {
        error make {msg: "--job-os must be linux or windows"}
    }
    {enabled: true, board_port: $port, job_os: $job_os}
}

def upload-args [host: string, local: string, remote: string] {
    ["--host" $host "--local" $local "--remote" (checked-remote-name $remote)]
}

def download-args [host: string, remote: string, local: string] {
    ["--host" $host "--remote" (checked-remote-name $remote) "--local" $local]
}

def expect [condition: bool, message: string] {
    if not $condition {
        error make {msg: $message}
    }
}

def run-cli [binary: string, argv: list<string>] {
    let result = (^$binary ...$argv | complete)
    if $result.exit_code != 0 {
        error make {msg: $"command failed (($argv | str join ' ')): ($result.stderr | str trim)"}
    }
    $result.stdout
}

def run-detached-job-smoke [binary: string, host: string, board_port: int, job_os: string] {
    let command = (task-command $job_os)
    let submitted_at = (date now)
    let acknowledgment = (run-cli $binary (detached-job-args $host $command $board_port))
    let acknowledged_at = (date now)
    let fast_acknowledgment = (($acknowledged_at - $submitted_at) <= 6sec)
    let job_id = (parse-job-id $acknowledgment)
    print $"Detached smoke accepted job ($job_id)"

    let deadline = (date now) + 60sec
    mut state = "Unobserved"
    while ((date now) < $deadline) and ($state not-in ["Done" "Failed" "Killed"]) {
        # Each status invocation is a new Controller process and a fresh pinned SSH connection.
        let status_output = (run-cli $binary (job-status-args $host $board_port $job_id))
        $state = (parse-job-state $status_output)
        print $"Detached smoke job ($job_id): ($state)"
        if $state not-in ["Done" "Failed" "Killed"] {
            sleep 1sec
        }
    }
    if $state in ["Failed" "Killed"] {
        error make {msg: $"detached smoke job ($job_id) reached terminal state ($state)"}
    }
    if $state != "Done" {
        error make {msg: $"detached smoke job ($job_id) did not reach Done within 60 seconds; last observed state: ($state)"}
    }
    if not $fast_acknowledgment {
        error make {msg: $"job ($job_id) reached Done, but submit took over six seconds; client-close preservation was not demonstrated"}
    }
    print $"PASS: detached smoke job ($job_id) reached Done after the submitting Controller process exited"
}

def self-test [] {
    expect (remote-name-valid (remote-name (new-run-id))) "generated random basename rejected"
    expect (remote-name-valid (remote-name "0123456789abcdef0123456789abcdef")) "generated basename rejected"
    expect (not (remote-name-valid "/tmp/qa-0123456789abcdef0123456789abcdef.bin")) "absolute SFTP path accepted"
    expect (not (remote-name-valid "nested/qa-0123456789abcdef0123456789abcdef.bin")) "SFTP path with separator accepted"
    expect (not (remote-name-valid "qa-0123456789abcdef0123456789abcdef.bin/../other")) "SFTP traversal path accepted"
    expect (not (remote-name-valid "qa-0123456789abcdef0123456789abcdef.bin\\other")) "SFTP backslash path accepted"
    expect ((host-args "lab") == ["--host" "lab"]) "host argv changed"
    expect ((command-args "lab" "printf ok") == ["--host" "lab" "--command" "printf ok"]) "exec argv changed"
    expect ((upload-args "lab" "in.bin" "qa-0123456789abcdef0123456789abcdef.bin") == ["--host" "lab" "--local" "in.bin" "--remote" "qa-0123456789abcdef0123456789abcdef.bin"]) "upload argv changed"
    expect ((download-args "lab" "qa-0123456789abcdef0123456789abcdef.bin" "out.bin") == ["--host" "lab" "--remote" "qa-0123456789abcdef0123456789abcdef.bin" "--local" "out.bin"]) "download argv changed"
    expect (try { upload-args "lab" "in.bin" "/tmp/qa-test.bin"; false } catch { true }) "upload argv builder accepted an absolute remote path"
    expect (try { download-args "lab" "nested/qa-test.bin" "out.bin"; false } catch { true }) "download argv builder accepted a path with separators"
    let valid_job_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
    expect (job-id-valid $valid_job_id) "valid ULID rejected"
    expect ((parse-job-id $"queued job ID: ($valid_job_id)") == $valid_job_id) "job ID output parser changed"
    expect (try { parse-job-id "job ID: 81ARZ3NDEKTSV4RRFFQ69G5FAV"; false } catch { true }) "invalid ULID accepted"
    expect (try { parse-job-id $"($valid_job_id) ($valid_job_id)"; false } catch { true }) "ambiguous job IDs accepted"
    expect ((parse-job-state "Status: Running") == "Running") "Running state parser changed"
    expect ((parse-job-state "Status: Done") == "Done") "Done state parser changed"
    expect ((parse-job-state "Job status: Done") == "Done") "labeled job state parser changed"
    expect ((parse-job-state "{\"job_id\": \"$valid_job_id\", \"status\": \"Done\"}") == "Done") "JSON job state parser changed"
    expect ((parse-job-state "Status: Failed") == "Failed") "Failed state parser changed"
    expect ((parse-job-state "Status: Killed") == "Killed") "Killed state parser changed"
    expect (try { parse-job-state "Status: Unknown"; false } catch { true }) "unknown job state accepted"
    expect (try { parse-job-state "Message: Done"; false } catch { true }) "unlabeled Done text accepted as job state"
    expect (try { parse-job-state "Status: Running\nStatus: Done"; false } catch { true }) "ambiguous job states accepted"
    expect ((task-command "linux") == "sleep 8") "Linux task command changed"
    expect ((task-command "windows") == "Start-Sleep -Seconds 8") "Windows task command changed"
    expect ((detached-job-args "lab" "sleep 8" 4321) == ["exec" "--host" "lab" "--command" "sleep 8" "--detach" "--board-port" "4321"]) "detached exec argv changed"
    expect ((job-status-args "lab" 4321 $valid_job_id) == ["job" "status" "--host" "lab" "--board-port" "4321" $valid_job_id]) "job status argv changed"
    expect (detached-cli-help-valid "exec --host HOST --detach --board-port PORT" "job status --host HOST --board-port PORT JOB_ID") "detached CLI capability help rejected"
    expect (not (detached-cli-help-valid "exec --command" "unknown command")) "old CLI accepted for optional detached smoke"
    expect (not ((job-config false "" "").enabled)) "job smoke must remain opt-in"
    expect ((job-config true "4321" "linux").enabled) "complete job opt-in rejected"
    expect (try { job-config true "" "linux"; false } catch { true }) "missing Board port accepted"
    expect (try { job-config false "4321" "linux"; false } catch { true }) "job smoke accepted without --job"
    expect (try { job-config true "0" "linux"; false } catch { true }) "invalid Board port accepted"
    expect (try { job-config true "4321" "macos"; false } catch { true }) "unsupported job OS accepted"
    print "hostlink native smoke self-tests passed"
}

def main [
    --host: string = ""
    --hostlink: string = "hostlink"
    --job
    --board-port: string = ""
    --job-os: string = ""
    --self-test
] {
    if $self_test {
        self-test
        return
    }
    if ($host | str trim | is-empty) {
        error make {msg: "--host must name an explicitly selected managed test host"}
    }
    let config = (job-config $job $board_port $job_os)
    if $config.enabled {
        require-detached-cli $hostlink
    }
    print $"Checking pinned HostLink identity for ($host)"
    run-cli $hostlink (["verify" $host]) | ignore
    run-cli $hostlink (["check"] ++ (host-args $host)) | ignore

    let nonce = (new-run-id)
    let remote = (remote-name $nonce)
    if not (remote-name-valid $remote) {
        error make {msg: "generated SFTP name failed basename validation"}
    }
    let temp_base = [$env.TEMP? $env.TMP? $env.TMPDIR? "/tmp"] | compact | first
    let local_dir = ($temp_base | path join $"hostlink-smoke-($nonce)")
    if ($local_dir | path exists) {
        error make {msg: "unique local smoke directory already exists; refusing to reuse it"}
    }
    mkdir $local_dir
    let source = ($local_dir | path join "source.bin")
    let downloaded = ($local_dir | path join "downloaded.bin")
    let payload = $"HostLink 1C-1214 disposable SFTP smoke ($nonce)"
    $payload | save --raw $source
    let local_hash = (open --raw $source | hash sha256)

    print "Running read-only remote command over pinned SSH"
    run-cli $hostlink (["exec"] ++ (command-args $host "whoami")) | ignore
    print "Uploading and downloading one uniquely named disposable SFTP file"
    run-cli $hostlink (["upload"] ++ (upload-args $host $source $remote)) | ignore
    run-cli $hostlink (["download"] ++ (download-args $host $remote $downloaded)) | ignore
    let downloaded_hash = (open --raw $downloaded | hash sha256)
    if $local_hash != $downloaded_hash {
        error make {msg: $"SFTP SHA-256 mismatch: source=($local_hash) downloaded=($downloaded_hash); remote artifact retained at ($remote)"}
    }

    rm --recursive --force $local_dir
    print $"PASS: pinned SSH checks and SFTP SHA-256 roundtrip ($local_hash)"
    print $"SFTP basename retained in this Controller's private Agent transfer root: ($remote)"
    if $config.enabled {
        run-detached-job-smoke $hostlink $host $config.board_port $config.job_os
    } else {
        print "Not exercised: detached Apalis job status, Agent crash/restart, or OS service lifecycle."
    }
    print "No physical network outage, Agent crash/restart, or OS service lifecycle was exercised."
}
