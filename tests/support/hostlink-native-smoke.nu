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
    print "hostlink native smoke self-tests passed"
}

def main [
    --host: string = ""
    --hostlink: string = "hostlink"
    --self-test
] {
    if $self_test {
        self-test
        return
    }
    if ($host | str trim | is-empty) {
        error make {msg: "--host must name an explicitly selected managed test host"}
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
    print "Not exercised: SSH disconnect/reconnect, detached Apalis job status, Agent crash/restart, or OS service lifecycle."
}
