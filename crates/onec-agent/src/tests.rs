use super::*;
use hostlink_protocol::{
    AgentErrorCode, AgentRequestKind, DEFAULT_EXEC_TIMEOUT_MS, SecretEnvironment, read_json_line,
};
use std::io::BufReader;

#[cfg(unix)]
use std::time::Instant;

struct LegacyPowerShellRule {
    name: &'static str,
    fragments: &'static [&'static str],
}

const LEGACY_MANAGED_POWERSHELL_ASSETS: [(&str, &str); 3] = [
    (
        "Install-OnecToolkit.ps1",
        include_str!("../assets/Install-OnecToolkit.ps1"),
    ),
    (
        "Update-OnecToolkit.ps1",
        include_str!("../assets/Update-OnecToolkit.ps1"),
    ),
    (
        "Run-OnecAgent.ps1",
        include_str!("../assets/Run-OnecAgent.ps1"),
    ),
];

const HOSTLINK_AGENT_POWERSHELL_ASSETS: [(&str, &str); 3] = [
    (
        "Install-HostLink-Agent.ps1",
        include_str!("../assets/Install-HostLink-Agent.ps1"),
    ),
    (
        "Run-HostLink-Agent.ps1",
        include_str!("../assets/Run-HostLink-Agent.ps1"),
    ),
    (
        "Update-HostLink-Agent.ps1",
        include_str!("../assets/Update-HostLink-Agent.ps1"),
    ),
];

const LEGACY_POWERSHELL_DENYLIST: &[LegacyPowerShellRule] = &[
    LegacyPowerShellRule {
        name: "ConvertFrom-Json",
        fragments: &["convertfrom-json"],
    },
    LegacyPowerShellRule {
        name: "ConvertTo-Json",
        fragments: &["convertto-json"],
    },
    LegacyPowerShellRule {
        name: "Get-Content -Raw",
        fragments: &["get-content", "-raw"],
    },
    LegacyPowerShellRule {
        name: "Get-ChildItem -Directory",
        fragments: &["get-childitem", "-directory"],
    },
    LegacyPowerShellRule {
        name: "Get-ChildItem -File",
        fragments: &["get-childitem", "-file"],
    },
    LegacyPowerShellRule {
        name: "Get-FileHash",
        fragments: &["get-filehash"],
    },
    LegacyPowerShellRule {
        name: "Get-NetTCPConnection",
        fragments: &["get-nettcpconnection"],
    },
    LegacyPowerShellRule {
        name: "String.IsNullOrWhiteSpace",
        fragments: &["isnullorwhitespace"],
    },
];

fn legacy_powershell_logical_lines(script: &str) -> Vec<String> {
    let mut logical_lines = Vec::new();
    let mut current = String::new();

    for line in script.lines() {
        let line = line.trim_end();
        if let Some(prefix) = line.strip_suffix('`') {
            current.push_str(prefix);
            current.push(' ');
            continue;
        }

        current.push_str(line);
        logical_lines.push(std::mem::take(&mut current).to_ascii_lowercase());
    }

    if !current.is_empty() {
        logical_lines.push(current.to_ascii_lowercase());
    }
    logical_lines
}

fn legacy_powershell_violations(script: &str) -> Vec<&'static str> {
    legacy_powershell_logical_lines(script)
        .into_iter()
        .flat_map(|line| {
            LEGACY_POWERSHELL_DENYLIST
                .iter()
                .filter(move |rule| {
                    rule.fragments
                        .iter()
                        .all(|fragment| line.contains(fragment))
                })
                .map(|rule| rule.name)
        })
        .collect()
}

#[test]
fn regression_inv_118_managed_target_powershell_obeys_legacy_compatibility_contract() {
    for (asset, script) in LEGACY_MANAGED_POWERSHELL_ASSETS {
        assert!(
            script.is_ascii(),
            "{asset} must remain ASCII unless it is intentionally materialized as UTF-8 with BOM for Windows PowerShell"
        );
        assert!(
            !script.as_bytes().starts_with(&[0xef, 0xbb, 0xbf]),
            "{asset} is ASCII-only and must not carry an unnecessary UTF-8 BOM"
        );

        let violations = legacy_powershell_violations(script);
        assert!(
            violations.is_empty(),
            "{asset} uses legacy-incompatible PowerShell constructs: {}",
            violations.join(", ")
        );
    }

    let continued = "Get-Content `\n  -LiteralPath $path `\n  -Raw";
    assert_eq!(
        legacy_powershell_violations(continued),
        vec!["Get-Content -Raw"],
        "line continuations must not bypass the compatibility guard"
    );
}

#[test]
fn hostlink_agent_assets_expose_only_the_fresh_root_and_exact_update_flow() {
    for (name, script) in HOSTLINK_AGENT_POWERSHELL_ASSETS {
        assert!(
            script.is_ascii(),
            "{name} must remain Windows PowerShell 2 compatible ASCII"
        );
        assert!(
            !script.contains("$PSScriptRoot"),
            "PowerShell 2 has no PSScriptRoot"
        );
        assert!(!script.to_ascii_lowercase().contains("get-filehash"));
        let violations = legacy_powershell_violations(script);
        assert!(
            violations.is_empty(),
            "{name} uses unsupported PowerShell syntax: {}",
            violations.join(", ")
        );
    }
    let install = HOSTLINK_AGENT_POWERSHELL_ASSETS[0].1;
    let run = HOSTLINK_AGENT_POWERSHELL_ASSETS[1].1;
    let update = HOSTLINK_AGENT_POWERSHELL_ASSETS[2].1;
    for required in [
        "$ArchiveFile",
        "$ArchiveSha256",
        "$PackageVersion",
        "$Target",
        "Is64BitOperatingSystem",
        "HostLink\\Agent",
        "LocalApplicationData",
        "hostlink-agent.exe",
        "ZipArchive",
        "__self-update",
        "--agent-only",
        "CreateNew",
        "[string]$ConfigFile",
        "[string]$HubUrl",
        "[string]$EnrollmentTokenFile",
        "__prepare-enrollment",
        "--token-file",
        "--state-dir",
        "[IO.Directory]::Move($stateDir, $publishedState)",
        "Do not reuse this token; create a new invite",
        "cannot run as a built-in service account",
        "requires an interactive user session",
        "x86_64-pc-windows-msvc",
        "x86_64-win7-windows-msvc",
        "i686-win7-windows-msvc",
        "Unsupported Windows package target",
        "System.IO.Compression.ZipArchive is unavailable",
        "Windows 7 PowerShell 2 on CLR 2 is not verified",
        "must run unelevated",
        "Join-Path $root 'jobs'",
        "Security.AccessControl.DirectorySecurity",
        "CreateDirectory($jobsRoot, $jobsSecurity)",
    ] {
        assert!(
            install.contains(required),
            "fresh installer lacks {required}"
        );
    }
    assert!(run.contains("hostlink-agent.exe"));
    assert!(run.contains("sha256"));
    assert!(run.contains("$agent = Join-Path $bin 'hostlink-agent.exe'"));
    assert!(install.contains("manual configuration mode"));
    assert!(install.contains("requires HubUrl and EnrollmentTokenFile together"));
    assert!(!install.contains("-EnrollToken"));
    assert!(!install.contains("Register-Service"));
    assert!(!install.contains("New-Service"));
    assert!(!install.contains("Shell.Application"));
    assert!(
        install.find("CreateDirectory($jobsRoot, $jobsSecurity)") < install.find("__self-update"),
        "private jobs root must exist before the candidate updater checks root/jobs"
    );
    for required in [
        "ArchiveFile",
        "ArchiveSha256",
        "PackageVersion",
        "--agent-only",
        "--archive-file",
        "--target",
        "Is64BitOperatingSystem",
        "LocalApplicationData",
        "ReparsePoint",
    ] {
        assert!(update.contains(required), "Agent updater lacks {required}");
    }
    for forbidden in [
        "onec.exe",
        "onec-toolkit",
        "Register-Service",
        "New-Service",
        "CurrentVersion\\Run",
    ] {
        assert!(
            !install.contains(forbidden),
            "fresh installer contains {forbidden}"
        );
    }
}

#[test]
fn managed_installer_keeps_win7_runtime_but_gates_target_ssh_at_nt_6_2() {
    let script = include_str!("../assets/Install-OnecToolkit.ps1");
    assert!(!script.contains("OSVersion.Version.Major -lt 10"));
    assert!(script.contains("($v.Major -lt 6) -or (($v.Major -eq 6) -and ($v.Minor -lt 1))"));
    assert!(script.contains(
        "return (($version.Major -gt 6) -or (($version.Major -eq 6) -and ($version.Minor -ge 2)))"
    ));
}

#[test]
fn direct_installer_does_not_require_private_toolkit_source_access() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    for retired in [
        "$ReleaseId",
        "$ReleaseManifestSha256",
        "$ReleaseVersion",
        "$ManagedReleaseId",
        "ReleaseBaseUrl",
        "$GitHubRepo",
        "installed_release_id",
        "release-manifest.json",
        "/latest/",
        "releases/latest",
    ] {
        assert!(
            !install.contains(retired),
            "installer retains retired selector {retired}"
        );
    }
    assert!(install.contains(
        "$metadata.Add('installed_package_sha256', $DirectPackageSha256.ToLowerInvariant())"
    ));
    assert!(update.contains("'__self-update', '--root', $Root"));
    assert!(!update.contains("github_repo"));
    assert!(!update.contains("Download-File"));
    assert!(!rust_update.contains("onec_managed_release"));
    assert!(!rust_update.contains("resolve_latest"));
}

#[test]
fn managed_runtime_bundle_owns_update_and_supervisor_assets() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let update_command = include_str!("../assets/onec-toolkit-update.cmd");
    let rust_update = include_str!("managed_update.rs");

    assert!(!supervisor.contains("Update-OnecToolkit.ps1"));
    assert!(update.contains("$publishedRunner = Join-Path $binDir 'Run-OnecAgent.ps1'"));
    assert!(update.contains("Copy-Item -Force $publishedRunner $runnerPath"));
    assert!(install.contains("'onec-toolkit-update.cmd'"));
    assert!(install.contains("Join-Path $binDir 'Run-OnecAgent.ps1'"));
    assert!(install.contains("Join-Path $binDir 'Update-OnecToolkit.ps1'"));
    assert!(install.contains("Join-Path $candidateDir 'onec-toolkit-update.cmd'"));
    assert!(update_command.contains("%~dp0Update-OnecToolkit.ps1"));
    assert!(!update_command.contains("..\\scripts"));

    assert!(
        !rust_update.contains("onec-access.exe"),
        "managed runtime bundle must exclude the controller-only onec-access executable"
    );

    for required in [
        "onec-agent.exe",
        "onec.exe",
        "Run-OnecAgent.ps1",
        "Update-OnecToolkit.ps1",
        "onec-toolkit-update.cmd",
    ] {
        assert!(
            rust_update.contains(&format!("\"{required}\"")),
            "Rust bundle verification must require {required}"
        );
    }
}

#[test]
fn installer_and_agent_updater_require_exact_direct_zip_packages() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    for parameter in [
        "DirectPackageUrl",
        "DirectPackageSha256",
        "DirectPackageVersion",
        "DirectPackageTarget",
    ] {
        assert!(install.contains(&format!("[string]${parameter} = ''")));
    }
    assert!(install.contains("if ($directPackageCount -ne $directPackageValues.Count)"));
    assert!(
        install
            .contains("Download-PinnedDirectFile $DirectPackageUrl $archive $DirectPackageSha256")
    );
    assert!(!install.contains("release-manifest.json"));
    assert!(!install.contains("/latest/"));
    assert!(!install.contains("latest"));
    assert!(!install.contains("Get-ManagedHttpMirror"));
    assert!(!install.contains("http://"));
    assert!(rust_update.contains("pub fn update_direct_package"));
    assert!(rust_update.contains("validate_direct_archive"));
    assert!(rust_update.contains("installed_package_sha256"));
    assert!(!update.contains("latest/manifest.json"));
    assert!(!update.contains("release-manifest.json"));
    assert!(update.contains("-ArchiveSha256"));
    assert!(update.contains("-PackageVersion"));
    assert!(update.contains("-Target"));
}

#[test]
fn direct_runtime_install_uses_operator_pins_without_manifest_or_redirects() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    for parameter in [
        "DirectPackageUrl",
        "DirectPackageSha256",
        "DirectPackageVersion",
        "DirectPackageTarget",
    ] {
        assert!(install.contains(&format!("[string]${parameter} = ''")));
        assert!(install.contains(parameter));
    }
    assert!(
        install
            .contains("Download-PinnedDirectFile $DirectPackageUrl $archive $DirectPackageSha256")
    );
    assert!(install.contains("$DirectPackageTarget -ne $target"));
    assert!(install.contains("GetFileName($directUri.AbsolutePath) -ne $archiveName"));
    assert!(install.contains(
        "DirectPackageUrl, DirectPackageSha256, DirectPackageVersion, and DirectPackageTarget"
    ));
    assert!(!install.contains("release-manifest.json"));
    assert!(!install.contains("/latest/"));
    assert!(!install.contains(".sha256"));

    assert!(install.contains("$request.AllowAutoRedirect = $false"));
    assert!(install.contains("Direct artifact URL changed during download."));
    assert!(install.contains("Direct package exceeds the 512 MiB size limit."));
    assert!(install.contains("$version -ceq $DirectPackageVersion"));
    assert!(install.contains("[Regex]::Escape($DirectPackageVersion)"));
    assert!(install.contains(r"\+src[0-9a-f]{16}$"));
    assert!(install.contains("if (-not $versionMatches)"));
    assert!(!install.contains("$version -ne $DirectPackageVersion"));
    assert!(install.contains("$directUri.Scheme -ne 'https'"));
    assert!(install.contains("$directUri.UserInfo"));
    assert!(install.contains("$directUri.Query"));
    assert!(install.contains("$directUri.Fragment"));
    assert!(install.contains(
        "$metadata.Add('installed_package_sha256', $DirectPackageSha256.ToLowerInvariant())"
    ));
    assert!(install.contains("Direct package ZIP must contain exactly five entries."));
    assert!(install.contains("Direct package ZIP does not contain the exact required entry set."));
    assert!(install.contains("$expectedRoot = 'onec-toolkit-' + $Target + '/'"));
    assert!(install.contains("$name -match '(^|/)\\.($|/)|(^|/)\\.\\.($|/)'"));
    assert!(install.contains("'https://github.com/git-for-windows/git/releases/download/'"));
    assert!(
        install.contains("PortableGit download failed. On old Windows without working TLS 1.2")
    );
    assert!(install.contains("Assert-Sha256 $archive $spec.Sha256"));
    for required in [
        "onec.exe",
        "onec-agent.exe",
        "Run-OnecAgent.ps1",
        "Update-OnecToolkit.ps1",
        "onec-toolkit-update.cmd",
    ] {
        assert!(install.contains(&format!("'{required}'")));
    }
}

#[test]
fn regression_inv_026_legacy_latest_metadata_no_longer_drives_agent_updates() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    assert!(!rust_update.contains("trimmed.strip_suffix(\"/latest\")"));
    assert!(!rust_update.contains("resolve_latest"));
    assert!(rust_update.contains("pub fn update_direct_package"));
    assert!(!update.contains("$candidateManagedReleaseRoot"));
}

#[test]
fn regression_inv_028_remote_user_session_update_detaches_before_stopping_transport() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");

    assert!(update.contains("function Start-DetachedUpdater"));
    assert!(update.contains("([WmiClass]'Win32_Process').Create($commandLine)"));
    assert!(update.contains("-StartDelaySeconds 2"));
    let pid_read = update
        .find("[IO.File]::ReadAllText($pidFile)")
        .expect("owned supervisor PID read");
    let detached_start = update
        .find("$detachedPid = Start-DetachedUpdater")
        .expect("detached handoff");
    assert!(pid_read < detached_start);
    assert!(!update[..detached_start].contains("Stop-Agent $AgentPid"));
    assert!(!update.contains("Get-ResidentAgentProcessIds"));
}

#[test]
fn regression_inv_050_agent_update_requires_exact_archive_and_never_resolves_latest() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    assert!(update.contains("Exact package selection is required"));
    assert!(update.contains("'--archive-sha256'"));
    assert!(update.contains("'--package-version'"));
    assert!(update.contains("'--target'"));
    assert!(!rust_update.contains("resolve_latest"));
    assert!(!rust_update.contains("release-manifest.json"));
    assert!(rust_update.contains("installed_package_sha256"));
    assert!(!update.contains("latest/manifest.json"));
}

#[test]
fn regression_inv_047_active_jobs_defer_before_detached_update_handoff() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    assert!(!supervisor.contains("Get-ActiveAgentJobIds"));
    assert!(!supervisor.contains("deferred_active_jobs"));
    assert!(update.contains("__self-update --root $Root --preflight"));
    assert!(rust_update.contains("pub fn preflight_runtime_update"));
    assert!(rust_update.contains("jobs::active_ids(&root.join(\"jobs\"))"));
    let active_jobs = rust_update
        .find("preflight_runtime_update(&request.root)")
        .expect("Rust active-job guard");
    let archive_download = rust_update
        .find("let mut staged_archive = tempfile::tempfile_in(&request.root)?")
        .expect("direct archive download");
    assert!(active_jobs < archive_download);
    assert!(!update.contains("Get-ActiveAgentJobIds"));
}

#[test]
fn regression_inv_053_resident_cli_lock_defers_before_mutation_and_preserves_publish_error() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    assert!(!update.contains("Get-ResidentOpsProcessIds"));
    assert!(!update.contains("Win32_Process -Filter \"Name='onec-ops.exe'\""));
    assert!(update.contains("Copy-Item -Force $currentAgent $tempAgent"));
    assert!(update.contains("'__self-update', '--root', $Root"));
    assert!(rust_update.contains("acquire_exclusive_file_lock"));
    assert!(rust_update.contains("update_extended().map_err(update_error)?"));
    assert!(!update.contains("$backupRoot"));
    assert!(!update.contains("Restore-File"));
}

#[test]
fn fresh_install_shares_root_writer_lock_with_managed_update() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");

    assert!(install.contains(
        "[IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)"
    ));
    assert!(install.contains("Acquire-InstallWriterLock (Join-Path $Root 'update.lock')"));
    assert!(rust_update.contains("request.root.join(\"update.lock\")"));

    let lock = install
        .find("$installWriterLock = Acquire-InstallWriterLock")
        .expect("install writer lock");
    let pinned_download = install
        .find("Download-PinnedDirectFile $DirectPackageUrl $archive $DirectPackageSha256")
        .expect("direct package download");
    let enrollment = install
        .find("Invoke-AgentHubJsonPost $candidateAgentPath")
        .expect("candidate enrollment");
    let release = install
        .find("$installWriterLock.Dispose()")
        .expect("writer lock release");

    assert!(lock < pinned_download);
    assert!(lock < enrollment);
    assert!(enrollment < release);
}

#[test]
fn regression_inv_059_detached_update_quiesces_supervisor_before_agent_publication() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    assert!(update.contains("onec-agent process $PidValue did not stop within 15 seconds."));
    assert!(update.contains("[IO.File]::ReadAllText($pidFile)"));
    assert!(update.contains("-StartDelaySeconds 2 -DetachedHandoff"));
    let maintenance = update
        .find("$maintenanceOwned = New-MaintenanceMarker 'update'")
        .expect("maintenance handoff");
    let wait_supervisor = update
        .find("Wait-SupervisorStopped 30")
        .expect("supervisor shutdown wait");
    let rust_update = update
        .find("$resultText = (& $tempAgent @updateArguments")
        .expect("Rust update handoff");
    assert!(maintenance < wait_supervisor);
    assert!(wait_supervisor < rust_update);
    assert!(!update[..rust_update].contains("Get-ResidentAgentProcessIds"));
}

#[test]
fn regression_inv_206_user_session_update_fails_closed_for_unowned_managed_agent() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1").replace("\r\n", "\n");

    assert!(update.contains(
        "Get-WmiObject -Class Win32_Process -Filter \"Name='onec-agent.exe'\" -ErrorAction Stop"
    ));
    assert!(update.contains("[IO.Path]::GetFullPath([string]$candidate.ExecutablePath)"));
    assert!(update.contains("[StringComparison]::OrdinalIgnoreCase"));
    assert!(
        update.contains(
            "$candidate.ConvertToDateTime($candidate.CreationDate).ToUniversalTime().Ticks"
        )
    );
    assert!(update.contains("$process.StartTime.ToUniversalTime().Ticks"));
    assert!(
        update.contains(
            "WMI returned a onec-agent process without an executable path; refusing update"
        )
    );
    assert!(
        update
            .contains("A managed onec-agent process is still running without its supervisor lock.")
    );
    assert!(update.contains("Close the orphan agent through the owning user session"));
    assert!(update.contains("if ($managedProcesses.Count -eq 0) { return }"));
    assert!(update.contains("if ([int]$mainAgents[0]['pid'] -ne $ownedAgentPid)"));
    assert!(update.contains("if ($mainAgents.Count -eq 0)"));
    assert!(update.contains("if ($mainAgents.Count -ne 1)"));

    let ownership_check = update
        .find("Assert-ManagedAgentOwnership $supervisorWasRunning $AgentPid")
        .expect("managed process ownership preflight");
    let delegated_update = update
        .find("Start-DetachedUpdater $recordedAgentPid")
        .expect("normal supervised detached handoff");
    let temporary_copy = update
        .find("Copy-Item -Force $currentAgent $tempAgent")
        .expect("temporary update copy");
    let runtime_update = update
        .find("rust_update_started target=")
        .expect("runtime publication");
    assert!(ownership_check < delegated_update);
    assert!(ownership_check < temporary_copy);
    assert!(ownership_check < runtime_update);
    assert!(!update.contains("Win32_Process.Terminate"));
    assert!(!update.contains("Stop-Process -Name 'onec-agent'"));
}

#[test]
fn regression_inv_206_supervised_main_agent_and_sshd_helper_are_distinct_roles() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1").replace("\r\n", "\n");
    let smoke =
        include_str!("../tests/managed_update_process_identity_smoke.ps1").replace("\r\n", "\n");

    assert!(update.contains("^run\\s+--config\\s+(?:\"([^\"]+)\"|(\\S+))$"));
    assert!(update.contains("return 'agent-run'"));
    assert!(update.contains("^__sshd-host\\s+--program\\s+"));
    assert!(update.contains("return 'sshd-host'"));
    assert!(update.contains(
        "$mainAgents = @($managedProcesses | Where-Object { $_['role'] -eq 'agent-run' })"
    ));
    assert!(
        update.contains(
            "$helpers = @($managedProcesses | Where-Object { $_['role'] -eq 'sshd-host' })"
        )
    );
    assert!(update.contains("[int]$helper['parent_pid'] -ne [int]$mainAgents[0]['pid']"));
    assert!(update.contains("$mainAgents.Count -ne 1"));
    assert!(!update.contains("$managedProcesses.Count -ne 1"));
    assert!(smoke.contains("Get-ManagedAgentRole $mainCommandLine $exe"));
    assert!(smoke.contains("Get-ManagedAgentRole $helperCommandLine $exe"));
    assert!(smoke.contains("unknown commandline"));
}

#[test]
fn regression_inv_206_wmi_start_time_allows_only_native_nine_tick_delta() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1").replace("\r\n", "\n");
    let smoke =
        include_str!("../tests/managed_update_process_identity_smoke.ps1").replace("\r\n", "\n");

    assert!(update.contains(
        "function Test-ManagedAgentStartIdentity([Int64]$ProcessStartTicks, [Int64]$WmiStartTicks)"
    ));
    assert!(update.contains("([Math]::Abs($ProcessStartTicks - $WmiStartTicks) -le 9)"));
    assert!(!update.contains("$startTicks -ne $wmiStartTicks"));
    assert!(smoke.contains("Test-ManagedAgentStartIdentity 10000 9991"));
    assert!(smoke.contains("Test-ManagedAgentStartIdentity 10000 9994"));
    assert!(smoke.contains("Test-ManagedAgentStartIdentity 10000 9990"));
    // Native WORK samples were 9 ticks apart for PID 16060 and 6 for PID 14464.
    let matches_native_tolerance = |delta: i64| delta <= 9;
    for (pid, observed_delta) in [(16060, 9i64), (14464, 6i64)] {
        assert!(
            matches_native_tolerance(observed_delta),
            "native process {pid} must pass the tolerance"
        );
    }
    assert!(
        !matches_native_tolerance(10),
        "a ten-tick difference must remain rejected"
    );
}

#[test]
fn regression_inv_206_orphan_unknown_role_and_owner_pid_mismatch_fail_closed() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1").replace("\r\n", "\n");

    assert!(update.contains("if (-not $SupervisorRunning)"));
    assert!(
        update
            .contains("A managed onec-agent process is still running without its supervisor lock.")
    );
    assert!(
        update.contains(
            "Managed sshd helper process(es) remain without a verified main agent owner."
        )
    );
    assert!(update.contains("WMI command line has an unknown onec-agent role; refusing update."));
    assert!(update.contains("if ([int]$mainAgents[0]['pid'] -ne $ownedAgentPid)"));
    assert!(update.contains("does not match the running managed agent PID"));
    assert!(update.contains("if ($mainAgents.Count -ne 1)"));
    assert!(!update.contains("Write-UpdateLog $candidate.CommandLine"));
}

#[test]
fn regression_inv_063_detached_update_persists_phase_and_failure_diagnostics() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");

    assert!(update.contains("$updateLog = Join-Path $agentDir 'update-events.log'"));
    assert!(update.contains("function Write-UpdateLog"));
    assert!(update.contains("Detached handoff requires a positive -AgentPid."));
    assert!(update.contains("update_delegated detached_pid="));
    assert!(update.contains("maintenance_requested agent_pid="));
    assert!(update.contains("supervisor_quiesced"));
    assert!(update.contains("rust_update_started target="));
    assert!(update.contains("rust_update_completed result="));
    assert!(update.contains("update_failed error="));
    assert!(
        update.contains(
            "Detached user-session update lost its supervisor before maintenance handoff."
        )
    );
    let maintenance = update
        .find("$maintenanceOwned = New-MaintenanceMarker 'update'")
        .expect("maintenance marker");
    let supervisor_wait = update
        .find("Wait-SupervisorStopped 30")
        .expect("supervisor wait");
    let publication = update
        .find("rust_update_started target=")
        .expect("Rust update phase log");
    assert!(maintenance < supervisor_wait);
    assert!(supervisor_wait < publication);
}

#[test]
fn managed_service_persistence_is_explicit_and_fail_closed_before_enrollment() {
    // Git may materialize this text asset with CRLF on Windows. Keep the static
    // contract independent of the checkout's configured line-ending conversion.
    let install = include_str!("../assets/Install-OnecToolkit.ps1").replace("\r\n", "\n");
    assert!(install.contains("[ValidateSet('user-session', 'windows-service')]"));
    assert!(install.contains("[string]$Persistence = 'user-session'"));
    assert!(install.contains("$payload.Add('persistence_mode', $Persistence)"));
    assert!(install.contains("$metadata.Add('persistence_mode', $Persistence)"));
    assert!(install.contains("*S-1-5-18:F"));
    assert!(install.contains("install-service --config $configPath --start"));
    assert!(install.contains("Wait-AgentServiceReady"));
    assert!(install.contains("Wait-AgentUserSessionReady"));
    assert!(install.contains("'tunnel.started'"));
    assert!(!install.contains("tunnel_started"));
    assert!(install.contains("$serviceExistedInitially"));
    assert!(install.contains("$serviceWasRunning"));
    assert!(install.contains("Remove-AgentAutostart"));
    let publish_rollback = install
        .split("$publishError = $_")
        .nth(1)
        .and_then(|tail| tail.split("throw \"onec-toolkit install failed").next())
        .expect("publish rollback block");
    let rollback_stop = publish_rollback
        .find("Stop-Service -Name 'onec-agent' -Force -ErrorAction Stop")
        .expect("service rollback stop");
    let rollback_restore = publish_rollback
        .find("Restore-File ([string]$file['backup'])")
        .expect("file rollback");
    assert!(
        rollback_stop < rollback_restore,
        "service must be stopped before executable/config rollback"
    );

    let elevation = install
        .find("windows-service persistence requires an elevated PowerShell session")
        .expect("service elevation guard");
    let transport = install.rfind("\nEnable-Tls12\n").expect("transport start");
    let enrollment = install.find("/v1/enroll").expect("enrollment request");
    assert!(
        elevation < transport,
        "elevation must fail before transport setup"
    );
    assert!(
        elevation < enrollment,
        "elevation must fail before token use"
    );
}

#[test]
fn regression_inv_006_user_session_persistence_is_explicitly_logon_scoped() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    assert!(install.contains("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
    assert!(install.contains("[Microsoft.Win32.Registry]::CurrentUser"));
    assert!(install.contains("Autostart: HKCU Run after user logon (current user, no elevation)"));
    assert!(install.contains("[string]$Persistence = 'user-session'"));
    assert!(install.contains("if ($Persistence -eq 'windows-service')"));
}

#[test]
fn managed_updater_preserves_persisted_service_mode_and_active_jobs() {
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");
    assert!(update.contains("$persistenceMode = 'user-session'"));
    assert!(update.contains("$metadata.ContainsKey('persistence_mode')"));
    assert!(rust_update.contains("preflight_runtime_update(&request.root)"));
    assert!(update.contains("& $AgentPath stop-service"));
    assert!(update.contains("& $AgentPath start-service"));
    assert!(!update.contains("Stop-Service -Name 'onec-agent'"));
    assert!(!update.contains("Start-Service -Name 'onec-agent'"));
    assert!(update.contains("$serviceWasRunning"));
    assert!(update.contains("$serviceStoppedForUpdate"));
    assert!(!update.contains("Get-ActiveAgentJobIds"));
}

#[test]
fn windows_service_backend_uses_library_not_manual_scm_ffi() {
    fn append_rust_sources(path: &std::path::Path, output: &mut String) {
        let mut entries = std::fs::read_dir(path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                append_rust_sources(&path, output);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                output.push_str(&std::fs::read_to_string(path).unwrap());
                output.push('\n');
            }
        }
    }

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut service = std::fs::read_to_string(manifest.join("src/service.rs")).unwrap();
    append_rust_sources(&manifest.join("src/service"), &mut service);

    assert!(service.contains("windows_service::service_manager"));
    assert!(service.contains("ServiceFailureActions"));
    for forbidden in [
        "StartServiceCtrlDispatcherW",
        "RegisterServiceCtrlHandlerExW",
        "SetServiceStatus(handle",
        "Command::new(\"sc.exe\")",
    ] {
        assert!(
            !service.contains(forbidden),
            "manual SCM path remained: {forbidden}"
        );
    }
}

#[test]
fn managed_scripts_execute_compat_curl_by_discovered_absolute_path() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");

    assert!(install.contains("$script:CompatCurl = [string]$tools['curl']"));
    assert!(install.contains("$arguments = @('--fail', '--silent', '--show-error'"));
    assert!(install.contains("& $curl $arguments"));
    assert!(install.contains("if (-not $NoRedirect) { $arguments += '--location' }"));
    assert!(!install.contains("& 'curl.exe'"));
    assert!(!install.contains("& curl.exe"));
    assert!(!update.contains("CompatCurl"));
    assert!(!update.contains("curl.exe"));
    assert!(!update.contains("Download-File"));
}

#[test]
fn regression_inv_073_portablegit_legacy_sfx_exit_one_requires_fresh_supported_layout() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("function Resolve-PortableGitLayout([string]$Root)"));
    assert!(
        install.contains("foreach ($candidateRoot in @($Root, (Join-Path $Root 'PortableGit')))")
    );
    assert!(install.contains("$candidateGit = Join-Path $candidateRoot 'cmd\\git.exe'"));
    assert!(install.contains("$candidateCurl = Join-Path $candidateRoot 'mingw64\\bin\\curl.exe'"));
    assert!(install.contains("function Test-PortableGitRuntime([object]$Layout)"));
    assert!(install.contains("$versionText = (& $git --version 2>&1 | Out-String).Trim()"));
    assert!(install.contains("[IO.File]::Exists($candidateSshKeygen) -and [IO.File]::Exists($candidateGit) -and [IO.File]::Exists($candidateCurl)"));

    let existing = install
        .find("$existingLayout = Resolve-PortableGitLayout $root")
        .expect("existing layout preflight");
    let reset = install
        .find("Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root")
        .expect("fresh extraction root reset");
    let launch = install
        .find("$process = Start-Process -FilePath $archive")
        .expect("portable git SFX launch");
    let postcondition = install
        .find("$extractedLayout = Resolve-PortableGitLayout $root")
        .expect("extraction postcondition");
    let missing = install
        .find("if (($null -eq $extractedLayout) -or (-not (Test-PortableGitRuntime $extractedLayout)))")
        .expect("missing postcondition failure");
    let unsupported = install
        .find("if (($process.ExitCode -ne 0) -and ($process.ExitCode -ne 1))")
        .expect("unknown non-zero exit guard");
    let legacy_one = install
        .find("if ($process.ExitCode -eq 1)")
        .expect("known legacy exit one branch");

    assert!(
        existing < reset,
        "complete managed extraction must be reusable"
    );
    assert!(
        reset < launch,
        "incomplete/stale root must be replaced before extraction"
    );
    assert!(
        launch < postcondition,
        "postcondition is evaluated after the SFX returns"
    );
    assert!(postcondition < missing);
    assert!(missing < unsupported);
    assert!(unsupported < legacy_one);
    assert!(install.contains(
        "PortableGit legacy SFX returned exit code 1 after producing the required PortableGit runtime; continuing with the verified extracted layout."
    ));
    assert!(install.contains(
        "PortableGit extraction returned unsupported exit code $($process.ExitCode) even though the required PortableGit runtime is present."
    ));
}

#[test]
fn regression_inv_073_fresh_reenrollment_republishes_missing_managed_files() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    for required in [
        "'onec.exe'",
        "'onec-agent.exe'",
        "'Run-OnecAgent.ps1'",
        "'Update-OnecToolkit.ps1'",
    ] {
        assert!(
            install.contains(required),
            "missing release requirement {required}"
        );
    }
    for publication in [
        "Remove-Item -LiteralPath $retiredController -Force -ErrorAction Stop",
        "Copy-Item -LiteralPath $candidateOnecPath -Destination (Join-Path $binDir 'onec.exe') -Force",
        "Copy-Item -LiteralPath $candidateAgentPath -Destination (Join-Path $binDir 'onec-agent.exe') -Force",
        "Copy-Item -LiteralPath (Join-Path $candidateDir 'Run-OnecAgent.ps1') -Destination (Join-Path $scriptsDir 'Run-OnecAgent.ps1') -Force",
        "Copy-Item -LiteralPath (Join-Path $candidateDir 'Update-OnecToolkit.ps1') -Destination (Join-Path $scriptsDir 'Update-OnecToolkit.ps1') -Force",
    ] {
        assert!(
            install.contains(publication),
            "missing repair publication {publication}"
        );
    }
    assert!(install.contains("if (-not (Test-Path $Source)) { return }"));
    assert!(install.contains("$file['existed'] = Test-Path ([string]$file['path'])"));
    assert!(install.contains("if (Test-Path -LiteralPath $retiredController) { throw 'Retired onec-ops.exe remains after removal.' }"));
    assert!(install.contains("Remove-Item -Force -ErrorAction SilentlyContinue $Destination"));
    assert!(
        install.contains(
            "# Retire the installer-owned split controller binary inside this transaction."
        )
    );
    assert!(install.contains(
        "@{ path = (Join-Path $binDir 'onec-ops.exe'); backup = (Join-Path $backupRoot 'bin\\onec-ops.exe') }"
    ));
    assert!(install.contains(
        "Restore-File ([string]$file['backup']) ([string]$file['path']) ([bool]$file['existed'])"
    ));
}

#[test]
fn managed_installer_treats_onec_controller_as_an_atomic_runtime_binary() {
    // Windows Git may checkout PowerShell assets with CRLF. Inspect the same
    // command structure independently of how the text file was checked out.
    let install = include_str!("../assets/Install-OnecToolkit.ps1").replace("\r\n", "\n");

    let required_start = install
        .find("$requiredNames = @(")
        .expect("installer required-file list");
    let required_end = install[required_start..]
        .find(")\n    foreach ($nameRequired")
        .expect("installer required-file list end")
        + required_start;
    let required = &install[required_start..required_end];
    assert!(required.contains("'onec.exe'"));
    assert!(!required.contains("onec-meta.exe"));
    assert!(!required.contains("onec-project.exe"));
    assert!(install.contains("$candidateOnec = Get-ChildItem -Path $expanded -Filter 'onec.exe' -Recurse | Select-Object -First 1"));
    assert!(
        install.contains(
            "$candidateOnecPath = [IO.Path]::GetFullPath([string]$candidateOnec.FullName)"
        )
    );
    assert!(install.contains("$onecVersionOutput = & $candidateOnecPath --version"));
    assert!(install.contains("& $candidateOnecPath project --help | Out-Null"));
    assert!(install.contains("& $candidateOnecPath meta --help | Out-Null"));
    assert!(install.contains(
        "@{ path = (Join-Path $binDir 'onec.exe'); backup = (Join-Path $backupRoot 'bin\\onec.exe') }"
    ));
    assert!(install.contains(
        "Copy-Item -LiteralPath $candidateOnecPath -Destination (Join-Path $binDir 'onec.exe') -Force"
    ));
    assert!(install.contains("$publishedOnecOutput = & $publishedOnec --version"));
    assert!(install.contains("Published onec.exe failed to start."));
    assert!(!required.contains("onec-ops.exe"));
    assert!(!install.contains("$candidateDir 'onec-ops.exe'"));
    assert!(!install.contains("Published onec-ops.exe"));
    assert!(install.contains("Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $binDir 'onec-meta.exe'), (Join-Path $binDir 'onec-project.exe')"));
}

#[test]
fn regression_inv_144_installer_preflights_expanded_candidate_controller_path() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    let candidate = install
        .find("$candidateOnec = Get-ChildItem -Path $expanded -Filter 'onec.exe'")
        .expect("candidate controller discovery");
    let candidate_path = install[candidate..]
        .find("$candidateOnecPath = [IO.Path]::GetFullPath([string]$candidateOnec.FullName)")
        .map(|offset| candidate + offset)
        .expect("expanded absolute candidate controller path");
    let version_preflight = install[candidate_path..]
        .find("$onecVersionOutput = & $candidateOnecPath --version")
        .map(|offset| candidate_path + offset)
        .expect("candidate version preflight uses expanded path");
    let project_preflight = install[candidate_path..]
        .find("& $candidateOnecPath project --help | Out-Null")
        .map(|offset| candidate_path + offset)
        .expect("candidate project preflight uses expanded path");
    let meta_preflight = install[candidate_path..]
        .find("& $candidateOnecPath meta --help | Out-Null")
        .map(|offset| candidate_path + offset)
        .expect("candidate meta preflight uses expanded path");

    assert!(candidate < candidate_path);
    assert!(candidate_path < version_preflight);
    assert!(version_preflight < project_preflight);
    assert!(project_preflight < meta_preflight);
    assert!(
        !install[candidate..meta_preflight].contains("& $candidateOnec "),
        "candidate FileInfo must never be invoked as a bare executable name"
    );
}

#[test]
fn regression_inv_146_installer_bundle_paths_are_independent_of_caller_working_directory() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    let root_absolute = install
        .find("$Root = [IO.Path]::GetFullPath($Root)")
        .expect("managed install root is resolved once to an absolute path");
    let managed_paths = install
        .find("$binDir = Join-Path $Root 'bin'")
        .expect("managed paths derive from the absolute install root");
    assert!(root_absolute < managed_paths);
    assert!(install.contains(
        "$tempRoot = [IO.Path]::GetFullPath((Join-Path $env:TEMP ('onec-toolkit-install-' + [Guid]::NewGuid().ToString('N'))))"
    ));

    let candidate_absolute = install
        .find("$candidateOnecPath = [IO.Path]::GetFullPath([string]$candidateOnec.FullName)")
        .expect("candidate controller uses its absolute filesystem path");
    let candidate_directory = install
        .find("$candidateDir = [IO.Path]::GetFullPath($candidateOnec.Directory.FullName)")
        .expect("candidate bundle directory is absolute");
    let candidate_agent_absolute = install
        .find("$candidateAgentPath = [IO.Path]::GetFullPath((Join-Path $candidateDir 'onec-agent.exe'))")
        .expect("candidate agent uses its absolute filesystem path");
    let publication = install
        .find("Copy-Item -LiteralPath $candidateOnecPath -Destination (Join-Path $binDir 'onec.exe') -Force")
        .expect("publication copies onec.exe from the absolute candidate path");
    let agent_publication = install
        .find("Copy-Item -LiteralPath $candidateAgentPath -Destination (Join-Path $binDir 'onec-agent.exe') -Force")
        .expect("publication copies onec-agent.exe from the absolute candidate path");
    assert!(candidate_absolute < publication);
    assert!(candidate_directory < publication);
    assert!(candidate_directory < candidate_agent_absolute);
    assert!(candidate_agent_absolute < agent_publication);
    assert!(publication < agent_publication);
    assert!(
        !install.contains("Copy-Item -Force $candidateOnec "),
        "passing FileInfo to Copy-Item can resolve its bare filename from the caller CWD"
    );
    assert!(
        !install.contains("Copy-Item -Force $candidateAgent "),
        "candidate onec-agent.exe publication must not resolve through the caller CWD"
    );

    for line in install.lines().filter(|line| {
        line.contains("Copy-Item")
            && (line.contains("$candidateAgent") || line.contains("$candidateDir"))
    }) {
        assert!(
            line.contains("-LiteralPath"),
            "candidate bundle files must be copied through explicit paths: {line}"
        );
    }
}

#[test]
fn regression_inv_149_installer_publication_uses_absolute_candidate_paths_from_foreign_cwd() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    // Model the field layout: the caller starts outside both the install root and the expanded
    // candidate directory. Publication must use paths captured from the extracted bundle.
    let caller_cwd = r"C:\Users\ExampleUser";
    let install_root = r"C:\Program Files\ExampleToolkit";
    let candidate_root = r"C:\Users\ExampleUser\AppData\Local\Temp\expanded";
    assert_ne!(caller_cwd, install_root);
    assert_ne!(caller_cwd, candidate_root);
    assert_ne!(install_root, candidate_root);

    for source_path in ["$candidateOnecPath", "$candidateAgentPath"] {
        assert!(
            install.contains(&format!(
                "Copy-Item -LiteralPath {source_path} -Destination"
            )),
            "publication must use a literal captured absolute source path: {source_path}"
        );
    }
    assert!(
        install.contains(
            "$candidateOnecPath = [IO.Path]::GetFullPath([string]$candidateOnec.FullName)"
        )
    );
    assert!(install.contains(
        "$candidateAgentPath = [IO.Path]::GetFullPath((Join-Path $candidateDir 'onec-agent.exe'))"
    ));
    assert!(!install.contains("Copy-Item -Force $candidateOnec "));
    assert!(!install.contains("Copy-Item -Force $candidateAgent "));
}

#[test]
fn regression_inv_073_recovery_stops_only_exact_managed_agent_and_waits_for_release() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("function Stop-ManagedAgentProcesses([string]$ManagedAgentPath)"));
    assert!(
        install.contains(r#"Get-WmiObject -Class Win32_Process -Filter "Name='onec-agent.exe'""#)
    );
    assert!(
        install.contains("$candidatePath.Equals($expected, [StringComparison]::OrdinalIgnoreCase)")
    );
    assert!(
        install.contains("Stop-Process -Id ([int]$candidate.ProcessId) -Force -ErrorAction Stop")
    );
    assert!(
        install.contains("function Wait-ManagedAgentBinaryReleased([string]$ManagedAgentPath)")
    );
    assert!(install.contains("[IO.FileShare]::None"));
    let stop_supervisor = install
        .find("Stop-ExistingUserAgent $agentDir")
        .expect("supervisor quiescence");
    let managed_path = install
        .find("$managedAgentPath = Join-Path $binDir 'onec-agent.exe'")
        .expect("managed agent path");
    let stop_exact = install
        .find("Stop-ManagedAgentProcesses $managedAgentPath")
        .expect("exact managed agent stop");
    let wait_release = install
        .find("Wait-ManagedAgentBinaryReleased $managedAgentPath")
        .expect("managed agent release proof");
    let backup = install
        .find("$backupRoot = Join-Path $tempRoot 'backup'")
        .expect("managed-file backup");
    assert!(stop_supervisor < managed_path);
    assert!(managed_path < stop_exact);
    assert!(stop_exact < wait_release);
    assert!(wait_release < backup);
    assert!(!install.contains("($process.ProcessName -eq 'onec-agent')"));
}

#[test]
fn regression_inv_073_optional_target_sshd_failure_falls_back_to_gateway_control() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let begin = install
        .find("$userSshServer = $null")
        .expect("optional target ssh boundary");
    let install_server = install[begin..]
        .find("$userSshServer = Install-UserSshServer")
        .map(|offset| begin + offset)
        .expect("target ssh install");
    let host_key = install[begin..]
        .find("$sshHostPublicKey = Ensure-UserSshHostKey")
        .map(|offset| begin + offset)
        .expect("target ssh host key");
    let preflight = install[begin..]
        .find("$targetSshReady = Test-UserSshServerPublicKey")
        .map(|offset| begin + offset)
        .expect("target ssh preflight");
    let fallback = install[begin..]
        .find("Target-side portable OpenSSH is unavailable; using the direct onec-agent compatibility carrier instead.")
        .map(|offset| begin + offset)
        .expect("gateway-control fallback");
    assert!(install_server < host_key && host_key < preflight && preflight < fallback);
    assert!(install.contains("$userSshServer = $null"));
    assert!(install.contains("$sshHostPublicKey = $null"));
}

#[test]
fn regression_inv_009_direct_invite_uses_verified_candidate_agent_for_enrollment() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");

    assert!(!install.contains("ReleaseId"));
    assert!(!install.contains("ReleaseManifestSha256"));
    assert!(!install.contains("ReleaseVersion"));
    assert!(
        install
            .contains("Download-PinnedDirectFile $DirectPackageUrl $archive $DirectPackageSha256")
    );
    assert!(install.contains(
        "Expand-DirectPackageZip $archive $expanded $DirectPackageTarget $DirectPackageSha256"
    ));
    assert!(install.contains("$metadata.Add('installed_runtime_files', $installedRuntimeFiles)"));
    assert!(install.contains("Invoke-AgentHubJsonPost $candidateAgentPath"));
    assert!(install.contains("Protect-SecretDirectory $requestRoot"));
    assert!(install.contains("Protect-SecretFile $tokenPath"));
    assert!(install.contains("& $Agent '__enroll-http' '--url' $Uri"));
    let private_request_root = install
        .find("Protect-SecretDirectory $requestRoot")
        .expect("private enrollment request directory");
    let token_write = install
        .find("Write-Utf8NoBom $tokenPath")
        .expect("enrollment token write");
    assert!(private_request_root < token_write);
    assert!(!install.contains("__bootstrap-transport"));
    assert!(!install.contains("$script:RustTransport"));
    assert!(!install.contains("Invoke-RustDownload"));

    let pinned_archive = install
        .find("Download-PinnedDirectFile $DirectPackageUrl $archive $DirectPackageSha256")
        .expect("pinned archive download");
    let candidate_agent = install
        .find("$candidateAgentPath = [IO.Path]::GetFullPath((Join-Path $candidateDir 'onec-agent.exe'))")
        .expect("verified candidate agent");
    let enrollment = install.find("/v1/enroll").expect("enrollment route");
    assert!(pinned_archive < candidate_agent);
    assert!(candidate_agent < enrollment);

    assert!(!install.contains("$LASTEXITCODE:"));
    assert!(install.contains("${LASTEXITCODE}: $Uri"));
    assert!(!update.contains("Invoke-WebClientDownload"));
    assert!(!update.contains("PortableGit"));
    assert!(update.contains("'__self-update', '--root', $Root"));
}

#[test]
fn regression_inv_009_legacy_json_payloads_avoid_powershell_hashtables() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(
        install.contains("$payload = New-Object System.Collections.Specialized.OrderedDictionary")
    );
    assert!(
        install.contains("$metadata = New-Object System.Collections.Specialized.OrderedDictionary")
    );
    assert!(!install.contains("$payload = @{"));
    assert!(!install.contains("$metadata = @{"));
    assert!(install.contains("$payload.Add('machine_id', $machineId)"));
    assert!(install.contains("$metadata.Add('installed_version', $version)"));
}

#[test]
fn regression_inv_113_legacy_windows_disables_target_ssh_before_enrollment() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("function Test-ManagedTargetSshNestedJobSupport"));
    assert!(install.contains(
        "return (($version.Major -gt 6) -or (($version.Major -eq 6) -and ($version.Minor -ge 2)))"
    ));
    assert!(install.contains(
        "Target-side portable OpenSSH is disabled on Windows versions before NT 6.2 because managed sshd and Win32-OpenSSH require nested Job Objects"
    ));

    let support_gate = install
        .find("elseif (Test-ManagedTargetSshNestedJobSupport)")
        .expect("legacy target SSH support gate");
    let install_server = install
        .find("$userSshServer = Install-UserSshServer")
        .expect("target SSH installation");
    let host_key = install
        .find("$sshHostPublicKey = Ensure-UserSshHostKey")
        .expect("target SSH host-key creation");
    let enrollment = install.find("/v1/enroll").expect("enrollment route");
    assert!(
        support_gate < install_server && support_gate < host_key && support_gate < enrollment,
        "legacy Job support must be decided before target SSH is installed or advertised"
    );

    assert!(install.contains("$payload.Add('ssh_host_public_key', $sshHostPublicKey)"));
    assert!(install.contains(
        "if ($null -ne $sshServerSettings) { $agentConfig.Add('ssh_server', $sshServerSettings) }"
    ));
}

#[test]
fn embedded_russh_candidate_preflight_is_explicit_and_fail_closed() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("[switch]$EmbeddedSshCandidate"));
    assert!(install.contains("function Test-EmbeddedSshServerCandidate("));
    assert!(install.contains(
        "& $Agent '__embedded-ssh-preflight' '--config' $configPath '--host-public-key' $HostPublicKeyPath '--identity' ([string]$SshConfig['identity']) '--scratch-dir' $testRoot"
    ));
    assert!(install.contains(
        "$embeddedHostPublicKey = Ensure-UserSshHostKey ([string]$managedTools['ssh_keygen'])"
    ));
    assert!(install.contains("$targetSshPort = 27322"));
    assert!(install.contains(
        "$embeddedSshServerReady = Test-EmbeddedSshServerCandidate $candidateAgentPath $sshConfig $sshHostKeyPath ($sshHostKeyPath + '.pub') $targetSshPort"
    ));
    assert!(install.contains("$embeddedSshServerSettings.Add('port', $targetSshPort)"));
    assert!(install.contains(
        "throw 'embedded russh candidate preflight failed; refusing to advertise target SSH'"
    ));
    assert!(install.contains(
        "throw \"embedded SSH candidate self-preflight failed with exit code $LASTEXITCODE\""
    ));
    assert!(install.contains(
        "if ($null -ne $embeddedSshServerSettings) { $agentConfig.Add('embedded_ssh_server', $embeddedSshServerSettings) }"
    ));

    let candidate_function_begin = install
        .find("function Test-EmbeddedSshServerCandidate(")
        .expect("embedded candidate preflight function");
    let candidate_function_end = install[candidate_function_begin..]
        .find("function Get-CurrentWindowsPrincipal")
        .map(|offset| candidate_function_begin + offset)
        .expect("function following embedded candidate preflight");
    let candidate_function = &install[candidate_function_begin..candidate_function_end];
    assert!(
        !candidate_function.contains("Get-FreeLoopbackPort"),
        "embedded candidate must preflight the exact final target SSH port"
    );
    assert!(candidate_function.contains("$embeddedSettings.Add('port', $Port)"));

    let candidate_begin = install
        .find("if ($EmbeddedSshCandidate)")
        .expect("embedded candidate branch");
    let legacy_begin = install[candidate_begin..]
        .find("elseif (Test-ManagedTargetSshNestedJobSupport)")
        .map(|offset| candidate_begin + offset)
        .expect("legacy external sshd branch");
    let candidate = &install[candidate_begin..legacy_begin];
    assert!(
        !candidate.contains("Install-UserSshServer"),
        "embedded candidate must not provision target Win32-OpenSSH"
    );
    assert!(
        !candidate.contains("using the direct onec-agent compatibility carrier instead"),
        "explicit embedded candidate failure must not silently fall back"
    );

    let self_test = install
        .find("$embeddedSshServerReady = Test-EmbeddedSshServerCandidate")
        .expect("candidate self-test");
    let advertisement = install
        .find("$payload.Add('ssh_host_public_key', $sshHostPublicKey)")
        .expect("target host-key advertisement");
    assert!(
        self_test < advertisement,
        "candidate transport must be proven before TargetSsh is advertised"
    );
}

#[test]
fn regression_inv_010_target_ssh_preflight_falls_back_to_gateway_control() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("function Test-UserSshServerPublicKey("));
    assert!(install.contains("icacls.exe $Path /setowner $owner /C"));
    assert!(install.contains("$targetSshReady = Test-UserSshServerPublicKey"));
    assert!(install.contains("$userSshServer = $null"));
    assert!(install.contains("$sshHostPublicKey = $null"));
    assert!(install.contains("$payload.Add('ssh_host_public_key', $sshHostPublicKey)"));
    assert!(install.contains(
        "if ($null -ne $sshServerSettings) { $agentConfig.Add('ssh_server', $sshServerSettings) }"
    ));
    assert!(install.contains(
        "Target-side portable OpenSSH is unavailable; using the direct onec-agent compatibility carrier instead."
    ));

    let preflight = install
        .find("$targetSshReady = Test-UserSshServerPublicKey")
        .expect("target SSH preflight");
    let enrollment = install.find("/v1/enroll").expect("enrollment route");
    assert!(
        preflight < enrollment,
        "target SSH must be proven before advertising ssh_host_public_key to the hub"
    );
}

#[test]
fn regression_inv_010_enrollment_uses_canonical_windows_principal() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    assert!(install.contains("[Security.Principal.WindowsIdentity]::GetCurrent().Name"));
    assert!(install.contains("$windowsPrincipal = Get-CurrentWindowsPrincipal"));
    assert!(install.contains("$payload.Add('username', $windowsPrincipal)"));
    assert!(install.contains("Write-UserSshdConfig $sshdConfigPath $sshHostKeyPath $sshAuthorizedKeysPath ([string]$userSshServer['sftp_server']) $windowsPrincipal"));
    assert!(!install.contains("$payload.Add('username', $env:USERNAME)"));
}

#[test]
fn regression_inv_076_enrollment_uses_windows_api_hostname_fallback() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("function Get-CanonicalComputerName"));
    assert!(install.contains("[Environment]::MachineName"));
    assert!(install.contains("$computerName = Get-CanonicalComputerName"));
    assert!(install.contains("$payload.Add('hostname', $computerName)"));
    assert!(!install.contains("$payload.Add('hostname', $env:COMPUTERNAME)"));
}

#[test]
fn regression_inv_114_managed_target_scripts_avoid_dotnet4_whitespace_api() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    assert!(install.contains("[string]::IsNullOrEmpty($name) -or $name.Trim().Length -eq 0"));
}

#[test]
fn regression_inv_060_installer_authorizes_all_controller_operator_keys() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(install.contains("$enroll.ContainsKey('operator_ssh_public_keys')"));
    assert!(install.contains("foreach ($candidate in @($enroll['operator_ssh_public_keys']))"));
    assert!(install.contains("duplicate operator_ssh_public_keys entries"));
    assert!(install.contains("if ($operatorPublicKeys.Count -eq 0)"));
    assert!(install.contains("$enroll['operator_ssh_public_key']"));
    assert!(install.contains("$operatorAuthorizedKeys = (($operatorPublicKeys | ForEach-Object"));
    assert!(install.contains("Write-Utf8NoBom $sshAuthorizedKeysPath $operatorAuthorizedKeys"));
}

#[test]
fn regression_inv_005_installer_and_updater_avoid_sha_dispose_for_legacy_dotnet() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    assert!(install.contains("finally { $stream.Close() }"), "{install}");
    assert!(!install.contains("$sha.Dispose()"), "{install}");
    assert!(!update.contains("SHA256"));
    assert!(!update.contains("Get-Sha256"));
}

#[test]
fn regression_inv_002_installer_and_updater_keep_tls12_probe_best_effort() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    assert!(
        install
            .contains("SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072")
    );
    assert!(!install.contains("SecurityProtocol = 3072"));
    assert!(!update.contains("SecurityProtocol"));
}

fn runtime() -> AgentRuntime {
    let jobs_dir = env::temp_dir().join(format!("onec-agent-test-jobs-{}", std::process::id()));
    AgentRuntime {
        name: "fixture".into(),
        secret: "0123456789abcdef".into(), // gitleaks:allow -- fixed test-only credential fixture
        jobs_dir,
        native_suite_policy_sha256: None,
    }
}

fn request(port: u16, request: AgentRequestKind) -> AgentResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect agent");
    write_json_line(&mut stream, &AgentRequest::new("0123456789abcdef", request))
        .expect("write request");
    read_json_line(BufReader::new(stream)).expect("response")
}

fn test_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let runtime = runtime();
    thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            handle_connection(stream.expect("connection"), &runtime).expect("handle");
        }
    });
    port
}

#[test]
fn malformed_exec_result_declaration_returns_typed_failure_and_invalid_json_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let mut client = TcpStream::connect(address).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    let runtime = runtime();
    let malformed_result = serde_json::json!({
        "version": 1,
        "token": runtime.secret.expose_secret(),
        "request": {
            "type": "exec",
            "program": "unused",
            "results": [
                {"name": "report.bin", "max_bytes": 1},
                {"name": "REPORT.BIN", "max_bytes": 1}
            ]
        }
    });
    client
        .write_all(malformed_result.to_string().as_bytes())
        .expect("write valid JSON with invalid Exec result declaration");
    client.write_all(b"\n").expect("terminate request line");

    handle_connection(server, &runtime).expect("invalid result declaration gets a response");
    let response: AgentResponse = read_json_line(BufReader::new(client)).expect("typed response");
    assert!(!response.ok);
    assert_eq!(response.error_code, Some(AgentErrorCode::ExecResultInvalid));
    assert!(
        response
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("duplicated case-insensitively") })
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("invalid-json listener");
    let address = listener.local_addr().expect("invalid-json address");
    let mut client = TcpStream::connect(address).expect("invalid-json connect");
    let (server, _) = listener.accept().expect("invalid-json accept");
    client
        .write_all(b"{\"version\":1,\"token\":\n")
        .expect("write malformed JSON");
    let error =
        handle_connection(server, &runtime).expect_err("malformed JSON remains a protocol error");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let mut response_bytes = Vec::new();
    client
        .read_to_end(&mut response_bytes)
        .expect("observe close");
    assert!(
        response_bytes.is_empty(),
        "malformed JSON must not get an application response"
    );
}

#[tokio::test]
async fn handle_connection_exec_from_tokio_task_uses_shared_runtime() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let mut client =
        TcpStream::connect(listener.local_addr().expect("listener address")).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    #[cfg(unix)]
    let (program, args) = ("printf", vec!["%s".into(), "tokio-dispatch".into()]);
    #[cfg(windows)]
    let (program, args) = (
        "powershell.exe",
        vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-Command".into(),
            "[Console]::Out.Write('tokio-dispatch')".into(),
        ],
    );
    write_json_line(
        &mut client,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::Exec {
                program: program.into(),
                args,
                cwd: None,
                env: Default::default(),
                secret_env: Default::default(),
                stdin: None,
                result_set_id: None,
                results: Vec::new(),
                timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
                raw_output: false,
            },
        ),
    )
    .expect("write Exec request");

    handle_connection(server, &runtime()).expect("handle Exec inside Tokio task");

    let response: AgentResponse =
        read_json_line(BufReader::new(client)).expect("read Exec response");
    assert!(response.ok, "Exec failed: {response:?}");
    assert!(matches!(
        response.response,
        Some(AgentResponseKind::Exec { ref stdout, .. }) if stdout.trim() == "tokio-dispatch"
    ));
}

#[test]
fn config_rejects_non_loopback_control_listener() {
    let error = serde_json::from_value::<AgentConfig>(serde_json::json!({
        "version": 1,
        "name": "fixture",
        "listen": "0.0.0.0:27391"
    }))
    .expect_err("untrusted JSON must fail at deserialization");
    assert!(error.to_string().contains("loopback-only"), "{error}");
}

#[test]
fn tunnel_config_accepts_legacy_client_fields_as_ignored_residue() {
    let config: SshTunnelConfig = serde_json::from_str(
        r#"{"program":"ssh.exe","gateway_host":"gateway.example","gateway_user":"agent","remote_port":41001,"identity":"agent.key","known_hosts":"known_hosts","mode":"open_ssh"}"#,
    )
    .expect("legacy OpenSSH fields remain readable");
    config.validate(27391).expect("russh tunnel contract");
    assert_eq!(config.program, Some(PathBuf::from("ssh.exe")));
    let serialized = serde_json::to_string(&config).expect("serialize migrated tunnel config");
    assert!(serialized.contains("\"gateways\""));
    assert!(!serialized.contains("gateway_host"));
    assert!(!serialized.contains("gateway_user"));
    assert!(!serialized.contains("gateway_port"));
    assert!(
        !serialized.contains("\"program\""),
        "legacy ssh.program must not be serialized by new configurations"
    );

    let plink: SshTunnelConfig = serde_json::from_str(
        r#"{"program":"plink.exe","gateway_host":"gateway.example","gateway_user":"agent","remote_port":41001,"identity":"agent.ppk","known_hosts":"known_hosts","mode":"plink","host_key":"SHA256:legacy"}"#,
    )
    .expect("retired external-client fields remain readable as inert residue");
    plink
        .validate(27391)
        .expect("legacy program/mode data must not control the russh transport");
    assert_eq!(plink.program, Some(PathBuf::from("plink.exe")));
    let serialized = serde_json::to_string(&plink).expect("serialize migrated legacy config");
    assert!(!serialized.contains("\"program\""));
    assert!(!serialized.contains("\"mode\""));
    assert!(!serialized.contains("\"host_key\""));
}

#[test]
fn regression_inv_021_reverse_tunnel_no_longer_requires_external_ssh_program() {
    let mut config = SshTunnelConfig {
        program: None,
        gateways: vec![SshGatewayEndpoint {
            host: "gateway.example".into(),
            user: "agent".into(),
            port: 22,
            tls_proxy: None,
        }],
        remote_port: 41001,
        identity: Some(PathBuf::from("agent.key")),
        known_hosts: Some(PathBuf::from("known_hosts")),
        reconnect_seconds: 5,
    };
    config
        .validate(27391)
        .expect("in-process russh needs no ssh.program");

    config.identity = None;
    assert_eq!(
        config
            .validate(27391)
            .expect_err("identity remains mandatory")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    config.identity = Some(PathBuf::from("agent.key"));
    config.known_hosts = None;
    assert_eq!(
        config
            .validate(27391)
            .expect_err("known_hosts remains mandatory")
            .kind(),
        io::ErrorKind::PermissionDenied
    );

    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    assert!(
        !install.contains("$sshSettings.Add('program'"),
        "fresh enrollment must not persist the retired external SSH client path"
    );
}

#[test]
fn installer_prefers_gateway_array_and_keeps_legacy_powershell_surface() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    assert!(install.contains("$enroll['gateways']"));
    assert!(install.contains("$sshSettings.Add('gateways', $agentGateways.ToArray())"));
    assert!(
        install.contains("$enroll['gateway_host']"),
        "old hubs remain supported"
    );
    assert!(install.contains("$gatewayKnownHosts.Append"));
    assert!(!install.contains("$sshSettings.Add('gateway_host'"));
    assert!(!install.contains("$sshSettings.Add('gateway_user'"));
    assert!(!install.contains("$sshSettings.Add('gateway_port'"));
    assert!(!install.contains("$sshSettings.Add('tls_proxy'"));
    assert!(install.is_ascii());
    assert!(legacy_powershell_violations(install).is_empty());
}

#[test]
fn user_sshd_config_requires_loopback_and_key_only_authentication() {
    let valid = "Port 27322\nListenAddress 127.0.0.1\nPubkeyAuthentication yes\nPasswordAuthentication no\n";
    validate_user_sshd_config(valid, 27322).expect("valid user sshd config");

    let public =
        "Port 27322\nListenAddress 0.0.0.0\nPubkeyAuthentication yes\nPasswordAuthentication no\n";
    assert_eq!(
        validate_user_sshd_config(public, 27322)
            .expect_err("public bind must be rejected")
            .kind(),
        io::ErrorKind::PermissionDenied
    );

    let password = "Port 27322\nListenAddress 127.0.0.1\nPubkeyAuthentication yes\nPasswordAuthentication yes\n";
    assert_eq!(
        validate_user_sshd_config(password, 27322)
            .expect_err("password authentication must be rejected")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn reverse_tunnel_can_use_explicit_tls_proxy_stream() {
    let mut config = SshTunnelConfig {
        program: None,
        gateways: vec![SshGatewayEndpoint {
            host: "gateway.example".into(),
            user: "agent".into(),
            port: 443,
            tls_proxy: Some(SshTlsProxyConfig {
                program: PathBuf::from("openssl.exe"),
                server_name: "mcp.example".into(),
                alpn: Some("http/1.1".into()),
            }),
        }],
        remote_port: 41001,
        identity: Some(PathBuf::from("agent.key")),
        known_hosts: Some(PathBuf::from("known_hosts")),
        reconnect_seconds: 5,
    };
    config.validate(27391).expect("valid TLS proxy config");

    config.gateways[0]
        .tls_proxy
        .as_mut()
        .expect("proxy")
        .server_name = "unsafe server".into();
    assert_eq!(
        config
            .validate(27391)
            .expect_err("unsafe SNI must fail")
            .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn run_rejects_occupied_control_port_before_spawning_tunnel() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind occupied port");
    let address = occupied.local_addr().expect("occupied address");
    let directory = env::temp_dir().join(format!(
        "onec-agent-bind-first-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).expect("test directory");
    let secret = directory.join("secret.txt");
    fs::write(&secret, "0123456789abcdef\n").expect("secret file"); // gitleaks:allow -- fixed test-only credential fixture
    let config: AgentConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "name": "fixture",
        "listen": address.to_string(),
        "secret_file": secret,
        "ssh": {
            "gateway_host": "gateway.example",
            "gateway_user": "agent",
            "remote_port": 41001,
            "identity": "agent.key",
            "known_hosts": "known_hosts"
        }
    }))
    .expect("static SSH config is checked");

    let error = run_with_tunnel(&config).expect_err("occupied port must fail before SSH spawn");
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    drop(occupied);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn hello_and_exec_round_trip() {
    let port = test_server();
    let hello = request(port, AgentRequestKind::Hello);
    assert!(hello.ok);
    let Some(AgentResponseKind::Hello {
        name, capabilities, ..
    }) = hello.response
    else {
        panic!("unexpected hello response");
    };
    assert_eq!(name, "fixture");
    for required in [
        "exec.env-v1",
        "exec.secret-env-v1",
        "exec.bounded-v1",
        "exec.stdin-v1",
        "exec.results-v1",
        "jobs.env-v1",
        "jobs.secret-env-v1",
        "jobs.stdin-v1",
        "jobs.results-v1",
        "results-v1",
        "filesystem.scoped-remove-v1",
    ] {
        assert!(
            capabilities.iter().any(|value| value == required),
            "missing {required}"
        );
    }

    #[cfg(unix)]
    let exec = request(
        port,
        AgentRequestKind::Exec {
            program: "sh".into(),
            args: vec!["-c".into(), "printf remote-agent".into()],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    #[cfg(unix)]
    assert!(matches!(
        exec.response,
        Some(AgentResponseKind::Exec { ref stdout, .. }) if stdout == "remote-agent"
    ));
}

#[cfg(unix)]
#[test]
fn exec_result_artifact_round_trips_through_typed_download_and_cleanup() {
    use hostlink_protocol::{ResultArtifactSpec, ResultOwner};

    let port = test_server();
    let result_set_id = format!(
        "result-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let response = request(
        port,
        AgentRequestKind::Exec {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                "printf 'managed-result' > \"$ONEC_RESULT_DIR/report.json\"; printf small-stdout"
                    .into(),
            ],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: Some(result_set_id.clone()),
            results: vec![
                ResultArtifactSpec::try_new(
                    "report.json".into(),
                    1024,
                    Some("application/json".into()),
                )
                .expect("valid result declaration"),
            ],
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    let Some(AgentResponseKind::Exec {
        exit_code,
        stdout,
        result_set: Some(result_set),
        ..
    }) = response.response
    else {
        panic!("unexpected result Exec response: {response:?}");
    };
    assert_eq!(exit_code, Some(0));
    assert_eq!(stdout, "small-stdout");
    assert_eq!(result_set.owner().exec_id(), Some(result_set_id.as_str()));
    assert_eq!(result_set.artifacts().len(), 1);
    assert_eq!(result_set.artifacts()[0].bytes(), 14);

    let owner = ResultOwner::exec(result_set_id).expect("valid result owner");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect result download");
    write_json_line(
        &mut stream,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::ResultDownload {
                owner: owner.clone(),
                name: "report.json".into(),
            },
        ),
    )
    .expect("write result download");
    let mut reader = BufReader::new(stream);
    let header: AgentResponse = read_json_line(&mut reader).expect("result download header");
    let Some(AgentResponseKind::ResultDownloadReady { artifact }) = header.response else {
        panic!("unexpected result download header: {header:?}");
    };
    let mut bytes = vec![0_u8; usize::try_from(artifact.bytes()).expect("bounded result length")];
    reader.read_exact(&mut bytes).expect("result bytes");
    assert_eq!(bytes, b"managed-result");
    assert_eq!(artifact, result_set.artifacts()[0]);

    let cleanup = request(
        port,
        AgentRequestKind::ResultCleanup {
            owner: owner.clone(),
        },
    );
    assert!(matches!(
        cleanup.response,
        Some(AgentResponseKind::ResultCleaned { removed: true })
    ));
    let missing = request(
        port,
        AgentRequestKind::ResultDownload {
            owner,
            name: "report.json".into(),
        },
    );
    assert!(!missing.ok);
}

#[cfg(unix)]
#[test]
fn exec_delivers_exact_multiline_stdin_and_closes_the_pipe() {
    let port = test_server();
    let payload = b"first line\nsecond line\n".to_vec();
    let response = request(
        port,
        AgentRequestKind::Exec {
            program: "cat".into(),
            args: Vec::new(),
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: Some(
                hostlink_protocol::StdinPayload::try_new(payload.clone()).expect("bounded stdin"),
            ),
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    let Some(AgentResponseKind::Exec {
        exit_code,
        stdout,
        stderr,
        ..
    }) = response.response
    else {
        panic!("unexpected stdin exec response: {response:?}");
    };
    assert_eq!(exit_code, Some(0));
    assert_eq!(stdout.as_bytes(), payload);
    assert!(stderr.is_empty(), "{stderr}");
}

#[cfg(windows)]
#[test]
fn regression_inv_217_windows_exec_delivers_exact_stdin_to_sort() {
    let payload = b"A\r\nZ\r\n".to_vec();
    let response = request(
        test_server(),
        AgentRequestKind::Exec {
            program: "sort.exe".into(),
            args: Vec::new(),
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: Some(
                hostlink_protocol::StdinPayload::try_new(payload.clone()).expect("bounded stdin"),
            ),
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 15_000,
            raw_output: false,
        },
    );
    let Some(AgentResponseKind::Exec {
        exit_code,
        stdout,
        stderr,
        ..
    }) = response.response
    else {
        panic!("unexpected sort stdin response: {response:?}");
    };

    assert_eq!(exit_code, Some(0));
    assert_eq!(stdout.as_bytes(), payload);
    assert!(stderr.is_empty(), "{stderr}");
}

#[cfg(windows)]
#[test]
fn regression_inv_217_powershell_encoded_command_requires_completion_marker() {
    use base64::Engine as _;

    fn is_first_use_progress_record(stderr: &str) -> bool {
        stderr.replace("\r\n", "\n").trim_end() == FIRST_USE_PROGRESS
    }

    const FIRST_USE_PROGRESS: &str = "#< CLIXML\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN><MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC><T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj></Objs>";
    assert!(is_first_use_progress_record(FIRST_USE_PROGRESS));
    assert!(!is_first_use_progress_record(&FIRST_USE_PROGRESS.replace(
        "Preparing modules for first use.",
        "Unexpected PowerShell error.",
    )));

    let script = "$ErrorActionPreference = 'Stop'\nWrite-Output 'ONEC_PS_ENCODED_BEGIN'\nif ((1 + 1) -ne 2) { throw 'Benign condition failed' }\nWrite-Output 'ONEC_PS_ENCODED_COMPLETE'\n";
    let utf16le = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert!(utf16le.len() <= 4096, "test script exceeded PS2 argv bound");
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16le);
    let response = request(
        test_server(),
        AgentRequestKind::Exec {
            program: "powershell.exe".into(),
            args: vec![
                "-NoLogo".into(),
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-EncodedCommand".into(),
                encoded,
            ],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 15_000,
            raw_output: false,
        },
    );
    let Some(AgentResponseKind::Exec {
        exit_code,
        stdout,
        stderr,
        ..
    }) = response.response
    else {
        panic!("unexpected PowerShell stdin response: {response:?}");
    };

    assert_eq!(exit_code, Some(0), "stderr: {stderr}");
    assert_eq!(
        stdout.as_bytes(),
        b"ONEC_PS_ENCODED_BEGIN\r\nONEC_PS_ENCODED_COMPLETE\r\n"
    );
    assert!(
        stderr.is_empty() || is_first_use_progress_record(&stderr),
        "unexpected PowerShell stderr: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn exec_timeout_remains_authoritative_when_stdin_writer_is_blocked() {
    let port = test_server();
    let payload = hostlink_protocol::StdinPayload::try_new(vec![
        b'x';
        hostlink_protocol::MAX_STDIN_PAYLOAD_BYTES
    ])
    .expect("max bounded stdin");
    let started = Instant::now();
    let response = request(
        port,
        AgentRequestKind::Exec {
            program: "sh".into(),
            args: vec!["-c".into(), "sleep 30".into()],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: Some(payload),
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 150,
            raw_output: false,
        },
    );
    assert_eq!(response.error_code, Some(AgentErrorCode::ExecTimeout));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "blocked stdin writer delayed timeout: {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
#[test]
fn exec_controller_disconnect_cancels_the_owned_process_tree() {
    use std::collections::BTreeMap;
    use std::sync::mpsc;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("listener address");
    let runtime = runtime();
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let result = handle_connection(listener.accept().expect("accept").0, &runtime);
        let _ = done_tx.send(result);
    });

    let marker_root = tempfile::tempdir().expect("marker root");
    let marker = marker_root.path().join("started");
    let mut environment = BTreeMap::new();
    environment.insert(
        "ONEC_EXEC_DISCONNECT_MARKER".to_owned(),
        marker.to_string_lossy().into_owned(),
    );
    let mut client = TcpStream::connect(address).expect("connect");
    write_json_line(
        &mut client,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::Exec {
                program: "sh".into(),
                args: vec![
                    "-c".into(),
                    r#"printf started > "$ONEC_EXEC_DISCONNECT_MARKER"; sleep 30"#.into(),
                ],
                cwd: None,
                env: environment,
                secret_env: Default::default(),
                stdin: None,
                result_set_id: None,
                results: Vec::new(),
                timeout_ms: hostlink_protocol::MAX_EXEC_TIMEOUT_MS,
                raw_output: false,
            },
        ),
    )
    .expect("write Exec request");

    let marker_deadline = Instant::now() + Duration::from_secs(3);
    while !marker.is_file() && Instant::now() < marker_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(marker.is_file(), "remote fixture process never started");

    let disconnected_at = Instant::now();
    drop(client);
    let _handler_result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("controller disconnect must cancel and reap the owned process tree");
    assert!(
        disconnected_at.elapsed() < Duration::from_secs(5),
        "disconnect teardown took too long: {:?}",
        disconnected_at.elapsed()
    );
}

#[test]
fn regression_inv_069_exec_secret_environment_is_redacted() {
    use std::collections::BTreeMap;

    let port = test_server();
    let sentinel = format!(
        "INV069_EXEC_SECRET_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let mut secrets = BTreeMap::new();
    secrets.insert("INV069_SECRET".to_owned(), sentinel.clone());
    #[cfg(unix)]
    let (program, args) = (
        "sh".to_owned(),
        vec![
            "-c".to_owned(),
            "printf '%s' \"$INV069_SECRET\"; printf '%s' \"$INV069_SECRET\" >&2".to_owned(),
        ],
    );
    #[cfg(windows)]
    let (program, args) = (
        "cmd.exe".to_owned(),
        vec![
            "/d".to_owned(),
            "/c".to_owned(),
            "if defined INV069_SECRET (<nul set /p =%INV069_SECRET% & <nul set /p =%INV069_SECRET% 1>&2 & exit /b 0) else exit /b 1"
                .to_owned(),
        ],
    );
    let response = request(
        port,
        AgentRequestKind::Exec {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: SecretEnvironment::new(secrets),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    let Some(AgentResponseKind::Exec { stdout, stderr, .. }) = response.response else {
        panic!("unexpected exec response: {response:?}");
    };
    assert_eq!(stdout.trim_end(), "[REDACTED]");
    assert_eq!(stderr.trim_end(), "[REDACTED]");
    assert!(!stdout.contains(&sentinel));
    assert!(!stderr.contains(&sentinel));
}

#[test]
fn bounded_exec_rejects_invalid_timeout_with_machine_code() {
    let port = test_server();
    let response = request(
        port,
        AgentRequestKind::Exec {
            program: if cfg!(windows) {
                "cmd.exe".into()
            } else {
                "true".into()
            },
            args: Vec::new(),
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 0,
            raw_output: false,
        },
    );
    assert!(!response.ok);
    assert_eq!(
        response.error_code,
        Some(AgentErrorCode::ExecInvalidTimeout)
    );
}

#[test]
fn immediate_exec_source_has_no_synchronous_process_polling() {
    let source = include_str!("control/runtime.rs");
    assert!(!source.contains("OwnedProcess"));
    assert!(!source.contains("try_wait"));
    assert!(!source.contains("thread::sleep"));
    assert!(!source.contains("background_command"));
    assert!(!source.contains("process_input::"));
}

#[cfg(unix)]
#[test]
fn bounded_exec_timeout_terminates_launcher_exited_descendant_tree() {
    let root = env::temp_dir().join(format!(
        "onec-agent-exec-timeout-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("timeout fixture root");
    let marker = root.join("escaped");
    let port = test_server();
    let response = request(
        port,
        AgentRequestKind::Exec {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                "(sleep 1; printf escaped > \"$1\") & exit 0".into(),
                "sh".into(),
                marker.to_string_lossy().into_owned(),
            ],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 150,
            raw_output: false,
        },
    );
    assert!(!response.ok, "unexpected timeout response: {response:?}");
    assert_eq!(response.error_code, Some(AgentErrorCode::ExecTimeout));
    thread::sleep(Duration::from_millis(1_200));
    assert!(
        !marker.exists(),
        "timed-out Exec left a descendant alive long enough to publish its marker"
    );
    let _ = fs::remove_dir_all(root);
}

#[cfg(windows)]
fn windows_process_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return false;
        }
        let mut exit_code = 0_u32;
        let queried = GetExitCodeProcess(process, &mut exit_code);
        let _ = CloseHandle(process);
        queried != 0 && exit_code == STILL_ACTIVE as u32
    }
}

#[cfg(windows)]
#[test]
fn bounded_exec_timeout_terminates_windows_job_descendant_after_launcher_exit() {
    let root = env::temp_dir().join(format!(
        "onec-agent-exec-timeout-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("timeout fixture root");
    let pid_file = root.join("descendant.pid");
    let pid_literal = pid_file.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$child = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru; [IO.File]::WriteAllText('{pid_literal}', [string]$child.Id); exit 0"
    );
    let port = test_server();
    let response = request(
        port,
        AgentRequestKind::Exec {
            program: "powershell.exe".into(),
            args: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                script,
            ],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 2_000,
            raw_output: false,
        },
    );
    assert!(!response.ok, "unexpected timeout response: {response:?}");
    assert_eq!(response.error_code, Some(AgentErrorCode::ExecTimeout));
    let pid = fs::read_to_string(&pid_file)
        .expect("descendant pid file")
        .trim()
        .parse::<u32>()
        .expect("descendant pid");
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while windows_process_is_alive(pid) && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !windows_process_is_alive(pid),
        "bounded Exec timeout left descendant PID {pid} alive"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn bounded_exec_noisy_output_fails_with_machine_code() {
    let port = test_server();
    #[cfg(unix)]
    let (program, args) = (
        "sh".to_owned(),
        vec![
            "-c".to_owned(),
            "yes X | head -c 300000; sleep 30".to_owned(),
        ],
    );
    #[cfg(windows)]
    let (program, args) = (
        "powershell.exe".to_owned(),
        vec![
            "-NoProfile".to_owned(),
            "-NonInteractive".to_owned(),
            "-Command".to_owned(),
            "[Console]::Out.Write('X' * 300000); Start-Sleep -Seconds 30".to_owned(),
        ],
    );
    let started = std::time::Instant::now();
    let response = request(
        port,
        AgentRequestKind::Exec {
            program,
            args,
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: 10_000,
            raw_output: false,
        },
    );
    assert!(
        !response.ok,
        "unexpected noisy-output response: {response:?}"
    );
    assert_eq!(response.error_code, Some(AgentErrorCode::ExecOutputLimit));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "output limit did not terminate the process tree promptly"
    );
}

#[cfg(unix)]
#[test]
fn structured_exec_preserves_unicode_argv_cwd_and_environment() {
    use std::collections::BTreeMap;

    let root = env::temp_dir().join(format!(
        "onec-agent-unicode-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let cwd = root.join("Каталог (тест) & 100%");
    fs::create_dir_all(&cwd).expect("unicode cwd");
    let port = test_server();

    let argv = request(
        port,
        AgentRequestKind::Exec {
            program: "printf".into(),
            args: vec!["%s".into(), "Проверка Обмена".into()],
            cwd: None,
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    assert!(matches!(
        argv.response,
        Some(AgentResponseKind::Exec { ref stdout, .. }) if stdout == "Проверка Обмена"
    ));

    let cwd_response = request(
        port,
        AgentRequestKind::Exec {
            program: "pwd".into(),
            args: Vec::new(),
            cwd: Some(cwd.to_string_lossy().into_owned()),
            env: Default::default(),
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    assert!(matches!(
        cwd_response.response,
        Some(AgentResponseKind::Exec { ref stdout, .. }) if stdout.trim_end() == cwd.to_string_lossy()
    ));

    let mut environment = BTreeMap::new();
    environment.insert("ONEC_LABEL".to_owned(), "Набор Юникод".to_owned());
    let env_response = request(
        port,
        AgentRequestKind::Exec {
            program: "env".into(),
            args: Vec::new(),
            cwd: None,
            env: environment,
            secret_env: Default::default(),
            stdin: None,
            result_set_id: None,
            results: Vec::new(),
            timeout_ms: DEFAULT_EXEC_TIMEOUT_MS,
            raw_output: false,
        },
    );
    assert!(matches!(
        env_response.response,
        Some(AgentResponseKind::Exec { ref stdout, .. }) if stdout.lines().any(|line| line == "ONEC_LABEL=Набор Юникод")
    ));

    fs::remove_dir_all(root).expect("cleanup unicode cwd");
}

#[test]
fn regression_inv_024_path_sha256_reports_exact_bytes_for_literal_paths() {
    let root = env::temp_dir().join(format!(
        "onec-agent-fs-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("fs root");
    let port = test_server();
    let artifact = root.join("Артефакт (тест) & 100%.bin");
    fs::write(&artifact, b"verified-agent-transfer").expect("artifact");
    let hash = request(
        port,
        AgentRequestKind::PathSha256 {
            path: artifact.to_string_lossy().into_owned(),
        },
    );
    let expected = format!("{:x}", Sha256::digest(b"verified-agent-transfer"));
    assert!(matches!(
        hash.response,
        Some(AgentResponseKind::PathSha256 { bytes: 23, ref sha256 }) if sha256 == &expected
    ));
    fs::remove_dir_all(root).expect("cleanup fs root");
}

#[test]
fn path_rename_preserves_no_overwrite_and_supports_atomic_replace() {
    let root = env::temp_dir().join(format!(
        "onec-agent-rename-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("rename root");
    let source = root.join("source.bin");
    let target = root.join("target.bin");
    fs::write(&source, b"new").expect("source");
    fs::write(&target, b"old").expect("target");
    let port = test_server();

    let refused = request(
        port,
        AgentRequestKind::PathRename {
            from: source.to_string_lossy().into_owned(),
            to: target.to_string_lossy().into_owned(),
            overwrite: false,
        },
    );
    assert!(!refused.ok);
    assert_eq!(fs::read(&source).expect("source preserved"), b"new");
    assert_eq!(fs::read(&target).expect("target preserved"), b"old");

    let replaced = request(
        port,
        AgentRequestKind::PathRename {
            from: source.to_string_lossy().into_owned(),
            to: target.to_string_lossy().into_owned(),
            overwrite: true,
        },
    );
    assert!(matches!(
        replaced.response,
        Some(AgentResponseKind::PathRenamed)
    ));
    assert!(!source.exists());
    assert_eq!(fs::read(&target).expect("target replaced"), b"new");

    fs::remove_dir_all(root).expect("cleanup rename root");
}

#[test]
fn regression_inv_071_scoped_remove_protocol_deletes_only_child() {
    let root = env::temp_dir().join(format!(
        "onec-agent-inv071-protocol-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let target = root.join("owned child");
    fs::create_dir_all(&target).expect("target");
    let port = test_server();

    let response = request(
        port,
        AgentRequestKind::PathRemoveScoped {
            root: root.to_string_lossy().into_owned(),
            path: target.to_string_lossy().into_owned(),
            recursive: true,
            missing_ok: false,
        },
    );
    assert!(matches!(
        response.response,
        Some(AgentResponseKind::PathRemoved { removed: true })
    ));
    assert!(root.is_dir());
    assert!(!target.exists());
    fs::remove_dir_all(root).expect("cleanup root");
}

#[test]
fn regression_inv_071_scoped_remove_preserves_literal_unicode_and_quote_path_data() {
    let root = env::temp_dir().join(format!(
        "onec-agent-inv071-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("root");
    #[cfg(windows)]
    let target = root.join("Каталог с пробелом 'quote'");
    #[cfg(not(windows))]
    let target = root.join("Каталог с пробелом 'quote' \"double\"");
    fs::create_dir_all(&target).expect("target");
    fs::write(target.join("keep.txt"), b"fixture").expect("file");

    let port = test_server();
    let response = request(
        port,
        AgentRequestKind::PathRemoveScoped {
            root: root.to_string_lossy().into_owned(),
            path: target.to_string_lossy().into_owned(),
            recursive: true,
            missing_ok: false,
        },
    );
    assert!(matches!(
        response.response,
        Some(AgentResponseKind::PathRemoved { removed: true })
    ));
    assert!(!target.exists());
    assert!(root.is_dir());
    fs::remove_dir_all(root).expect("cleanup root");
}

#[cfg(unix)]
#[test]
fn regression_inv_071_scoped_remove_protocol_removes_final_symlink_without_following() {
    use std::os::unix::fs::symlink;

    let base = env::temp_dir().join(format!(
        "onec-agent-inv071-link-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let root = base.join("owned");
    let outside = base.join("outside");
    fs::create_dir_all(&root).expect("owned root");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(outside.join("survivor.txt"), b"must survive").expect("outside file");
    let escape = root.join("escape-link");
    symlink(&outside, &escape).expect("symlink fixture");

    let port = test_server();
    let response = request(
        port,
        AgentRequestKind::PathRemoveScoped {
            root: root.to_string_lossy().into_owned(),
            path: escape.to_string_lossy().into_owned(),
            recursive: true,
            missing_ok: false,
        },
    );
    assert!(matches!(
        response.response,
        Some(AgentResponseKind::PathRemoved { removed: true })
    ));
    assert!(outside.join("survivor.txt").is_file());
    assert!(!escape.exists());

    fs::remove_dir_all(&base).expect("cleanup base");
}

#[test]
fn wrong_secret_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        handle_connection(listener.accept().expect("accept").0, &runtime()).expect("handle");
    });
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write_json_line(
        &mut stream,
        &AgentRequest::new("wrong-secret-value", AgentRequestKind::Hello),
    )
    .expect("write");
    let response: AgentResponse = read_json_line(BufReader::new(stream)).expect("response");
    assert!(!response.ok);
    assert_eq!(response.error.as_deref(), Some("authentication failed"));
}

#[test]
fn agent_runtime_debug_redacts_control_secret() {
    let runtime = AgentRuntime {
        name: "fixture".into(),
        secret: "agent-control-secret-sentinel".into(),
        jobs_dir: PathBuf::from("jobs"),
        native_suite_policy_sha256: None,
    };
    let debug = format!("{runtime:?}");
    assert!(!debug.contains("agent-control-secret-sentinel"), "{debug}");
    assert!(debug.contains("[REDACTED]"), "{debug}");
}

#[test]
fn runtime_can_read_service_secret_from_file() {
    let directory = env::temp_dir().join(format!(
        "onec-agent-secret-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).expect("secret directory");
    let path = directory.join("secret.txt");
    fs::write(&path, "0123456789abcdef\n").expect("secret file");
    let config: AgentConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "name": "fixture",
        "secret_file": path
    }))
    .expect("valid config");
    let runtime = config.runtime().expect("runtime");
    assert_eq!(runtime.secret.expose_secret(), "0123456789abcdef");
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn interrupted_overwrite_upload_preserves_existing_file() {
    use std::io::Write;
    use std::net::Shutdown;

    let directory = env::temp_dir().join(format!(
        "onec-agent-upload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).expect("upload directory");
    let target = directory.join("artifact.bin");
    fs::write(&target, b"original").expect("original");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let worker =
        thread::spawn(move || handle_connection(listener.accept().expect("accept").0, &runtime()));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write_json_line(
        &mut stream,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::Upload {
                path: target.to_string_lossy().into_owned(),
                bytes: 8,
                overwrite: true,
            },
        ),
    )
    .expect("request");
    let ready: AgentResponse =
        read_json_line(BufReader::new(stream.try_clone().expect("clone"))).expect("ready");
    assert!(matches!(
        ready.response,
        Some(AgentResponseKind::UploadReady)
    ));
    let staging = fs::read_dir(&directory)
        .expect("staging directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path != &target)
        .expect("same-directory staging file");
    assert_eq!(staging.parent(), Some(directory.as_path()));
    assert!(
        staging
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".onec-upload-"))
    );

    stream.write_all(b"new").expect("partial payload");
    stream.shutdown(Shutdown::Write).expect("shutdown");
    assert!(worker.join().expect("worker").is_err());
    assert_eq!(fs::read(&target).expect("preserved target"), b"original");
    assert_eq!(
        fs::read_dir(&directory).expect("directory").count(),
        1,
        "staging file must be removed"
    );
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn upload_without_overwrite_refuses_existing_target_without_staging() {
    let directory = env::temp_dir().join(format!(
        "onec-agent-upload-no-overwrite-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).expect("upload directory");
    let target = directory.join("artifact.bin");
    fs::write(&target, b"original").expect("original");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let worker =
        thread::spawn(move || handle_connection(listener.accept().expect("accept").0, &runtime()));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write_json_line(
        &mut stream,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::Upload {
                path: target.to_string_lossy().into_owned(),
                bytes: 8,
                overwrite: false,
            },
        ),
    )
    .expect("request");
    let refused: AgentResponse =
        read_json_line(BufReader::new(stream.try_clone().expect("clone"))).expect("refused");
    assert!(!refused.ok);
    assert!(refused.response.is_none());
    worker.join().expect("worker").expect("handler");

    assert_eq!(fs::read(&target).expect("target preserved"), b"original");
    assert_eq!(
        fs::read_dir(&directory).expect("directory").count(),
        1,
        "refused upload must not create staging"
    );
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn complete_overwrite_upload_replaces_existing_file() {
    use std::io::Write;

    let directory = env::temp_dir().join(format!(
        "onec-agent-upload-ok-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).expect("upload directory");
    let target = directory.join("artifact.bin");
    fs::write(&target, b"original").expect("original");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let worker =
        thread::spawn(move || handle_connection(listener.accept().expect("accept").0, &runtime()));

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    write_json_line(
        &mut stream,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::Upload {
                path: target.to_string_lossy().into_owned(),
                bytes: 8,
                overwrite: true,
            },
        ),
    )
    .expect("request");
    let ready: AgentResponse =
        read_json_line(BufReader::new(stream.try_clone().expect("clone"))).expect("ready");
    assert!(matches!(
        ready.response,
        Some(AgentResponseKind::UploadReady)
    ));
    stream.write_all(b"replaced").expect("payload");
    let done: AgentResponse =
        read_json_line(BufReader::new(stream.try_clone().expect("clone"))).expect("done");
    assert!(matches!(
        done.response,
        Some(AgentResponseKind::Uploaded { bytes: 8 })
    ));
    worker.join().expect("worker").expect("handler");
    assert_eq!(fs::read(&target).expect("target"), b"replaced");
    assert_eq!(fs::read_dir(&directory).expect("directory").count(), 1);
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn tcp_connect_preserves_bidirectional_half_close() {
    use std::io::{Read, Write};
    use std::net::Shutdown;

    let target = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_port = target.local_addr().expect("target addr").port();
    let target_worker = thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("target accept");
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .expect("target reads request through EOF");
        assert_eq!(request, b"ping");
        stream.write_all(b"pong").expect("target response");
        stream
            .shutdown(Shutdown::Write)
            .expect("target response EOF");
    });

    let listener = TcpListener::bind("127.0.0.1:0").expect("agent bind");
    let agent_port = listener.local_addr().expect("agent addr").port();
    let agent_worker = thread::spawn(move || {
        handle_connection(listener.accept().expect("accept").0, &runtime()).expect("handle");
    });

    let mut stream = TcpStream::connect(("127.0.0.1", agent_port)).expect("agent connect");
    write_json_line(
        &mut stream,
        &AgentRequest::new(
            "0123456789abcdef",
            AgentRequestKind::TcpConnect {
                host: "127.0.0.1".into(),
                port: target_port,
                timeout_ms: 1000,
            },
        ),
    )
    .expect("connect request");
    let response: AgentResponse =
        read_json_line(BufReader::new(stream.try_clone().expect("clone"))).expect("ready");
    assert!(matches!(
        response.response,
        Some(AgentResponseKind::TcpReady)
    ));

    stream.write_all(b"ping").expect("proxy write");
    stream
        .shutdown(Shutdown::Write)
        .expect("client request EOF");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("client response through EOF");
    assert_eq!(response, b"pong");

    target_worker.join().expect("target worker");
    agent_worker.join().expect("agent worker");
}

#[test]
fn windows_supervisor_only_manages_agent_and_never_starts_unselected_update() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let updater = include_str!("../assets/Update-OnecToolkit.ps1");
    let rust_update = include_str!("managed_update.rs");
    assert!(!supervisor.contains("Get-ActiveAgentJobIds"));
    assert!(!supervisor.contains("deferred_active_jobs"));
    assert!(updater.contains("__self-update --root $Root --preflight"));
    assert!(rust_update.contains("pub fn preflight_runtime_update"));
    assert!(rust_update.contains("jobs::active_ids(&root.join(\"jobs\"))"));
    assert!(!updater.contains("Get-ActiveAgentJobIds"));
}

#[test]
fn regression_inv_055_managed_windows_scripts_do_not_require_modern_powershell_json_cmdlets() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");

    assert!(update.contains("JavaScriptSerializer"));
    assert!(!supervisor.contains("JavaScriptSerializer"));
    assert!(install.contains("DeserializeObject($statusText)"));
    assert!(!supervisor.contains("$jobsRoot"));
    assert!(!supervisor.contains("state-*.json"));
    assert!(!supervisor.contains("deferred_active_jobs"));
    assert!(!update.contains("$jobsRoot"));
}

#[test]
fn regression_inv_023_installer_owns_git_ssh_path_projection() {
    let install = include_str!("../assets/Install-OnecToolkit.ps1");
    let update = include_str!("../assets/Update-OnecToolkit.ps1");

    assert!(install.contains("$managedTools = Install-PortableOpenSsh"));
    assert!(install.contains("$agentConfig.Add('path_prepend', $managedPathPrepend.ToArray())"));
    assert!(install.contains("foreach ($directory in $managedPathPrepend) { Add-UserPath"));
    assert!(install.contains("$gitVersionOutput = & git --version"));
    assert!(install.contains("$pathOnecOutput = & onec --version"));
    assert!(install.contains("Published Git command was not available through PATH"));
    assert!(install.contains("Published onec command was not available through PATH"));
    assert!(!update.contains("path_prepend"));
    assert!(!install.contains("tools ensure git"));
    assert!(!install.contains("tools ensure ssh"));
    assert!(!update.contains("tools ensure git"));
    assert!(!update.contains("tools ensure ssh"));
}

#[test]
fn regression_inv_021_supervisor_does_not_launch_unselected_powershell_updater() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let updater = include_str!("../assets/Update-OnecToolkit.ps1");
    assert!(!supervisor.contains("Update-OnecToolkit.ps1"));
    assert!(!supervisor.contains("update_started agent_pid="));
    assert!(!supervisor.contains("UpdateHours"));
    assert!(updater.contains("System32\\WindowsPowerShell\\v1.0\\powershell.exe"));
    assert!(!supervisor.contains("& powershell.exe -NoProfile"));
}

#[test]
fn regression_inv_133_non_owner_supervisor_cannot_remove_active_agent_pid() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1").replace("\r\n", "\n");
    let finally = supervisor
        .rsplit_once("} finally {")
        .expect("supervisor outer finally")
        .1;
    let pid_cleanup = "Remove-Item -Force -ErrorAction SilentlyContinue $pidFile";

    assert!(finally.contains(
        "if ($null -ne $lock) {\n        Remove-Item -Force -ErrorAction SilentlyContinue $pidFile\n        $lock.Dispose()\n    }"
    ));
    assert_eq!(finally.matches(pid_cleanup).count(), 1);
}

#[test]
fn structured_agent_event_log_is_jsonl_and_drops_free_form_error_text() {
    let root = std::env::temp_dir().join(format!(
        "onec-agent-events-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("event temp dir");
    let path = root.join("agent-events.log");
    write_agent_event(
        &path,
        "tunnel.spawn_failed",
        "error",
        AgentEventFields::default().remote_port(18403),
    )
    .expect("write event");
    let text = fs::read_to_string(&path).expect("event log");
    let value: serde_json::Value = serde_json::from_str(text.trim()).expect("event json");
    assert_eq!(value["schema_version"], AGENT_EVENT_SCHEMA_VERSION);
    assert_eq!(value["event_code"], "tunnel.spawn_failed");
    assert_eq!(value["component"], "onec_agent");
    assert_eq!(value["remote_port"], 18403);
    assert!(value.get("message").is_none());
    assert!(value.get("error").is_none());
    assert!(value.get("path").is_none());
    fs::remove_dir_all(root).ok();
}

#[test]
fn run_local_exec_stage_events_serialize_only_fixed_stage_and_elapsed_time() {
    let root = std::env::temp_dir().join(format!(
        "onec-agent-exec-events-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&root).expect("event temp dir");
    let path = root.join("agent-events.log");
    write_agent_event(
        &path,
        "exec.stage_completed",
        "info",
        AgentEventFields::default()
            .stage("subprocess_start")
            .elapsed_ms(17),
    )
    .expect("write event");
    let text = fs::read_to_string(&path).expect("event log");
    let value: serde_json::Value = serde_json::from_str(text.trim()).expect("event json");
    assert_eq!(value["event_code"], "exec.stage_completed");
    assert_eq!(value["stage"], "subprocess_start");
    assert_eq!(value["elapsed_ms"], 17);
    assert!(value.get("program").is_none());
    assert!(value.get("args").is_none());
    assert!(value.get("path").is_none());
    fs::remove_dir_all(root).ok();
}

#[test]
fn supervisor_and_agent_persist_tunnel_lifecycle_diagnostics() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    assert!(supervisor.contains("ONEC_AGENT_EVENT_LOG"));
    assert!(supervisor.contains("agent_started pid="));
    assert!(supervisor.contains("agent_exited pid="));
    assert!(supervisor.contains("agent_restart_scheduled"));
}

#[test]
fn regression_inv_143_live_maintenance_owner_is_never_removed_by_another_process() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let updater = include_str!("../assets/Update-OnecToolkit.ps1");
    let installer = include_str!("../assets/Install-OnecToolkit.ps1");

    for script in [supervisor, updater, installer] {
        assert!(script.contains("maintenance.gate"));
        assert!(
            script.contains("maintenance_marker_owner_live")
                || script.contains("A live update/install process owns the maintenance marker.")
        );
        assert!(script.contains("StartTime.ToUniversalTime().Ticks"));
    }
    assert!(updater.contains("maintenance_cleanup_skipped owner_changed"));
    assert!(
        updater.contains("[string]::Equals($current, $OwnerText, [StringComparison]::Ordinal)")
    );
    assert!(!updater.contains("Remove-Item -Force -ErrorAction SilentlyContinue $maintenance"));
    assert!(!installer.contains("Remove-Item -Force -ErrorAction SilentlyContinue $maintenance"));
}

#[test]
fn regression_inv_143_orphan_maintenance_marker_requires_process_identity_proof() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let updater = include_str!("../assets/Update-OnecToolkit.ps1");
    let installer = include_str!("../assets/Install-OnecToolkit.ps1");

    for script in [updater, installer] {
        assert!(script.contains("catch [ArgumentException]"));
        assert!(script.contains("return 'orphan'"));
        assert!(script.contains("return 'unknown'"));
        assert!(script.contains("[IO.FileMode]::CreateNew"));
    }
    assert!(supervisor.contains("catch [ArgumentException]"));
    assert!(supervisor.contains("return 'orphan'"));
    assert!(supervisor.contains("return 'unknown'"));
    assert!(supervisor.contains("if ($state -eq 'orphan')"));
    assert!(supervisor.contains("[IO.File]::Delete($maintenance)"));
    assert!(updater.contains("if ($state -eq 'orphan')"));
    assert!(installer.contains("if ($state -eq 'orphan')"));
}

#[test]
fn regression_inv_143_supervisor_logs_maintenance_early_exit_reason() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    assert!(supervisor.contains("supervisor_stopped maintenance_marker_owner_live"));
    assert!(supervisor.contains("supervisor_stopped maintenance_marker_owner_unverifiable"));
    assert!(supervisor.contains("maintenance_orphan_recovered owner_process_absent_or_reused"));
    assert!(supervisor.contains("if ($maintenanceState -eq 'live')"));
    assert!(supervisor.contains("if ($maintenanceState -eq 'unknown')"));
}

#[test]
fn regression_inv_143_interrupted_update_recovers_at_user_session_supervisor_startup() {
    let supervisor = include_str!("../assets/Run-OnecAgent.ps1");
    let updater = include_str!("../assets/Update-OnecToolkit.ps1");
    let installer = include_str!("../assets/Install-OnecToolkit.ps1");

    assert!(updater.contains("$maintenanceOwned = New-MaintenanceMarker 'update'"));
    assert!(updater.contains("Wait-SupervisorStopped 30"));
    assert!(updater.contains("Remove-OwnedMaintenanceMarker $maintenanceOwned"));
    assert!(supervisor.contains("Get-MaintenanceStateUnderGate"));
    assert!(supervisor.contains("agent_restart_scheduled delay_seconds=5"));
    let orphan_recovery = supervisor
        .find("$maintenanceState = Get-MaintenanceStateUnderGate")
        .expect("maintenance recovery before agent prerequisites");
    let bin_prerequisite = supervisor
        .find("if (-not (Test-Path $bin))")
        .expect("binary prerequisite check");
    let config_prerequisite = supervisor
        .find("if (-not (Test-Path $config))")
        .expect("config prerequisite check");
    assert!(orphan_recovery < bin_prerequisite);
    assert!(bin_prerequisite < config_prerequisite);
    assert!(
        installer
            .contains("$maintenanceOwner = New-OwnedMaintenanceMarker $AgentDirectory 'install'")
    );
    assert!(installer.contains("Remove-OwnedMaintenanceMarker $agentDir $maintenanceOwned"));
}
