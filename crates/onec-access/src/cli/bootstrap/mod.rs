mod direct;
mod invite;
mod migrate;
mod render;

pub(in crate::cli) use invite::invite;
pub(in crate::cli) use migrate::{migrate_runtime, migration_exec_mode};

#[cfg(test)]
mod tests {
    use super::render::{
        RemoteDirectInviteBootstrap, RemoteRuntimeMigrationBootstrap, normalized_script_sha256,
        powershell_encoded_command, remote_direct_invite_bootstrap,
        remote_runtime_migration_bootstrap,
    };

    fn decode_powershell_encoded_command(encoded: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let bytes = STANDARD.decode(encoded).expect("valid Base64");
        let (pairs, remainder) = bytes.as_chunks::<2>();
        assert!(remainder.is_empty());
        let utf16 = pairs
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        String::from_utf16(&utf16).expect("valid UTF-16LE")
    }

    #[test]
    fn direct_invite_bootstrap_uses_external_artifact_sha_without_manifest_route() {
        let script_sha = normalized_script_sha256(super::direct::WINDOWS_TOOLKIT_BOOTSTRAP);
        let package_sha = "b".repeat(64);
        let script = remote_direct_invite_bootstrap(&RemoteDirectInviteBootstrap {
            installer_url: "https://downloads.example.test/Install-OnecToolkit.ps1",
            installer_sha256: &script_sha,
            hub_url: "https://hub.example.test",
            package_url: "https://downloads.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            package_sha256: &package_sha,
            package_version: "1.2.3",
            package_target: "x86_64-win7-windows-msvc",
            persistence: "user-session",
            embedded_ssh_candidate: false,
        });
        let decoded = decode_powershell_encoded_command(&powershell_encoded_command(&script));

        assert_eq!(decoded, script);
        assert!(script.contains("$request.AllowAutoRedirect=$false"));
        assert!(script.contains(&format!("$expected='{script_sha}'")));
        assert!(script.contains(&format!("-DirectPackageSha256 '{package_sha}'")));
        assert!(script.contains("-DirectPackageVersion '1.2.3'"));
        assert!(!script.contains("-ReleaseId"));
        assert!(!script.contains("-ReleaseManifestSha256"));
        assert!(!script.contains("-ReleaseBaseUrl"));
        assert!(!script.contains("/release-manifest.json"));
    }

    #[test]
    fn runtime_migration_bootstrap_is_direct_pinned_and_detaches_with_wmi() {
        let installer_sha = "a".repeat(64);
        let package_sha = "b".repeat(64);
        let input = RemoteRuntimeMigrationBootstrap {
            installer_url: "https://downloads.example.test/Install-OnecToolkit.ps1",
            installer_sha256: &installer_sha,
            persistence: "user-session",
            direct_package_url: "https://downloads.example.test/onec-toolkit-x86_64-win7-windows-msvc.zip",
            direct_package_sha256: &package_sha,
            direct_package_version: "1.2.3",
            direct_package_target: "x86_64-win7-windows-msvc",
        };
        let script = remote_runtime_migration_bootstrap(&input);

        assert!(script.contains(&format!("$expected='{installer_sha}'")));
        assert!(script.contains(&format!("$packageSha256='{package_sha}'")));
        assert!(script.contains("$request.AllowAutoRedirect=$false"));
        assert!(script.contains("Win32_Process').Create($commandLine)"));
        assert!(script.contains("package_version='+$packageVersion"));
        assert!(script.contains("[IO.Directory]::Delete($fullRoot,$false)"));
        assert!(script.contains("migration-last-failure.json"));
        assert!(script.contains("{\"phase\":\"installer_execution\""));
        assert!(script.contains("\"error_type\":\"''+$errorType"));
        assert!(script.contains("\"line\":''+[string]$errorLine"));
        assert!(script.contains("[IO.FileMode]::CreateNew"));
        assert!(script.contains("[IO.FileAttributes]::ReparsePoint"));
        assert!(script.contains("catch { $record=$_;"));
        assert!(script.contains("finally { $fullParent="));
        assert!(!script.contains("$record.Exception.Message"));
        assert!(!script.contains("$record.ToString()"));
        assert!(!script.contains("Write-Output $record"));
        let diagnostic_payload = script
            .split_once("$json='")
            .expect("diagnostic JSON payload")
            .1
            .split_once("';$bytes=")
            .expect("payload ends before UTF-8 encoding")
            .0;
        assert!(diagnostic_payload.contains("{\"phase\":\"installer_execution\""));
        assert!(diagnostic_payload.contains("\"error_type\":\"''+$errorType"));
        assert!(diagnostic_payload.contains("\"line\":''+[string]$errorLine"));
        assert!(!diagnostic_payload.contains("packageUrl"));
        assert!(!diagnostic_payload.contains("packageSha256"));
        assert!(!diagnostic_payload.contains("packageVersion"));
        assert!(!diagnostic_payload.contains("installerPath"));
        assert!(!diagnostic_payload.contains("Exception"));
        assert!(script.contains("Win32_Process').Create($commandLine)"));
        assert!(script.contains("if (($null -eq $result) -or ([int]$result.ReturnValue -ne 0) -or ([int]$result.ProcessId -le 0))"));
        assert!(script.contains("ONEC_TOOLKIT_MIGRATION_RECEIPT: detached_pid="));
        assert!(!script.contains("$fallback="));
        assert!(!script.contains("-ReleaseId"));
        assert!(!script.contains("-ReleaseManifestSha256"));
        assert!(!script.contains("-ReleaseBaseUrl"));
        assert!(!script.contains("-HubUrl"));
        assert!(!script.contains("-EnrollToken"));
        assert!(!script.contains("release-manifest.json"));
        assert!(powershell_encoded_command(&script).len() < 100_000);
    }
}
