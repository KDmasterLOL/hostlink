mod direct;
mod invite;
mod render;

pub(in crate::cli) use invite::invite;

#[cfg(test)]
mod tests {
    use super::render::{
        RemoteDirectInviteBootstrap, normalized_script_sha256, powershell_encoded_command,
        remote_direct_invite_bootstrap,
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

    fn assert_ps2_sha256_cleanup(script: &str) {
        for hasher in ["$hasher", "$archiveHasher", "$agentHasher"] {
            assert!(script.contains(&format!("{hasher}.Clear()")), "{hasher}");
            assert!(
                !script.contains(&format!("{hasher}.Dispose()")),
                "{hasher} must use the CLR2-compatible Clear method"
            );
        }
    }

    #[test]
    fn direct_invite_bootstrap_is_pinned_agent_only_and_keeps_token_out_of_argv() {
        let script_sha = normalized_script_sha256(super::direct::HOSTLINK_AGENT_BOOTSTRAP);
        let package_sha = "b".repeat(64);
        let script = remote_direct_invite_bootstrap(&RemoteDirectInviteBootstrap {
            installer_url: "https://downloads.example.test/Install-HostLink-Agent.ps1",
            installer_sha256: &script_sha,
            hub_url: "https://hub.example.test",
            package_url: "https://downloads.example.test/hostlink-agent-x86_64-win7-windows-msvc.zip",
            package_sha256: &package_sha,
            package_version: "1.2.3",
            package_target: "x86_64-win7-windows-msvc",
            agent_executable_url: Some("https://downloads.example.test/hostlink-agent.exe"),
            agent_executable_sha256: Some(&package_sha),
        });
        let decoded = decode_powershell_encoded_command(&powershell_encoded_command(&script));

        assert_eq!(decoded, script);
        assert_ps2_sha256_cleanup(&script);
        assert!(script.contains("$installerRequest.AllowAutoRedirect=$false"));
        assert!(script.contains("$packageRequest.AllowAutoRedirect=$false"));
        assert!(script.contains("$agentRequest.AllowAutoRedirect=$false"));
        assert!(
            script.contains(
                "$agentExecutableUrl='https://downloads.example.test/hostlink-agent.exe'"
            )
        );
        assert!(
            script.contains("-AgentExecutableFile ([IO.Path]::GetFullPath($agentExecutablePath))")
        );
        assert!(script.contains("-AgentExecutableSha256 $agentExecutableSha256"));
        assert!(script.contains(
            "$agentOutput=New-Object IO.FileStream($agentExecutablePath,[IO.FileMode]::CreateNew"
        ));
        assert!(script.contains("HostLink Agent executable SHA-256 mismatch."));
        for unsupported_ps2_api in ["Invoke-WebRequest", "Get-FileHash", "::new("] {
            assert!(
                !script.contains(unsupported_ps2_api),
                "{unsupported_ps2_api}"
            );
        }
        assert!(script.contains(&format!("$installerSha256='{script_sha}'")));
        assert!(script.contains(&format!("$packageSha256='{package_sha}'")));
        assert!(script.contains("icacls.exe"));
        assert!(script.contains("$directoryAcl.GetOwner"));
        assert!(script.contains("$tokenAcl.GetOwner"));
        assert!(script.contains("S-1-5-18"));
        assert!(script.contains("-EnrollmentTokenFile"));
        assert!(script.contains("-HubUrl $hubUrl"));
        assert!(script.contains("-ArchiveFile"));
        assert!(script.contains("$LASTEXITCODE=$null"));
        assert!(script.contains("$installerExitCode=$LASTEXITCODE"));
        assert!(
            script.contains("if (($null -eq $installerExitCode) -or ($installerExitCode -ne 0))")
        );
        assert!(script.contains("The invite may have been consumed; do not retry this token."));
        assert!(script.contains("ZeroFreeBSTR"));
        assert!(script.contains("do not retry this token"));
        assert!(script.contains("Read-Host 'One-use HostLink enrollment token' -AsSecureString"));
        assert!(!script.contains("Enrollment token: "));
        assert!(!script.contains("-EnrollToken "));
        assert!(!script.contains("-Token $token"));
        assert!(!script.contains("Write-Output $token"));
        assert!(!script.contains("onec.exe"));
        assert!(!script.contains("onec-toolkit-"));
        assert!(powershell_encoded_command(&script).len() < 100_000);
    }

    #[test]
    fn current_windows_bootstrap_omits_agent_sidecar_download_and_arguments() {
        let script_sha = normalized_script_sha256(super::direct::HOSTLINK_AGENT_BOOTSTRAP);
        let package_sha = "b".repeat(64);
        let script = remote_direct_invite_bootstrap(&RemoteDirectInviteBootstrap {
            installer_url: "https://downloads.example.test/Install-HostLink-Agent.ps1",
            installer_sha256: &script_sha,
            hub_url: "https://hub.example.test",
            package_url: "https://downloads.example.test/hostlink-agent-x86_64-pc-windows-msvc.zip",
            package_sha256: &package_sha,
            package_version: "1.2.3",
            package_target: "x86_64-pc-windows-msvc",
            agent_executable_url: None,
            agent_executable_sha256: None,
        });

        assert_ps2_sha256_cleanup(&script);
        assert!(script.contains("$agentExecutableUrl=''"));
        assert!(script.contains("if ($agentExecutableUrl -ne '')"));
        assert!(script.contains("if ($null -ne $agentExecutablePath)"));
    }
}
