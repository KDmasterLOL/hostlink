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
        });
        let decoded = decode_powershell_encoded_command(&powershell_encoded_command(&script));

        assert_eq!(decoded, script);
        assert!(script.contains("$installerRequest.AllowAutoRedirect=$false"));
        assert!(script.contains("$packageRequest.AllowAutoRedirect=$false"));
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
}
