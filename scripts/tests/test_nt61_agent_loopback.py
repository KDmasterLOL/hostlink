"""Static contract checks for the NT6.1 SSH/SFTP loopback acceptance harness."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-nt61-agent-loopback.ps1"
DOC = ROOT / "docs" / "WIN7_REWRITE_ACCEPTANCE.md"
PRIOR_HARNESS = ROOT / "scripts" / "verify-win7-side-by-side.ps1"


class Nt61AgentLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")

    def test_server_2008_r2_ps2_and_interactive_user_are_required(self):
        for value in (
            "^6\\.1\\.7601",
            "Windows Server 2008 R2 Standard",
            "OSArchitecture",
            "PSVersionTable.PSVersion.Major -ne 2",
            "Administrator",
            "SessionId",
            "S-1-5-18",
        ):
            self.assertIn(value, self.script)
        self.assertIn("NT6.1 Windows Server 2008 R2 Standard x64", self.script)

    def test_exact_source_build_four_binaries_and_off_host_keys_are_inputs(self):
        for value in (
            "$SourceSha",
            "$BuildReceipt",
            "$X64Agent",
            "$X64Client",
            "$X86Agent",
            "$X86Client",
            "$HostPrivateKey",
            "$HostPublicKey",
            "$ControllerPrivateKey",
            "$ControllerPublicKey",
            "PE_BUILD_AND_INSPECTION_PASS",
            "x86_64-win7-windows-msvc",
            "i686-win7-windows-msvc",
            "hostlink-agent.exe",
            "hostlink.exe",
        ):
            self.assertIn(value, self.script)

    def test_private_empty_root_loopback_and_exact_configuration_contract(self):
        for value in (
            "DisposableRoot must be pre-created, private and empty",
            "AreAccessRulesProtected",
            "GetOwner",
            "ReparsePoint",
            "127.0.0.1:' + $port",
            "user='hostlink-native'",
            "host_key=$hostPrivate",
            "authorized_keys=$authorizedPath",
            "jobs_root=$jobs",
            "gateway=$null",
            "gateway_alternates=@()",
            "identity=$controllerPrivate",
            "host_public_key=$hostPin",
        ):
            self.assertIn(value, self.script)
        self.assertIn("for ($port = 20000; $port -le 29999; $port++)", self.script)

    def test_runs_both_real_cli_pairs_and_preserves_exit_and_sftp_digest(self):
        for value in (
            "@('check','--config',$agentConfigPath)",
            "Quote-ProcessArgument 'run'",
            "@('check','--config',$clientConfigPath)",
            "@('exec','--config',$clientConfigPath,'--command','exit 7')",
            "if ($execExit -ne 7)",
            "@('upload','--config',$clientConfigPath",
            "@('download','--config',$clientConfigPath",
            "Get-Sha256 $downloadPath",
            "negative_wrong_pin_exit",
            "negative_unknown_user_exit",
            "x64-native",
            "x86-wow64",
        ):
            self.assertIn(value, self.script)

    def test_bounded_capture_and_exact_owned_child_cleanup(self):
        for value in (
            "maximumBytes",
            "OutputExceeded",
            "process.Kill()",
            "process.WaitForExit(10000)",
            "Process object started above",
            "stdout_sha256",
            "stderr_sha256",
            "artifact_sha256",
            "cleanup_outcome",
        ):
            self.assertIn(value, self.script)
        for unsupported in ("ConvertFrom-Json", "ReadToEndAsync", ".Dispose()", "Start-Process"):
            self.assertNotIn(unsupported, self.script)
        self.assertNotIn("[IO.Path]::Combine($", self.script.replace("[IO.Path]::Combine($First, $Second)", ""))

    def test_doc_has_exact_ps2_invocation_and_preserves_prior_harness(self):
        self.assertTrue(PRIOR_HARNESS.exists())
        self.assertIn("verify-nt61-agent-loopback.ps1", self.doc)
        self.assertIn("-HostPrivateKey", self.doc)
        self.assertIn("-ControllerPrivateKey", self.doc)
        self.assertIn("Windows Server 2008 R2 Standard", self.doc)
        self.assertIn("4456b6004019b523a60487992ddfda66ecff9fde", self.doc)
        self.assertIn("WOW64", self.doc)


if __name__ == "__main__":
    unittest.main()
