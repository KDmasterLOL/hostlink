"""Static contract checks for the opt-in Win11 native live updater harness."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-windows-agent-updater-native.ps1"
DOC = ROOT / "docs" / "AGENT_UPDATE_WINDOWS.md"
README = ROOT / "README.md"


class WindowsAgentUpdaterHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")

    def test_requires_disposable_profile_sid_and_both_source_sentinels(self):
        for token in (
            "ExpectedDisposableSid",
            "ProtectedWorkSid",
            "ExpectedDisposableProfile",
            "ProtectedWorkProfile",
            "SentinelPath",
            "HOSTLINK-NATIVE-UPDATER-DISPOSABLE",
            "NTUSER.DAT",
            "Administrators execution is forbidden",
            "SourceShaA",
            "SourceShaB",
        ):
            self.assertIn(token, self.script)
        self.assertIn("$SourceShaA -ceq $SourceShaB", self.script)
        self.assertIn("|SOURCE_A=' + $SourceShaA + '|SOURCE_B=' + $SourceShaB", self.script)

    def test_uses_os_localappdata_and_rejects_existing_root_and_run_value(self):
        self.assertIn("SHGetFolderPathW([IntPtr]::Zero, 0x001c", self.script)
        self.assertIn("$script:LocalAppData = Full $localBuffer.ToString()", self.script)
        self.assertIn("$env:LOCALAPPDATA -and -not (SamePath", self.script)
        self.assertNotRegex(self.script, r"(?i)Join-Path\s+\$env:LOCALAPPDATA")
        self.assertIn("HostLink parent already exists", self.script)
        self.assertIn("pre-existing HostLink Agent HKCU Run value", self.script)

    def test_binds_a_and_b_to_distinct_source_build_and_executable_hashes(self):
        for token in (
            "Validate-Build $BuildRootA $SourceShaA 'build A'",
            "Validate-Build $BuildRootB $SourceShaB 'build B'",
            "function PathsOverlap",
            "build and package evidence roots must be distinct and non-overlapping",
            "build_receipt.sha256",
            "PE_BUILD_AND_INSPECTION_PASS",
            "native_acceptance.status",
            "source_sha -cne $ExpectedSourceSha",
            "sidecar_sha256 -ceq $script:AgentB.Receipt.sidecar_sha256",
            "source-verified package A and B executable SHA values are identical",
            "support file differs and cannot be safely updated",
        ):
            self.assertIn(token, self.script)
        self.assertIn("Validate-Package $PackageARoot", self.script)
        self.assertIn("Validate-Package $PackageBRoot", self.script)

    def test_candidate_b_is_separate_updater_and_successful_live_update(self):
        self.assertIn("Copy-Item -LiteralPath $script:AgentB.Sidecar -Destination $script:Updater", self.script)
        self.assertIn("(Sha256 $script:Updater) -cne $script:AgentB.Receipt.sidecar_sha256", self.script)
        self.assertIn("registered live Agent update A to B", self.script)
        self.assertIn("Assert-AgentPidExited $oldPid", self.script)
        self.assertIn("ssh_banner=true", self.script)
        self.assertRegex(self.script, r"Require-CommandSuccess\s+\$positive")

    def test_negative_job_cases_assert_distinct_expected_diagnostics(self):
        self.assertIn("'jobs not terminal'", self.script)
        self.assertIn("'job record is invalid or incomplete'", self.script)
        self.assertIn("'prepared','running','interrupted'", self.script)
        self.assertIn("'corrupt durable job record rejection'", self.script)
        self.assertIn("function Require-CommandFailureContains", self.script)
        self.assertIn("Assert-FileSnapshot $snapshot \"$state job deferral\"", self.script)
        self.assertIn("Assert-FileSnapshot $unknownSnapshot 'unknown job rejection'", self.script)

    def test_health_rollback_is_explicitly_not_tested(self):
        self.assertIn("health_failure_rollback=NOT_TESTED", self.script)
        self.assertIn("Candidate health-failure rollback is explicitly `NOT_TESTED`", self.doc)
        self.assertNotIn("candidate startup health failure", self.script)
        self.assertNotIn("old Agent start after health rollback", self.script)
        self.assertNotIn("service stop before health-failure injection", self.script)

    def test_cleanup_preserves_unknown_or_ambiguous_root_content(self):
        self.assertIn("function Assert-CleanupInventory", self.script)
        self.assertIn("function Remove-VerifiedTree", self.script)
        self.assertIn("extra: $extra; missing: $missing", self.script)
        self.assertIn("preserving whole tree", self.script)
        self.assertIn("Remove-HarnessJob", self.script)
        self.assertNotIn("Remove-Item -LiteralPath $jobDir -Recurse", self.script)
        self.assertIn("owner.source_sha_a -ceq $SourceShaA", self.script)
        self.assertIn("owner.source_sha_b -ceq $SourceShaB", self.script)
        self.assertIn("owner.candidate_sha256 -ceq $script:AgentB.Receipt.sidecar_sha256", self.script)
        self.assertIn("[IO.Directory]::Delete($item.FullName, $false)", self.script)
        self.assertNotIn("Remove-Item -LiteralPath $script:Root -Recurse", self.script)

    def test_documentation_separates_static_and_live_proof(self):
        self.assertIn("Windows 11 live registered-Agent acceptance", self.doc)
        self.assertIn("ALEXROVICH\\TIS", self.doc)
        self.assertIn("Static tests and a PowerShell parse do not count as live", self.doc)
        self.assertIn("two distinct executable", self.doc)
        self.assertIn("-BuildRootA", self.doc)
        self.assertIn("-BuildRootB", self.doc)
        self.assertIn("verify-windows-agent-updater-native.ps1", self.readme)


if __name__ == "__main__":
    unittest.main()
