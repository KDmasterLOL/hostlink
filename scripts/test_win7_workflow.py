"""Static guardrails for the manually dispatched Win7 candidate workflow."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "win7-candidate.yml"


class Win7CandidateWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_manual_only_read_only_test_artifact(self) -> None:
        self.assertIn("on:\n  workflow_dispatch:\n", self.workflow)
        self.assertNotIn("  push:", self.workflow)
        self.assertNotIn("  pull_request:", self.workflow)
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertEqual(self.workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("retention-days: 3", self.workflow)
        self.assertIn("include-hidden-files: true", self.workflow)
        self.assertIn("if-no-files-found: error", self.workflow)
        self.assertNotIn("actions/upload-release-asset", self.workflow)

    def test_msvc_environment_is_carried_across_github_steps(self) -> None:
        self.assertIn("vcvars64.bat", self.workflow)
        self.assertIn("$env:GITHUB_ENV", self.workflow)
        self.assertIn("'PATH', 'INCLUDE', 'LIB', 'LIBPATH'", self.workflow)
        self.assertIn("vcvars64.bat did not configure required", self.workflow)

    def test_pinned_build_has_no_ordinary_windows_fallback(self) -> None:
        self.assertIn("nightly-2026-08-22", self.workflow)
        self.assertIn("--component rust-src", self.workflow)
        self.assertIn("-Z build-std=std,panic_abort build --release --locked", self.workflow)
        self.assertIn("x86_64-win7-windows-msvc", self.workflow)
        self.assertNotIn("x86_64-pc-windows-msvc", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)

    def test_agent_package_and_raw_binary_are_both_checked(self) -> None:
        self.assertIn(
            "python scripts/package_hostlink.py agent $target .dist/staging .dist/out",
            self.workflow,
        )
        self.assertIn("hostlink-agent-x86_64-win7-windows-msvc.zip", self.workflow)
        for script in (
            "Install-HostLink-Agent.ps1",
            "Run-HostLink-Agent.ps1",
            "Update-HostLink-Agent.ps1",
        ):
            with self.subTest(script=script):
                self.assertIn(script, self.workflow)
        self.assertIn("hostlink-agent.exe.sha256", self.workflow)
        self.assertIn("$zip.Entries", self.workflow)
        self.assertIn("ZIP inventory mismatch", self.workflow)
        self.assertIn("'onec.exe'", self.workflow)


if __name__ == "__main__":
    unittest.main()
