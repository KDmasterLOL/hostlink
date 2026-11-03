"""The retired ZIP harness must never imply native raw-binary acceptance."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BootstrapHarnessRetirementTests(unittest.TestCase):
    def test_retired_harness_fails_before_any_operations(self):
        script = (ROOT / "scripts/verify-win7-bootstrap-native.ps1").read_text()
        statements = [line for line in script.splitlines() if line and not line.startswith("#")]
        self.assertEqual(len(statements), 1)
        self.assertTrue(statements[0].startswith("throw '"))
        self.assertIn("RETIRED.", statements[0])
        self.assertIn("No native test executed", statements[0])
        self.assertIn("WIN7_REWRITE_ACCEPTANCE.md", statements[0])

    def test_powershell_bootstrap_and_native_harness_sources_exist(self):
        # Native PowerShell validation belongs to WORK/Win7, not GitHub Actions.
        paths = (
            "crates/client/assets/github-windows.ps1",
            "crates/client/assets/bootstrap-windows.ps1",
            "scripts/verify-win7-bootstrap-native.ps1",
            "scripts/verify-windows-agent-lifecycle.ps1",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), path)

    def test_no_hosted_github_actions_workflows(self):
        # Source/release verification runs on HOME/WORK and disposable targets.
        workflows = ROOT / ".github/workflows"
        hosted = sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml")))
        self.assertEqual(hosted, [], "HostLink builds and checks run locally")


if __name__ == "__main__":
    unittest.main()
