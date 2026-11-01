"""The retired ZIP harness must never imply native raw-binary acceptance."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BootstrapHarnessRetirementTests(unittest.TestCase):
    def test_retired_harness_fails_before_any_operations(self):
        script = (ROOT / "scripts/verify-win7-bootstrap-native.ps1").read_text()
        statements = [line for line in script.splitlines() if line and not line.startswith("#")]
        self.assertEqual(len(statements), 1)
        self.assertTrue(statements[0].startswith("throw '"))
        self.assertIn("RETIRED (1C-1164)", statements[0])
        self.assertIn("No native test executed", statements[0])
        self.assertIn("WIN7_REWRITE_ACCEPTANCE.md", statements[0])

    def test_windows_ci_parses_only_existing_powershell_files(self):
        workflow = (ROOT / ".github/workflows/dev-ci.yml").read_text()
        self.assertIn("$assets = @(", workflow)
        sources = workflow.split("$assets = @(", 1)[1].split(")", 1)[0]
        paths = re.findall(r"'([^'\n]+\.ps1)'", sources)
        self.assertTrue(paths)
        self.assertIn("crates/client/assets/github-windows.ps1", paths)
        self.assertIn("crates/client/assets/bootstrap-windows.ps1", paths)
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), path)


if __name__ == "__main__":
    unittest.main()
