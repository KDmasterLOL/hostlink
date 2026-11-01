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
        self.assertIn("RETIRED (1C-1164)", statements[0])
        self.assertIn("No native test executed", statements[0])
        self.assertIn("WIN7_REWRITE_ACCEPTANCE.md", statements[0])


if __name__ == "__main__":
    unittest.main()
