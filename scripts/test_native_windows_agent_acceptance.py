"""Static guards for the source-exact Windows Agent acceptance harness."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent


class NativeWindowsAgentAcceptanceTest(unittest.TestCase):
    def test_harness_resolves_updater_from_installed_agent_bin(self) -> None:
        harness = (ROOT / "scripts" / "native_windows_agent_acceptance.ps1").read_text(
            encoding="utf-8"
        )
        updater = (ROOT / "crates" / "onec-agent" / "src" / "managed_update.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "$updater = Join-Path $script:Root 'hostlink-agent\\bin\\Update-HostLink-Agent.ps1'",
            harness,
        )
        self.assertIn('root.join("hostlink-agent/bin")', updater)
        self.assertIn('"Update-HostLink-Agent.ps1"', updater)


if __name__ == "__main__":
    unittest.main()
