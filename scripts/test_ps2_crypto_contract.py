"""Native Windows 7 CLR2 contract for the installed HostLink Run script."""

from pathlib import Path
import unittest


RUN_SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "crates"
    / "onec-agent"
    / "assets"
    / "Run-HostLink-Agent.ps1"
)


class Win7HashAlgorithmContractTest(unittest.TestCase):
    def test_run_script_clears_sha256_under_clr2(self) -> None:
        source = RUN_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("$sha = [Security.Cryptography.SHA256]::Create()", source)
        self.assertIn("finally { $stream.Dispose(); $sha.Clear() }", source)
        self.assertNotIn("$sha.Dispose()", source)


if __name__ == "__main__":
    unittest.main()
