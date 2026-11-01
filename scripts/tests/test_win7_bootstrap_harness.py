#!/usr/bin/env python3
#!/usr/bin/env python3
"""Static contract checks for the Windows PowerShell 2 bootstrap harness."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts" / "verify-win7-bootstrap-native.ps1"
DOC = ROOT / "docs" / "WIN7_REWRITE_ACCEPTANCE.md"


class BootstrapHarnessContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = HARNESS.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")

    def test_runs_exact_win7_targets_and_actual_cli(self):
        for target in ("x86_64-win7-windows-msvc", "i686-win7-windows-msvc"):
            self.assertIn(target, self.script)
        self.assertIn("'bootstrap-verify','--archive'", self.script)
        self.assertIn("'--sha256'", self.script)
        self.assertIn("'--target'", self.script)
        self.assertIn("'--version'", self.script)
        self.assertIn("'--output'", self.script)

    def test_binds_source_build_package_and_sidecar_receipts(self):
        for field in ("source_sha", "archive_sha256", "sidecar_sha256", "build_receipt", "receipt.json", "artifact-receipt.json"):
            self.assertIn(field, self.script)
        self.assertIn("ZIP SHA-256 sidecar is malformed or mismatched", self.script)
        self.assertIn("Agent executable sidecar manifest is malformed or mismatched", self.script)

    def test_requires_private_nonadmin_disposable_staging_and_negative_cases(self):
        for guard in ("Administrator", "AreAccessRulesProtected", "ReparsePoint", "GetOwner", "must be empty", "wrong-digest", "wrong-target", "duplicate-entry.zip", "existing-output"):
            self.assertIn(guard, self.script)
        self.assertIn("Set-PrivateDirectory $stage", self.script)
        self.assertIn("[IO.Path]::Combine($disposable, ('hostlink-bootstrap-'", self.script)

    def test_output_receipt_is_checked_and_sensitive_fields_are_rejected(self):
        self.assertIn("Assert-OutputReceipt", self.script)
        self.assertIn("token|secret|credential|public.?key|invite|auth", self.script)
        self.assertIn("native bootstrap receipt does not match", self.script)
        self.assertIn("installed archive digest does not match independently selected source", self.script)
        self.assertIn("preserved manifest member digest or size mismatch", self.script)
        self.assertIn("preserved manifest member digest or size mismatch", self.script)
        self.assertIn("$Artifact.Files.Count + 3", self.script)

    def test_nt61_server_is_not_mislabeled_as_desktop_windows7(self):
        self.assertIn("Get-WmiObject -Class Win32_OperatingSystem", self.script)
        self.assertIn("this host is not desktop Windows 7", self.script)

    def test_source_stays_powershell_2_compatible(self):
        for unsupported in ("ConvertFrom-Json", "ConvertTo-Json", "ReadToEndAsync", "Start-Process -Verb RunAs"):
            self.assertNotIn(unsupported, self.script)
        self.assertIn("System.Web.Script.Serialization.JavaScriptSerializer", self.script)
        self.assertNotIn(".Dispose()", self.script)
        self.assertIn("$writer.Close()", self.script)
        self.assertIn("@(Get-ChildItem -LiteralPath $Output -Force | Where-Object { $_.PSIsContainer }).Count", self.script)
        # .NET 3.5 lacks the Path.Combine(string,string,string) overload.
        self.assertNotIn("::Combine($package, $Version,", self.script)
        self.assertIn("::Combine([IO.Path]::Combine($package, $Version), $archiveName)", self.script)

    def test_docs_label_host_os_and_show_invocation(self):
        self.assertIn("verify-win7-bootstrap-native.ps1", self.doc)
        self.assertIn("-DisposableRoot", self.doc)
        self.assertIn("-BuildRoot", self.doc)
        self.assertIn("WoW64", self.doc)
        self.assertIn("NT6.1", self.doc)


if __name__ == "__main__":
    unittest.main()
