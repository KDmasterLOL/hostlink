#!/usr/bin/env python3
"""Focused static contract checks for the NT6.1 side-by-side harness."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts" / "verify-win7-side-by-side.ps1"
DOC = ROOT / "docs" / "WIN7_REWRITE_ACCEPTANCE.md"
BOOTSTRAP_HELPER = ROOT / "scripts" / "verify-win7-bootstrap-native.ps1"


class Win7SideBySideContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = HARNESS.read_text(encoding="utf-8")
        cls.doc = DOC.read_text(encoding="utf-8")
        cls.bootstrap = BOOTSTRAP_HELPER.read_text(encoding="utf-8")

    def test_exact_inputs_and_nt61_win7_sp1_gate(self):
        for argument in ("SourceSha", "BuildRoot", "X64PackageRoot", "X86PackageRoot", "DisposableRoot"):
            self.assertIn("[string]$" + argument, self.script)
        self.assertIn("^6\\.1\\.7601", self.script)
        self.assertIn("Windows 7", self.script)
        self.assertIn("ServicePackMajorVersion", self.script)
        self.assertIn("requires a 64-bit Windows 7 OS", self.script)

    def test_preflights_user_owned_private_nonadmin_nonreparse_root(self):
        for invariant in ("Administrator", "AreAccessRulesProtected", "GetOwner", "ReparsePoint", "grants access to another identity", "must be empty", "SessionId"):
            self.assertIn(invariant, self.script)
        self.assertIn("Set-PrivateDirectory $run $sid", self.script)

    def test_executes_both_real_targets_and_records_stream_receipts(self):
        self.assertIn("x86_64-win7-windows-msvc", self.script)
        self.assertIn("i686-win7-windows-msvc", self.script)
        self.assertIn("@('--version')", self.script)
        self.assertIn("'bootstrap-verify','--archive'", self.script)
        for negative in ("wrong-digest", "wrong-target", "duplicate-entry.zip", "existing-output"):
            self.assertIn(negative, self.bootstrap)
        self.assertIn("malformed-archive.bin", self.script)
        self.assertIn("verify-win7-bootstrap-native.ps1", self.script)
        for field in ("stdout_sha256", "stderr_sha256", "artifact_sha256", "exit_code", "cleanup_outcome"):
            self.assertIn(field, self.script)

    def test_no_install_or_enrollment_actions_and_powershell2_syntax_contract(self):
        self.assertNotIn("bootstrap-finalize", self.script)
        self.assertNotIn("Service\\", self.script)
        self.assertNotIn("Enroll", self.script)
        for unsupported in ("ConvertFrom-Json", "ReadToEndAsync", "Start-Process -Verb RunAs"):
            self.assertNotIn(unsupported, self.script)
        self.assertIn("System.Web.Script.Serialization.JavaScriptSerializer", self.script)
        self.assertNotIn("$process.Dispose()", self.script)
        self.assertNotIn("::Combine($X64PackageRoot, $x64Version,", self.script)
        self.assertNotIn("::Combine($X86PackageRoot, $x86Version,", self.script)

    def test_documentation_uses_exact_invocation_and_distinguishes_wow64(self):
        self.assertIn("verify-win7-side-by-side.ps1", self.doc)
        self.assertIn("-SourceSha", self.doc)
        self.assertIn("-DisposableRoot", self.doc)
        self.assertIn("WOW64 execution on Windows 7 x64", self.doc)
        self.assertIn("Windows 7 OS remains unproven", self.doc)


if __name__ == "__main__":
    unittest.main()
