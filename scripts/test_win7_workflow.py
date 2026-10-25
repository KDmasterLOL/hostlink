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

    def test_dispatch_is_manual_and_target_is_strictly_whitelisted(self) -> None:
        self.assertIn("on:\n  workflow_dispatch:\n", self.workflow)
        self.assertIn("    inputs:\n      target:\n", self.workflow)
        self.assertIn("        type: choice", self.workflow)
        self.assertIn("        required: true", self.workflow)
        self.assertIn("        default: x86_64-win7-windows-msvc", self.workflow)
        self.assertIn("          - x86_64-win7-windows-msvc\n          - i686-win7-windows-msvc", self.workflow)
        self.assertIn("$supportedTargets = @('x86_64-win7-windows-msvc', 'i686-win7-windows-msvc')", self.workflow)
        self.assertIn("$supportedTargets -cnotcontains $target", self.workflow)
        self.assertNotIn("  push:", self.workflow)
        self.assertNotIn("  pull_request:", self.workflow)
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertEqual(self.workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("retention-days: 3", self.workflow)
        self.assertIn("include-hidden-files: true", self.workflow)
        self.assertIn("if-no-files-found: error", self.workflow)
        self.assertNotIn("actions/upload-release-asset", self.workflow)

    def test_msvc_environment_selects_the_exact_architecture(self) -> None:
        self.assertIn("vcvars64.bat", self.workflow)
        self.assertIn("vcvarsall.bat", self.workflow)
        self.assertIn("`\"$vcvars`\" x64_x86", self.workflow)
        self.assertIn("VSCMD_ARG_HOST_ARCH -ne 'x64'", self.workflow)
        self.assertIn("VSCMD_ARG_TGT_ARCH -ne 'x86'", self.workflow)
        self.assertIn(r"\\lib\\x86$", self.workflow)
        self.assertIn(r"\\um\\x86$", self.workflow)
        self.assertIn(r"\\ucrt\\x86$", self.workflow)
        self.assertIn("$env:GITHUB_ENV", self.workflow)
        self.assertIn("'PATH', 'INCLUDE', 'LIB', 'LIBPATH'", self.workflow)
        self.assertIn("$vcvarsLabel did not configure required", self.workflow)

    def test_pinned_build_is_static_crt_and_has_no_pc_windows_fallback(self) -> None:
        self.assertIn("nightly-2026-08-22", self.workflow)
        self.assertIn("--component rust-src", self.workflow)
        self.assertIn("-Z build-std=std,panic_abort build --release --locked", self.workflow)
        self.assertIn("RUSTFLAGS: '-C target-feature=+crt-static'", self.workflow)
        self.assertIn("Build output does not show std/panic_abort compilation", self.workflow)
        self.assertIn("Win7 candidate still imports a dynamic CRT", self.workflow)
        self.assertIn("x86_64-win7-windows-msvc", self.workflow)
        self.assertIn("i686-win7-windows-msvc", self.workflow)
        self.assertIn(r"14C machine \(x86\)", self.workflow)
        self.assertIn("pe_machine=i386 (0x14C)", self.workflow)
        self.assertIn(r"8664 machine \(x64\)", self.workflow)
        self.assertIn("pe_machine=AMD64 (0x8664)", self.workflow)
        self.assertIn("--target $target", self.workflow)
        self.assertNotIn("x86_64-pc-windows-msvc", self.workflow)
        self.assertNotIn("i686-pc-windows-msvc", self.workflow)
        self.assertIn("source_sha=$head", self.workflow)
        self.assertIn("source_tree_sha=$tree", self.workflow)
        self.assertIn("crt_mode=static", self.workflow)
        self.assertIn("dynamic_crt_imports=none", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)

    def test_agent_zip_and_raw_binary_are_target_scoped_and_checked(self) -> None:
        self.assertIn(
            "python scripts/package_hostlink.py agent $target .dist/staging .dist/out",
            self.workflow,
        )
        self.assertIn("$rawOut = \".dist/out/$target/hostlink-agent.exe\"", self.workflow)
        self.assertIn("$rawSidecarPath = \"$rawOut.sha256\"", self.workflow)
        self.assertIn("$archive = \".dist/out/hostlink-agent-$target.zip\"", self.workflow)
        self.assertIn('"hostlink-agent-$target/hostlink-agent.exe"', self.workflow)
        for script in (
            "Install-HostLink-Agent.ps1",
            "Run-HostLink-Agent.ps1",
            "Update-HostLink-Agent.ps1",
        ):
            with self.subTest(script=script):
                self.assertIn(script, self.workflow)
        self.assertIn('"$rawOut.sha256"', self.workflow)
        self.assertIn("$zip.Entries", self.workflow)
        self.assertIn("ZIP inventory mismatch", self.workflow)
        self.assertIn("'onec.exe'", self.workflow)


if __name__ == "__main__":
    unittest.main()
