"""Exercise real packaging → release staging using disposable Git/PE fixtures."""
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
import test_package_hostlink_agent as fixtures

package = fixtures.package

SCRIPT = Path(__file__).resolve().parents[1] / "stage-hostlink-github-release.py"
spec = importlib.util.spec_from_file_location("github_stage", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class GitHubReleaseStagingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PackageHostlinkAgentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.base
        self.out = self.root / "release"

    def packaged(self, target="x86_64-unknown-linux-gnu"):
        receipt = self.fixture.pe(target) if "windows" in target else None
        out = self.root / target
        self.fixture.make(target, receipt, out)
        return out

    def test_all_four_assets_source_exact_no_wrappers_or_published_metadata(self):
        inputs = [self.packaged(t) for t in package.TARGETS]
        staged = release.stage(inputs, self.out, require_all_targets=True)
        expected = {f"hostlink-agent-{t}" + (".exe" if "windows" in t else "") for t in package.TARGETS}
        self.assertEqual(set(staged["assets"]), expected)
        self.assertEqual({p.name for p in self.out.iterdir()}, expected | {".release-receipt.json"})
        self.assertEqual(staged["source_sha"], self.fixture.sha)
        self.assertEqual(staged, json.loads((self.out / ".release-receipt.json").read_text()))
        for directory in inputs:
            receipt = json.loads((directory / "artifact-receipt.json").read_text())
            name = receipt["asset"]
            self.assertEqual((self.out / name).read_bytes(), (directory / name).read_bytes())
            self.assertEqual(staged["assets"][name], receipt["asset_sha256"])
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o700)

    def test_preserves_staging_cli_and_require_all_targets(self):
        source = self.packaged()
        command = ["python3", str(SCRIPT), "--package-dir", str(source),
                   "--output-dir", str(self.out)]
        result = subprocess.run(command + ["--require-all-targets"], text=True,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("every supported", result.stderr)
        self.assertFalse(self.out.exists())
        result = subprocess.run(command, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["assets"]), 1)

    def test_refuses_tampered_binary_or_size_and_legacy_extra_files(self):
        source = self.packaged()
        receipt_path = source / "artifact-receipt.json"
        receipt = json.loads(receipt_path.read_text())
        asset = source / receipt["asset"]
        original = asset.read_bytes()
        asset.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "differs from package receipt"):
            release.stage([source], self.out)
        asset.write_bytes(original)
        receipt_path.write_text(json.dumps({**receipt, "asset_size": 1}))
        with self.assertRaisesRegex(ValueError, "size differs"):
            release.stage([source], self.out)
        receipt_path.write_text(json.dumps(receipt))
        for obsolete in ("bundle.zip", "manifest.json", "Install-HostLink-Agent.ps1", "archive.sha256", "bootstrap-receipt.json"):
            extra = source / obsolete
            extra.touch()
            with self.assertRaisesRegex(ValueError, "exactly one raw binary"):
                release.stage([source], self.out)
            extra.unlink()
        self.assertFalse(self.out.exists())

    def test_refuses_mixed_source_or_version_duplicate_and_missing_targets(self):
        linux = self.packaged()
        win = self.packaged("x86_64-win7-windows-msvc")
        path = win / "artifact-receipt.json"
        receipt = json.loads(path.read_text())
        for field, value in (("source_sha", "b" * 40), ("version", "9.9.9")):
            path.write_text(json.dumps({**receipt, field: value}))
            with self.assertRaisesRegex(ValueError, "different versions or source"):
                release.stage([linux, win], self.out)
        path.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "duplicate release target"):
            release.stage([linux, linux], self.out)
        with self.assertRaisesRegex(ValueError, "every supported"):
            release.stage([linux], self.out, True)
        self.assertFalse(self.out.exists())
        release.stage([linux], self.out)
        with self.assertRaisesRegex(ValueError, "new directory"):
            release.stage([linux], self.out)

    def test_refuses_unsafe_receipt_paths_hashes_and_links(self):
        source = self.packaged()
        path = source / "artifact-receipt.json"
        receipt = json.loads(path.read_text())
        for field, value in (("format", 1), ("asset", "../outside"), ("version", "../bad"),
                             ("source_sha", "bad"), ("asset_sha256", None), ("asset_size", True)):
            path.write_text(json.dumps({**receipt, field: value}))
            with self.assertRaises(ValueError):
                release.stage([source], self.out)
        path.write_text(json.dumps(receipt))
        asset = source / receipt["asset"]
        external = self.root / "external"
        asset.rename(external)
        asset.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "invalid release input"):
            release.stage([source], self.out)
        asset.unlink()
        asset.hardlink_to(external)
        with self.assertRaisesRegex(ValueError, "invalid release input"):
            release.stage([source], self.out)
        asset.unlink()
        external.rename(asset)
        linked = self.root / "linked-parent"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "parent must be an existing directory"):
            release.stage([source], linked / "release")


if __name__ == "__main__":
    unittest.main()
