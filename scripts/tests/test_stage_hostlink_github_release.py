import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "stage-hostlink-github-release.py"
spec = importlib.util.spec_from_file_location("github_stage", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class GitHubReleaseStagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "release"
        self.source = "a" * 40

    def fixture(self, target, version="1.2.3", source=None, installer_content=b"installer"):
        parent = self.root / target
        version_dir = parent / version
        sidecar_dir = version_dir / target
        sidecar_dir.mkdir(parents=True)
        windows = "windows" in target
        executable = "hostlink-agent.exe" if windows else "hostlink-agent"
        installer = "Install-HostLink-Agent.ps1" if windows else "install-hostlink-agent.sh"
        zip_name = f"hostlink-agent-{target}.zip"
        body = f"binary for {target}".encode()
        (sidecar_dir / executable).write_bytes(body)
        (version_dir / installer).write_bytes(installer_content)
        sha = lambda data: hashlib.sha256(data).hexdigest()
        manifest = {"format": 2, "component": "agent", "target": target,
                    "version": version, "files": {executable: {"size": len(body), "sha256": sha(body)}}}
        archive = version_dir / zip_name
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr(f"hostlink-agent-{target}/{executable}", body)
            zf.writestr(f"hostlink-agent-{target}/manifest.json", json.dumps(manifest))
        receipt = {"source_sha": source or self.source, "target": target, "version": version,
                   "archive": zip_name, "archive_sha256": sha(archive.read_bytes()),
                   "sidecar": f"{version}/{target}/{executable}", "sidecar_sha256": sha(body),
                   "installer": installer, "installer_sha256": sha(installer_content)}
        (parent / "artifact-receipt.json").write_text(json.dumps(receipt))
        return parent

    def test_flattens_linux_and_windows_assets_without_collisions(self):
        linux = self.fixture("x86_64-unknown-linux-gnu")
        win = self.fixture("x86_64-win7-windows-msvc")
        staged = release.stage([linux, win], self.out)
        self.assertEqual(staged["source_sha"], self.source)
        self.assertEqual(len(staged["assets"]), 6)
        self.assertIn("hostlink-agent-x86_64-win7-windows-msvc.exe", staged["assets"])
        self.assertIn("hostlink-agent-x86_64-unknown-linux-gnu.zip", staged["assets"])
        self.assertFalse((self.out / "hostlink-agent.exe").exists())
        self.assertTrue((self.out / ".release-receipt.json").is_file())

    def test_refuses_tampered_asset_before_publication(self):
        source = self.fixture("x86_64-unknown-linux-gnu")
        (source / "1.2.3/install-hostlink-agent.sh").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "differs from package receipt"):
            release.stage([source], self.out)
        self.assertFalse(self.out.exists())

    def test_refuses_mixed_source_or_version(self):
        linux = self.fixture("x86_64-unknown-linux-gnu")
        win = self.fixture("x86_64-win7-windows-msvc", source="b" * 40)
        with self.assertRaisesRegex(ValueError, "different versions or source"):
            release.stage([linux, win], self.out)
        self.assertFalse(self.out.exists())

    def test_require_all_targets_fail_closed(self):
        linux = self.fixture("x86_64-unknown-linux-gnu")
        with self.assertRaisesRegex(ValueError, "every supported"):
            release.stage([linux], self.out, require_all_targets=True)

    def test_refuses_existing_output_and_duplicate_target(self):
        linux = self.fixture("x86_64-unknown-linux-gnu")
        with self.assertRaisesRegex(ValueError, "duplicate release target"):
            release.stage([linux, linux], self.out)
        release.stage([linux], self.out)
        with self.assertRaisesRegex(ValueError, "new directory"):
            release.stage([linux], self.out)


if __name__ == "__main__":
    unittest.main()
