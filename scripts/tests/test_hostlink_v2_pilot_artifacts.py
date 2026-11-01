"""Raw pilot artifacts using real packaging, Git and a tiny offline Cargo workspace."""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pilot_artifacts", SCRIPTS / "hostlink-v2-pilot.py")
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class PilotArtifactTests(unittest.TestCase):
    def setUp(self):
        # Model the stock CI runner without changing PATH or replacing services.
        which = shutil.which
        runtime_tools = {"caddy", "sshd", "openssl", "ssh-keygen", "ssh-keyscan"}
        lookup = patch.object(pilot.shutil, "which", side_effect=lambda name: (
            None if name in runtime_tools else which(name)))
        lookup.start()
        self.addCleanup(lookup.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="pilot artifacts ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "source repo"
        self.repo.mkdir()
        (self.repo / "scripts").mkdir()
        shutil.copyfile(SCRIPTS / "package-hostlink-agent.py", self.repo / "scripts/package-hostlink-agent.py")
        (self.repo / ".gitignore").write_text("target/\n", encoding="utf-8")
        self.version = "1.2.3"  # Must come from this source, not the pilot's VERSION constant.
        (self.repo / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["hub", "agent", "client"]\nresolver = "2"\n'
            f'[workspace.package]\nversion = "{self.version}"\n', encoding="utf-8")
        for folder, name in (("hub", "hostlink-hub"), ("agent", "hostlink-agent"), ("client", "hostlink")):
            crate = self.repo / folder
            (crate / "src").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion.workspace = true\nedition = "2021"\n', encoding="utf-8")
            (crate / "src/main.rs").write_text(f'fn main() {{ println!("{name} fixture"); }}\n', encoding="utf-8")
        self.command("cargo", "generate-lockfile", "--offline", "--manifest-path", str(self.repo / "Cargo.toml"))
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Pilot Test", "-c", "user.email=pilot@example.invalid", "commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.root = self.base / "private pilot"
        self.root.mkdir(mode=0o700)
        self.target = self.repo / "target"
        self.release = self.target / "release"
        self.release.mkdir(parents=True)
        self.names = {"hub": "hostlink-hub", "agent": "hostlink-agent", "client": "hostlink"}
        for name in self.names.values():
            (self.release / name).write_bytes(f"synthetic {name}\n".encode())
            (self.release / name).chmod(0o755)
        previous = os.environ.get("CARGO_TARGET_DIR")
        os.environ["CARGO_TARGET_DIR"] = str(self.target)
        self.addCleanup(self.restore_target_dir, previous)
        self.artifacts = self.root / "artifacts"
        self.receipt_path = self.artifacts / "artifact-receipt.json"
        self.asset = self.artifacts / f"hostlink-agent-{pilot.TARGET}"

    @staticmethod
    def restore_target_dir(previous):
        if previous is None:
            os.environ.pop("CARGO_TARGET_DIR", None)
        else:
            os.environ["CARGO_TARGET_DIR"] = previous

    def command(self, *args):
        result = subprocess.run(args, text=True, capture_output=True, timeout=60,
                                env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def git(self, *args):
        return self.command("git", "-C", str(self.repo), *args)

    def configure(self):
        return pilot.configure_artifacts(self.repo, self.root, self.sha)

    def package(self):
        self.command("python3", str(self.repo / "scripts/package-hostlink-agent.py"),
                     "--source-sha", self.sha, "--target", pilot.TARGET, "--version", self.version,
                     "--binary", str(self.release / "hostlink-agent"), "--output-dir", str(self.artifacts))
        return json.loads(self.receipt_path.read_text())

    def existing(self):
        receipt = self.package()
        dest = self.root / "bin"
        dest.mkdir(mode=0o700)
        hashes = {}
        for role, name in self.names.items():
            shutil.copyfile(self.release / name, dest / name)
            (dest / name).chmod(0o700)
            hashes[role] = pilot.digest(dest / name)
        pilot.private_write(self.root / "build-receipt.json", json.dumps({
            "schema": 1, "source_sha": self.sha, "binary_sha256": hashes}).encode())
        return receipt

    def write_receipt(self, value):
        self.receipt_path.write_text(json.dumps(value), encoding="utf-8")

    def test_cold_path_builds_real_source_and_packages_raw_bytes_without_runtime_tools(self):
        for name in ("caddy", "sshd", "openssl", "ssh-keygen", "ssh-keyscan"):
            self.assertIsNone(pilot.shutil.which(name))
        result = self.configure()
        receipt = result["receipt"]
        self.assertEqual(set(receipt), {"format", "source_sha", "target", "version", "asset",
                                        "asset_sha256", "asset_size", "build_receipt"})
        self.assertEqual(receipt["format"], 2)
        self.assertEqual(receipt["version"], self.version)
        self.assertIsNone(receipt["build_receipt"])
        self.assertEqual(receipt["source_sha"], self.sha)
        self.assertEqual(receipt["target"], pilot.TARGET)
        self.assertEqual(receipt["asset"], self.asset.name)
        self.assertEqual({p.name for p in self.artifacts.iterdir()}, {self.asset.name, self.receipt_path.name})
        self.assertEqual(receipt["asset_size"], self.asset.stat().st_size)
        self.assertEqual(receipt["asset_sha256"], hashlib.sha256(self.asset.read_bytes()).hexdigest())
        self.assertEqual(self.asset.read_bytes(), Path(result["binaries"]["agent"]).read_bytes())
        for role, name in self.names.items():
            copy = Path(result["binaries"][role])
            self.assertEqual(self.command(str(copy)), f"{name} fixture\n")
            self.assertEqual(copy.stat().st_mode & 0o777, 0o700)
            self.assertEqual(result["binary_sha256"][role], pilot.digest(copy))
        self.assertEqual(self.artifacts.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result, self.configure())

    def test_valid_existing_package_and_owned_copies_do_not_use_target_cache(self):
        receipt = self.existing()
        shutil.rmtree(self.target)
        result = self.configure()
        self.assertEqual(result["receipt"], receipt)
        self.assertEqual(result["binary_sha256"]["agent"], receipt["asset_sha256"])
        self.assertFalse(self.target.exists())

    def test_missing_copies_rebuild_all_roles_and_refuse_stale_packaged_agent(self):
        self.package()  # Synthetic target cache is not evidence of source provenance.
        with self.assertRaisesRegex(pilot.PilotError, "built Agent binary does not match"):
            self.configure()
        self.assertFalse((self.root / "bin").exists())
        for name in self.names.values():
            self.assertEqual(self.command(str(self.release / name)), f"{name} fixture\n")

    def test_retained_real_package_can_recreate_copies_with_relative_target_dir(self):
        result = self.configure()
        shutil.rmtree(self.root / "bin")
        (self.root / "build-receipt.json").unlink()
        # Remove the target cache so recreation must build from source again.
        shutil.rmtree(self.target)
        os.environ["CARGO_TARGET_DIR"] = "target"
        self.assertEqual(result, self.configure())

    def test_tampered_raw_bytes_are_rejected(self):
        self.existing()
        raw = self.asset.read_bytes()
        self.asset.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaisesRegex(pilot.PilotError, "SHA-256 changed"):
            self.configure()

    def test_receipt_schema_identity_and_size_fail_closed(self):
        receipt = self.existing()
        cases = [
            {**receipt, "format": 1}, {**receipt, "format": 2.0},
            {**receipt, "source_sha": "0" * 40}, {**receipt, "target": "x86_64-pc-windows-msvc"},
            {**receipt, "version": "9.9.9"}, {**receipt, "asset": "../hostlink-agent"},
            {**receipt, "asset": str(self.asset)}, {**receipt, "asset": "hostlink-agent.zip"},
            {**receipt, "asset_sha256": "0" * 64}, {**receipt, "asset_sha256": "A" * 64},
            {**receipt, "asset_sha256": None}, {**receipt, "asset_size": True},
            {**receipt, "asset_size": 0}, {**receipt, "asset_size": 256 * 1024 * 1024 + 1},
            {**receipt, "asset_size": receipt["asset_size"] + 1},
            {**receipt, "build_receipt": {}}, {**receipt, "unexpected": "field"},
            {key: value for key, value in receipt.items() if key != "asset_size"}, [], None,
            {"format": 1, "source_sha": self.sha, "target": pilot.TARGET, "version": self.version,
             "archive": "hostlink-agent.zip", "sidecar": "hostlink-agent", "installer": "install.sh"},
        ]
        for value in cases:
            with self.subTest(receipt=value):
                self.write_receipt(value)
                with self.assertRaises(pilot.PilotError):
                    self.configure()
        self.write_receipt(receipt)
        self.assertEqual(self.configure()["receipt"], receipt)

    def test_unexpected_artifact_members_including_old_zip_are_rejected(self):
        self.existing()
        for name in ("hostlink-agent.zip", "install.sh", "archive.sha256", "unknown"):
            with self.subTest(name=name):
                extra = self.artifacts / name
                extra.write_bytes(b"obsolete")
                with self.assertRaisesRegex(pilot.PilotError, "unexpected members"):
                    self.configure()
                extra.unlink()

    def test_symlinked_files_and_dangling_links_are_rejected(self):
        self.existing()
        for path in (self.asset, self.receipt_path, self.root / "build-receipt.json",
                     self.root / "bin/hostlink-hub", self.root / "bin/hostlink-agent", self.root / "bin/hostlink"):
            original = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            outside = self.base / "outside"
            outside.write_bytes(original)
            outside.chmod(mode)
            for target in (outside, self.base / "absent"):
                with self.subTest(path=path.name, target=target.name):
                    path.unlink()
                    path.symlink_to(target)
                    with self.assertRaises(pilot.PilotError):
                        self.configure()
            path.unlink()
            path.write_bytes(original)
            path.chmod(mode)
            self.assertEqual(outside.read_bytes(), original)

    def test_symlinked_or_public_directories_are_rejected(self):
        self.existing()
        for path in (self.root / "bin", self.artifacts):
            moved = self.base / "moved"
            path.rename(moved)
            path.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(pilot.PilotError):
                self.configure()
            path.unlink()
            moved.rename(path)
            path.chmod(0o755)
            with self.assertRaisesRegex(pilot.PilotError, "not private"):
                self.configure()
            path.chmod(0o700)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(pilot.PilotError, "not private"):
            self.configure()

    def test_nonregular_empty_oversized_and_public_files_are_rejected(self):
        self.existing()
        for path in (self.asset, self.receipt_path, self.root / "build-receipt.json", self.root / "bin/hostlink-hub"):
            original = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            for kind in ("empty", "oversized", "fifo", "directory", "public", "hardlink"):
                with self.subTest(path=path.name, kind=kind):
                    path.unlink()
                    if kind == "fifo":
                        os.mkfifo(path, mode)
                    elif kind == "directory":
                        path.mkdir(mode=0o700)
                    else:
                        path.write_bytes(original)
                        path.chmod(mode)
                        if kind in ("empty", "oversized"):
                            with path.open("wb") as stream:
                                stream.truncate(0 if kind == "empty" else 256 * 1024 * 1024 + 1)
                        elif kind == "public":
                            path.chmod(0o644)
                        else:
                            os.link(path, self.base / "hardlink")
                    with self.assertRaises(pilot.PilotError):
                        self.configure()
                    if kind == "directory":
                        path.rmdir()
                    else:
                        path.unlink()
                    if kind == "hardlink":
                        (self.base / "hardlink").unlink()
                    path.write_bytes(original)
                    path.chmod(mode)

    def test_malformed_receipts_are_rejected(self):
        self.existing()
        for path in (self.receipt_path, self.root / "build-receipt.json"):
            original = path.read_bytes()
            for value in (b"not JSON", b"\xff", b"[]", b"null", b"x" * 65537):
                with self.subTest(path=path.name, value=value[:12]):
                    path.write_bytes(value)
                    with self.assertRaises(pilot.PilotError):
                        self.configure()
            path.write_bytes(original)

    def test_binary_receipt_and_raw_agent_binding_are_checked(self):
        self.existing()
        path = self.root / "build-receipt.json"
        saved = json.loads(path.read_text())
        for value in ([], {**saved, "source_sha": "0" * 40}, {**saved, "schema": True},
                      {**saved, "binary_sha256": []}, {**saved, "binary_sha256": {"agent": "0" * 64}},
                      {**saved, "extra": True}, {**saved, "binary_sha256": {**saved["binary_sha256"], "hub": None}}):
            path.write_text(json.dumps(value))
            with self.assertRaises(pilot.PilotError):
                self.configure()
        path.write_text(json.dumps(saved))
        for role, name in self.names.items():
            binary = self.root / "bin" / name
            original = binary.read_bytes()
            binary.write_bytes(b"changed")
            with self.assertRaisesRegex(pilot.PilotError, f"{role} binary changed"):
                self.configure()
            binary.write_bytes(original)
        agent = self.root / "bin/hostlink-agent"
        agent.write_bytes(b"different but receipt-bound Agent")
        saved["binary_sha256"]["agent"] = pilot.digest(agent)
        path.write_text(json.dumps(saved))
        with self.assertRaisesRegex(pilot.PilotError, "stored Agent binary does not match"):
            self.configure()

    def test_orphan_build_receipt_is_rejected_before_rebuilding(self):
        self.existing()
        shutil.rmtree(self.root / "bin")
        original = (self.root / "build-receipt.json").read_bytes()
        with self.assertRaisesRegex(pilot.PilotError, "without the owned binary directory"):
            self.configure()
        self.assertFalse((self.root / "bin").exists())
        self.assertEqual((self.root / "build-receipt.json").read_bytes(), original)
        self.assertEqual((self.release / "hostlink-agent").read_bytes(), b"synthetic hostlink-agent\n")

    def test_dirty_source_or_wrong_source_pin_is_rejected(self):
        self.existing()
        with self.assertRaisesRegex(pilot.PilotError, "exact clean Git HEAD"):
            pilot.configure_artifacts(self.repo, self.root, "0" * 40)
        (self.repo / "untracked").write_text("dirty")
        with self.assertRaisesRegex(pilot.PilotError, "exact clean Git HEAD"):
            self.configure()


if __name__ == "__main__":
    unittest.main()
