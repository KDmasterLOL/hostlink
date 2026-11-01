"""Raw binary packaging against a real, disposable Git source tree."""
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "package-hostlink-agent.py"
spec = importlib.util.spec_from_file_location("package_hostlink_agent", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageHostlinkAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Package Test")
        (self.root / "fixture.txt").write_text("source", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD").strip()
        self.binary = self.base / "hostlink-agent"
        self.binary.write_bytes(b"synthetic executable fixture\n")
        self.out = self.base / "package"

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *args], text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})

    def make(self, target="x86_64-unknown-linux-gnu", receipt=None, output=None):
        return package.create_package(self.root, self.sha, target, "1.2.3", self.binary,
                                      output or self.out, receipt)

    def pe(self, target):
        image = bytearray(128)
        image[:2] = b"MZ"
        image[0x3C:0x40] = (64).to_bytes(4, "little")
        image[64:68] = b"PE\0\0"
        machine = 0x8664 if target.startswith("x86_64-") else 0x14C
        image[68:70] = machine.to_bytes(2, "little")
        self.binary.write_bytes(image)
        receipt = self.base / "build-receipt.json"
        receipt.write_text(json.dumps({
            "status": "PE_BUILD_AND_INSPECTION_PASS", "source": {"git_sha": self.sha},
            "native_acceptance": {"status": "NOT_RUN"},
            "targets": [{"target": target, "binaries": [{
                "file": "hostlink-agent.exe", "sha256": package.digest(self.binary),
                "pe_machine": hex(machine), "subsystem": {"major": 6, "minor": 0},
                "static_crt_import_check": "passed"}]}],
        }))
        return receipt

    def test_source_exact_raw_bytes_and_local_provenance_only(self):
        receipt = self.make()
        name = "hostlink-agent-x86_64-unknown-linux-gnu"
        self.assertEqual({p.name for p in self.out.iterdir()}, {name, "artifact-receipt.json"})
        self.assertEqual((self.out / name).read_bytes(), self.binary.read_bytes())
        self.assertEqual(receipt["asset_sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.assertEqual(receipt["asset_size"], self.binary.stat().st_size)
        self.assertEqual(receipt["source_sha"], self.sha)
        self.assertEqual(receipt, json.loads((self.out / "artifact-receipt.json").read_text()))
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.out / name).stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.out / "artifact-receipt.json").stat().st_mode), 0o600)
        second = self.base / "again"
        self.assertEqual(receipt, self.make(output=second))
        self.assertEqual((second / name).read_bytes(), self.binary.read_bytes())

    def test_preserves_packaging_cli_with_real_source_tree(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        script = scripts / SCRIPT.name
        shutil.copyfile(SCRIPT, script)
        self.git("add", "scripts")
        self.git("commit", "-qm", "source-exact packager")
        sha = self.git("rev-parse", "HEAD").strip()
        command = ["python3", str(script), "--source-sha", sha,
                   "--target", "x86_64-unknown-linux-gnu", "--version", "1.2.3",
                   "--binary", str(self.binary), "--output-dir", str(self.out)]
        result = subprocess.run(command, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["source_sha"], sha)
        result = subprocess.run(command, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be new", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_refuses_wrong_head_dirty_source_and_existing_output(self):
        with self.assertRaisesRegex(ValueError, "worktree HEAD"):
            package.create_package(self.root, "0" * 40, "x86_64-unknown-linux-gnu", "1.2.3", self.binary, self.out)
        for dirty in (self.root / "untracked", self.root / "fixture.txt"):
            dirty.write_text("dirty")
            with self.assertRaisesRegex(ValueError, "worktree must be clean"):
                self.make()
            if dirty.name == "untracked":
                dirty.unlink()
            else:
                dirty.write_text("source")
        self.make()
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.make()

    def test_every_windows_raw_asset_and_win7_build_binding(self):
        for target in package.TARGETS:
            if "windows" not in target:
                continue
            with self.subTest(target=target):
                build = self.pe(target)
                out = self.base / target
                if "win7" in target:
                    with self.assertRaisesRegex(ValueError, "require.*PE build receipt"):
                        self.make(target, output=out)
                receipt = self.make(target, build, out)
                name = f"hostlink-agent-{target}.exe"
                self.assertEqual(receipt["asset"], name)
                self.assertEqual((out / name).read_bytes(), self.binary.read_bytes())
                self.assertEqual(receipt["build_receipt"]["sha256"], package.digest(build))

    def test_build_receipt_rejects_each_mismatched_identity_and_pe_proof(self):
        target = "x86_64-win7-windows-msvc"
        path = self.pe(target)
        original = json.loads(path.read_text())
        mutations = [("source", {"git_sha": "0" * 40}), ("status", "NOT_RUN")]
        for field, value in mutations:
            receipt = {**original, field: value}
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                self.make(target, path)
        for field, value in (("sha256", "0" * 64), ("pe_machine", "0x14c"),
                             ("subsystem", "6.1"), ("static_crt_import_check", "failed")):
            receipt = json.loads(json.dumps(original))
            receipt["targets"][0]["binaries"][0][field] = value
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                self.make(target, path)
        path.write_text(json.dumps(original))
        with self.assertRaises(ValueError):
            package.verify_build_receipt(path, self.sha, "i686-win7-windows-msvc", package.digest(self.binary))
        with self.assertRaisesRegex(ValueError, "Machine does not match"):
            package.validate_pe(self.binary, "i686-win7-windows-msvc")
        self.binary.write_bytes(b"not a PE")
        with self.assertRaisesRegex(ValueError, "not a PE"):
            self.make(target, path)

    def test_refuses_symlinks_empty_input_invalid_target_and_version(self):
        self.binary.unlink()
        self.binary.symlink_to(self.root / "fixture.txt")
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            self.make()
        self.binary.unlink()
        self.binary.touch()
        with self.assertRaisesRegex(ValueError, "size"):
            self.make()
        self.binary.write_bytes(b"binary")
        with self.assertRaisesRegex(ValueError, "unsupported target"):
            self.make("x86_64-pc-windows-gnu")
        self.assertFalse(package.valid_semver("01.2.3"))
        with self.assertRaisesRegex(ValueError, "semantic version"):
            package.create_package(self.root, self.sha, "x86_64-unknown-linux-gnu", "../bad", self.binary, self.out)
        parent = self.base / "linked"
        parent.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "parent path contains a symlink"):
            self.make(output=parent / "new-output")


if __name__ == "__main__":
    unittest.main()
