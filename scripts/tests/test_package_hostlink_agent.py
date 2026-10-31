import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "package-hostlink-agent.py"
spec = importlib.util.spec_from_file_location("package_hostlink_agent", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageHostlinkAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()
        (self.root / "crates/agent/assets").mkdir(parents=True)
        shutil.copy(Path(__file__).resolve().parents[2] / "crates/agent/assets/install-hostlink-agent.sh", self.root / "crates/agent/assets/install-hostlink-agent.sh")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Package Test"], check=True)
        (self.root / "fixture.txt").write_text("source", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()
        self.binary = Path(self.temp.name) / "hostlink-agent"
        self.binary.write_bytes(b"fixture linux executable\n")
        self.out = Path(self.temp.name) / "published"

    def tearDown(self):
        self.temp.cleanup()

    def make(self):
        return package.create_package(self.root, self.sha, "x86_64-unknown-linux-gnu", "1.2.3", self.binary, self.out)

    def test_source_exact_deterministic_layout_and_hashes(self):
        first = self.make()
        archive = self.out / "1.2.3/hostlink-agent-x86_64-unknown-linux-gnu.zip"
        first_bytes = archive.read_bytes()
        self.assertEqual(package.digest(archive), first["archive_sha256"])
        with zipfile.ZipFile(archive) as zf:
            self.assertEqual(zf.namelist(), [
                "hostlink-agent-x86_64-unknown-linux-gnu/hostlink-agent",
                "hostlink-agent-x86_64-unknown-linux-gnu/manifest.json",
            ])
            manifest = json.loads(zf.read(zf.namelist()[-1]))
            self.assertEqual(manifest["format"], 2)
            self.assertEqual(manifest["target"], "x86_64-unknown-linux-gnu")
            self.assertEqual(manifest["component"], "agent")
            self.assertEqual(manifest["files"]["hostlink-agent"]["sha256"], hashlib.sha256(self.binary.read_bytes()).hexdigest())
            self.assertEqual((zf.getinfo(zf.namelist()[0]).external_attr >> 16) & 0o777, 0o755)
        self.assertTrue((self.out / "invite-inputs.json").is_file())
        self.assertTrue((self.out / "artifact-receipt.json").is_file())
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o700)
        self.assertEqual(first_bytes, archive.read_bytes())
        second_out = Path(self.temp.name) / "published-again"
        package.create_package(self.root, self.sha, "x86_64-unknown-linux-gnu", "1.2.3", self.binary, second_out)
        self.assertEqual(first_bytes, (second_out / "1.2.3/hostlink-agent-x86_64-unknown-linux-gnu.zip").read_bytes())

    def test_refuses_nonclean_source_and_existing_output(self):
        (self.root / "dirty").write_text("dirty", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "worktree must be clean"):
            self.make()
        (self.root / "dirty").unlink()
        self.make()
        with self.assertRaisesRegex(ValueError, "must be new"):
            self.make()

    def test_build_receipt_is_bound_to_source_target_and_binary_digest(self):
        binary_sha = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        receipt = Path(self.temp.name) / "receipt.json"
        receipt.write_text(json.dumps({
            "status": "PE_BUILD_AND_INSPECTION_PASS",
            "source": {"git_sha": self.sha},
            "targets": [{"target": "x86_64-win7-windows-msvc", "binaries": [
                {"file": "hostlink-agent.exe", "sha256": binary_sha,
                 "pe_machine": "0x8664",
                 "subsystem": {"major": 6, "minor": 0},
                 "static_crt_import_check": "passed"}
            ]}],
        }), encoding="utf-8")
        self.assertEqual(package.verify_build_receipt(receipt, self.sha, "x86_64-win7-windows-msvc", binary_sha)["sha256"], package.digest(receipt))
        with self.assertRaisesRegex(ValueError, "source SHA"):
            package.verify_build_receipt(receipt, "0" * 40, "x86_64-win7-windows-msvc", binary_sha)
        # The first source-exact Win7 x64/x86 PE receipt used this valid
        # independently checked schema, before the official builder shipped.
        receipt.write_text(json.dumps({
            "result": "PE_BUILD_AND_INSPECTION_PASS",
            "source": {"git_sha": self.sha},
            "targets": [{"target": "x86_64-win7-windows-msvc", "artifacts": [
                {"name": "hostlink-agent.exe", "sha256": binary_sha,
                 "pe_machine": "0x8664", "subsystem": "6.0",
                 "dynamic_crt_imports_absent": True}
            ]}],
        }), encoding="utf-8")
        self.assertEqual(
            package.verify_build_receipt(receipt, self.sha, "x86_64-win7-windows-msvc", binary_sha)["sha256"],
            package.digest(receipt),
        )
        tampered = json.loads(receipt.read_text(encoding="utf-8"))
        tampered["targets"][0]["artifacts"][0]["dynamic_crt_imports_absent"] = False
        receipt.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "CRT"):
            package.verify_build_receipt(receipt, self.sha, "x86_64-win7-windows-msvc", binary_sha)

    def test_windows_installer_contract_and_pe_machine_checks(self):
        installer = Path(__file__).resolve().parents[2] / "crates/agent/assets/Install-HostLink-Agent.ps1"
        package.verify_installer(installer, "windows")
        incomplete = Path(self.temp.name) / "incomplete.ps1"
        incomplete.write_text(installer.read_text(encoding="utf-8").replace("bootstrap-finalize", "bootstrap-finialize"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "installer contract"):
            package.verify_installer(incomplete, "windows")
        pe = Path(self.temp.name) / "agent.exe"
        image = bytearray(128)
        image[:2] = b"MZ"
        image[0x3C:0x40] = (64).to_bytes(4, "little")
        image[64:68] = b"PE\0\0"
        image[68:70] = (0x8664).to_bytes(2, "little")
        pe.write_bytes(image)
        package.validate_pe(pe, "x86_64-pc-windows-msvc")
        with self.assertRaisesRegex(ValueError, "Machine does not match"):
            package.validate_pe(pe, "i686-win7-windows-msvc")

    def test_refuses_symlink_input_and_invalid_target_or_version(self):
        self.binary.unlink()
        self.binary.symlink_to(self.root / "fixture.txt")
        with self.assertRaisesRegex(ValueError, "regular non-symlink"):
            self.make()
        self.binary.unlink()
        self.binary.write_bytes(b"binary")
        with self.assertRaisesRegex(ValueError, "unsupported target"):
            package.create_package(self.root, self.sha, "x86_64-pc-windows-gnu", "1.2.3", self.binary, self.out)
        self.assertFalse(package.valid_semver("01.2.3"))
        with self.assertRaisesRegex(ValueError, "semantic version"):
            package.create_package(self.root, self.sha, "x86_64-unknown-linux-gnu", "latest", self.binary, self.out)


if __name__ == "__main__":
    unittest.main()
