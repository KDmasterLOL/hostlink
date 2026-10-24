"""Offline release artifact contract tests: no Rust build or managed hosts involved."""
from __future__ import annotations

import hashlib
import os
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from package_hostlink import FILES, package


class PackageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "src"
        self.output = self.base / "out"
        self.source.mkdir()
        self.output.mkdir()

    def source_files(self, component: str, target: str) -> None:
        key = "windows" if "windows" in target else "linux"
        for file in FILES[component][key]:
            (self.source / file).write_bytes(("fixture:" + file).encode())

    def test_agent_archive_is_deterministic_exact_and_has_no_toolkit_executable(self) -> None:
        target = "x86_64-win7-windows-msvc"
        self.source_files("agent", target)
        archive, checksum = package("agent", target, self.source, self.output)
        name = f"hostlink-agent-{target}"
        with ZipFile(archive) as obj:
            names = obj.namelist()
            self.assertEqual(names, [f"{name}/{x}" for x in FILES["agent"]["windows"]])
            self.assertFalse(any("onec.exe" in x or "onec-toolkit" in x for x in names))
            self.assertIsNone(obj.testzip())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.assertEqual(checksum.read_text(), f"{digest}  {archive.name}\n")
        self.assertRaises(FileExistsError, package, "agent", target, self.source, self.output)
        other = self.base / "other"
        other.mkdir()
        b, _ = package("agent", target, self.source, other)
        self.assertEqual(archive.read_bytes(), b.read_bytes())

    def test_missing_file_invalid_target_and_symlink_rejected_without_output(self) -> None:
        self.assertRaises(ValueError, package, "agent", "unknown", self.source, self.output)
        self.assertRaises(
            ValueError, package, "agent", "x86_64-pc-windows-msvc", self.source, self.output
        )
        self.source_files("controller", "x86_64-pc-windows-msvc")
        (self.source / "hostlink.exe").unlink()
        (self.source / "hostlink.exe").symlink_to(self.base / "outside")
        self.assertRaises(
            ValueError, package, "controller", "x86_64-pc-windows-msvc", self.source, self.output
        )
        self.assertEqual(list(self.output.iterdir()), [])

    def test_concurrent_sidecar_collision_preserves_other_output(self) -> None:
        target = "x86_64-pc-windows-msvc"
        self.source_files("controller", target)
        stem = f"hostlink-controller-{target}"
        archive = self.output / f"{stem}.zip"
        sidecar = self.output / f"{stem}.zip.sha256"
        original_link = os.link

        def concurrent_publish(source: str | os.PathLike[str], dest: str | os.PathLike[str]) -> None:
            if Path(dest) == sidecar:
                sidecar.write_text("other-publisher\\n")
                raise FileExistsError("concurrent publication")
            original_link(source, dest)

        with patch("package_hostlink.os.link", side_effect=concurrent_publish):
            with self.assertRaises(FileExistsError):
                package("controller", target, self.source, self.output)
        self.assertFalse(archive.exists(), "partial archive must be withdrawn")
        self.assertEqual(sidecar.read_text(), "other-publisher\\n")

    def test_hub_linux_archive(self) -> None:
        target = "x86_64-unknown-linux-gnu"
        self.source_files("hub", target)
        archive, _ = package("hub", target, self.source, self.output)
        with ZipFile(archive) as f:
            self.assertEqual(f.namelist(), [f"hostlink-hub-{target}/hostlink-hub"])
        self.assertRaises(ValueError, package, "hub", "i686-win7-windows-msvc", self.source, self.output)


if __name__ == "__main__":
    unittest.main()
