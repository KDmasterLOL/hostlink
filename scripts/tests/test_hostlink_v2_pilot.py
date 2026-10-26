#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "hostlink-v2-pilot.sh"


class PilotLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hostlink pilot tests ")
        self.base = Path(self.temp.name)
        self.repo = self.base / "source repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.repo / "scripts" / SCRIPT.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Pilot Test"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "pilot-test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "scripts"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "test source"], check=True)
        self.sha = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.script = self.repo / "scripts" / SCRIPT.name
        self.root = self.base / "private pilot root"

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, *args, expected=0):
        result = subprocess.run([str(self.script), *args], text=True, capture_output=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def prepare(self, root=None, sha=None, expected=0):
        return self.run_cli("prepare", "--root", str(root or self.root), "--source-sha", sha or self.sha, expected=expected)

    def test_prepare_is_private_idempotent_and_source_pinned(self):
        result = self.prepare()
        self.assertIn("PREPARED", result.stdout)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        marker = json.loads((self.root / ".hostlink-v2-pilot.json").read_text())
        self.assertEqual(marker, {"schema": 1, "uid": os.getuid(), "source_sha": self.sha})
        self.assertEqual((self.root / ".hostlink-v2-pilot.json").stat().st_mode & 0o777, 0o600)
        self.prepare()
        self.prepare(sha="0" * 40, expected=2)

    def test_relative_and_symlink_paths_are_rejected(self):
        self.prepare(root=Path("relative-pilot"), expected=2)
        target = self.base / "real target"
        target.mkdir()
        link = self.base / "pilot link"
        link.symlink_to(target, target_is_directory=True)
        self.prepare(root=link, expected=2)

    def test_status_and_down_preserve_stopped_data(self):
        self.prepare()
        (self.root / "logs" / "pilot.log").write_text("owned log\n")
        self.assertIn("PREPARED", self.run_cli("status", "--root", str(self.root)).stdout)
        self.assertIn("owned log", self.run_cli("logs", "--root", str(self.root)).stdout)
        self.assertIn("already stopped", self.run_cli("down", "--root", str(self.root)).stdout)
        self.assertTrue((self.root / ".hostlink-v2-pilot.json").exists())

    def test_logs_are_bounded_and_help_is_available(self):
        self.assertIn("Usage:", self.run_cli("--help").stdout)
        self.prepare()
        (self.root / "logs" / "huge.log").write_bytes(b"x" * (1024 * 1024 + 1))
        self.run_cli("logs", "--root", str(self.root), expected=2)

    def test_malformed_or_foreign_marker_fails_closed(self):
        self.prepare()
        marker = self.root / ".hostlink-v2-pilot.json"
        marker.write_text("not json")
        self.run_cli("status", "--root", str(self.root), expected=2)
        marker.write_text(json.dumps({"schema": 1, "uid": os.getuid() + 1, "source_sha": self.sha}))
        self.run_cli("purge", "--root", str(self.root), expected=2)

    def test_foreign_or_unknown_process_and_unknown_jobs_are_never_touched(self):
        self.prepare()
        foreign = os.getpid()
        (self.root / "processes.json").write_text(json.dumps({"state": "running", "items": [foreign]}))
        self.assertIn("OWNED-PROCESS-UNKNOWN", self.run_cli("status", "--root", str(self.root)).stdout)
        self.run_cli("down", "--root", str(self.root), expected=2)
        self.run_cli("purge", "--root", str(self.root), expected=2)
        os.kill(foreign, 0)
        (self.root / "processes.json").unlink()
        (self.root / "jobs.json").write_text(json.dumps({"state": "unknown", "items": ["job"]}))
        self.run_cli("purge", "--root", str(self.root), expected=2)
        self.assertTrue(self.root.exists())

    def test_purge_refuses_links_and_unowned_entries_then_removes_owned_root(self):
        self.prepare()
        outside = self.base / "outside"
        outside.write_text("keep")
        (self.root / "link").symlink_to(outside)
        self.run_cli("purge", "--root", str(self.root), expected=2)
        self.assertEqual(outside.read_text(), "keep")
        (self.root / "link").unlink()
        self.run_cli("purge", "--root", str(self.root))
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
