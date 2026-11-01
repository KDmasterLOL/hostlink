#!/usr/bin/env python3
import json
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "hostlink-v2-pilot.sh"
HELPER = SCRIPT.with_name("hostlink-v2-pilot.py")


class PilotLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hostlink pilot tests ")
        self.base = Path(self.temp.name)
        self.repo = self.base / "source repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.repo / "scripts" / SCRIPT.name)
        shutil.copy2(HELPER, self.repo / "scripts" / HELPER.name)
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
        self.assertEqual(marker, {"schema": 2, "uid": os.getuid(), "source_sha": self.sha})
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
        self.assertIn("STOPPED", self.run_cli("status", "--root", str(self.root)).stdout)
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
        os.chmod(self.root / "processes.json", 0o600)
        self.run_cli("status", "--root", str(self.root), expected=2)
        self.run_cli("down", "--root", str(self.root), expected=2)
        self.run_cli("purge", "--root", str(self.root), expected=2)
        os.kill(foreign, 0)
        (self.root / "processes.json").unlink()
        jobs = self.root / "agent" / "instance" / "jobs"
        jobs.mkdir(parents=True, mode=0o700)
        (jobs / "bad-entry").write_text("unknown")
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

    def test_up_and_check_require_exact_prepared_source_and_real_processes(self):
        self.prepare()
        # This controlled fake Git worktree is not the actual repository source and cannot
        # manufacture binaries or report online from an empty state.
        self.run_cli("up", "--root", str(self.root), expected=2)
        self.run_cli("check", "--root", str(self.root), expected=2)

    def test_pid_reuse_fails_closed_without_signalling_current_process(self):
        self.prepare()
        current = os.getpid()
        entry = {"pid": current, "start": -1, "exe": "/bin/false", "dev": 1, "ino": 1, "cmd": [], "hub_config": []}
        (self.root / "processes.json").write_text(json.dumps({"schema": 1, "state": "running", "items": [entry]}))
        os.chmod(self.root / "processes.json", 0o600)
        self.run_cli("status", "--root", str(self.root), expected=2)
        self.run_cli("down", "--root", str(self.root), expected=2)
        os.kill(current, 0)

    def test_sshd_retitle_does_not_obscure_source_owned_process_identity(self):
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location("pilot_sshd_retitle", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        now = {"pid": 123, "start": 500, "exe": "/usr/sbin/sshd", "dev": 7, "ino": 9,
               "cmd": ["sshd: /tmp/example/sshd_config [listener]"], "hub_config": []}
        record = {**now, "role": "sshd", "cmd": ["/usr/sbin/sshd", "-D"], "listen_port": 23001}
        with patch.object(helper, "proc_identity", return_value=now):
            self.assertTrue(helper.identity_matches(record))
            self.assertFalse(helper.identity_matches({**record, "start": 501}))
            self.assertFalse(helper.identity_matches({**record, "ino": 10}))
            self.assertFalse(helper.identity_matches({**record, "role": "agent"}))

    def test_duplicate_pid_ledger_is_rejected_before_signalling(self):
        self.prepare()
        current = os.getpid()
        entry = {"pid": current, "start": -1, "exe": "/bin/false", "dev": 1, "ino": 1, "cmd": [], "hub_config": []}
        (self.root / "processes.json").write_text(json.dumps({"schema": 1, "state": "running", "items": [entry, entry]}))
        os.chmod(self.root / "processes.json", 0o600)
        result = self.run_cli("down", "--root", str(self.root), expected=2)
        self.assertIn("duplicate PIDs", result.stderr)
        os.kill(current, 0)

    def test_malicious_env_is_not_sourced(self):
        self.prepare()
        marker = self.root / ".hostlink-v2-pilot.json"
        original = marker.read_bytes()
        malicious = self.base / "do-not-run"
        env_file = self.root / ".env"
        env_file.write_text(f"touch {malicious}\n")
        self.run_cli("status", "--root", str(self.root))
        self.assertFalse(malicious.exists())
        marker.write_bytes(original)

    def test_occupied_loopback_listener_is_detected_without_reconfiguration(self):
        import socket
        try:
            listener = socket.socket()
        except PermissionError as error:
            self.skipTest(f"loopback sockets are denied by this sandbox: {error}")
        try:
            listener.bind(("127.0.0.1", 0)); listener.listen()
        except PermissionError as error:
            listener.close()
            self.skipTest(f"loopback sockets are denied by this sandbox: {error}")
        occupied = listener.getsockname()[1]
        self.assertTrue(listener.getsockname()[0].startswith("127."))
        spec = importlib.util.spec_from_file_location("pilot_port_helper", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        self.assertFalse(helper.port_free(occupied))
        self.assertTrue(listener.fileno() >= 0)
        listener.close()

    def test_down_refuses_active_or_unknown_job_state_and_preserves_root(self):
        self.prepare()
        jobs = self.root / "agent" / "instance" / "jobs"
        jobs.mkdir(parents=True, mode=0o700)
        (jobs / "00000000-0000-0000-0000-000000000000").mkdir(mode=0o700)
        self.run_cli("down", "--root", str(self.root), expected=2)
        self.run_cli("purge", "--root", str(self.root), expected=2)
        self.assertTrue(self.root.exists())

    def test_wrong_tls_trust_cannot_be_treated_as_healthy(self):
        self.prepare()
        # The helper's health gate requires an explicit private CA; no insecure bypass exists.
        source = HELPER.read_text()
        self.assertIn("create_default_context(cafile=str(ca))", source)
        self.assertNotIn("_create_unverified_context", source)

    def test_generated_private_ca_is_accepted_by_strict_python_tls_verifier(self):
        import ssl
        spec = importlib.util.spec_from_file_location("pilot_tls", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        root = self.base / "private CA"
        root.mkdir(mode=0o700)
        ca, cert, _ = helper.create_tls(root)
        self.assertEqual(ca.stat().st_mode & 0o777, 0o600)
        self.assertEqual(cert.stat().st_mode & 0o777, 0o600)
        ssl.create_default_context(cafile=str(ca))
        extensions = subprocess.check_output(["openssl", "x509", "-in", str(ca), "-noout", "-text"], text=True)
        self.assertIn("Certificate Sign", extensions)
        self.assertIn("CA:TRUE", extensions)
        valid = subprocess.run(["openssl", "verify", "-x509_strict", "-CAfile", str(ca), str(cert)], capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

    def test_only_public_tls_certificates_can_reuse_legacy_owner_readable_mode(self):
        spec = importlib.util.spec_from_file_location("pilot_legacy_certificate", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        path = self.base / "old-public-ca.pem"
        path.write_text("PUBLIC CERTIFICATE\n", encoding="utf-8")
        path.chmod(0o644)
        self.assertEqual(helper.private_text(path, public_certificate=True), "PUBLIC CERTIFICATE\n")
        with self.assertRaises(helper.PilotError):
            helper.private_text(path)

    def test_partial_start_rollback_stops_only_ledger_owned_child(self):
        spec = importlib.util.spec_from_file_location("pilot_helper", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        self.prepare()
        first, first_record = helper.launch([os.sys.executable, "-c", "import time; time.sleep(60)"], self.root / "logs" / "first.log")
        second, second_record = helper.launch([os.sys.executable, "-c", "import time; time.sleep(60)"], self.root / "logs" / "second.log")
        helper.write_ledger(self.root, [first_record, second_record], True)
        helper.stop_items(self.root, [second_record])
        second.wait(timeout=3)
        self.assertNotEqual(second.returncode, 0)
        os.kill(first.pid, 0)
        helper.stop_items(self.root, [first_record])
        first.wait(timeout=3)
        self.assertNotEqual(first.returncode, 0)

    def test_owned_process_log_reopens_for_append_without_following_symlinks(self):
        spec = importlib.util.spec_from_file_location("pilot_log_restart", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        self.prepare()
        log = self.root / "logs" / "reusable.log"
        for value in ("first", "second"):
            child, record = helper.launch(
                [os.sys.executable, "-c", "import sys,time; print(sys.argv[1],flush=True);time.sleep(60)", value], log
            )
            import time
            for _ in range(50):
                if value.encode() in log.read_bytes():
                    break
                time.sleep(.01)
            helper.write_ledger(self.root, [record], True)
            helper.stop_items(self.root, [record])
            child.wait(timeout=5)
        self.assertIn(b"first", log.read_bytes())
        self.assertIn(b"second", log.read_bytes())
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)
        log.unlink()
        outside = self.base / "unowned-log-target"
        outside.write_text("must not append")
        log.symlink_to(outside)
        with self.assertRaises((OSError, helper.PilotError)):
            helper.launch([os.sys.executable, "-c", "pass"], log)
        self.assertEqual(outside.read_text(), "must not append")

    def test_partial_start_rollback_reaps_already_exited_owned_child(self):
        spec = importlib.util.spec_from_file_location("pilot_exited_process", HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        self.prepare()
        first, first_record = helper.launch([os.sys.executable, "-c", "import time; time.sleep(60)"], self.root / "logs" / "running.log")
        second, second_record = helper.launch([os.sys.executable, "-c", "import sys; sys.exit(43)"], self.root / "logs" / "exited.log")
        self.assertEqual(second.wait(timeout=5), 43)
        helper.write_ledger(self.root, [first_record, second_record], True)
        helper.stop_items(self.root, [first_record, second_record])
        first.wait(timeout=5)
        self.assertEqual(helper.ledger_read(self.root)["state"], "stopped")

    def test_down_preserves_terminal_job_history(self):
        self.prepare()
        jobs = self.root / "agent" / "instance" / "jobs"
        job = jobs / "00000000-0000-0000-0000-000000000000"
        job.mkdir(parents=True, mode=0o700)
        os.chmod(self.root / "agent", 0o700)
        os.chmod(self.root / "agent" / "instance", 0o700)
        os.chmod(jobs, 0o700)
        record = job / "record.json"
        record.write_text(json.dumps({"state": {"state": "exited", "code": 7}}))
        os.chmod(record, 0o600)
        self.assertIn("preserved", self.run_cli("down", "--root", str(self.root)).stdout)
        self.assertTrue(record.exists())

    def test_down_refuses_prepared_running_and_interrupted_jobs(self):
        self.prepare()
        jobs = self.root / "agent" / "instance" / "jobs"
        job = jobs / "00000000-0000-0000-0000-000000000000"
        job.mkdir(parents=True, mode=0o700)
        os.chmod(self.root / "agent", 0o700)
        os.chmod(self.root / "agent" / "instance", 0o700)
        os.chmod(jobs, 0o700)
        record = job / "record.json"
        for state in ("prepared", "running", "interrupted"):
            record.write_text(json.dumps({"state": {"state": state}}))
            os.chmod(record, 0o600)
            self.run_cli("down", "--root", str(self.root), expected=2)
        self.assertTrue(self.root.exists())


if __name__ == "__main__":
    unittest.main()
