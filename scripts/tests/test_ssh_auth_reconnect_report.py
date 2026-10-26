import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ssh-auth-reconnect-report.py"


class SshAuthReconnectReportTests(unittest.TestCase):
    def run_report(self, data=b"", *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--stdin", "--format", "json", *arguments],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    @staticmethod
    def accepted_line(timestamp, suffix=""):
        return (
            f"{timestamp} gateway sshd[123]: Accepted publickey for alice "
            f"from 192.0.2.10 port 4567 ssh2: ED25519 SHA256:fixture{suffix}"
        )

    def test_162_spaced_accepts_are_bucketed_without_deduplication(self):
        from datetime import datetime, timedelta, timezone

        start = datetime(2026, 10, 26, tzinfo=timezone.utc)
        lines = []
        for index in range(162):
            stamp = start + timedelta(seconds=index * (1800 / 162))
            lines.append(self.accepted_line(stamp.isoformat(timespec="seconds").replace("+00:00", "Z")))
        result = self.run_report(("\n".join(lines) + "\n").encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["counts"]["accepted_publickey"], 162)
        self.assertEqual(len(report["buckets_5m_utc"]), 6)
        self.assertEqual(
            [bucket["counts"]["accepted"] for bucket in report["buckets_5m_utc"]],
            [27] * 6,
        )
        self.assertIn("not deduplicated", " ".join(report["interpretation"]))

    def test_failed_authentication_is_not_an_accept(self):
        line = "2026-10-26T00:01:00+00:00 gateway sshd[5]: Failed publickey for alice from 192.0.2.4 port 22 ssh2"
        report = json.loads(self.run_report(line.encode()).stdout)
        self.assertEqual(report["counts"]["accepted_publickey"], 0)
        self.assertEqual(report["counts"]["failed_authentication"], 1)

    def test_maxstartups_and_persource_penalties_are_distinct(self):
        lines = [
            "2026-10-26T00:01:00+00:00 gateway sshd[5]: drop connection #1 from 192.0.2.1 past MaxStartups",
            "2026-10-26T00:02:00+00:00 gateway sshd[6]: refused connection from 192.0.2.2 due to PerSourcePenalties",
            "2026-10-26T00:03:00+00:00 gateway sshd[7]: Connection closed by 192.0.2.3 port 23 [preauth]",
        ]
        report = json.loads(self.run_report("\n".join(lines).encode()).stdout)
        self.assertEqual(report["counts"]["accepted_publickey"], 0)
        self.assertEqual(report["counts"]["maxstartups_events"], 1)
        self.assertEqual(report["counts"]["persource_penalty_events"], 1)
        self.assertEqual(report["counts"]["preauth_drops"], 1)

    def test_mixed_timezone_and_untimestamped_lines_are_warned(self):
        lines = [
            self.accepted_line("2026-10-26T00:01:00+00:00"),
            self.accepted_line("2026-10-26T03:01:00+03:00"),
            "gateway sshd[4]: Failed publickey for bob from 192.0.2.5 port 5 ssh2",
        ]
        result = self.run_report("\n".join(lines).encode())
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(report["counts"]["accepted_publickey"], 2)
        self.assertEqual(report["counts"]["failed_authentication"], 0)
        self.assertEqual(report["buckets_5m_utc"], [])
        self.assertIsNone(report["observed_window_utc"]["start"])
        warnings = " ".join(report["warnings"])
        self.assertIn("Mixed timestamp offsets", warnings)
        self.assertIn("lacked a usable timestamp", warnings)

    def test_syslog_requires_year_and_timezone(self):
        line = "Oct 26 12:00:00 gateway sshd[5]: Accepted publickey for alice from 192.0.2.1 port 22 ssh2"
        missing = json.loads(self.run_report(line.encode()).stdout)
        self.assertEqual(missing["counts"]["accepted_publickey"], 0)
        self.assertTrue(any("--year and --timezone" in item for item in missing["warnings"]))
        with_context = json.loads(
            self.run_report(line.encode(), "--year", "2026", "--timezone", "+03:00").stdout
        )
        self.assertEqual(with_context["counts"]["accepted_publickey"], 1)
        self.assertEqual(with_context["observed_window_utc"]["start"], "2026-10-26T09:00:00Z")

    def test_empty_input_has_zero_counts_and_no_window(self):
        result = self.run_report()
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["counts"]["accepted_publickey"], 0)
        self.assertEqual(report["counts"]["unknown_lines"], 0)
        self.assertEqual(report["buckets_5m_utc"], [])
        self.assertEqual(report["observed_window_utc"], {"start": None, "end": None})

    def test_invalid_utf8_is_rejected_without_echoing_input(self):
        result = self.run_report(b"private-host private-user PRIVATE_TOKEN \xff")
        self.assertEqual(result.returncode, 2)
        combined = result.stdout + result.stderr
        for secret in (b"private-host", b"private-user", b"PRIVATE_TOKEN"):
            self.assertNotIn(secret, combined)
        self.assertIn(b"not valid UTF-8", result.stderr)

    def test_untrusted_values_never_appear_in_json_or_text(self):
        secret_host = "sensitive-host.example.invalid"
        secret_user = "private_user_7"
        secret_token = "TOKEN-DO-NOT-LEAK-9981"
        secret_fingerprint = "SHA256:private-fingerprint-12345"
        line = (
            "2026-10-26T00:00:00+00:00 "
            f"{secret_host} sshd[42]: Accepted publickey for {secret_user} from 203.0.113.200 "
            f"port 4444 ssh2: ssh-ed25519 AAAA{secret_token} {secret_fingerprint}"
        )
        for output_format in ("json", "text"):
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--stdin", "--format", output_format],
                input=line.encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            combined = result.stdout + result.stderr
            for secret in (secret_host, secret_user, secret_token, secret_fingerprint, "203.0.113.200", "4444"):
                self.assertNotIn(secret.encode(), combined)

    def test_read_error_and_oversized_input_are_generic(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "private-name-do-not-echo"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--input", str(missing), "--format", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(missing.name.encode(), result.stdout + result.stderr)
        result = self.run_report(b"x" * (5 * 1024 * 1024 + 1))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"5 MiB limit", result.stderr)

    def test_source_pseudonyms_are_ephemeral_and_minimum_thresholded(self):
        lines = [
            f"2026-10-26T00:0{index}:00+00:00 gateway sshd[{index}]: Accepted publickey for u from 192.0.2.9 port {index} ssh2"
            for index in range(5)
        ]
        result = self.run_report(
            "\n".join(lines).encode(), "--include-source-pseudonyms"
        )
        report = json.loads(result.stdout)
        self.assertEqual(len(report["source_pseudonyms"]), 1)
        self.assertTrue(report["source_pseudonyms"][0]["source"].startswith("src-"))
        self.assertNotIn("192.0.2.9", result.stdout.decode())

    def test_report_never_claims_rate_limiting_confirmed(self):
        result = self.run_report(self.accepted_line("2026-10-26T00:00:00+00:00").encode())
        report = json.loads(result.stdout)
        self.assertEqual(report["attribution"], "none; counts describe only the supplied log sample")
        self.assertFalse(any("rate limiting confirmed" in item.lower() for item in report["interpretation"]))
        self.assertIn("No rate limiting is confirmed", " ".join(report["interpretation"]))

    def test_fail2ban_and_session_lifecycle_are_separate_evidence(self):
        lines = [
            "2026-10-26T00:00:00+00:00 host fail2ban.actions[8]: NOTICE [sshd] Ban 192.0.2.6",
            "2026-10-26T00:01:00+00:00 host sshd[77]: pam_unix(sshd:session): session opened for user u",
        ]
        report = json.loads(self.run_report("\n".join(lines).encode()).stdout)
        self.assertEqual(report["counts"]["fail2ban_events"], 1)
        self.assertEqual(report["counts"]["session_open_events"], 1)
        self.assertEqual(report["counts"]["successful_ongoing_sessions_observed"], 1)


if __name__ == "__main__":
    unittest.main()
