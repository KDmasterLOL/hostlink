#!/usr/bin/env python3
"""Exercise release preflight in an isolated, real Git repository."""
import hashlib
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class StagePreflight(unittest.TestCase):
    def test_missing_build_does_not_block_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp)
            shutil.copy(ROOT / "Justfile", repo / "Justfile")
            (repo / ".gitignore").write_text("/target/\n")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "add", "Justfile", ".gitignore"], cwd=repo, check=True)
            subprocess.run(
                ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "fixture"], cwd=repo, check=True,
            )
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            targets = ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
                       "x86_64-win7-windows-msvc", "i686-win7-windows-msvc")
            for missing in targets:
                # Populate only the preceding inputs; the named target must fail preflight.
                for target in targets[:targets.index(missing)]:
                    root = repo / "target" / "local-build" / sha / target
                    suffix = "" if target.endswith("linux-gnu") else ".exe"
                    artifact = root / target / "release" / ("hostlink-agent" + suffix)
                    artifact.parent.mkdir(parents=True, exist_ok=True)
                    artifact.write_bytes(b"fixture bytes")
                    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                    (root / "build.sha256").write_text(f"{digest}  {artifact}\n")
                    (root / "toolchain").write_text("fixture\n")
                result = subprocess.run(["just", "stage"], cwd=repo, capture_output=True, text=True,
                                        env={**os.environ, "JUST_TEMPDIR": tempfile.gettempdir()})
                self.assertNotEqual(result.returncode, 0, missing)
                self.assertNotIn("Candidate already exists", result.stderr)
                self.assertFalse((repo / "target" / "release-candidate" / sha).exists(), missing)

            first = repo / "target" / "local-build" / sha / targets[0]
            artifact = first / targets[0] / "release" / "hostlink-agent"
            artifact.write_bytes(b"changed after receipt")
            result = subprocess.run(["just", "stage"], cwd=repo, capture_output=True, text=True,
                                    env={**os.environ, "JUST_TEMPDIR": tempfile.gettempdir()})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((repo / "target" / "release-candidate" / sha).exists())


if __name__ == "__main__":
    unittest.main()
