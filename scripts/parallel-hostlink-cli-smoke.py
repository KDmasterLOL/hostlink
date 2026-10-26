#!/usr/bin/env python3
"""Source-pinned disposable Agent/Controller CLI smoke without legacy side effects.

Run against compiled binaries from one exact HostLink revision. The script
creates its own private temporary root, SSH keys, jobs and loopback listener,
then stops only the Agent process it created. It never touches the installed
legacy Agent or a real Hub.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid


def command(*argv: str, timeout: float = 15.0, expected: int = 0) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    if result.returncode != expected:
        raise RuntimeError(
            f"CLI operation returned {result.returncode} instead of {expected}: "
            f"{Path(argv[0]).name} {argv[1]} (diagnostic output withheld)"
        )
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def key(private: Path) -> str:
    command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private), timeout=10)
    private.chmod(0o600)
    public = private.with_suffix(private.suffix + ".pub")
    return public.read_text(encoding="ascii").strip()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def stop_agent(agent: subprocess.Popen[bytes]) -> None:
    if agent.poll() is not None:
        return
    # The CLI registers Ctrl-C as an owned cooperative shutdown. No process
    # group signal, PID-file trust, or attempt to terminate a foreign Agent.
    agent.send_signal(signal.SIGINT)
    try:
        agent.wait(timeout=8)
    except subprocess.TimeoutExpired:
        agent.terminate()
        try:
            agent.wait(timeout=4)
        except subprocess.TimeoutExpired:
            agent.kill()
            agent.wait(timeout=4)


def smoke(agent_bin: Path, client_bin: Path, expected_source_sha: str) -> dict[str, object]:
    if os.name != "posix":
        raise RuntimeError("This specific disposable CLI smoke requires POSIX")
    if not agent_bin.is_file() or not client_bin.is_file():
        raise RuntimeError("Both exact Agent and Client binaries must already exist")
    source = Path(__file__).resolve().parents[1]
    head = command("git", "-C", str(source), "rev-parse", "HEAD").stdout.decode().strip()
    if head != expected_source_sha:
        raise RuntimeError("Selected Git source commit does not match requested exact SHA")
    if command("git", "-C", str(source), "status", "--porcelain", "--untracked-files=no").stdout.strip():
        raise RuntimeError("Tracked source worktree files are not clean")

    binaries = {"hostlink-agent": sha256(agent_bin), "hostlink": sha256(client_bin)}
    with tempfile.TemporaryDirectory(prefix="hostlink-new-agent-only-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        host_key = root / "host-ed25519"
        controller_key = root / "controller-ed25519"
        wrong_key = root / "foreign-ed25519"
        host_pub = key(host_key)
        controller_pub = key(controller_key)
        wrong_pub = key(wrong_key)
        authorized_keys = root / "authorized_keys"
        authorized_keys.write_text(controller_pub + "\n", encoding="ascii")
        authorized_keys.chmod(0o600)
        jobs = root / "jobs"
        jobs.mkdir(mode=0o700)
        endpoint = f"127.0.0.1:{free_port()}"
        agent_config = root / "agent.json"
        host_config = root / "host.json"
        write_json(
            agent_config,
            {
                "listen": endpoint,
                "user": "pilot-agent",
                "host_key": str(host_key),
                "authorized_keys": str(authorized_keys),
                "jobs_root": str(jobs),
                "gateway": None,
                "gateway_alternates": [],
            },
        )
        write_json(
            host_config,
            {
                "endpoint": endpoint,
                "user": "pilot-agent",
                "identity": str(controller_key),
                "host_public_key": host_pub,
                "gateway": None,
            },
        )
        command(str(agent_bin), "check", "--config", str(agent_config))
        log = root / "agent.log"
        with log.open("wb") as agent_log:
            agent = subprocess.Popen(
                [str(agent_bin), "run", "--config", str(agent_config)],
                stdin=subprocess.DEVNULL,
                stdout=agent_log,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            try:
                deadline = time.monotonic() + 15
                while True:
                    if agent.poll() is not None:
                        raise RuntimeError("Owned Agent exited before controller SSH readiness")
                    try:
                        command(str(client_bin), "check", "--config", str(host_config), timeout=2)
                        break
                    except (RuntimeError, subprocess.TimeoutExpired):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Source-exact new Agent did not become SSH-ready")
                        time.sleep(0.15)
                completed: list[str] = ["check"]

                bad_pin = root / "host-wrong-pin.json"
                write_json(
                    bad_pin,
                    {
                        "endpoint": endpoint,
                        "user": "pilot-agent",
                        "identity": str(controller_key),
                        "host_public_key": wrong_pub,
                        "gateway": None,
                    },
                )
                if subprocess.run(
                    [str(client_bin), "check", "--config", str(bad_pin)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                ).returncode == 0:
                    raise RuntimeError("Wrong SSH host public key was unexpectedly accepted")
                completed.append("wrong-hostkey-denied")

                bad_controller = root / "foreign-controller.json"
                write_json(
                    bad_controller,
                    {
                        "endpoint": endpoint,
                        "user": "pilot-agent",
                        "identity": str(wrong_key),
                        "host_public_key": host_pub,
                        "gateway": None,
                    },
                )
                if subprocess.run(
                    [str(client_bin), "check", "--config", str(bad_controller)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                ).returncode == 0:
                    raise RuntimeError("Unauthorized Controller Ed25519 identity was accepted")
                completed.append("wrong-controller-denied")

                binary = command(
                    str(client_bin),
                    "exec",
                    "--config",
                    str(host_config),
                    "--command",
                    r"printf 'pilot\000\377'; exit 7",
                    expected=7,
                )
                if binary.stdout != b"pilot\x00\xff":
                    raise RuntimeError("Agent SSH exec corrupted binary stdout")
                completed.append("exec-raw-exit7")

                payload = b"pilot-artifact\x00\xff"
                local = root / "local-artifact"
                local.write_bytes(payload)
                local.chmod(0o600)
                remote = hashlib.sha256(payload).hexdigest() + ".upload"
                command(
                    str(client_bin),
                    "upload",
                    "--config",
                    str(host_config),
                    "--local",
                    str(local),
                    "--remote",
                    remote,
                )
                existing = subprocess.run(
                    [
                        str(client_bin),
                        "upload",
                        "--config",
                        str(host_config),
                        "--local",
                        str(local),
                        "--remote",
                        remote,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=12,
                )
                if existing.returncode == 0:
                    raise RuntimeError("SFTP create-only upload unexpectedly overwrote a file")
                output = root / "download"
                command(
                    str(client_bin),
                    "download",
                    "--config",
                    str(host_config),
                    "--remote",
                    remote,
                    "--local",
                    str(output),
                )
                if output.read_bytes() != payload:
                    raise RuntimeError("SFTP downloaded artifact content differs")
                completed.append("sftp-create-only-roundtrip")

                program_dir = root / "programs"
                program_dir.mkdir(mode=0o700)
                program = program_dir / "job-child"
                program.write_text("#!/bin/sh\nprintf 'durable\\000\\377'; exit 7\n", encoding="ascii")
                program.chmod(0o500)
                job_id = str(uuid.uuid4())
                start = command(
                    str(client_bin),
                    "job",
                    "start",
                    "--config",
                    str(host_config),
                    "--program",
                    str(program),
                    "--source-sha256",
                    sha256(program),
                    "--id",
                    job_id,
                    timeout=20,
                )
                if job_id.encode() not in start.stdout:
                    raise RuntimeError("Durable job start omitted its canonical UUID")
                deadline = time.monotonic() + 12
                status = b""
                while time.monotonic() < deadline:
                    status = command(
                        str(client_bin),
                        "job",
                        "status",
                        "--config",
                        str(host_config),
                        "--id",
                        job_id,
                    ).stdout
                    if b"completed" in status.lower() or b"exited" in status.lower():
                        break
                    time.sleep(0.15)
                else:
                    raise RuntimeError("Durable job did not reach a terminal state")
                job_output = command(
                    str(client_bin),
                    "job",
                    "output",
                    "--config",
                    str(host_config),
                    "--id",
                    job_id,
                    "--stream",
                    "stdout",
                    "--offset",
                    "0",
                )
                if job_output.stdout != b"durable\x00\xff":
                    raise RuntimeError("Durable job output is not binary-exact")
                completed.append("job-start-status-output-reattach")
            finally:
                stop_agent(agent)
        if agent.poll() is None:
            raise RuntimeError("Owned Agent process remained running after cleanup")
        if subprocess.run(
            [str(client_bin), "check", "--config", str(host_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).returncode == 0:
            raise RuntimeError("Agent SSH listener still responded after owned stop")
        completed.append("owned-stop-closes-listener")
        return {
            "source_sha": head,
            "binary_sha256": binaries,
            "operating_system": "linux",
            "scenario": "disposable-direct-unmanaged-new-hostlink",
            "checks": completed,
            "result": "PASS",
            "old_agent_modified": False,
            "old_agent_coexistence_on_installed_target": "NOT_TESTED",
            "managed_https_hub_gateway_invite": "NOT_TESTED",
            "agent_root_removed": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-binary", required=True, type=Path)
    parser.add_argument("--client-binary", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    print(json.dumps(smoke(args.agent_binary.resolve(), args.client_binary.resolve(), args.source_sha), indent=2))


if __name__ == "__main__":
    main()
