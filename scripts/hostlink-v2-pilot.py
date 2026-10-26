#!/usr/bin/env python3
"""Private, user-owned Linux HostLink v2 managed pilot lifecycle."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.request

MARKER = ".hostlink-v2-pilot.json"
UID = os.getuid()
SCHEMA = 2
VERSION = "0.1.0"
TARGET = "x86_64-unknown-linux-gnu"
TOOLS = ("cargo", "sshd", "caddy", "openssl", "ssh-keygen", "ssh-keyscan")
CHILDREN: dict[int, subprocess.Popen] = {}


class PilotError(Exception):
    pass


def fail(message: str) -> None:
    raise PilotError(message)


def run(args: list[str], *, env=None, timeout=40, capture=True):
    try:
        return subprocess.run(args, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
                              timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"command failed: {pathlib.Path(args[0]).name} ({type(error).__name__})")


def private_dir(path: pathlib.Path) -> None:
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(path, 0o700)


def private_write(path: pathlib.Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def safe_root(raw: str) -> pathlib.Path:
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw or raw == "/":
        fail("root must be a normalized absolute non-root path")
    path = pathlib.Path(raw)
    cursor = pathlib.Path("/")
    for part in path.parts[1:]:
        cursor /= part
        try:
            info = os.lstat(cursor)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            fail("root path contains a symbolic link")
    return path


def directory(path: pathlib.Path, mode=0o700) -> None:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID:
        fail("pilot directory is not a current-user-owned real directory")
    if stat.S_IMODE(info.st_mode) != mode:
        fail("pilot directory permissions are not private")


def source_identity(repo: pathlib.Path, expected: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        fail("source SHA must be a 40-character lowercase Git SHA")
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain=v1", "--untracked-files=all"], text=True, stderr=subprocess.DEVNULL)
    if head != expected or dirty:
        fail("source must be the exact clean Git HEAD")


def marker_read(root: pathlib.Path) -> dict:
    path = root / MARKER
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != UID or stat.S_IMODE(info.st_mode) != 0o600:
        fail("pilot marker ownership, type, or permissions are invalid")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("pilot marker is malformed")
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or data.get("uid") != UID:
        fail("pilot marker schema or owner does not match")
    if not isinstance(data.get("source_sha"), str) or not re.fullmatch(r"[0-9a-f]{40}", data["source_sha"]):
        fail("pilot marker source SHA is invalid")
    return data


def digest(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def proc_identity(pid: int) -> dict | None:
    base = pathlib.Path("/proc") / str(pid)
    try:
        stat_text = (base / "stat").read_text()
        fields = stat_text[stat_text.rfind(")") + 2:].split()
        start = int(fields[19])
        exe = os.readlink(base / "exe")
        exe_stat = os.stat(base / "exe")
        cmd = (base / "cmdline").read_bytes().split(b"\0")
        cmd = [part.decode("utf-8", "replace") for part in cmd if part]
        env = (base / "environ").read_bytes().split(b"\0")
        env_config = [item.decode("utf-8", "replace") for item in env if item.startswith(b"HOSTLINK_HUB_CONFIG=")]
        return {"pid": pid, "start": start, "exe": exe, "dev": exe_stat.st_dev,
                "ino": exe_stat.st_ino, "cmd": cmd, "hub_config": env_config}
    except (OSError, ValueError, IndexError, PermissionError):
        return None


def identity_matches(record: dict) -> bool:
    now = proc_identity(record.get("pid", -1))
    if not now or any(now[key] != record.get(key) for key in ("start", "exe", "dev", "ino")):
        return False
    if record.get("role") == "sshd":
        # OpenSSH overwrites its process title and clears parts of environ
        # after startup. Its captured PID birth + executable inode/digest are
        # stable; do not mistake this normal re-title for PID reuse.
        return (pathlib.Path(now["exe"]).name == "sshd"
                and bool(record.get("cmd"))
                and pathlib.Path(record["cmd"][0]).name == "sshd"
                and isinstance(record.get("listen_port"), int))
    return now["cmd"] == record.get("cmd") and now["hub_config"] == record.get("hub_config")


def process_stopped(record: dict) -> bool:
    proc = pathlib.Path("/proc") / str(record.get("pid", -1))
    if not proc.exists():
        return True
    try:
        raw = (proc / "stat").read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        # A same-birth zombie cannot execute or receive work; its parent may reap it later.
        return fields[0] == "Z" and int(fields[19]) == record.get("start")
    except (OSError, ValueError, IndexError):
        return False


def ledger_read(root: pathlib.Path) -> dict:
    path = root / "processes.json"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"state": "stopped", "items": []}
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or stat.S_IMODE(info.st_mode) != 0o600:
        fail("process ledger is untrusted")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("process ledger is malformed")
    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("items") is None:
        fail("process ledger schema is invalid")
    items = data["items"]
    if not isinstance(items, list) or len(items) > 8 or any(not isinstance(item, dict) or not isinstance(item.get("pid"), int) for item in items):
        fail("process ledger entries are invalid")
    if len({item["pid"] for item in items}) != len(items):
        fail("process ledger contains duplicate PIDs")
    state = data.get("state")
    if state not in ("stopped", "starting", "running") or (state == "stopped" and items) or (state == "running" and not items):
        fail("process ledger state conflicts with its owned process set")
    for item in items:
        if process_stopped(item):
            continue
        if not identity_matches(item):
            fail("owned process identity is missing, reused, or changed")
        if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("exe_sha256", ""))) or digest(pathlib.Path("/proc") / str(item["pid"]) / "exe") != item["exe_sha256"]:
            fail("owned process executable digest changed")
    return data


def write_ledger(root: pathlib.Path, items: list[dict], running: bool) -> None:
    path = root / "processes.json"
    temp = root / f".processes-{os.getpid()}-{time.time_ns()}.tmp"
    state = ("running" if items else "starting") if running else "stopped"
    private_write(temp, json.dumps({"schema": 1, "state": state, "items": items}, sort_keys=True).encode() + b"\n")
    os.replace(temp, path)
    directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def port_free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def established_loopback_sessions(port: int) -> bool:
    wanted = f"{port:04X}"
    for table in (pathlib.Path("/proc/net/tcp"), pathlib.Path("/proc/net/tcp6")):
        try:
            lines = table.read_text().splitlines()[1:]
        except OSError:
            fail("cannot inspect kernel TCP state before stopping the owned gateway")
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[1].rsplit(":", 1)[-1].upper() == wanted and fields[3] == "01":
                return True
    return False


def wait_port(port: int, process: subprocess.Popen, deadline=20) -> None:
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        if process.poll() is not None:
            fail("owned service exited before becoming ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    fail("owned loopback service did not become ready")


def snapshot_process(process: subprocess.Popen) -> dict:
    identity = proc_identity(process.pid)
    if not identity:
        fail("cannot read newly launched process identity")
    identity["exe_sha256"] = digest(pathlib.Path("/proc") / str(process.pid) / "exe")
    return identity


def launch(args: list[str], log: pathlib.Path, *, env=None) -> tuple[subprocess.Popen, dict]:
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    stream = os.fdopen(fd, "wb")
    try:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                 env=env, close_fds=True, start_new_session=True)
    finally:
        stream.close()
    CHILDREN[child.pid] = child
    identity = snapshot_process(child)
    identity["role"] = pathlib.Path(args[0]).name
    return child, identity


def stop_items(root: pathlib.Path, items: list[dict]) -> None:
    # Validate the complete set before sending any signal, then checkpoint each stopped PID.
    if any(not identity_matches(item) and not process_stopped(item) for item in items):
        fail("process ownership changed before stop; remaining state preserved")
    remaining = items[:]
    for item in reversed(items):
        if process_stopped(item):
            remaining = [candidate for candidate in remaining if candidate["pid"] != item["pid"]]
            write_ledger(root, remaining, True)
            continue
        if not identity_matches(item):
            fail("process ownership changed during stop; remaining state preserved")
        if item.get("role") == "sshd":
            port = item.get("listen_port")
            if not isinstance(port, int) or established_loopback_sessions(port):
                fail("active or unknown SSH gateway session blocks shutdown")
        os.kill(item["pid"], signal.SIGTERM)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            child = CHILDREN.get(item["pid"])
            if child is not None and child.poll() is not None:
                break
            current = proc_identity(item["pid"])
            if current is None:
                if process_stopped(item):
                    break
                time.sleep(.1)
                continue
            if not identity_matches(item):
                fail("PID identity changed during stop; remaining state preserved")
            time.sleep(.1)
        else:
            fail("owned process did not stop safely; no SIGKILL was sent")
        remaining = [candidate for candidate in remaining if candidate["pid"] != item["pid"]]
        write_ledger(root, remaining, True)
    write_ledger(root, [], False)


def jobs_safe(root: pathlib.Path) -> None:
    jobs = root / "agent" / "instance" / "jobs"
    for candidate in (root / "agent", root / "agent" / "instance", jobs):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or stat.S_IMODE(info.st_mode) != 0o700:
            fail("Agent jobs path contains an unsafe directory")
    directory(jobs)
    entries = list(jobs.iterdir())
    if len(entries) > 4096:
        fail("durable job state exceeds safe inspection bound")
    for entry in entries:
        info = os.lstat(entry)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or not re.fullmatch(r"[0-9a-f-]{36}", entry.name):
            fail("unknown durable job entry blocks shutdown")
        record_path = entry / "record.json"
        rec_info = os.lstat(record_path)
        if not stat.S_ISREG(rec_info.st_mode) or stat.S_ISLNK(rec_info.st_mode) or rec_info.st_uid != UID or stat.S_IMODE(rec_info.st_mode) != 0o600 or rec_info.st_size > 65536:
            fail("unknown durable job record blocks shutdown")
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
            state = record["state"]["state"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
            fail("malformed durable job record blocks shutdown")
        if state in ("prepared", "running", "interrupted") or state not in ("exited", "failed"):
            fail("active or unknown durable job blocks shutdown")


def clean_tree(root: pathlib.Path) -> None:
    dev = os.lstat(root).st_dev
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = pathlib.Path(current) / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or info.st_uid != UID or info.st_dev != dev or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                fail("purge refused: pilot tree contains links, foreign files, special files, or mount crossings")


def wait_https(url: str, ca: pathlib.Path, process: subprocess.Popen, timeout=25) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if process.poll() is not None:
            fail("owned Caddy process exited before HTTPS became ready")
        try:
            context = __import__("ssl").create_default_context(cafile=str(ca))
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            with opener.open(url + "/healthz", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(.1)
    fail("strictly verified local HTTPS endpoint did not become ready")


def configure_artifacts(repo: pathlib.Path, root: pathlib.Path, source_sha: str) -> dict:
    source_identity(repo, source_sha)
    for tool in TOOLS:
        if not shutil.which(tool):
            fail(f"required local tool is missing: {tool}")
    artifacts = root / "artifacts"
    receipt_path = artifacts / "artifact-receipt.json"
    if artifacts.exists():
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            fail("existing source artifact receipt is unavailable or malformed")
        if receipt.get("source_sha") != source_sha or receipt.get("target") != TARGET or receipt.get("version") != VERSION:
            fail("existing package receipt does not match this source/target/version")
        sidecar_rel = pathlib.PurePosixPath(str(receipt.get("sidecar", "")))
        archive_rel = pathlib.PurePosixPath(str(receipt.get("archive", "")))
        installer_rel = pathlib.PurePosixPath(str(receipt.get("installer", "")))
        if any(path.is_absolute() or ".." in path.parts for path in (sidecar_rel, archive_rel, installer_rel)):
            fail("artifact receipt contains an unsafe path")
        sidecar = artifacts.joinpath(*sidecar_rel.parts)
        # The packager publishes ZIP and installer under VERSION/, while the
        # agent sidecar is nested one level further under VERSION/TARGET/.
        archive = artifacts.joinpath(VERSION, *archive_rel.parts)
        installer = artifacts.joinpath(VERSION, *installer_rel.parts)
        for path, expected in ((sidecar, receipt.get("sidecar_sha256")), (archive, receipt.get("archive_sha256")), (installer, receipt.get("installer_sha256"))):
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or digest(path) != expected:
                fail("existing source-pinned package member changed")
    else:
        run(["cargo", "build", "--offline", "--locked", "--release", "-p", "hostlink-hub", "-p", "hostlink-agent", "-p", "hostlink"], timeout=1800)
        target_dir = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", str(repo / "target")))
        binaries = {"hub": target_dir / "release/hostlink-hub", "agent": target_dir / "release/hostlink-agent", "client": target_dir / "release/hostlink"}
        run([sys.executable, str(repo / "scripts/package-hostlink-agent.py"), "--source-sha", source_sha,
             "--target", TARGET, "--version", VERSION, "--binary", str(binaries["agent"]), "--output-dir", str(artifacts)])
        receipt = json.loads((artifacts / "artifact-receipt.json").read_text(encoding="utf-8"))
    target_dir = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", str(repo / "target")))
    binaries = {"hub": target_dir / "release/hostlink-hub", "agent": target_dir / "release/hostlink-agent", "client": target_dir / "release/hostlink"}
    dest = root / "bin"
    build_receipt = root / "build-receipt.json"
    if dest.exists():
        directory(dest)
        try:
            saved = json.loads(build_receipt.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            fail("existing build receipt is unavailable or malformed")
        if saved.get("schema") != 1 or saved.get("source_sha") != source_sha:
            fail("existing build receipt does not match the pilot source")
        binary_sha = {}
        for key, path in ((key, dest / value.name) for key, value in binaries.items()):
            info = os.lstat(path)
            expected = saved.get("binary_sha256", {}).get(key)
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or digest(path) != expected:
                fail(f"stored source-exact {key} binary changed")
            binary_sha[key] = expected
    else:
        if not all(path.is_file() and not path.is_symlink() for path in binaries.values()):
            run(["cargo", "build", "--offline", "--locked", "--release", "-p", "hostlink-hub", "-p", "hostlink-agent", "-p", "hostlink"], timeout=1800)
        private_dir(dest)
        binary_sha = {}
        for key, path in binaries.items():
            if not path.is_file() or path.is_symlink():
                fail(f"source-exact {key} binary is unavailable")
            shutil.copyfile(path, dest / path.name)
            os.chmod(dest / path.name, 0o700)
            binary_sha[key] = digest(dest / path.name)
        private_write(build_receipt, json.dumps({"schema": 1, "source_sha": source_sha, "binary_sha256": binary_sha}, sort_keys=True).encode() + b"\n")
    return {"receipt": receipt, "binaries": {key: str(dest / path.name) for key, path in binaries.items()},
            "binary_sha256": binary_sha}


def create_tls(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    tls = root / "tls"
    private_dir(tls)
    ca_key, ca_cert = tls / "ca.key", tls / "ca.pem"
    leaf_key, leaf_cert, csr, ext = tls / "server.key", tls / "server.pem", tls / "server.csr", tls / "server.ext"
    run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "365", "-subj", "/CN=HostLink HOME Pilot Private CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
    os.chmod(ca_key, 0o600)
    run(["openssl", "req", "-new", "-newkey", "ed25519", "-nodes", "-keyout", str(leaf_key), "-out", str(csr), "-subj", "/CN=localhost"])
    os.chmod(leaf_key, 0o600)
    private_write(ext, b"subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
    run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(leaf_cert), "-days", "365", "-extfile", str(ext)])
    csr.unlink(); ext.unlink()
    return ca_cert, leaf_cert, leaf_key


def private_text(path: pathlib.Path) -> str:
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
        fail("pilot configuration or credential is not a bounded private regular file")
    return path.read_text(encoding="utf-8")


def private_path_below(root: pathlib.Path, path: pathlib.Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        fail("pilot file path escapes the owned root")
    current = root
    for part in relative.parts[:-1]:
        current /= part
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != UID or stat.S_IMODE(info.st_mode) != 0o700:
            fail("pilot file path contains an unsafe directory")


def restart_existing(root: pathlib.Path, marker: dict, artifacts: dict) -> None:
    try:
        data = json.loads(private_text(root / "pilot.json"))
    except (json.JSONDecodeError, UnicodeError):
        fail("stored pilot configuration is malformed")
    if data.get("schema") != 1 or data.get("source_sha") != marker["source_sha"]:
        fail("stored pilot configuration does not match its source marker")
    ports = data.get("ports")
    if not isinstance(ports, dict) or set(ports) != {"sshd", "hub_http", "https", "reverse"} or any(not isinstance(value, int) or not (1024 <= value <= 65535) for value in ports.values()):
        fail("stored pilot port map is invalid")
    if len(set(ports.values())) != 4:
        fail("stored pilot port map contains duplicates")
    if data.get("hub_url") != f"https://localhost:{ports['https']}" or data.get("agent_root") != str(root / "agent/instance") or data.get("controller_config") != str(root / "controller/hub.json"):
        fail("stored pilot endpoints or roots do not match this owned root")
    tool_paths = data.get("tools")
    if not isinstance(tool_paths, dict) or set(tool_paths) != {"caddy", "sshd"}:
        fail("stored service tool identities are missing")
    for name, saved in tool_paths.items():
        current = shutil.which(name)
        if not current or str(pathlib.Path(current).resolve()) != saved.get("path") or digest(pathlib.Path(current)) != saved.get("sha256"):
            fail(f"installed {name} binary changed since this pilot was prepared")
    for filename in ("hub.json", "Caddyfile", "gateway/sshd_config", "operator.token", "gateway.token", "tls/ca.pem", "tls/server.pem", "tls/server.key", "gateway/host_key", "gateway/controller_authorized_keys", "controller/identity"):
        path = root / filename
        private_path_below(root, path)
        private_text(path)
    ca = root / "tls/ca.pem"
    env = os.environ.copy()
    for name in ("BASH_ENV", "ENV", "HOSTLINK_HUB_OPERATOR_TOKEN", "HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN"):
        env.pop(name, None)
    env["HOSTLINK_HUB_OPERATOR_TOKEN"] = private_text(root / "operator.token").strip()
    env["HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN"] = private_text(root / "gateway.token").strip()
    env["HOSTLINK_HUB_CONFIG"] = str(root / "controller/hub.json")
    env["HOME"] = str(root / "controller")
    items: list[dict] = []
    processes: list[subprocess.Popen] = []
    write_ledger(root, items, True)
    try:
        hub, identity = launch([artifacts["binaries"]["hub"], "serve", "--config", str(root / "hub.json")], root / "logs/hub.log", env=env)
        processes.append(hub); items.append(identity); write_ledger(root, items, True); wait_port(ports["hub_http"], hub)
        caddy_env = env.copy()
        caddy_env["HOME"] = str(root / "caddy-home"); caddy_env["XDG_CONFIG_HOME"] = str(root / "caddy-config"); caddy_env["XDG_DATA_HOME"] = str(root / "caddy-data")
        caddy, identity = launch([tool_paths["caddy"]["path"], "run", "--config", str(root / "Caddyfile"), "--adapter", "caddyfile"], root / "logs/caddy.log", env=caddy_env)
        processes.append(caddy); items.append(identity); write_ledger(root, items, True); wait_https(data["hub_url"], ca, caddy)
        sshd, identity = launch([tool_paths["sshd"]["path"], "-D", "-e", "-f", str(root / "gateway/sshd_config")], root / "logs/sshd.log", env=env)
        identity["listen_port"] = ports["sshd"]
        processes.append(sshd); items.append(identity); write_ledger(root, items, True); wait_port(ports["sshd"], sshd)
        agent_config = pathlib.Path(data["agent_root"]) / "state/agent.json"
        private_path_below(root, agent_config)
        private_text(agent_config)
        agent_env = env.copy(); agent_env["HOME"] = str(pathlib.Path(data["agent_root"]))
        agent, identity = launch([artifacts["binaries"]["agent"], "run", "--config", str(agent_config)], root / "logs/agent.log", env=agent_env)
        processes.append(agent); items.append(identity); write_ledger(root, items, True)
        client = artifacts["binaries"]["client"]
        deadline = time.monotonic() + 30
        while True:
            try:
                run([client, "verify", "home-v2-pilot"], env=env, timeout=25)
                break
            except PilotError:
                if time.monotonic() >= deadline or agent.poll() is not None:
                    raise
                time.sleep(.25)
        print(f"UP source_sha={marker['source_sha']} hub={data['hub_url']} processes={len(items)} resumed=yes")
    except BaseException:
        try:
            stop_items(root, items)
        except BaseException:
            pass
        raise


def up(root: pathlib.Path, repo: pathlib.Path, marker: dict) -> None:
    if os.geteuid() == 0:
        fail("refusing root execution")
    if os.path.lexists(root / "processes.json"):
        ledger = ledger_read(root)
        if ledger.get("state") == "running" and ledger.get("items"):
            if any(process_stopped(item) for item in ledger["items"]):
                fail("pilot is partially stopped; run down before attempting another up")
            print("ALREADY-UP")
            return
        if ledger.get("state") == "starting":
            fail("pilot startup/shutdown ledger is uncertain; inspect processes before recovery")
    source_sha = marker["source_sha"]
    user = pwd.getpwuid(UID).pw_name
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", user):
        fail("current account name is not safe for the isolated sshd configuration")
    artifacts = configure_artifacts(repo, root, source_sha)
    if os.path.lexists(root / "pilot.json"):
        restart_existing(root, marker, artifacts)
        return
    for name in ("gateway", "controller", "agent"):
        private_dir(root / name)
    tool_paths = {}
    for name in ("caddy", "sshd"):
        path = shutil.which(name)
        if not path:
            fail(f"required local service binary is missing: {name}")
        resolved = str(pathlib.Path(path).resolve())
        tool_paths[name] = {"path": resolved, "sha256": digest(pathlib.Path(path))}
    gateway = root / "gateway"
    controller = root / "controller"
    agent_root = root / "agent" / "instance"
    for key_name in ("controller", "gateway-host"):
        key_path = (controller / "identity") if key_name == "controller" else (gateway / "host_key")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)])
        os.chmod(key_path, 0o600); os.chmod(pathlib.Path(str(key_path) + ".pub"), 0o600)
    ssh_port, hub_port, tls_port, reverse_port = [free_port() for _ in range(4)]
    ports = [ssh_port, hub_port, tls_port, reverse_port]
    if len(set(ports)) != 4 or any(not port_free(p) for p in ports):
        fail("loopback port collision during pilot preflight")
    host_pub = (gateway / "host_key.pub").read_text().strip()
    operator_pub = (controller / "identity.pub").read_text().strip()
    token = __import__("secrets").token_urlsafe(48)
    lookup = __import__("secrets").token_urlsafe(48)
    private_write(root / "operator.token", (token + "\n").encode())
    private_write(root / "gateway.token", (lookup + "\n").encode())
    ca, cert, cert_key = create_tls(root)
    private_write(gateway / "controller_authorized_keys", (operator_pub + " hostlink-v2-pilot-controller\n").encode())
    sshd_config = gateway / "sshd_config"
    sshd_quote = lambda value: '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'
    sshd_config_text = (f"Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {sshd_quote(gateway / 'host_key')}\nPidFile {sshd_quote(gateway / 'sshd.pid')}\n"
        f"AuthorizedKeysFile {sshd_quote(gateway / 'controller_authorized_keys')} {sshd_quote(gateway / 'hostlink-v2-authorized_keys')}\nStrictModes no\nAllowUsers {user}\n"
        "PubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\n"
        "AllowTcpForwarding yes\nGatewayPorts no\nX11Forwarding no\nPermitUserEnvironment no\nSubsystem sftp internal-sftp\nLogLevel VERBOSE\n")
    private_write(sshd_config, sshd_config_text.encode())
    run([tool_paths["sshd"]["path"], "-t", "-f", str(sshd_config)])
    tls_url = f"https://localhost:{tls_port}"
    hub_config = root / "hub.json"
    value = {"version": 2, "listen": f"127.0.0.1:{hub_port}", "public_url": tls_url,
             "state_root": str(root / "hostlink-hub-v2"), "authorized_keys": str(gateway / "hostlink-v2-authorized_keys"),
             "gateways": [{"host": "127.0.0.1", "user": user, "port": ssh_port, "host_public_key": host_pub}],
             "operator_ssh_public_keys": [operator_pub], "operator_token_env": "HOSTLINK_HUB_OPERATOR_TOKEN",
             "gateway_lookup_token_env": "HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN", "port_from": reverse_port,
             "port_to": reverse_port, "reserved_ports": [ssh_port, hub_port, tls_port]}
    private_write(hub_config, json.dumps(value, sort_keys=True).encode() + b"\n")
    caddyfile = root / "Caddyfile"
    caddy_quote = lambda value: json.dumps(str(value))
    content = (f"{{\n  admin off\n  auto_https off\n}}\nhttps://localhost:{tls_port} {{\n  bind 127.0.0.1\n  tls {caddy_quote(cert)} {caddy_quote(cert_key)}\n  route {{\n"
        f"    @hub path /v2/* /healthz\n    handle @hub {{\n      reverse_proxy http://127.0.0.1:{hub_port}\n    }}\n"
        f"    handle {{\n      root * {caddy_quote(root / 'artifacts')}\n      file_server\n    }}\n  }}\n}}\n")
    private_write(caddyfile, content.encode())
    caddy_dirs = [root / f"caddy-{n}" for n in ("home", "config", "data")]
    for item in caddy_dirs: private_dir(item)
    host_known = gateway / "known_hosts"
    private_write(host_known, f"[127.0.0.1]:{ssh_port} {host_pub}\n".encode())
    # Credentials are read from private files and placed only in the Hub process environment.
    env = os.environ.copy()
    env.pop("BASH_ENV", None); env.pop("ENV", None)
    env["HOSTLINK_HUB_OPERATOR_TOKEN"] = token
    env["HOSTLINK_HUB_GATEWAY_LOOKUP_TOKEN"] = lookup
    env["HOSTLINK_HUB_CONFIG"] = str(root / "controller" / "hub.json")
    env["HOME"] = str(root / "controller")
    env["CURL_CA_BUNDLE"] = str(ca); env["SSL_CERT_FILE"] = str(ca)
    items = []
    write_ledger(root, items, True)
    processes = []
    try:
        hub_p, hub_id = launch([artifacts["binaries"]["hub"], "serve", "--config", str(hub_config)], root / "logs" / "hub.log", env=env)
        processes.append(hub_p); items.append(hub_id); write_ledger(root, items, True); wait_port(hub_port, hub_p)
        caddy_env = env.copy(); caddy_env["HOME"] = str(caddy_dirs[0]); caddy_env["XDG_CONFIG_HOME"] = str(caddy_dirs[1]); caddy_env["XDG_DATA_HOME"] = str(caddy_dirs[2])
        caddy_p, caddy_id = launch([tool_paths["caddy"]["path"], "run", "--config", str(caddyfile), "--adapter", "caddyfile"], root / "logs" / "caddy.log", env=caddy_env)
        processes.append(caddy_p); items.append(caddy_id); write_ledger(root, items, True); wait_https(tls_url, ca, caddy_p)
        ssh_p, ssh_id = launch([tool_paths["sshd"]["path"], "-D", "-e", "-f", str(sshd_config)], root / "logs" / "sshd.log", env=env)
        ssh_id["listen_port"] = ssh_port
        processes.append(ssh_p); items.append(ssh_id); write_ledger(root, items, True); wait_port(ssh_port, ssh_p)
        run([artifacts["binaries"]["hub"], "check", "--config", str(hub_config)], env=env)
        client = artifacts["binaries"]["client"]
        cfg_path = env["HOSTLINK_HUB_CONFIG"]
        cfg_args = [client, "hub", "configure", "--hub-url", tls_url, "--hub-ca-cert", str(ca), "--token-file", str(root / "operator.token"), "--ssh-user", user, "--identity", str(controller / "identity"), "--gateway-identity", str(controller / "identity"), "--preferred-gateway", f"127.0.0.1:{ssh_port}"]
        run(cfg_args, env=env)
        # The CLI's one-use token output is captured in memory and immediately written to a 0600 file.
        invite = run([client, "invite", "--token-only", "--name", "home-v2-pilot", "--ttl-seconds", "900"], env=env)
        match = re.search(rb"^token: ([A-Za-z0-9_-]+)$", invite.stdout, re.M)
        if not match:
            fail("HostLink invite did not return the documented one-use token")
        token_path = root / "enrollment.token"
        private_write(token_path, match.group(1) + b"\n")
        enrollment_env = env.copy()
        enrollment_env["HOME"] = str(root / "agent")
        run([artifacts["binaries"]["agent"], "enroll", "--hub-url", tls_url, "--hub-ca-cert", str(ca), "--token-file", str(token_path), "--root", str(agent_root), "--name", "home-v2-pilot", "--user", user, "--gateway-index", "0"], env=enrollment_env)
        token_path.unlink()
        agent_cfg = agent_root / "state" / "agent.json"
        agent_process_env = enrollment_env.copy()
        agent_process_env["RUST_LOG"] = "warn"
        agent_p, agent_id = launch([artifacts["binaries"]["agent"], "run", "--config", str(agent_cfg)], root / "logs" / "agent.log", env=agent_process_env)
        processes.append(agent_p); items.append(agent_id); write_ledger(root, items, True)
        # CLI check proves the Hub inventory route and the pinned authenticated russh target.
        deadline = time.monotonic() + 30
        while True:
            try:
                run([client, "verify", "home-v2-pilot"], env=env, timeout=25)
                break
            except PilotError:
                if time.monotonic() > deadline or agent_p.poll() is not None:
                    raise
                time.sleep(.25)
        identity = {"schema": 1, "source_sha": source_sha, "source_binary_sha256": artifacts["binary_sha256"],
                    "artifact_receipt": artifacts["receipt"], "ports": {"sshd": ssh_port, "hub_http": hub_port, "https": tls_port, "reverse": reverse_port},
                    "hub_url": tls_url, "agent_root": str(agent_root), "controller_config": cfg_path, "tools": tool_paths}
        private_write(root / "pilot.json", json.dumps(identity, sort_keys=True).encode() + b"\n")
        print(f"UP source_sha={source_sha} hub=https://localhost:{tls_port} processes={len(items)}")
    except BaseException:
        try:
            stop_items(root, items)
        except BaseException:
            # Leave all ledgers intact if process ownership cannot be proven during rollback.
            pass
        raise


def action(command: str, root: pathlib.Path, repo: pathlib.Path, expected_sha: str | None) -> None:
    if command == "prepare":
        if os.geteuid() == 0: fail("refusing root execution")
        source_identity(repo, expected_sha or "")
        if root.exists():
            directory(root); marker = marker_read(root)
            if marker["source_sha"] != expected_sha: fail("existing pilot source SHA differs")
            print(f"PREPARED source_sha={expected_sha}"); return
        directory(root.parent, stat.S_IMODE(os.lstat(root.parent).st_mode))
        if os.lstat(root.parent).st_uid != UID: fail("pilot parent must belong to current user")
        private_dir(root)
        private_write(root / MARKER, json.dumps({"schema": SCHEMA, "uid": UID, "source_sha": expected_sha}, sort_keys=True).encode() + b"\n")
        private_dir(root / "logs")
        print(f"PREPARED source_sha={expected_sha}"); return
    directory(root)
    marker = marker_read(root)
    if expected_sha: fail("--source-sha is valid only for prepare")
    if command == "up":
        up(root, repo, marker); return
    if command == "status":
        ledger = ledger_read(root)
        if ledger.get("state") == "running":
            processes = ",".join(f"{item.get('role', 'unknown')}:{item['pid']}" for item in ledger["items"])
            state = ("OWNED-PROCESSES-DEGRADED" if any(process_stopped(item) for item in ledger["items"])
                     else "OWNED-PROCESSES-ALIVE")
            print(f"{state} source_sha={marker['source_sha']} pids={processes}")
        elif ledger.get("state") == "starting":
            print(f"STARTUP-OR-SHUTDOWN-UNCERTAIN source_sha={marker['source_sha']}")
        else:
            print(f"STOPPED source_sha={marker['source_sha']}")
        return
    if command == "check":
        ledger = ledger_read(root)
        if ledger.get("state") != "running" or not ledger.get("items"): fail("pilot is stopped")
        if any(process_stopped(item) for item in ledger["items"]):
            fail("pilot has stopped an owned process; check is not proof of health")
        data = json.loads((root / "pilot.json").read_text())
        env = os.environ.copy(); env["HOME"] = str(root / "controller"); env["HOSTLINK_HUB_CONFIG"] = str(root / "controller" / "hub.json")
        hub = run([str(root / "bin/hostlink"), "hub", "check"], env=env)
        sshd_key = run(["ssh-keyscan", "-p", str(data["ports"]["sshd"]), "127.0.0.1"], timeout=10)
        expected = (root / "gateway" / "host_key.pub").read_text().split()[1]
        if expected not in sshd_key.stdout.decode(errors="replace"): fail("sshd host key does not match the owned key pin")
        verify = run([str(root / "bin/hostlink"), "verify", "home-v2-pilot"], env=env, timeout=30)
        print("HUB_API=PASS\nSSHD_PINNED=PASS\nAGENT_AUTHENTICATED_SSH=PASS")
        _ = hub, verify
        return
    if command == "logs":
        for item in sorted((root / "logs").iterdir()):
            info = os.lstat(item)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != UID or info.st_size > 1024 * 1024: fail("log entry is unsafe or exceeds 1 MiB")
            print(f"===== {item.name} =====")
            sys.stdout.write(item.read_text(encoding="utf-8", errors="replace"))
        return
    if command == "down":
        jobs_safe(root)
        ledger = ledger_read(root)
        if ledger.get("state") == "starting": fail("startup/shutdown state is uncertain; no process was signalled")
        if ledger.get("state") != "running":
            print("STOPPED (already stopped); pilot data preserved."); return
        stop_items(root, ledger["items"])
        print("STOPPED; pilot identity, Hub state, enrollment keys and job history preserved.")
        return
    if command == "purge":
        jobs_safe(root)
        ledger = ledger_read(root)
        if ledger.get("state") != "stopped" or ledger.get("items"): fail("purge requires a stopped owned pilot")
        clean_tree(root)
        shutil.rmtree(root)
        print("PURGED")
        return
    fail("unsupported command")


def main() -> int:
    usage = "Usage: hostlink-v2-pilot.sh prepare|up|status|logs|check|down|purge --root ABS [--source-sha SHA]"
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(usage); return 0
    if len(sys.argv) < 4:
        print(usage, file=sys.stderr); return 2
    command = sys.argv[1]
    if command not in {"prepare", "up", "status", "logs", "check", "down", "purge"}: return 2
    args = sys.argv[2:]
    try:
        if len(args) not in (2, 4) or args[0] != "--root" or (len(args) == 4 and args[2] != "--source-sha"):
            print(usage, file=sys.stderr); return 2
        root_value = args[args.index("--root") + 1]
        expected = args[args.index("--source-sha") + 1] if "--source-sha" in args else None
        if any(item not in ("--root", root_value, "--source-sha", expected) for item in args): return 2
        root = safe_root(root_value)
        repo = pathlib.Path(__file__).resolve().parents[1]
        action(command, root, repo, expected)
        return 0
    except (PilotError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"hostlink-v2-pilot: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
