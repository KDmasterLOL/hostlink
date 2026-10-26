#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/hostlink-v2-pilot.sh prepare --root ABS_PRIVATE_ROOT --source-sha EXACT_SHA
  scripts/hostlink-v2-pilot.sh status  --root ABS_PRIVATE_ROOT
  scripts/hostlink-v2-pilot.sh logs    --root ABS_PRIVATE_ROOT
  scripts/hostlink-v2-pilot.sh down    --root ABS_PRIVATE_ROOT
  scripts/hostlink-v2-pilot.sh purge   --root ABS_PRIVATE_ROOT
EOF
}

command_name=${1:-}
if [[ -z "$command_name" ]]; then usage >&2; exit 2; fi
if [[ "$command_name" == -h || "$command_name" == --help ]]; then usage; exit 0; fi
shift
root=
source_sha=
while (($#)); do
  case "$1" in
    --root)
      (($# >= 2)) || { usage >&2; exit 2; }
      root=$2
      shift 2
      ;;
    --source-sha)
      (($# >= 2)) || { usage >&2; exit 2; }
      source_sha=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$root" ]] || { echo '--root is required' >&2; exit 2; }
if [[ "$command_name" == prepare ]]; then
  [[ -n "$source_sha" ]] || { echo '--source-sha is required for prepare' >&2; exit 2; }
else
  [[ -z "$source_sha" ]] || { echo '--source-sha is valid only for prepare' >&2; exit 2; }
fi

python3 - "$command_name" "$root" "$source_sha" "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)" <<'PY'
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile

action, raw_root, expected_sha, source_root = sys.argv[1:]
uid = os.getuid()
marker_name = ".hostlink-v2-pilot.json"
schema = 1


def fail(message):
    print(f"hostlink-v2-pilot: {message}", file=sys.stderr)
    raise SystemExit(2)


def checked_path(raw):
    path = pathlib.Path(raw)
    if not path.is_absolute() or raw != os.path.normpath(raw):
        fail("root must be a normalized absolute path")
    if raw == "/":
        fail("filesystem root cannot be a pilot root")
    cursor = pathlib.Path("/")
    for part in path.parts[1:]:
        cursor = cursor / part
        try:
            info = os.lstat(cursor)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            fail("root path contains a symbolic link")
    return path


def check_directory(path, *, private=False):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        fail("pilot root does not exist; run prepare first")
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail("pilot root is not a real directory")
    if info.st_uid != uid:
        fail("pilot root is not owned by the current user")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        fail("pilot root permissions must be exactly 0700")


def read_marker(path):
    marker = path / marker_name
    try:
        info = os.lstat(marker)
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            fail("pilot marker is not a regular file")
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600:
            fail("pilot marker ownership or permissions are invalid")
        with marker.open("r", encoding="utf-8") as stream:
            data = json.load(stream)
    except FileNotFoundError:
        fail("pilot marker is missing")
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail("pilot marker is malformed or unreadable")
    if not isinstance(data, dict) or data != {
        "schema": schema,
        "uid": uid,
        "source_sha": data.get("source_sha") if isinstance(data, dict) else None,
    }:
        fail("pilot marker schema or owner does not match")
    if not isinstance(data["source_sha"], str) or not re.fullmatch(r"[0-9a-f]{40}", data["source_sha"]):
        fail("pilot marker source SHA is invalid")
    return data


def read_state(path, filename):
    state_path = path / filename
    try:
        info = os.lstat(state_path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        return "unknown"
    try:
        with state_path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(payload, dict) or payload.get("state") != "stopped" or payload.get("items") != []:
        return "unknown"
    return "stopped"


def ensure_tree_owned_no_links(path):
    root_dev = os.lstat(path).st_dev
    for current, dirs, files in os.walk(path, topdown=True, followlinks=False):
        for name in dirs + files:
            child = pathlib.Path(current) / name
            info = os.lstat(child)
            if stat.S_ISLNK(info.st_mode):
                fail("purge refused: tree contains a symbolic link")
            if info.st_uid != uid:
                fail("purge refused: tree contains an unowned entry")
            if info.st_dev != root_dev:
                fail("purge refused: tree crosses a filesystem boundary")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                fail("purge refused: tree contains a special file")


root = checked_path(raw_root)
if action not in {"prepare", "status", "logs", "down", "purge"}:
    fail("unsupported command")

if action == "prepare":
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        fail("source SHA must be a 40-character lowercase Git SHA")
    if os.geteuid() == 0:
        fail("refusing root execution")
    try:
        head = subprocess.check_output(["git", "-C", source_root, "rev-parse", "--verify", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
        dirty = subprocess.check_output(["git", "-C", source_root, "status", "--porcelain", "--untracked-files=all"], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        fail("source worktree is not a Git repository")
    if head != expected_sha or dirty:
        fail("source must be the exact clean Git HEAD")
    if root.exists():
        check_directory(root, private=True)
        marker = read_marker(root)
        if marker["source_sha"] != expected_sha:
            fail("existing pilot source SHA differs")
        print(f"PREPARED root={root} source_sha={expected_sha}")
        raise SystemExit(0)
    try:
        parent_info = os.lstat(root.parent)
    except FileNotFoundError:
        fail("pilot parent directory must already exist")
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode) or parent_info.st_uid != uid:
        fail("pilot parent directory must be a real directory owned by the current user")
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    marker_data = {"schema": schema, "uid": uid, "source_sha": expected_sha}
    fd, temp_name = tempfile.mkstemp(prefix=".pilot-marker-", dir=root)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(marker_data, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, root / marker_name)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    (root / "logs").mkdir(mode=0o700)
    print(f"PREPARED root={root} source_sha={expected_sha}")
    raise SystemExit(0)

check_directory(root, private=True)
marker = read_marker(root)
process_state = read_state(root, "processes.json")
job_state = read_state(root, "jobs.json")

if action == "status":
    if process_state is None or process_state == "stopped":
        print(f"PREPARED root={root} source_sha={marker['source_sha']}")
    else:
        print(f"OWNED-PROCESS-UNKNOWN root={root} source_sha={marker['source_sha']}")
    raise SystemExit(0)

if action == "logs":
    logs = root / "logs"
    try:
        info = os.lstat(logs)
    except FileNotFoundError:
        print("No pilot logs.")
        raise SystemExit(0)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
        fail("logs directory is not safely owned")
    entries = sorted(logs.iterdir(), key=lambda item: item.name)
    if len(entries) > 32:
        fail("logs refused: too many files")
    for entry in entries:
        item = os.lstat(entry)
        if not stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode) or item.st_uid != uid:
            fail("logs refused: contains a non-owned or non-regular file")
        if item.st_size > 1024 * 1024:
            fail("logs refused: log exceeds 1 MiB")
    if not entries:
        print("No pilot logs.")
    for entry in entries:
        with entry.open("rb") as stream:
            contents = stream.read(1024 * 1024 + 1)
        if len(contents) > 1024 * 1024:
            fail("logs refused: log grew beyond 1 MiB")
        print(f"===== {entry.name} =====")
        sys.stdout.write(contents.decode("utf-8", errors="replace"))
        if not contents.endswith(b"\n"):
            print()
    raise SystemExit(0)

if action == "down":
    if process_state not in (None, "stopped"):
        fail("process ownership is unknown; root preserved and no PID was signalled")
    if job_state != "stopped" and job_state is not None:
        fail("jobs are active or unknown; root preserved")
    print("STOPPED (already stopped); pilot data preserved.")
    raise SystemExit(0)

if process_state not in (None, "stopped"):
    fail("process ownership is unknown; purge refused")
if job_state not in (None, "stopped"):
    fail("jobs are active or unknown; purge refused")
ensure_tree_owned_no_links(root)
shutil.rmtree(root)
print("PURGED")
PY
