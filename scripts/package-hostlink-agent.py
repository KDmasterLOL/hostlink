#!/usr/bin/env python3
"""Stage one source-bound raw HostLink Agent executable and local provenance."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_FILE = 256 * 1024 * 1024
TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux", "hostlink-agent"),
    "x86_64-pc-windows-msvc": ("windows", "hostlink-agent.exe"),
    "x86_64-win7-windows-msvc": ("windows", "hostlink-agent.exe"),
    "i686-win7-windows-msvc": ("windows", "hostlink-agent.exe"),
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_pe(path: Path, target: str) -> None:
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise ValueError("Windows Agent binary is not a PE executable")
        offset = int.from_bytes(dos[0x3C:0x40], "little")
        stream.seek(offset)
        header = stream.read(6)
    expected = 0x8664 if target.startswith("x86_64-") else 0x14C
    if len(header) != 6 or header[:4] != b"PE\0\0" or int.from_bytes(header[4:6], "little") != expected:
        raise ValueError(f"PE Machine does not match target {target}")


def checked_regular(path: Path, limit: int = MAX_FILE) -> tuple[int, str]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"package input must be a regular non-symlink file: {path.name}")
    if info.st_size <= 0 or info.st_size > limit:
        raise ValueError(f"package input size is outside bounds: {path.name}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"package input is not owned by the current user: {path.name}")
    return info.st_size, digest(path)


def valid_semver(value: str) -> bool:
    pattern = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    return re.fullmatch(pattern, value) is not None


def verify_build_receipt(path: Path, source_sha: str, target: str, binary_sha: str) -> dict:
    checked_regular(path, 4 * 1024 * 1024)
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt_source = receipt.get("source_sha") or receipt.get("source", {}).get("git_sha")
    if receipt_source != source_sha:
        raise ValueError("build receipt source SHA does not match selected source")
    entries = [item for item in receipt.get("targets", []) if item.get("target") == target]
    binaries = [
        b
        for entry in entries
        for b in entry.get("binaries", []) + entry.get("artifacts", [])
        if (b.get("file") or b.get("name")) == "hostlink-agent.exe"
    ]
    if len(binaries) != 1 or binaries[0].get("sha256") != binary_sha:
        raise ValueError("build receipt target/binary SHA-256 does not match input")
    if (receipt.get("status") or receipt.get("result")) != "PE_BUILD_AND_INSPECTION_PASS":
        raise ValueError("build receipt does not record a passing PE build/inspection")
    binary = binaries[0]
    expected_machine = "0x8664" if target.startswith("x86_64-") else "0x14c"
    if str(binary.get("pe_machine", "")).lower() != expected_machine:
        raise ValueError("build receipt does not confirm the exact Windows PE machine")
    subsystem = binary.get("subsystem")
    correct_subsystem = (
        subsystem == "6.0"
        or isinstance(subsystem, dict)
        and subsystem.get("major") == 6
        and subsystem.get("minor") == 0
    )
    if not correct_subsystem:
        raise ValueError("build receipt does not confirm the Windows 6.0 subsystem")
    if (
        binary.get("static_crt_import_check") != "passed"
        and binary.get("dynamic_crt_imports_absent") is not True
    ):
        raise ValueError("build receipt lacks a successful static CRT import check")
    return {"path": str(path), "sha256": digest(path)}


def create_package(repo: Path, source_sha: str, target: str, version: str, binary: Path,
                   output_dir: Path, build_receipt: Path | None = None) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("--source-sha must be a full lowercase Git SHA")
    if not valid_semver(version):
        raise ValueError("--version must be semantic version")
    if target not in TARGETS:
        raise ValueError("unsupported target")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output directory must be new; artifacts are never overwritten")
    if not hasattr(os, "getuid"):
        raise ValueError("packaging requires a platform with verifiable current-user file ownership")
    uid = os.getuid()
    raw_parent = Path(os.path.abspath(output_dir.parent))
    current = Path(raw_parent.anchor)
    for part in raw_parent.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ValueError("output parent path contains a symlink")
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if head != source_sha:
        raise ValueError("source SHA does not match this worktree HEAD")
    if subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain=v1", "--untracked-files=all"], text=True):
        raise ValueError("source worktree must be clean, including untracked files")
    binary = Path(os.path.abspath(binary))
    if not binary.exists() and not binary.is_symlink():
        raise ValueError("binary path does not exist")
    binary_size, binary_sha = checked_regular(binary)
    platform, executable = TARGETS[target]
    if platform == "windows":
        validate_pe(binary, target)
        if target.endswith("win7-windows-msvc") and build_receipt is None:
            raise ValueError("Win7 packages require the same-source PE build receipt")
    receipt_info = verify_build_receipt(build_receipt, source_sha, target, binary_sha) if build_receipt else None
    asset_name = f"hostlink-agent-{target}" + (".exe" if executable.endswith(".exe") else "")
    parent = raw_parent
    if not parent.is_dir() or parent.stat().st_uid != uid:
        raise ValueError("output parent must exist and be owned by current user")
    temp = Path(tempfile.mkdtemp(prefix=".hostlink-package-", dir=parent))
    try:
        asset = temp / asset_name
        shutil.copyfile(binary, asset)
        asset.chmod(0o700)
        if checked_regular(asset) != (binary_size, binary_sha):
            raise ValueError("binary changed while packaging")
        receipt = {"format": 2, "source_sha": source_sha, "target": target, "version": version,
                   "asset": asset_name, "asset_sha256": binary_sha, "asset_size": binary_size,
                   "build_receipt": receipt_info}
        # Local provenance only: never publish this file as a release asset.
        (temp / "artifact-receipt.json").write_bytes(canonical_json(receipt))
        (temp / "artifact-receipt.json").chmod(0o600)
        current_head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        current_status = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain=v1", "--untracked-files=all"], text=True)
        if current_head != source_sha or current_status:
            raise ValueError("source worktree changed during packaging")
        os.rename(temp, output_dir)
        output_dir.chmod(0o700)
        return receipt
    finally:
        if temp.exists():
            shutil.rmtree(temp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--build-receipt", type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    try:
        result = create_package(repo, args.source_sha, args.target, args.version, args.binary, args.output_dir, args.build_receipt)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"package-hostlink-agent: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
