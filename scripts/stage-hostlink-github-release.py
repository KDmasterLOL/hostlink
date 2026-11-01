#!/usr/bin/env python3
"""Stage verified, uniquely named HostLink GitHub Release assets; never publish."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

TARGETS = {
    "x86_64-unknown-linux-gnu": "hostlink-agent",
    "x86_64-pc-windows-msvc": "hostlink-agent.exe",
    "x86_64-win7-windows-msvc": "hostlink-agent.exe",
    "i686-win7-windows-msvc": "hostlink-agent.exe",
}


def checked_file(path: Path, expected_sha: str, max_bytes: int) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > max_bytes:
        raise ValueError(f"invalid release input: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ValueError(f"release input is not owned by current user: {path}")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64 or any(char not in "0123456789abcdef" for char in expected_sha):
        raise ValueError(f"invalid pinned checksum: {path}")
    hasher = hashlib.sha256()
    with path.open("rb") as data:
        for block in iter(lambda: data.read(1024 * 1024), b""):
            hasher.update(block)
    if hasher.hexdigest() != expected_sha:
        raise ValueError(f"release input differs from package receipt: {path}")

def stage(packages: list[Path], output: Path, require_all_targets: bool = False) -> dict:
    if not packages:
        raise ValueError("at least one package receipt is required")
    if output.exists() or output.is_symlink():
        raise ValueError("release output must be a new directory")
    parent = output.absolute().parent
    if not parent.is_dir() or any(p.is_symlink() for p in (parent, *parent.parents)):
        raise ValueError("release output parent must be an existing directory")
    if hasattr(os, "getuid") and parent.stat().st_uid != os.getuid():
        raise ValueError("release output parent must be user-owned")
    version = source_sha = None
    staged: dict[str, tuple[Path, str, int]] = {}
    seen_targets: set[str] = set()
    for package in packages:
        if any(p.is_symlink() for p in (package.absolute(), *package.absolute().parents)) or not package.is_dir():
            raise ValueError("package input must be a directory, not a symlink")
        receipt_path = package / "artifact-receipt.json"
        if not receipt_path.is_file() or receipt_path.is_symlink() or receipt_path.stat().st_size > 65536:
            raise ValueError("missing or unsafe artifact receipt")
        receipt = json.loads(receipt_path.read_text("utf-8"))
        if not isinstance(receipt, dict):
            raise ValueError("artifact receipt must be a JSON object")
        target = receipt.get("target")
        v = receipt.get("version")
        source = receipt.get("source_sha")
        if (not isinstance(target, str) or target not in TARGETS or not isinstance(v, str)
                or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", v) is None
                or not isinstance(source, str) or re.fullmatch(r"[0-9a-f]{40}", source) is None):
            raise ValueError("invalid source, version or target")
        if target in seen_targets:
            raise ValueError(f"duplicate release target: {target}")
        seen_targets.add(target)
        if version is None:
            version, source_sha = v, source
        elif version != v or source_sha != source:
            raise ValueError("release packages come from different versions or source revisions")
        asset_name = f"hostlink-agent-{target}" + (".exe" if TARGETS[target].endswith(".exe") else "")
        expected_fields = {"format", "source_sha", "target", "version", "asset", "asset_sha256", "asset_size", "build_receipt"}
        if receipt.get("format") != 2 or set(receipt) != expected_fields or receipt.get("asset") != asset_name:
            raise ValueError("package receipt disagrees with the raw binary convention")
        if {entry.name for entry in package.iterdir()} != {asset_name, "artifact-receipt.json"}:
            raise ValueError("package must contain exactly one raw binary and its local receipt")
        size = receipt.get("asset_size")
        if type(size) is not int or not 0 < size <= 256 * 1024 * 1024:
            raise ValueError("invalid raw binary size")
        file = package / asset_name
        sha = receipt.get("asset_sha256")
        checked_file(file, sha, 256 * 1024 * 1024)
        if file.stat().st_size != size:
            raise ValueError("raw binary size differs from package receipt")
        staged[asset_name] = (file, sha, size)
    if require_all_targets and seen_targets != set(TARGETS):
        raise ValueError("release must include every supported Agent target")
    staging = Path(tempfile.mkdtemp(prefix=".hostlink-github-release-", dir=parent))
    try:
        files = {}
        for name, (source, expected_sha, expected_size) in sorted(staged.items()):
            target = staging / name
            shutil.copyfile(source, target)
            target.chmod(0o600)
            checked_file(target, expected_sha, 256 * 1024 * 1024)
            if target.stat().st_size != expected_size:
                raise ValueError("raw binary changed during release staging")
            files[name] = expected_sha
        # Hidden receipt stays local; a shell glob used to upload release assets
        # must not accidentally publish build-machine provenance metadata.
        (staging / ".release-receipt.json").write_text(
            json.dumps({"version": version, "source_sha": source_sha, "assets": files, "targets": sorted(seen_targets)}, sort_keys=True, indent=2) + "\n",
            encoding="ascii",
        )
        os.rename(staging, output)
        output.chmod(0o700)
        return {"version": version, "source_sha": source_sha, "assets": files, "targets": sorted(seen_targets)}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, required=True, action="append", dest="packages")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--require-all-targets", action="store_true")
    args = parser.parse_args()
    try:
        result = stage(args.packages, args.output_dir, args.require_all_targets)
    except (ValueError, OSError) as error:
        print(f"stage-hostlink-github-release: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
