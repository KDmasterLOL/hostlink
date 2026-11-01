#!/usr/bin/env python3
"""Stage verified, uniquely named HostLink GitHub Release assets; never publish."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import zipfile
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
    if len(expected_sha) != 64 or any(char not in "0123456789abcdef" for char in expected_sha):
        raise ValueError(f"invalid pinned checksum: {path}")
    hasher = hashlib.sha256()
    with path.open("rb") as data:
        for block in iter(lambda: data.read(1024 * 1024), b""):
            hasher.update(block)
    if hasher.hexdigest() != expected_sha:
        raise ValueError(f"release input differs from package receipt: {path}")

def file_digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as data:
        for block in iter(lambda: data.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def stage(packages: list[Path], output: Path, require_all_targets: bool = False) -> dict:
    if not packages:
        raise ValueError("at least one package receipt is required")
    if output.exists() or output.is_symlink():
        raise ValueError("release output must be a new directory")
    parent = output.absolute().parent
    if not parent.is_dir() or parent.is_symlink():
        raise ValueError("release output parent must be an existing directory")
    if hasattr(os, "getuid") and parent.stat().st_uid != os.getuid():
        raise ValueError("release output parent must be user-owned")
    version = source_sha = None
    staged: dict[str, Path] = {}
    seen_targets: set[str] = set()
    for package in packages:
        if package.is_symlink() or not package.is_dir():
            raise ValueError("package input must be a directory, not a symlink")
        receipt_path = package / "artifact-receipt.json"
        if not receipt_path.is_file() or receipt_path.is_symlink() or receipt_path.stat().st_size > 65536:
            raise ValueError("missing or unsafe artifact receipt")
        receipt = json.loads(receipt_path.read_text("utf-8"))
        target = receipt.get("target")
        v = receipt.get("version")
        source = receipt.get("source_sha")
        if target not in TARGETS or not isinstance(v, str) or not isinstance(source, str):
            raise ValueError("invalid source, version or target")
        if target in seen_targets:
            raise ValueError(f"duplicate release target: {target}")
        seen_targets.add(target)
        if version is None:
            version, source_sha = v, source
        elif version != v or source_sha != source:
            raise ValueError("release packages come from different versions or source revisions")
        executable = TARGETS[target]
        zip_name = f"hostlink-agent-{target}.zip"
        sidecar_name = f"hostlink-agent-{target}" + (".exe" if executable.endswith(".exe") else "")
        installer_name = "Install-HostLink-Agent.ps1" if executable.endswith(".exe") else "install-hostlink-agent.sh"
        if receipt.get("archive") != zip_name or receipt.get("sidecar") != f"{v}/{target}/{executable}" or receipt.get("installer") != installer_name:
            raise ValueError("package receipt paths disagree with the GitHub release convention")
        sources = (
            (zip_name, package / v / zip_name, receipt.get("archive_sha256"), 512 * 1024 * 1024),
            (sidecar_name, package / v / target / executable, receipt.get("sidecar_sha256"), 256 * 1024 * 1024),
            (installer_name, package / v / installer_name, receipt.get("installer_sha256"), 1024 * 1024),
        )
        for name, file, sha, limit in sources:
            checked_file(file, sha, limit)
            if name in staged:
                # Shared installer script must be identical across all packages.
                if name != installer_name and name not in ("Install-HostLink-Agent.ps1", "install-hostlink-agent.sh"):
                    raise ValueError(f"duplicate GitHub asset: {name}")
                if file_digest(staged[name]) != sha:
                    raise ValueError(f"same-name installer differs between targets: {name}")
            else:
                staged[name] = file
        with zipfile.ZipFile(package / v / zip_name) as archive:
            package_manifest = f"hostlink-agent-{target}/manifest.json"
            try:
                if archive.getinfo(package_manifest).file_size > 65536:
                    raise ValueError("package manifest exceeds bound")
                metadata = json.loads(archive.read(package_manifest))
            except (KeyError, json.JSONDecodeError) as error:
                raise ValueError("missing/invalid package manifest") from error
            if metadata.get("format") != 2 or metadata.get("component") != "agent" or metadata.get("target") != target or metadata.get("version") != v:
                raise ValueError("ZIP metadata does not match release selection")
            if metadata.get("files", {}).get(executable, {}).get("sha256") != receipt.get("sidecar_sha256"):
                raise ValueError("ZIP executable identity differs from sidecar")
    if require_all_targets and seen_targets != set(TARGETS):
        raise ValueError("release must include every supported Agent target")
    staging = Path(tempfile.mkdtemp(prefix=".hostlink-github-release-", dir=parent))
    try:
        files = {}
        for name, source in sorted(staged.items()):
            target = staging / name
            shutil.copyfile(source, target)
            target.chmod(0o600)
            checksum = file_digest(target)
            files[name] = checksum
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
    except (ValueError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print(f"stage-hostlink-github-release: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
