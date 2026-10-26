#!/usr/bin/env python3
"""Create deterministic, source-bound HostLink Agent package artifacts."""
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
import zipfile
from pathlib import Path

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux", "hostlink-agent"),
    "x86_64-pc-windows-msvc": ("windows", "hostlink-agent.exe"),
    "x86_64-win7-windows-msvc": ("windows", "hostlink-agent.exe"),
    "i686-win7-windows-msvc": ("windows", "hostlink-agent.exe"),
}
WINDOWS_ASSETS = ("Install-HostLink-Agent.ps1", "Run-HostLink-Agent.ps1", "Update-HostLink-Agent.ps1")
EPOCH = (1980, 1, 1, 0, 0, 0)


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


def verify_installer(path: Path, platform: str) -> None:
    content = path.read_text(encoding="utf-8")
    required = ("HubUrl", "AgentUri", "AgentSha256", "AgentVersion", "ArchiveUri", "ArchiveSha256", "Target", "AsSecureString", "AllowAutoRedirect", "bootstrap-verify", "bootstrap-finalize") if platform == "windows" else ("--hub-url", "--agent-url", "--agent-sha256", "--agent-version", "--archive-url", "--archive-sha256", "--target", "bootstrap-verify", "bootstrap-finalize")
    missing = [token for token in required if token not in content]
    if missing:
        raise ValueError(f"installer contract is incomplete: {path.name}")


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
    inputs: list[tuple[str, Path]] = [(executable, binary)]
    installer_asset = repo / "crates" / "agent" / "assets" / ("Install-HostLink-Agent.ps1" if platform == "windows" else "install-hostlink-agent.sh")
    checked_regular(installer_asset)
    verify_installer(installer_asset, platform)
    if platform == "windows":
        for name in WINDOWS_ASSETS:
            path = repo / "crates" / "agent" / "assets" / name
            checked_regular(path)
            inputs.append((name, path))
    total = sum(checked_regular(path)[0] for _, path in inputs)
    if total > MAX_TOTAL:
        raise ValueError("uncompressed package exceeds total size limit")
    files = {name: {"size": size, "sha256": sha} for name, path in inputs for size, sha in [checked_regular(path)]}
    manifest = {"format": 1, "component": "agent", "target": target, "version": version, "files": files}
    inputs.append(("manifest.json", None))  # manifest is materialized in private staging below
    parent = raw_parent
    if not parent.is_dir() or parent.stat().st_uid != uid:
        raise ValueError("output parent must exist and be owned by current user")
    temp = Path(tempfile.mkdtemp(prefix=".hostlink-package-", dir=parent))
    try:
        package_name = f"hostlink-agent-{target}"
        zip_path = temp / f"{package_name}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
            ordered = [(name, path) for name, path in inputs if path is not None]
            ordered.append(("manifest.json", None))
            for name, path in ordered:
                content = canonical_json(manifest) if path is None else path.read_bytes()
                if path is not None:
                    expected_identity = manifest["files"][name]
                    if len(content) != expected_identity["size"] or hashlib.sha256(content).hexdigest() != expected_identity["sha256"]:
                        raise ValueError(f"package input changed while packaging: {name}")
                info = zipfile.ZipInfo(f"{package_name}/{name}", EPOCH)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (0o755 if name == executable else 0o644)) << 16
                info.flag_bits |= 0x800
                archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        with zipfile.ZipFile(zip_path, "r") as archive:
            expected_names = [f"{package_name}/{name}" for name, _ in inputs]
            if archive.namelist() != expected_names:
                raise ValueError("generated ZIP member order does not match the package contract")
            for index, (name, path) in enumerate(inputs):
                item = archive.infolist()[index]
                if stat.S_IFMT(item.external_attr >> 16) != stat.S_IFREG:
                    raise ValueError("generated ZIP contains a non-regular member")
                if path is None and archive.read(item) != canonical_json(manifest):
                    raise ValueError("generated ZIP manifest bytes are not canonical")
                if path is not None:
                    data = archive.read(item)
                    identity = manifest["files"][name]
                    if len(data) != identity["size"] or hashlib.sha256(data).hexdigest() != identity["sha256"]:
                        raise ValueError(f"generated ZIP member does not match manifest: {name}")
        archive_sha = digest(zip_path)
        semver_dir = temp / version
        target_dir = semver_dir / target
        target_dir.mkdir(parents=True, mode=0o700)
        sidecar = target_dir / executable
        shutil.copyfile(binary, sidecar)
        sidecar.chmod(0o700)
        shutil.copyfile(zip_path, semver_dir / zip_path.name)
        shutil.copyfile(repo / "crates/agent/assets/Install-HostLink-Agent.ps1" if platform == "windows" else repo / "crates/agent/assets/install-hostlink-agent.sh", semver_dir / ("Install-HostLink-Agent.ps1" if platform == "windows" else "install-hostlink-agent.sh"))
        installer = semver_dir / ("Install-HostLink-Agent.ps1" if platform == "windows" else "install-hostlink-agent.sh")
        installer.chmod(0o600)
        verify_installer(installer, platform)
        (semver_dir / (zip_path.name + ".sha256")).write_text(f"{archive_sha}  {zip_path.name}\n", encoding="ascii")
        sidecar_sha = digest(sidecar)
        if sidecar_sha != files[executable]["sha256"] or sidecar.stat().st_size != files[executable]["size"]:
            raise ValueError("sidecar bytes do not match packaged executable identity")
        (target_dir / (executable + ".sha256")).write_text(f"{sidecar_sha}  {executable}\n", encoding="ascii")
        receipt = {"format": 1, "source_sha": source_sha, "target": target, "version": version,
                   "archive": zip_path.name, "archive_sha256": archive_sha,
                   "sidecar": f"{version}/{target}/{executable}", "sidecar_sha256": sidecar_sha,
                   "installer": installer.name, "installer_sha256": digest(installer),
                   "files": manifest["files"], "build_receipt": receipt_info}
        (temp / "artifact-receipt.json").write_bytes(canonical_json(receipt))
        (temp / "invite-inputs.json").write_bytes(canonical_json({"version":version,"target":target,"installer_sha256":receipt["installer_sha256"],"agent_sha256":sidecar_sha,"archive_sha256":archive_sha}))
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
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"package-hostlink-agent: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
