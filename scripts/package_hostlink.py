#!/usr/bin/env python3
"""Assemble exact, digest-addressed HostLink source artifacts without rebuilding."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


WINDOWS = (
    "x86_64-pc-windows-msvc",
    "x86_64-win7-windows-msvc",
    "i686-win7-windows-msvc",
)
LINUX = ("x86_64-unknown-linux-gnu",)

FILES = {
    "agent": {
        "windows": (
            "hostlink-agent.exe",
            "Install-HostLink-Agent.ps1",
            "Run-HostLink-Agent.ps1",
            "Update-HostLink-Agent.ps1",
        ),
        "linux": ("hostlink-agent",),
    },
    "controller": {
        "windows": ("hostlink.exe",),
        "linux": ("hostlink",),
    },
    "hub": {"linux": ("hostlink-hub",)},
}


def package(component: str, target: str, source: Path, output: Path) -> tuple[Path, Path]:
    if target not in (*WINDOWS, *LINUX):
        raise ValueError(f"unsupported target: {target}")
    platform = "windows" if target in WINDOWS else "linux"
    required = FILES[component].get(platform)
    if required is None:
        raise ValueError(f"{component} does not support {platform}")
    if source.is_symlink() or not source.is_dir():
        raise ValueError("source must be an existing non-symlink directory")
    if output.is_symlink() or not output.is_dir():
        raise ValueError("output must be an existing non-symlink directory")
    for name in required:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"required source file missing or symlinked: {name}")

    stem = f"hostlink-{component}-{target}"
    archive = output / f"{stem}.zip"
    checksum = output / f"{stem}.zip.sha256"
    if archive.exists() or archive.is_symlink() or checksum.exists() or checksum.is_symlink():
        raise FileExistsError("refusing to overwrite existing artifact or checksum")

    fd, temporary = tempfile.mkstemp(prefix=f".{stem}.", suffix=".tmp", dir=output)
    staged = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as sink, ZipFile(
            sink, mode="w", compression=ZIP_DEFLATED, compresslevel=9
        ) as bundle:
            for name in required:
                data = (source / name).read_bytes()
                member = ZipInfo(f"{stem}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
                member.compress_type = ZIP_DEFLATED
                member.create_system = 3
                executable = name.endswith(".exe") or name in {
                    "hostlink", "hostlink-agent", "hostlink-hub"
                }
                member.external_attr = ((0o755 if executable else 0o644) | stat.S_IFREG) << 16
                bundle.writestr(member, data, compress_type=ZIP_DEFLATED, compresslevel=9)
            bundle.close()
            sink.flush()
            os.fsync(sink.fileno())
        with ZipFile(staged) as check:
            if check.testzip() is not None:
                raise ValueError("ZIP CRC verification failed")
            if check.namelist() != [f"{stem}/{name}" for name in required]:
                raise ValueError("ZIP member inventory mismatch")
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        os.link(staged, archive)  # Atomic create-new publication (no overwrite).
        fd_sidecar, pending_sidecar = tempfile.mkstemp(
            prefix=f".{stem}.", suffix=".sha.tmp", dir=output
        )
        try:
            with os.fdopen(fd_sidecar, "w", encoding="ascii", newline="\n") as out:
                out.write(f"{digest}  {archive.name}\n")
                out.flush()
                os.fsync(out.fileno())
            os.link(pending_sidecar, checksum)  # Never overwrite concurrent publisher.
        finally:
            Path(pending_sidecar).unlink(missing_ok=True)
    finally:
        staged.unlink(missing_ok=True)
    return archive, checksum


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=tuple(FILES))
    parser.add_argument("target")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    archive, checksum = package(args.component, args.target, args.source, args.output)
    print(f"archive={archive}\nsha256_sidecar={checksum}")


if __name__ == "__main__":
    main()
