"""Static HostLink workspace boundaries; allow immutable historical wire identifiers."""
from __future__ import annotations

from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
CRATES = ROOT / "crates"

FORBIDDEN = {
    "onec-core",
    "onec-cli",
    "onec-project",
    "onec-infobase",
    "onec-1cv8",
    "onec-metadata",
}


def manifest(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


class ArchitectureContractTest(unittest.TestCase):
    def test_workspace_has_only_independently_owned_crates(self) -> None:
        actual = set(manifest(ROOT / "Cargo.toml")["workspace"]["members"])
        self.assertEqual(
            actual,
            {
                "crates/onec-access",
                "crates/onec-hub",
                "crates/onec-agent",
                "crates/onec-agent-protocol",
                "crates/hostlink-core",
            },
        )

    def test_dependency_graph_never_imports_toolkit_source_or_domain(self) -> None:
        for cargo_file in CRATES.glob("*/Cargo.toml"):
            data = manifest(cargo_file)
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, dep in data.get(section, {}).items():
                    with self.subTest(crate=cargo_file.parent.name, section=section, name=name):
                        self.assertNotIn(name, FORBIDDEN)
                        if isinstance(dep, dict) and "path" in dep:
                            resolved = (cargo_file.parent / dep["path"]).resolve()
                            self.assertTrue(
                                resolved.is_relative_to(ROOT) and resolved.is_dir(),
                                f"Non-HostLink path dependency: {cargo_file} {name} -> {resolved}",
                            )

    def test_public_binary_names_are_neutral(self) -> None:
        expected = {
            "onec-access": "hostlink",
            "onec-hub": "hostlink-hub",
            "onec-agent": "hostlink-agent",
        }
        for folder, name in expected.items():
            with self.subTest(crate=folder):
                data = manifest(CRATES / folder / "Cargo.toml")
                binaries = {target["name"] for target in data.get("bin", [])}
                self.assertIn(name, binaries, "Explicit standalone binary name required")

    def test_fresh_agent_bundle_uses_only_hostlink_assets(self) -> None:
        from package_hostlink import FILES
        names = FILES["agent"]["windows"]
        self.assertNotIn("onec.exe", names)
        self.assertEqual(names[0], "hostlink-agent.exe")
        for asset in names[1:]:
            with self.subTest(asset=asset):
                self.assertTrue((CRATES / "onec-agent" / "assets" / asset).is_file())


if __name__ == "__main__":
    unittest.main()
