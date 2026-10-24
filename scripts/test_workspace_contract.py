"""Static HostLink boundaries; historical wire identifiers remain compatible."""
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


def workspace_crates() -> list[tuple[Path, dict]]:
    members = manifest(ROOT / "Cargo.toml")["workspace"]["members"]
    return [(ROOT / member, manifest(ROOT / member / "Cargo.toml")) for member in members]


class ArchitectureContractTest(unittest.TestCase):
    def test_workspace_members_are_locally_owned_and_finite(self) -> None:
        crates = workspace_crates()
        self.assertEqual(len(crates), 5, "Extraction owns controller, Hub, Agent, protocol, core")
        for crate_path, data in crates:
            with self.subTest(crate=crate_path):
                self.assertTrue(crate_path.resolve().is_relative_to(CRATES))
                self.assertNotIn(data["package"]["name"], FORBIDDEN)

    def test_dependency_graph_never_imports_toolkit_source_or_domain(self) -> None:
        for crate_path, data in workspace_crates():
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, dep in data.get(section, {}).items():
                    with self.subTest(crate=crate_path.name, section=section, name=name):
                        self.assertNotIn(name, FORBIDDEN)
                        if isinstance(dep, dict) and "path" in dep:
                            resolved = (crate_path / dep["path"]).resolve()
                            self.assertTrue(
                                resolved.is_relative_to(ROOT) and resolved.is_dir(),
                                f"Non-HostLink path dependency: {crate_path} {name} -> {resolved}",
                            )

    def test_public_binary_names_are_neutral(self) -> None:
        names = {
            binary["name"]
            for _, data in workspace_crates()
            for binary in data.get("bin", [])
        }
        self.assertTrue(
            {"hostlink", "hostlink-hub", "hostlink-agent"} <= names,
            f"Missing neutral standalone binaries: {names}",
        )

    def test_fresh_agent_bundle_uses_only_hostlink_assets(self) -> None:
        from package_hostlink import FILES

        names = FILES["agent"]["windows"]
        self.assertNotIn("onec.exe", names)
        self.assertEqual(names[0], "hostlink-agent.exe")
        agents = [
            crate_path
            for crate_path, data in workspace_crates()
            if any(binary["name"] == "hostlink-agent" for binary in data.get("bin", []))
        ]
        self.assertEqual(len(agents), 1, "Agent binary must have one owner")
        for asset in names[1:]:
            with self.subTest(asset=asset):
                self.assertTrue((agents[0] / "assets" / asset).is_file())


if __name__ == "__main__":
    unittest.main()
