//! Package and installed-file identity formats and integrity validation.

mod contents;
mod installed;
pub(crate) use contents::validate_contents;
pub(crate) use installed::{read_installed, read_regular, validate_installed, verify_executable};

pub(crate) const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub(crate) const PACKAGE_MANIFEST: &str = "manifest.json";
pub(crate) const ARCHIVE_DIGEST: &str = "archive.sha256";
pub(crate) const EXECUTABLE_BASE: &str = "hostlink-agent";

pub(crate) fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}
pub(crate) fn invalid_owned(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
pub(crate) fn supported_targets() -> &'static [&'static str] {
    &[
        "x86_64-pc-windows-msvc",
        "x86_64-win7-windows-msvc",
        "i686-win7-windows-msvc",
        "x86_64-unknown-linux-gnu",
    ]
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn target_matches_runtime(target: &str) -> bool {
    target == "x86_64-unknown-linux-gnu"
}
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) fn target_matches_runtime(target: &str) -> bool {
    matches!(
        target,
        "x86_64-pc-windows-msvc" | "x86_64-win7-windows-msvc"
    )
}
#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub(crate) fn target_matches_runtime(target: &str) -> bool {
    target == "i686-win7-windows-msvc"
}
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86")
)))]
pub(crate) fn target_matches_runtime(_target: &str) -> bool {
    false
}

use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageManifest {
    pub(super) format: u32,
    pub(super) component: String,
    pub(super) target: String,
    pub(super) version: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    pub(super) files: BTreeMap<String, FileIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileIdentity {
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BootstrapReceipt {
    pub(super) format: u32,
    pub(super) component: String,
    pub(super) target: String,
    pub(super) version: String,
    pub(super) archive_sha256: String,
    pub(super) sidecar_sha256: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    pub(super) files: BTreeMap<String, FileIdentity>,
}

fn deserialize_unique_file_map<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, FileIdentity>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueFileMapVisitor;

    impl<'de> Visitor<'de> for UniqueFileMapVisitor {
        type Value = BTreeMap<String, FileIdentity>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of unique Agent package file identities")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut files = BTreeMap::new();
            while let Some((name, identity)) = map.next_entry::<String, FileIdentity>()? {
                match files.entry(name) {
                    Entry::Vacant(entry) => {
                        entry.insert(identity);
                    }
                    Entry::Occupied(_) => {
                        return Err(de::Error::custom("duplicate Agent package manifest file"));
                    }
                }
            }
            Ok(files)
        }
    }

    deserializer.deserialize_map(UniqueFileMapVisitor)
}
pub(crate) fn package_files(target: &str) -> Vec<String> {
    let mut files = vec![
        if target.contains("windows") {
            "hostlink-agent.exe"
        } else {
            EXECUTABLE_BASE
        }
        .to_owned(),
    ];
    if target.contains("windows") {
        files.extend(
            [
                "Install-HostLink-Agent.ps1",
                "Run-HostLink-Agent.ps1",
                "Update-HostLink-Agent.ps1",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    files
}
