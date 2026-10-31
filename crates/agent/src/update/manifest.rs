//! Package and installed-file identity formats and integrity validation.

use super::private_fs::open_private_file;
use super::{EXECUTABLE_BASE, invalid, invalid_owned};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt,
    io::{self, Read},
    path::Path,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackageManifest {
    pub(super) format: u32,
    pub(super) component: String,
    pub(super) target: String,
    pub(super) version: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    pub(super) files: BTreeMap<String, FileIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallMetadata {
    pub(super) format: u32,
    pub(super) target: String,
    pub(super) installed_version: String,
    pub(super) installed_package_sha256: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    pub(super) installed_files: BTreeMap<String, FileIdentity>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BootstrapReceipt {
    pub(super) format: u32,
    pub(super) component: String,
    pub(super) target: String,
    pub(super) version: String,
    pub(super) archive_sha256: String,
    pub(super) sidecar_sha256: String,
    #[serde(deserialize_with = "deserialize_unique_file_map")]
    pub(super) files: BTreeMap<String, FileIdentity>,
}

pub(super) fn deserialize_unique_file_map<'de, D>(
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
pub(super) fn read_install_metadata(path: &Path) -> io::Result<InstallMetadata> {
    let file = open_private_file(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err(invalid("Agent install metadata exceeds its size limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_owned(format!("invalid Agent install metadata: {error}")))
}

pub(super) fn package_files(target: &str) -> Vec<String> {
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
