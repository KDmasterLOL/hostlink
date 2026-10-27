//! Package and installed-file identity formats and integrity validation.

use super::private_fs::is_reparse_point;
use super::private_fs::{file_identities, open_private_file};
#[cfg(windows)]
use super::windows::validate_windows_private_acl;
use super::{EXECUTABLE_BASE, invalid, invalid_owned, validate_sha256};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fmt, fs,
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
    let file = open_private_file(path, false)?;
    #[cfg(windows)]
    validate_windows_private_acl(path, &file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err(invalid("Agent install metadata exceeds its size limit"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid_owned(format!("invalid Agent install metadata: {error}")))
}

pub(super) fn validate_installed(
    bin_root: &Path,
    metadata: &InstallMetadata,
    target: &str,
) -> io::Result<()> {
    if metadata.format != 1 || metadata.target != target {
        return Err(invalid(
            "installed Agent metadata has a different format or target",
        ));
    }
    semver::Version::parse(&metadata.installed_version)
        .map_err(|_| invalid("installed Agent version metadata is malformed"))?;
    validate_sha256(&metadata.installed_package_sha256)
        .map_err(|_| invalid("installed Agent archive digest metadata is malformed"))?;
    let bin_metadata = fs::symlink_metadata(bin_root)?;
    if !bin_metadata.is_dir()
        || bin_metadata.file_type().is_symlink()
        || is_reparse_point(&bin_metadata)
    {
        return Err(invalid(
            "installed Agent bin directory is missing or unsafe",
        ));
    }
    #[cfg(windows)]
    validate_windows_private_acl(bin_root, &bin_metadata)?;
    semver::Version::parse(&metadata.installed_version)
        .map_err(|_| invalid("installed Agent version metadata is malformed"))?;
    validate_sha256(&metadata.installed_package_sha256)
        .map_err(|_| invalid("installed Agent archive digest metadata is malformed"))?;
    let bin_metadata = fs::symlink_metadata(bin_root)?;
    if !bin_metadata.is_dir()
        || bin_metadata.file_type().is_symlink()
        || is_reparse_point(&bin_metadata)
    {
        return Err(invalid(
            "installed Agent bin directory is missing or unsafe",
        ));
    }
    let expected = package_files(target).into_iter().collect::<BTreeSet<_>>();
    let mut actual_names = BTreeSet::new();
    for entry in fs::read_dir(bin_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("installed Agent filename is not valid UTF-8"))?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() || !actual_names.insert(name) {
            return Err(invalid(
                "installed Agent bin contains an unsafe or unexpected entry",
            ));
        }
        #[cfg(windows)]
        validate_windows_private_acl(&entry.path(), &entry.metadata()?)?;
    }
    if actual_names != expected {
        return Err(invalid(
            "installed Agent bin inventory differs from its exact package",
        ));
    }
    let actual = file_identities(bin_root, &package_files(target))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for name in package_files(target) {
            let mode = fs::metadata(bin_root.join(&name))?.mode();
            if mode & 0o022 != 0 || (name == EXECUTABLE_BASE && mode & 0o100 == 0) {
                return Err(invalid("installed Agent package permissions are unsafe"));
            }
        }
    }
    if actual != metadata.installed_files {
        return Err(invalid(
            "installed Agent files do not match their recorded integrity metadata",
        ));
    }
    Ok(())
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
