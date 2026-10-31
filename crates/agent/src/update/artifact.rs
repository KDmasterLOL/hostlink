//! Exactly one caller-approved HTTPS URL/version/target/digest; no release discovery.

use super::{invalid, supported_targets, target_matches_runtime, validate_sha256};
use reqwest::Url;
use self_update::{Release, ReleaseAsset, ReleaseSource};
use std::io;

#[derive(Clone, Debug)]
pub struct Artifact {
    pub(super) url: Url,
    pub(super) sha256: String,
    pub(super) target: String,
    pub(super) version: String,
}

impl Artifact {
    pub fn new(url: &str, sha256: String, target: String, version: String) -> io::Result<Self> {
        Self::parse(url, sha256, target, version, false)
    }

    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn loopback(
        url: &str,
        sha256: String,
        target: String,
        version: String,
    ) -> io::Result<Self> {
        Self::parse(url, sha256, target, version, true)
    }

    fn parse(
        value: &str,
        sha256: String,
        target: String,
        version: String,
        fixture_http: bool,
    ) -> io::Result<Self> {
        validate_sha256(&sha256)?;
        semver::Version::parse(&version).map_err(|_| invalid("exact semantic version required"))?;
        if !supported_targets().contains(&target.as_str()) || !target_matches_runtime(&target) {
            return Err(invalid("unsupported Agent target for this runtime"));
        }
        if value.contains(['\\', '%', '@'])
            || value.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err(invalid(
                "artifact URL requires a literal path without traversal or credentials",
            ));
        }
        let url = Url::parse(value).map_err(|_| invalid("invalid artifact URL"))?;
        let loopback = fixture_http
            && url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some_and(|port| port != 0);
        if (!loopback && url.scheme() != "https")
            || url.host_str().is_none()
            || url.port() == Some(0)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(invalid(
                "credential-free HTTPS artifact URL without a fragment required",
            ));
        }
        let name = format!("hostlink-agent-{target}.zip");
        let tagged = format!("v{version}");
        let segments = url
            .path_segments()
            .ok_or_else(|| invalid("invalid artifact URL path"))?
            .collect::<Vec<_>>();
        if segments.last().copied() != Some(name.as_str())
            || !segments
                .iter()
                .any(|part| *part == version || *part == tagged)
        {
            return Err(invalid(
                "artifact URL must name the exact version and target",
            ));
        }
        Ok(Self {
            url,
            sha256,
            target,
            version,
        })
    }
}

impl ReleaseSource for Artifact {
    fn get_releases(&self) -> self_update::Result<Vec<Release>> {
        Ok(vec![
            Release::builder()
                .version(&self.version)
                .asset(ReleaseAsset::new(
                    format!("hostlink-agent-{}.zip", self.target),
                    self.url.as_str(),
                ))
                .build()?,
        ])
    }
}
