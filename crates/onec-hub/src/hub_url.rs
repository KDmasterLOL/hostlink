//! Typed HTTPS URL policy for onec-hub endpoints and release roots.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::{error::Error, fmt, str::FromStr};
use url::Url;

/// Error returned when a hub/release URL violates the shared HTTPS URL policy.
#[derive(Debug)]
pub struct HubUrlError(HubUrlErrorKind);

#[derive(Debug)]
enum HubUrlErrorKind {
    Policy(String),
    Parse(url::ParseError),
}

impl HubUrlError {
    fn policy(message: impl Into<String>) -> Self {
        Self(HubUrlErrorKind::Policy(message.into()))
    }

    fn parse(source: url::ParseError) -> Self {
        Self(HubUrlErrorKind::Parse(source))
    }
}

impl fmt::Display for HubUrlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            HubUrlErrorKind::Policy(message) => formatter.write_str(message),
            HubUrlErrorKind::Parse(source) => write!(formatter, "invalid onec-hub URL: {source}"),
        }
    }
}

impl Error for HubUrlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0 {
            HubUrlErrorKind::Policy(_) => None,
            HubUrlErrorKind::Parse(source) => Some(source),
        }
    }
}

/// Validated, credential-free HTTPS base/public/release URL shared by onec-hub and onec-access.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HubHttpsUrl(Url);

impl HubHttpsUrl {
    /// Parses and normalizes one absolute credential-free HTTPS hub URL.
    ///
    /// Query, fragment, userinfo, non-HTTPS schemes, and non-hierarchical/hostless URLs are
    /// rejected. Non-root trailing slashes are normalized away.
    ///
    /// # Errors
    ///
    /// Returns [`HubUrlError`] when the URL violates this policy.
    pub fn parse(value: &str) -> Result<Self, HubUrlError> {
        let mut url = Url::parse(value).map_err(HubUrlError::parse)?;
        if url.scheme() != "https" {
            return Err(HubUrlError::policy("onec-hub URL must use https"));
        }
        if url.cannot_be_a_base() || url.host().is_none() {
            return Err(HubUrlError::policy(
                "onec-hub URL must be an absolute hierarchical URL with a host",
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HubUrlError::policy(
                "onec-hub URL must not contain username or password",
            ));
        }
        if url.query().is_some() {
            return Err(HubUrlError::policy("onec-hub URL must not contain a query"));
        }
        if url.fragment().is_some() {
            return Err(HubUrlError::policy(
                "onec-hub URL must not contain a fragment",
            ));
        }

        let normalized_path = if url.path() == "/" {
            "/".to_owned()
        } else {
            url.path().trim_end_matches('/').to_owned()
        };
        url.set_path(&normalized_path);
        Ok(Self(url))
    }

    /// Returns the validated underlying URL.
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    /// Appends path segments without escaping the validated origin/prefix policy.
    ///
    /// # Errors
    ///
    /// Returns [`HubUrlError`] when the underlying URL cannot act as a hierarchical base or the
    /// resulting URL violates [`HubHttpsUrl`] policy.
    pub fn append_segments<'a>(
        &self,
        segments: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, HubUrlError> {
        let mut url = self.0.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| HubUrlError::policy("onec-hub URL cannot be used as a base URL"))?;
            path.pop_if_empty();
            for segment in segments {
                path.push(segment);
            }
        }
        Self::parse(url.as_str())
    }

    /// Returns whether this URL is on the same origin and strictly below `base` by path segments.
    pub fn is_strict_descendant_of(&self, base: &Self) -> bool {
        if self.0.origin() != base.0.origin() {
            return false;
        }
        let Some(base_segments) = base.0.path_segments() else {
            return false;
        };
        let Some(child_segments) = self.0.path_segments() else {
            return false;
        };
        let base_segments = base_segments
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let child_segments = child_segments
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        child_segments.len() > base_segments.len()
            && child_segments[..base_segments.len()] == base_segments[..]
    }

    fn serialized(&self) -> String {
        let value = self.0.as_str();
        if self.0.path() == "/" {
            value.strip_suffix('/').unwrap_or(value).to_owned()
        } else {
            value.to_owned()
        }
    }
}

impl fmt::Debug for HubHttpsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HubHttpsUrl")
            .field(&self.serialized())
            .finish()
    }
}

impl fmt::Display for HubHttpsUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.serialized())
    }
}

impl FromStr for HubHttpsUrl {
    type Err = HubUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for HubHttpsUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.serialized())
    }
}

impl<'de> Deserialize<'de> for HubHttpsUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_malformed_userinfo_query_fragment_and_plain_http() {
        for value in [
            "https://".to_owned(),
            ["https://", "user@", "hub.example.test"].concat(),
            ["https://", "user:secret@", "hub.example.test"].concat(),
            "https://hub.example.test?mode=test".to_owned(),
            "https://hub.example.test#fragment".to_owned(),
            "http://hub.example.test".to_owned(),
        ] {
            assert!(HubHttpsUrl::parse(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn malformed_url_preserves_typed_source_without_echoing_raw_input() {
        let value = ["https://", "user:super-secret@", "[::1"].concat();
        let expected_source = Url::parse(&value).expect_err("fixture URL must be invalid");
        let error = HubHttpsUrl::parse(&value).expect_err("malformed URL must fail");

        assert_eq!(
            error.to_string(),
            format!("invalid onec-hub URL: {expected_source}")
        );
        assert!(!error.to_string().contains("super-secret"));
        assert!(!format!("{error:?}").contains("super-secret"));
        assert!(
            Error::source(&error)
                .and_then(|source| source.downcast_ref::<url::ParseError>())
                .is_some()
        );
    }

    #[test]
    fn policy_error_keeps_existing_message_without_parser_source() {
        let error =
            HubHttpsUrl::parse("http://hub.example.test").expect_err("plain HTTP must fail");
        assert_eq!(error.to_string(), "onec-hub URL must use https");
        assert!(Error::source(&error).is_none());
    }

    #[test]
    fn normalization_preserves_prefix_ports_ipv6_and_string_serde() {
        let prefixed = HubHttpsUrl::parse("https://hub.example.test:8443/root/api/").unwrap();
        assert_eq!(
            prefixed.to_string(),
            "https://hub.example.test:8443/root/api"
        );
        assert_eq!(
            serde_json::to_string(&prefixed).unwrap(),
            r#""https://hub.example.test:8443/root/api""#
        );
        let round_trip: HubHttpsUrl =
            serde_json::from_str(&serde_json::to_string(&prefixed).unwrap()).unwrap();
        assert_eq!(round_trip, prefixed);

        let ipv6 = HubHttpsUrl::parse("https://[2001:db8::1]:8443/hub/").unwrap();
        assert_eq!(ipv6.to_string(), "https://[2001:db8::1]:8443/hub");
        assert_eq!(
            HubHttpsUrl::parse("https://hub.example.test").unwrap(),
            HubHttpsUrl::parse("https://hub.example.test/").unwrap()
        );
    }

    #[test]
    fn path_segment_append_preserves_prefix_and_encodes_dynamic_segment() {
        let base = HubHttpsUrl::parse("https://hub.example.test/prefix").unwrap();
        let endpoint = base
            .append_segments(["v1", "agents", "machine/id"])
            .unwrap();
        assert_eq!(
            endpoint.to_string(),
            "https://hub.example.test/prefix/v1/agents/machine%2Fid"
        );
    }

    #[test]
    fn descendant_requires_same_origin_and_segment_boundary() {
        let base = HubHttpsUrl::parse("https://downloads.example.test:8443/releases").unwrap();
        let child = HubHttpsUrl::parse(
            "https://downloads.example.test:8443/releases/v1/Install-OnecToolkit.ps1",
        )
        .unwrap();
        let sibling =
            HubHttpsUrl::parse("https://downloads.example.test:8443/releases-old/file").unwrap();
        let other = HubHttpsUrl::parse("https://other.example.test/releases/v1/file").unwrap();
        assert!(child.is_strict_descendant_of(&base));
        assert!(!sibling.is_strict_descendant_of(&base));
        assert!(!other.is_strict_descendant_of(&base));
    }
}
