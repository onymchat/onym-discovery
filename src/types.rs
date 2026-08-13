//! Document shapes and field validation for the
//! static-snapshot/Ed25519 profile (`Discovery-Static-Ed25519.md` §4).
//!
//! Top-level documents parse strictly (`deny_unknown_fields`); catalog
//! entries decode lossily — a malformed entry is skipped, the snapshot
//! survives.

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::{Host, Url};

use crate::error::Error;

pub const IMPLEMENTATION_PROFILE: &str = "onym:discovery-implementation:static-ed25519-v1";

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
pub const MAX_DESTINATION_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_ENTRIES: usize = 512;
pub const MAX_EXPIRY_WINDOW: time::Duration = time::Duration::days(90);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProviderManifest {
    pub version: u32,
    pub implementation_profile: String,
    pub provider_id: String,
    pub operator: String,
    pub seat: String,
    pub catalogs: Vec<CatalogDescriptor>,
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_profile_uri: Option<String>,
    pub offers: Vec<serde_json::Value>,
    pub valid_until: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CatalogDescriptor {
    pub catalog_id: String,
    pub snapshot: String,
    pub audience: String,
    pub seat_types: Vec<String>,
    pub policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CatalogSnapshot {
    pub version: u32,
    pub implementation_profile: String,
    pub catalog_id: String,
    pub provider_id: String,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_digest: Option<String>,
    pub policy_digest: String,
    pub generated_at: String,
    pub expires_at: String,
    /// Lossy: entries are decoded individually so one malformed entry
    /// cannot take the snapshot down with it.
    pub entries: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CatalogEntry {
    pub component_id: String,
    pub seat_type: String,
    pub manifest: ManifestRef,
    pub operator: String,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
    pub listed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    pub relationship: String,
    pub placement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ManifestRef {
    pub uri: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub uri: String,
    pub digest: String,
}

pub const RELATIONSHIPS: &[&str] = &[
    "none",
    "catalog-subscriber",
    "listing-fee",
    "sponsored-placement",
    "common-owner",
    "catalog-sponsor",
    "other-disclosed",
];

/// `onym:key:<64 lowercase hex>` → 32 raw public-key bytes.
pub fn parse_operator_key(value: &str) -> Result<[u8; 32], Error> {
    let hex_part = value.strip_prefix("onym:key:").ok_or_else(|| {
        Error::Malformed(format!(
            "operator key must start with onym:key: — got {value}"
        ))
    })?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Error::Malformed(
            "operator key must be 64 lowercase hex characters".into(),
        ));
    }
    let bytes = hex::decode(hex_part).map_err(|e| Error::Malformed(e.to_string()))?;
    Ok(bytes.try_into().expect("length checked"))
}

/// `onym:component:<token>` with token in `[a-z0-9-]{1,64}`.
pub fn validate_component_id(value: &str) -> Result<(), Error> {
    let token = value.strip_prefix("onym:component:").ok_or_else(|| {
        Error::Malformed(format!(
            "component id must start with onym:component: — got {value}"
        ))
    })?;
    if token.is_empty()
        || token.len() > 64
        || !token
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(Error::Malformed(format!(
            "invalid component token: {token}"
        )));
    }
    Ok(())
}

/// `[a-z0-9-]{1,64}` — catalog ids.
pub fn validate_catalog_id(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(Error::Malformed(format!("invalid catalog id: {value}")));
    }
    Ok(())
}

/// `sha256:<64 lowercase hex>`.
pub fn validate_digest(value: &str) -> Result<(), Error> {
    let hex_part = value
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Malformed(format!("digest must start with sha256: — got {value}")))?;
    if hex_part.len() != 64
        || !hex_part
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Error::Malformed(
            "digest must be 64 lowercase hex characters".into(),
        ));
    }
    Ok(())
}

/// Profile §7 URI rules: https only, DNS host (no IP literals), no
/// userinfo/query/fragment, default port only.
pub fn validate_uri(value: &str) -> Result<(), Error> {
    let url = Url::parse(value).map_err(|e| Error::Malformed(format!("{value}: {e}")))?;
    if url.scheme() != "https" {
        return Err(Error::Malformed(format!("{value}: scheme must be https")));
    }
    match url.host() {
        Some(Host::Domain(_)) => {}
        _ => {
            return Err(Error::Malformed(format!(
                "{value}: host must be a DNS name"
            )))
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Malformed(format!("{value}: userinfo not allowed")));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Malformed(format!(
            "{value}: query/fragment not allowed"
        )));
    }
    if url.port().is_some() {
        return Err(Error::Malformed(format!(
            "{value}: explicit port not allowed"
        )));
    }
    Ok(())
}

/// RFC 3339 UTC timestamp with `Z` suffix.
pub fn parse_timestamp(value: &str) -> Result<OffsetDateTime, Error> {
    if !value.ends_with('Z') {
        return Err(Error::Malformed(format!(
            "timestamp must be UTC with Z suffix: {value}"
        )));
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| Error::Malformed(format!("{value}: {e}")))
}

pub fn format_timestamp(ts: OffsetDateTime) -> String {
    ts.replace_millisecond(0)
        .expect("zero millisecond is valid")
        .format(&Rfc3339)
        .expect("rfc3339 formatting")
}
