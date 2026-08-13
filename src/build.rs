//! Snapshot builder: turns an operator's source config into a signed,
//! chain-linked snapshot with deterministic bytes.

use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::error::Error;
use crate::sign::sign_document;
use crate::types::*;
use crate::verify::sha256_digest;

/// Operator-authored build config. Entries mirror `CatalogEntry`,
/// except `manifest.digest` may be replaced by `manifestFile`, a local
/// path whose bytes are hashed at build time — the "retrieve and
/// verify, then pin a digest" step of the publication flow.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SnapshotConfig {
    pub catalog_id: String,
    pub provider_id: String,
    pub policy_digest: String,
    /// Days until expiry, counted from generatedAt; ≤ 90.
    pub expiry_days: u16,
    pub entries: Vec<Value>,
}

pub struct BuiltSnapshot {
    pub bytes: Vec<u8>,
    pub sequence: u64,
    pub digest: String,
}

pub fn build_snapshot(
    config: &SnapshotConfig,
    previous_raw: Option<&[u8]>,
    generated_at: OffsetDateTime,
    key: &ed25519_dalek::SigningKey,
    config_dir: &std::path::Path,
) -> Result<BuiltSnapshot, Error> {
    validate_catalog_id(&config.catalog_id)?;
    validate_component_id(&config.provider_id)?;
    validate_digest(&config.policy_digest)?;
    if config.expiry_days == 0 || i64::from(config.expiry_days) > MAX_EXPIRY_WINDOW.whole_days() {
        return Err(Error::Malformed("expiryDays must be 1..=90".into()));
    }

    let (sequence, previous_digest) = match previous_raw {
        None => (1u64, None),
        Some(bytes) => {
            let previous: CatalogSnapshot = serde_json::from_slice(bytes)
                .map_err(|e| Error::Malformed(format!("previous snapshot: {e}")))?;
            if previous.catalog_id != config.catalog_id {
                return Err(Error::Malformed(
                    "previous snapshot is for a different catalog".into(),
                ));
            }
            (previous.sequence + 1, Some(sha256_digest(bytes)))
        }
    };

    let mut entries = Vec::new();
    for raw_entry in &config.entries {
        entries.push(resolve_entry(raw_entry, config_dir)?);
    }

    let expires_at = generated_at + time::Duration::days(i64::from(config.expiry_days));
    let mut document = json!({
        "version": 1,
        "implementationProfile": IMPLEMENTATION_PROFILE,
        "catalogId": config.catalog_id,
        "providerId": config.provider_id,
        "sequence": sequence,
        "policyDigest": config.policy_digest,
        "generatedAt": format_timestamp(generated_at),
        "expiresAt": format_timestamp(expires_at),
        "entries": entries,
    });
    if let Some(previous_digest) = previous_digest {
        document
            .as_object_mut()
            .expect("object")
            .insert("previousDigest".into(), Value::String(previous_digest));
    }

    let unsigned = serde_json::to_vec(&document).map_err(|e| Error::Internal(e.to_string()))?;
    let bytes = sign_document(&unsigned, key)?;
    let digest = sha256_digest(&bytes);
    Ok(BuiltSnapshot {
        bytes,
        sequence,
        digest,
    })
}

/// Resolve `manifestFile` into a pinned digest and validate the entry
/// shape by round-tripping it through the strict decoder.
fn resolve_entry(raw_entry: &Value, config_dir: &std::path::Path) -> Result<Value, Error> {
    let mut entry = raw_entry.clone();
    let object = entry
        .as_object_mut()
        .ok_or_else(|| Error::Malformed("entry must be an object".into()))?;

    if let Some(Value::String(path)) = object.remove("manifestFile") {
        let manifest_bytes = std::fs::read(config_dir.join(&path))?;
        if manifest_bytes.len() > MAX_DESTINATION_MANIFEST_BYTES {
            return Err(Error::Malformed(format!(
                "{path}: destination manifest too large"
            )));
        }
        let digest = sha256_digest(&manifest_bytes);
        let manifest_ref = object
            .entry("manifest")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| Error::Malformed("entry.manifest must be an object".into()))?;
        manifest_ref.insert("digest".into(), Value::String(digest));
    }

    let decoded: CatalogEntry = serde_json::from_value(entry.clone())
        .map_err(|e| Error::Malformed(format!("entry: {e}")))?;
    validate_component_id(&decoded.component_id)?;
    validate_uri(&decoded.manifest.uri)?;
    validate_digest(&decoded.manifest.digest)?;
    parse_operator_key(&decoded.operator)?;
    if !RELATIONSHIPS.contains(&decoded.relationship.as_str()) {
        return Err(Error::Malformed(format!(
            "unknown relationship {}",
            decoded.relationship
        )));
    }
    // Re-serialize through the typed struct so field order and shape
    // are deterministic regardless of config formatting.
    serde_json::to_value(&decoded).map_err(|e| Error::Internal(e.to_string()))
}
