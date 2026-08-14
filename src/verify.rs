//! Verification per `Discovery-Static-Ed25519.md` §6: provider
//! manifests, snapshot chains, and destination-manifest digests.

use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::canonical::signing_bytes;
use crate::error::Error;
use crate::keys;
use crate::types::*;

pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug)]
pub struct VerifiedManifest {
    pub manifest: ProviderManifest,
    /// Descriptors that survived lossy per-descriptor decoding.
    pub catalogs: Vec<CatalogDescriptor>,
    /// Indexes of `catalogs[]` descriptors that were skipped (unknown
    /// keys or otherwise malformed) — surfaced, never silently dropped.
    pub skipped: Vec<usize>,
}

/// Verify a provider manifest's schema, fields, expiry, and
/// self-signature. Catalog descriptors decode lossily (§4.1): a
/// malformed descriptor is skipped and counted; zero surviving
/// descriptors is `provider_manifest_invalid`.
pub fn verify_manifest(raw: &[u8], now: OffsetDateTime) -> Result<VerifiedManifest, Error> {
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err(Error::ProviderManifestInvalid(format!(
            "manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let manifest: ProviderManifest = serde_json::from_slice(raw)
        .map_err(|e| Error::ProviderManifestInvalid(format!("schema: {e}")))?;
    let invalid = |m: String| Error::ProviderManifestInvalid(m);

    if manifest.version != 1 {
        return Err(invalid(format!("unsupported version {}", manifest.version)));
    }
    if manifest.implementation_profile_id != IMPLEMENTATION_PROFILE {
        return Err(invalid(format!(
            "unsupported implementation profile {}",
            manifest.implementation_profile_id
        )));
    }
    if manifest.seat != "discovery" {
        return Err(invalid(format!(
            "seat must be discovery, got {}",
            manifest.seat
        )));
    }
    validate_component_id(&manifest.provider_id).map_err(|e| invalid(e.to_string()))?;
    let operator_key =
        parse_operator_key(&manifest.operator).map_err(|e| invalid(e.to_string()))?;

    // Lossy per-descriptor decode (§4.1): a descriptor with unknown
    // keys or otherwise malformed is skipped and counted, never
    // document-fatal; zero surviving descriptors is fatal.
    let mut catalogs = Vec::new();
    let mut skipped = Vec::new();
    for (index, value) in manifest.catalogs.iter().enumerate() {
        match decode_descriptor(value) {
            Ok(descriptor) => catalogs.push(descriptor),
            Err(_) => skipped.push(index),
        }
    }
    if catalogs.is_empty() {
        return Err(invalid("no surviving catalog descriptors".into()));
    }
    let mut seen = std::collections::BTreeSet::new();
    for catalog in &catalogs {
        if !seen.insert(catalog.catalog_id.clone()) {
            return Err(invalid(format!(
                "duplicate catalogId {}",
                catalog.catalog_id
            )));
        }
    }
    validate_uri(&manifest.privacy_profile_uri).map_err(|e| invalid(e.to_string()))?;
    validate_digest(&manifest.privacy_profile).map_err(|e| invalid(e.to_string()))?;

    let valid_until = parse_timestamp(&manifest.valid_until).map_err(|e| invalid(e.to_string()))?;
    if valid_until <= now {
        return Err(invalid(format!(
            "manifest expired at {}",
            manifest.valid_until
        )));
    }

    let signature = manifest
        .signature
        .as_deref()
        .ok_or_else(|| invalid("manifest is unsigned".into()))?;
    let bytes = signing_bytes(raw).map_err(|e| invalid(e.to_string()))?;
    keys::verify(&operator_key, &bytes, signature).map_err(|e| invalid(e.to_string()))?;

    Ok(VerifiedManifest {
        manifest,
        catalogs,
        skipped,
    })
}

/// Strict decode + field validation for one `catalogs[]` descriptor.
fn decode_descriptor(value: &Value) -> Result<CatalogDescriptor, Error> {
    let descriptor: CatalogDescriptor = serde_json::from_value(value.clone())
        .map_err(|e| Error::Malformed(format!("descriptor: {e}")))?;
    validate_catalog_id(&descriptor.catalog_id)?;
    validate_uri(&descriptor.snapshot)?;
    validate_digest(&descriptor.policy)?;
    validate_uri(&descriptor.policy_uri)?;
    Ok(descriptor)
}

#[derive(Debug)]
pub struct VerifiedSnapshot {
    pub snapshot: CatalogSnapshot,
    pub entries: Vec<CatalogEntry>,
    /// Indexes of entries that failed lossy decoding and were skipped.
    pub skipped: Vec<usize>,
    pub digest: String,
}

/// Verify a snapshot against its provider manifest and, when given,
/// the exact bytes of the previously accepted snapshot.
pub fn verify_snapshot(
    raw: &[u8],
    manifest: &VerifiedManifest,
    previous_raw: Option<&[u8]>,
    now: OffsetDateTime,
) -> Result<VerifiedSnapshot, Error> {
    if raw.len() > MAX_SNAPSHOT_BYTES {
        return Err(Error::SnapshotInvalid(format!(
            "snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
        )));
    }
    let snapshot: CatalogSnapshot =
        serde_json::from_slice(raw).map_err(|e| Error::SnapshotInvalid(format!("schema: {e}")))?;
    let invalid = |m: String| Error::SnapshotInvalid(m);

    if snapshot.version != 1 {
        return Err(invalid(format!("unsupported version {}", snapshot.version)));
    }
    if snapshot.implementation_profile_id != IMPLEMENTATION_PROFILE {
        return Err(invalid("unsupported implementation profile".into()));
    }
    if snapshot.provider_id != manifest.manifest.provider_id {
        return Err(invalid(format!(
            "providerId {} does not match manifest {}",
            snapshot.provider_id, manifest.manifest.provider_id
        )));
    }
    let descriptor = manifest
        .catalogs
        .iter()
        .find(|c| c.catalog_id == snapshot.catalog_id)
        .ok_or_else(|| {
            invalid(format!(
                "catalogId {} not declared by manifest",
                snapshot.catalog_id
            ))
        })?;
    validate_digest(&snapshot.policy_digest).map_err(|e| invalid(e.to_string()))?;
    if snapshot.policy_digest != descriptor.policy {
        return Err(invalid(
            "policyDigest does not match manifest's pinned policy".into(),
        ));
    }

    // Chain rules.
    if snapshot.sequence == 0 {
        return Err(invalid("sequence starts at 1".into()));
    }
    if snapshot.sequence == 1 {
        if snapshot.previous_digest.is_some() {
            return Err(invalid("sequence 1 must not carry previousDigest".into()));
        }
    } else {
        let prev_digest = snapshot
            .previous_digest
            .as_deref()
            .ok_or_else(|| invalid("sequence > 1 requires previousDigest".into()))?;
        validate_digest(prev_digest).map_err(|e| invalid(e.to_string()))?;
    }
    if let Some(previous_raw) = previous_raw {
        let previous: CatalogSnapshot = serde_json::from_slice(previous_raw)
            .map_err(|e| invalid(format!("previous snapshot: {e}")))?;
        if previous.catalog_id != snapshot.catalog_id {
            return Err(invalid(
                "previous snapshot is for a different catalog".into(),
            ));
        }
        if snapshot.sequence != previous.sequence + 1 {
            return Err(invalid(format!(
                "sequence must increase by 1: previous {} → {}",
                previous.sequence, snapshot.sequence
            )));
        }
        let expected = sha256_digest(previous_raw);
        if snapshot.previous_digest.as_deref() != Some(expected.as_str()) {
            return Err(invalid(
                "previousDigest does not match previous snapshot bytes".into(),
            ));
        }
    }

    // Freshness.
    let generated_at =
        parse_timestamp(&snapshot.generated_at).map_err(|e| invalid(e.to_string()))?;
    let expires_at = parse_timestamp(&snapshot.expires_at).map_err(|e| invalid(e.to_string()))?;
    if expires_at <= generated_at {
        return Err(invalid("expiresAt must be after generatedAt".into()));
    }
    if expires_at - generated_at > MAX_EXPIRY_WINDOW {
        return Err(invalid("expiry window exceeds 90 days".into()));
    }
    // A future-dated generatedAt would let a provider mint freshness
    // past the 90-day ceiling; allow only small clock skew.
    if generated_at > now + CLOCK_SKEW {
        return Err(invalid(format!(
            "generatedAt {} is in the future",
            snapshot.generated_at
        )));
    }
    // Symmetric skew (§4.2/§9): expired only when expiresAt is more
    // than the skew allowance in the past — a fast clock must not
    // reject a fresh snapshot.
    if expires_at + CLOCK_SKEW < now {
        return Err(Error::SnapshotExpired(format!(
            "expired at {}",
            snapshot.expires_at
        )));
    }

    // Signature over the exact fetched bytes' canonical form, by the
    // manifest's operator key.
    let operator_key =
        parse_operator_key(&manifest.manifest.operator).map_err(|e| invalid(e.to_string()))?;
    let signature = snapshot
        .signature
        .as_deref()
        .ok_or_else(|| invalid("snapshot is unsigned".into()))?;
    let bytes = signing_bytes(raw).map_err(|e| invalid(e.to_string()))?;
    keys::verify(&operator_key, &bytes, signature).map_err(|e| invalid(e.to_string()))?;

    // Entries: lossy decode, then strict per-entry field validation;
    // duplicates among surviving entries are fatal.
    if snapshot.entries.len() > MAX_ENTRIES {
        return Err(invalid(format!(
            "{} entries exceeds {MAX_ENTRIES}",
            snapshot.entries.len()
        )));
    }
    let mut entries = Vec::new();
    let mut skipped = Vec::new();
    for (index, value) in snapshot.entries.iter().enumerate() {
        match decode_entry(value) {
            Ok(entry) => entries.push(entry),
            Err(_) => skipped.push(index),
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for entry in &entries {
        if !seen.insert(entry.component_id.clone()) {
            return Err(invalid(format!(
                "duplicate componentId {}",
                entry.component_id
            )));
        }
    }

    Ok(VerifiedSnapshot {
        snapshot,
        entries,
        skipped,
        digest: sha256_digest(raw),
    })
}

fn decode_entry(value: &Value) -> Result<CatalogEntry, Error> {
    let entry: CatalogEntry = serde_json::from_value(value.clone())
        .map_err(|e| Error::Malformed(format!("entry: {e}")))?;
    validate_component_id(&entry.component_id)?;
    if entry.seat_type.is_empty() {
        return Err(Error::Malformed("empty seatType".into()));
    }
    validate_uri(&entry.manifest.uri)?;
    validate_digest(&entry.manifest.digest)?;
    parse_operator_key(&entry.operator)?;
    parse_timestamp(&entry.listed_at)?;
    if let Some(reviewed) = &entry.reviewed_at {
        parse_timestamp(reviewed)?;
    }
    if !RELATIONSHIPS.contains(&entry.relationship.as_str()) {
        return Err(Error::Malformed(format!(
            "unknown relationship {}",
            entry.relationship
        )));
    }
    if entry.placement.is_empty() {
        return Err(Error::Malformed("empty placement".into()));
    }
    for evidence in &entry.evidence {
        validate_uri(&evidence.uri)?;
        validate_digest(&evidence.digest)?;
    }
    Ok(entry)
}

/// Verify fetched destination-manifest bytes against the digest the
/// catalog entry pinned.
pub fn verify_destination(manifest_bytes: &[u8], pinned_digest: &str) -> Result<(), Error> {
    if manifest_bytes.len() > MAX_DESTINATION_MANIFEST_BYTES {
        return Err(Error::EntryManifestMismatch(format!(
            "destination manifest exceeds {MAX_DESTINATION_MANIFEST_BYTES} bytes"
        )));
    }
    let actual = sha256_digest(manifest_bytes);
    if actual != pinned_digest {
        return Err(Error::EntryManifestMismatch(format!(
            "pinned {pinned_digest}, fetched bytes hash to {actual}"
        )));
    }
    Ok(())
}
