//! Verification per `Discovery-Static-Ed25519.md` §6: provider
//! manifests, snapshot chains, and destination-manifest digests.

use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::canonical::{reject_duplicate_keys, signing_bytes};
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
    /// Indexes of descriptors that decoded but whose `audience` is not
    /// exactly `"public"` — skipped per §1, surfaced in the source's
    /// skipped-catalog count, and NOT counted toward manifest
    /// invalidity (a manifest of all-non-public catalogs is a valid,
    /// empty-by-policy source).
    pub audience_skipped: Vec<usize>,
    /// The `catalogId`s of the audience-skipped descriptors, tracked so
    /// a snapshot naming one gets the accurate "audience-skipped
    /// (non-public)" diagnosis instead of "not declared by manifest".
    pub audience_skipped_ids: Vec<String>,
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
    let mut audience_skipped = Vec::new();
    let mut audience_skipped_ids = Vec::new();
    let mut decoded_ids = std::collections::BTreeSet::new();
    for (index, value) in manifest.catalogs.iter().enumerate() {
        match decode_descriptor(value) {
            Ok(descriptor) => {
                // Duplicate detection runs over every DECODED
                // descriptor, audience-skipped or not (§4.1).
                if !decoded_ids.insert(descriptor.catalog_id.clone()) {
                    return Err(invalid(format!(
                        "duplicate catalogId {}",
                        descriptor.catalog_id
                    )));
                }
                if descriptor.audience != "public" {
                    // §1: non-public catalogs are skipped, never a
                    // soft private-catalog path and never invalidity.
                    audience_skipped.push(index);
                    audience_skipped_ids.push(descriptor.catalog_id);
                } else {
                    catalogs.push(descriptor);
                }
            }
            Err(_) => skipped.push(index),
        }
    }
    if decoded_ids.is_empty() {
        return Err(invalid("no decodable catalog descriptors".into()));
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
        audience_skipped,
        audience_skipped_ids,
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
    // §4.1: members are seat-type tokens or the lone `"*"` wildcard; a
    // member matching neither form skips the descriptor (one lossiness
    // model per level).
    for member in &descriptor.seat_types {
        validate_seat_type_member(member)?;
    }
    // An empty `seatTypes` declares a catalog whose policy accepts no
    // seat type at all — not a state §4.1 defines. Treated as a
    // descriptor-skip (consistent with member-invalid → skip) pending
    // the explicit spec pin.
    if descriptor.seat_types.is_empty() {
        return Err(Error::Malformed("empty seatTypes".into()));
    }
    if descriptor.seat_types.iter().any(|m| m == "*") && descriptor.seat_types.len() > 1 {
        return Err(Error::Malformed(
            "\"*\" must appear alone in seatTypes".into(),
        ));
    }
    Ok(descriptor)
}

/// What the client retains per `(providerId, catalogId)` between
/// refreshes (§8): the last accepted snapshot's sequence and digest,
/// plus the catalog's previously declared `policy` digest (the §4.2
/// one-generation transition grace).
#[derive(Debug, Clone)]
pub struct RetainedCatalogState {
    /// The provider the retained snapshot belongs to — retained state
    /// is keyed per `(providerId, catalogId)` (§8), so comparing a
    /// snapshot against state retained for a DIFFERENT provider is a
    /// caller error, rejected distinctly (never a fork or rollback).
    pub provider_id: String,
    /// The catalog the retained snapshot belongs to — same §8 keying:
    /// state retained for a DIFFERENT catalog is a caller error,
    /// rejected distinctly (not as a fork).
    pub catalog_id: String,
    pub sequence: u64,
    pub digest: String,
    pub previous_policy: Option<String>,
}

impl RetainedCatalogState {
    /// Derive retained state from the exact bytes of a previously
    /// accepted snapshot, plus the catalog's previously declared
    /// `policy` digest when the client retained one (the §4.2
    /// one-generation transition grace).
    ///
    /// The grace is bounded to ONE accepted generation, and expiring
    /// it is the CALLER's obligation: drop `previous_policy` after the
    /// first accepted snapshot that cites the manifest's current
    /// policy (the accepted [`VerifiedSnapshot`] reports which digest
    /// matched via its `policy_transition` flag; [`Self::after_acceptance`]
    /// computes the successor state with the drop applied). A retained
    /// `previous_policy` carried indefinitely would let a provider keep
    /// publishing against a superseded policy forever.
    pub fn from_snapshot_bytes(raw: &[u8], previous_policy: Option<String>) -> Result<Self, Error> {
        // §3: duplicate keys make the document invalid — checked
        // BEFORE the tree parse, whose last-key-wins decoding would
        // otherwise let a duplicate-key previous file smuggle a chosen
        // sequence/providerId/catalogId into the retained state.
        reject_duplicate_keys(raw)
            .map_err(|e| Error::Malformed(format!("previous snapshot: {e}")))?;
        let snapshot: CatalogSnapshot = serde_json::from_slice(raw)
            .map_err(|e| Error::Malformed(format!("previous snapshot: {e}")))?;
        Ok(RetainedCatalogState {
            provider_id: snapshot.provider_id,
            catalog_id: snapshot.catalog_id,
            sequence: snapshot.sequence,
            digest: sha256_digest(raw),
            previous_policy,
        })
    }

    /// The state to retain after ACCEPTING `verified` — discharges the
    /// caller obligation documented on [`Self::from_snapshot_bytes`]:
    /// the retained `previous_policy` survives only while the accepted
    /// snapshot still cites it (`policy_transition` true); the first
    /// accepted snapshot citing the manifest's CURRENT policy drops it,
    /// closing the §4.2 one-generation grace window.
    pub fn after_acceptance(
        previous: Option<&RetainedCatalogState>,
        verified: &VerifiedSnapshot,
    ) -> Self {
        RetainedCatalogState {
            provider_id: verified.snapshot.provider_id.clone(),
            catalog_id: verified.snapshot.catalog_id.clone(),
            sequence: verified.snapshot.sequence,
            digest: verified.digest.clone(),
            previous_policy: if verified.policy_transition {
                previous.and_then(|p| p.previous_policy.clone())
            } else {
                None
            },
        }
    }
}

/// §6's four-case chain comparison outcome for an ACCEPTED snapshot
/// (rollback and fork are rejections, not outcomes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    /// No retained state: first acceptance of this catalog. Any
    /// sequence is accepted — TOFU pinning covers trust, and an
    /// established catalog past its first snapshot must be addable.
    FirstAcceptance,
    /// `sequence` = retained + 1 with matching `previousDigest`.
    Successor,
    /// Same sequence, same bytes: the provider simply hasn't published
    /// since. No warning.
    NoOpRefresh,
    /// `sequence` more than retained + 1: accepted with a
    /// source-integrity note (§6). The intermediate-fetch continuity
    /// walk is a fetch-side obligation this offline verifier does not
    /// perform — gap-listed in the profile's §11.
    ForwardJumpWithNote { missed: u64 },
}

#[derive(Debug)]
pub struct VerifiedSnapshot {
    pub snapshot: CatalogSnapshot,
    pub entries: Vec<CatalogEntry>,
    /// Indexes of entries that failed lossy decoding and were skipped.
    pub skipped: Vec<usize>,
    pub digest: String,
    pub outcome: ChainOutcome,
    /// True when `policyDigest` matched the retained PREVIOUS policy
    /// declaration rather than the manifest's current one — accepted
    /// with a surfaced policy-transition note (§4.2). This is the
    /// caller's signal for bounding the grace to one generation: drop
    /// the retained `previous_policy` after the first accepted
    /// snapshot where this is `false` under a retained previous policy
    /// — i.e. the first acceptance that cites the current policy
    /// ([`RetainedCatalogState::after_acceptance`] applies exactly
    /// that rule).
    pub policy_transition: bool,
}

/// Verify a snapshot against its provider manifest and, when given,
/// the retained per-catalog acceptance state (§6/§8).
pub fn verify_snapshot(
    raw: &[u8],
    manifest: &VerifiedManifest,
    retained: Option<&RetainedCatalogState>,
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
            // Distinguish the diagnosis: a catalog the manifest DOES
            // declare but with a non-public audience was skipped per
            // §1 — saying "not declared" would send the operator
            // hunting for a typo that isn't there. Both remain
            // snapshot_invalid.
            if manifest
                .audience_skipped_ids
                .iter()
                .any(|id| id == &snapshot.catalog_id)
            {
                invalid(format!(
                    "catalog {} is audience-skipped (non-public)",
                    snapshot.catalog_id
                ))
            } else {
                invalid(format!(
                    "catalogId {} not declared by manifest",
                    snapshot.catalog_id
                ))
            }
        })?;
    // §8: retained state is per `(providerId, catalogId)` — state
    // retained for a different provider or a different catalog must
    // never be compared against this snapshot's chain (a distinct
    // caller-error rejection, never a "fork" or "rollback").
    if let Some(r) = retained {
        if r.provider_id != snapshot.provider_id {
            return Err(invalid(format!(
                "previous snapshot is from a different provider ({} vs {})",
                r.provider_id, snapshot.provider_id
            )));
        }
        if r.catalog_id != snapshot.catalog_id {
            return Err(invalid(format!(
                "previous snapshot is for a different catalog ({} vs {})",
                r.catalog_id, snapshot.catalog_id
            )));
        }
    }
    validate_digest(&snapshot.policy_digest).map_err(|e| invalid(e.to_string()))?;
    // §4.2 policy-transition grace: the snapshot's policyDigest must
    // match the manifest's current declaration OR the immediately
    // previous declaration the client retained — accepted with a
    // surfaced transition note. Any other digest is snapshot_invalid.
    let mut policy_transition = false;
    if snapshot.policy_digest != descriptor.policy {
        match retained.and_then(|r| r.previous_policy.as_deref()) {
            Some(previous) if previous == snapshot.policy_digest => {
                policy_transition = true;
            }
            _ => {
                return Err(invalid(
                    "policyDigest matches neither the manifest's pinned policy \
                     nor the retained previous declaration"
                        .into(),
                ))
            }
        }
    }

    // Chain rules (structural).
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
    // §6 four-case comparison against the retained acceptance.
    let digest = sha256_digest(raw);
    let outcome = match retained {
        None => ChainOutcome::FirstAcceptance,
        Some(r) => {
            if snapshot.sequence < r.sequence {
                // Rollback.
                return Err(invalid(format!(
                    "rollback: sequence {} after accepted {}",
                    snapshot.sequence, r.sequence
                )));
            } else if snapshot.sequence == r.sequence {
                if digest == r.digest {
                    ChainOutcome::NoOpRefresh
                } else {
                    // Fork: same sequence, different bytes.
                    return Err(invalid(format!(
                        "fork: sequence {} republished with different bytes",
                        snapshot.sequence
                    )));
                }
            } else if snapshot.sequence == r.sequence + 1 {
                if snapshot.previous_digest.as_deref() != Some(r.digest.as_str()) {
                    // Fork: successor that does not chain onto the
                    // retained acceptance.
                    return Err(invalid(
                        "fork: previousDigest does not match retained snapshot digest".into(),
                    ));
                }
                ChainOutcome::Successor
            } else {
                // Forward jump: accepted with a source-integrity note.
                // The §6 intermediate continuity walk is fetch-side
                // and not performed by this offline verifier.
                ChainOutcome::ForwardJumpWithNote {
                    missed: snapshot.sequence - r.sequence - 1,
                }
            }
        }
    };

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
        digest,
        outcome,
        policy_transition,
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
    // §4.2: evidence must be absent or empty in v1 — a non-empty
    // evidence array skips the entry (unrenderable attestation).
    if !entry.evidence.is_empty() {
        return Err(Error::Malformed("non-empty evidence in v1".into()));
    }
    // §4.2: status, when present, is {state: warning|review, uri?};
    // anything else is undecodable and skips the entry. A VALID status
    // must not skip the entry — it is exactly the warning the field
    // exists to surface.
    if let Some(status) = &entry.status {
        if !STATUS_STATES.contains(&status.state.as_str()) {
            return Err(Error::Malformed(format!(
                "unknown status state {}",
                status.state
            )));
        }
        if let Some(uri) = &status.uri {
            validate_uri(uri)?;
        }
    }
    Ok(entry)
}

/// Verify fetched destination-manifest bytes against the digest the
/// catalog entry pinned.
pub fn verify_destination(manifest_bytes: &[u8], pinned_digest: &str) -> Result<(), Error> {
    // §9 pins oversize destination manifests to
    // entry_manifest_unavailable (a fetch-bound failure), not
    // entry_manifest_mismatch (a digest/content conflict).
    if manifest_bytes.len() > MAX_DESTINATION_MANIFEST_BYTES {
        return Err(Error::EntryManifestUnavailable(format!(
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

/// §3 detached-`.sig` agreement, defined AFTER base64 decoding: the
/// embedded signature and the `.sig` file contents must decode to the
/// same 64 signature bytes, regardless of padding differences. A
/// client that fetches the detached form fails closed on disagreement
/// (`snapshot_invalid` when `snapshot` is true, else
/// `provider_manifest_invalid`).
pub fn verify_detached_sig(
    signed_document: &[u8],
    sig_file: &[u8],
    snapshot: bool,
) -> Result<(), Error> {
    let fail = |m: String| {
        if snapshot {
            Error::SnapshotInvalid(m)
        } else {
            Error::ProviderManifestInvalid(m)
        }
    };
    // §3: duplicate keys make the document invalid — checked BEFORE
    // the tree parse, whose last-key-wins decoding would otherwise let
    // a document with two `signature` fields slip through this path.
    reject_duplicate_keys(signed_document).map_err(|e| fail(e.to_string()))?;
    let value: Value = serde_json::from_slice(signed_document)
        .map_err(|e| fail(format!("malformed JSON: {e}")))?;
    let embedded = value
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("document has no signature field".into()))?;
    // Trim trailing line endings including CRLF: a `.sig` written by a
    // CRLF-minded tool must fail (or pass) on the SIGNATURE comparison,
    // not on a stray `\r` corrupting the base64 decode's diagnosis.
    let detached = std::str::from_utf8(sig_file)
        .map_err(|_| fail("detached .sig is not UTF-8".into()))?
        .trim_end_matches(['\r', '\n']);
    let embedded_bytes =
        keys::decode_signature_b64(embedded).map_err(|e| fail(format!("embedded: {e}")))?;
    let detached_bytes =
        keys::decode_signature_b64(detached).map_err(|e| fail(format!("detached: {e}")))?;
    if embedded_bytes != detached_bytes {
        return Err(fail(
            "detached .sig disagrees with embedded signature".into(),
        ));
    }
    Ok(())
}

/// Outcome of the §4.2 cross-catalog equivocation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCatalogCheck {
    /// One provider, no componentId bound to conflicting digests —
    /// explicit, so an empty conflict list can never be misread as
    /// "check not applicable".
    NoConflict,
    /// componentIds bound to conflicting digests within one provider
    /// (always non-empty).
    Conflicts(Vec<String>),
    /// The snapshots do not all share one `providerId` — the check is
    /// defined WITHIN a provider; disagreement between providers is a
    /// §9 `source_conflict`, not provider-level equivocation.
    DifferentProviders,
}

/// §4.2: within one provider, entries for the same `componentId`
/// across its catalogs must carry the same `manifest.digest`; a
/// mismatch is provider-level equivocation, surfaced as a source
/// integrity warning. Returns the offending componentIds, or
/// `DifferentProviders` when the snapshots span providers.
pub fn cross_catalog_equivocation(snapshots: &[&VerifiedSnapshot]) -> CrossCatalogCheck {
    let mut providers = snapshots.iter().map(|s| s.snapshot.provider_id.as_str());
    if let Some(first) = providers.next() {
        if providers.any(|p| p != first) {
            return CrossCatalogCheck::DifferentProviders;
        }
    }
    let conflicts = conflicting_digests(snapshots.iter().map(|s| s.entries.as_slice()));
    if conflicts.is_empty() {
        CrossCatalogCheck::NoConflict
    } else {
        CrossCatalogCheck::Conflicts(conflicts)
    }
}

/// §9 `source_conflict`: two configured sources bind the same
/// `componentId` to different manifest digests — both claims are
/// preserved; the conflict is surfaced, never suppressed. Returns the
/// conflicted componentIds.
pub fn source_conflicts(a: &[CatalogEntry], b: &[CatalogEntry]) -> Vec<String> {
    conflicting_digests([a, b])
}

fn conflicting_digests<'a>(
    entry_sets: impl IntoIterator<Item = &'a [CatalogEntry]>,
) -> Vec<String> {
    let mut bindings: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    let mut conflicted = std::collections::BTreeSet::new();
    for entries in entry_sets {
        for entry in entries {
            match bindings.get(entry.component_id.as_str()) {
                Some(digest) if *digest != entry.manifest.digest => {
                    conflicted.insert(entry.component_id.clone());
                }
                _ => {
                    bindings.insert(&entry.component_id, &entry.manifest.digest);
                }
            }
        }
    }
    conflicted.into_iter().collect()
}
