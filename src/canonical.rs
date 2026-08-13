//! Canonical signing bytes for the static-snapshot/Ed25519 profile.
//!
//! Deliberately the same mechanism as `onym-moderation`'s
//! `authority/src/canonical.rs`, which is the system's precedent for
//! cross-language byte agreement. The agreement is pinned by fixtures,
//! not shared code.
//!
//! Encode, drop the `signature` field **structurally**, re-serialize
//! with sorted keys. Removing a signature by string surgery is
//! forgeable: an attacker can plant extra copies of a known signature
//! elsewhere in the document so that removing every occurrence
//! reconstructs the signed bytes while decoding different content.
//!
//! `serde_json::Value` uses a `BTreeMap` for objects, so serialization
//! is key-sorted, matching Swift's `.sortedKeys`; serde_json also does
//! not escape `/`, matching `.withoutEscapingSlashes`.

use serde_json::Value;

use crate::error::Error;

/// Canonical bytes of `raw` with the given top-level fields removed.
pub fn canonical_bytes(raw: &[u8], omit: &[&str]) -> Result<Vec<u8>, Error> {
    let mut value: Value = serde_json::from_slice(raw)
        .map_err(|e| Error::Malformed(format!("malformed JSON: {e}")))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| Error::Malformed("expected a JSON object".into()))?;
    for key in omit {
        object.remove(*key);
    }
    serde_json::to_vec(&value).map_err(|e| Error::Internal(format!("re-serialize: {e}")))
}

/// The bytes an operator signs for a provider manifest or a catalog
/// snapshot: every field except `signature`.
pub fn signing_bytes(raw: &[u8]) -> Result<Vec<u8>, Error> {
    canonical_bytes(raw, &["signature"])
}

/// Serialize a value in canonical (compact, key-sorted) form. Used by
/// the builder so that emitted files are byte-deterministic: the served
/// bytes ARE the canonical bytes plus the `signature` field, which
/// sorts into place like any other key.
pub fn to_canonical_vec(value: &Value) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|e| Error::Internal(format!("serialize: {e}")))
}
