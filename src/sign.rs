//! Deterministic signing: the emitted file bytes are the canonical
//! serialization (compact, key-sorted) with the `signature` field
//! embedded — so published bytes are reproducible from content + key,
//! and the digest other documents pin is stable.

use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::canonical::{signing_bytes, to_canonical_vec};
use crate::error::Error;
use crate::keys;

/// Sign a JSON document: drop any existing `signature`, sign the
/// canonical bytes, embed the new signature, and return the exact
/// bytes to publish.
pub fn sign_document(raw: &[u8], key: &SigningKey) -> Result<Vec<u8>, Error> {
    let bytes_to_sign = signing_bytes(raw)?;
    let signature = keys::sign(key, &bytes_to_sign);
    let mut value: Value =
        serde_json::from_slice(&bytes_to_sign).map_err(|e| Error::Internal(e.to_string()))?;
    value
        .as_object_mut()
        .expect("canonical bytes are an object")
        .insert("signature".into(), Value::String(signature));
    to_canonical_vec(&value)
}

/// The detached-signature sibling contents (base64 of the 64 raw
/// bytes), for `<name>.json.sig` publishing.
pub fn detached_signature(signed_document: &[u8]) -> Result<String, Error> {
    let value: Value = serde_json::from_slice(signed_document)
        .map_err(|e| Error::Malformed(format!("malformed JSON: {e}")))?;
    value
        .get("signature")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Malformed("document has no signature field".into()))
}
