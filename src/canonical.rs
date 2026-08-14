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
//! is key-sorted in **UTF-8 byte order**, which is what §3 requires.
//! Foundation's `.sortedKeys` does NOT conform in general — it sorts
//! case-insensitively, so keys differing only by letter case at a
//! discriminating position diverge; the §10 case-divergence fixture is
//! what pins agreement for any serializer-delegating implementation.
//! serde_json also does not escape `/` and escapes exactly the §3 set
//! (two-char forms plus lowercase `\u00xx` for remaining controls),
//! pinned by the escaping fixture.
//!
//! §3 additionally makes a document with duplicate keys invalid;
//! `serde_json`'s tree decoding is last-key-wins, so duplicates are
//! rejected here by a streaming scan before the tree parse.

use serde_json::Value;

use crate::error::Error;

/// §3: a document with duplicate keys — in any object, at any depth —
/// is invalid. `serde_json::Value` silently keeps the last occurrence,
/// so this streaming visitor walks the raw bytes and fails on the
/// first repeated key instead.
pub fn reject_duplicate_keys(raw: &[u8]) -> Result<(), Error> {
    struct AnyValue;

    impl<'de> serde::de::Deserialize<'de> for AnyValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            struct AnyVisitor;

            impl<'de> serde::de::Visitor<'de> for AnyVisitor {
                type Value = AnyValue;

                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("any JSON value")
                }

                fn visit_bool<E>(self, _: bool) -> Result<AnyValue, E> {
                    Ok(AnyValue)
                }
                fn visit_i64<E>(self, _: i64) -> Result<AnyValue, E> {
                    Ok(AnyValue)
                }
                fn visit_u64<E>(self, _: u64) -> Result<AnyValue, E> {
                    Ok(AnyValue)
                }
                fn visit_f64<E>(self, _: f64) -> Result<AnyValue, E> {
                    Ok(AnyValue)
                }
                fn visit_str<E>(self, _: &str) -> Result<AnyValue, E> {
                    Ok(AnyValue)
                }
                fn visit_unit<E>(self) -> Result<AnyValue, E> {
                    Ok(AnyValue)
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<AnyValue, A::Error>
                where
                    A: serde::de::SeqAccess<'de>,
                {
                    while seq.next_element::<AnyValue>()?.is_some() {}
                    Ok(AnyValue)
                }

                fn visit_map<A>(self, mut map: A) -> Result<AnyValue, A::Error>
                where
                    A: serde::de::MapAccess<'de>,
                {
                    let mut seen = std::collections::BTreeSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if !seen.insert(key.clone()) {
                            return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
                        }
                        map.next_value::<AnyValue>()?;
                    }
                    Ok(AnyValue)
                }
            }

            deserializer.deserialize_any(AnyVisitor)
        }
    }

    serde_json::from_slice::<AnyValue>(raw)
        .map(|_| ())
        .map_err(|e| Error::Malformed(format!("invalid JSON: {e}")))
}

/// Canonical bytes of `raw` with the given top-level fields removed.
pub fn canonical_bytes(raw: &[u8], omit: &[&str]) -> Result<Vec<u8>, Error> {
    reject_duplicate_keys(raw)?;
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
