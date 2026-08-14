//! Conformance fixtures and tamper suite per
//! `Discovery-Static-Ed25519.md` §10.
//!
//! Fixtures are deterministic (fixed seed, fixed timestamps) and
//! byte-pinned in `tests/fixtures/`. Regenerate deliberately with:
//!
//! ```sh
//! DISCOVERY_REGEN_FIXTURES=1 cargo test --test conformance
//! ```
//!
//! Client implementations (the iOS `OnymDiscovery` package) consume
//! these exact files; a byte change here is a cross-repo event, not a
//! formality.

use serde_json::{json, Value};
use time::macros::datetime;

use onym_discovery::build::{build_snapshot, SnapshotConfig};
use onym_discovery::canonical::signing_bytes;
use onym_discovery::error::Error;
use onym_discovery::keys;
use onym_discovery::sign::sign_document;
use onym_discovery::types::*;
use onym_discovery::verify::*;

const SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const OTHER_SEED_HEX: &str = "0909090909090909090909090909090909090909090909090909090909090909";
const GENERATED_AT: time::OffsetDateTime = datetime!(2026-08-13 00:00:00 UTC);
const VERIFY_AT: time::OffsetDateTime = datetime!(2026-08-14 00:00:00 UTC);

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn regen() -> bool {
    std::env::var("DISCOVERY_REGEN_FIXTURES").is_ok()
}

fn key() -> ed25519_dalek::SigningKey {
    keys::signing_key_from_seed_hex(SEED_HEX).unwrap()
}

fn operator() -> String {
    keys::operator_id(&key().verifying_key())
}

fn destination_manifest_bytes() -> Vec<u8> {
    // A stand-in courier manifest; discovery pins bytes, the
    // destination seat owns the schema.
    let unsigned = serde_json::to_vec(&json!({
        "version": 1,
        "componentId": "onym:component:onym-courier",
        "seat": "transport.message",
        "operator": operator(),
        "endpoints": [{"uri": "wss://nostr.onym.app", "role": "read-write"}],
        "offers": [{"offerId": "courier-free-v1", "model": "free"}],
        "validUntil": "2026-12-31T23:59:59Z"
    }))
    .unwrap();
    sign_document(&unsigned, &key()).unwrap()
}

fn provider_manifest_bytes() -> Vec<u8> {
    let unsigned = serde_json::to_vec(&json!({
        "version": 1,
        "implementationProfileId": IMPLEMENTATION_PROFILE,
        "providerId": "onym:component:onym-discovery",
        "operator": operator(),
        "seat": "discovery",
        "catalogs": [{
            "catalogId": "public-all-seats",
            "snapshot": "https://discovery.onym.app/catalogs/public-all-seats.json",
            "audience": "public",
            "seatTypes": ["transport.message", "notary", "moderation"],
            "policy": format!("sha256:{}", "11".repeat(32)),
            "policyUri": "https://discovery.onym.app/policies/public-all-seats.md",
        }],
        "capabilities": ["signed-snapshot-v1", "local-filtering-v1"],
        "privacyProfile": format!("sha256:{}", "33".repeat(32)),
        "privacyProfileUri": "https://discovery.onym.app/privacy.md",
        "offers": [],
        "validUntil": "2026-12-31T23:59:59Z"
    }))
    .unwrap();
    sign_document(&unsigned, &key()).unwrap()
}

fn snapshot_config(destination_digest: &str) -> SnapshotConfig {
    let config = json!({
        "catalogId": "public-all-seats",
        "providerId": "onym:component:onym-discovery",
        "policyDigest": format!("sha256:{}", "11".repeat(32)),
        "expiryDays": 30,
        "entries": [{
            "componentId": "onym:component:onym-courier",
            "seatType": "transport.message",
            "manifest": {
                "uri": "https://discovery.onym.app/manifests/onym-courier.json",
                "digest": destination_digest,
            },
            "operator": operator(),
            "profiles": ["onym:message-implementation:nostr-courier-v1"],
            "listedAt": "2026-08-13T00:00:00Z",
            "relationship": "common-owner",
            "placement": "policy-ranked"
        }]
    });
    serde_json::from_value(config).unwrap()
}

fn build_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let destination = destination_manifest_bytes();
    let config = snapshot_config(&sha256_digest(&destination));
    let dir = fixtures_dir();
    let s1 = build_snapshot(&config, None, GENERATED_AT, &key(), &dir).unwrap();
    let s2 = build_snapshot(&config, Some(&s1.bytes), GENERATED_AT, &key(), &dir).unwrap();
    let s3 = build_snapshot(&config, Some(&s2.bytes), GENERATED_AT, &key(), &dir).unwrap();
    (destination, s1.bytes, s2.bytes, s3.bytes)
}

fn scrambled_canonical_input() -> &'static [u8] {
    // Key order deliberately unsorted; canonicalization must produce
    // identical bytes to the sorted equivalent, with `/` unescaped.
    br#"{"zeta": 1, "alpha": {"nested/slash": "a/b", "b": 2, "a": 3}, "signature": "SIG", "mid": [1, 2, 3]}"#
}

#[test]
fn fixtures_match_or_regenerate() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let (destination, s1, s2, s3) = build_chain();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("provider-manifest.json", provider_manifest_bytes()),
        ("destination-manifest.json", destination),
        ("snapshot-1.json", s1),
        ("snapshot-2.json", s2),
        ("snapshot-3.json", s3),
        ("canonical-input.json", scrambled_canonical_input().to_vec()),
        (
            "canonical-bytes.bin",
            signing_bytes(scrambled_canonical_input()).unwrap(),
        ),
    ];
    for (name, bytes) in files {
        let path = dir.join(name);
        if regen() {
            std::fs::write(&path, &bytes).unwrap();
        } else {
            let existing = std::fs::read(&path)
                .unwrap_or_else(|_| panic!("{name} missing — run with DISCOVERY_REGEN_FIXTURES=1"));
            assert_eq!(existing, bytes, "{name} drifted from generated bytes");
        }
    }
}

#[test]
fn valid_chain_verifies() {
    let manifest_raw = provider_manifest_bytes();
    let manifest = verify_manifest(&manifest_raw, VERIFY_AT).unwrap();
    let (_, s1, s2, s3) = build_chain();
    let v1 = verify_snapshot(&s1, &manifest, None, VERIFY_AT).unwrap();
    assert_eq!(v1.snapshot.sequence, 1);
    assert_eq!(v1.entries.len(), 1);
    let v2 = verify_snapshot(&s2, &manifest, Some(&s1), VERIFY_AT).unwrap();
    assert_eq!(v2.snapshot.sequence, 2);
    verify_snapshot(&s3, &manifest, Some(&s2), VERIFY_AT).unwrap();
}

#[test]
fn destination_digest_binds_bytes() {
    let (destination, s1, ..) = build_chain();
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let verified = verify_snapshot(&s1, &manifest, None, VERIFY_AT).unwrap();
    let pinned = &verified.entries[0].manifest.digest;
    verify_destination(&destination, pinned).unwrap();

    let mut tampered = destination.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let err = verify_destination(&tampered, pinned).unwrap_err();
    assert_eq!(err.code(), Some("entry_manifest_mismatch"));
}

#[test]
fn bad_signature_rejected() {
    let mut raw: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    let sig = raw["signature"].as_str().unwrap().to_owned();
    let mut chars: Vec<char> = sig.chars().collect();
    chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
    raw["signature"] = Value::String(chars.into_iter().collect());
    let err = verify_manifest(&serde_json::to_vec(&raw).unwrap(), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
}

#[test]
fn rekeyed_manifest_rejected() {
    // Same content, signed by a different key than `operator` names.
    let mut raw: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    raw.as_object_mut().unwrap().remove("signature");
    let other = keys::signing_key_from_seed_hex(OTHER_SEED_HEX).unwrap();
    let resigned = sign_document(&serde_json::to_vec(&raw).unwrap(), &other).unwrap();
    let err = verify_manifest(&resigned, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
}

#[test]
fn sequence_rollback_and_gap_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, s2, s3) = build_chain();
    // Rollback: sequence 1 presented after sequence 2 was accepted.
    let err = verify_snapshot(&s1, &manifest, Some(&s2), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    // Gap: sequence 3 with sequence 1 as predecessor.
    let err = verify_snapshot(&s3, &manifest, Some(&s1), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn forked_previous_digest_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, s2, _) = build_chain();
    // A fork: same sequence 2, but previousDigest pointing elsewhere.
    let mut fork: Value = serde_json::from_slice(&s2).unwrap();
    fork.as_object_mut().unwrap().remove("signature");
    fork["previousDigest"] = Value::String(format!("sha256:{}", "22".repeat(32)));
    let forked = sign_document(&serde_json::to_vec(&fork).unwrap(), &key()).unwrap();
    let err = verify_snapshot(&forked, &manifest, Some(&s1), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn expired_snapshot_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let late = datetime!(2027-01-01 00:00:00 UTC);
    let err = verify_snapshot(&s1, &manifest, None, late).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_expired"));
}

#[test]
fn duplicate_component_id_rejected() {
    let (_, s1, ..) = build_chain();
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let mut doc: Value = serde_json::from_slice(&s1).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    let entry = doc["entries"][0].clone();
    doc["entries"].as_array_mut().unwrap().push(entry);
    let doubled = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let err = verify_snapshot(&doubled, &manifest, None, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn malformed_entry_skipped_not_fatal() {
    let (_, s1, ..) = build_chain();
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let mut doc: Value = serde_json::from_slice(&s1).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["entries"]
        .as_array_mut()
        .unwrap()
        .push(json!({"componentId": "onym:component:broken"}));
    let lossy = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let verified = verify_snapshot(&lossy, &manifest, None, VERIFY_AT).unwrap();
    assert_eq!(verified.entries.len(), 1);
    assert_eq!(verified.skipped, vec![1]);
}

#[test]
fn uri_rules_enforced() {
    for bad in [
        "http://discovery.onym.app/catalog.json",
        "https://discovery.onym.app/catalog.json?user=1",
        "https://discovery.onym.app/catalog.json#frag",
        "https://192.168.1.1/catalog.json",
        "https://[::1]/catalog.json",
        "https://user@discovery.onym.app/catalog.json",
        "https://discovery.onym.app:8443/catalog.json",
    ] {
        assert!(validate_uri(bad).is_err(), "{bad} should be rejected");
    }
    validate_uri("https://discovery.onym.app/catalogs/public.json").unwrap();
}

#[test]
fn unknown_top_level_field_rejected_strictly() {
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["surprise"] = json!(true);
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let err = verify_manifest(&signed, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
}

#[test]
fn planted_signature_does_not_survive_canonicalization() {
    // Only the TOP-LEVEL signature field is removed structurally; a
    // planted nested "signature" stays inside the signed bytes, so it
    // cannot be used to reconstruct signed bytes from different
    // content (the string-surgery forgery the profile §3 forbids).
    let doc = br#"{"a": {"signature": "PLANTED"}, "signature": "REAL"}"#;
    let canonical = signing_bytes(doc).unwrap();
    let text = String::from_utf8(canonical).unwrap();
    assert!(
        text.contains("PLANTED"),
        "nested signature must remain signed content"
    );
    assert!(
        !text.contains("REAL"),
        "top-level signature must be dropped"
    );
}

#[test]
fn canonicalization_sorts_and_preserves_slashes() {
    let canonical = signing_bytes(scrambled_canonical_input()).unwrap();
    let expected = br#"{"alpha":{"a":3,"b":2,"nested/slash":"a/b"},"mid":[1,2,3],"zeta":1}"#;
    assert_eq!(canonical, expected);
}

#[test]
fn oversize_snapshot_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let padding = "x".repeat(MAX_SNAPSHOT_BYTES);
    let oversized = format!("{{\"pad\": \"{padding}\"}}");
    let err = verify_snapshot(oversized.as_bytes(), &manifest, None, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn error_matches_expected_variant() {
    // Guard the Error::code mapping itself.
    assert_eq!(
        Error::EntryManifestMismatch(String::new()).code(),
        Some("entry_manifest_mismatch")
    );
    assert_eq!(Error::Malformed(String::new()).code(), None);
}

#[test]
fn unknown_key_descriptor_skipped_not_fatal() {
    // §4.1: a descriptor with unknown keys is skipped and counted,
    // never document-fatal — valid siblings survive.
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    let mut extra = doc["catalogs"][0].clone();
    extra["catalogId"] = json!("second-catalog");
    extra["surprise"] = json!(true);
    doc["catalogs"].as_array_mut().unwrap().push(extra);
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let verified = verify_manifest(&signed, VERIFY_AT).unwrap();
    assert_eq!(verified.catalogs.len(), 1);
    assert_eq!(verified.catalogs[0].catalog_id, "public-all-seats");
    assert_eq!(verified.skipped, vec![1]);
}

#[test]
fn zero_surviving_descriptors_invalid() {
    // §4.1: a manifest whose descriptors all fail lossy decode is
    // provider_manifest_invalid, never an empty-but-valid source.
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["catalogs"][0]["surprise"] = json!(true);
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let err = verify_manifest(&signed, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
}

#[test]
fn missing_required_privacy_or_policy_fields_rejected() {
    // privacyProfile/privacyProfileUri are required at the top level;
    // a descriptor without policyUri fails its lossy decode.
    for field in ["privacyProfile", "privacyProfileUri"] {
        let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
        doc.as_object_mut().unwrap().remove("signature");
        doc.as_object_mut().unwrap().remove(field);
        let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
        let err = verify_manifest(&signed, VERIFY_AT).unwrap_err();
        assert_eq!(err.code(), Some("provider_manifest_invalid"), "{field}");
    }
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["catalogs"][0].as_object_mut().unwrap().remove("policyUri");
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let err = verify_manifest(&signed, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
}

#[test]
fn expiry_skew_boundary() {
    // §4.2/§9: expired only when expiresAt is MORE than 10 minutes in
    // the past. The chain expires 30 days after GENERATED_AT.
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let expires_at = datetime!(2026-09-12 00:00:00 UTC);
    // Exactly 10 minutes past expiry: within the skew allowance.
    verify_snapshot(&s1, &manifest, None, expires_at + time::Duration::minutes(10)).unwrap();
    // One second beyond the allowance: snapshot_expired.
    let err = verify_snapshot(
        &s1,
        &manifest,
        None,
        expires_at + time::Duration::minutes(10) + time::Duration::seconds(1),
    )
    .unwrap_err();
    assert_eq!(err.code(), Some("snapshot_expired"));
}

#[test]
fn future_dated_snapshot_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    // Verify at an instant well before generatedAt (2026-08-13): the
    // snapshot is future-dated from that clock's perspective.
    let early = datetime!(2026-08-01 00:00:00 UTC);
    let err = verify_snapshot(&s1, &manifest, None, early).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}
