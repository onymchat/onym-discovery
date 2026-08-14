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
//! Client implementations (the iOS and Android discovery packages)
//! consume these exact files; a byte change here is a cross-repo
//! event, not a formality.
//!
//! §10 item 9 (the privacy fetch trace) is not representable as an
//! offline byte fixture — it is a network-behavior obligation on
//! clients (snapshot download + local filtering, no per-query
//! requests, no cookies or identifiers) and is discharged by client
//! test suites, not by a file here.

use serde_json::{json, Value};
use time::macros::datetime;

use onym_discovery::build::{build_snapshot, SnapshotConfig};
use onym_discovery::canonical::{reject_duplicate_keys, signing_bytes};
use onym_discovery::error::Error;
use onym_discovery::keys;
use onym_discovery::sign::{detached_signature, sign_document};
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

fn other_key() -> ed25519_dalek::SigningKey {
    keys::signing_key_from_seed_hex(OTHER_SEED_HEX).unwrap()
}

fn operator() -> String {
    keys::operator_id(&key().verifying_key())
}

fn retained(bytes: &[u8]) -> RetainedCatalogState {
    RetainedCatalogState::from_snapshot_bytes(bytes, None).unwrap()
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

/// §10 item 10: the provider manifest re-signed with a NEW policy
/// digest, while the latest snapshot still cites the previous one.
fn transition_manifest_bytes() -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["catalogs"][0]["policy"] = json!(format!("sha256:{}", "22".repeat(32)));
    sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap()
}

/// §10 item 13: a valid manifest whose single catalog is non-public —
/// an empty-by-policy source, skip count surfaced, never invalid.
fn audience_skip_manifest_bytes() -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["catalogs"][0]["audience"] = json!("internal");
    sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap()
}

/// §10 item 7: a second, independently keyed provider binding the same
/// componentId to a DIFFERENT manifest digest.
fn conflict_provider_bytes() -> Vec<u8> {
    let unsigned = serde_json::to_vec(&json!({
        "version": 1,
        "implementationProfileId": IMPLEMENTATION_PROFILE,
        "providerId": "onym:component:example-directory",
        "operator": keys::operator_id(&other_key().verifying_key()),
        "seat": "discovery",
        "catalogs": [{
            "catalogId": "public-all-seats",
            "snapshot": "https://directory.example.org/catalogs/public-all-seats.json",
            "audience": "public",
            "seatTypes": ["*"],
            "policy": format!("sha256:{}", "11".repeat(32)),
            "policyUri": "https://directory.example.org/policies/public-all-seats.md",
        }],
        "capabilities": ["signed-snapshot-v1", "local-filtering-v1"],
        "privacyProfile": format!("sha256:{}", "33".repeat(32)),
        "privacyProfileUri": "https://directory.example.org/privacy.md",
        "offers": [],
        "validUntil": "2026-12-31T23:59:59Z"
    }))
    .unwrap();
    sign_document(&unsigned, &other_key()).unwrap()
}

fn conflict_snapshot_bytes() -> Vec<u8> {
    let config: SnapshotConfig = serde_json::from_value(json!({
        "catalogId": "public-all-seats",
        "providerId": "onym:component:example-directory",
        "policyDigest": format!("sha256:{}", "11".repeat(32)),
        "expiryDays": 30,
        "entries": [{
            "componentId": "onym:component:onym-courier",
            "seatType": "transport.message",
            "manifest": {
                "uri": "https://directory.example.org/manifests/onym-courier.json",
                "digest": format!("sha256:{}", "44".repeat(32)),
            },
            "operator": operator(),
            "profiles": ["onym:message-implementation:nostr-courier-v1"],
            "listedAt": "2026-08-13T00:00:00Z",
            "relationship": "none",
            "placement": "policy-ranked"
        }]
    }))
    .unwrap();
    build_snapshot(&config, None, GENERATED_AT, &other_key(), &fixtures_dir())
        .unwrap()
        .bytes
}

/// §10 items 6 and the §4.2 status obligation: a snapshot carrying a
/// sponsored-placement disclosure and a disclosed-warning entry, both
/// of which MUST survive into the client's rendered attribution.
fn sponsored_snapshot_bytes(destination_digest: &str) -> Vec<u8> {
    let config: SnapshotConfig = serde_json::from_value(json!({
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
            "relationship": "sponsored-placement",
            "placement": "sponsored"
        }, {
            "componentId": "onym:component:onym-relayer",
            "seatType": "notary",
            "manifest": {
                "uri": "https://relayer.onym.app/manifest.json",
                "digest": format!("sha256:{}", "55".repeat(32)),
            },
            "operator": operator(),
            "listedAt": "2026-08-13T00:00:00Z",
            "relationship": "none",
            "placement": "policy-ranked",
            "status": {
                "state": "warning",
                "uri": "https://discovery.onym.app/status/onym-relayer.md"
            }
        }]
    }))
    .unwrap();
    build_snapshot(&config, None, GENERATED_AT, &key(), &fixtures_dir())
        .unwrap()
        .bytes
}

/// §10 item 12: one provider, two catalogs, the same componentId bound
/// to different manifest digests — provider-level equivocation.
fn equivocation_manifest_bytes() -> Vec<u8> {
    let catalog = |id: &str| {
        json!({
            "catalogId": id,
            "snapshot": format!("https://discovery.onym.app/catalogs/{id}.json"),
            "audience": "public",
            "seatTypes": ["transport.message"],
            "policy": format!("sha256:{}", "11".repeat(32)),
            "policyUri": format!("https://discovery.onym.app/policies/{id}.md"),
        })
    };
    let unsigned = serde_json::to_vec(&json!({
        "version": 1,
        "implementationProfileId": IMPLEMENTATION_PROFILE,
        "providerId": "onym:component:onym-discovery",
        "operator": operator(),
        "seat": "discovery",
        "catalogs": [catalog("catalog-a"), catalog("catalog-b")],
        "capabilities": ["signed-snapshot-v1", "local-filtering-v1"],
        "privacyProfile": format!("sha256:{}", "33".repeat(32)),
        "privacyProfileUri": "https://discovery.onym.app/privacy.md",
        "offers": [],
        "validUntil": "2026-12-31T23:59:59Z"
    }))
    .unwrap();
    sign_document(&unsigned, &key()).unwrap()
}

fn equivocation_snapshot_bytes(catalog_id: &str, digest_byte: &str) -> Vec<u8> {
    let config: SnapshotConfig = serde_json::from_value(json!({
        "catalogId": catalog_id,
        "providerId": "onym:component:onym-discovery",
        "policyDigest": format!("sha256:{}", "11".repeat(32)),
        "expiryDays": 30,
        "entries": [{
            "componentId": "onym:component:onym-courier",
            "seatType": "transport.message",
            "manifest": {
                "uri": "https://discovery.onym.app/manifests/onym-courier.json",
                "digest": format!("sha256:{}", digest_byte.repeat(32)),
            },
            "operator": operator(),
            "listedAt": "2026-08-13T00:00:00Z",
            "relationship": "common-owner",
            "placement": "policy-ranked"
        }]
    }))
    .unwrap();
    build_snapshot(&config, None, GENERATED_AT, &key(), &fixtures_dir())
        .unwrap()
        .bytes
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

fn case_divergence_input() -> &'static [u8] {
    // §10 item 1 case-divergence sub-vector: a SYNTHETIC document
    // whose keys differ only by letter case at a discriminating
    // position. UTF-8 byte order puts uppercase before lowercase
    // ("AB" < "Ab" < "aB" < "ab"); a case-insensitive sort
    // (Foundation's `.sortedKeys`) diverges on exactly this input.
    br#"{"ab": 1, "aB": 2, "Ab": 3, "AB": 4, "signature": "SIG"}"#
}

fn escaping_input() -> &'static [u8] {
    // §10 item 1 escaping sub-vector: every §3 escape class — the
    // two-character forms, `\u00xx` lowercase-hex control characters,
    // unescaped `/`, unescaped non-ASCII, and unescaped U+007F.
    br#"{"controls": "\u0001\u001F", "delete": "\u007F", "quote": "q\"b\\e", "slash": "a/b", "twochar": "\b\f\n\r\t", "unicode": "h\u00E9llo \u2192 \u65E5\u672C", "signature": "SIG"}"#
}

fn duplicate_keys_input() -> &'static [u8] {
    // §3: a document with duplicate keys is invalid — at any depth.
    br#"{"alpha": {"k": 1, "k": 2}, "signature": "SIG"}"#
}

fn mismatched_detached_sig() -> Vec<u8> {
    use base64::Engine as _;
    let mut wrong = [0u8; 64];
    wrong[0] = 1;
    let mut out = base64::engine::general_purpose::STANDARD
        .encode(wrong)
        .into_bytes();
    out.push(b'\n');
    out
}

#[test]
fn fixtures_match_or_regenerate() {
    let dir = fixtures_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let (destination, s1, s2, s3) = build_chain();
    let manifest = provider_manifest_bytes();
    let manifest_sig = format!("{}\n", detached_signature(&manifest).unwrap()).into_bytes();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("provider-manifest.json", manifest),
        ("provider-manifest.json.sig", manifest_sig),
        ("detached-sig-mismatch.sig", mismatched_detached_sig()),
        ("destination-manifest.json", destination.clone()),
        ("snapshot-1.json", s1),
        ("snapshot-2.json", s2),
        ("snapshot-3.json", s3),
        (
            "snapshot-sponsored.json",
            sponsored_snapshot_bytes(&sha256_digest(&destination)),
        ),
        ("canonical-input.json", scrambled_canonical_input().to_vec()),
        (
            "canonical-bytes.bin",
            signing_bytes(scrambled_canonical_input()).unwrap(),
        ),
        (
            "canonical-case-input.json",
            case_divergence_input().to_vec(),
        ),
        (
            "canonical-case-bytes.bin",
            signing_bytes(case_divergence_input()).unwrap(),
        ),
        ("canonical-escaping-input.json", escaping_input().to_vec()),
        (
            "canonical-escaping-bytes.bin",
            signing_bytes(escaping_input()).unwrap(),
        ),
        ("duplicate-keys-input.json", duplicate_keys_input().to_vec()),
        (
            "policy-transition-manifest.json",
            transition_manifest_bytes(),
        ),
        (
            "audience-skip-manifest.json",
            audience_skip_manifest_bytes(),
        ),
        ("conflict-provider-b.json", conflict_provider_bytes()),
        ("conflict-snapshot-b.json", conflict_snapshot_bytes()),
        ("equivocation-manifest.json", equivocation_manifest_bytes()),
        (
            "equivocation-snapshot-a.json",
            equivocation_snapshot_bytes("catalog-a", "66"),
        ),
        (
            "equivocation-snapshot-b.json",
            equivocation_snapshot_bytes("catalog-b", "77"),
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
    assert_eq!(v1.outcome, ChainOutcome::FirstAcceptance);
    let v2 = verify_snapshot(&s2, &manifest, Some(&retained(&s1)), VERIFY_AT).unwrap();
    assert_eq!(v2.snapshot.sequence, 2);
    assert_eq!(v2.outcome, ChainOutcome::Successor);
    verify_snapshot(&s3, &manifest, Some(&retained(&s2)), VERIFY_AT).unwrap();
}

#[test]
fn first_acceptance_takes_any_sequence() {
    // §6: on first acceptance of a source there is no retained state
    // to compare against — an established catalog past its first
    // snapshot must be addable (TOFU covers trust).
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, _, _, s3) = build_chain();
    let v3 = verify_snapshot(&s3, &manifest, None, VERIFY_AT).unwrap();
    assert_eq!(v3.snapshot.sequence, 3);
    assert_eq!(v3.outcome, ChainOutcome::FirstAcceptance);
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
fn oversize_destination_is_unavailable_not_mismatch() {
    // §9 pins the oversize destination manifest to
    // entry_manifest_unavailable.
    let oversized = vec![b'x'; MAX_DESTINATION_MANIFEST_BYTES + 1];
    let err = verify_destination(&oversized, &format!("sha256:{}", "11".repeat(32))).unwrap_err();
    assert_eq!(err.code(), Some("entry_manifest_unavailable"));
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
    let resigned = sign_document(&serde_json::to_vec(&raw).unwrap(), &other_key()).unwrap();
    let err = verify_manifest(&resigned, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
}

#[test]
fn sequence_rollback_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, s2, _) = build_chain();
    // Rollback: sequence 1 presented after sequence 2 was accepted.
    let err = verify_snapshot(&s1, &manifest, Some(&retained(&s2)), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn forward_jump_accepted_with_note() {
    // §6/§10 item 8: sequence N against a retained N−2 — accepted,
    // carrying the source-integrity note (the offline verifier does
    // not perform the intermediate-fetch continuity walk).
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, _, s3) = build_chain();
    let v = verify_snapshot(&s3, &manifest, Some(&retained(&s1)), VERIFY_AT).unwrap();
    assert_eq!(v.outcome, ChainOutcome::ForwardJumpWithNote { missed: 1 });
}

#[test]
fn no_op_refresh_is_not_a_warning() {
    // §6/§10 item 11: identical latest snapshot re-fetched — the
    // provider simply hasn't published since; no warning.
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, _, s2, _) = build_chain();
    let v = verify_snapshot(&s2, &manifest, Some(&retained(&s2)), VERIFY_AT).unwrap();
    assert_eq!(v.outcome, ChainOutcome::NoOpRefresh);
}

#[test]
fn same_sequence_fork_rejected() {
    // Fork: same sequence, different bytes — equivocation, never
    // silently resolved toward either side.
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, _, s2, _) = build_chain();
    let mut doc: Value = serde_json::from_slice(&s2).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["expiresAt"] = json!("2026-09-13T00:00:00Z");
    let forked = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let err = verify_snapshot(&forked, &manifest, Some(&retained(&s2)), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn forked_previous_digest_rejected() {
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, s2, _) = build_chain();
    // A fork: sequence 2, but previousDigest pointing elsewhere.
    let mut fork: Value = serde_json::from_slice(&s2).unwrap();
    fork.as_object_mut().unwrap().remove("signature");
    fork["previousDigest"] = Value::String(format!("sha256:{}", "22".repeat(32)));
    let forked = sign_document(&serde_json::to_vec(&fork).unwrap(), &key()).unwrap();
    let err = verify_snapshot(&forked, &manifest, Some(&retained(&s1)), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn policy_transition_grace() {
    // §4.2/§10 item 10: manifest updated to a new policy digest, the
    // snapshot still citing the previous one — accepted with the
    // transition note; any third digest fails.
    let manifest = verify_manifest(&transition_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    // Without the retained previous declaration: snapshot_invalid.
    let err = verify_snapshot(&s1, &manifest, None, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    // With it: accepted, transition surfaced.
    let mut state = retained(&s1);
    state.previous_policy = Some(format!("sha256:{}", "11".repeat(32)));
    let v = verify_snapshot(&s1, &manifest, Some(&state), VERIFY_AT).unwrap();
    assert!(v.policy_transition);
    // A third digest matches neither: snapshot_invalid.
    let mut third = retained(&s1);
    third.previous_policy = Some(format!("sha256:{}", "99".repeat(32)));
    let err = verify_snapshot(&s1, &manifest, Some(&third), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn policy_transition_grace_from_fixtures() {
    // The same §4.2 grace, exercised end-to-end over the byte-pinned
    // fixture files and the `from_snapshot_bytes` constructor the CLI
    // uses (previously the constructor could not carry the retained
    // previous policy, making the grace unreachable from the CLI).
    let dir = fixtures_dir();
    let manifest_raw = std::fs::read(dir.join("policy-transition-manifest.json")).unwrap();
    let s1 = std::fs::read(dir.join("snapshot-1.json")).unwrap();
    let manifest = verify_manifest(&manifest_raw, VERIFY_AT).unwrap();
    let state =
        RetainedCatalogState::from_snapshot_bytes(&s1, Some(format!("sha256:{}", "11".repeat(32))))
            .unwrap();
    let v = verify_snapshot(&s1, &manifest, Some(&state), VERIFY_AT).unwrap();
    assert!(v.policy_transition);
    // Without the retained previous declaration the grace must NOT
    // fire: snapshot_invalid.
    let bare = RetainedCatalogState::from_snapshot_bytes(&s1, None).unwrap();
    let err = verify_snapshot(&s1, &manifest, Some(&bare), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
}

#[test]
fn previous_snapshot_from_different_catalog_rejected() {
    // §8: retained state is per (providerId, catalogId); a previous
    // snapshot from a DIFFERENT catalog is rejected distinctly, not
    // misreported as a chain fork.
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let other = equivocation_snapshot_bytes("catalog-a", "66");
    let state = RetainedCatalogState::from_snapshot_bytes(&other, None).unwrap();
    let err = verify_snapshot(&s1, &manifest, Some(&state), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    let message = err.to_string();
    assert!(message.contains("different catalog"), "{message}");
    assert!(!message.contains("fork"), "{message}");
}

#[test]
fn previous_snapshot_from_different_provider_rejected() {
    // §8: retained state is per (providerId, catalogId). The conflict
    // provider's catalog is ALSO named "public-all-seats", so a
    // catalogId-only identity check would sail past this and misreport
    // the mismatch as a same-sequence fork. It must be the distinct
    // caller-error rejection — never "fork", never "rollback".
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let state =
        RetainedCatalogState::from_snapshot_bytes(&conflict_snapshot_bytes(), None).unwrap();
    assert_eq!(state.catalog_id, "public-all-seats");
    let err = verify_snapshot(&s1, &manifest, Some(&state), VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    let message = err.to_string();
    assert!(message.contains("different provider"), "{message}");
    assert!(!message.contains("fork"), "{message}");
    assert!(!message.contains("rollback"), "{message}");
}

#[test]
fn after_acceptance_bounds_grace_to_one_generation() {
    // The §4.2 grace expiry is a caller obligation; after_acceptance
    // discharges it: previous_policy survives only while the accepted
    // snapshot still cites it, and the first acceptance citing the
    // manifest's CURRENT policy drops it.
    let previous_digest = format!("sha256:{}", "11".repeat(32));
    let (_, s1, s2, _) = build_chain();
    let state =
        RetainedCatalogState::from_snapshot_bytes(&s1, Some(previous_digest.clone())).unwrap();
    // Under the updated manifest the snapshot still cites the previous
    // policy: transition fires, and the retained grace carries over.
    let transition = verify_manifest(&transition_manifest_bytes(), VERIFY_AT).unwrap();
    let v = verify_snapshot(&s2, &transition, Some(&state), VERIFY_AT).unwrap();
    assert!(v.policy_transition);
    let carried = RetainedCatalogState::after_acceptance(Some(&state), &v);
    assert_eq!(
        carried.previous_policy.as_deref(),
        Some(previous_digest.as_str())
    );
    assert_eq!(carried.sequence, 2);
    assert_eq!(carried.provider_id, "onym:component:onym-discovery");
    // Under a manifest whose CURRENT policy the snapshot cites, the
    // first acceptance closes the window: previous_policy dropped.
    let current = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let v = verify_snapshot(&s2, &current, Some(&state), VERIFY_AT).unwrap();
    assert!(!v.policy_transition);
    let closed = RetainedCatalogState::after_acceptance(Some(&state), &v);
    assert!(closed.previous_policy.is_none());
}

#[test]
fn duplicate_key_previous_snapshot_rejected_by_builder() {
    // §3: the builder derives the new sequence and previousDigest from
    // the --previous bytes, so a duplicate-key previous file must be
    // rejected BEFORE the last-key-wins tree parse can pick a value.
    let (destination, s1, ..) = build_chain();
    let config = snapshot_config(&sha256_digest(&destination));
    let mut doc = s1.clone();
    let insert_at = doc.len() - 1;
    let dup = br#","sequence":9"#;
    doc.splice(insert_at..insert_at, dup.iter().copied());
    let err =
        build_snapshot(&config, Some(&doc), GENERATED_AT, &key(), &fixtures_dir()).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
    // The unmodified previous bytes still build fine.
    build_snapshot(&config, Some(&s1), GENERATED_AT, &key(), &fixtures_dir()).unwrap();
}

#[test]
fn duplicate_key_previous_snapshot_rejected() {
    // §3: duplicate keys make a document invalid — including the
    // PREVIOUS snapshot handed to the retained-state constructor,
    // whose last-key-wins tree decode was the last remaining last-wins
    // path.
    let (_, s1, ..) = build_chain();
    let mut doc = s1.clone();
    let insert_at = doc.len() - 1;
    let dup = br#","sequence":9"#;
    doc.splice(insert_at..insert_at, dup.iter().copied());
    let err = RetainedCatalogState::from_snapshot_bytes(&doc, None).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
    // The unmodified bytes still construct fine.
    RetainedCatalogState::from_snapshot_bytes(&s1, None).unwrap();
}

#[test]
fn audience_skipped_catalog_gets_distinct_diagnosis() {
    // A snapshot for a catalog the manifest declares but audience-skips
    // (§1 non-public) is snapshot_invalid with an "audience-skipped"
    // diagnosis, not the misleading "not declared by manifest".
    let manifest = verify_manifest(&audience_skip_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let err = verify_snapshot(&s1, &manifest, None, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    let message = err.to_string();
    assert!(
        message.contains("audience-skipped (non-public)"),
        "{message}"
    );
    assert!(!message.contains("not declared"), "{message}");
    // A catalog the manifest genuinely never declared keeps the
    // original diagnosis.
    let public = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let other = equivocation_snapshot_bytes("catalog-a", "66");
    let err = verify_snapshot(&other, &public, None, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    assert!(err.to_string().contains("not declared"), "{err}");
}

#[test]
fn audience_skip_manifest_is_valid_and_empty() {
    // §1/§10 item 13: a manifest of decodable but non-public catalogs
    // is a valid, empty-by-policy source; the skip count is surfaced.
    let verified = verify_manifest(&audience_skip_manifest_bytes(), VERIFY_AT).unwrap();
    assert!(verified.catalogs.is_empty());
    assert_eq!(verified.audience_skipped, vec![0]);
    assert!(verified.skipped.is_empty());
    // The same counts, over the byte-pinned fixture file the CLI's
    // `verify manifest` audience-skipped line reports from.
    let raw = std::fs::read(fixtures_dir().join("audience-skip-manifest.json")).unwrap();
    let from_fixture = verify_manifest(&raw, VERIFY_AT).unwrap();
    assert!(from_fixture.catalogs.is_empty());
    assert_eq!(from_fixture.audience_skipped, vec![0]);
    assert!(from_fixture.skipped.is_empty());
}

#[test]
fn invalid_seat_types_member_skips_descriptor() {
    // §4.1: a member that is neither a token nor the lone wildcard
    // skips the descriptor; "*" must appear alone.
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    let mut bad = doc["catalogs"][0].clone();
    bad["catalogId"] = json!("bad-members");
    bad["seatTypes"] = json!(["Notary!"]);
    let mut wildcard = doc["catalogs"][0].clone();
    wildcard["catalogId"] = json!("wildcard-not-alone");
    wildcard["seatTypes"] = json!(["*", "notary"]);
    doc["catalogs"].as_array_mut().unwrap().push(bad);
    doc["catalogs"].as_array_mut().unwrap().push(wildcard);
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let verified = verify_manifest(&signed, VERIFY_AT).unwrap();
    assert_eq!(verified.catalogs.len(), 1);
    assert_eq!(verified.skipped, vec![1, 2]);
}

#[test]
fn empty_seat_types_skips_descriptor() {
    // An empty seatTypes array declares a catalog accepting no seat
    // type at all — not a state §4.1 defines; treated as a
    // descriptor-skip, consistent with member-invalid → skip.
    let mut doc: Value = serde_json::from_slice(&provider_manifest_bytes()).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    let mut empty = doc["catalogs"][0].clone();
    empty["catalogId"] = json!("empty-seats");
    empty["seatTypes"] = json!([]);
    doc["catalogs"].as_array_mut().unwrap().push(empty);
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let verified = verify_manifest(&signed, VERIFY_AT).unwrap();
    assert_eq!(verified.catalogs.len(), 1);
    assert_eq!(verified.skipped, vec![1]);
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
fn sponsored_disclosure_and_status_survive() {
    // §10 item 6 + §4.2 status: the sponsored-placement disclosure and
    // a valid warning status must SURVIVE decoding — an entry carrying
    // a valid status is never skipped (skipping it is the exact
    // warning-dropping failure the field exists to prevent).
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let raw = sponsored_snapshot_bytes(&sha256_digest(&destination_manifest_bytes()));
    let verified = verify_snapshot(&raw, &manifest, None, VERIFY_AT).unwrap();
    assert_eq!(verified.entries.len(), 2);
    assert!(verified.skipped.is_empty());
    assert_eq!(verified.entries[0].relationship, "sponsored-placement");
    assert_eq!(verified.entries[0].placement, "sponsored");
    let status = verified.entries[1].status.as_ref().unwrap();
    assert_eq!(status.state, "warning");
    assert!(status.uri.is_some());
}

#[test]
fn invalid_status_or_nonempty_evidence_skips_entry() {
    let (_, s1, ..) = build_chain();
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    for tamper in [
        json!({"state": "suspended"}),
        json!({"state": "warning", "uri": "http://insecure.example/x"}),
        json!("warning"),
    ] {
        let mut doc: Value = serde_json::from_slice(&s1).unwrap();
        doc.as_object_mut().unwrap().remove("signature");
        doc["entries"][0]["status"] = tamper;
        let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
        let verified = verify_snapshot(&signed, &manifest, None, VERIFY_AT).unwrap();
        assert!(verified.entries.is_empty());
        assert_eq!(verified.skipped, vec![0]);
    }
    // §4.2: non-empty evidence is deferred to v2; the entry is
    // skipped, never passed through as an unrenderable attestation.
    let mut doc: Value = serde_json::from_slice(&s1).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["entries"][0]["evidence"] = json!([{"type": "audit", "uri": "https://x.example/a", "digest": format!("sha256:{}", "11".repeat(32))}]);
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let verified = verify_snapshot(&signed, &manifest, None, VERIFY_AT).unwrap();
    assert!(verified.entries.is_empty());
    assert_eq!(verified.skipped, vec![0]);
}

#[test]
fn builder_rejects_bad_status_and_nonempty_evidence() {
    // The builder must not emit entries a conforming verifier would
    // skip: an invalid status state or non-empty §4.2 evidence fails
    // the build outright.
    let mut tampered_status = json!({
        "catalogId": "public-all-seats",
        "providerId": "onym:component:onym-discovery",
        "policyDigest": format!("sha256:{}", "11".repeat(32)),
        "expiryDays": 30,
        "entries": [{
            "componentId": "onym:component:onym-courier",
            "seatType": "transport.message",
            "manifest": {
                "uri": "https://discovery.onym.app/manifests/onym-courier.json",
                "digest": format!("sha256:{}", "44".repeat(32)),
            },
            "operator": operator(),
            "listedAt": "2026-08-13T00:00:00Z",
            "relationship": "none",
            "placement": "policy-ranked"
        }]
    });
    let mut tampered_evidence = tampered_status.clone();
    tampered_status["entries"][0]["status"] = json!({"state": "suspended"});
    tampered_evidence["entries"][0]["evidence"] = json!([{
        "type": "audit",
        "uri": "https://x.example/a",
        "digest": format!("sha256:{}", "11".repeat(32)),
    }]);
    for bad in [tampered_status, tampered_evidence] {
        let config: SnapshotConfig = serde_json::from_value(bad).unwrap();
        let err = build_snapshot(&config, None, GENERATED_AT, &key(), &fixtures_dir());
        assert!(err.is_err());
    }
}

#[test]
fn unknown_relationship_skips_entry() {
    // §4.2 fails closed against the extensible relationship set: a
    // disclosure the client cannot render is one the user never saw.
    let (_, s1, ..) = build_chain();
    let manifest = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let mut doc: Value = serde_json::from_slice(&s1).unwrap();
    doc.as_object_mut().unwrap().remove("signature");
    doc["entries"][0]["relationship"] = json!("equity-stake");
    let signed = sign_document(&serde_json::to_vec(&doc).unwrap(), &key()).unwrap();
    let verified = verify_snapshot(&signed, &manifest, None, VERIFY_AT).unwrap();
    assert!(verified.entries.is_empty());
    assert_eq!(verified.skipped, vec![0]);
}

#[test]
fn source_conflict_pair_detected() {
    // §10 item 7: two providers bind the same componentId to different
    // manifest digests — both claims preserved, conflict surfaced.
    let manifest_a = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let a = verify_snapshot(&s1, &manifest_a, None, VERIFY_AT).unwrap();
    let manifest_b = verify_manifest(&conflict_provider_bytes(), VERIFY_AT).unwrap();
    let b = verify_snapshot(&conflict_snapshot_bytes(), &manifest_b, None, VERIFY_AT).unwrap();
    assert_eq!(
        source_conflicts(&a.entries, &b.entries),
        vec!["onym:component:onym-courier".to_string()]
    );
    // No conflict against itself.
    assert!(source_conflicts(&a.entries, &a.entries).is_empty());
}

#[test]
fn cross_catalog_equivocation_surfaced() {
    // §4.2/§10 item 12: one provider, two catalogs, one componentId,
    // two digests — the cheapest equivocation must not be the one
    // nobody checks.
    let manifest = verify_manifest(&equivocation_manifest_bytes(), VERIFY_AT).unwrap();
    let a = verify_snapshot(
        &equivocation_snapshot_bytes("catalog-a", "66"),
        &manifest,
        None,
        VERIFY_AT,
    )
    .unwrap();
    let b = verify_snapshot(
        &equivocation_snapshot_bytes("catalog-b", "77"),
        &manifest,
        None,
        VERIFY_AT,
    )
    .unwrap();
    assert_eq!(
        cross_catalog_equivocation(&[&a, &b]),
        CrossCatalogCheck::Conflicts(vec!["onym:component:onym-courier".to_string()])
    );
    // Agreement is the explicit NoConflict, so an empty conflict list
    // can never be misread as "check not applicable".
    assert_eq!(
        cross_catalog_equivocation(&[&a, &a]),
        CrossCatalogCheck::NoConflict
    );
    assert_eq!(
        cross_catalog_equivocation(&[&a]),
        CrossCatalogCheck::NoConflict
    );
}

#[test]
fn cross_catalog_check_requires_one_provider() {
    // §4.2's equivocation check is defined WITHIN a provider; handing
    // it snapshots from different providers is a category error,
    // surfaced distinctly (cross-provider disagreement is the §9
    // source_conflict path instead).
    let manifest_a = verify_manifest(&provider_manifest_bytes(), VERIFY_AT).unwrap();
    let (_, s1, ..) = build_chain();
    let a = verify_snapshot(&s1, &manifest_a, None, VERIFY_AT).unwrap();
    let manifest_b = verify_manifest(&conflict_provider_bytes(), VERIFY_AT).unwrap();
    let b = verify_snapshot(&conflict_snapshot_bytes(), &manifest_b, None, VERIFY_AT).unwrap();
    assert_eq!(
        cross_catalog_equivocation(&[&a, &b]),
        CrossCatalogCheck::DifferentProviders
    );
}

#[test]
fn detached_sig_agreement_fails_closed() {
    // §3/§10 item 14: embedded and detached forms must decode to the
    // same 64 bytes; disagreement fails closed for the document.
    let manifest = provider_manifest_bytes();
    let good = format!("{}\n", detached_signature(&manifest).unwrap());
    verify_detached_sig(&manifest, good.as_bytes(), false).unwrap();
    let err = verify_detached_sig(&manifest, &mismatched_detached_sig(), false).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
    let (_, s1, ..) = build_chain();
    let err = verify_detached_sig(&s1, &mismatched_detached_sig(), true).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
    // Padding differences are not disagreement: compare after decode.
    let unpadded = good.trim_end().trim_end_matches('=').to_string();
    verify_detached_sig(&manifest, unpadded.as_bytes(), false).unwrap();
    // A CRLF line ending is not disagreement either: the trailing \r\n
    // is trimmed, so a CRLF-minded tool's .sig gets the signature
    // comparison, not a stray-\r base64 failure.
    let crlf = format!("{}\r\n", good.trim_end());
    verify_detached_sig(&manifest, crlf.as_bytes(), false).unwrap();
    // And a CRLF .sig with a WRONG signature still gets the
    // disagreement diagnosis.
    let mut wrong_crlf = mismatched_detached_sig();
    wrong_crlf.pop();
    wrong_crlf.extend_from_slice(b"\r\n");
    let err = verify_detached_sig(&manifest, &wrong_crlf, false).unwrap_err();
    assert!(err.to_string().contains("disagrees"), "{err}");
}

#[test]
fn detached_sig_rejects_duplicate_signature_keys() {
    // §3: a document with TWO signature fields must fail closed on the
    // detached-sig path too — last-key-wins tree decoding must never
    // pick which one to compare.
    let doc = br#"{"a": 1, "signature": "AAAA", "signature": "BBBB"}"#;
    let sig = b"AAAA\n";
    let err = verify_detached_sig(doc, sig, false).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
    let err = verify_detached_sig(doc, sig, true).unwrap_err();
    assert_eq!(err.code(), Some("snapshot_invalid"));
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
        // §7: EMPTY userinfo parses to an empty username, so the raw
        // authority must reject any `@` outright.
        "https://@discovery.onym.app/catalog.json",
        "https://discovery.onym.app:8443/catalog.json",
        // §7: the RAW string must not carry a port component — URL
        // libraries normalize a redundant `:443` away before any
        // parsed-port check is reachable.
        "https://discovery.onym.app:443/catalog.json",
        // Integer-form IPv4 literal.
        "https://3232235777/catalog.json",
        // Hex/dotted-integer IPv4 forms.
        "https://0xc0a80101/catalog.json",
    ] {
        assert!(validate_uri(bad).is_err(), "{bad} should be rejected");
    }
    validate_uri("https://discovery.onym.app/catalogs/public.json").unwrap();
}

#[test]
fn duplicate_keys_rejected() {
    // §3: duplicate keys, at any depth, make the document invalid —
    // never last-key-wins.
    assert!(reject_duplicate_keys(duplicate_keys_input()).is_err());
    assert!(signing_bytes(duplicate_keys_input()).is_err());
    assert!(reject_duplicate_keys(br#"{"a": 1, "b": [{"c": 1, "c": 1}]}"#).is_err());
    reject_duplicate_keys(br#"{"a": {"x": 1}, "b": {"x": 1}}"#).unwrap();
    // A duplicate-key provider manifest is provider_manifest_invalid.
    let mut doc = provider_manifest_bytes();
    let insert_at = doc.len() - 1;
    let dup = br#","version":1"#;
    doc.splice(insert_at..insert_at, dup.iter().copied());
    let err = verify_manifest(&doc, VERIFY_AT).unwrap_err();
    assert_eq!(err.code(), Some("provider_manifest_invalid"));
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
fn canonical_case_divergence_vector() {
    // §3/§10 item 1: the sort is UTF-8 byte order — uppercase before
    // lowercase. A case-insensitive sort fails exactly here.
    let canonical = signing_bytes(case_divergence_input()).unwrap();
    let expected = br#"{"AB":4,"Ab":3,"aB":2,"ab":1}"#;
    assert_eq!(canonical, expected);
}

#[test]
fn canonical_escaping_vector() {
    // §3/§10 item 1: escaping is pinned — two-char forms, lowercase
    // \u00xx for remaining controls, and NOTHING else escaped: no `/`,
    // no non-ASCII, no U+007F.
    let canonical = signing_bytes(escaping_input()).unwrap();
    let text = String::from_utf8(canonical.clone()).unwrap();
    assert!(text.contains(r#""controls":"\u0001\u001f""#), "{text}");
    assert!(text.contains("\"delete\":\"\u{7f}\""), "{text}");
    assert!(text.contains(r#""quote":"q\"b\\e""#), "{text}");
    assert!(text.contains(r#""slash":"a/b""#), "{text}");
    assert!(text.contains(r#""twochar":"\b\f\n\r\t""#), "{text}");
    assert!(text.contains("\"unicode\":\"héllo → 日本\""), "{text}");
    // Full-byte equality against the byte-pinned fixture: the class
    // spot-checks above cannot catch an extra or reordered byte.
    let fixture = std::fs::read(fixtures_dir().join("canonical-escaping-bytes.bin")).unwrap();
    assert_eq!(canonical, fixture);
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
    assert_eq!(
        Error::EntryManifestUnavailable(String::new()).code(),
        Some("entry_manifest_unavailable")
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
fn zero_decodable_descriptors_invalid() {
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
    doc["catalogs"][0]
        .as_object_mut()
        .unwrap()
        .remove("policyUri");
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
    verify_snapshot(
        &s1,
        &manifest,
        None,
        expires_at + time::Duration::minutes(10),
    )
    .unwrap();
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
