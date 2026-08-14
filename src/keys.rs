//! Operator key handling: 32-byte Ed25519 seeds stored as 64 hex
//! characters in a file the operator keeps out of the served directory.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::Error;

pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

pub fn signing_key_from_seed_hex(seed_hex: &str) -> Result<SigningKey, Error> {
    let trimmed = seed_hex.trim();
    let bytes = hex::decode(trimmed).map_err(|e| Error::Malformed(format!("seed hex: {e}")))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Malformed("seed must be 32 bytes of hex".into()))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn operator_id(key: &VerifyingKey) -> String {
    format!("onym:key:{}", hex::encode(key.to_bytes()))
}

/// Short human-checkable fingerprint: first 8 bytes of SHA-256 of the
/// raw public key, colon-separated. Shown at TOFU pinning time.
pub fn fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    digest[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn sign(key: &SigningKey, message: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key.sign(message).to_bytes())
}

/// Decode a base64 Ed25519 signature (padded or unpadded accepted on
/// read, §3) into its 64 raw bytes.
pub fn decode_signature_b64(signature_b64: &str) -> Result<[u8; 64], Error> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let no_pad = base64::engine::general_purpose::STANDARD_NO_PAD;
    let raw = engine
        .decode(signature_b64)
        .or_else(|_| no_pad.decode(signature_b64))
        .map_err(|e| Error::Malformed(format!("signature base64: {e}")))?;
    raw.try_into()
        .map_err(|_| Error::Malformed("signature must be 64 bytes".into()))
}

pub fn verify(key_bytes: &[u8; 32], message: &[u8], signature_b64: &str) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|e| Error::Malformed(format!("public key: {e}")))?;
    let sig_bytes = decode_signature_b64(signature_b64)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    key.verify(message, &signature)
        .map_err(|_| Error::Malformed("signature verification failed".into()))
}
