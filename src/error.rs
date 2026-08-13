//! Error taxonomy mirroring `Discovery.md` §12 and the profile's §9
//! mapping. The `code()` strings are the abstract contract's stable
//! error identifiers; everything else is diagnostic context.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("provider_manifest_invalid: {0}")]
    ProviderManifestInvalid(String),
    #[error("snapshot_invalid: {0}")]
    SnapshotInvalid(String),
    #[error("snapshot_expired: {0}")]
    SnapshotExpired(String),
    #[error("entry_manifest_mismatch: {0}")]
    EntryManifestMismatch(String),
    #[error("malformed input: {0}")]
    Malformed(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// The abstract contract's stable error code, where one applies.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Error::ProviderManifestInvalid(_) => Some("provider_manifest_invalid"),
            Error::SnapshotInvalid(_) => Some("snapshot_invalid"),
            Error::SnapshotExpired(_) => Some("snapshot_expired"),
            Error::EntryManifestMismatch(_) => Some("entry_manifest_mismatch"),
            _ => None,
        }
    }
}
