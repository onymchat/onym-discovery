use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use time::OffsetDateTime;

use onym_discovery::build::{build_snapshot, SnapshotConfig};
use onym_discovery::keys;
use onym_discovery::sign::{detached_signature, sign_document};
use onym_discovery::types::parse_timestamp;
use onym_discovery::verify::{sha256_digest, verify_destination, verify_manifest, verify_snapshot};

#[derive(Parser)]
#[command(
    name = "onym-discovery",
    version,
    about = "Onym Discovery static-snapshot/Ed25519 reference tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new operator seed and print its public identity.
    Keygen {
        /// File to write the 64-hex-character seed to (0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the operator id and fingerprint for a seed file.
    Fingerprint {
        #[arg(long)]
        seed: PathBuf,
    },
    /// Sign a provider manifest (or any profile document): emits
    /// canonical bytes with the signature embedded, plus a detached
    /// `.sig` sibling.
    SignManifest {
        #[arg(long)]
        seed: PathBuf,
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Build and sign a catalog snapshot from a source config.
    BuildSnapshot {
        #[arg(long)]
        seed: PathBuf,
        #[arg(long)]
        config: PathBuf,
        /// Exact bytes of the previously published snapshot; omit for
        /// the genesis snapshot (sequence 1).
        #[arg(long)]
        previous: Option<PathBuf>,
        /// RFC 3339 UTC generation time; defaults to now.
        #[arg(long)]
        generated_at: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify documents.
    #[command(subcommand)]
    Verify(VerifyCommand),
}

#[derive(Subcommand)]
enum VerifyCommand {
    /// Verify a provider manifest.
    Manifest {
        file: PathBuf,
        /// Evaluate expiry at this RFC 3339 instant instead of now.
        #[arg(long)]
        at: Option<String>,
    },
    /// Verify a snapshot against its provider manifest (and, when
    /// given, the previously accepted snapshot's exact bytes).
    Snapshot {
        file: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        previous: Option<PathBuf>,
        #[arg(long)]
        at: Option<String>,
    },
    /// Verify fetched destination-manifest bytes against a pinned
    /// digest.
    Destination {
        file: PathBuf,
        #[arg(long)]
        digest: String,
    },
}

fn moment(at: &Option<String>) -> Result<OffsetDateTime> {
    match at {
        None => Ok(OffsetDateTime::now_utc()),
        Some(value) => Ok(parse_timestamp(value)?),
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { out } => {
            if out.exists() {
                bail!(
                    "{} already exists; refusing to overwrite a key",
                    out.display()
                );
            }
            let seed = keys::generate_seed();
            let key = keys::signing_key_from_seed_hex(&hex::encode(seed))?;
            std::fs::write(&out, format!("{}\n", hex::encode(seed)))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("operator:    {}", keys::operator_id(&key.verifying_key()));
            println!("fingerprint: {}", keys::fingerprint(&key.verifying_key()));
            println!(
                "seed:        {} (keep out of the served directory)",
                out.display()
            );
        }
        Command::Fingerprint { seed } => {
            let key = load_key(&seed)?;
            println!("operator:    {}", keys::operator_id(&key.verifying_key()));
            println!("fingerprint: {}", keys::fingerprint(&key.verifying_key()));
        }
        Command::SignManifest { seed, input, out } => {
            let key = load_key(&seed)?;
            let raw = std::fs::read(&input).with_context(|| input.display().to_string())?;
            let signed = sign_document(&raw, &key)?;
            std::fs::write(&out, &signed)?;
            let sig = detached_signature(&signed)?;
            std::fs::write(sig_path(&out), format!("{sig}\n"))?;
            println!(
                "wrote {} ({} bytes, digest {})",
                out.display(),
                signed.len(),
                sha256_digest(&signed)
            );
        }
        Command::BuildSnapshot {
            seed,
            config,
            previous,
            generated_at,
            out,
        } => {
            let key = load_key(&seed)?;
            let config_raw =
                std::fs::read(&config).with_context(|| config.display().to_string())?;
            let parsed: SnapshotConfig = serde_json::from_slice(&config_raw)
                .with_context(|| format!("parse {}", config.display()))?;
            let previous_raw = previous
                .as_ref()
                .map(|p| std::fs::read(p).with_context(|| p.display().to_string()))
                .transpose()?;
            let config_dir = config
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_owned();
            let built = build_snapshot(
                &parsed,
                previous_raw.as_deref(),
                moment(&generated_at)?,
                &key,
                &config_dir,
            )?;
            std::fs::write(&out, &built.bytes)?;
            let sig = detached_signature(&built.bytes)?;
            std::fs::write(sig_path(&out), format!("{sig}\n"))?;
            println!(
                "wrote {} (sequence {}, {} bytes, digest {})",
                out.display(),
                built.sequence,
                built.bytes.len(),
                built.digest
            );
        }
        Command::Verify(command) => match command {
            VerifyCommand::Manifest { file, at } => {
                let raw = std::fs::read(&file).with_context(|| file.display().to_string())?;
                let manifest = verify_manifest(&raw, moment(&at)?)?;
                println!(
                    "OK {} — operator {}",
                    manifest.provider_id, manifest.operator
                );
                println!("digest {}", sha256_digest(&raw));
            }
            VerifyCommand::Snapshot {
                file,
                manifest,
                previous,
                at,
            } => {
                let raw = std::fs::read(&file).with_context(|| file.display().to_string())?;
                let manifest_raw =
                    std::fs::read(&manifest).with_context(|| manifest.display().to_string())?;
                let now = moment(&at)?;
                let parsed_manifest = verify_manifest(&manifest_raw, now)?;
                let previous_raw = previous
                    .as_ref()
                    .map(|p| std::fs::read(p).with_context(|| p.display().to_string()))
                    .transpose()?;
                let verified =
                    verify_snapshot(&raw, &parsed_manifest, previous_raw.as_deref(), now)?;
                println!(
                    "OK {} sequence {} — {} entries ({} skipped), digest {}",
                    verified.snapshot.catalog_id,
                    verified.snapshot.sequence,
                    verified.entries.len(),
                    verified.skipped.len(),
                    verified.digest
                );
            }
            VerifyCommand::Destination { file, digest } => {
                let raw = std::fs::read(&file).with_context(|| file.display().to_string())?;
                verify_destination(&raw, &digest)?;
                println!("OK — bytes match {digest}");
            }
        },
    }
    Ok(())
}

fn load_key(seed_path: &PathBuf) -> Result<ed25519_dalek::SigningKey> {
    let seed_hex =
        std::fs::read_to_string(seed_path).with_context(|| seed_path.display().to_string())?;
    Ok(keys::signing_key_from_seed_hex(&seed_hex)?)
}

fn sig_path(out: &std::path::Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(".sig");
    out.with_file_name(name)
}
