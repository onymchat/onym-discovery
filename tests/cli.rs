//! CLI-level behavior that unit tests cannot reach: the §5 retention
//! sibling written by `build-snapshot` names one published sequence
//! forever, so a re-run producing DIFFERENT bytes for the same
//! sequence must refuse instead of silently forking the chain and
//! destroying the evidence. A byte-identical re-run (same inputs, same
//! `--generated-at`) succeeds.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_onym-discovery")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn build(seed: &Path, config: &Path, out: &Path, generated_at: &str) -> Output {
    Command::new(bin())
        .args(["build-snapshot", "--seed"])
        .arg(seed)
        .arg("--config")
        .arg(config)
        .arg("--generated-at")
        .arg(generated_at)
        .arg("--out")
        .arg(out)
        .output()
        .unwrap()
}

#[test]
fn retention_sibling_refuses_divergent_overwrite() {
    let dir = scratch("retention-overwrite");
    let seed = dir.join("operator.seed");
    std::fs::write(&seed, format!("{SEED_HEX}\n")).unwrap();
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"catalogId":"smoke","providerId":"onym:component:smoke-provider","policyDigest":"sha256:{}","expiryDays":30,"entries":[]}}"#,
            "11".repeat(32)
        ),
    )
    .unwrap();
    let out = dir.join("smoke.json");

    // Genesis build succeeds and writes the sequence-1 sibling.
    let first = build(&seed, &config, &out, "2026-08-13T00:00:00Z");
    assert!(first.status.success(), "{first:?}");
    let sibling = dir.join("smoke-1.json");
    let published = std::fs::read(&sibling).unwrap();
    let published_sig = std::fs::read(dir.join("smoke-1.json.sig")).unwrap();

    // A second build without --previous is sequence 1 again, with a
    // different generatedAt → different bytes: refused, and neither
    // the sibling nor its .sig nor the latest files were touched.
    let latest_before = std::fs::read(&out).unwrap();
    let second = build(&seed, &config, &out, "2026-08-13T01:00:00Z");
    assert!(!second.status.success(), "divergent re-run must fail");
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("refusing to overwrite"), "{stderr}");
    assert_eq!(std::fs::read(&sibling).unwrap(), published);
    assert_eq!(
        std::fs::read(dir.join("smoke-1.json.sig")).unwrap(),
        published_sig
    );
    assert_eq!(std::fs::read(&out).unwrap(), latest_before);

    // A byte-identical re-run (same inputs AND same --generated-at) is
    // a no-op on the sibling and succeeds.
    let rerun = build(&seed, &config, &out, "2026-08-13T00:00:00Z");
    assert!(rerun.status.success(), "{rerun:?}");
    assert_eq!(std::fs::read(&sibling).unwrap(), published);
}
