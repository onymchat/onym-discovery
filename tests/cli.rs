//! CLI-level behavior that unit tests cannot reach: the §5 retention
//! sibling written by `build-snapshot` names one published sequence
//! forever, so a re-run producing DIFFERENT bytes for the same
//! sequence must refuse instead of silently forking the chain and
//! destroying the evidence. A byte-identical re-run (same inputs, same
//! `--generated-at`) succeeds. Plus the `verify` surface as an
//! operator drives it: detached-`.sig` agreement, chain-outcome
//! printing, and the §4.2 policy-transition grace notes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";
/// Instant at which the byte-pinned fixtures are valid and unexpired.
const AT: &str = "2026-08-14T00:00:00Z";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_onym-discovery")
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
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

#[test]
fn verify_manifest_detached_sig_agreement_and_disagreement() {
    let dir = fixtures();
    // Agreeing .sig: verified, and the agreement is reported.
    let ok = Command::new(bin())
        .args(["verify", "manifest"])
        .arg(dir.join("provider-manifest.json"))
        .arg("--sig")
        .arg(dir.join("provider-manifest.json.sig"))
        .args(["--at", AT])
        .output()
        .unwrap();
    assert!(ok.status.success(), "{ok:?}");
    let stdout = String::from_utf8_lossy(&ok.stdout);
    assert!(
        stdout.contains("OK onym:component:onym-discovery"),
        "{stdout}"
    );
    assert!(
        stdout.contains("detached .sig agrees with embedded signature"),
        "{stdout}"
    );

    // Disagreeing .sig: the whole verification fails closed.
    let bad = Command::new(bin())
        .args(["verify", "manifest"])
        .arg(dir.join("provider-manifest.json"))
        .arg("--sig")
        .arg(dir.join("detached-sig-mismatch.sig"))
        .args(["--at", AT])
        .output()
        .unwrap();
    assert!(!bad.status.success(), "disagreeing .sig must fail");
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(
        stderr.contains("disagrees with embedded signature"),
        "{stderr}"
    );
}

#[test]
fn verify_snapshot_previous_policy_prints_grace_and_outcome() {
    // snapshot-1 re-verified against itself under the transition
    // manifest: the §6 no-op-refresh outcome AND both §4.2 grace notes
    // (the transition itself, and the one-generation caller obligation)
    // must be printed.
    let dir = fixtures();
    let out = Command::new(bin())
        .args(["verify", "snapshot"])
        .arg(dir.join("snapshot-1.json"))
        .arg("--manifest")
        .arg(dir.join("policy-transition-manifest.json"))
        .arg("--previous")
        .arg(dir.join("snapshot-1.json"))
        .args(["--previous-policy", &format!("sha256:{}", "11".repeat(32))])
        .args(["--at", AT])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("note: no-op refresh"), "{stdout}");
    assert!(
        stdout.contains("previous policy declaration (transition grace)"),
        "{stdout}"
    );
    assert!(stdout.contains("caller's obligation to expire"), "{stdout}");
    assert!(
        stdout.contains("drop --previous-policy after the first accepted snapshot"),
        "{stdout}"
    );

    // Without --previous-policy the grace must not fire: the snapshot
    // cites a policy the updated manifest no longer declares.
    let bare = Command::new(bin())
        .args(["verify", "snapshot"])
        .arg(dir.join("snapshot-1.json"))
        .arg("--manifest")
        .arg(dir.join("policy-transition-manifest.json"))
        .arg("--previous")
        .arg(dir.join("snapshot-1.json"))
        .args(["--at", AT])
        .output()
        .unwrap();
    assert!(
        !bare.status.success(),
        "grace must require --previous-policy"
    );
    let stderr = String::from_utf8_lossy(&bare.stderr);
    assert!(stderr.contains("snapshot_invalid"), "{stderr}");
}

#[test]
fn verify_snapshot_prints_forward_jump_outcome() {
    // snapshot-3 against retained snapshot-1: accepted, with the §6
    // forward-jump source-integrity note printed.
    let dir = fixtures();
    let out = Command::new(bin())
        .args(["verify", "snapshot"])
        .arg(dir.join("snapshot-3.json"))
        .arg("--manifest")
        .arg(dir.join("provider-manifest.json"))
        .arg("--previous")
        .arg(dir.join("snapshot-1.json"))
        .args(["--at", AT])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("note: forward jump"), "{stdout}");
    assert!(stdout.contains("1 intermediate publication"), "{stdout}");
}
