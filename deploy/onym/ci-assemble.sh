#!/usr/bin/env bash
#
# ci-assemble.sh — build, sign, verify, and assemble the tree served at
# https://discovery.onym.app/ from the sources in deploy/onym.
#
# Run from anywhere; paths are derived from this script's location.
#
# Modes (SKIP_SIGNING):
#   false  (default) Sign in CI. The three operator seeds arrive in env —
#          DISCOVERY_OPERATOR_SEED, COURIER_OPERATOR_SEED,
#          BLOSSOM_OPERATOR_SEED, 64 hex chars each — and everything under
#          deploy/onym/out/ is produced fresh on the runner (out/ is
#          gitignored scratch, never committed).
#   true   Deploy the pre-signed artifacts COMMITTED under
#          deploy/onym/signed/ (signed locally per the README runbook).
#          No seed ever reaches CI in this mode.
#
# Either way, every artifact is verified exactly as a client would verify
# it before a byte leaves the runner, and the assembled tree lands in
# SERVE_DIR for ci-deploy.sh to rsync byte-for-byte.
#
# Environment:
#   SERVE_DIR        where to assemble the served tree (default deploy/onym/serve)
#   DISCOVERY_HOST   public hostname (default discovery.onym.app)
#   SKIP_SIGNING     "true" to use committed deploy/onym/signed/ artifacts
#   GENESIS          "true" only for the very first publish (sequence 1);
#                    any build that would start a new chain aborts without it
#   CF_API_TOKEN     optional; lets the genesis guard cross-check Cloudflare
#   DOMAIN           Cloudflare zone for that cross-check (default onym.app)
#   DROPLET_IP       optional; the target droplet's public IP. Enables the
#                    genesis RECOVERY path: a first deploy that wedged after
#                    DNS but before the cert leaves the host resolving with
#                    nothing fetchable, and only an A record that provably
#                    points at THIS droplet may unwedge it (see below)
#   *_OPERATOR_SEED  signing seeds (only when SKIP_SIGNING != true)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC="$SCRIPT_DIR"
OUT="$SRC/out"          # CI-built artifacts — gitignored scratch
SIGNED="$SRC/signed"    # pre-signed, COMMITTED artifacts (skip_signing)
SERVE_DIR="${SERVE_DIR:-$SRC/serve}"
WORK="${WORK_DIR:-$(mktemp -d)}"
# The work dir holds the fetched previous snapshot AND (briefly) the
# signing seeds; make sure it dies with the script, on success or abort.
trap 'rm -rf "$WORK"' EXIT
DISCOVERY_HOST="${DISCOVERY_HOST:-discovery.onym.app}"
SKIP_SIGNING="${SKIP_SIGNING:-false}"
GENESIS="${GENESIS:-false}"
DOMAIN="${DOMAIN:-onym.app}"
DROPLET_IP="${DROPLET_IP:-}"
BIN="$REPO_ROOT/target/release/onym-discovery"
CONFIG="$SRC/catalogs/onym-services.config.json"
POLICY="$SRC/policies/onym-services.md"
PRIVACY="$SRC/privacy.md"

info() { printf '==> %s\n' "$*"; }
err()  { printf '==> ERROR: %s\n' "$*" >&2; }
die()  { err "$@"; exit 1; }

for c in curl python3; do
    command -v "$c" >/dev/null || die "missing required command: $c"
done

# ─── Source sanity (fail fast, before anything is signed) ─────────────
#
# Fail on the runner, with a reason, before anything is signed: the
# templates ship with REPLACE-* placeholders that must be filled once
# (operator keys, policy/privacy digests), and the manifest pins the
# exact bytes of documents that must therefore exist to be served.

placeholders="$(grep -rlF 'REPLACE-' \
    "$SRC/provider-manifest.src.json" "$SRC/catalogs" "$SRC/manifests" 2>/dev/null || true)"
[ -z "$placeholders" ] || die "unfilled REPLACE-* placeholders remain (fill the operator keys and digests per deploy/onym/README.md 'One-time setup'):
$placeholders"

missing=""
for f in "$POLICY" "$PRIVACY" "$SRC/reviewed/onym-relayer.json" "$SRC/reviewed/onym-authority.json"; do
    [ -f "$f" ] || missing="$missing  $f
"
done
[ -z "$missing" ] || die "required source files are missing:
$missing  policies/onym-services.md and privacy.md are served and digest-pinned
  by the manifest; reviewed/*.json are the externally hosted manifests you
  fetched and REVIEWED (the digest you pin is the review you performed).
  See deploy/onym/README.md."

# The manifest pins sha256 digests of the policy and privacy documents.
# A drifted digest would sign a promise about bytes that are not the
# bytes being served, so check before signing rather than after a client
# rejects them.
python3 - "$CONFIG" "$SRC/provider-manifest.src.json" "$POLICY" "$PRIVACY" <<'PY'
import hashlib, json, sys

config_path, manifest_path, policy_path, privacy_path = sys.argv[1:5]

def digest(path):
    with open(path, "rb") as handle:
        return "sha256:" + hashlib.sha256(handle.read()).hexdigest()

problems = []
policy_digest = digest(policy_path)
privacy_digest = digest(privacy_path)

with open(config_path) as handle:
    config = json.load(handle)
if config.get("policyDigest") != policy_digest:
    problems.append(
        f"{config_path}: policyDigest is {config.get('policyDigest')} "
        f"but {policy_path} hashes to {policy_digest}"
    )

with open(manifest_path) as handle:
    manifest = json.load(handle)
for catalog in manifest.get("catalogs", []):
    if catalog.get("catalogId") == config.get("catalogId") \
            and catalog.get("policy") != policy_digest:
        problems.append(
            f"{manifest_path}: catalog policy is {catalog.get('policy')} "
            f"but {policy_path} hashes to {policy_digest}"
        )
if manifest.get("privacyProfile") != privacy_digest:
    problems.append(
        f"{manifest_path}: privacyProfile is {manifest.get('privacyProfile')} "
        f"but {privacy_path} hashes to {privacy_digest}"
    )

if problems:
    print("digest mismatches (the manifest pins the exact bytes being served):",
          file=sys.stderr)
    for problem in problems:
        print("  - " + problem, file=sys.stderr)
    sys.exit(1)
PY

if [ ! -x "$BIN" ]; then
    info "building release CLI..."
    (cd "$REPO_ROOT" && cargo build --release --locked)
fi

# ─── Previous snapshot (the chain) ────────────────────────────────────
#
# The snapshot must chain onto the previously PUBLISHED bytes. Only
# these outcomes may proceed: the live snapshot was fetched (chain onto
# it), or the operator explicitly declared this the genesis publish
# (GENESIS=true) and the Cloudflare cross-check does not contradict
# that. A failed fetch is NEVER taken as evidence that nothing is
# published — DNS can fail for a host that served a chain yesterday
# (resolver outage, deleted record, runner egress) — and quietly
# building a genesis snapshot over an already published chain would
# fork the sequence.
#
# With GENESIS=true, EVERY failure path cross-checks Cloudflare:
#   - host doesn't resolve + no A record        -> clean genesis
#   - clean HTTP 404 (record absent or ours)    -> clean genesis
#   - any other failure (TLS, refused, 5xx...)  -> genesis RECOVERY,
#     eligible only when every A record for the host points at THIS
#     deploy's droplet (DROPLET_IP) AND no snapshot is fetchable from
#     that droplet directly — the signature of a first deploy that
#     wedged between the DNS upsert and cert issuance. Proceeds with a
#     loud warning; anything less aborts.
# With GENESIS=false every failure path aborts, full stop.

# cf_a_records — print the content (IP) of each Cloudflare A record for
# DISCOVERY_HOST, one per line. Returns 0 if records exist, 1 if there
# provably are none, 2 if the check itself could not be performed.
cf_a_records() {
    [ -n "${CF_API_TOKEN:-}" ] || return 2
    local cf="https://api.cloudflare.com/client/v4" zone_id ips
    zone_id="$(curl -fsS --connect-timeout 15 "$cf/zones?name=$DOMAIN" \
        -H "Authorization: Bearer $CF_API_TOKEN" 2>/dev/null \
        | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print(r[0]['id'] if r else '')")" \
        || return 2
    [ -n "$zone_id" ] || return 2
    ips="$(curl -fsS --connect-timeout 15 \
        "$cf/zones/$zone_id/dns_records?type=A&name=$DISCOVERY_HOST" \
        -H "Authorization: Bearer $CF_API_TOKEN" 2>/dev/null \
        | python3 -c "import sys,json
for rec in json.load(sys.stdin)['result']:
    print(rec['content'])")" \
        || return 2
    [ -n "$ips" ] || return 1
    printf '%s\n' "$ips"
}

# genesis_recovery_or_die <why> — the fetch failed in a way that used to
# be fatal even with GENESIS=true. One situation must stay recoverable:
# a FIRST deploy that wedged mid-run (DNS record created, vhost or cert
# never finished) leaves the host resolving to our droplet with nothing
# fetchable — host resolves, TLS fails — and without this path every
# genesis retry would abort forever. Eligibility is deliberately strict;
# any doubt aborts.
genesis_recovery_or_die() {
    local why="$1" records cf_rc bad probe probe_rc
    if [ "$GENESIS" != "true" ]; then
        die "could not fetch the previous snapshot ($why). Refusing to
  guess: if a snapshot is already published, building genesis would fork the
  sequence chain. Retry when $SNAPSHOT_URL is reachable."
    fi
    set +e
    records="$(cf_a_records)"
    cf_rc=$?
    set -e
    [ "$cf_rc" -ne 2 ] || die "genesis=true and the snapshot fetch failed ($why), but the
  Cloudflare cross-check is unavailable (CF_API_TOKEN unset or the API
  unreachable), so this run cannot prove the failure is a wedged first
  deploy rather than an outage of a published chain. Aborting."
    [ "$cf_rc" -ne 1 ] || die "genesis=true and the snapshot fetch failed ($why), but the host
  resolved while Cloudflare holds NO A record for it — the resolution came
  from somewhere this deploy does not control. Aborting rather than guess;
  investigate where $DISCOVERY_HOST's DNS is actually served."
    [ -n "$DROPLET_IP" ] || die "genesis=true and the snapshot fetch failed ($why). A Cloudflare
  A record exists, but DROPLET_IP is not set, so this run cannot prove the
  record points at this deploy's own droplet. Aborting; set DROPLET_IP (CI
  resolves it via doctl) to enable the wedged-first-deploy recovery path."
    bad="$(printf '%s\n' "$records" | grep -vxF "$DROPLET_IP" || true)"
    [ -z "$bad" ] || die "genesis=true and the snapshot fetch failed ($why), but a Cloudflare
  A record for $DISCOVERY_HOST points at $bad — not this deploy's droplet
  ($DROPLET_IP). That host may be serving a published chain. Aborting."
    # The record is ours. Last check: nothing fetchable from the droplet
    # itself (TLS unverified — a wedged first deploy has no cert yet). A
    # 200 here means a chain IS published and only the public path is
    # broken: abort, never fork.
    set +e
    probe="$(curl -ksS --connect-timeout 15 --max-time 30 \
        --resolve "$DISCOVERY_HOST:443:$DROPLET_IP" \
        -o /dev/null -w '%{http_code}' "$SNAPSHOT_URL" 2>/dev/null)"
    probe_rc=$?
    set -e
    if [ "$probe_rc" -eq 0 ] && [ "$probe" = "200" ]; then
        die "genesis=true, but the droplet at $DROPLET_IP serves a snapshot at
  $SNAPSHOT_URL (probed directly, TLS unverified) — a chain is already
  published and only the public fetch path is broken ($why). Building
  genesis would fork it. Fix the public path and re-run without genesis."
    fi
    err "WARNING: proceeding as GENESIS RECOVERY. The snapshot fetch failed
  ($why), but every Cloudflare A record for $DISCOVERY_HOST points at this
  deploy's own droplet ($DROPLET_IP) and no snapshot is fetchable from that
  droplet directly — the signature of a FIRST deploy that wedged between
  the DNS upsert and certificate issuance. Building genesis (sequence 1).
  If a chain was EVER published on this host, STOP THIS RUN NOW."
}

PREV="$WORK/previous.json"
PREV_ARGS=()
SNAPSHOT_URL="https://$DISCOVERY_HOST/catalogs/onym-services.json"
info "fetching previously published snapshot: $SNAPSHOT_URL"
set +e
status="$(curl -sS --connect-timeout 15 -o "$PREV" -w '%{http_code}' "$SNAPSHOT_URL" 2>"$WORK/curl.err")"
rc=$?
set -e
if [ "$rc" -eq 6 ]; then
    # DNS resolution failed. That is NOT proof nothing is published:
    # cross-check the Cloudflare zone before even considering genesis.
    set +e
    cf_a_records >/dev/null
    cf_rc=$?
    set -e
    if [ "$cf_rc" -eq 0 ]; then
        # A record exists but the host does not resolve — either an
        # outage of a published chain, or a wedged first deploy whose
        # record has not propagated to the resolver yet. Only the strict
        # recovery check may distinguish them.
        genesis_recovery_or_die "host does not resolve, yet a Cloudflare A record exists"
    elif [ "$GENESIS" != "true" ]; then
        die "$DISCOVERY_HOST did not resolve and this run was not declared the
  genesis publish. A DNS failure is not evidence that nothing is published,
  and building genesis over an existing chain would fork the sequence.
  If this truly is the FIRST publish (sequence 1), re-run the workflow with
  genesis=true. Otherwise retry when $SNAPSHOT_URL resolves."
    elif [ "$cf_rc" -eq 1 ]; then
        info "  $DISCOVERY_HOST does not resolve and has no Cloudflare A record; genesis=true — genesis publish (sequence 1)"
    else
        info "  $DISCOVERY_HOST does not resolve (Cloudflare cross-check unavailable); genesis=true — genesis publish (sequence 1)"
    fi
elif [ "$rc" -ne 0 ]; then
    cat "$WORK/curl.err" >&2 || true
    # Host resolved but the fetch failed (TLS handshake, connection
    # refused, timeout...). With genesis=true this may be a wedged first
    # deploy — the strict recovery check decides; genesis=false aborts.
    genesis_recovery_or_die "curl exit $rc"
elif [ "$status" = "404" ]; then
    if [ "$GENESIS" != "true" ]; then
        die "$SNAPSHOT_URL answers HTTP 404 but this run was not declared the
  genesis publish. If this truly is the FIRST publish (sequence 1), re-run
  the workflow with genesis=true. If a snapshot has ever been published,
  investigate the 404 before deploying — genesis would fork the chain."
    fi
    # Clean 404 + genesis=true is a true genesis — TLS worked, the vhost
    # answered, no snapshot exists. Still cross-check Cloudflare: an A
    # record pointing somewhere else means the 404 came from a host this
    # deploy does not control.
    set +e
    records="$(cf_a_records)"
    cf_rc=$?
    set -e
    if [ "$cf_rc" -eq 0 ] && [ -n "$DROPLET_IP" ]; then
        bad="$(printf '%s\n' "$records" | grep -vxF "$DROPLET_IP" || true)"
        [ -z "$bad" ] || die "genesis=true and $SNAPSHOT_URL answers 404, but a Cloudflare A
  record for $DISCOVERY_HOST points at $bad — not this deploy's droplet
  ($DROPLET_IP). That 404 came from a host this deploy does not control.
  Aborting rather than guess."
    fi
    info "  no snapshot published yet (clean HTTP 404); genesis=true — genesis publish (sequence 1)"
elif [ "$status" = "200" ]; then
    if [ "$GENESIS" = "true" ]; then
        die "genesis=true, but $SNAPSHOT_URL is live — a chain is already
  published. Re-run without genesis to chain onto it."
    fi
    PREV_ARGS=(--previous "$PREV")
    info "  chaining onto sequence $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sequence"])' "$PREV")"
    # Keep the exact previous bytes (and detached signature) for the §5
    # retention sibling written below — the previousDigest chain pins
    # these bytes, so they must come from THIS fetch, not a later one.
    if ! curl -fsS --connect-timeout 15 -o "$PREV.sig" "$SNAPSHOT_URL.sig"; then
        rm -f "$PREV.sig"
        err "warning: could not fetch $SNAPSHOT_URL.sig — the previous snapshot's retention sibling will be published without its detached signature"
    fi
else
    # Unexpected HTTP status (403, 5xx...). Same rule as every other
    # failure: genesis=false aborts, genesis=true takes the strict
    # recovery check.
    genesis_recovery_or_die "unexpected HTTP $status"
fi

# ─── Assemble the served tree ─────────────────────────────────────────

rm -rf "$SERVE_DIR"
mkdir -p "$SERVE_DIR/catalogs" "$SERVE_DIR/manifests" "$SERVE_DIR/policies"

# §5 retention siblings (`onym-services-<sequence>.json`): once PR #3's
# tooling lands, build-snapshot writes them itself. Snapshots published
# before that carry none, so:
#
#   1. The snapshot we just chained onto becomes its own sibling, from
#      the EXACT bytes fetched above — the new snapshot's previousDigest
#      pins those bytes, so re-fetching (or losing) them would break the
#      chain a client walks. This guarantees every publish preserves its
#      predecessor even before PR #3's CLI-written siblings land.
#   2. Best-effort backfill of older siblings the live site already
#      serves (a missing one is a 404, not a failure) — bounded to the
#      newest SIBLING_BACKFILL_MAX sequences so it cannot grow into an
#      unbounded serial curl walk, fetched in parallel with short
#      timeouts. ci-deploy.sh rsyncs without --delete, so droplet-side
#      history older than the bound survives regardless.
SIBLING_BACKFILL_MAX="${SIBLING_BACKFILL_MAX:-100}"
if [ "${#PREV_ARGS[@]}" -gt 0 ]; then
    prev_seq="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sequence"])' "$PREV")"

    cp "$PREV" "$SERVE_DIR/catalogs/onym-services-$prev_seq.json"
    [ ! -f "$PREV.sig" ] || cp "$PREV.sig" "$SERVE_DIR/catalogs/onym-services-$prev_seq.json.sig"

    first_seq=$(( prev_seq > SIBLING_BACKFILL_MAX ? prev_seq - SIBLING_BACKFILL_MAX + 1 : 1 ))
    i="$first_seq"
    in_flight=0
    while [ "$i" -le "$prev_seq" ]; do
        for name in "onym-services-$i.json" "onym-services-$i.json.sig"; do
            dst="$SERVE_DIR/catalogs/$name"
            [ -f "$dst" ] && continue   # never overwrite the exact bytes kept above
            { curl -fsS --connect-timeout 5 --max-time 20 \
                -o "$dst" "https://$DISCOVERY_HOST/catalogs/$name" \
                || rm -f "$dst"; } &
            in_flight=$((in_flight + 1))
            if [ "$in_flight" -ge 16 ]; then
                wait
                in_flight=0
            fi
        done
        i=$((i + 1))
    done
    wait
fi

# ─── Sign (or adopt the pre-signed out/) ──────────────────────────────

if [ "$SKIP_SIGNING" != "true" ]; then
    rm -rf "$OUT"
    mkdir -p "$OUT/catalogs" "$OUT/manifests"
    SEEDS="$WORK/seeds"
    mkdir -p "$SEEDS"
    chmod 700 "$SEEDS"

    write_seed() {
        local name="$1" value="$2" path="$3"
        [ -n "$value" ] || die "secret $name is not set.
  Generate the seed once:  onym-discovery keygen --out $name.seed
  (the secret value is the file's single 64-hex-char line), publish the
  printed fingerprint out of band, and add $name as an Actions secret in
  this repository or the org. Alternatively re-run this workflow with
  skip_signing=true to deploy pre-signed artifacts committed under
  deploy/onym/signed/ — see deploy/onym/README.md for the tradeoff."
        # [[ =~ ]] anchors over the WHOLE value — grep matches per line,
        # so "junk\n<64 hex>\n" would sneak past a piped grep.
        [[ "$value" =~ ^[0-9a-fA-F]{64}$ ]] \
            || die "$name must be exactly 64 hex chars (a raw Ed25519 seed)"
        (umask 077 && printf '%s\n' "$value" > "$path")
    }

    write_seed DISCOVERY_OPERATOR_SEED "${DISCOVERY_OPERATOR_SEED:-}" "$SEEDS/discovery.seed"
    write_seed COURIER_OPERATOR_SEED   "${COURIER_OPERATOR_SEED:-}"   "$SEEDS/courier.seed"
    write_seed BLOSSOM_OPERATOR_SEED   "${BLOSSOM_OPERATOR_SEED:-}"   "$SEEDS/blossom.seed"

    # Seat manifests hosted here are signed by THEIR operator's key —
    # same organization today, separate seeds by policy.
    info "signing seat manifests..."
    "$BIN" sign-manifest --seed "$SEEDS/courier.seed" \
        "$SRC/manifests/onym-courier.src.json" --out "$OUT/manifests/onym-courier.json"
    "$BIN" sign-manifest --seed "$SEEDS/blossom.seed" \
        "$SRC/manifests/onym-blossom.src.json" --out "$OUT/manifests/onym-blossom.json"

    info "building snapshot..."
    "$BIN" build-snapshot --seed "$SEEDS/discovery.seed" \
        --config "$CONFIG" \
        ${PREV_ARGS[@]+"${PREV_ARGS[@]}"} \
        --out "$OUT/catalogs/onym-services.json"

    info "signing provider manifest..."
    "$BIN" sign-manifest --seed "$SEEDS/discovery.seed" \
        "$SRC/provider-manifest.src.json" --out "$OUT/manifest.json"

    rm -rf "$SEEDS"
else
    # Pre-signed artifacts live in the COMMITTED signed/ directory —
    # out/ is gitignored CI scratch and deliberately stays that way, so
    # the two modes can never contaminate each other.
    info "skip_signing=true — using pre-signed artifacts from deploy/onym/signed/"
    OUT="$SIGNED"
    for f in manifest.json manifest.json.sig \
             catalogs/onym-services.json catalogs/onym-services.json.sig \
             manifests/onym-courier.json manifests/onym-courier.json.sig \
             manifests/onym-blossom.json manifests/onym-blossom.json.sig; do
        [ -f "$OUT/$f" ] || die "skip_signing=true but deploy/onym/signed/$f is missing.
  Sign locally per the deploy/onym/README.md runbook and commit the
  artifacts under deploy/onym/signed/, or re-run without skip_signing to
  sign in CI."
    done
fi

# ─── Verify gate — exactly as a client would ──────────────────────────
#
# Nothing reaches the droplet unverified. After PR #3 lands, add
# `--sig <file>.sig` to both commands so the detached signatures are
# checked for agreement with the embedded ones too.

info "verifying manifest..."
"$BIN" verify manifest "$OUT/manifest.json"
info "verifying snapshot (chain + entries)..."
"$BIN" verify snapshot "$OUT/catalogs/onym-services.json" \
    --manifest "$OUT/manifest.json" \
    ${PREV_ARGS[@]+"${PREV_ARGS[@]}"}

# ─── Final layout (see README: "Layout served at ...") ────────────────

cp "$OUT/manifest.json" "$OUT/manifest.json.sig" "$SERVE_DIR/"
# Includes any retention siblings build-snapshot wrote (post-PR #3).
cp "$OUT"/catalogs/onym-services*.json "$OUT"/catalogs/onym-services*.json.sig "$SERVE_DIR/catalogs/"
cp "$OUT"/manifests/*.json "$OUT"/manifests/*.json.sig "$SERVE_DIR/manifests/"
cp "$POLICY" "$SERVE_DIR/policies/onym-services.md"
cp "$PRIVACY" "$SERVE_DIR/privacy.md"

info "assembled $SERVE_DIR:"
(cd "$SERVE_DIR" && find . -type f | sort | sed 's/^/  /')
