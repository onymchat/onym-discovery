#!/usr/bin/env bash
#
# ci-deploy.sh — push the assembled discovery tree (ci-assemble.sh's
# SERVE_DIR) to the droplet the rest of the onym.app stack runs on,
# ensure the Caddy vhost, upsert Cloudflare DNS, and purge the cache.
#
# Deliberately reuses onym-infra's conventions: the DO_API_KEY /
# CF_API_TOKEN / SSH_PRIVATE_KEY secrets, doctl droplet resolution by
# DROPLET_ID with fallback to the stable droplet name, root ssh with a
# deploy key, and grey-cloud (DNS-only) Cloudflare records so Caddy's
# ACME challenge works.
#
# Environment:
#   DO_API_KEY       (required) DigitalOcean API token
#   CF_API_TOKEN     (required) Cloudflare token (DNS edit on the zone;
#                    cache purge additionally needs Zone.Cache Purge)
#   SERVE_DIR        (required) assembled tree from ci-assemble.sh
#   SSH_KEY_PATH     private key trusted by the droplet (default ~/.ssh/deploy_key)
#   DISCOVERY_HOST   default discovery.onym.app
#   DOMAIN           Cloudflare zone, default onym.app
#   DROPLET_ID       reuse a specific droplet; else resolved by name
#   DROPLET_NAME     default onym-infra
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVE_DIR="${SERVE_DIR:?set SERVE_DIR to the tree assembled by ci-assemble.sh}"
DISCOVERY_HOST="${DISCOVERY_HOST:-discovery.onym.app}"
DOMAIN="${DOMAIN:-onym.app}"
DROPLET_NAME="${DROPLET_NAME:-onym-infra}"
DROPLET_ID="${DROPLET_ID:-}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/deploy_key}"
WEB_ROOT="/var/www/discovery"

: "${DO_API_KEY:?set DO_API_KEY (DigitalOcean API token)}"
: "${CF_API_TOKEN:?set CF_API_TOKEN (Cloudflare API token for $DOMAIN)}"

info() { printf '==> %s\n' "$*"; }
warn() { printf '==> WARNING: %s\n' "$*" >&2; }
err()  { printf '==> ERROR: %s\n' "$*" >&2; }
die()  { err "$@"; exit 1; }

for c in doctl ssh rsync curl python3 dig; do
    command -v "$c" >/dev/null || die "missing required command: $c"
done
[ -d "$SERVE_DIR" ] || die "SERVE_DIR not found: $SERVE_DIR (run ci-assemble.sh first)"
[ -f "$SERVE_DIR/manifest.json" ] || die "$SERVE_DIR/manifest.json missing — incomplete assembly"
[ -f "$SSH_KEY_PATH" ] || die "SSH key not found at $SSH_KEY_PATH"

# ─── Resolve the droplet (never create one) ───────────────────────────
#
# Same idempotent resolution as onym-infra's deploy.sh: prefer an
# explicit DROPLET_ID, otherwise adopt the droplet with the stable name.
# Unlike onym-infra this script NEVER creates a droplet — discovery is a
# tenant on the existing box, and a missing box means the stack it
# shares (Caddy above all) is missing too.

info "authenticating with DigitalOcean..."
doctl auth init --access-token "$DO_API_KEY" >/dev/null 2>&1

if [ -z "$DROPLET_ID" ] || ! doctl compute droplet get "$DROPLET_ID" >/dev/null 2>&1; then
    DROPLET_ID="$(doctl compute droplet list "$DROPLET_NAME" --format ID --no-header 2>/dev/null | head -1)"
fi
if [ -z "$DROPLET_ID" ] || ! doctl compute droplet get "$DROPLET_ID" >/dev/null 2>&1; then
    die "no droplet named '$DROPLET_NAME' found (and no valid DROPLET_ID).
  This workflow deploys onto the existing onym-infra box — run onym-infra's
  deploy first, or set the DROPLET_ID / DROPLET_NAME repository variables."
fi
DROPLET_IP="$(doctl compute droplet get "$DROPLET_ID" --format PublicIPv4 --no-header)"
info "droplet $DROPLET_ID ($DROPLET_IP)"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 -i "$SSH_KEY_PATH")
# shellcheck disable=SC2029  # client-side expansion of the command is intended
ssh_do() { ssh "${SSH_OPTS[@]}" "root@$DROPLET_IP" "$@"; }

# ─── Sync the served tree ─────────────────────────────────────────────
#
# NO --delete, on purpose: §5 retention siblings published by earlier
# runs (onym-services-<sequence>.json) must stay live until they expire,
# and a snapshot once published is never un-published by a later deploy.

info "syncing $SERVE_DIR -> $WEB_ROOT ..."
ssh_do "mkdir -p $WEB_ROOT"
rsync -az -e "ssh ${SSH_OPTS[*]}" "$SERVE_DIR/" "root@$DROPLET_IP:$WEB_ROOT/"

# ─── Caddy vhost (idempotent, validated, no-op when present) ──────────

info "ensuring Caddy vhost for $DISCOVERY_HOST ..."
ssh_do "bash -s -- '$DISCOVERY_HOST'" < "$SCRIPT_DIR/ensure-caddy-vhost.sh"

# ─── DNS (Cloudflare, DNS-only / grey-cloud, as in onym-infra) ────────

info "upserting Cloudflare A record for $DISCOVERY_HOST (DNS-only)..."
CF="https://api.cloudflare.com/client/v4"
CF_ZONE_ID="$(curl -s "$CF/zones?name=$DOMAIN" -H "Authorization: Bearer $CF_API_TOKEN" \
    | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print(r[0]['id'] if r else '')")"
[ -n "$CF_ZONE_ID" ] || die "could not find Cloudflare zone for $DOMAIN (check CF_API_TOKEN scope)"

res="$(curl -s "$CF/zones/$CF_ZONE_ID/dns_records?type=A&name=$DISCOVERY_HOST" \
    -H "Authorization: Bearer $CF_API_TOKEN")"
existing_id="$(echo "$res" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print(r[0]['id'] if r else '')")"
body="{\"type\":\"A\",\"name\":\"$DISCOVERY_HOST\",\"content\":\"$DROPLET_IP\",\"ttl\":120,\"proxied\":false}"
if [ -n "$existing_id" ]; then
    curl -s -X PUT "$CF/zones/$CF_ZONE_ID/dns_records/$existing_id" \
        -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
        --data "$body" >/dev/null
    info "  updated $DISCOVERY_HOST -> $DROPLET_IP"
else
    curl -s -X POST "$CF/zones/$CF_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
        --data "$body" >/dev/null
    info "  created $DISCOVERY_HOST -> $DROPLET_IP"
fi

info "waiting for DNS to propagate..."
for i in $(seq 1 30); do
    [ "$(dig +short "$DISCOVERY_HOST" @1.1.1.1 | tail -1)" = "$DROPLET_IP" ] \
        && { info "  $DISCOVERY_HOST resolves"; break; }
    [ "$i" -eq 30 ] && warn "$DISCOVERY_HOST not resolving to $DROPLET_IP yet — Caddy will retry certs once it does"
    sleep 6
done

# ─── Cache purge ──────────────────────────────────────────────────────
#
# Non-fatal on purpose: the record is grey-cloud, so Cloudflare is not
# caching these paths today, and the shared CF_API_TOKEN may carry only
# DNS:Edit. If the record is ever orange-clouded (it must not be — that
# breaks ACME and wss://, see onym-docs deployment.md), this becomes the
# step that keeps signed bytes fresh.

info "purging Cloudflare cache for the deployed paths..."
PURGE_LIST="$(cd "$SERVE_DIR" && find . -type f | sed 's|^\./||')"
if ! CF_API_TOKEN="$CF_API_TOKEN" CF_ZONE_ID="$CF_ZONE_ID" \
     DISCOVERY_HOST="$DISCOVERY_HOST" PURGE_LIST="$PURGE_LIST" \
     python3 - <<'PY'
import json, os, sys, urllib.request

host = os.environ["DISCOVERY_HOST"]
zone = os.environ["CF_ZONE_ID"]
token = os.environ["CF_API_TOKEN"]
urls = [f"https://{host}/{line.strip()}"
        for line in os.environ["PURGE_LIST"].splitlines() if line.strip()]

failed = False
for start in range(0, len(urls), 30):  # Cloudflare caps purge-by-URL at 30 per call
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/zones/{zone}/purge_cache",
        data=json.dumps({"files": urls[start:start + 30]}).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if not json.load(resp).get("success"):
                failed = True
    except Exception as exc:  # noqa: BLE001 — reported, non-fatal by design
        print(f"purge failed: {exc}", file=sys.stderr)
        failed = True
sys.exit(1 if failed else 0)
PY
then
    warn "cache purge failed (token likely lacks Zone.Cache Purge) — harmless while the record is DNS-only"
fi

# ─── Health: the live bytes must be the bytes we assembled ────────────

info "checking https://$DISCOVERY_HOST/manifest.json serves the deployed bytes..."
sha() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
want="$(sha "$SERVE_DIR/manifest.json")"
live="$(mktemp)"
healthy=false
for i in $(seq 1 36); do
    if curl -fsS --connect-timeout 10 -o "$live" "https://$DISCOVERY_HOST/manifest.json" \
        && [ "$(sha "$live")" = "$want" ]; then
        healthy=true
        break
    fi
    [ "$i" -eq 36 ] || sleep 10
done
if [ "$healthy" = "true" ]; then
    info "live and byte-identical: https://$DISCOVERY_HOST/manifest.json"
else
    die "https://$DISCOVERY_HOST/manifest.json is not serving the deployed bytes
  after 6 minutes. On a FIRST deploy this is usually Let's Encrypt issuance
  still catching up after the fresh DNS record — check:
    ssh root@$DROPLET_IP 'cd /opt/onym-infra && docker compose logs caddy | tail -50'
  and re-run the workflow once the certificate is issued."
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### discovery.onym.app deploy"
        echo "- droplet: \`$DROPLET_ID\` ($DROPLET_IP) — set the DROPLET_ID variable to pin it"
        echo "- web root: \`$WEB_ROOT\`"
        echo "- manifest sha256: \`$want\`"
    } >> "$GITHUB_STEP_SUMMARY"
fi
