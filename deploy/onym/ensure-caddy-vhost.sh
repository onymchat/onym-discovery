#!/usr/bin/env bash
#
# ensure-caddy-vhost.sh — run ON the onym-infra droplet (ci-deploy.sh
# streams it over ssh: `ssh root@<ip> bash -s -- <host> < this-file`).
#
# Idempotently ensures Caddy serves /var/www/discovery at the discovery
# hostname, without editing anything onym-infra owns beyond one guarded
# `import` line:
#
#   /opt/onym-infra/caddy.d/discovery.caddy    the vhost (ours)
#   /opt/onym-infra/docker-compose.override.yml mounts for caddy (ours)
#   /opt/onym-infra/Caddyfile                  += one `import caddy.d/*` line
#
# No-op when everything is already in place. Note that onym-infra's own
# deploy rsyncs its repository with --delete, which removes the override
# and re-writes the Caddyfile; the next run of this script simply puts
# them back. The durable home for this vhost is onym-infra itself — once
# it grows a native {$DISCOVERY_HOST} block this script detects that and
# steps aside.
set -euo pipefail

HOST="${1:-discovery.onym.app}"
INFRA_DIR="${INFRA_DIR:-/opt/onym-infra}"
WEB_ROOT="${WEB_ROOT:-/var/www/discovery}"
SNIPPET_DIR="$INFRA_DIR/caddy.d"
SNIPPET="$SNIPPET_DIR/discovery.caddy"
OVERRIDE="$INFRA_DIR/docker-compose.override.yml"
CADDYFILE="$INFRA_DIR/Caddyfile"
IMPORT_LINE='import /etc/caddy/caddy.d/*.caddy'

info() { printf '==> %s\n' "$*"; }
err()  { printf '==> ERROR: %s\n' "$*" >&2; }
die()  { err "$@"; exit 1; }

[ -d "$INFRA_DIR" ] || die "$INFRA_DIR not found — is this the onym-infra droplet?"
[ -f "$CADDYFILE" ] || die "$CADDYFILE not found — has onym-infra's deploy run here?"
mkdir -p "$WEB_ROOT" "$SNIPPET_DIR"

# If onym-infra grows a native vhost for the discovery host, it owns the
# routing (and the mounts) and this stopgap must not fight it. Only an
# actual site block counts: a site-address line opening a `{` block for
# the literal host (dots escaped — sub.onym.app must not match
# subXonym.app) or for the {$DISCOVERY_HOST} placeholder, optionally
# with a scheme/port or further comma-separated addresses. A comment or
# an unrelated mention of the hostname must NOT make this script exit 0
# while no vhost exists.
HOST_RE="$(printf '%s' "$HOST" | sed 's/\./\\./g')"
SITE_ADDR_RE="^[[:space:]]*(https?://)?(\{\\\$DISCOVERY_HOST\}|${HOST_RE})(:[0-9]+)?[[:space:]]*(,[^{}]*)?\{[[:space:]]*$"
if grep -qE "$SITE_ADDR_RE" "$CADDYFILE"; then
    info "Caddyfile already carries a native $HOST vhost — nothing to do"
    exit 0
fi

# The compose override is only ours to write when it is absent or when
# it carries our managed header. Anything else — hand-written on the
# box, or owned by another deploy — must NEVER be overwritten, and must
# be refused BEFORE the backup is taken, so a backup can never capture
# (and a rollback never "restore") a clobbered copy of someone else's
# file.
MANAGED_HEADER="# managed by onym-discovery deploy"
if [ -f "$OVERRIDE" ] && ! grep -qiF "$MANAGED_HEADER" "$OVERRIDE"; then
    die "$OVERRIDE exists but does not carry the managed header
  ('$MANAGED_HEADER'), so it is owned by something else and this script
  will not touch it. To proceed, merge these two mounts into the caddy
  service of that file yourself:
      - $WEB_ROOT:/srv/discovery:ro
      - ./caddy.d:/etc/caddy/caddy.d:ro
  then add the managed header as its first line ONLY if you want this
  deploy to take ownership (re-deploys will rewrite the whole file), or
  leave it unmanaged and keep the mounts in sync by hand."
fi

BACKUP="$(mktemp -d)"
cp -p "$CADDYFILE" "$BACKUP/Caddyfile"
[ ! -f "$SNIPPET" ]  || cp -p "$SNIPPET"  "$BACKUP/discovery.caddy"
[ ! -f "$OVERRIDE" ] || cp -p "$OVERRIDE" "$BACKUP/docker-compose.override.yml"

rollback() {
    cp "$BACKUP/Caddyfile" "$CADDYFILE"
    if [ -f "$BACKUP/discovery.caddy" ]; then
        cp "$BACKUP/discovery.caddy" "$SNIPPET"
    else
        rm -f "$SNIPPET"
    fi
    if [ -f "$BACKUP/docker-compose.override.yml" ]; then
        cp "$BACKUP/docker-compose.override.yml" "$OVERRIDE"
    else
        rm -f "$OVERRIDE"
    fi
}

changed=0
write_if_changed() {
    # write_if_changed <path> — desired content on stdin.
    local path="$1" tmp
    tmp="$(mktemp)"
    cat > "$tmp"
    if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
        rm -f "$tmp"
        return 0
    fi
    mv "$tmp" "$path"
    changed=1
}

# The vhost. Static files only; the signed JSON must go out
# byte-for-byte (encode is transfer compression, not re-serialization).
# .sig files are detached Ed25519 signatures — text/plain, matching how
# the authority's manifest.json.sig is served. The policy and privacy
# documents are served as the Markdown that was signed off, verbatim,
# for the same reason the authority's terms are: without the header
# Caddy hands the browser application/octet-stream and it downloads
# instead of showing them.
write_if_changed "$SNIPPET" <<EOF
# Managed by onym-discovery deploy (deploy/onym/ensure-caddy-vhost.sh).
# Do not edit by hand — re-deploys rewrite it.
$HOST {
	encode zstd gzip
	root * /srv/discovery
	@sig path *.sig
	header @sig Content-Type "text/plain; charset=utf-8"
	@md path *.md
	header @md Content-Type "text/markdown; charset=utf-8"
	file_server
}
EOF

# Compose merges override volume lists with the base service by target
# path, so this only ADDS the two mounts the vhost needs.
write_if_changed "$OVERRIDE" <<EOF
# Managed by onym-discovery deploy (deploy/onym/ensure-caddy-vhost.sh).
# Adds the static discovery site to the Caddy container. onym-infra's
# own deploy removes this file (rsync --delete); the next discovery
# deploy puts it back.
services:
  caddy:
    volumes:
      - $WEB_ROOT:/srv/discovery:ro
      - ./caddy.d:/etc/caddy/caddy.d:ro
EOF

if ! grep -qF "$IMPORT_LINE" "$CADDYFILE"; then
    printf '\n# Extra vhosts installed by service deploys (onym-discovery).\n%s\n' \
        "$IMPORT_LINE" >> "$CADDYFILE"
    changed=1
fi

if [ "$changed" -eq 0 ]; then
    info "Caddy vhost for $HOST already in place — no-op"
    exit 0
fi

cd "$INFRA_DIR"

# Validate the merged config in a throwaway container BEFORE touching
# the running one: every other onym.app vhost rides on this Caddy, and a
# bad snippet must fail here, not take the stack down.
#
# This works because onym-infra BIND-MOUNTS the Caddyfile into the stock
# image — onym-infra/docker-compose.yml, caddy service:
#   `- ./Caddyfile:/etc/caddy/Caddyfile:ro`
# (image `caddy:2-alpine`, nothing baked in) — and our override above
# bind-mounts caddy.d the same way, so the throwaway `compose run`
# container sees exactly the effective config the running one will load.
info "validating Caddy config..."
if ! docker compose run --rm --no-deps -T caddy \
        caddy validate --config /etc/caddy/Caddyfile; then
    rollback
    die "Caddy config validation failed — rolled back; the running Caddy is untouched"
fi

# `up -d` recreates the container when the override changed (new
# mounts); the explicit reload covers the remaining case where only the
# bind-mounted snippet bytes changed and compose sees no diff. If the
# container WAS just recreated it may still be starting, so the reload
# can race its admin socket — retry with a short backoff instead of
# failing the deploy on a race. The config already passed validation, so
# a persistent reload failure is an environment problem: roll the files
# back (and best-effort reload the restored config) rather than leave
# on-disk state that the running Caddy never accepted.
info "applying (recreate if mounts changed, then reload)..."
docker compose up -d caddy
reloaded=false
for attempt in 1 2 3 4 5; do
    if docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile; then
        reloaded=true
        break
    fi
    [ "$attempt" -eq 5 ] || { info "  reload attempt $attempt failed — retrying in 2s..."; sleep 2; }
done
if [ "$reloaded" != "true" ]; then
    rollback
    docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile || true
    die "caddy reload failed after 5 attempts — rolled back the vhost files
  and re-issued a reload of the restored config. Inspect the container:
  cd $INFRA_DIR && docker compose logs caddy | tail -50"
fi

info "Caddy vhost for $HOST ensured (root $WEB_ROOT)"
