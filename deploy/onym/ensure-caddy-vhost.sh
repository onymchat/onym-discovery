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
#
# STDIN IS THE SCRIPT. Because ci-deploy.sh streams this file into
# `bash -s`, bash reads it from stdin incrementally as it executes.
# Any child command that reads (or merely attaches and drains) stdin
# eats the REST OF THE SCRIPT: bash then sees EOF and exits 0 mid-way.
# That is exactly what sank genesis run 31872313566 — `docker compose
# run -T ... caddy validate` attached the streamed stdin to the
# throwaway container and drained it, so the script silently ended
# right after "Valid configuration": `up -d` and the reload never ran,
# the live container kept its old mounts, and the vhost never loaded.
# Two defenses, both deliberate:
#   1. the whole script body lives in main(), so bash must parse it all
#      before executing anything — a drained stdin can no longer
#      truncate execution;
#   2. every docker invocation gets an explicit `</dev/null`, so no
#      child can drain the stream in the first place (belt AND braces —
#      keep both when editing).
set -euo pipefail

info() { printf '==> %s\n' "$*"; }
err()  { printf '==> ERROR: %s\n' "$*" >&2; }
die()  { err "$@"; exit 1; }

# True when the RUNNING caddy container has both vhost mounts from our
# compose override (/etc/caddy/caddy.d and /srv/discovery). False when
# the container is absent, or is an old instance created before the
# override existed — the failure mode of genesis run 31872313566, where
# the files on disk were perfect but the live container had never been
# recreated to pick them up.
caddy_has_vhost_mounts() {
    local cid mounts
    cid="$(docker compose ps -q caddy </dev/null)" || return 1
    [ -n "$cid" ] || return 1
    mounts="$(docker inspect \
        --format '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' \
        "$cid" </dev/null)" || return 1
    grep -qxF '/etc/caddy/caddy.d' <<<"$mounts" \
        && grep -qxF '/srv/discovery' <<<"$mounts"
}

main() {

HOST="${1:-discovery.onym.app}"
INFRA_DIR="${INFRA_DIR:-/opt/onym-infra}"
WEB_ROOT="${WEB_ROOT:-/var/www/discovery}"
SNIPPET_DIR="$INFRA_DIR/caddy.d"
SNIPPET="$SNIPPET_DIR/discovery.caddy"
OVERRIDE="$INFRA_DIR/docker-compose.override.yml"
CADDYFILE="$INFRA_DIR/Caddyfile"
IMPORT_LINE='import /etc/caddy/caddy.d/*.caddy'

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
    # mktemp creates 0600; these are world-readable config files (the
    # snippet is bind-mounted into the caddy container, the override is
    # read by compose), so open them up before moving into place.
    chmod 644 "$tmp"
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

# Coupling note (verified against the onym-infra repo): the Caddyfile
# this appends to is GIT-TRACKED in onym-infra (`git ls-files` lists
# `Caddyfile` at the repo root) and bind-mounted into the stock
# caddy:2-alpine image (`./Caddyfile:/etc/caddy/Caddyfile:ro`,
# docker-compose.yml line 46). onym-infra's deploy rsyncs the repo with
# --delete, which rewrites the Caddyfile from that tracked copy —
# dropping this appended import — in the same sweep that deletes
# caddy.d/ and the compose override. The guarded import therefore
# cannot outlive the caddy.d mount it depends on; the next discovery
# deploy reinstates both together.
if ! grep -qF "$IMPORT_LINE" "$CADDYFILE"; then
    printf '\n# Extra vhosts installed by service deploys (onym-discovery).\n%s\n' \
        "$IMPORT_LINE" >> "$CADDYFILE"
    changed=1
fi

cd "$INFRA_DIR"

# "Nothing changed on disk" is NOT the same as "the site is up": genesis
# run 31872313566 left exactly this state — files perfect, but the live
# container predated the override and had neither mount, so the vhost
# never loaded. A plain files-only no-op here would have made every
# subsequent deploy exit 0 while the site stayed dark. Only no-op when
# the RUNNING container also carries the mounts; otherwise fall through
# and recreate it.
if [ "$changed" -eq 0 ] && caddy_has_vhost_mounts; then
    info "Caddy vhost for $HOST already in place (files AND running container) — no-op"
    exit 0
fi

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
#
# Empirically verified on the droplet (docker image inspect):
# caddy:2-alpine has ENTRYPOINT=[] (none) and only a CMD — so
# `compose run caddy <args>` executes <args> verbatim, and the argv
# must spell out the binary: `caddy validate ...`. (An earlier review
# claimed the image had ENTRYPOINT ["caddy"] and this line was changed
# to bare `validate ...`, which failed in run 31872186177 with
# 'exec: "validate": not found' — trust the inspect, not the docs.)
#
# The `</dev/null` is load-bearing: without it, compose run attaches
# the ssh-streamed script (our stdin) to the container and drains it —
# see the header comment.
info "validating Caddy config..."
if ! docker compose run --rm --no-deps -T caddy \
        caddy validate --config /etc/caddy/Caddyfile </dev/null; then
    rollback
    die "Caddy config validation failed — rolled back; the running Caddy is untouched"
fi

if [ "$changed" -ne 0 ]; then
    # `up -d` recreates the container when the override changed (new
    # mounts); the explicit reload covers the remaining case where only
    # the bind-mounted snippet bytes changed and compose sees no diff.
    # If the container WAS just recreated it may still be starting, so
    # the reload can race its admin socket — retry with a short backoff
    # instead of failing the deploy on a race. The config already passed
    # validation, so a persistent reload failure is an environment
    # problem: roll the files back (and best-effort reload the restored
    # config) rather than leave on-disk state that the running Caddy
    # never accepted.
    info "applying: 'docker compose up -d caddy' may now RECREATE the SHARED Caddy"
    info "  container — it fronts EVERY onym.app vhost (relayer wss://, moderation,"
    info "  the works), so open WebSocket connections will drop and reconnect."
    info "  Validation above guarded the config, not this restart."
    docker compose up -d caddy </dev/null
    reloaded=false
    for attempt in 1 2 3 4 5; do
        if docker compose exec -T caddy \
                caddy reload --config /etc/caddy/Caddyfile </dev/null; then
            reloaded=true
            break
        fi
        [ "$attempt" -eq 5 ] || { info "  reload attempt $attempt failed — retrying in 2s..."; sleep 2; }
    done
    if [ "$reloaded" != "true" ]; then
        rollback
        docker compose exec -T caddy \
            caddy reload --config /etc/caddy/Caddyfile </dev/null || true
        die "caddy reload failed after 5 attempts — rolled back the vhost files
  and re-issued a reload of the restored config. Inspect the container:
  cd $INFRA_DIR && docker compose logs caddy | tail -50"
    fi
fi

# ASSERT the applied state before letting ci-deploy.sh proceed to DNS
# and the health check — "the compose commands exited 0" has already
# proven insufficient once. Two checks:
#
# 1. The RUNNING container must carry both override mounts. If it does
#    not (compose somehow kept the old container), force-recreate once
#    and re-check; still missing means something is deeply wrong (an
#    explicit COMPOSE_FILE excluding the override, a renamed base file
#    breaking override auto-loading, ...) and we die loudly rather than
#    hand ci-deploy a droplet that cannot serve the vhost.
if ! caddy_has_vhost_mounts; then
    info "running caddy container is missing the vhost mounts — forcing recreate..."
    info "  (this restarts the SHARED Caddy fronting every onym.app vhost)"
    docker compose up -d --force-recreate caddy </dev/null
    caddy_has_vhost_mounts || die "caddy container STILL lacks the vhost mounts
  (/etc/caddy/caddy.d and $WEB_ROOT->/srv/discovery) after a forced
  recreate. Compose is not seeing $OVERRIDE — check for an explicit
  COMPOSE_FILE / -f selection in $INFRA_DIR that excludes the override.
  Inspect: cd $INFRA_DIR && docker compose config caddy
       and: docker inspect \$(docker compose ps -q caddy) --format '{{.Mounts}}'"
fi

# 2. The config must be loadable AS THE RUNNING CONTAINER SEES IT:
#    `caddy validate` via exec re-adapts /etc/caddy/Caddyfile inside
#    the live filesystem, so it fails if the import glob's caddy.d
#    mount is stale/absent — the exact silent gap of run 31872313566
#    (an unmatched `import` glob is not an error, so the old container
#    validated fine while serving nothing). A positive "is the vhost
#    answering" probe is deliberately NOT done from inside the
#    container: Caddy answers HTTP with a redirect to https://$HOST,
#    which pre-DNS resolves nowhere, and busybox wget can't inspect a
#    status without following it. ci-deploy.sh already curls the
#    droplet IP with the Host header immediately after this script, so
#    the end-to-end probe lives there. (exec argv spells out `caddy`:
#    the image has NO entrypoint — ENTRYPOINT=[], verified above.)
info "verifying the running container loads the merged config..."
docker compose exec -T caddy \
        caddy validate --config /etc/caddy/Caddyfile </dev/null \
    || die "the RUNNING caddy container cannot validate /etc/caddy/Caddyfile —
  its mounts are present but the config does not load inside it. Do not
  proceed. Inspect: cd $INFRA_DIR && docker compose logs caddy | tail -50"

info "Caddy vhost for $HOST ensured (root $WEB_ROOT)"

}

main "$@"
