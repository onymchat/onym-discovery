# Onym Discovery deployment (`discovery.onym.app`)

Source templates and runbook for publishing Onym's own Discovery
provider. Everything here is **unsigned source**; the signed artifacts
are produced at publish time with the operator seed, which never enters
this repository.

## Layout served at `https://discovery.onym.app/`

```text
manifest.json                      # signed DiscoveryProviderManifest
manifest.json.sig
catalogs/onym-services.json        # signed CatalogSnapshot (sequence chain)
catalogs/onym-services.json.sig
catalogs/onym-services-<N>.json    # §5 retention siblings: every published
catalogs/onym-services-<N>.json.sig  # sequence N stays served until it expires
manifests/onym-courier.json        # signed courier ServiceManifest (nostr.onym.app)
manifests/onym-blossom.json        # signed blob ServiceManifest (blossom.onym.app)
policies/onym-services.md          # inclusion/ranking policy the snapshot pins
privacy.md                         # provider privacy profile
```

The notary and moderation entries need no hosted manifest here: the
relayer serves its own at `https://relayer.onym.app/manifest.json`
(`RELAYER_OPERATOR_MANIFEST`), and the authority already serves
`https://moderation.onym.app/manifest.json`. The courier and blossom
manifests are hosted here because a WebSocket relay and a blob store
have no natural HTTPS document root of their own.

## One-time setup

```sh
onym-discovery keygen --out ~/secrets/onym-discovery-operator.seed
# note the printed fingerprint: publish it out of band (site, repo, release notes)
```

Fill every `REPLACE-OPERATOR-KEY` in the `*.src.json` templates with the
printed `onym:key:<hex>`. Distinct seats may use distinct keys; the
courier/blossom manifests are signed by *their* operator's key (today
the same organization, still separate seed files by policy).

## Each publish

```sh
# 1. sign the seat manifests hosted here (only when their content changed)
onym-discovery sign-manifest --seed courier.seed manifests/onym-courier.src.json \
  --out out/manifests/onym-courier.json
onym-discovery sign-manifest --seed blossom.seed manifests/onym-blossom.src.json \
  --out out/manifests/onym-blossom.json

# 2. fetch and REVIEW the live external manifests, then pin their bytes
curl -fsS https://relayer.onym.app/manifest.json  > reviewed/onym-relayer.json
curl -fsS https://moderation.onym.app/manifest.json > reviewed/onym-authority.json
# read them; the digest you pin is the review you performed

# 3. backfill the retention siblings already published (§5) into out/
#    BEFORE building: build-snapshot writes the new sequence's sibling
#    with an overwrite guard that refuses to replace a same-named file
#    with different bytes — the guard can only catch an accidental
#    re-mint of an already-published sequence if the previously
#    published bytes are sitting in out/ when the build runs. It also
#    keeps a later mirroring upload from dropping the siblings.
mkdir -p out/catalogs
base=https://discovery.onym.app/catalogs
fetch() {  # fetch to a temp file, move into place only on success —
           # a failed curl must never leave a 0-byte file behind
  curl -fsS "$base/$1" -o "out/catalogs/$1.tmp" \
    && mv "out/catalogs/$1.tmp" "out/catalogs/$1" \
    || { rm -f "out/catalogs/$1.tmp"; return 1; }
}
if listing=$(curl -fsS "$base/"); then
  siblings=$(printf '%s\n' "$listing" \
    | grep -o 'onym-services-[0-9]*\.json\(\.sig\)\?' | sort -u)
  # a served index that lists no siblings is only correct before the
  # first publish — on any later publish treat it as a failed listing,
  # never as "nothing to preserve"
  for f in $siblings; do
    [ -e "out/catalogs/$f" ] || fetch "$f" \
      || { echo "FATAL: could not fetch published sibling $f" >&2; exit 1; }
  done
else
  echo "WARNING: cannot enumerate $base/ (no directory listing?)" >&2
  echo "backfilling by explicit sequence range instead" >&2
  # walk N down from the currently served sequence until the first 404
  # (older siblings past that have expired and been removed)
  current=$(curl -fsS "$base/onym-services.json" \
    | grep -o '"sequence":[0-9]*' | head -1 | cut -d: -f2)
  [ -n "$current" ] || current=0   # nothing served yet: first publish
  n=$((current - 1))
  while [ "$n" -ge 1 ]; do
    fetch "onym-services-$n.json" || break
    fetch "onym-services-$n.json.sig" \
      || { echo "FATAL: sibling $n served without its .sig" >&2; exit 1; }
    n=$((n - 1))
  done
fi

# 4. build the snapshot (chain onto the previously PUBLISHED bytes;
#    same temp-then-move pattern — a failed fetch must not leave an
#    empty previous.json that a later run mistakes for a document)
if curl -fsS "$base/onym-services.json" -o previous.json.tmp; then
  mv previous.json.tmp previous.json; PREVIOUS=1
else
  rm -f previous.json.tmp; PREVIOUS=   # first publish: no previous
fi
onym-discovery build-snapshot --seed operator.seed \
  --config catalogs/onym-services.config.json \
  ${PREVIOUS:+--previous previous.json} \
  --out out/catalogs/onym-services.json

# 5. sign the provider manifest (only when it changed)
onym-discovery sign-manifest --seed operator.seed provider-manifest.src.json \
  --out out/manifest.json

# 6. verify everything exactly as a client will — the bytes AND both
#    detached .sig files (a .sig that disagrees fails the whole publish)
onym-discovery verify manifest out/manifest.json \
  --sig out/manifest.json.sig
onym-discovery verify snapshot out/catalogs/onym-services.json \
  --manifest out/manifest.json \
  --sig out/catalogs/onym-services.json.sig \
  ${PREVIOUS:+--previous previous.json}
# if this publish also changed the catalog's declared policy digest,
# verify the way an already-subscribed client will: add the previously
# declared digest so the §4.2 one-generation grace is what's checked
#   ... --previous previous.json --previous-policy sha256:<previous-digest>
# (the grace lasts ONE generation: subscribed clients drop the retained
# previous digest after their first acceptance citing the current one)

# 7. upload out/ to the static host, byte-for-byte — and NEVER with a
#    mirror/delete flag (rsync --delete, aws s3 sync --delete): out/
#    now contains every unexpired retention sibling, but a mirroring
#    upload from a fresh or partial out/ would still drop history
```

Rules that are easy to violate and must not be:

- never edit a published snapshot; corrections are a new sequence;
- never re-serialize any signed file on upload (no CDN "minification");
- the digest in a catalog entry pins the bytes you reviewed — if the
  live manifest changed since, review again, don't just re-fetch at
  build time;
- the operator seed stays out of the served directory and this repo.
