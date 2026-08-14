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

# 3. build the snapshot (chain onto the previously PUBLISHED bytes)
curl -fsS https://discovery.onym.app/catalogs/onym-services.json > previous.json \
  || true   # first publish: no previous
onym-discovery build-snapshot --seed operator.seed \
  --config catalogs/onym-services.config.json \
  ${PREVIOUS:+--previous previous.json} \
  --out out/catalogs/onym-services.json

# 4. sign the provider manifest (only when it changed)
onym-discovery sign-manifest --seed operator.seed provider-manifest.src.json \
  --out out/manifest.json

# 5. verify everything exactly as a client will
onym-discovery verify manifest out/manifest.json
onym-discovery verify snapshot out/catalogs/onym-services.json \
  --manifest out/manifest.json ${PREVIOUS:+--previous previous.json}

# 6. upload out/ to the static host, byte-for-byte
```

Rules that are easy to violate and must not be:

- never edit a published snapshot; corrections are a new sequence;
- never re-serialize any signed file on upload (no CDN "minification");
- the digest in a catalog entry pins the bytes you reviewed — if the
  live manifest changed since, review again, don't just re-fetch at
  build time;
- the operator seed stays out of the served directory and this repo.
