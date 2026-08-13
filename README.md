# onym-discovery

Reference implementation of the Onym Discovery seat's
[static-snapshot/Ed25519 profile](https://github.com/onymchat/onym-system/blob/main/discovery/Discovery-Static-Ed25519.md):
a CLI that signs provider manifests, builds chain-linked catalog
snapshots, and verifies everything — plus the conformance fixtures every
client implementation pins byte-for-byte.

There is deliberately no service here. Discovery in this profile is
static signed files on any HTTPS host; the operator runs this tool at
publish time and uploads the output. Nothing has to stay online beyond a
file server, and any mirror serves the same verifiable bytes.

## Quick start

```sh
# one-time: create the operator key (keep the seed file OUT of the served dir)
onym-discovery keygen --out operator.seed

# sign the provider manifest you wrote (canonical bytes out, .sig sibling)
onym-discovery sign-manifest --seed operator.seed manifest.src.json --out manifest.json

# build the first snapshot from a source config
onym-discovery build-snapshot --seed operator.seed \
  --config catalog.config.json --out catalogs/public-all-seats.json

# next publish: chain onto the exact bytes of the previous snapshot
onym-discovery build-snapshot --seed operator.seed \
  --config catalog.config.json \
  --previous catalogs/public-all-seats.json \
  --out catalogs/public-all-seats.next.json

# verify what you (or anyone else) published
onym-discovery verify manifest manifest.json
onym-discovery verify snapshot catalogs/public-all-seats.next.json \
  --manifest manifest.json --previous catalogs/public-all-seats.json
onym-discovery verify destination courier-manifest.json --digest sha256:...
```

`keygen` prints the operator id (`onym:key:<hex>`) and the short
fingerprint clients display at trust-on-first-use pinning. Publish the
fingerprint out of band; it is what lets a user check they pinned *you*.

## Snapshot config

`build-snapshot` reads a JSON config; entries are `CatalogEntry` objects,
except `manifest.digest` may be replaced by a `manifestFile` path whose
bytes are hashed at build time — the "retrieve, review, then pin" step:

```json
{
  "catalogId": "public-all-seats",
  "providerId": "onym:component:onym-discovery",
  "policyDigest": "sha256:...",
  "expiryDays": 30,
  "entries": [
    {
      "componentId": "onym:component:onym-relayer",
      "seatType": "notary",
      "manifest": { "uri": "https://relayer.onym.app/manifest.json" },
      "manifestFile": "reviewed/onym-relayer-manifest.json",
      "operator": "onym:key:...",
      "profiles": ["onym:notary-implementation:stellar-soroban-sep-plonk-v1"],
      "listedAt": "2026-08-13T00:00:00Z",
      "relationship": "common-owner",
      "placement": "policy-ranked"
    }
  ]
}
```

Sequence numbers and `previousDigest` are derived from `--previous`, never
hand-written. Emitted bytes are canonical (compact, key-sorted), so the
same content + key always produces the same file and the same digest.

## Conformance fixtures

`tests/fixtures/` holds the deterministic vectors listed in the profile's
§10 — a signed manifest, a three-snapshot chain, a destination manifest,
and canonicalization vectors. CI regenerates and byte-compares them on
every push, so implementation drift fails the build. Client repos (the
iOS `OnymDiscovery` package) consume these exact files.

Regenerate deliberately after an intentional change:

```sh
DISCOVERY_REGEN_FIXTURES=1 cargo test --test conformance
```

## What verification enforces

- Ed25519 signatures over canonical bytes (structural signature removal,
  key-sorted compact JSON, unescaped `/` — the same mechanism as
  `onym-moderation`'s canonical.rs, pinned by fixtures not shared code);
- strict top-level schemas, lossy per-entry decoding;
- sequence +1 chains with `previousDigest` over exact published bytes —
  rollback, gaps, and forks are named failures;
- ≤ 90-day expiry windows, and expiry evaluated at verify time;
- profile §7 bounds and URI rules (https-only, DNS hosts, no IP
  literals, no query/fragment/userinfo/port);
- destination manifests bound by pinned digest — drifted bytes are
  `entry_manifest_mismatch`, never silently refreshed.

Known limitation: duplicate JSON keys are not detected (serde_json keeps
the last occurrence). The canonical form a signer emits never contains
duplicates; a verifier that must treat duplicate-key documents as
invalid needs a stricter parse pass than this reference currently does.

## License

MIT
