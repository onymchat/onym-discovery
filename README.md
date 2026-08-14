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
canonicalization vectors (including the case-divergence and escaping
sub-vectors), a sponsored-placement + disclosed-status snapshot, a
source-conflict provider pair, a policy-transition manifest, an
audience-skip manifest, cross-catalog equivocation snapshots, a
duplicate-key rejection vector, and a detached-`.sig` disagreement pair.
The forward-jump and no-op-refresh cases are exercised as tests over the
chain fixtures. §10 item 9 (the privacy fetch trace) is a client
network-behavior obligation, not an offline byte fixture. CI regenerates
and byte-compares fixtures on every push, so implementation drift fails
the build. Client repos (the iOS and Android discovery packages) consume
these exact files.

Regenerate deliberately after an intentional change:

```sh
DISCOVERY_REGEN_FIXTURES=1 cargo test --test conformance
```

## What verification enforces

- Ed25519 signatures over canonical bytes (structural signature removal,
  UTF-8-byte-order key sorting, compact JSON, unescaped `/`, pinned
  string escaping — the same mechanism as `onym-moderation`'s
  canonical.rs, pinned by fixtures not shared code);
- duplicate JSON keys rejected at any depth (a streaming scan before the
  tree parse — never last-key-wins);
- strict top-level schemas, lossy per-entry and per-descriptor decoding
  with surfaced skip counts; non-public catalogs skipped by `audience`;
  `seatTypes` member validation; entry `status` decoded and surfaced
  (never skipped when valid); non-empty `evidence` skips the entry;
- the §6 four-case chain comparison against retained per-catalog state:
  no-op refresh (no warning), rollback and forks rejected, forward
  jumps accepted with a source-integrity note; first acceptance of a
  source takes any sequence (TOFU covers trust);
- the §4.2 one-generation policy-transition grace, surfaced as a note;
- ≤ 90-day expiry windows, expiry and future-dating evaluated with the
  symmetric 10-minute skew allowance;
- profile §7 bounds and URI rules (https-only, DNS hosts, no IP
  literals including integer forms, no query/fragment/userinfo, and no
  port component in the RAW string — a redundant `:443` is rejected
  before URL-library normalization can hide it);
- destination manifests bound by pinned digest — drifted bytes are
  `entry_manifest_mismatch`, oversize is `entry_manifest_unavailable`,
  never silently refreshed;
- detached-`.sig` agreement (compared after base64 decoding) with a
  verify path that fails closed on disagreement;
- cross-catalog digest equivocation and two-source `source_conflict`
  detection helpers, consumed by the fixtures.

Known limitations: the §6 intermediate-fetch continuity walk over
retained `<catalogId>-<sequence>.json` siblings is a fetch-side
behavior this offline CLI does not perform (forward jumps degrade to
accept-with-note, which §6 permits); the builder does publish the §5
retention siblings.

## License

MIT
