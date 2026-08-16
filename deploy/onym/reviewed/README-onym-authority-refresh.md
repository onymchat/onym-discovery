# Refreshing `onym-authority.json` after the finalize-manifest deploy

`onym-authority.json` is a byte-accurate copy of what
`https://authority.onym.app/manifest.json` served when it was last
reviewed — the catalog pins the sha256 of these exact bytes.

The onym-infra deploy that lands onym-moderation#43 / onym-infra#21
**changes the served bytes**: the manifest is finalized for
destination-manifest review, so it becomes canonical compact JSON
(keys sorted in UTF-8 byte order, no trailing LF) carrying three new
top-level fields — `name` ("Onym Authority"), `endpoints`
(`[{"uri": "https://authority.onym.app"}]`), and an **embedded**
`signature` by the operator key over the canonical signing bytes.

The new bytes are **not producible locally** — the embedded signature
needs the droplet's `AUTHORITY_SIGNING_SEED` — so this file must not
be regenerated from a template; it is refreshed from the live
manifest, after that deploy, and only then:

```sh
cd deploy/onym
curl -fsS https://authority.onym.app/manifest.json > reviewed/onym-authority.json
# READ IT — the digest you pin is the review you performed.
```

Review checklist for the refreshed bytes:

- `operator` is still
  `onym:key:bdec68a8440f36591dd822748f86fee3582794b3d20445b06953db6f266f3dca`
  (the key pinned in `catalogs/onym-services.config.json`; a changed
  key is a re-keying, not a refresh);
- the spine is intact (`componentId: onym:component:onym-authority`,
  `seat: moderation`, a future `validUntil`) and the policy terms are
  the ones reviewed before;
- `signature` is present and the document is canonical (a re-run of
  `onym-discovery sign-manifest` by the operator over the same content
  would reproduce it byte-for-byte).

Then commit the refreshed copy. No manual snapshot rebuild is needed
on the default CI-signing path — the snapshot is built at publish time
from the committed `reviewed/` bytes (see `README.md`, "Before the
genesis dispatch"); only the `skip_signing` path bakes it early and
must be re-run. Until the refresh is committed, `ci-assemble.sh`'s
freshness gate will (correctly) hard-fail any signing run: the live
bytes no longer match the committed review.
