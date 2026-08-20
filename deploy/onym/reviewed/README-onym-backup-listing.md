# Listing the device-backup operator

`storage.backup` is declared in the provider manifest's `seatTypes`, so
the catalog may carry a backup entry. **It does not carry one yet**, and
this file is the second half of that change.

An entry pins the sha256 of the bytes the operator actually serves, and
those bytes do not exist until it is deployed: the manifest carries an
embedded signature by the operator key, which lives only in the
droplet's `BACKUP_SIGNING_SEED`. So the file under `reviewed/` cannot be
generated from a template here — it is fetched from the live operator,
read, and only then pinned. Same constraint as
`README-onym-authority-refresh.md`, for the same reason.

Declaring the seat type ahead of the entry is deliberate and harmless: a
catalog whose `seatTypes` omits `storage.backup` is one where clients
filter the entry out and never see it, so the declaration has to land
first or with the entry, never after.

## After onym-infra#24 deploys

```sh
cd deploy/onym
curl -fsS https://backup.onym.app/manifest.json > reviewed/onym-backup.json
# READ IT. The digest you pin is the review you performed.
```

Check the fetched bytes before pinning:

- `seat` is `storage.backup`. An entry whose manifest declares a
  different seat is skipped by clients — a catalog must not be able to
  install one kind of service into another kind's slot.
- `operator` is the key you expect, and matches the `operator` you put
  in the catalog entry. It is derived from `BACKUP_SIGNING_SEED`, so a
  changed key means the seed changed — which, for this seat, means
  every consent record already issued no longer matches. Do not paper
  over that by re-pinning.
- `endpoints` carries a `read-write` entry on `https://backup.onym.app`
  with no port. A manifest whose read-write entries are all unusable is
  refused by the client outright.
- `implementationProfileId` is
  `onym:backup-implementation:object-http-v1` and `backupProfileId` is
  `onym:backup-profile:sealed-device-archive-v1`.
- `entitlementIssuers` is empty. That is free mode, and it is what the
  deployment currently runs — a non-empty list here means the operator
  will demand a credential that nothing issues yet.
- `declaredTerms` is a `sha256:` digest, and it resolves:
  `curl -fsS https://backup.onym.app/terms/<hex>.json`. A pinned terms
  document that 404s is a promise nobody can read.

Then add the entry to `catalogs/onym-services.config.json`:

```json
{
  "componentId": "onym:component:onym-backup",
  "seatType": "storage.backup",
  "manifest": { "uri": "https://backup.onym.app/manifest.json" },
  "manifestFile": "../reviewed/onym-backup.json",
  "operator": "onym:key:<the key from the fetched manifest>",
  "profiles": ["onym:backup-implementation:object-http-v1"],
  "listedAt": "<the date you reviewed it>",
  "relationship": "common-owner",
  "placement": "policy-ranked"
}
```

`relationship: "common-owner"` because the same people run this catalog
and that operator. It is a disclosure, not a formality — a client shows
it, and understating it is the misrepresentation the disclosure exists
to prevent.

## Being listed is still not enough

A listed operator is one a client can *find*. Consenting to it needs a
seat picker in the app, and at the time of writing neither onym-ios nor
onym-android has one for `storage.backup` — the settings section that
would use it can never appear. Listing the entry before that lands is
harmless (nothing queries the seat type), but it does not make the
feature reachable on its own.
