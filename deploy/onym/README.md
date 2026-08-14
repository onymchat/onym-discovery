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

Everything below is a hard requirement: `ci-assemble.sh` fails fast,
with the reason, when any of it is missing. This list is where those
fail-fast messages point.

**1. Create and PROTECT the `production` GitHub environment — before
the first dispatch.** The deploy job runs in `environment: production`,
but naming an environment in a workflow is not a gate: **GitHub
auto-creates the environment, unprotected, the first time the workflow
is dispatched**, and an unprotected environment releases its secrets to
any run that asks. The approval gate exists only after you create the
environment in the repository settings (Settings → Environments →
`production`) and add **required reviewers**. Do this first, so a
dispatch — or any workflow change that reaches for the seed secrets —
needs a human approval before the environment's secrets are released.

**2. Generate the signing keys.**

```sh
onym-discovery keygen --out ~/secrets/onym-discovery-operator.seed
# note the printed fingerprint: publish it out of band (site, repo, release notes)
```

Distinct seats may use distinct keys; the courier/blossom manifests are
signed by *their* operator's key (today the same organization, still
separate seed files by policy).

**3. Author the served documents.** Write the two Markdown documents
this directory serves — they do not exist until you write them:

- `policies/onym-services.md` — the inclusion/ranking policy the
  snapshot pins;
- `privacy.md` — the provider privacy profile.

**4. Compute and fill both digests.** The templates pin the exact bytes
of those documents; compute the digests from the final files:

```sh
shasum -a 256 policies/onym-services.md
shasum -a 256 privacy.md
```

Prefix each hex digest with `sha256:` and fill:

- `REPLACE-POLICY-DIGEST` (policy digest) — in
  `catalogs/onym-services.config.json` (`policyDigest`) and
  `provider-manifest.src.json` (the catalog's `policy`);
- `REPLACE-PRIVACY-DIGEST` (privacy digest) — in
  `provider-manifest.src.json` (`privacyProfile`).

Editing either document later means recomputing its digest, or the
digest check aborts the build.

**5. Fill the operator keys.** Each `onym:key:REPLACE-*` placeholder
takes the `onym:key:<hex>` a `keygen` run printed:

- `REPLACE-OPERATOR-KEY` in `provider-manifest.src.json` — the
  discovery operator key;
- the four per-seat keys in `catalogs/onym-services.config.json`:
  `REPLACE-AUTHORITY-KEY`, `REPLACE-RELAYER-KEY`,
  `REPLACE-COURIER-KEY`, `REPLACE-BLOSSOM-KEY` — each entry's key must
  be the one its manifest is actually signed with;
- `REPLACE-COURIER-KEY` again in `manifests/onym-courier.src.json` and
  `REPLACE-BLOSSOM-KEY` in `manifests/onym-blossom.src.json`.

**6. Fetch and review the external manifests.** The relayer and
authority host their own manifests; you pin the bytes you reviewed:

```sh
curl -fsS https://relayer.onym.app/manifest.json    > reviewed/onym-relayer.json
curl -fsS https://moderation.onym.app/manifest.json > reviewed/onym-authority.json
# read them; the digest you pin is the review you performed
```

## Publishing from CI (the default path)

`.github/workflows/deploy.yml` runs the publish from a manual
`workflow_dispatch` (type `deploy` in the confirm input; for the very
first publish also set `genesis: true` — without it, a run that cannot
fetch the live snapshot aborts rather than start a new chain). It
builds the release CLI, signs, chains the snapshot onto the previously
*published* bytes, verifies everything exactly as a client
would, rsyncs to `/var/www/discovery` on the onym-infra droplet
(resolved with `doctl` by `DROPLET_ID` variable or the `onym-infra`
name, same as onym-infra's own deploy), idempotently installs the Caddy
vhost, confirms the vhost answers on the droplet directly, and only
then upserts the grey-cloud Cloudflare A record — DNS is the last state
a deploy creates, so a mid-run failure never leaves a public name
pointing at a half-configured host.

Secrets it needs, matching onym-infra's names where they already exist:

| Secret | Status |
|---|---|
| `DO_API_KEY` | org-level, exists |
| `CF_API_TOKEN` | org-level, exists |
| `SSH_PRIVATE_KEY` | the key the droplet trusts — same secret onym-infra deploys with |
| `DISCOVERY_OPERATOR_SEED` | **you must generate and add** (64 hex chars) |
| `COURIER_OPERATOR_SEED` | **you must generate and add** (64 hex chars) |
| `BLOSSOM_OPERATOR_SEED` | **you must generate and add** (64 hex chars) |

Generate each seed with `onym-discovery keygen --out <name>.seed`; the
secret value is the file's single 64-hex-char line. Publish the printed
fingerprints out of band. The seed files themselves stay out of this
repository (`.gitignore` covers `*.seed`).

**CI-held keys are a real tradeoff.** Putting the seeds in Actions
secrets means GitHub (and anyone who can edit this repository's
workflows) is inside your signing perimeter: a malicious workflow change
could exfiltrate a seed or sign something you never reviewed. In
exchange, publishing is one click and the seeds never sit on a laptop.
If you prefer the keys never to leave your machine, run the workflow
with `skip_signing: true`: it then deploys the pre-signed artifacts
committed under `signed/` (produced by the manual runbook below), and CI
is reduced to verify + transport — it holds no signing material at all.
(`out/` is CI's own gitignored signing scratch; the committed pre-signed
artifacts live in `signed/` precisely so the two never mix.) Either way
the verify gate runs before a byte leaves the runner.

CI hard-fails, with the reason, when: a `REPLACE-*` placeholder is still
unfilled; `policies/onym-services.md`, `privacy.md`, or the `reviewed/`
manifests are missing; a pinned digest does not match the bytes being
served; a seed secret is unset (and `skip_signing` is not); or the live
snapshot cannot be fetched — for any reason, including DNS failure —
without `genesis: true`. A fetch failure is never read as "nothing
published yet": with `genesis: false`, **every** failure path aborts,
full stop. With `genesis: true`, **every** failure path cross-checks
the Cloudflare zone before deciding:

- host doesn't resolve **and** no A record exists — clean genesis
  (sequence 1);
- clean HTTP 404 from a host whose A record is absent or points at this
  deploy's own droplet — true genesis, proceeds;
- any other failure (TLS handshake, connection refused, unexpected
  status, or an A record present while the host doesn't resolve) —
  **genesis recovery**: eligible only when every A record for the host
  points at this deploy's own droplet *and* no snapshot is fetchable
  from that droplet directly. That is the signature of a first deploy
  that wedged between the DNS upsert and certificate issuance; it
  proceeds with a loud warning. Anything less — a record pointing
  elsewhere, a snapshot answering on the droplet, or no way to perform
  the check — aborts rather than fork the sequence chain.

Note for after PR #3 lands (retention siblings + `--sig` verify flags):
`build-snapshot` will start writing `onym-services-<sequence>.json`
retention siblings itself, and the verify gate in `ci-assemble.sh`
should grow `--sig <file>.sig` on both `verify` calls so the detached
signatures are checked for agreement too. Until then CI preserves any
already-published siblings by fetching them and by never rsyncing with
`--delete`.

## Each publish (manual runbook — the alternative)

Artifacts signed by hand go under `signed/`, which is **committed** —
that is what makes the `skip_signing: true` deploy possible (`out/` is
CI's gitignored scratch and must stay out of the repository).

```sh
# 1. sign the seat manifests hosted here (only when their content changed)
onym-discovery sign-manifest --seed courier.seed manifests/onym-courier.src.json \
  --out signed/manifests/onym-courier.json
onym-discovery sign-manifest --seed blossom.seed manifests/onym-blossom.src.json \
  --out signed/manifests/onym-blossom.json

# 2. fetch and REVIEW the live external manifests, then pin their bytes
curl -fsS https://relayer.onym.app/manifest.json  > reviewed/onym-relayer.json
curl -fsS https://moderation.onym.app/manifest.json > reviewed/onym-authority.json
# read them; the digest you pin is the review you performed

# 3. backfill the retention siblings already published (§5) into signed/
#    BEFORE building: build-snapshot writes the new sequence's sibling
#    with an overwrite guard that refuses to replace a same-named file
#    with different bytes — the guard can only catch an accidental
#    re-mint of an already-published sequence if the previously
#    published bytes are sitting in signed/ when the build runs. It also
#    keeps a later mirroring upload from dropping the siblings.
mkdir -p signed/catalogs
base=https://discovery.onym.app/catalogs
fetch() {  # fetch to a temp file, move into place only on success —
           # a failed curl must never leave a 0-byte file behind
  curl -fsS "$base/$1" -o "signed/catalogs/$1.tmp" \
    && mv "signed/catalogs/$1.tmp" "signed/catalogs/$1" \
    || { rm -f "signed/catalogs/$1.tmp"; return 1; }
}
served_sequence() {  # sequence of the currently served latest; 0 when
                     # nothing is served yet (first publish)
  seq=$(curl -fsS "$base/onym-services.json" \
    | grep -o '"sequence":[0-9]*' | head -1 | cut -d: -f2)
  echo "${seq:-0}"
}
backfill_by_sequence() {
  # walk N down from the currently served sequence until the first 404
  # (older siblings past that have expired and been removed); starts AT
  # the served sequence — its own sibling is published too and must be
  # preserved like the rest
  current=$(served_sequence)
  n=$current
  while [ "${n:-0}" -ge 1 ]; do
    fetch "onym-services-$n.json" || break
    fetch "onym-services-$n.json.sig" \
      || { echo "FATAL: sibling $n served without its .sig" >&2; exit 1; }
    n=$((n - 1))
  done
}
if listing=$(curl -fsS "$base/"); then
  siblings=$(printf '%s\n' "$listing" \
    | grep -o 'onym-services-[0-9]*\.json\(\.sig\)\?' | sort -u)
  if [ -z "$siblings" ] && [ "$(served_sequence)" -ge 1 ]; then
    # a served index that lists no siblings is only correct before the
    # first publish — while any snapshot is being served, treat it as a
    # FAILED listing, never as "nothing to preserve", and fall back to
    # the explicit sequence walk
    echo "WARNING: $base/ lists no siblings while a snapshot is served" >&2
    echo "treating as a failed listing; backfilling by sequence range" >&2
    backfill_by_sequence
  fi
  for f in $siblings; do
    [ -e "signed/catalogs/$f" ] || fetch "$f" \
      || { echo "FATAL: could not fetch published sibling $f" >&2; exit 1; }
  done
else
  echo "WARNING: cannot enumerate $base/ (no directory listing?)" >&2
  echo "backfilling by explicit sequence range instead" >&2
  backfill_by_sequence
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
  --out signed/catalogs/onym-services.json

# 5. sign the provider manifest (only when it changed)
onym-discovery sign-manifest --seed operator.seed provider-manifest.src.json \
  --out signed/manifest.json

# 6. verify everything exactly as a client will — the bytes AND both
#    detached .sig files (a .sig that disagrees fails the whole publish)
onym-discovery verify manifest signed/manifest.json \
  --sig signed/manifest.json.sig
onym-discovery verify snapshot signed/catalogs/onym-services.json \
  --manifest signed/manifest.json \
  --sig signed/catalogs/onym-services.json.sig \
  ${PREVIOUS:+--previous previous.json}
# if this publish also changed the catalog's declared policy digest,
# verify the way an already-subscribed client will: add the previously
# declared digest so the §4.2 one-generation grace is what's checked
#   ... --previous previous.json --previous-policy sha256:<previous-digest>
# (the grace lasts ONE generation: subscribed clients drop the retained
# previous digest after their first acceptance citing the current one)

# 7. publish, byte-for-byte — and NEVER with a mirror/delete flag
#    (rsync --delete, aws s3 sync --delete): signed/ now contains every
#    unexpired retention sibling, but a mirroring upload from a fresh or
#    partial tree would still drop history. Either commit signed/ and
#    run the deploy workflow with skip_signing: true, or rsync it to
#    /var/www/discovery on the droplet yourself.
```

Rules that are easy to violate and must not be:

- never edit a published snapshot; corrections are a new sequence;
- never re-serialize any signed file on upload (no CDN "minification");
- the digest in a catalog entry pins the bytes you reviewed — if the
  live manifest changed since, review again, don't just re-fetch at
  build time;
- the operator seed stays out of the served directory and this repo.
