# Inclusion and ranking policy: the `onym-services` catalog

This is the policy pinned by every snapshot of the `onym-services`
catalog, published by the Onym Discovery provider
(`onym:component:onym-discovery`) at `discovery.onym.app`. The catalog
snapshot you verified declares this document's exact bytes by digest —
if the digest in the snapshot does not match the file you are reading,
you are not reading the policy that governs that snapshot.

A quick orientation before the rules: a Discovery catalog is a signed
list of *references* to services. Each entry points at a manifest that
the service's own operator signed. Inclusion here is a recommendation by
this provider and nothing more — it is not certification, not protocol
approval, and not proof that the service is safe or currently up. You,
or your client software, always verify the service's own manifest before
using it. (This is the Onym Discovery contract's core rule, and this
catalog follows it.)

## What can be listed

This catalog lists services for four seat types:

| Seat type | What that is |
|---|---|
| `moderation` | A moderation authority that signs content rulings |
| `notary` | A group-verification notary deployment |
| `transport.message` | A message courier (for example, a Nostr-style relay) |
| `blob.storage` | A sealed-blob storage provider |

Nothing else is eligible in this catalog version. The catalog is
deliberately small and curated; it does not attempt to list every
compatible service that exists, and it never claims completeness.

## What it takes to get in

Every entry in the catalog got there the same way:

1. The service's operator published a signed manifest conforming to that
   seat's own contract.
2. This provider fetched that manifest and **reviewed the exact bytes**
   — signature, schema, seat type, declared endpoints, profiles, and
   expiry.
3. Only after that review did the provider pin the manifest's SHA-256
   digest into the catalog entry. The digest is the review: an entry
   recommends precisely the bytes that were read, and no others. If the
   operator later changes the manifest, the old entry does not silently
   follow — the change gets reviewed again and published as a new
   snapshot, or the entry is removed.

There is no required third-party attestation or audit in this catalog
version. Manifest freshness is checked at review time (an expired
manifest is not pinned); there is no continuous availability monitoring
behind an entry.

## Relationships, disclosed

Every entry currently in this catalog carries
`"relationship": "common-owner"`: the listed services are operated by
the same organization that operates this Discovery provider. That is
exactly the kind of conflict the Discovery contract requires a provider
to disclose on each affected entry, and this policy makes the disclosure
blanket and explicit: **today, this is a catalog of our own services.**
Treat the recommendations accordingly, and remember that your client can
add other Discovery sources or import any manifest directly — absence
from this catalog never blocks direct use.

If an entry from an unrelated operator is ever added, its entry will say
`"relationship": "none"` (or whichever disclosed value applies), and
this policy will be updated — which changes this document's digest, so
the change is visible to every subscribed client.

## Ranking

Ranking is deterministic and boring, on purpose:

- Entries appear in **policy order**: the order in the snapshot's
  `entries` array is the listing order, chosen by this provider when the
  snapshot is built.
- Every entry is `"placement": "policy-ranked"`. There is **no paid
  placement** in this catalog version — no listing fees, no sponsored
  slots, no rank for sale. If a future catalog version introduces a paid
  placement offer, the affected entries will say so in their `placement`
  field and this policy will change (and re-digest) first.
- There is no personalization. Every client that downloads a given
  snapshot sees exactly the same entries in exactly the same order.

Your client may re-rank locally — that is its right — but a local order
is the client's, not this catalog's.

## Removal and corrections

A published snapshot is immutable. Every change — adding an entry,
removing one, correcting a mistake — is a **new snapshot with the next
sequence number**, chained to the previous snapshot by digest, so
removals and replacements are observable to any client that keeps
history.

When an entry is removed, the reason falls under the abstract Discovery
contract's bounded reason codes: `manifest_expired`, `policy_mismatch`,
`evidence_expired`, `unreachable`, `operator_request`,
`security_response`, or `commercial_term_ended`. (This profile's
snapshot format does not yet carry a machine-readable reason field; until
it does, the reason for a removal is stated in this provider's release
notes for the publishing commit.)

Removal from this catalog means only that this catalog no longer
recommends the entry. It does not revoke the operator's manifest and
does not prevent anyone from using the service directly.

**Corrections and appeals.** If an entry misdescribes a service, or you
operate a listed service and want it corrected or removed, contact the
operator at `lead@onym.app`. A security-driven emergency removal may be
published before a detailed explanation when explaining first would make
an active problem worse; the removal still lands as a normal new
sequence under this policy.

## Review cadence and expiry

Entries are re-reviewed **at every publish**: building a new snapshot
re-checks each pinned manifest before its digest is carried forward.
There is no fixed calendar cadence beyond that — but snapshots expire
(the `expiresAt` field, at most the profile's 90-day ceiling, normally
much shorter), so a catalog that stops being maintained stops being
current, visibly, rather than lingering as a stale recommendation.

## What this provider does NOT verify

Read this section as carefully as the rest:

- **Service quality.** An entry says the operator's manifest was
  well-formed and properly signed — nothing about how good the service
  is.
- **Availability.** There are no SLAs here and no uptime monitoring
  behind an entry. A listed endpoint can be down right now.
- **Destination-seat compliance beyond the manifest.** The review checks
  the manifest's signature, schema, and declared claims. Whether the
  running service actually honors its seat contract in operation is
  between you, the operator, and that seat's own verification rules —
  applied by your client after discovery, as the contract requires.

If any of this policy is unclear, the authoritative context is the Onym
Discovery contract and its static-Ed25519 implementation profile,
published in the Onym system documentation.
