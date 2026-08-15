# Privacy profile: the Onym Discovery provider

This is the privacy profile declared by the Discovery provider manifest
served at `discovery.onym.app` (`onym:component:onym-discovery`). The
manifest pins this document's exact bytes by digest, so what you are
reading is what the provider signed up to.

The short version: **this service is a folder of signed static files.**
There is nothing here that can watch what you search for, because there
is no search here at all.

## How queries work: they don't reach us

This provider implements the static-snapshot Discovery profile. Your
client downloads whole catalog snapshots and filters them **locally, on
your device**. There are:

- no accounts and no sign-in of any kind;
- no cookies and no client-side identifiers set by this service;
- no query endpoints and no server-side search — the server cannot see
  *which* services you were looking for, only that a snapshot file was
  fetched;
- no per-user or per-session URLs: everyone fetches the same files.

This is the Discovery contract's recommended baseline, chosen precisely
because a remote query could reveal which kinds of services interest a
person. A full-snapshot download reveals only that someone uses Onym
discovery at all.

## What the infrastructure can see

Honesty over marketing: serving files over HTTPS still involves
infrastructure, and infrastructure sees network metadata.

- The files are served by a standard web server (Caddy) on a
  DigitalOcean droplet operated by Onym. **Standard web-server access
  logs may exist at that infrastructure layer** — the usual fields:
  client IP address, request path, timestamp, user agent, response
  status. These are hosting-level operational logs, not a discovery
  feature; their retention and handling follow the Onym infrastructure
  operations policy (`onym-infra`), and they are used for operating the
  host (debugging, abuse response), not for analytics about you.
- DNS for `discovery.onym.app` is hosted at Cloudflare in DNS-only mode:
  your requests go directly to the droplet, not through Cloudflare's
  proxy. Cloudflare sees DNS resolution traffic, as any DNS host would.
- As with any HTTPS service, networks between you and the server can see
  that a connection to `discovery.onym.app` happened, but not the
  content.

Subprocessors, completely: DigitalOcean (hosting) and Cloudflare (DNS
only). No analytics service, no CDN in front of the content, no
third-party scripts — the served content is JSON and Markdown.

## Rate limiting

There is no application-level rate limiting and no rate-limit state tied
to any identifier. Any throttling that ever occurs would be generic
infrastructure-level protection (per-IP, anonymous, transient), never
account-bound — there are no accounts to bind it to.

## What this provider will never do

These are the Discovery contract's baseline prohibitions, and this
provider adopts them without exception:

- **No personalization.** Every client that fetches a given snapshot
  gets the identical signed bytes, in the identical order. There is no
  mechanism by which results *could* be tailored to you.
- **No cross-seat profiling.** Nothing here joins your interest in one
  kind of service with your interest in another to build a behavioral
  profile — there are no queries to join.
- **No destination callbacks.** Listed services are never told who
  viewed, skipped, or selected them. Browsing this catalog identifies
  you to no one; a service learns about you only if and when you choose
  to use it, under that service's own rules.
- **No sale or disclosure of access data** for advertising, eligibility,
  pricing, or surveillance purposes.
- **No identity requirement.** Public discovery here never requires an
  identity key, recovery secret, message key, or group-membership proof.

## Changes

Any change to this document changes its digest, which changes the signed
provider manifest — so a privacy change can never happen silently
underneath a manifest your client already verified. Questions about this
profile: `lead@onym.app`.
