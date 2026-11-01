# App instances and extra domains

Status: draft for approval (2026-11-02)

## Intent

Two teams want their own Grafana, fully separate. More generally:

- any template can run as **several independent copies** ("instances");
- each copy gets **hostnames the admin chooses**, on the main domain or on an
  **extra domain or subdomain** enrolled in Portcullis, with its own DNS
  records and wildcard certificate.

Today one template = one deployment, its hostnames are fixed by the
template (`grafana.${PORTCULLIS_DOMAIN}`), and everything lives under one
domain.

## Goals

1. **Instances.** An admin can add any number of instances of a template.
   - Each instance has an id/name (e.g. `grafana-team-a`) and its own:
     - compose project, containers and volumes (data);
     - settings, env and generated secrets;
     - Keycloak client;
     - access/admin groups, auth policy, public exceptions and sign-in mode;
     - drift tracking and last-operation record.
   - Nothing is shared between instances.
   - Existing single deployments keep working unchanged, as the template's
     default instance with today's id, hostnames and group names.
2. **Hostnames per endpoint.** When adding an instance, the admin picks a name
   and a domain.
   - Every hostname the template serves (each router) is pre-filled from the
     instance name and domain. The template's subdomain is kept and the
     instance suffix is added, e.g. `grafana.<domain>` →
     `grafana-team-a.<domain>`; an api router gets `api-team-a.<domain>`.
   - Each hostname is individually editable.
3. **Changing hostnames.** An admin can change a running instance's hostnames
   or domain at any time ("change is change").
   - The Hub updates everything that depends on them: the app's URL settings,
     its Keycloak client redirect URIs, policies and public share links. Then
     it restarts the instance.
   - The old hostnames stop working immediately (no redirects).
4. **Enrolled domains.** A Hub admin can enroll an extra domain or subdomain,
   e.g. `team-a.com` or `team-a.<main domain>`, by giving its DNS provider
   and an API token that can edit its records. Portcullis then:
   - creates `<d>` and `*.<d>` (A, and AAAA when the host has IPv6) pointing
     at the server;
   - obtains a Let's Encrypt wildcard certificate for `*.<d>` and `<d>` with
     DNS-01, and renews it;
   - shows the domain's status: records OK, certificate valid until, last
     error.
5. **Domain rules.**
   - Extra domains carry **only** the instances assigned to them, never core
     pages (portal, hub, people, auth, …).
   - A domain can't be removed while an instance uses it.
   - Tokens are write-only in the Hub: never shown again, never readable by
     apps, replaceable.
6. **Sign-in across domains without an extra key touch.** A user signed in on
   the main domain who opens an instance on an extra domain is redirected
   once to central sign-in and straight back, with no prompt — like Amazon
   Midway. The only exception is when the instance's policy needs a stronger
   factor than the session has; that prompts today too.
7. **Delete is delete, guarded, with backups.** Removing an instance needs the instance id typed to confirm. It first takes an automatic backup of the instance, then permanently removes its containers, volumes, Keycloak client, generated secrets, `users_<id>`/`admin_<id>` groups and Hub state. Admins can also back up any instance on demand and restore a backup into the same instance (replacing its data) or into a new instance id.
8. **Admin-only and audited.** Adding, changing and removing instances and
   domains is admin-only and audited. Delegates (edit_details / invite /
   remove) have no access to it.

## Non-goals

- A per-hostname HTTP-01 certificate fallback for domains whose DNS has no API:
  a DNS provider token is required for every enrolled domain.
- Redirects from old hostnames after a change.
- Sharing data, settings or users between instances.
- Core services on extra domains.

## Anti-goals

- Weakening the gateway:
  - an instance on an extra domain must be protected exactly like one on the
    main domain (forward-auth, group-gate, policy, mTLS tiers, public
    exceptions);
  - group-gate must never apply one hostname's policy to another.
- **Secret sprawl.** DNS tokens must not reach the Hub's other code paths,
  apps, logs, audit or backups unencrypted.
- **Collisions.** Two instances, or an instance and a core service, must never
  serve the same hostname. Two instances must never share a volume.
- **Breaking existing installs' templates silently.** An existing template
  keeps working as the default instance. A template that can't run as
  multiple instances is marked so, and the Hub refuses extra instances of it
  with a clear reason.

## Constraints and facts (verified in the code)

- **Templates hard-code `<sub>.${PORTCULLIS_DOMAIN}`.** They do this in
  Traefik rules and in app env (e.g. `APP_URL: https://finance.${PORTCULLIS_DOMAIN}`,
  GitLab's `external_url`). 20 of 22 templates set explicit volume names
  (`name: portcullis_<app>-…`).
  - → The template contract (portcullis-templates schema + validator +
    contract §3) needs per-router host variables.
  - → The Hub must namespace volumes per instance (compose override
    `volumes.<key>.name`).
- **group-gate keys policies, groups, path groups and public paths by
  subdomain only** (contract §4; the Hub rejects rules that aren't
  `<sub>.${PORTCULLIS_DOMAIN}`).
  - → Policy file **v5** keyed by **full hostname**, and the Hub's route
    parser accepts any enrolled domain.
  - Core hostnames stay protected by the map file (now full hostnames
    derived from the main domain).
- **lego reads one set of credentials per provider type.** Traefik's ACME
  client reads DNS credentials from process-wide env vars, so two Cloudflare
  accounts can't coexist in one Traefik; adding a resolver also needs a
  Traefik restart.
  - → Certificates for enrolled domains are obtained by a separate core
    service, not by Traefik's resolver (see Calls).
- **oauth2-proxy session cookies are per domain.** Cross-domain SSO uses the
  existing Keycloak session at `auth.<main>`. A forward-auth login on
  `<x>.team-a.com` redirects to Keycloak, the SSO session satisfies the
  requested acr, and Keycloak returns without a prompt.
  - oauth2-proxy needs the extra domain in its cookie domains and whitelist
    (redirect) domains. These change at runtime, so core must regenerate
    oauth2-proxy's config and restart it when domains change.
- **Hub rules still apply:**
  - prefer libraries;
  - fail closed;
  - Hub.mu is never held across network calls;
  - per-instance lock (today per-app);
  - no migration code (there are no installs — existing state is the
    default instance by construction, not a migration).

## Decided by the user

- Instances are fully separate.
- Hostnames: pick a name + domain, everything pre-filled, each editable.
- Extra domains and subdomains can be enrolled by **Hub admins from the
  browser**, token included.
- DNS provider token required for every enrolled domain (no HTTP fallback).
- Extra domains only carry what's assigned to them; core pages stay on the
  main domain.
- Hostnames of a running instance can be changed; old ones stop working.
- No extra key touch across domains (Midway-like), verified live.

## Calls made while drafting (check these)

1. **Certificates and records for enrolled domains: a new core service,
   `domains`.**
   - It holds the DNS tokens and runs ACME DNS-01 per domain with
     `github.com/go-acme/lego/v4` as a library, so each domain has its own
     credentials.
   - It creates the A/AAAA records with the `libdns` provider packages
     (`github.com/libdns/<provider>`).
   - It writes certs to a volume Traefik reads through its file provider
     (`tls.certificates`), and renews 30 days before expiry.
   - The Hub talks to it over an internal API with a shared secret, like the
     invite API. The Hub sends the token once; `domains` stores it encrypted
     at rest in its own volume, with the key under `secrets/`, so tokens are
     in backups only encrypted. Nothing else ever sees them.
   - Supported providers start with what core's `dns setup` supports
     (Cloudflare, Porkbun, Route 53, DigitalOcean, Hetzner); others later.
2. **Main domain unchanged.** It keeps Traefik's built-in resolver and core's
   `dns setup`. Only enrolled domains use the `domains` service.
3. **Instance id = DNS label, `^[a-z][a-z0-9-]{0,30}$`.** The default
   instance's id is the template id. New instances default to
   `<template>-<suffix>`. The id names the compose project
   (`portcullis-<instance>`), Keycloak client id, groups
   (`users_<instance>`, `admin_<instance>`), volumes
   (`portcullis_<instance>-<key>`) and state keys.
4. **Template contract v2.** The manifest gains `instances: multi|single`
   (default single until a template opts in).
   - Each router gets a variable `PORTCULLIS_HOST_<ROUTER>`, the full
     hostname the Hub assigns; templates use it in labels and env instead of
     `<sub>.${PORTCULLIS_DOMAIN}`.
   - The Hub sets these variables for every instance, default included, so
     single-instance templates can migrate gradually.
   - The validator enforces: no `${PORTCULLIS_DOMAIN}` in rules of
     multi-instance templates, and no hard-coded volume names (the Hub sets
     them).
   - All 22 templates get converted as part of this work (they're ours).
5. **Policy file v5.**
   - `policies`, `groups`, `path_groups` and `public_paths` are keyed by
     **full hostname**.
   - `expiring` is unchanged.
   - Core hostnames come from the map file as `<sub>` entries, expanded to
     `<sub>.<main domain>` by group-gate. A Hub entry for any core hostname
     is ignored, as today.
   - group-gate matches the request Host exactly (lowercased, without port).
6. **Hostname changes:**
   - collision check against all instances, core hostnames and enrolled
     domains;
   - regenerate env and override, update the Keycloak client redirect URIs,
     rewrite the published policy for the new hostnames, then restart;
   - everything is audited, and the old names vanish from the policy at
     once.
7. **oauth2-proxy config:** core regenerates its cookie/whitelist domain
   lists from the enrolled domains published by the Hub, and restarts
   oauth2-proxy when they change. Sessions on the main domain survive
   because the cookie secret is unchanged.
8. **UI:**
   - App Catalog cards show "Add instance" for multi-instance templates.
   - An app's detail shows its instances.
   - A new **Domains** section in Settings: enroll, status, replace token,
     remove when unused.

9. **Sign-in callback on extra domains (builder check).** oauth2-proxy uses a relative redirect URL (`/oauth2/callback`, resolved against the request host) and host-only cookies for extra domains. The Hub adds a `Host(<instance host>) && PathPrefix(/oauth2/)` router to oauth2-proxy for every instance hostname on an extra domain (Host-scoped, so it gets the domain's TLS options; core CI's "no host-less router" rule still holds; extra domains get no core pages). The forward-auth Keycloak client's redirect URIs include `https://*.<enrolled domain>/oauth2/callback`, maintained by the Hub. group-gate's step-up URL is built from the request host (`https://<host>/oauth2/start?…`) on extra domains. Result: no oauth2-proxy config change or restart when domains change; certificates arrive through Traefik's file provider (hot reload). The main domain keeps today's `auth.<main>` callback and `.<main>` cookie.
10. **Host ports across instances.** Templates with host ports (adguard, pihole, netbird) can be instantiated; each instance uses the existing per-port settings and port collision check, so a second instance must choose free ports (or disable them) before it can start.
11. **Instance backups.** The Hub archives an instance's volumes (helper container through its socket proxy, owner uid preserved, SQLite-safe where the template marks a DB file) plus its config (state, env, overrides, policy) into `<data>/backups/<instance>/<timestamp>.tar` (checksummed). Core's `portcullis backup` includes that directory, so `--offsite` ships instance backups too. Restore stops the instance, replaces its volumes and config from the archive, and starts it; restoring into a new id rewrites hostnames to the new instance's defaults and creates a new Keycloak client and groups.
12. **Testing.** CI: core gets a Pebble ACME server and a fake libdns provider for the `domains` service; the Hub gets unit tests with fakes; one e2e covers an instance on a second (Pebble) domain including the silent cross-domain sign-in. Live: a check on the test server with a real second domain or subdomain zone.

## Left to the builder

- `domains` service internals (renewal scheduling, backoff), the at-rest
  encryption choice (a mature library, e.g. age or NaCl secretbox), and
  logging (never the token).
- How the Hub renders the hostname editor, plus validation messages.
- Policy v5 field names, beyond "keyed by full hostname".
- Order of conversion of the 22 templates (the validator must pass for all).

## Open questions

- None known; the builder check may raise some.
