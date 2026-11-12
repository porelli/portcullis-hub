# Polish batch 1 — logo, security-key names, part 3 follow-ups (design)

Status: decided by the assistant under the user's goal "complete all the items in the queue still open" (no interruptions). Every decision below is the assistant's call unless marked as the user's.

## 1. Logo and favicon (user chose concept 1 "Raised gate", 2026-11-12)
- Source: `/Volumes/workspace/portcullis/branding/` (not a repo): `concept-1-mark.svg`, `concept-1-mark-dark.svg`, `favicon.svg` (has a prefers-color-scheme dark variant), `favicon.ico` (16/32/48), `apple-touch-icon.png` (180), `icon-192.png`, `icon-512.png`, `maskable-512.png`, `site.webmanifest` (example). Colours: iron `#1c2738`, brass `#c48a2c` (light), mist `#e8edf5`, lantern `#e3ac52` (dark).
- The wordmark is live text ("Portcullis") in the existing UI font stack, never the outlined lockup (it was made from Avenir Next, a commercial font): no font files are added anywhere.
- Where: (a) the Hub — both listeners' pages (hub.<d>, people.<d>: favicon set + webmanifest + the mark in each page's header next to the existing title); `handleStatic` gains content types `.svg` image/svg+xml, `.png` image/png, `.ico` image/x-icon, `.webmanifest` application/manifest+json (nosniff stays); the people listener's `peopleStatic` allowlist gains exactly the icon files. (b) Keycloak's login theme `portcullis` in core (`keycloak/themes/portcullis`): favicon + the mark above the login card. (c) group-gate's own pages (portal, sign-in pages, ended/deny pages): an inline `data:` SVG favicon and the mark inline in the header (group-gate serves no static files; CSP-compatible: no external loads). (d) the docs site (zensical config: logo + favicon).
- One copy of each asset per repo; a test in each repo pins the copy's sha256 to the branding source (recorded in the test, not read from outside the repo).

## 2. Sign-in page: method names, key models, rename
- Section headings on the Sign-in page and the person's Sign-in tab: "Security key", "Device-bound passkey", "Synced passkey", "YubiKey certificate", "Browser certificate", "Password" (replacing "Security key passkey (YubiKey touch)" etc.; one table of names shared by both views).
- Each passkey row: its name = Keycloak's credential `userLabel` (the same field the account console edits and our registration JS sets as "Security key <date time>"); its model = the FIDO MDS v3 entry for its AAGUID (`description`), display only and never stored ("unknown model" when the AAGUID is zero or not in the list); "added <date>".
- Rename (user ruling: Keycloak's `userLabel`, never a Portcullis-side name): `PUT /api/me/signin/passkeys/{credentialId}/label` `{"label": "…"}` on the people listener (CSRF; the caller's own credential only — another person's id is 404; 1–64 runes after trimming, one line, no control or bidi characters; unique among the caller's credentials case-insensitively, else 409, because Keycloak rejects duplicate labels). The Hub calls Keycloak's `PUT /admin/realms/{r}/users/{id}/credentials/{credentialId}/userLabel` (text/plain). Refused while impersonated (the existing read-only rule). Audited `signin.passkey.label` (old → new label). MCP: follow the Hub's parity rule (a people tool `rename_my_passkey`, or a parity exemption with a reason if the rule allows — the plan decides from the parity test).
- The person's Sign-in tab (admins, sign_in_help holders) shows name + model read-only.

## 3. Part 3 follow-ups
- Flaky Hub tests `TestStopInterruptedEnable` (stop_test.go, "lock still held") and `TestStopResumeConcurrent` ("another operation on other is in progress"): find the race (op-stop lock release vs the test's next call) and fix it in the code if it's a real race, else in the test; prove with `-race -count=50`.
- group-gate step-up returns to the requested page: `rd` = the original request's `https://<host><path>?<query>` (same host only — never another host; path+query ≤ 2048 bytes, else the host root; never for non-GET), for both the main and extra-domain step-ups. Check oauth2-proxy's whitelist accepts it (it does for the main domain's hosts; extra domains use relative `rd=/…`). Contract §5 + tests.
- While impersonated, the person's own Sign-in page hides Set / Create / + Add / Remove / Revoke buttons (the Hub refuses them anyway); a line says "Changes are off while <admin> is signed in as you."
- Keycloak smoke: token introspection of an impersonated access token carries `act` and `pc_imp`, and `exp` ≤ until.

## Non-goals
No back-compat code (user rule). No new dependencies unless a mature library replaces hand-rolled code.
