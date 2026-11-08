# People & groups: one place, group pages, person pages — design

Status: agreed in conversation 2026-11-08 (brainstorming, mockups approved); written for the plan.

## Why

The admin can't find how to add someone to a rule-based group by hand, and
finds the flow confusing: our own pages manage the same things in several
places that behave differently. The UI inventory
(`.superpowers/ui-inventory/inventory.md` in the Hub's main checkout,
screenshots next to it) found, among others:

- Users & Groups exists twice with the same admin powers: Hub → Users &
  Groups and people.<domain> (same `directory.js`).
- Group membership is edited in three places (person dialog, group card,
  invite dialog) that behave differently: only the group card sets end dates;
  the person and invite dialogs silently leave rule-based groups out; the same
  person shows "manual" in one place and "(leaving)" in another.
- The rule override exists (an "include" exception) but only at the bottom of
  an expanded rule-group card, called "exception".
- Adding someone directly to a rule-based group through the API / the AI's
  `add_member` answers ok and the evaluator silently removes them a minute
  later.
- "Who has access to an app" is shown in four places and changeable in one,
  with no links between them. Deleting a group silently purges every app's
  settings rows naming it.

## Goals

- **One place** for people and groups: people.<domain>. hub.<domain>'s
  "Users & Groups" tab becomes a link there (option 1: nothing moves into the
  people listener but what is already there; the people listener still never
  carries app / Docker routes).
- **Whatever you start from ends on the same view.** From a person ("give Alice
  access to Gitea"), from an app ("who's in Gitea") or from the group list, you
  land on the **group's page**, the only place membership is changed. (Option A.)
- Adding someone by hand to a rule-based group is just **Add**, shown as "added
  by hand"; taking a rule match out is **Keep out…**. No separate "exception"
  form.
- A **person's page** shows their groups (links to the group pages, with how
  they're in each), the apps they reach and through which group, and their
  per-app values.

## Non-goals

- The app side (default instance in the card vs extra instances in a window,
  hostnames / backups / delete only in the window, "Settings" meaning three
  things): a separate, later design.
- No change to what delegates may do, to the rule language, to the evaluator's
  timing, or to LLDAP / Keycloak behaviour.
- No merge of the Hub into people.<domain> (option 2 rejected: it would rest
  admin pages on one check instead of the gateway's `lldap_admin` gate plus the
  Hub's).

## Anti-goals

- A second membership editor anywhere (person page, invite, app settings, AI /
  file-sharing tabs). Everywhere else **links** to the group page.
- Rule-based groups silently missing from any picker.
- Weakening access control: admin-only actions stay admin-only on both
  listeners; the people listener gains no app routes.

## The pages (people.<domain>; admin view — mockups `people-pages.html`)

Top tabs: People · Groups · Org chart · My apps · Setup ⚙ (Fields, Permissions).

### Groups list

A table: group, kind (rule-based / manual / built-in), number of people, what it
gives access to (app links). Search, **New group**. Every row opens the group's
page. No expanding cards.

### A group's page

- Header: name; "Gives access to <app>" (link) or what it's used for; for a
  rule-based group the rule with **Edit rule…** and **Make manual**; for a
  manual group **Make rule-based…** (today's dialogs).
- **People**, each row a link to the person's page, with how they're in it:
  - rule-based group: "matches the rule" (action **Keep out…**: reason
    required, optional end), "added by hand · until <date> · "<reason>""
    (actions **Change end**, **Remove**), "kept out · "<reason>"" (action
    **Let back in**);
  - manual group: "member · until <date>" (actions **Change end**, **Remove**).
- **Add people**: pick one or more people, optional end date; on a rule-based
  group a reason is required (see the rules below for people who already
  match). The save waits for the evaluator's run (about a second), so the row
  shows its final state.
- **Used by** panel: the apps this group grants (access / admin group), every
  app setting row that names it (e.g. "Immich › storage quota: 50 GiB"), and
  delegated permissions it holds — each a link. **Delete group…** sits here,
  with the existing typed confirmation, and states what it will remove.

### History (on the group page)

The audit log already records all of it: who changed the rule (`group.rule`,
with the rule text), who added or kept out whom and why (`group.exception`:
user, added / kept out, reason, end), and every membership change the rule
made on its own (`group.sync`, actor "portcullis-hub (rules)", cause: rule,
exception, exception expired, membership expired, reverted outside change).
The group page gets a **History** section showing those entries for this
group, newest first, in plain words ("bob joined — matches the rule after
department changed", "carol changed the rule to …"); the person page shows the
same entries for that person. Admins only (as the audit log today).

### A person's page

Replaces today's person dialog (deep links `#users/<name>…` keep working).

- Header: display name, username, email; custom fields; **Edit details**.
- **Groups**: each a link to the group page, with how they're in it ("matches
  the rule", "added by hand until …", "member", "kept out"). **Add to group…**:
  pick a group → that group's page opens with this person already picked in Add
  people.
- **Apps**: apps they can reach and through which group (with an end date when
  the membership has one), each linking to the group.
- **Values**: their resolved value for each per-person setting of each app
  ("Immich · storage quota · 50 GiB · from office_milan"), linking to the app's
  setting.
- **Sign-in**: passkeys / invite status and today's actions (Send new invite,
  Require passkey, Reset passkeys…, Password…, Delete person…).

### Invite

Keeps a short "groups" pick (the moment you know where someone belongs). It
offers rule-based groups too, saved the same way as Add people (an "added by
hand" entry with a reason when the new person won't match).

## Other changes (folded in)

- **Audit log**: moves out of Users & Groups → Setup into its own tab on the
  Hub (it covers the whole Hub). Builder's call whether people.<domain> keeps a
  read-only copy for admins.
- **"Create missing groups"** in one place: the App Catalog banner. The second
  copy in the Groups tab goes.
- **Every place that names a group links to its page**: settings "Who gets
  what" (incl. the "N members of office_milan have no access" warning), an
  app's access / admin group (instance overview, card), the AI tab's and file
  sharing's "people with access" lines.
- **Backend gap closed**: adding someone directly to a rule-based group
  (`POST /api/directory/groups/{g}/members`, the AI's `add_member`) records an
  "added by hand" entry (include exception) instead of a membership the
  evaluator later removes; a reason is required (the API answers 400 without
  one — a caller that sends none gets a clear message). Setting an end date on a
  rule-group member sets the entry's end. Contract §9 changes first.
- **Delegates** keep exactly their powers; they see the same pages without the
  controls they can't use.

## Rules for "added by hand", "kept out" and end dates

An "added by hand" entry is today's include exception and "kept out" is
today's exclude exception (same records, same evaluator); the pages only name
them differently.

- **Add people on a rule-based group**: someone who doesn't match needs a
  reason and gets an "added by hand" entry. Someone who already matches can
  still be added by hand (reason required): the entry is stored and the row
  shows **"added by hand · also matches the rule"** with a warning that they
  keep access if they stop matching. The same flag shows whenever an existing
  hand-added person starts matching (rule or details changed). The form says
  who already matches as you pick (the rules preview the editor already
  uses).
- **End dates**: an "added by hand" entry's end is the entry's end; after it the
  rule decides alone (in if they match by then). A "kept out" entry may have an
  end; after it they're back in if they still match. A person who's in only
  because they match the rule gets no end date (to limit them, keep them out
  from a date with an end, or change the data the rule reads) — the page offers
  Keep out…, not Change end, on those rows.
- **No visible delay**: every directory change already re-runs the evaluator
  about a second later (`kick`, 1 s debounce; the one-minute tick is only the
  fallback). The page waits for that run after Add / Keep out / Remove /
  rule changes and shows the result, so the person appears (or goes) when the
  save finishes. Only if the run fails or LLDAP is down does the row show
  "saved, not applied yet: <why>"; it is the stored entry, so Remove / Change
  end work on it as on any other.
- **Invite**: the invite already takes details (custom fields). Rule-based
  groups in its groups pick are checked against the details entered: one the
  new person will match needs nothing; one they won't match needs a reason
  (an "added by hand" entry, stored with the new person).
- **What non-admins see**: as today. Delegates and other people see group
  members read-only, without the entries' reasons and without the Used by
  panel (reasons can be sensitive; Used by names permissions).
- **Existing direct adds** to rule groups: no migration (no installs to
  upgrade); the evaluator removes them as it does today.

## Constraints

- Contract first (`portcullis-docs/docs/guides/integration-contracts.md` §9;
  §15.10 for `add_member` / `add_exception` / `set_member_expiry` / MCP
  parity), then code; docs pages (`operations/groups.md`, `operations/hub.md`)
  and the Hub's `web/docs` copies in the same change.
- Frontend: vanilla JS, no build step, everything through `esc`/`escapeHtml`,
  data-* attributes + delegated listeners; shared `directory.js` stays the one
  implementation for both listeners.
- No migration / back-compat code. Deep links that exist today keep working.
- Fail closed; never weaken access control or a test.

## Left to the builder

- Routing inside people.<domain> (hash routes for group / person pages) and how
  the Hub's tab links there.
- Exact labels and layout within the approved mockups.
- How the person page gets per-app values (a new admin read on the Hub listener
  or the people listener's directory API — whichever keeps the people
  listener's route set rule: no app routes) and how "Used by" is computed.
- Whether the API change for direct adds is a new route or a changed one.

## Calls I made (check these)

- The **Used by** panel on the group page (deleting a group already removes its
  settings rows silently).
- The save waits for the evaluator's run (about a second) instead of showing
  "pending".
- The invite keeps a groups pick, including rule-based groups.
- Direct adds to a rule group become "added by hand" entries with a required
  reason (today they are silently undone).
- The audit log becomes a Hub tab.
- Adding someone who already matches stores the entry and flags "also
  matches the rule" (they keep access if they stop matching).
- No end dates on people who are in only because they match the rule.
- Invite checks rule groups against the details entered; non-matching ones
  need a reason.
- Non-admins don't see entry reasons or the Used by panel.
