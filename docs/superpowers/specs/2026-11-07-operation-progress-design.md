# Operation progress and Stop — design

Status: approved in conversation 2026-11-07 (brainstorming); written for the plan.

## Why

Enabling an app shows only "Enabling…". The admin can't tell whether it is
downloading, starting or stuck, is tempted to refresh and retry, and after a
refresh the page shows the app as not enabled with a normal Enable button
(the operation keeps running on the server; a second click answers 409
"another operation … is in progress"). Nothing can be stopped.

## Goals

- Every long app operation shows a **step-by-step list**: each step ticks off
  when done, the running step shows a **percentage** wherever there is
  something to measure, and finished steps show how long they took.
- The progress survives a page refresh, a second tab and a second admin:
  anyone opening the app sees the running operation, who started it and when.
- Every operation has a **Stop** button that puts things back as they were
  before the operation (per-operation rules below).
- The same progress is available to the Portcullis MCP (`get_op`,
  `wait_for_op`) and a Stop tool.

## Non-goals

- No progress for Hub-wide jobs (source sync, doctor scans) in this change.
- No pause/resume. Stop is final.
- No new storage engine: progress lives in the existing per-instance op
  record (`<data>/ops/<id>.json`).

## Operations covered

Enable, disable, restart, AI support on/off and mode change for a companion,
back up, restore (same instance), restore into a new instance, create
instance, delete instance.

## The panel (UI, option B)

- Clicking the operation's button opens a **progress panel** (dialog). It can
  be closed at any time ("you can close this, it keeps going") and reopened
  from the app's card, which shows "Enabling… show progress" while the
  operation runs. Opening an app whose operation is running shows the same.
- Header: "Enabling Gitea", "Started by <user> at <time>".
- Steps: ✓ done (with duration), ◐ running (percentage + bar + one detail line,
  e.g. per image "gitea/gitea:1.25 — 312 of 690 MB"), ○ waiting, ■ stopped,
  ✗ failed (with the existing error text and hint).
- Buttons: **Stop** (confirm: "Stop enabling Gitea and undo what it did?")
  and Close.
- While stopping: the undo steps, ticking off. Final state: "Gitea was not
  enabled · everything is back as before" (or the operation's equivalent),
  "Stopped by <user> at <time>".
- Vanilla JS in `web/index.html` per the Hub's frontend rules; every value
  escaped; poll the op record (the existing `runInstanceOp` pattern), no
  websockets.

### Enable steps (example)

1. Groups (`users_<id>`, `admin_<id>`) — "created" or "already exist"
2. Sign-in client in Keycloak
3. Downloading images — % from the pull's byte counts, per-image detail
4. Starting services (n of m)
5. Waiting until healthy (n of m)
6. Applying settings (start hooks, data files)

Other operations get their own step lists from their existing phases (backup:
stopping the app, copying each volume with %, writing the archive, starting
the app; restore: verifying the archive with %, pre-restore backup, replacing
volumes with %, starting; delete: backup, stopping, removing volumes,
Keycloak, groups, files).

## Stop semantics (agreed)

| Operation | Stop does | Stop unavailable |
|---|---|---|
| Enable | Undo everything this enable did: containers removed; volumes this enable created removed (pre-existing volumes kept); the Keycloak client and groups deleted **only if this enable created them**; downloaded images kept | never |
| Restart | The app back running as before | never |
| AI on/off / mode | The switch back as it was, with its credentials, scopes and clients | never |
| Back up | The partial archive deleted; the app restarted if it was running | never |
| Restore | Rolled back from the pre-restore backup (today's failure path) | never |
| Create / restore into a new id | The new instance removed completely | never |
| Delete | The delete cancelled, the app back as before | once data removal starts: the panel shows "past the point of no return — finishing" |
| Disable | The app turned back on | never |

- Stop is available at every step until the operation ends, including the
  last one (an app that already started is taken down and undone).
- Stop is audited (`<op>.stop`: who, which op, at which step) like every
  lifecycle action, with `via`/`client` when it comes from the AI.
- An operation interrupted by a Hub restart shows "interrupted" with Stop to
  clean it up (today such records are only marked interrupted).
- The undo itself reports progress and can fail; a failed undo is shown with
  what is left and is retried by pressing Stop again.

## Groups (folded in)

- Enable already creates the instance's missing derived groups
  (`users_<id>` / `admin_<id>`); each instance has its own groups.
- Firefly III's template names its groups `users_firefly` / `admin_firefly`
  (not derived from `firefly-iii`), so they are only warned about. **Builder's
  call (mine):** rename them in the template to `users_firefly-iii` /
  `admin_firefly-iii` so they follow the rule and are created automatically
  (no installs to migrate).
- The groups step in the panel says which groups were created and which
  already existed.

## Interfaces (for the plan)

- Op record gains `steps: [{key, label, state, percent?, detail?, started_at,
  ended_at}]`, `started_by`, `stopped_by`, `stoppable`, `point_of_no_return`.
  Contract §11.4–11.6 (op record) and §15.11 change docs-first.
- `POST /api/instances/{id}/op/stop` (admins, Hub listener, CSRF guard),
  answers the op record; `409` when nothing is running or past the point of
  no return.
- Enable, disable, restart and AI switches become asynchronous like backups
  (202 + poll); the synchronous Hub methods stay for tests and MCP.
- Image pull progress: compose `--progress json` (check the pinned compose
  version) or the Engine API pull stream; byte counts summed per image.
- MCP: `get_op` / `wait_for_op` return the steps; new `stop_op` tool (class
  W — it only reverses; the delete point of no return still applies) with its
  HTTP twin for parity.

## Left to the builder

- How each operation reports its steps (a small progress reporter passed down
  the existing call paths).
- How cancellation reaches compose / Engine calls (context cancellation; the
  compose CLI killed and the project rolled back).
- Exact step labels per operation, following the examples above.
- e2e: a CI scenario that starts an enable, stops it mid-pull and checks
  nothing is left (groups, client, containers, new volumes).

## Calls I made (check these)

- **What "this enable created" means:** each creating step records what it
  made in the op record (`created: {volumes, keycloak_clients, groups}`),
  written as it happens; Stop undoes exactly that list. Nothing is inferred
  at Stop time.
- **Delete's point of no return** is the first volume removal. The backup and
  stopping steps can still be stopped (the app is started again).
- **One code path:** the synchronous Hub methods and the async routes share
  the lock and the op record, so a test, the MCP and the UI all see the same
  running operation.
- **Image download progress** comes from the Engine API pull stream: the
  Hub pulls each pinned image itself before `compose up --no-start` (which
  then finds them present); byte counts are summed per image.
- **Undo steps are idempotent** and recorded as they finish; pressing Stop
  again after a failed undo skips the steps already done.
- **Interrupted operations:** steps and the `created` list are persisted as
  they change, so Stop on an interrupted operation undoes from the record.

- Volumes created by the stopped enable are deleted; pre-existing ones kept.
- Firefly III groups renamed to the derived names.
- `stop_op` is class W for the AI (reversal only).
- Interrupted operations get Stop as cleanup.
