# App updates: template auto-merge, Hub-managed upgrades, migrations

Status: draft for approval (2026-11-02)

## Intent

Keep apps current with little effort and without breaking anyone's data:

- the templates repo updates itself when tests pass, and opens an issue when
  they don't;
- running app instances get minor and major updates, automatically or on an
  admin's click, per instance;
- hard upgrades (a Postgres major, Elasticsearch, …) are handled by
  Portcullis-provided migrations, or are clearly blocked until one exists.

## Goals

1. **Templates name tags, the Hub pins digests.**
   - Templates reference images by tag (e.g. `postgres:18`, `grafana/grafana:13`)
     instead of `tag@sha256`.
   - The Hub resolves a tag to a digest when an instance is installed or
     updated, records it per instance and service, and always starts that
     recorded digest. The UI shows it.
   - Reproducible, auditable, no "whatever the tag is today" at start.
2. **Two kinds of update.**
   - **Minor:** the same tag has a newer digest.
   - **Major:** the template's tag for a service changed (e.g. `postgres:18`
     → `postgres:19`), with the upgrade path the template declares.
3. **Detection.** The Hub checks the registries for every instance's tags
   periodically (daily, and on demand) and on template syncs. It shows
   "update available" (minor or major) per instance, with what changes:
   service, from → to tag and digest, and the upgrade method.
4. **Per-instance update channel** (decided by the user):
   1. **immediate**: the newest digest of the instance's tag as soon as the
      registry has it. No CI gate.
   2. **tested minor**: only digests CI has tested, within the latest major.
      CI tests only the latest major, so an instance on an older major gets
      no minor updates until it moves to the latest major.
   3. **tested major**: like 2, plus moving to a new major once CI has
      tested that major and its upgrade path.

   For channels 2 and 3, each green templates CI run publishes a
   tested-digest list, per template revision, per service, with tag and
   digest. The Hub installs only digests on that list.

   Combined with the **update mode** below: on manual, the Hub shows
   "update available" within the chosen channel.
4b. **Per-instance update mode** (admins, audited). One of:
   - **manual:** the admin clicks Update;
   - **automatic minor**;
   - **automatic minor + major**.

   Default: automatic minor, manual major.
   - Automatic updates run in a maintenance window (default 03:00–05:00
     server time, configurable in Hub Settings).
5. **Upgrade paths declared by the template.** For each service whose
   tag changes, the manifest declares how to get from the previous major:
   - `auto`: the image upgrades itself on start (MySQL/MariaDB with
     auto-upgrade): pull and recreate;
   - `migration: <name>`: a Portcullis-provided migration (first:
     `postgres-major`);
   - `unsupported`: no workaround yet. The Hub shows the major as
     **blocked** with the reason. The instance stays on its current major,
     still gets minor updates within it, and nothing breaks.
6. **Safe execution.** Every update, minor or major, follows the same steps:
   1. instance backup (the instance-backup machinery from the instances
      plan);
   2. pull;
   3. migration if declared;
   4. recreate;
   5. health check (the template's healthchecks, plus Task 2c's sign-in
      check where it can run headless — see Calls).

   On failure the Hub restores the backup, restarts on the previous
   digests, marks the update as failed with the output (the last-operation
   record), and turns automatic updates off for that instance until an admin
   looks at it.
7. **Templates repo automation.**
   - Dependabot (or Renovate, see Calls) proposes tag/major bumps.
   - CI runs the full per-app tests (Task 2c) plus, for a major with a
     declared path, an **upgrade test**: start the old major with seeded
     data, apply the path, verify the data and the sign-in.
   - All green → the bump is merged into `main` automatically.
   - Any failure → an issue is opened (or updated) with the app, the version
     jump, the failing step and links to the run's screenshots/traces; the
     PR stays open.
   - A major whose path is `unsupported` is never auto-merged.
   - A scheduled job also re-runs every app's tests weekly against the
     newest digest of each tag, so a broken upstream minor surfaces as an
     issue before instances pick it up.

## Non-goals

- Downgrades beyond restoring the pre-update backup.
- Writing migrations for every database now: only `postgres-major` ships
  first; others start as `unsupported`.
- Updating core services through this mechanism (core keeps
  `./portcullis upgrade`).

## Anti-goals

- An update that loses data. Backups come first, always; failure → restore.
- Silent major jumps. Majors are visible, declared, and (when automatic)
  opted into per instance.
- Unpinned starts. A container never starts from a tag without a recorded
  digest.

## Decided by the user

- Per-instance opt-in: manual, automatic minor, automatic minor + major.
- Minor = latest image of the same tag; major = new tag from the template.
- Templates say e.g. `postgres:18` and Portcullis manages upgrades.
- The template declares whether an upgrade is clean, needs a Portcullis
  workaround, or has none yet.
- The Hub detects new digests and offers the update when automatic minor is
  off.
- Templates repo: periodic updates, auto-merge when all tests pass, an issue
  when they don't.

## Calls made while drafting (check these)

1. **Registry access from the Hub:** `github.com/google/go-containerregistry`,
   anonymous pulls by default, with optional registry credentials stored like
   other Hub secrets.
   - Digest resolution doesn't go through the Docker socket proxy (no
     distribution endpoint needed).
   - Pulls still go through the Engine API.
2. **Supply-chain policy change.** Templates no longer pin digests, and the
   validator enforces tag-only images with an explicit major (e.g. `:18`,
   not `:latest`). The Hub's recorded digests become the pin.
   - Core images stay digest-pinned (core isn't Hub-managed).
   - The templates' Dependabot config moves to tracking tags.
   - Renovate is preferred if Dependabot can't propose major tag bumps for
     compose tags without digests. The builder decides after a quick check
     and documents it.
3. **Manifest `upgrades` block:**
   ```yaml
   upgrades:
     db:                        # compose service
       from: "17"               # previous major the path starts from
       method: migration        # auto | migration | unsupported
       migration: postgres-major
       reason: ""               # required for unsupported
   ```
   - Multi-step jumps (16 → 18) chain declared single-step paths.
   - A missing step = unsupported.
4. **Migrations live in the Hub** (`internal/migrations/<name>`), run as
   helper containers through the socket proxy with the instance's volumes:
   - `postgres-major` does a `pg_dumpall` from the old major into the new
     major's fresh volume and swaps volumes atomically. The old volume is
     kept until the next successful backup;
   - each migration has an integration test in CI.
5. **Health check after update:**
   - the compose healthchecks must turn healthy within the template's
     timeout;
   - for apps with `tests.signin`, the Hub checks the main host answers
     through the gateway (no browser in the Hub) — the browser sign-in check
     stays in CI.
6. **Auto-merge on main.** The user works on `main` without PRs, but bot
   PRs are fine. A workflow merges green Dependabot/Renovate PRs (`gh pr
   merge --squash --auto`) and opens or updates an issue per app and jump on
   red, using a label `update-failed`.

7. **Builder-check rulings.**
   - **Instances pin a template revision**, not only digests. A copy of the
     template per revision is kept by the Hub; "update" also moves the
     instance to the new revision. Instances blocked on a major keep running
     their own revision's compose and scripts.
   - **The tag to track is declared per service in the manifest**
     (`track: {tag: "18", major: "^(\\d+)"}` or `track: exact`). With
     `exact`, every bump is a major for that service, with no minor
     updates; such majors default to `auto` when the service has no state
     volumes.
   - **Pre-update backups cover state volumes (DB, config) and the instance
     config.** Templates mark big media volumes `backup: bulk` (excluded
     from update backups, still in full backups). Not enough disk → the
     update is skipped with the reason.
   - **Required intermediate versions:** `upgrades.<service>.steps` lists
     each hop with its tag (e.g. GitLab upgrade stops, Nextcloud one major
     at a time). The Hub runs each hop with health checks in between; a
     missing hop = unsupported.
   - **Auto-merge without branch protection:** a `workflow_run`-triggered
     job checks the results of the test workflows itself, then merges the
     bot PR (no secrets exposed to Dependabot runs) or opens/updates the
     `update-failed` issue.
   - **Missing `upgrades` entry:** `auto` for services without state
     volumes; services with state volumes must declare a path (CI fails the
     bump otherwise, and an issue is opened).

8. **User correction (supersedes Goal 1, Goal 4's tested-digest list and Call 2).** Templates **keep `tag@sha256`**. Bot updates (digest bumps = minor, tag bumps = major) reach templates `main` only when every test is green, so **every template revision on `main` is CI-tested**: the template's digest *is* the tested digest, and there is no separate tested-digest list.
   - Channel **immediate**: the Hub ignores the template's digest and resolves the newest digest for the tag (recorded per instance).
   - Channel **tested minor**: the Hub follows the template's digest within the instance's current major.
   - Channel **tested major**: also follows the template's tag (major) bumps with their declared upgrade paths.
   - Instances on an older major get no minor updates (the template carries only the latest major's digest) — the caveat the user accepted.
   - The validator keeps requiring `tag@sha256`; the Hub's per-instance record still pins what each instance actually runs (relevant for channel immediate).

## Left to the builder

- Scheduler details, registry rate-limit handling and caching, UI layout,
  issue text template, and how many old digests to keep per instance for
  rollback.

## Open questions

- None known; the builder check may raise some.
