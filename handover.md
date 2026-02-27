# Handover — 2026-02-27 (Session 6)

## 30-Second Summary

Session 6: (1) Documentation audit — updated all 5 .md files to match reality (endpoint counts, line counts, checked off completed items, converted PRINCIPLES.md from TypeScript to JavaScript), (2) VM disk crisis — disk was 100% full (74GB/75GB), freed 21GB by deleting video backup files + /tmp, (3) Hetzner VM upgrade — resized CPX22→CPX32 in-place (2 vCPU→4, 4GB→8GB RAM, 80GB→160GB disk, €7.13→€12.48/mo), (4) Backup gaps fixed — added dashboard + BannerForge SQLite backups, removed hardcoded Telegram token from backup script, (5) Revenue analysis — discovered all 3 Stripe keys point to same account, zero real paying customers yet, (6) **CRITICAL BUG FOUND: AbschlussCheck auto-refunds on large documents** — a real customer (Lea Kruschka) paid €19 for a 68-page thesis review, the AI analysis pipeline timed out, and the app auto-refunded her. Bug is NOT yet fixed.

**Most important thing for next session:** Fix the AbschlussCheck timeout bug in `/c/Users/kreyh/Projekte/abschlusscheck/`. This is a revenue-killing bug — every large document will auto-refund.

## Session Focus

1. Audit and update all documentation to match current reality
2. Fix VM disk space crisis (was 100% full)
3. Deep analysis of revenue and user traffic
4. Fix infrastructure gaps (backups, cron, cleanup)

## Completed

- [x] **Doc audit:** Updated PRINCIPLES.md (TypeScript→JavaScript code blocks, removed class-validator/NestJS references)
- [x] **Doc audit:** Updated README.md (endpoint count, features, keyboard shortcuts, known limitations)
- [x] **Doc audit:** Updated handover.md (endpoint listing, product readiness score)
- [x] **Doc audit:** Updated productization-plan.md (checked off completed Phase 0 items, updated next actions)
- [x] **Doc audit:** Updated product-strategy.md (status, competitor row, built features list)
- [x] **Endpoint count fix:** All docs now say 77 endpoints (verified by grep of `app.get/post/put/patch/delete`)
- [x] **PRINCIPLES.md stale refs:** Fixed "Use class-validator decorators" → "Use validation helpers at route boundaries"
- [x] **PRINCIPLES.md stale refs:** Fixed "Type annotations everywhere (TypeScript)" → "JSDoc annotations for non-obvious functions"
- [x] **VM disk cleanup:** Deleted 15 video `.backup_20260223/26` files (6GB), cleared /tmp (415MB)
- [x] **VM resize:** CPX22→CPX32 via Hetzner Console (2→4 CPU, 4→8GB RAM, 80→160GB disk)
- [x] **All 18 containers verified healthy** after resize
- [x] **Nginx verified running** after resize
- [x] **Dashboard backup added:** `/home/deploy/appmanager/scripts/backup-sqlite.sh` — backs up auth.db + data.db daily at 4:00 AM
- [x] **BannerForge backup added:** Same script, backs up bannerforge.db via `docker cp` daily at 4:10 AM
- [x] **Docker build cache prune** added to weekly cron (was accumulating ~1.6GB)
- [x] **Duplicate visit-watcher killed** (2 processes → 1)
- [x] **Hardcoded Telegram token removed** from backup-databases.sh (now sources .env)
- [x] **Dangling Docker volume removed** (saved ~13KB, minor)
- [x] **Revenue analysis complete:** All 3 Stripe keys = same account, $75 net (all self-test), 0 real customers
- [x] **Traffic analysis complete:** Only 3/13 sites have Plausible (theadhdmind.org, thecreativeprogrammer.dev, agorahoch3.org)
- [x] **AbschlussCheck bug root-caused** (see below)

## In Progress / Not Done

- [ ] **FIX AbschlussCheck timeout bug** — Root cause identified, source code read, fix NOT applied yet. See "Critical Bug" section below.
- [ ] **Install Plausible on all apps** — User requested this. Not started. Only 3/13 sites tracked.
- [ ] **Commit local changes** — 11 files modified (docs + code from sessions 4-6), not committed
- [ ] **Squash git history** — Secrets still in git history, must squash before making repo public
- [ ] **Rotate Telegram bot token** — Via @BotFather `/revoke`
- [ ] **Make repo public** — After squash + rotate
- [ ] **CONTRIBUTING.md** — Not started

## CRITICAL BUG: AbschlussCheck Auto-Refund on Large Documents

### What happened
- **Customer:** Lea Kruschka (lea.kruschka@gmail.com), bachelor thesis, 68 pages, €19
- **Date:** 2026-02-27 07:33 UTC
- **Result:** Auto-refunded 2 minutes after payment

### Root cause (verified in source code)
**File:** `/c/Users/kreyh/Projekte/abschlusscheck/app/api/webhook/route.ts` (lines 56-81)

The webhook triggers processing via an internal HTTP call with `AbortSignal.timeout(30000)` (30 seconds). A 68-page document takes ~97 seconds to analyze. The trigger times out, retries 3 times (each spawning a NEW parallel pipeline), all pipelines eventually fail because chunks are being processed by multiple workers, then the catch block in `app/api/process/route.ts` (line 130-138) auto-refunds.

### Two bugs:
1. **`AbortSignal.timeout(30000)` is too short** (webhook/route.ts line 68) — 30s is not enough for large documents. The processing itself works (logs show progress 5/14, 10/14, 14/14) but the trigger call gives up.
2. **Race condition** — Failed trigger retries fire `triggerProcessing()` which spawns parallel pipeline instances. No mutex/lock prevents duplicate processing of the same review.

### Fix needed (in abschlusscheck repo, NOT appManager):
1. **Increase timeout** to 300000 (5 min) or remove timeout entirely and make it fire-and-forget
2. **Add idempotency to process route** — Check if review is already `processing` status before starting pipeline
3. **Test with a large PDF** (60+ pages) to verify

### Key files:
- `/c/Users/kreyh/Projekte/abschlusscheck/app/api/webhook/route.ts` — Stripe webhook, triggers processing
- `/c/Users/kreyh/Projekte/abschlusscheck/app/api/process/route.ts` — AI analysis pipeline, auto-refund on failure
- `/c/Users/kreyh/Projekte/abschlusscheck/lib/claude.ts` — `runAnalysisPipeline()` function
- `/c/Users/kreyh/Projekte/abschlusscheck/lib/stripe.ts` — Stripe client

### Relevant logs:
```
[49b947c2] Starting analysis pipeline
[49b947c2] PDF chunked: 68 pages, 14 chunks
[49b947c2] Processing trigger attempt 1 error: Error [TimeoutError]: The operation was aborted due to timeout
[49b947c2] Processing trigger attempt 2 error: Error [TimeoutError]: The operation was aborted due to timeout
[49b947c2] Processing trigger attempt 3 error: Error [TimeoutError]: The operation was aborted due to timeout
[49b947c2] Pipeline FAILED: Error: Alle 14 Chunks fehlgeschlagen. Analyse abgebrochen.
[49b947c2] Auto-refund issued for pi_3T5LY7RJyY7UPueJ0n2ekFsT
```

## Decisions Made

| Decision | Why | Alternatives Considered |
|----------|-----|------------------------|
| Resize VM in-place (CPX22→CPX32) | 100% disk, doubled everything for €5.35/mo more | Migrate to new VM (unnecessary work), delete content (risky) |
| Delete video .backup_ files | 6GB of dated duplicates, originals exist alongside | Keep them (disk was full) |
| Add backup-sqlite.sh as new script | Dashboard + BannerForge use SQLite, not Postgres | Extend backup-databases.sh (different backup method needed) |
| Source .env in backup cron | Telegram token was hardcoded as fallback | Keep fallback (security risk in git) |
| Skip Headshot AI backup | No database found — uses external API only | Add it anyway (nothing to back up) |

## Known Issues

1. **AbschlussCheck timeout bug** — Auto-refunds large documents. Revenue-killing. See critical bug section.
2. **All 3 Stripe keys = same account** — PromoForge, Headshot AI, AbschlussCheck all use `acct_1SWLDMRJyY7UPueJ`. Revenue can't be tracked per-app.
3. **Plausible only tracks 3/13 sites** — theadhdmind.org, thecreativeprogrammer.dev, agorahoch3.org. All SaaS apps are untracked.
4. **Plausible API key may be invalid** — Queries return 401. Key `RPhS4ua3eo...` (dashboard-v2, id=6) doesn't work via localhost:8000.
5. **Git history has secrets** — Must squash before public launch.
6. **fail2ban bans Claude** — Too many rapid SSH connections trigger ban. Space out SSH calls or add deploy user to fail2ban whitelist.
7. **Headshot AI webhook receives AbschlussCheck payments** — Same Stripe account, webhooks go to all endpoints. Headshot AI logs `webhook.metadata_missing` but silently discards (no harm, just noise).
8. **PromoForge Docker images are 25GB** — worker=17.7GB, api=7.5GB. Absurdly large. Not blocking but wastes disk.

## Next Steps (Priority Order)

1. **FIX AbschlussCheck timeout bug** — In `/c/Users/kreyh/Projekte/abschlusscheck/`. Change `AbortSignal.timeout(30000)` to `300000` in webhook/route.ts line 68. Add processing lock in process/route.ts. Build, deploy, test with large PDF.
2. **Install Plausible on all 13 sites** — User explicitly requested this. Add Plausible script tag to all apps. Need to create sites in Plausible first, then add snippet to each app's HTML.
3. **Commit all local appManager changes** — 11 files, ~2000 lines changed (sessions 4-6: banners, playbooks, toast, cross-promo, doc updates)
4. **Squash git history** — `git checkout --orphan clean-main && git add -A && git commit -m "Initial release" && git branch -D master && git branch -m master && git push --force`
5. **Rotate Telegram bot token** — Via @BotFather `/revoke`, update .env on server
6. **Make repo public** — After steps 3-5
7. **Fix Plausible API key** — Generate new key in Plausible admin, update .env

## Rollback Info

- **VM resize:** Cannot downsize disk (CPU/RAM can be downsized). This is permanent.
- **Backup script:** `/home/deploy/appmanager/scripts/backup-sqlite.sh` — can remove cron entries if issues
- **Last committed appManager:** `532d1a1` (Dockerfile, CI, AGPL, secret cleanup)
- **Rollback appManager code:** `git checkout 532d1a1 -- dashboard/server.js dashboard/public/index.html`
- **Note:** server.js is baked into Docker image — rollback requires `docker compose build dashboard && docker compose up -d dashboard`

## Files Modified This Session (appManager repo)

| File | What Changed |
|------|-------------|
| `PRINCIPLES.md` | TypeScript→JavaScript code blocks (14 blocks), removed class-validator/NestJS references, added reality check note, updated date |
| `README.md` | Endpoint count 56→77, added cross-promo/banners/playbook features, added BannerForge integration, added 4 keyboard shortcuts, added Known Limitations section, added private repo note |
| `handover.md` | This file — full rewrite for session 6 |
| `plans/productization-plan.md` | Checked off 15 completed items, fixed package names, updated next actions, endpoint count fix |
| `plans/product-strategy.md` | Status updated, competitor row fixed, added 5 built features, checked off auth/discovery, line counts updated |
| `dashboard/config.yml` | (from session 5, not this session) |
| `dashboard/public/index.html` | (from session 5, not this session) |
| `dashboard/server.js` | (from session 5, not this session) |
| `nginx-appmanager.conf` | (from session 5, not this session) |

## Files Modified on VM (not in git)

| File | What Changed |
|------|-------------|
| `/home/deploy/appmanager/scripts/backup-sqlite.sh` | **NEW** — SQLite backup script for dashboard + BannerForge |
| `/home/deploy/appmanager/scripts/backup-databases.sh` | Removed hardcoded Telegram token fallback |
| `crontab (deploy)` | Added: dashboard backup 4AM, BannerForge backup 4:10AM, builder prune in weekly cron, .env sourcing for backup-databases.sh |
| `/home/deploy/backups/dashboard/` | **NEW** — dashboard backup directory with auth.db + data.db backups |
| `/home/deploy/backups/bannerforge/` | **NEW** — BannerForge backup directory |
| `/var/www/logos/videos/*.backup_*` | **DELETED** — 15 video backup files (6GB freed) |
| `/tmp/showcase-videos/` etc. | **DELETED** — stale deploy artifacts (415MB freed) |

## VM State After This Session

- **Server:** CPX32, 4 vCPU, 8GB RAM, 160GB disk
- **Disk:** 52GB used / 150GB available (37%)
- **Containers:** 18/18 running + healthy
- **IP:** 91.99.104.132 (unchanged)
- **Cost:** €12.48/mo (was €7.13)

## Backup Schedule (Complete)

```
3:00 AM  — PromoForge (Postgres)
3:15 AM  — LohnCheck (Postgres)
3:30 AM  — SacredLens (Postgres)
3:45 AM  — Plausible PG + ClickHouse
4:00 AM  — Dashboard (SQLite: auth.db + data.db)
4:10 AM  — BannerForge (SQLite via docker cp)
3:00 AM  — AbschlussCheck (SQLite, root crontab)
Sunday 4AM — Docker system prune + builder prune
```

## Revenue Reality Check

- **Stripe account:** Single account `acct_1SWLDMRJyY7UPueJ` (kreyhe12@gmail.com)
- **All-time gross:** €315 (13 charges)
- **All-time refunded:** €240 (10 charges — 9 self-tests + 1 bug-caused)
- **Net retained:** $75 (3 self-test charges)
- **Active subscriptions:** 1 × $19/mo (likely self-test)
- **Real customers:** 1 (Lea Kruschka) — auto-refunded due to bug
- **Available balance:** €55.08

## Traffic Reality Check

- **Plausible tracked (30d):** theadhdmind.org (49 visitors), creativeprogrammer.dev (49 visitors), agorahoch3.org (21 visitors)
- **Untracked SaaS apps:** PromoForge, BannerForge, Headshot AI, AbschlussCheck, LohnCheck, SacredLens
- **Telegram visit-watcher confirms:** AbschlussCheck, LohnCheck, TheADHDMind have real organic users
- **Plausible sites configured:** Only 3 sites in Plausible DB (theadhdmind.org, thecreativeprogrammer.dev, agorahoch3.org)

## Quick Links

- **Dashboard:** https://admin.crelvo.dev (nginx basic auth + session auth)
- **GitHub:** https://github.com/Crelvo/appManager (private)
- **AbschlussCheck source:** `/c/Users/kreyh/Projekte/abschlusscheck/`
- **Plans:** `plans/productization-plan.md`, `plans/product-strategy.md`
- **Principles:** `PRINCIPLES.md`
- **Memory:** `.claude/projects/.../memory/MEMORY.md`

## Key Files Reference

- `dashboard/server.js` (3,852 lines) — Express API, 77 endpoints, 14 SQLite tables
- `dashboard/public/index.html` (3,457 lines) — Vanilla JS SPA, 9 marketing tabs, 17 keyboard shortcuts
- `dashboard/config.yml` — 13 apps with domains, containers, marketing metadata
- `scripts/backup-sqlite.sh` — NEW this session, backs up SQLite DBs
- `scripts/backup-databases.sh` — Postgres backup script (token hardcode removed)
