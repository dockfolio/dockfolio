# Handover — 2026-02-27 (Session 12)

## 30-Second Summary

Session 12: Built **Projects Manager** (lifecycle, tasks, kanban roadmap, AI insights — fully deployed and tested). Built **Ops Intelligence** backend + frontend (worry score, heartbeat, report cards, drift detection, dependency map, ADHD mode) — code complete but **NOT YET DEPLOYED**. Updated **dockfolio.dev** landing page with Security + Projects features. Added Dockfolio itself to config.yml (15 apps now). Deep investigation found: Stripe webhook cross-contamination (HeadshotAI receiving AbschlussCheck events), 5/6 apps missing Sentry DSN, disk jumped 37%→58%.

**Most important thing for next session:** Fix the Stripe webhook cross-contamination (HeadshotAI receiving AbschlussCheck events). Enable Sentry DSN on PromoForge + AbschlussCheck. Post launches.

## Session Focus

1. Verify Security Manager works (full fleet audit — passed)
2. Build Projects Manager (done, deployed, tested)
3. Build Ops Intelligence (done in code, NOT deployed)
4. Update dockfolio.dev landing page (done, live)
5. Deep security/app investigation

## Completed

- [x] Force pushed to dockfolio/dockfolio remote (master → main)
- [x] Full Security Manager fleet verification (93/100, all scanners match ground truth)
- [x] **Projects Manager** — 5 tables, 16 endpoints, 4 crons, 4-tab frontend (deployed + tested)
- [x] Imported 4 handover carry-forward items as project tasks
- [x] AI insights working via Claude Haiku (~$0.001/call)
- [x] Added Dockfolio to config.yml (15 apps total now)
- [x] Updated dockfolio.dev landing page: +Security Auditing, +Projects Manager, stats 93/19/13/17
- [x] Deep investigation: expired Stripe key root cause (22h gap between .env update and container restart)
- [x] Deep investigation: all 6 non-static apps audited for errors, Sentry, keys, logs
- [x] **Ops Intelligence backend** — 3 tables, 5 core functions, 10 endpoints, 3 crons, briefing integration, command palette
- [x] **Ops Intelligence frontend** — CSS (~70 rules), HTML panel (4 tabs), JS (~15 functions), keyboard shortcuts (o, Shift+A)

## Deployed & Verified This Session

- [x] **Ops Intelligence deployed** — `bash deploy.sh --rebuild` — all 10 endpoints tested
- [x] **First baseline created** — 18 containers, 6 apps with env hashes, 40% disk
- [x] **Worry Score: 0/100** — all green, 15 apps, 5 shared keys detected
- [x] **Report Cards**: Plausible F(57), PromoForge C(73), statics A(90)
- [x] **Committed as `58c7a3c`** — pushed to dockfolio/dockfolio main
- [x] **Disk reclaimed** — 4.2GB build cache freed, disk 58%→38%

## Not Done — Carry Forward

- [ ] **Fix Stripe webhook cross-contamination** — HeadshotAI receives AbschlussCheck payment webhooks (same Stripe account, shared webhook endpoint). Real customer `lea.kruschka@gmail.com` affected. Fix in Stripe dashboard: filter webhook events per endpoint.
- [ ] **Enable Sentry on all apps** — PromoForge + AbschlussCheck have SDK installed but no SENTRY_DSN in .env. Add DSN to their .env files. BannerForge/HeadshotAI/LohnCheck need SDK installed too.
- [x] ~~Reclaim disk space~~ — Done, 38% now
- [ ] **Fix BannerForge fontconfig** — Missing fontconfig in Docker image, affects font rendering.
- [ ] **Increase ClickHouse memory** — Plausible events DB at 68% of 512MB cap.
- [ ] **Post Show HN** — content in LAUNCH.md, best timing Tue-Thu 9-10AM EST
- [ ] **Post on r/selfhosted** — content in LAUNCH.md
- [ ] **Rotate Telegram bot token** — manual: @BotFather `/revoke`, update `.env`
- [ ] **Fix GitHub Actions billing** — all repos failing CI/CD
- [ ] **Container name rename** — docker-compose.yml has appmanager→dockfolio NOT deployed

## Ops Intelligence — Architecture

### Tables (3 new, added to db.exec block ~line 1700)

| Table | Purpose |
|-------|---------|
| `ops_baselines` | Config snapshots: env hashes (SHA256), container states, disk%, config hash |
| `ops_events` | Timeline: drift events, key rotations, score changes. Severity + acknowledge |
| `ops_scores` | Worry score history + streak tracking (15-min intervals) |

### Core Functions (5, added after Projects Manager ~line 4930)

| Function | Purpose |
|----------|---------|
| `calculateWorryScore()` | Composite 0-100 from 7 sources: containers(25), keys(20), disk(15), backups(15), security(10), healing(10), seo(5) |
| `snapshotBaseline(type)` | Capture env hashes, container states, disk%, config hash |
| `detectDrift()` | Compare current state vs last baseline. Detects: env changes, container state, image changes, config.yml, disk jumps |
| `calculateAppReportCard(slug)` | Per-app A-F grade across 7 dimensions: security, backup, revenue, traffic, SEO, uptime, freshness |
| `getAppDependencyMap()` | Shared keys graph. Nodes=apps, edges=shared keys. Blast radius count. |

### API Endpoints (10)

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/ops/worry-score | Score + breakdown + streak |
| GET | /api/ops/heartbeat | Per-app health pulse data |
| GET | /api/ops/report-card/:slug | Single app scorecard |
| GET | /api/ops/report-cards | All app scorecards |
| GET | /api/ops/dependencies | Dependency graph |
| GET | /api/ops/drift | Current drifts vs baseline |
| POST | /api/ops/drift/:id/acknowledge | Mark drift expected |
| POST | /api/ops/baseline | Create manual baseline |
| GET | /api/ops/streak | Streak + 7-day history |
| GET | /api/ops/timeline | Recent ops events |

### Cron Jobs (3)

| Schedule | Job |
|----------|-----|
| `*/15 * * * *` | Worry score + streak update |
| `0 2 * * *` | Auto baseline + drift detection + Telegram critical alerts + cleanup old data |
| `0 9 * * 1` | Key rotation reminder (Telegram if baseline >90 days) |

### Frontend (4 tabs, keyboard: `o`)

- **Pulse tab**: 64px worry score number (color-coded), streak counter, 7 breakdown factors, app heartbeat grid (pulsing circles)
- **Keys & Deps tab**: Shared keys with blast radius, app connection graph (lazy-loaded)
- **Report Cards tab**: Per-app scorecards sorted worst-first, 7 dimension mini-grades (lazy-loaded)
- **Timeline tab**: Chronological ops events with severity colors, acknowledge button
- **ADHD Mode** (`Shift+A`): Dims healthy items, stored in localStorage, orange border on button when active
- **Auto-refresh**: Worry badge updates every 5 minutes

### Briefing Integration

Added to `collectBriefingContext()`: worry score, streak days, unacknowledged drifts count.

### Command Palette

Added: `ops`, `worry`, `drift`, `reportcards`

## Projects Manager — Architecture (Session 12, Deployed)

### Tables (5): project_meta, project_tasks, project_roadmap, project_snapshots, project_ai_insights
### Endpoints (16): overview, meta CRUD, tasks CRUD+import+complete+overdue+today, roadmap CRUD+ship, insights per-app + portfolio
### Crons (4): reminder 15min, overdue daily 8AM, weekly snapshot Mon 6AM, AI summaries Sun 4AM
### Frontend: 4 tabs (Overview, Tasks, Roadmap, Insights), keyboard `j`

## Investigation Findings (Critical)

| Issue | Severity | Details |
|-------|----------|---------|
| Stripe webhook cross-contamination | **CRITICAL** | HeadshotAI + AbschlussCheck share Stripe account. HeadshotAI receives AbschlussCheck payment webhooks. Real customer affected. |
| 5/6 apps no error tracking | **HIGH** | Only SacredLens has working Sentry. PromoForge + AbschlussCheck have SDK but no DSN. |
| Disk 37%→58% | **MEDIUM** | 32GB reclaimable Docker build cache. PromoForge worker image 17.7GB. |
| BannerForge fontconfig missing | **MEDIUM** | Font rendering broken in banner generation |
| ClickHouse at 68% memory | **MEDIUM** | 348/512MB, potential OOM if Plausible traffic grows |
| HeadshotAI missing i18n | **LOW** | `legal.impressum.addressCountry` missing for de/es |

## Decisions Made

| Decision | Why | Alternatives |
|----------|-----|-------------|
| Worry Score 0-100 (lower=better) | Intuitive "temperature" metaphor, ADHD-friendly single number | Could invert to health score (higher=better) |
| 7 weighted components | Covers all existing data sources without new collection | Could add SSL cert expiry, traffic anomaly |
| ADHD Mode dims instead of hides | Preserves context while reducing noise | Could fully hide healthy items |
| Streak breaks at score >30 | Generous threshold keeps streaks motivating | Could use 20 (stricter) or 50 (more lenient) |
| Report cards sorted worst-first | ADHD users see problems first | Could sort alphabetically or by type |

## Rollback Info

**Ops Intelligence rollback:** `git checkout -- dashboard/server.js dashboard/public/index.html` — Ops code is NOT deployed yet, so just reverting files is sufficient. If already deployed, revert + `bash deploy.sh --rebuild`.

**Projects Manager rollback:** Revert to commit `63e403f`. Projects code is mixed into server.js/index.html after Security Manager sections.

**Last known good deployed state:** Commit `63e403f` (Security Manager + banner injection). Current running container has Projects Manager but NOT Ops Intelligence.

## Files Modified This Session

### appManager repo
| File | What Changed |
|------|-------------|
| `dashboard/server.js` | +511 lines: Projects Manager (5 tables, 16 endpoints, 4 crons) + Ops Intelligence (3 tables, 5 functions, 10 endpoints, 3 crons, briefing, command palette) |
| `dashboard/public/index.html` | +292 lines: Projects Manager (CSS, HTML 4 tabs, JS ~20 functions) + Ops Intelligence (CSS ~70 rules, HTML panel 4 tabs, JS ~15 functions, keyboard shortcuts) |
| `dashboard/config.yml` | +15 lines: Added Dockfolio as infra app with marketing fields |
| `handover.md` | This file |

### VM Changes (not in git)
| File | What Changed |
|------|-------------|
| `/home/deploy/dockfolio-landing/index.html` | Updated: +Security Auditing, +Projects Manager features, stats 77→93 endpoints, 14→19 tables, 6→13 crons, 15→17 shortcuts |

## Git State

| Repo | Branch | Status | Latest Commit |
|------|--------|--------|---------------|
| appManager | master | clean | 58c7a3c |
| dockfolio/dockfolio | main | synced | 58c7a3c |

## Next Steps (Priority Order)

1. **Fix Stripe webhook cross-contamination** — filter events in Stripe dashboard per endpoint
2. **Enable Sentry DSN** on PromoForge + AbschlussCheck (.env + container restart)
3. **Post Show HN** — LAUNCH.md ready (Tue-Thu 9-10AM EST)
4. **Post r/selfhosted** — LAUNCH.md ready
5. **Rotate Telegram bot token** — @BotFather `/revoke`, update `.env`
6. **Fix GitHub Actions billing**
7. **Add CSP headers** — per-site, report-only mode first

## Key URLs

| Resource | URL |
|----------|-----|
| Dashboard | https://admin.crelvo.dev |
| Dockfolio landing | https://dockfolio.dev |
| GitHub (Dockfolio) | https://github.com/dockfolio/dockfolio |
| Plan file | .claude/plans/stateless-stirring-sun.md |
| Security KB | plans/security-knowledge-base.md |
