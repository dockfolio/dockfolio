# Handover

**Date:** 2026-03-29 (Session 2, continued)

## Summary

Implemented config-driven cross-promo pairing system, fixed BannerForge render auth, migrated all 14 confirm() dialogs to custom modal, added IntersectionObserver for infra panels, fixed AbschlussCheck timeout bug on 68+ page documents, cleaned up old banner data, upgraded all cross-promo banners to BannerForge-rendered PNG images, and freed 37GB disk space. 6 commits to Dockfolio, 3 to BannerForge, 1 to AbschlussCheck — all pushed and deployed. 18 cross-promo placements live with professional rendered banners. Disk 76%→54%. 37/37 containers healthy.

**Most important for next session:** Stripe webhook cross-contamination (task #11) still needs manual fix in Stripe dashboard. 17 remaining project tasks (AbschlussCheck timeout fixed + marked done).

## Completed

### Cross-Promo System (Dockfolio commit 73cc60a)
- [x] Designed 16 directional app pairings across German career/finance and English maker/creative clusters
- [x] Added `crossPromo` config section to config.example.yml and production config.yml
- [x] Replaced broken `auto-place` endpoint (referenced non-existent DB columns) with 2 new endpoints:
  - `GET /api/marketing/crosspromo/pairings` — returns config pairings with resolved app metadata
  - `POST /api/marketing/crosspromo/provision` — creates banners + placements from config (idempotent)
- [x] Provisioned 11 banners + 18 placements, all activated in production

### BannerForge Render Auth Fix (BannerForge commits 85e8fa8, 87332e0)
- [x] Made `/api/render` route auth optional — anonymous callers get PNG/JPG, authenticated users get all formats
- [x] Added `/api/render` to proxy.ts publicPaths (Next.js 16 uses proxy.ts, not middleware.ts)
- [x] Updated Dockfolio's BannerForge schema calls to match current API (commit 2960f6d)

### Frontend: confirm() to confirmAction() (Dockfolio commit c845c58)
- [x] Migrated all 14 native `confirm()` calls to `confirmAction(title, message, callback)` custom modal
- [x] Covers: container restart, Docker prune, SSL renew, banner/campaign/playbook delete, snapshot rollback, alert rule delete, maintenance window delete, app removal, task deletion

### Frontend: IntersectionObserver (Dockfolio commit 0b26095)
- [x] Replaced 300ms setTimeout with IntersectionObserver for 10 below-fold infra panels
- [x] Panels now lazy-load only when scrolled into view (200px rootMargin for pre-fetch)
- [x] Each panel loads once and is unobserved

### AbschlussCheck Timeout Fix (AbschlussCheck commit 6b33157)
- [x] Increased Anthropic API timeout from 120s to 180s per call
- [x] Increased default MAX_PARALLEL_CHUNKS from 3 to 5 (matches config.ts)
- [x] Scaled reconciliation stuck threshold: 15min for ≤60 pages, 30min for >60 pages
- [x] Deployed and healthy

### Production Cleanup (no git commits — DB + Docker ops)
- [x] Deleted 39 old paused placements and 7 old banners from previous undirected system
- [x] Upgraded all 11 cross-promo banners from custom_html to BannerForge-rendered PNG images (~45-51KB each)
- [x] Freed 37GB disk space: build cache 45GB→2.7GB, images 74GB→39GB (disk 76%→54%)
- [x] Marked AbschlussCheck timeout task (#13) as done in project_tasks

## In Progress

Nothing — all work committed, pushed, and deployed.

## Decisions Made

| Decision | Why | Alternatives Rejected | Why Rejected |
|----------|-----|-----------------------|--------------|
| Config-driven pairings in config.yml | Version-controlled, easy to edit, explicit | DB-only pairings | Not visible in git, harder to review |
| custom_html banner type for cross-promo | Works without BannerForge, immediate | bannerforge type | BannerForge was broken at time of implementation |
| Auth optional on /api/render (not removed) | Preserves format restrictions for paid users | Remove auth entirely | Loses GIF/WebP format gating for paid plans |
| proxy.ts not middleware.ts | Next.js 16 uses proxy.ts; middleware.ts conflicts | Add middleware.ts | Build fails: "Both middleware and proxy detected" |
| 30min stuck threshold for large docs | 68-page thesis with 14 chunks needs ~10-15min | Increase to 60min | Too long before refunding actual failures |
| MAX_PARALLEL 5 (not 3) | Config already said 5; 3 was just the env default | Keep at 3 | Unnecessarily slow for large documents |

## Known Issues

- **Stripe webhook cross-contamination** (task #11) — Stale webhook in AbschlussCheck Stripe account pointing to bewerbungsfotos-ai.de. Must delete manually in Stripe dashboard.
- **GitHub Actions billing** — CI/CD builds still failing. Deploy manually.
- **Disk climbs to ~76% between prune cycles** — Weekly Docker prune cron runs Sunday 3:45 AM but images accumulate from frequent rebuilds. Consider more aggressive pruning or image cleanup.
- **PromoForge worker OOM** — Ongoing, self-heals via restart.

## Next Steps (Priority Order)

1. **Delete stale Stripe webhook** — Manual: Stripe dashboard > AbschlussCheck account > Developers > Webhooks > delete endpoint pointing to bewerbungsfotos-ai.de
2. **Create GitHub fine-grained token** — Manual: GitHub > Settings > Developer settings
3. **Configure off-site backup** — Order Hetzner Storage Box, set env vars (script already exists: `scripts/backup-offsite.sh`)
4. **Address remaining 17 project tasks** — Sentry setup (#7), BannerForge Stripe billing (#10), SEO content, landing page optimization, etc.

## Rollback Info

- **Pre-session state (Dockfolio):** `6276e12`
- **Session commits (Dockfolio):** 5 commits (`73cc60a` through `0b26095`)
- **Pre-session state (BannerForge):** `e60ce73`
- **Session commits (BannerForge):** 3 commits (`85e8fa8` through `87332e0`)
- **Pre-session state (AbschlussCheck):** `8200b47`
- **Session commits (AbschlussCheck):** 1 commit (`6b33157`)
- **Production DB changes (not in git):**
  - 11 banners created (ids 11-21) with `crosspromo,{slug}` tags
  - 18 placements created (ids 41-58, status=active)
  - AbschlussCheck task #13 marked done
  - Revert banners: `DELETE FROM banners WHERE id >= 11 AND id <= 21`
  - Revert placements: `DELETE FROM banner_placements WHERE id >= 41 AND id <= 58`

## Files Modified This Session

### Dockfolio (5 commits, all pushed + deployed)
- `dashboard/config.example.yml` — Added crossPromo pairings section
- `dashboard/routes/marketing.js` — Replaced broken auto-place, added pairings+provision endpoints, fixed BannerForge render schema
- `dashboard/public/index.html` — 14 confirm()→confirmAction() migrations, IntersectionObserver for 10 infra panels

### BannerForge (3 commits, all pushed + deployed)
- `src/app/api/render/route.ts` — Auth made optional (anonymous: PNG/JPG only)
- `src/proxy.ts` — Added /api/render to publicPaths
- `src/middleware.ts` — Created then deleted (conflicts with proxy.ts in Next.js 16)
- `docker-compose.prod.yml` — Healthcheck URL fix (localhost→127.0.0.1)
- `docker-compose.yml` — Healthcheck URL fix, start_period 15s→30s

### AbschlussCheck (1 commit, pushed + deployed)
- `lib/claude.ts` — API timeout 120s→180s, MAX_PARALLEL default 3→5
- `app/api/cron/reconcile/route.ts` — Scaled stuck threshold: 15min (small) / 30min (large docs)

### Production config (not in git)
- `/home/deploy/appmanager/dashboard/config.yml` — Added crossPromo section
- `data.db`: 11 banners, 18 placements created + activated
