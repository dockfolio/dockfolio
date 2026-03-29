# Handover

**Date:** 2026-03-29 (Session 2, final)

## Summary

Massive cross-promo and infrastructure session across 4 repos. Built config-driven cross-promo pairing system (16 pairings, 18 placements), fixed BannerForge render auth, replaced all 14 confirm() dialogs, added IntersectionObserver for infra panels, fixed AbschlussCheck 68+ page timeout bug, upgraded all banners to BannerForge-rendered PNGs, and debugged+fixed banner delivery across all sites (CORS/CORP, CSP, slug mismatches, nginx sub_filter vs React hydration). Freed 37GB disk. Cross-promo banners now verified working on static sites and AbschlussCheck (Next.js).

**Most important for next session:** BannerForge layout.tsx still needs the embed.js Script component (was in progress when session ended). Headshot AI layout.tsx was committed+pushed but NOT deployed. Other Next.js apps (PromoForge is Express, not Next.js) may need the same treatment. Static sites all work now.

## Completed

### Dockfolio (7 commits: 73cc60a through 85e7b40, all pushed+deployed)
- [x] Config-driven cross-promo pairings in config.example.yml + production config.yml
- [x] Two new API endpoints: GET /api/marketing/crosspromo/pairings, POST /api/marketing/crosspromo/provision
- [x] Replaced broken auto-place endpoint (referenced non-existent DB columns)
- [x] Fixed BannerForge render schema (brand/copy/size/colors objects updated)
- [x] Replaced all 14 native confirm() with confirmAction() custom modal
- [x] IntersectionObserver for 10 below-fold infra panels (replaces 300ms setTimeout)
- [x] Added Cross-Origin-Resource-Policy: cross-origin to setCORS() for embed.js/track.js/pixel.gif
- [x] Added setCORS to analytics track.js and pixel.gif endpoints

### BannerForge (3 commits: 85e8fa8 through 87332e0, all pushed+deployed)
- [x] /api/render auth made optional (anonymous: PNG/JPG only, auth: all formats)
- [x] Added /api/render to proxy.ts publicPaths (Next.js 16 uses proxy.ts not middleware.ts)
- [x] Docker-compose healthcheck URL fixes

### AbschlussCheck (4 commits: 6b33157 through b40eb29, all pushed+deployed)
- [x] Timeout fix: API timeout 120s->180s, MAX_PARALLEL 3->5, stuck threshold scaled 15/30min
- [x] CSP updated: removed strict-dynamic, added admin.crelvo.dev to script-src and connect-src
- [x] Added Dockfolio embed.js via Next.js Script component in app/layout.tsx (same-origin /api/banners/ proxy)

### Headshot AI (1 commit: a4ff0f9, pushed but NOT deployed)
- [x] Replaced hardcoded crelvo-banner.js with Dockfolio embed.js Script component

### Production ops (no git, all on VM)
- [x] Provisioned 11 banners + 18 placements via /api/marketing/crosspromo/provision
- [x] Activated all 18 placements
- [x] Deleted 39 old paused placements + 7 old banners
- [x] Upgraded all 11 cross-promo banners to BannerForge-rendered PNG images (~45-51KB each)
- [x] Freed 37GB disk: build cache 45GB->2.7GB, images 74GB->39GB (disk 76%->54%)
- [x] Fixed embed.js URLs in 12 nginx configs (relative -> full admin.crelvo.dev URL)
- [x] Fixed data-app slug mismatches in 2 nginx configs (codewithrigor->code-with-rigor, creativeprogrammer->creative-programmer)
- [x] Added embed.js injection to best-age.de nginx config (was missing)
- [x] Moved AbschlussCheck embed.js from </body> to </head> sub_filter injection
- [x] Marked AbschlussCheck timeout task (#13) as done in project_tasks DB

## In Progress

- [ ] **BannerForge layout.tsx needs embed.js Script component** — Was about to edit `src/app/layout.tsx` when session ended. File was read (lines 64-128). Need to add `<Script src="/api/banners/embed.js" data-app="bannerforge" strategy="lazyOnload" />` before `</body>`. BannerForge nginx already has `/api/banners/` proxy. Commit and deploy via `bash deploy.sh`.
- [ ] **Headshot AI needs deploy** — Commit a4ff0f9 pushed to git but NOT deployed to VM. Deploy script location: check repo for deploy.sh or use same pattern as AbschlussCheck (tar + docker build + compose up). Container: headshot-ai-headshot-web-1, port 3001, compose at /opt or /home/deploy.
- [ ] **Other Next.js apps banner verification** — PromoForge is Express (not Next.js, sub_filter should work). SacredLens repo not found locally. LohnCheck is Python/FastAPI (sub_filter works). Need to verify banners actually render on: lohnpruefung.de, promoforge.app, sacredlens.de, bewerbungsfotos-ai.de, bannerforge.app, theadhdmind.org, oldworldlogos.com, agorahoch3.org, best-age.de, abfindungsoptimizer.de, schenkungsplaner.eu.

## Decisions Made

| Decision | Why | Alternatives Rejected | Why Rejected |
|----------|-----|-----------------------|--------------|
| Config-driven pairings in config.yml | Version-controlled, explicit, easy to review | DB-only pairings | Not visible in git |
| custom_html then upgraded to bannerforge type | Started with text, upgraded once render was public | Image banners from start | BannerForge was auth-gated initially |
| Auth optional on /api/render (not removed) | Preserves GIF/WebP format gating for paid users | Remove auth entirely | Loses paid feature differentiation |
| proxy.ts not middleware.ts for Next.js 16 | Next.js 16 uses proxy.ts; middleware.ts causes build error | middleware.ts | "Both middleware and proxy detected" build error |
| Script component for Next.js apps | React hydration strips nginx sub_filter injected scripts | nginx sub_filter only | Doesn't work — React removes non-React DOM nodes |
| Same-origin /api/banners/ proxy for Next.js | Avoids CSP issues, works with nonces | Cross-origin admin.crelvo.dev URL | Blocked by CSP strict-dynamic or nonce requirements |
| Cross-origin for static sites | Static sites don't have React hydration issues | Same-origin proxy for all | Requires adding nginx proxy to every site; overkill for static |
| CORP: cross-origin in setCORS() | Helmet default same-origin blocks cross-origin script loading | Disable Helmet CORP globally | Too broad; only public endpoints need cross-origin |
| 30min stuck threshold for 60+ pages | 68-page thesis needs ~10-15min for MAP-REDUCE | Single 30min for all | Would delay refunds for genuinely stuck small docs |
| Removed strict-dynamic from AbschlussCheck CSP | strict-dynamic ignores URL allowlists, blocks sub_filter scripts | Keep strict-dynamic + use nonce on injected scripts | nginx can't know the per-request nonce |

## Known Issues

- **Stripe webhook cross-contamination** (task #11) — Stale webhook in AbschlussCheck Stripe account pointing to bewerbungsfotos-ai.de. Must delete manually in Stripe dashboard.
- **GitHub Actions billing** — CI/CD builds still failing. Deploy manually.
- **BannerForge layout.tsx not updated** — Needs Script component for embed.js (in progress, see above).
- **Headshot AI not deployed** — Commit pushed but container not rebuilt.
- **PromoForge/SacredLens/LohnCheck banner delivery unverified** — embed.js is injected via nginx but not yet verified with Playwright that banners actually render.
- **Disk climbs to ~76% between prune cycles** — Weekly Docker prune cron runs Sunday 3:45 AM but images accumulate. Currently at 54% after manual prune.
- **AbschlussCheck CSP weakened** — Replaced strict-dynamic with unsafe-inline + URL allowlist. Functional but slightly weaker CSP. Could revisit with nonce-based approach later.
- **GTM blocked on codewithrigor.com** — CSP doesn't include googletagmanager.com. Pre-existing, not introduced this session.

## Next Steps (Priority Order)

1. **Add embed.js Script to BannerForge layout.tsx** — Read `src/app/layout.tsx` lines 118-126, add `<Script src="/api/banners/embed.js" data-app="bannerforge" strategy="lazyOnload" />` before `</body>`. Commit, push, deploy via `bash deploy.sh`.
2. **Deploy Headshot AI** — Find deploy method (check for deploy.sh in repo, or tar+build+compose pattern used for AbschlussCheck at /opt/abschlusscheck). Container: headshot-ai-headshot-web-1.
3. **Verify banners on all 13 source sites** — Use Playwright to visit each, check `document.getElementById('dockfolio-banner')` exists and has content. Fix any remaining issues.
4. **Delete stale Stripe webhook** — Manual: Stripe dashboard > AbschlussCheck account > Developers > Webhooks > delete bewerbungsfotos-ai.de endpoint.
5. **Create GitHub fine-grained token** — Manual: GitHub > Settings > Developer settings.
6. **Configure off-site backup** — Order Hetzner Storage Box, set env vars (script exists: `scripts/backup-offsite.sh`).
7. **Remaining 16 project tasks** — Sentry setup, BannerForge Stripe billing, SEO content, etc.

## Rollback Info

### Dockfolio
- Pre-session: `6276e12`
- Current: `85e7b40` (7 commits)
- Rollback: `git reset --hard 6276e12` + redeploy
- Each commit self-contained, can revert individually

### BannerForge
- Pre-session: `e60ce73`
- Current: `87332e0` (3 commits)
- Rollback: `git reset --hard e60ce73` + redeploy

### AbschlussCheck
- Pre-session: `8200b47`
- Current: `b40eb29` (4 commits)
- Rollback: `git reset --hard 8200b47` + rebuild + compose up

### Headshot AI
- Pre-session: `692fcc5`
- Current: `a4ff0f9` (1 commit, NOT deployed)
- Rollback: `git reset --hard 692fcc5`

### Production DB (not in git)
- 11 banners created (ids 11-21) with `crosspromo,{slug}` tags
- 18 placements created (ids 41-58, status=active)
- 39 old placements deleted, 7 old banners deleted
- AbschlussCheck task #13 marked done
- Revert: `DELETE FROM banners WHERE id >= 11 AND id <= 21; DELETE FROM banner_placements WHERE id >= 41`

### Nginx configs (not in git, on VM)
- 12 sites: embed.js URL changed from relative to full admin.crelvo.dev
- 2 sites: data-app slugs fixed (codewithrigor, creativeprogrammer)
- 1 site: embed.js added (best-age.de)
- 1 site: embed.js moved from </body> to </head> (abschlusscheck.de)

## Files Modified This Session

### Dockfolio (7 commits, all pushed+deployed)
- `dashboard/config.example.yml` — Added crossPromo pairings section (16 pairings)
- `dashboard/routes/marketing.js` — Replaced broken auto-place with pairings+provision endpoints, fixed BannerForge render schema for create+regenerate
- `dashboard/public/index.html` — 14 confirm()->confirmAction() migrations, IntersectionObserver for 10 infra panels
- `dashboard/server.js` — Added Cross-Origin-Resource-Policy: cross-origin to setCORS(), passed setCORS to analytics routes
- `dashboard/routes/analytics.js` — Added setCORS to track.js and pixel.gif endpoints

### BannerForge (3 commits, all pushed+deployed)
- `src/app/api/render/route.ts` — Auth made optional
- `src/proxy.ts` — Added /api/render to publicPaths
- `docker-compose.prod.yml` + `docker-compose.yml` — Healthcheck fixes

### AbschlussCheck (4 commits, all pushed+deployed)
- `lib/claude.ts` — API timeout 120s->180s, MAX_PARALLEL default 3->5
- `app/api/cron/reconcile/route.ts` — Scaled stuck threshold by page count
- `middleware.ts` — CSP: removed strict-dynamic, added admin.crelvo.dev
- `app/layout.tsx` — Added Dockfolio embed.js Script component

### Headshot AI (1 commit, pushed, NOT deployed)
- `app/layout.tsx` — Replaced crelvo-banner.js with Dockfolio embed.js Script component

### Production VM (not in git)
- `/home/deploy/appmanager/dashboard/config.yml` — Added crossPromo section
- `/home/deploy/nginx-configs/sites/*` — 12 embed.js URL fixes, 2 slug fixes, 1 addition, 1 head/body move
- `data.db` — 11 banners, 18 placements, 39+7 deletions, 1 task status update
