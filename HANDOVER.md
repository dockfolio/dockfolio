# Handover

**Date:** 2026-03-29 (Session 3)

## Summary

Completed all cross-promo banner deployment work from session 2. Deployed BannerForge, Headshot AI, and PromoForge to VM. Fixed CSP across 7 nginx site configs. Fixed PromoForge banner delivery (React body replacement). Removed agorahoch3 from cross-promo (not user's website). All 11 owned sites with banner placements verified working. Fixed /api/status endpoint (was showing 29/31 apps as "down"), parallelized health checks (155s → 1s), added 90-day uptime heatmap to public status page, fixed duplicate security headers on BannerForge/AbschlussCheck, standardized X-Frame-Options across all sites, exposed public API endpoints through nginx. Pruned Docker build cache (77% → 53% disk).

## Completed

### Session 3 work (this session)

- [x] **BannerForge deployed** — embed.js Script component was already committed (1bc14b4); deployed to VM via `deploy.sh`
- [x] **Headshot AI deployed** — Built Docker image on VM from source (commit a4ff0f9), restarted container
- [x] **CSP fixes across 7 sites** — Added admin.crelvo.dev to script-src/connect-src/img-src:
  - Shared snippet: Created `/home/deploy/nginx-configs/security-headers-no-csp.conf` (deploy-owned) with admin.crelvo.dev. Switched crelvo, codewithrigor, best-age.de to use it (original `/etc/nginx/snippets/security-headers.conf` is root-owned, can't edit)
  - Per-site CSP: Updated theadhdmind, creativeprogrammer, lohnpruefung, sacredlens
- [x] **PromoForge embed.js** — Added to `<head>` in `web/index.html` (body scripts stripped by React). Committed (2c013cc), pushed, rebuilt Docker image, deployed. Service worker caches old HTML — new visitors get it immediately, existing visitors on next SW update
- [x] **Removed agorahoch3 from cross-promo** — Not user's website. Removed embed.js/track.js nginx injection, removed from crossPromo pairings in config.example.yml and production config.yml
- [x] **Verified all 11 banner placements working** via Playwright

### Session 2 work (previous, all still intact)
- [x] Config-driven cross-promo pairings (15 pairings after agorahoch3 removal)
- [x] Two new API endpoints: GET /api/marketing/crosspromo/pairings, POST /api/marketing/crosspromo/provision
- [x] BannerForge /api/render auth optional, proxy.ts public paths, healthcheck fixes
- [x] AbschlussCheck timeout fix, CSP update, embed.js Script component
- [x] Headshot AI embed.js Script component
- [x] 14 confirm() → confirmAction() migrations, IntersectionObserver for infra panels
- [x] CORS/CORP fixes, 37GB disk freed, 11 BannerForge-rendered PNG banners

## Banner Delivery Status (Final)

| Site | Method | Status |
|------|--------|--------|
| bannerforge.app | Next.js Script component | Working |
| bewerbungsfotos-ai.de | Next.js Script component | Working |
| abschlusscheck.de | Next.js Script component (same-origin proxy) | Working |
| promoforge.app | Vite index.html `<head>` (same-origin proxy) | Working |
| theadhdmind.org | nginx sub_filter + CSP fixed | Working |
| thecreativeprogrammer.dev | nginx sub_filter + CSP fixed | Working |
| codewithrigor.com | nginx sub_filter + CSP fixed | Working |
| oldworldlogos.com | nginx sub_filter + CSP fixed | Working |
| best-age.de | nginx sub_filter + CSP fixed | Working |
| lohnpruefung.de | nginx sub_filter + CSP fixed | Working |
| sacredlens.de | nginx sub_filter works, no placement configured | No banner |
| crelvo.dev | nginx sub_filter works, no placement configured | No banner |
| agorahoch3.org | Removed (not user's website) | N/A |

## In Progress

Nothing actively in progress.

### Also completed this session (after initial handover update)
- [x] **Fixed /api/status endpoint** — Was fetching bare health paths (e.g. `/health`) without constructing URLs. Now uses `https://DOMAIN/health`. All 31 apps show correct status
- [x] **Parallelized status health checks** — Changed from sequential to Promise.all. Response time ~155s → ~1s
- [x] **Skip bare IPs in status checks** — "The Stones Cry Out" (domain=91.99.104.132) no longer falsely shows as down
- [x] **Auto-refresh on public status page** — Added `<meta http-equiv="refresh" content="60">`
- [x] **90-day uptime heatmap** — New `GET /api/status/heatmap` endpoint + visual heatmap bars on `/status` page. Color coded: green (99.9%+), light green (99%+), yellow (95%+), red (<95%)
- [x] **Fixed duplicate security headers** — BannerForge and AbschlussCheck had nginx + Helmet both setting headers. Removed nginx-level duplicates
- [x] **Standardized X-Frame-Options** — Changed theadhdmind + creativeprogrammer from SAMEORIGIN to DENY for consistency
- [x] **Exposed public nginx endpoints** — Added auth_basic off for /status, /api/status, /api/status-page, /health, /api/health, /login, /api/auth/ in appmanager nginx config

## Decisions Made

| Decision | Why | Alternatives Rejected | Why Rejected |
|----------|-----|-----------------------|--------------|
| deploy-owned security-headers-no-csp.conf | Can't edit root-owned /etc/nginx/snippets/ (no sudo password) | Edit shared snippet | Requires root sudo |
| PromoForge embed.js in `<head>` not `<body>` | React SPA replaces body content on mount, stripping injected scripts | `<body>` placement | Scripts get stripped |
| Same-origin /api/banners/ proxy for PromoForge | Express Helmet sets strict CSP; same-origin avoids CSP issues | Cross-origin admin.crelvo.dev | Blocked by CSP script-src |
| Remove agorahoch3 entirely from cross-promo | User said it's not their website | Keep it | Would show banners on third-party site |
| All prior session 2 decisions still valid | See session 2 handover for full table | — | — |

## Known Issues

- **Stripe webhook cross-contamination** (task #11) — Stale webhook in AbschlussCheck Stripe account pointing to bewerbungsfotos-ai.de. Must delete manually in Stripe dashboard
- **GitHub Actions billing** — CI/CD builds still failing. Deploy manually
- **PromoForge service worker** — Caches old index.html without embed.js. Existing visitors won't see banners until SW updates (automatic, usually within 24h). New visitors work immediately
- **sacredlens + crelvo have no banner placements** — embed.js loads but serve returns null. Provision placements if desired
- **Disk at ~70%** — Was 54% after last session's prune, climbed back. Weekly prune cron runs Sunday 3:45 AM
- **AbschlussCheck CSP weakened** — strict-dynamic replaced with unsafe-inline + URL allowlist (from session 2)
- **GTM blocked on codewithrigor.com** — Pre-existing CSP issue
- **Root-owned security-headers.conf still has old CSP** — 3 sites (crelvo, codewithrigor, best-age.de) switched to deploy-owned copy. Other sites using the root snippet will still block admin.crelvo.dev

## Next Steps (Priority Order)

1. **Delete stale Stripe webhook** — Manual: Stripe dashboard > AbschlussCheck account > Developers > Webhooks > delete bewerbungsfotos-ai.de endpoint
2. **Create GitHub fine-grained token** — Manual: GitHub > Settings > Developer settings. Fix CI/CD
3. **Configure off-site backup** — Order Hetzner Storage Box, set env vars (script exists: `scripts/backup-offsite.sh`)
4. **Provision sacredlens/crelvo banner placements** — If desired, use POST /api/marketing/crosspromo/provision
5. **Docker prune** — Disk at 70%, run `docker system prune -a --volumes` if needed before Sunday cron
6. **Remaining project tasks** — Sentry setup, BannerForge Stripe billing, SEO content, etc.

## Rollback Info

### Session 3 changes

**BannerForge** — deployed with embed.js Script component (commit 1bc14b4, was already committed in session 2)

**Headshot AI** — deployed commit a4ff0f9. Rollback: `git reset --hard 692fcc5` + rebuild on VM

**PromoForge** — 2 commits (7e9e3fc, 2c013cc). Rollback: `git reset --hard e2c2cdf` + rebuild Docker on VM

**Nginx CSP changes (not in git, on VM):**
- `/home/deploy/nginx-configs/security-headers-no-csp.conf` — new file, used by crelvo/codewithrigor/best-age.de
- theadhdmind, creativeprogrammer, lohnpruefung, sacredlens — admin.crelvo.dev added to CSP
- agorahoch3 — embed.js/track.js injection removed
- Rollback: restore from nginx config backups or revert sed changes

**Production config.yml** — agorahoch3 removed from crossPromo section

**Dockfolio config.example.yml** — agorahoch3 removed from crossPromo (uncommitted)

## Files Modified This Session

### Dockfolio (4 commits: 5b100e3 through b14b26d — all pushed + deployed)
- `dashboard/config.example.yml` — Removed agorahoch3 from crossPromo pairings
- `dashboard/routes/status.js` — Fixed /api/status URL construction, parallelized health checks, skip bare IPs, auto-refresh, 90-day heatmap API + visualization
- `HANDOVER.md` — This file

### PromoForge (2 commits: 7e9e3fc, 2c013cc — both pushed)
- `web/index.html` — Added embed.js to `<head>` for cross-promo banners

### Production VM (not in git)
- `/home/deploy/nginx-configs/security-headers-no-csp.conf` — New file with admin.crelvo.dev in CSP
- `/home/deploy/nginx-configs/sites/crelvo` — Switched to deploy-owned security headers
- `/home/deploy/nginx-configs/sites/codewithrigor` — Switched to deploy-owned security headers
- `/home/deploy/nginx-configs/sites/best-age.de` — Switched to deploy-owned security headers
- `/home/deploy/nginx-configs/sites/theadhdmind` — Added admin.crelvo.dev to CSP
- `/home/deploy/nginx-configs/sites/creativeprogrammer` — Added admin.crelvo.dev to CSP
- `/home/deploy/nginx-configs/sites/lohnpruefung` — Added admin.crelvo.dev to CSP
- `/home/deploy/nginx-configs/sites/sacredlens` — Added admin.crelvo.dev to CSP + unsafe-inline
- `/home/deploy/nginx-configs/sites/agorahoch3` — Removed embed.js/track.js injection
- `/home/deploy/nginx-configs/sites/bannerforge` — Removed duplicate security headers (app Helmet handles them)
- `/home/deploy/nginx-configs/sites/abschlusscheck.de` — Removed duplicate security headers
- `/home/deploy/nginx-configs/sites/theadhdmind` — X-Frame-Options SAMEORIGIN → DENY
- `/home/deploy/nginx-configs/sites/creativeprogrammer` — X-Frame-Options SAMEORIGIN → DENY
- `/home/deploy/nginx-configs/sites/appmanager` — Added auth_basic off for public endpoints (/status, /api/status, /api/health, /login, /api/auth/)
- `/home/deploy/appmanager/dashboard/config.yml` — Removed agorahoch3 from crossPromo
- `/opt/promoforge/web/index.html` — Added embed.js to head
