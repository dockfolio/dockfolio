# Handover

**Date:** 2026-03-29 (Session 3, final)

## Summary

Session 3 completed all remaining cross-promo banner work from session 2, then fixed multiple bugs and added new features. Deployed BannerForge, Headshot AI, and PromoForge to VM. Fixed CSP on 7 nginx configs blocking admin.crelvo.dev. Fixed PromoForge (React SPA strips body scripts — moved embed.js to `<head>`). Removed agorahoch3 from cross-promo (not user's website). Fixed broken /api/status endpoint (was showing 29/31 apps as "down" — bare health paths weren't full URLs). Parallelized status health checks (155s → 1s). Added 90-day uptime heatmap to public status page. Fixed duplicate security headers on BannerForge/AbschlussCheck. Standardized X-Frame-Options. Exposed public endpoints through nginx. Pruned Docker build cache (77% → 53%).

**Most important for next session:** All cross-promo and status work is done. Remaining items are manual tasks (Stripe webhook cleanup, GitHub token, Hetzner backup) and longer-term feature work. System is stable and healthy.

## Completed

### Cross-promo banner system (fully operational)
- [x] BannerForge deployed — embed.js Script component already committed (1bc14b4), deployed via `deploy.sh`
- [x] Headshot AI deployed — Built Docker image on VM from source (commit a4ff0f9), container running healthy
- [x] PromoForge embed.js — Added to `<head>` in `web/index.html` (2 commits: 7e9e3fc, 2c013cc, pushed+deployed)
- [x] CSP fixes on 7 sites — Added admin.crelvo.dev to script-src/connect-src/img-src:
  - Created `/home/deploy/nginx-configs/security-headers-no-csp.conf` for crelvo, codewithrigor, best-age.de (original `/etc/nginx/snippets/security-headers.conf` is root-owned, no sudo)
  - Updated per-site CSP: theadhdmind, creativeprogrammer, lohnpruefung, sacredlens
- [x] Removed agorahoch3 from cross-promo — embed.js/track.js nginx injection removed, removed from config.example.yml + production config.yml
- [x] Verified all 11 banner placements working via Playwright

### Status page overhaul
- [x] Fixed /api/status — Was fetching bare paths (`/health`) instead of full URLs. Now uses `https://DOMAIN/health`. Result: 2/31 → 31/31 apps correct
- [x] Parallelized health checks — Changed for-loop to Promise.all. Response: ~155s → ~1s
- [x] Skip bare IP domains — "The Stones Cry Out" (domain=91.99.104.132) no longer falsely "down"
- [x] Auto-refresh on /status page — `<meta http-equiv="refresh" content="60">`
- [x] 90-day uptime heatmap — New `GET /api/status/heatmap?app=SLUG&days=N` endpoint + visual bars on `/status`
- [x] Public nginx endpoints — Added auth_basic off for /status, /api/status, /api/status-page, /health, /api/health, /login, /api/auth/

### Security headers cleanup
- [x] BannerForge — Removed nginx-level security headers (app Helmet handles them, was causing duplicates)
- [x] AbschlussCheck — Same duplicate header removal
- [x] theadhdmind + creativeprogrammer — X-Frame-Options changed from SAMEORIGIN to DENY

### Infrastructure
- [x] Docker build cache pruned — 77% → 53% disk (freed ~35GB)
- [x] All 37 containers running healthy
- [x] 119 unit tests passing

## In Progress

Nothing in progress. All work committed and deployed.

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

## Decisions Made

| Decision | Why | Alternatives Rejected | Why Rejected |
|----------|-----|-----------------------|--------------|
| deploy-owned security-headers-no-csp.conf | Can't edit root-owned /etc/nginx/snippets/ (no sudo password for tee/cp) | Edit shared snippet directly | Requires root sudo, deploy user only has passwordless nginx/certbot |
| PromoForge embed.js in `<head>` not `<body>` | React SPA replaces body content on mount, stripping all injected scripts | `<body>` placement | Scripts get stripped — confirmed via Playwright |
| Same-origin /api/banners/ proxy for PromoForge | Express Helmet sets strict CSP (script-src 'self' only); same-origin avoids CSP entirely | Cross-origin admin.crelvo.dev URL | Blocked by CSP script-src, would need app code change |
| Remove agorahoch3 entirely from cross-promo | User explicitly said "never banner dieagora its not my website" | Keep placement but deactivate | User was clear about removal |
| Public domain URLs for /api/status health checks | Docker container can't reach host localhost:PORT (ECONNREFUSED — Docker network isolation) | Internal http://127.0.0.1:PORT URLs | Container networking prevents access to host-bound ports |
| Parallel Promise.all for status checks | Sequential was O(n*timeout) = ~155s for 31 apps; parallel is O(timeout) = ~5s max | Keep sequential | Unacceptable response time for a public API |
| Remove nginx security headers from BannerForge/AbschlussCheck | Next.js Helmet already sets them; nginx + Helmet = duplicate headers in response | Keep both | Duplicate headers can cause browser confusion (e.g. conflicting X-Frame-Options DENY vs SAMEORIGIN) |
| X-Frame-Options DENY for all sites | Consistency; none of these sites need to be framed | Keep SAMEORIGIN for theadhdmind/creativeprogrammer | No framing needed, DENY is more secure |
| All prior session 2 decisions still valid | See session 2 decisions in git history | — | — |

## Known Issues

- **Stripe webhook cross-contamination** (task #11) — Stale webhook in AbschlussCheck Stripe account pointing to bewerbungsfotos-ai.de. Must delete manually in Stripe dashboard
- **GitHub Actions billing** — CI/CD builds still failing. Deploy manually via deploy.sh
- **PromoForge service worker caching** — Old index.html cached in SW without embed.js. New visitors work immediately. Existing visitors get update on next SW refresh cycle (~24h)
- **sacredlens + crelvo have no banner placements** — embed.js loads but serve returns null. Provision via POST /api/marketing/crosspromo/provision if desired
- **Disk climbs after Docker builds** — Currently 53%, will climb as builds happen. Weekly prune cron (Sunday 3:45 AM) handles it. Manual: `docker builder prune -f`
- **AbschlussCheck CSP weakened** — strict-dynamic replaced with unsafe-inline + URL allowlist (from session 2)
- **Root-owned security-headers.conf still has old CSP** — 3 sites switched to deploy-owned copy. Other sites using root snippet won't have admin.crelvo.dev in CSP
- **Public endpoints need --http1.1 from local curl** — nginx listens `443 ssl` (no http2 directive). Browsers negotiate fine; curl on Windows defaults to HTTP/2 which causes 401. Non-issue in practice
- **OldWorldLogos X-Frame-Options is SAMEORIGIN** — Intentional, uses giscus comments iframe. Don't change to DENY

## Next Steps (Priority Order)

1. **Delete stale Stripe webhook** — Manual: Stripe dashboard > AbschlussCheck account > Developers > Webhooks > delete bewerbungsfotos-ai.de endpoint
2. **Create GitHub fine-grained token** — Manual: GitHub > Settings > Developer settings. Fixes CI/CD builds
3. **Configure off-site backup** — Order Hetzner Storage Box, set env vars (script exists: `scripts/backup-offsite.sh`)
4. **Feature work from plans/feature-ideas-2026.md** — Top candidates:
   - Predictive Resource Alerts (1.3) — Easy, linear regression on existing time series
   - Smart Alert Explanations (1.6) — Easy, contextual prompts with existing data
   - App Health Score on status page (4.2) — Easy, endpoint exists (/api/apps/health-scores), just needs public exposure
5. **Remaining project tasks** — Sentry setup, BannerForge Stripe billing, SEO content generation

## Rollback Info

### Dockfolio (5 commits: 5b100e3 through a315669)
- Pre-session: `65b6fe6`
- Current: `a315669`
- Rollback: `git reset --hard 65b6fe6` + `bash deploy.sh --rebuild`
- Each commit is self-contained, can revert individually

### PromoForge (2 commits: 7e9e3fc, 2c013cc)
- Pre-session: `e2c2cdf`
- Current: `2c013cc`
- Rollback: `git reset --hard e2c2cdf` + rebuild Docker on VM (`cd /opt/promoforge && docker compose build --no-cache api && docker compose down api && docker compose up -d api worker`)

### BannerForge (deployed, no new commits this session)
- Deployed commit 1bc14b4 (was already committed in session 2)
- Deploy: `cd /c/Users/kreyh/Projekte/ad/bannerforge && bash deploy.sh`

### Headshot AI (deployed, no new commits this session)
- Deployed commit a4ff0f9 (was already committed in session 2)
- Deploy: Upload source to /opt/headshot-ai/build-tmp via tar+ssh, then `docker build -t headshot-ai-pro:latest . && cd /opt/headshot-ai && docker compose down && docker compose up -d`

### Nginx configs (not in git, on VM)
- `/home/deploy/nginx-configs/security-headers-no-csp.conf` — New file with admin.crelvo.dev in CSP
- crelvo, codewithrigor, best-age.de — Switched include from /etc/nginx/snippets/security-headers.conf to deploy-owned copy
- theadhdmind, creativeprogrammer, lohnpruefung, sacredlens — admin.crelvo.dev added to script-src, connect-src, img-src
- bannerforge — Removed duplicate security headers (6 add_header lines deleted)
- abschlusscheck.de — Removed duplicate security headers (6 lines at 87-92 deleted)
- theadhdmind, creativeprogrammer — X-Frame-Options SAMEORIGIN → DENY
- agorahoch3 — embed.js/track.js injection lines removed
- appmanager — Added 7 location blocks with auth_basic off for public endpoints (before the "# Dashboard" comment)

### Production DB
- agorahoch3 placement (id 52) still exists but inactive (nginx no longer injects embed.js)
- To fully remove: DELETE FROM banner_placements WHERE id = 52 (requires app auth or direct DB access)

## Files Modified This Session

### Dockfolio (5 commits: 5b100e3 through a315669 — all pushed + deployed)
- `dashboard/config.example.yml` — Removed agorahoch3 from crossPromo pairings
- `dashboard/routes/status.js` — Fixed /api/status URL construction, parallelized health checks, skip bare IPs, auto-refresh, 90-day heatmap API + visualization
- `HANDOVER.md` — This file

### PromoForge (2 commits: 7e9e3fc, 2c013cc — both pushed + deployed)
- `web/index.html` — Added embed.js to `<head>` for cross-promo banners (moved from body after discovering React strips body scripts)

### Production VM (not in git)
- `/home/deploy/nginx-configs/security-headers-no-csp.conf` — New file, deploy-owned CSP with admin.crelvo.dev
- `/home/deploy/nginx-configs/sites/crelvo` — Switched to deploy-owned security headers
- `/home/deploy/nginx-configs/sites/codewithrigor` — Switched to deploy-owned security headers
- `/home/deploy/nginx-configs/sites/best-age.de` — Switched to deploy-owned security headers
- `/home/deploy/nginx-configs/sites/theadhdmind` — Added admin.crelvo.dev to CSP + X-Frame-Options DENY
- `/home/deploy/nginx-configs/sites/creativeprogrammer` — Added admin.crelvo.dev to CSP + X-Frame-Options DENY
- `/home/deploy/nginx-configs/sites/lohnpruefung` — Added admin.crelvo.dev to script-src + connect-src
- `/home/deploy/nginx-configs/sites/sacredlens` — Added admin.crelvo.dev to CSP + unsafe-inline
- `/home/deploy/nginx-configs/sites/bannerforge` — Removed 6 duplicate security header lines
- `/home/deploy/nginx-configs/sites/abschlusscheck.de` — Removed 6 duplicate security header lines (87-92)
- `/home/deploy/nginx-configs/sites/agorahoch3` — Removed embed.js/track.js injection lines
- `/home/deploy/nginx-configs/sites/appmanager` — Added 7 location blocks with auth_basic off for public endpoints
- `/home/deploy/appmanager/dashboard/config.yml` — Removed agorahoch3 from crossPromo
- `/opt/promoforge/web/index.html` — Added embed.js to head (matches git commit)
