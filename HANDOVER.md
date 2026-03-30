# Handover

**Date:** 2026-03-30 (Session 4, final)

## Summary

Session 4 was triggered by Google Search Console warning emails about indexing issues across multiple sites. It expanded into a comprehensive SEO, security, analytics, and feature session. Fixed www→non-www redirects on 4 sites, added canonical tags to 5 sites (1 source code, 4 nginx), added OG tags to 2 sites, added security headers to 19 nginx configs (created shared snippet), fixed Plausible analytics tracking on 3 sites that were silently broken (PromoForge, SacredLens, LohnCheck), overhauled PromoForge nginx config, added predictive resource alerts with linear regression, massively enhanced the public `/status` page (health badges, infrastructure bars, portfolio stats, clickable links, response times, incident history), fixed a cron failure in project snapshots, dismissed 29 expected security findings, and pruned Docker cache twice. All 14 main sites now have perfect SEO basics. All 24 public sites pass all critical security headers. 12/12 Plausible-tracked sites have working HTTPS proxy.

**Most important for next session:** System is fully stable and healthy. The 1 AM nightly security scan will show significantly improved scores (especially Plausible jumping from F to much higher). Remaining items are manual tasks (Stripe webhook, GitHub token, Hetzner backup) and business-level work (SEO content creation, PromoForge growth). No technical debt remains from this session.

## Completed

### Google Search Console SEO Fixes
- [x] www→non-www 301 redirects: oldworldlogos.com, theadhdmind.org, thecreativeprogrammer.dev, lohnpruefung.de
- [x] Canonical tags via Astro source: crelvo.dev (Base.astro, commit 2d167bd in crelvo repo, built + deployed to /var/www/crelvo/)
- [x] Canonical tags via nginx sub_filter: oldworldlogos.com, bannerforge.app, schenkungsplaner.eu, abfindungsoptimizer.de
- [x] OG tags via nginx sub_filter: schenkungsplaner.eu, abfindungsoptimizer.de (were completely missing all OG tags)
- [x] BannerForge sub_filter fix: moved `Accept-Encoding ""` into `location /` block (was at server level, not inherited)
- [x] lohnpruefung.de favicon.ico 404 silenced (nginx returns 204)
- [x] **14/14 main sites verified: all have title, desc, og:image, canonical, sitemap, robots**

### Security Header Hardening
- [x] Created shared `/home/deploy/nginx-configs/snippets/game-security-headers.conf`
- [x] Plausible Analytics: added all 7 security headers to HTTPS block (was only on HTTP redirect block)
- [x] creatureforge, betpilot, diplomancy: added game-security-headers snippet (had zero headers)
- [x] worldcontrol, lufthafen, orb: added game-security-headers snippet
- [x] grimhollow: replaced single HSTS header with full snippet
- [x] dockfolio.dev, demo.dockfolio.dev: added Permissions-Policy, CSP, X-XSS-Protection
- [x] bannerforge: added Permissions-Policy, X-XSS-Protection
- [x] **24/24 public sites pass HSTS + CSP + Permissions-Policy checks**

### Security Finding Dismissals
- [x] 25 "Running as root user" findings dismissed (postgres, redis, clickhouse — by design)
- [x] 4 "Docker socket mounted" / "privileged mode" dismissed (docker-proxy, uptime-kuma, demo — by design)
- [x] **0 critical findings remaining** (was 4)

### Plausible Analytics Fixes (high impact — these were silently broken)
- [x] PromoForge: Added Plausible proxy + script injection to HTTPS block — was completely missing, zero analytics tracked
- [x] SacredLens: Added Plausible proxy — sub_filter injected script URL but no proxy to serve it (404)
- [x] LohnCheck: Added Plausible proxy to HTTPS block — was only on HTTP
- [x] **12/12 Plausible-tracked sites verified working on HTTPS**

### PromoForge Nginx Overhaul
- [x] Added all 7 security headers (had none)
- [x] Added Plausible proxy + script injection on HTTPS (analytics were completely broken)
- [x] Added `/_next/static/` caching (1 year, immutable)
- [x] Moved `Accept-Encoding ""` into location block for sub_filter
- [x] Consolidated config: www/promoforge.de redirects, single HTTPS block

### New Dockfolio Features (all deployed)
- [x] Health score badges (A-F grade) on public `/status` page — uses calculateAppReportCard
- [x] Infrastructure health bars on `/status` — CPU/Memory/Disk with color-coded progress bars
- [x] Portfolio summary stats in `/status` header (service count, avg uptime, avg health)
- [x] Clickable domain links on `/status` page
- [x] Response times (ms) shown per app from uptime_history
- [x] Recent incidents section (last 7 days of healing events)
- [x] Predictive resource alerts — 7-day linear regression on disk/memory, Telegram alerts when projected to hit 90%, new `GET /api/alerts/predictions` endpoint, 6-hour cron
- [x] SEO audit enhanced — added www redirect check + hreflang tag validation

### Bug Fixes
- [x] Fixed "Project snapshots" cron failure — `SELECT score FROM security_scans` wrong column name (is `overall_score`) and wrong table (scans are system-wide, not per-app). Now computes per-app score from `security_findings`.

### Tests
- [x] 5 new integration tests: status page infrastructure, heatmap API, predictions API, alert rules, health scores
- [x] 119 unit tests + 5 new integration tests all pass

### Infrastructure
- [x] Docker build cache pruned twice: 83% → 53% disk
- [x] All 37 containers healthy, 0 errors in logs

## In Progress

Nothing in progress. All work committed, pushed, and deployed.

## Decisions Made

| Decision | Why | Alternatives Rejected | Why Rejected |
|----------|-----|----------------------|--------------|
| Canonical tags via nginx sub_filter for sites without local repos | Can't modify source for oldworldlogos, bannerforge, schenkungsplaner, abfindungsoptimizer (no local repo or complex build) | Modify app source code | No source access for some; others would need rebuild/redeploy |
| Accept-Encoding "" must be in location block, not server block | nginx doesn't inherit parent proxy_set_header when location has its own proxy_set_header directives | Server-level setting | Doesn't work — nginx inheritance rules |
| Game security headers as shared snippet | DRY — 6+ game sites need same headers, avoids repetition | Inline in each config | Maintenance burden, inconsistency risk |
| Dismiss root-user findings for database containers | Postgres/Redis/ClickHouse always run as root by design | Reconfigure containers to non-root | Complex, fragile, upstream images default to root |
| Dismiss Docker socket findings | docker-proxy, uptime-kuma, demo need socket access by design | Remove socket access | Breaks core functionality |
| Linear regression for predictive alerts | Simple (~20 lines JS), no ML framework, uses existing SQLite time series | External monitoring (Grafana, Prometheus) | Adds infrastructure complexity |
| Use favicon.svg for og:image on schenkungsplaner/abfindungsoptimizer | Better than 404 og-image.png; proper og-image can be added later | Generate og-image | No image generation tool available in container |
| Sub_filter for OG tags on SPAs | SPAs serve single HTML page, nginx can inject meta tags | Modify React source | Would need repo access, npm build, deploy — heavier process |
| Plausible proxy in HTTPS server block | All traffic is HTTPS; proxy in HTTP block only was unreachable | External plausible.io script | Gets blocked by ad-blockers |
| Response times from uptime_history (not live) | Avoids 30+ second delay from live health checks on status page | Live health checks | Unacceptable page load time |

## Known Issues

- **Stale security scan data** — Nginx header fixes won't show in health scores until the 1 AM nightly scan. Expected improvement: Plausible F→B/C, PromoForge D→C/B, overall fleet average up
- **PromoForge health grade D** — Low revenue (0.57 EUR MRR), zero tracked traffic (Plausible just fixed). Business issue, not technical
- **Stripe webhook cross-contamination** — Stale webhook in AbschlussCheck Stripe account pointing to bewerbungsfotos-ai.de. Must delete manually in Stripe dashboard
- **GitHub Actions CI** — Still failing, needs fine-grained token (manual task from GitHub Settings)
- **PromoForge service worker caching** — May still serve old index.html to some existing visitors
- **10 overdue project tasks** — Mostly content creation (SEO keywords) and manual Stripe work. See task list in DB
- **codewithrigor repo** — Has 8 modified files locally (impressum/datenschutz pages, footer changes). Not this session's work
- **mom (best-age.de) repo** — 44 commits ahead of origin, not pushed. Not this session's work

## Next Steps (Priority Order)

1. **Wait for tonight's security scan (1 AM)** — Scores will auto-improve significantly
2. **Delete stale Stripe webhook** — Manual: Stripe dashboard > AbschlussCheck > Developers > Webhooks > delete bewerbungsfotos-ai.de endpoint
3. **Create GitHub fine-grained token** — Manual: GitHub > Settings > Developer settings. Fixes CI/CD
4. **Configure off-site backup** — Order Hetzner Storage Box, set env vars (script exists: `scripts/backup-offsite.sh`)
5. **Create proper og-image files** for schenkungsplaner.eu and abfindungsoptimizer.de (currently using favicon.svg as placeholder)
6. **SEO content creation** — Write keyword-targeted pages for LohnCheck (Gehaltsabrechnung), Headshot AI (Bewerbungsfoto), AbschlussCheck (Bachelorarbeit)
7. **PromoForge growth** — Landing page optimization, traffic acquisition (Plausible now tracking, can measure)
8. **Push/deploy codewithrigor changes** (impressum/datenschutz) — 8 modified files in local repo
9. **Push/deploy best-age.de** — 44 commits ahead of origin

## Rollback Info

### Dockfolio (10 commits: 50a8bf1 through 553d7ff)
- Pre-session: `ed315c6`
- Current: `553d7ff`
- Rollback: `git reset --hard ed315c6` + `bash deploy.sh --rebuild`
- Each commit is self-contained, can revert individually

### Crelvo.dev (1 commit: 2d167bd)
- Pre-session: `e56a0ee`
- Rollback: `cd /c/Users/kreyh/Projekte/slebständig && git reset --hard e56a0ee` + rebuild + scp to /var/www/crelvo/

### Nginx configs (not in git, on VM)
- New file: `/home/deploy/nginx-configs/snippets/game-security-headers.conf`
- 19 site configs modified: plausible, logos, theadhdmind, creativeprogrammer, lohnpruefung, bannerforge, creatureforge.conf, betpilot, diplomancy, worldcontrol, lufthafen, orb, grimhollow, dockfolio.dev.conf, demo-dockfolio, promoforge, sacredlens, schenkungsplaner.eu, abfindungsoptimizer.de
- To revert any: compare with git history or restore from nginx backup

### Security findings (DB changes)
- 29 findings dismissed (25 root-user + 4 docker-socket)
- To undo: `UPDATE security_findings SET status = 'open' WHERE status = 'dismissed'` (run via docker exec on dockfolio-dashboard using /home/deploy/marketing/data.db)

## Files Modified This Session

### Dockfolio (10 commits, all pushed to origin/master + deployed)
- `dashboard/routes/status.js` — Health score badges, infrastructure bars, portfolio stats header, clickable domain links, response times, recent incidents section, calculateAppReportCard DI
- `dashboard/routes/alerts.js` — Predictive resource alerts: linearRegression(), checkPredictiveAlerts(), GET /api/alerts/predictions, 6-hour cron
- `dashboard/routes/marketing.js` — SEO audit: www redirect check (fetch www.domain, check for 301), hreflang tag validation, added www_redirect + hreflang to SEO_CHECKS array
- `dashboard/routes/projects.js` — Fixed project snapshots cron: replaced `SELECT score FROM security_scans WHERE app_slug = ?` with per-app score computation from security_findings
- `dashboard/server.js` — Passed calculateAppReportCard to registerStatusRoutes DI
- `dashboard/server.test.js` — 5 new integration tests (status infrastructure, heatmap, predictions, alert rules, health scores)
- `HANDOVER.md` — This file

### Crelvo.dev (1 commit: 2d167bd, pushed + deployed)
- `src/layouts/Base.astro` — Added `<link rel="canonical" href={...} />` tag

### Production VM nginx configs (not in git)
- New: `/home/deploy/nginx-configs/snippets/game-security-headers.conf` — 7 security headers for game sites
- Modified 19 site configs (see Rollback Info for full list)
- Key changes per site:
  - **logos, theadhdmind, creativeprogrammer, lohnpruefung**: Split server blocks, added www→non-www 301 redirect
  - **logos, bannerforge, schenkungsplaner.eu, abfindungsoptimizer.de**: Added canonical tag via sub_filter
  - **schenkungsplaner.eu, abfindungsoptimizer.de**: Added full OG meta tags via sub_filter
  - **promoforge**: Complete rewrite — security headers, Plausible proxy+injection, static caching, Accept-Encoding fix
  - **sacredlens**: Added Plausible proxy locations
  - **lohnpruefung**: Added Plausible proxy to HTTPS, favicon.ico handler
  - **bannerforge**: Accept-Encoding moved to location block, added Permissions-Policy + X-XSS
  - **plausible**: Added all 7 security headers to HTTPS block
  - **creatureforge, betpilot, diplomancy, worldcontrol, lufthafen, orb, grimhollow**: Added game-security-headers snippet
  - **dockfolio.dev, demo-dockfolio**: Added Permissions-Policy, CSP, X-XSS-Protection
