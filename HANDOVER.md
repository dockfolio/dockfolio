# Handover

**Date:** 2026-03-30 (Session 4)

## Summary

Session 4 focused on SEO fixes from Google Search Console warnings, security hardening across all nginx sites, new Dockfolio features, and bug fixes. Fixed www→non-www redirects on 4 sites, added canonical tags to 5 sites, added security headers to 9 nginx configs, created predictive resource alerts with linear regression, added health score badges and infrastructure bars to the public status page, enhanced the SEO audit with www redirect and hreflang checks, fixed a cron failure in project snapshots, and dismissed 29 expected security findings. Pruned Docker build cache (79% → 58%). All 24 public sites now pass all critical security header checks. All 14 main sites pass canonical + www redirect checks.

**Most important for next session:** System is stable and fully healthy. Remaining items are manual tasks (Stripe webhook, GitHub token, Hetzner backup) and business-level improvements (content creation for SEO keywords, PromoForge growth). Tonight's 1 AM security scan will show significantly improved scores across the fleet.

## Completed

### Google Search Console SEO Fixes
- [x] www→non-www 301 redirects: oldworldlogos.com, theadhdmind.org, thecreativeprogrammer.dev, lohnpruefung.de
- [x] Canonical tags via Astro source: crelvo.dev (Base.astro, commit 2d167bd, built + deployed)
- [x] Canonical tags via nginx sub_filter: oldworldlogos.com, bannerforge.app, schenkungsplaner.eu, abfindungsoptimizer.de
- [x] BannerForge sub_filter fix: moved `Accept-Encoding ""` into `location /` block (was at server level, not inherited by location with own proxy_set_header directives)
- [x] 14/14 main sites verified: all pass canonical + www redirect checks
- [x] lohnpruefung.de favicon.ico 404 silenced (nginx returns 204)

### Security Header Hardening
- [x] Created shared `/home/deploy/nginx-configs/snippets/game-security-headers.conf` snippet
- [x] Plausible Analytics: added all 7 security headers to HTTPS block (was only on HTTP redirect block)
- [x] creatureforge, betpilot, diplomancy: added game-security-headers snippet (had zero headers)
- [x] worldcontrol, lufthafen: added game-security-headers snippet (had partial headers)
- [x] orb: added game-security-headers snippet
- [x] grimhollow: replaced single HSTS header with full snippet
- [x] dockfolio.dev, demo.dockfolio.dev: added Permissions-Policy, CSP, X-XSS-Protection
- [x] bannerforge: added Permissions-Policy, X-XSS-Protection
- [x] **24/24 public sites now pass HSTS + CSP + Permissions-Policy checks**

### Security Finding Dismissals
- [x] 25 "Running as root user" findings dismissed (postgres, redis, clickhouse — by design)
- [x] 4 "Docker socket mounted" / "privileged mode" findings dismissed (docker-proxy, uptime-kuma, demo — by design)
- [x] 0 critical findings remaining (was 4)

### New Dockfolio Features
- [x] Health score badges (A-F grade) on public `/status` page — uses calculateAppReportCard
- [x] Infrastructure health bars on `/status` — CPU/Memory/Disk with color-coded progress bars
- [x] Predictive resource alerts — 7-day linear regression on disk/memory, Telegram alerts when projected to hit 90%, new `GET /api/alerts/predictions` endpoint, 6-hour cron
- [x] SEO audit enhanced — added www redirect check (flags sites serving www without redirect) and hreflang tag validation

### Bug Fixes
- [x] Fixed "Project snapshots" cron failure — `SELECT score FROM security_scans` → wrong column name (should be `overall_score`) and wrong table (scans are system-wide, not per-app). Now computes per-app score from `security_findings`.

### Tests
- [x] 5 new integration tests: status page infrastructure section, heatmap API, predictions API, alert rules, health scores
- [x] 119 unit tests + 5 new integration tests all pass

### Infrastructure
- [x] Docker build cache pruned: 79% → 58% disk (freed ~33GB)
- [x] All 37 containers healthy

## In Progress

Nothing in progress. All work committed and deployed.

## Decisions Made

| Decision | Why | Alternatives Rejected |
|----------|-----|----------------------|
| Canonical tags via nginx sub_filter for sites without local repos | Can't modify source code for oldworldlogos (no repo) | N/A |
| Accept-Encoding "" in location block, not server block | nginx doesn't inherit parent proxy_set_header when location has its own | Server-level setting (doesn't work) |
| Game security headers as shared snippet | DRY — 6+ game sites need same headers, avoids repetition | Inline in each config |
| Dismiss root-user findings for database containers | Postgres/Redis/ClickHouse always run as root by design | Reconfigure containers (complex, fragile) |
| Dismiss Docker socket findings | docker-proxy, uptime-kuma, demo need socket access by design | Remove socket access (breaks functionality) |
| Linear regression for predictive alerts | Simple, no ML framework needed, ~20 lines of JS | External monitoring service (complexity) |

## Known Issues

- **Stale security scan data** — Nginx header fixes won't show in health scores until the 1 AM nightly scan
- **PromoForge D grade** — Low revenue (0.57 EUR MRR), zero tracked traffic, 16 container findings. Business issue, not technical
- **Plausible Analytics F grade** — Will improve significantly after tonight's scan (4 header findings fixed + root-user dismissed)
- **Stripe webhook cross-contamination** — Still needs manual fix in Stripe dashboard (from session 3)
- **GitHub Actions CI** — Still failing, needs fine-grained token (manual task)
- **PromoForge service worker caching** — May still serve old index.html to existing visitors
- **10 overdue project tasks** — Mostly content creation (SEO keywords) and manual Stripe work

## Next Steps (Priority Order)

1. **Wait for tonight's security scan** — Scores will auto-improve at 1 AM
2. **Delete stale Stripe webhook** — Manual: Stripe dashboard > AbschlussCheck > Webhooks
3. **Create GitHub fine-grained token** — Manual: GitHub > Settings > Developer settings
4. **Configure off-site backup** — Order Hetzner Storage Box, run `scripts/backup-offsite.sh`
5. **SEO content creation** — Write keyword-targeted pages for LohnCheck (Gehaltsabrechnung), Headshot AI (Bewerbungsfoto), AbschlussCheck (Bachelorarbeit)
6. **PromoForge growth** — Landing page optimization, traffic acquisition

## Rollback Info

### Dockfolio (7 commits this session: 50a8bf1 through current)
- Pre-session: `ed315c6`
- Current: see `git log --oneline -7`
- Rollback: `git reset --hard ed315c6` + `bash deploy.sh --rebuild`

### Crelvo.dev (1 commit: 2d167bd)
- Pre-session: `e56a0ee`
- Rollback: `git reset --hard e56a0ee` + rebuild + deploy to /var/www/crelvo/

### Nginx configs (not in git, on VM)
- `/home/deploy/nginx-configs/snippets/game-security-headers.conf` — New shared snippet
- Sites modified: plausible, logos, theadhdmind, creativeprogrammer, lohnpruefung, bannerforge, creatureforge.conf, betpilot, diplomancy, worldcontrol, lufthafen, orb, grimhollow, dockfolio.dev.conf, demo-dockfolio

### Security findings (DB changes)
- 29 findings dismissed (25 root-user + 4 docker-socket). To undo: `UPDATE security_findings SET status = 'open' WHERE status = 'dismissed'`

## Files Modified This Session

### Dockfolio (7 commits, all pushed + deployed)
- `dashboard/routes/status.js` — Health score badges, infrastructure bars, calculateAppReportCard DI
- `dashboard/routes/alerts.js` — Predictive resource alerts (linear regression, cron, API endpoint)
- `dashboard/routes/marketing.js` — SEO audit: www redirect check, hreflang validation
- `dashboard/routes/projects.js` — Fixed project snapshots cron (wrong column name)
- `dashboard/server.js` — Passed calculateAppReportCard to status routes
- `dashboard/server.test.js` — 5 new integration tests
- `HANDOVER.md` — This file

### Crelvo.dev (1 commit: 2d167bd, pushed + deployed)
- `src/layouts/Base.astro` — Added `<link rel="canonical">` tag

### Production VM (nginx configs, not in git)
- New: `/home/deploy/nginx-configs/snippets/game-security-headers.conf`
- Modified: 15 site configs (see Rollback Info section)
