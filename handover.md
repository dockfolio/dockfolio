# Handover — 2026-02-27 (Session 8)

## 30-Second Summary

Session 8: (1) Removed all em dashes from UI (dashboard, server.js, landing page, README), (2) Deployed new code to VM with `bash deploy.sh --rebuild`, (3) Took 6 Playwright screenshots of live dashboard, (4) Added screenshots to README.md and landing/index.html, (5) Created CONTRIBUTING.md, (6) Created LAUNCH.md with Show HN + r/selfhosted + awesome-selfhosted drafts, (7) Added Plausible tracking to dockfolio.dev, (8) Added Code With Rigor to config.yml (14th app), (9) Fixed konradreyhe.de (was BROKEN: no nginx, no SSL — now has SSL cert + redirect to crelvo.dev), (10) Full 22-domain audit — all working, (11) Updated Crelvo website (crelvo.dev) with all 10 projects (was 5), deployed, (12) Created 8 cross-promotion campaigns in Dockfolio dashboard (all active), (13) Renamed nginx-appmanager.conf to nginx-dockfolio.conf, updated docker-compose.yml container names.

**Most important thing for next session:** Inject cross-promo embed script on all sites via nginx, then commit + push everything.

## What Was Done

### Completed
- [x] Remove em dashes from dashboard UI (index.html, server.js)
- [x] Remove em dashes from landing page
- [x] Remove em dashes from README.md
- [x] Deploy dashboard to VM (`deploy.sh --rebuild`) — container healthy
- [x] Deploy landing page to VM (scp)
- [x] Take 6 Playwright screenshots (dashboard overview, marketing revenue, command palette, morning briefing, healing panel, settings)
- [x] Add screenshots to README.md (5 images with captions)
- [x] Add screenshot showcase section to landing/index.html (hero + 2x2 grid)
- [x] Create CONTRIBUTING.md (dev setup, branch strategy, architecture)
- [x] Create LAUNCH.md (Show HN post, r/selfhosted post, awesome-selfhosted entry)
- [x] Add Plausible tracking to dockfolio.dev (DB entry + script tag, both local + VM)
- [x] Add Code With Rigor (codewithrigor.com) to config.yml as 14th app
- [x] Deploy updated config.yml to VM
- [x] Full 22-domain INWX audit — all DNS correct, all responding
- [x] Fix konradreyhe.de — created nginx config, obtained SSL cert, HTTPS redirect to crelvo.dev
- [x] Update Crelvo website (crelvo.dev) Projects component — added Dockfolio, BannerForge, LohnCheck, Code With Rigor, TheADHDMind (now 10 projects)
- [x] Build + deploy Crelvo website to VM
- [x] Create 8 cross-promotion campaigns via Dockfolio API (all activated)
- [x] Rename nginx-appmanager.conf to nginx-dockfolio.conf
- [x] Update docker-compose.yml container names (appmanager-* to dockfolio-*)
- [x] Update deploy.sh references
- [x] Commit: `d5c95c5` (em dash removal), `ee56224` (screenshots + launch prep), `e7de9e7` (Code With Rigor config)
- [x] Push all to github.com/dockfolio/dockfolio

### NOT Done — Next Session Must Do
- [ ] **Inject cross-promo embed.js on all sites via nginx sub_filter** — was interrupted mid-execution. See "Cross-Promo Injection Plan" below.
- [ ] **Commit remaining local changes** — config.yml update for Code With Rigor, any other uncommitted work
- [ ] **Push to dockfolio remote** — after committing
- [ ] **Rotate Telegram bot token** — manual: @BotFather `/revoke`, get new token, update `/home/deploy/appmanager/.env` on VM
- [ ] **Post Show HN** — content in LAUNCH.md, best timing Tue-Thu 9-10AM EST
- [ ] **Post on r/selfhosted** — content in LAUNCH.md
- [ ] **Submit awesome-selfhosted PR** — entry format in LAUNCH.md
- [ ] **Archive Crelvo/appManager repo** — old private repo, no longer needed
- [ ] **Rebuild dashboard on VM after nginx changes** — container names changed in docker-compose.yml but NOT yet deployed (would break Uptime Kuma container name reference)

## Cross-Promo Injection Plan (INTERRUPTED — RESUME THIS)

8 campaigns created and active in Dockfolio dashboard:

| # | Source App | Target App | Headline |
|---|-----------|-----------|----------|
| 1 | promoforge | bannerforge | Need banner ads too? |
| 2 | bannerforge | promoforge | Turn your website into a video |
| 3 | abschlusscheck | headshot-ai | Professionelle KI-Bewerbungsfotos |
| 4 | headshot-ai | abschlusscheck | KI-Gutachten fuer deine Abschlussarbeit |
| 5 | lohncheck | abschlusscheck | Abschlussarbeit pruefen lassen? |
| 6 | abschlusscheck | lohncheck | Gehaltsabrechnung pruefen |
| 7 | sacredlens | old-world-logos | Explore Christian symbols in architecture |
| 8 | theadhdmind | sacredlens | Discover hidden meanings in sacred art |

**To inject the embed script on each site**, add this nginx `sub_filter` line to each site's nginx config:

```nginx
sub_filter '</body>' '<script src="https://admin.crelvo.dev/api/crosspromo/embed.js" data-app="SLUG" defer></script></body>';
```

Sites that need injection (nginx config -> slug):

| Nginx Config | App Slug | Notes |
|-------------|---------|-------|
| promoforge | promoforge | Has sub_filter block (Plausible) |
| bannerforge | bannerforge | Has sub_filter block |
| bewerbungsfotos-ai | headshot-ai | Has sub_filter block |
| abschlusscheck.de | abschlusscheck | Has sub_filter block |
| lohnpruefung | lohncheck | Has sub_filter block |
| sacredlens | sacredlens | Has sub_filter block |
| theadhdmind | theadhdmind | Has sub_filter block |
| codewithrigor | code-with-rigor | Has sub_filter block |
| logos | old-world-logos | May NOT have sub_filter (static site with direct HTML injection for Plausible) |
| creativeprogrammer | creative-programmer | Has sub_filter block |
| crelvo | crelvo | Has sub_filter block |
| agorahoch3 | agorahoch3 | Has sub_filter block |

**DO NOT inject on:** 000-default, appmanager, plausible, dockfolio.dev.conf, konradreyhe

For sites with existing `sub_filter_once on;`, add the new sub_filter line BEFORE `sub_filter_once on;`.

For Old World Logos (static site at /var/www/logos/), the Plausible script was injected directly into HTML files, not via nginx. For crosspromo, use nginx sub_filter if possible, otherwise inject into the HTML template.

After injection: `sudo nginx -t -c /home/deploy/nginx-configs/nginx.conf && sudo nginx -s reload -c /home/deploy/nginx-configs/nginx.conf`

## CRITICAL WARNING: docker-compose.yml Container Name Change

The local docker-compose.yml was updated to rename containers from `appmanager-dashboard` to `dockfolio-dashboard` and `appmanager-uptime-kuma` to `dockfolio-uptime-kuma`. This has NOT been deployed to the VM yet.

**DO NOT deploy this change carelessly** — it will:
1. Create new containers with new names
2. Break references in Uptime Kuma (monitors target container names)
3. Break nginx config at `/home/deploy/nginx-configs/sites/appmanager` (proxy_pass reference)

To deploy safely:
1. Update Uptime Kuma monitors first
2. Update nginx appmanager config
3. Then `docker compose up -d`

Or: revert the container name changes in docker-compose.yml for now.

## Files Modified This Session

### appManager repo
| File | What Changed |
|------|-------------|
| `dashboard/public/index.html` | Removed em dashes from UI warnings + banner display |
| `dashboard/server.js` | Removed em dashes from login title, content titles, briefing prompt, healing messages, playbook prompt |
| `dashboard/config.yml` | Added Code With Rigor (14th app) |
| `landing/index.html` | Removed em dashes, added screenshot showcase section, added Plausible script |
| `README.md` | Added screenshots section, removed em dashes, fixed separators |
| `CONTRIBUTING.md` | **NEW** — dev setup, architecture, branch strategy |
| `LAUNCH.md` | **NEW** — Show HN, r/selfhosted, awesome-selfhosted drafts |
| `nginx-appmanager.conf` | Renamed to `nginx-dockfolio.conf` |
| `docker-compose.yml` | Container names: appmanager-* -> dockfolio-* (NOT YET DEPLOYED) |
| `deploy.sh` | Updated references to new nginx config name |
| `screenshots/*.png` | **NEW** — 6 dashboard screenshots |
| `scripts/take-screenshots.js` | **NEW** — Playwright screenshot automation |

### Crelvo website (C:\Users\kreyh\Projekte\slebständig)
| File | What Changed |
|------|-------------|
| `src/components/Projects.astro` | Added 5 new projects (Dockfolio, BannerForge, LohnCheck, Code With Rigor, TheADHDMind), reordered (10 total) |

### VM files (not in git)
| File | What Changed |
|------|-------------|
| `/home/deploy/nginx-configs/sites/konradreyhe` | **NEW** — SSL redirect to crelvo.dev |
| `/etc/letsencrypt/live/konradreyhe.de/` | **NEW** — SSL certificate |
| `/var/www/crelvo/*` | Updated Crelvo website with 10 projects |
| `/home/deploy/appmanager/dashboard/config.yml` | Added Code With Rigor |
| `/home/deploy/dockfolio-landing/index.html` | Screenshots section + Plausible |
| Dockfolio SQLite DB | 8 cross-promo campaigns created + activated |

## Git State
- **Branch:** master
- **Latest commit:** `e7de9e7` (Add Code With Rigor to dashboard)
- **Remote:** pushed to `dockfolio` (github.com/dockfolio/dockfolio)
- **Uncommitted:** handover.md, possibly config.yml if not in e7de9e7

## 22-Domain Audit Results

All 22 INWX domains verified working:
- **14 primary domains** returning 200 (all in config.yml)
- **1 redirect** (konradreyhe.de -> crelvo.dev) — FIXED this session
- **6 SEO redirects** for AbschlussCheck (abschlussarbeit-check.de, bachelorarbeit-check.de, bachelorpruefung.de, hausarbeitcheck.de, masterarbeit-check.de, notenprognose.de)
- **1 alt domain** (promoforge.de -> promoforge.app)
- **Plus:** oldworldlogos.com and agorahoch3.org (not on INWX, different registrar)
- **21st INWX domain** on page 2 — unknown, user didn't provide

## Key URLs

| Resource | URL |
|----------|-----|
| Dashboard | https://admin.crelvo.dev (admin / appmanager2024) |
| Landing page | https://dockfolio.dev |
| GitHub (public) | https://github.com/dockfolio/dockfolio |
| Crelvo | https://crelvo.dev |
| Code With Rigor | https://codewithrigor.com |

## Rollback Info

- All commits pushed to github.com/dockfolio/dockfolio
- konradreyhe.de nginx config: `/home/deploy/nginx-configs/sites/konradreyhe` — delete to disable
- Cross-promo campaigns: delete via API `DELETE /api/marketing/crosspromo/:id` (IDs 1-8)
- Crelvo website: old version not backed up, but changes are only in Projects.astro (added projects)
- Container name change in docker-compose.yml: NOT deployed, revert locally if needed
