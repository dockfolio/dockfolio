# Handover — 2026-02-27 (Session 10)

## 30-Second Summary

Session 10: Deployed banner advertisement injection across all 12 user-facing websites via nginx `sub_filter`. Zero code changes to any site — pure nginx-level injection. Each site proxies `/api/banners/` to the Dockfolio dashboard (localhost:9091) for same-origin requests, avoiding CSP issues. Added `GET /api/banners/injection-status` endpoint + UI indicator in Banners tab. Created and verified a test banner on theadhdmind.org (view/click tracking works). Also did deep monetization research — conclusion: Dockfolio should be used as a cross-promotion engine for the existing SaaS portfolio, not monetized directly until it has community traction (500+ stars).

**Most important thing for next session:** Post the launches (LAUNCH.md is ready). The banner system is fully deployed and controllable from the dashboard — use it to cross-promote your SaaS apps once traffic arrives.

## Session Focus

1. Deploy banner/cross-promotion embed.js to all websites
2. Make banners 100% controllable from the Dockfolio dashboard
3. Analyze monetization strategy for Dockfolio

## Completed

- [x] Verified nginx `ngx_http_sub_module` is available on VM
- [x] Read and analyzed all 12 site nginx configs
- [x] Created Python deployment script (`scripts/deploy-banner-injection.py`)
- [x] Deployed `sub_filter` injection to all 12 user-facing sites
- [x] Added `/api/banners/` proxy location to all 12 sites (same-origin, no CSP issues)
- [x] Fixed codewithrigor.com proxy (needed `^~` prefix to beat regex location match)
- [x] Replaced old `crelvo-banner.js` on bewerbungsfotos-ai.de with new embed.js system
- [x] Added `GET /api/banners/injection-status` endpoint to server.js
- [x] Added "Embed Status" UI panel in Banners tab (index.html)
- [x] Deployed dashboard to VM (`bash deploy.sh --rebuild`)
- [x] Verified 12/12 sites: embed.js injected AND proxy returning correct data
- [x] Created test banner "Try PromoForge - AI Video Ads" (id=4, type=image_url, 728x90)
- [x] Created placement on theadhdmind (id=2, status=active)
- [x] Verified end-to-end: view tracking (1 view), click redirect (302 -> promoforge.app), click tracking (1 click)
- [x] Deep monetization research (Coolify, Plausible, Umami, Uptime Kuma, Cal.com, sponsorware models)

## Not Done — Carry Forward from Session 9

- [ ] **Post Show HN** — content in LAUNCH.md, best timing Tue-Thu 9-10AM EST
- [ ] **Post on r/selfhosted** — content in LAUNCH.md
- [ ] **Rotate Telegram bot token** — manual: @BotFather `/revoke`, update `/home/deploy/appmanager/.env`
- [ ] **Fix GitHub Actions billing** — all repos failing CI/CD
- [ ] **Archive Crelvo/appManager repo** — old private repo
- [ ] **Container name rename** — docker-compose.yml has appmanager->dockfolio NOT deployed

## Decisions Made

| Decision | Why | Alternatives Considered |
|----------|-----|------------------------|
| nginx `sub_filter` injection (not per-site code changes) | Zero code changes to any of 13 sites. Works across all tech stacks. One-time setup. | Editing each site's HTML manually, dashboard-managed nginx configs |
| Same-origin proxy (`/api/banners/` -> :9091) instead of cross-origin | Avoids CSP changes on all sites. Several sites have strict CSP. | Updating CSP headers on all sites, using CORS |
| `^~` prefix on codewithrigor proxy location | Its `location ~* \.(js|css|...)$` regex was catching `/api/banners/embed.js` | Exact match locations, reordering location blocks |
| Don't monetize Dockfolio directly yet | Zero community/stars. Addressable market is tiny. Coolify could replicate features in a week. | Cloud tier ($9-19/mo), sponsorware, premium content |
| Use Dockfolio as cross-promotion engine | Banner system is now deployed on all 12 sites. Drive traffic between own SaaS apps. | Building cloud version, seeking VC |

## Monetization Research Summary

- **Coolify:** 51k stars, $15.7k/mo (solo dev), cloud model ($5/server/mo), no feature gating
- **Plausible:** 21k stars, $3.1M ARR (2 people), open-core + cloud, gates funnels/revenue metrics
- **Uptime Kuma:** 62k stars, $1,700/YEAR on Open Collective. Donations don't work.
- **Realistic Y1 revenue for Dockfolio:** $0-200/mo. Not viable as standalone business yet.
- **Best use:** Cross-promo engine for portfolio + credibility/content marketing for Crelvo brand
- **Revisit monetization at 500+ stars** — then consider Plausible model (cloud + feature gating)

## Known Issues

- **nginx warnings (pre-existing):** Duplicate MIME type and protocol redefinition warnings on several sites. Not caused by our changes. Cosmetic only.
- **Test banner live on theadhdmind.org:** The "Try PromoForge" banner (placement id=2) is active. Pause it from dashboard if unwanted.

## How the Banner System Works Now

1. nginx injects `<script src="/api/banners/embed.js" data-app="SLUG"></script>` before `</body>` on all 12 sites
2. Each site's nginx proxies `/api/banners/*` to `http://127.0.0.1:9091/api/banners/*` (dashboard container)
3. embed.js fetches `/api/banners/serve?app=SLUG` — if no active placements, returns null (no visual effect)
4. Dashboard Banners tab: create banners, add placements per app, activate/pause, view/click stats
5. Control is 100% from dashboard — no code changes needed on any site

### Site-to-Slug Mapping

| Site | Slug | Type |
|------|------|------|
| promoforge.app | `promoforge` | proxy |
| bannerforge.app | `bannerforge` | proxy |
| bewerbungsfotos-ai.de | `headshot-ai` | proxy |
| abschlusscheck.de | `abschlusscheck` | proxy |
| lohnpruefung.de | `lohncheck` | static |
| sacredlens.de | `sacredlens` | static |
| theadhdmind.org | `theadhdmind` | static |
| thecreativeprogrammer.dev | `creative-programmer` | static |
| crelvo.dev | `crelvo` | static |
| oldworldlogos.com | `old-world-logos` | static |
| codewithrigor.com | `code-with-rigor` | static |
| agorahoch3.org | `agorahoch3` | static |

## Rollback Info

**Banner injection rollback (nginx):**
```bash
ssh deploy@91.99.104.132
cp -r /home/deploy/nginx-configs/sites-backup-20260227-151517/* /home/deploy/nginx-configs/sites/
sudo nginx -t -c /home/deploy/nginx-configs/nginx.conf
sudo nginx -s reload -c /home/deploy/nginx-configs/nginx.conf
```

**Dashboard rollback:** Last clean commit is `ef030c6`. Current changes are additive only (injection-status endpoint + UI).

## Files Modified This Session

### appManager repo (local, NOT committed)
| File | What Changed |
|------|-------------|
| `dashboard/server.js` | Added `GET /api/banners/injection-status` endpoint (~25 lines after line 3687) |
| `dashboard/public/index.html` | Added Embed Status UI panel + `checkInjectionStatus()` JS function, tab auto-loads on Banners tab |
| `scripts/deploy-banner-injection.py` | NEW — Python script that injects sub_filter + proxy into all 12 nginx configs |
| `scripts/deploy-banner-injection.sh` | NEW — Bash version (not used, Python version was used instead) |
| `handover.md` | Updated for session 10 |

### VM Changes (not in git)
| File | What Changed |
|------|-------------|
| `/home/deploy/nginx-configs/sites/*` | 12 site configs: added `sub_filter` for embed.js + `location /api/banners/` proxy block |
| `/home/deploy/nginx-configs/sites-backup-20260227-151517/` | Pre-change backup of all nginx configs |

## Next Steps (Priority Order)

1. **Commit session 10 changes** — `git add` the 4 modified/new files, commit
2. **Post Show HN** — LAUNCH.md has copy-paste ready content (Tue-Thu 9-10AM EST best)
3. **Post r/selfhosted** — LAUNCH.md ready
4. **Create cross-promo banners** — Now that injection works, create banners for each SaaS app and place them on other sites (e.g., PromoForge banner on AbschlussCheck, BannerForge banner on TheADHDMind)
5. **Rotate Telegram bot token** — @BotFather `/revoke`
6. **Fix GitHub Actions billing**

## Git State

| Repo | Branch | Status | Remote |
|------|--------|--------|--------|
| appManager | master | 4 uncommitted files | last push: ef030c6 |

## Key URLs

| Resource | URL |
|----------|-----|
| Dashboard | https://admin.crelvo.dev |
| Dockfolio landing | https://dockfolio.dev |
| GitHub (Dockfolio) | https://github.com/dockfolio/dockfolio |
| Banner test (live) | https://theadhdmind.org (has active PromoForge banner) |
