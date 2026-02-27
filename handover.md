# Handover — 2026-02-27 (Session 9)

## 30-Second Summary

Session 9: (1) Analyzed priorities — deprioritized cross-promo injection (zero traffic), focused on launch readiness, (2) Rewrote LAUNCH.md (Show HN + r/selfhosted posts sharpened for impact), (3) Added ACCOUNTS.md to .gitignore, (4) Added Creative Programmer + AgoraHoch3 to crelvo.dev (was missing 2 of 12 projects), updated hero stat 6->12, deployed, (5) Fixed AbschlussCheck admin reprocess timeout bug (last AbortSignal.timeout(30000) in codebase), built + deployed manually to VM (GitHub Actions billing blocked), (6) Generated 45 showcase banners for BannerForge using its own AI pipeline from 5 real portfolio sites, added showcase section to landing page, deployed.

**Most important thing for next session:** Post the launches (LAUNCH.md is ready to copy-paste). Then rotate Telegram token.

## What Was Done

### Completed This Session
- [x] Rewrote LAUNCH.md — Show HN + r/selfhosted posts (story-driven, daily-use focused)
- [x] Added ACCOUNTS.md to .gitignore (has credentials)
- [x] Added Creative Programmer + AgoraHoch3 to crelvo.dev Projects component
- [x] Updated crelvo.dev hero stat: 6 -> 12 Live Products
- [x] Built + deployed crelvo.dev to VM
- [x] Verified all 14 domains are live and responding
- [x] Fixed AbschlussCheck admin reprocess timeout (removed AbortSignal.timeout(30000) from app/api/admin/reprocess/route.ts)
- [x] Built AbschlussCheck from source on VM (GitHub Actions billing issue)
- [x] Swapped AbschlussCheck compose from GHCR image to local build
- [x] Generated 45 showcase banners for BannerForge (5 brands x 3 variants x 3 sizes)
- [x] Added showcase section to BannerForge landing page (8 banners, mixed sizes)
- [x] Deployed BannerForge to VM via deploy.sh
- [x] Committed + pushed: appManager (e784c89, e45b114), abschlusscheck (e35ab4b), bannerforge (b790206), crelvo (564fc58)

### Deliberately Skipped
- **Cross-promo embed.js injection** — sites have near-zero traffic, do after launch drives traffic
- **Container name rename deploy** (appmanager->dockfolio) — risky, not urgent

### NOT Done — Next Session Must Do
- [ ] **Post Show HN** — content in LAUNCH.md, best timing Tue-Thu 9-10AM EST
- [ ] **Post on r/selfhosted** — content in LAUNCH.md
- [ ] **Submit awesome-selfhosted PR** — entry in LAUNCH.md (wait for stars)
- [ ] **Rotate Telegram bot token** — manual: @BotFather `/revoke`, get new token, update `/home/deploy/appmanager/.env` on VM
- [ ] **Fix GitHub Actions billing** — all repos failing CI/CD. Go to github.com/settings/billing
- [ ] **Archive Crelvo/appManager repo** — old private repo, no longer needed
- [ ] **Inject cross-promo embed.js** — after traffic justifies it. Plan in session 8 handover (git log)
- [ ] **Container name rename** — docker-compose.yml has appmanager->dockfolio NOT deployed. See warning below.

## Key Decisions Made This Session

1. **Deprioritized cross-promo injection** — zero traffic means zero impact. Launch posts are the bottleneck.
2. **Manual VM deploy for AbschlussCheck** — GitHub Actions billing blocked. Built from source at `/opt/abschlusscheck/src/`, swapped compose to `image: abschlusscheck:latest` (local, not GHCR).
3. **BannerForge showcase generated from own pipeline** — used `scripts/generate-showcase.ts` which calls scraper + Claude AI copy + Satori renderer directly. Bypasses auth/quota. Rerunnable anytime.

## CRITICAL WARNING: docker-compose.yml Container Name Change

The appManager local docker-compose.yml renames containers from `appmanager-*` to `dockfolio-*`. **NOT deployed to VM.** Deploying will break Uptime Kuma monitors and nginx proxy_pass. See session 8 handover (in git history) for safe deploy steps.

## CRITICAL WARNING: AbschlussCheck Compose Changed

`/opt/abschlusscheck/docker-compose.prod.yml` was changed from `image: ghcr.io/konradreyhe/abschlusscheck:latest` to `image: abschlusscheck:latest`. Future deploys must build locally on VM from `/opt/abschlusscheck/src/` until GitHub Actions billing is fixed.

## Git State

| Repo | Branch | Latest Commit | Remote |
|------|--------|--------------|--------|
| appManager | master | e45b114 | pushed to dockfolio |
| abschlusscheck | main | e35ab4b | pushed to origin |
| bannerforge | main | b790206 | pushed to origin |
| slebständig (crelvo) | master | 564fc58 | pushed to origin |

All repos: working tree clean, all pushed.

## Files Modified This Session

### appManager repo
| File | What Changed |
|------|-------------|
| LAUNCH.md | Rewrote Show HN + r/selfhosted posts |
| .gitignore | Added ACCOUNTS.md |
| handover.md | Updated for session 9 |

### Crelvo website (C:\Users\kreyh\Projekte\slebständig)
| File | What Changed |
|------|-------------|
| src/components/Projects.astro | Added Creative Programmer + AgoraHoch3 (12 projects) |
| src/components/Hero.astro | 6 -> 12 Live Products |

### AbschlussCheck (C:\Users\kreyh\Projekte\abschlusscheck)
| File | What Changed |
|------|-------------|
| app/api/admin/reprocess/route.ts | Removed AbortSignal.timeout(30000), fire-and-forget |

### BannerForge (C:\Users\kreyh\Projekte\ad\bannerforge)
| File | What Changed |
|------|-------------|
| src/app/page.tsx | Added showcase section with 8 banner grid |
| public/showcase/ | NEW — 45 AI-generated PNG banners (5 brands) |
| scripts/generate-showcase.ts | NEW — Showcase generation script |

### VM Changes (not in git)
| File | What Changed |
|------|-------------|
| /opt/abschlusscheck/docker-compose.prod.yml | image changed to local build |
| /opt/abschlusscheck/src/ | NEW — cloned source for local builds |
| /var/www/crelvo/* | Updated with 12 projects |

## Key URLs

| Resource | URL |
|----------|-----|
| Dashboard | https://admin.crelvo.dev |
| Dockfolio landing | https://dockfolio.dev |
| BannerForge | https://bannerforge.app |
| Crelvo | https://crelvo.dev |
| GitHub (Dockfolio) | https://github.com/dockfolio/dockfolio |
