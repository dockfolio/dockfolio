# Handover — 2026-02-27 (Session 9)

## 30-Second Summary

Session 9: (1) Analyzed priorities and deprioritized cross-promo injection (zero traffic = zero impact), (2) Rewrote LAUNCH.md - Show HN and r/selfhosted posts sharpened for impact (story-driven, focused on daily-use features), (3) Added ACCOUNTS.md to .gitignore (contains credentials), (4) Added Creative Programmer + AgoraHoch3 to crelvo.dev (was missing 2 of 12 projects), (5) Updated crelvo.dev hero stat from "6 Live Products" to "12", (6) Fixed project descriptions to match actual site content, (7) Built + deployed crelvo.dev to VM, (8) Verified all 14 domains are live, (9) Pushed all commits to github.com/dockfolio/dockfolio.

**Most important thing for next session:** Post the launches (LAUNCH.md is ready). Then rotate Telegram token.

## What Was Done

### Completed This Session
- [x] Sharpened LAUNCH.md (Show HN + r/selfhosted posts rewritten for impact)
- [x] Added ACCOUNTS.md to .gitignore (has Stripe IDs, emails, credentials)
- [x] Added Creative Programmer (thecreativeprogrammer.dev) to crelvo.dev projects
- [x] Added AgoraHoch3 (agorahoch3.org) to crelvo.dev projects
- [x] Fixed project descriptions to match actual site content
- [x] Updated crelvo.dev hero stat: 6 -> 12 Live Products
- [x] Built + deployed crelvo.dev to VM (all 8 languages rebuilt)
- [x] Verified all 14 domains are live and responding
- [x] Committed: `e784c89` (launch posts + gitignore)
- [x] Pushed to github.com/dockfolio/dockfolio

### Deliberately Skipped
- **Cross-promo embed.js injection** — deprioritized. Sites have near-zero traffic, cross-promoting between empty rooms does nothing. Do this after launch drives traffic.
- **Container name rename deploy** — still risky, still not urgent. See warning below.

### NOT Done — Next Session Must Do
- [ ] **Post Show HN** — content in LAUNCH.md, best timing Tue-Thu 9-10AM EST
- [ ] **Post on r/selfhosted** — content in LAUNCH.md
- [ ] **Submit awesome-selfhosted PR** — entry format in LAUNCH.md (wait for some stars first)
- [ ] **Rotate Telegram bot token** — manual: @BotFather `/revoke`, get new token, update `/home/deploy/appmanager/.env` on VM
- [ ] **Archive Crelvo/appManager repo** — old private repo, no longer needed
- [ ] **Fix AbschlussCheck timeout bug** — auto-refunds large documents (68+ pages), revenue-killing bug. Root cause in `/c/Users/kreyh/Projekte/abschlusscheck/app/api/webhook/route.ts` line 68 (30s timeout too short). See session 6 handover for full analysis.
- [ ] **Inject cross-promo embed.js** — after traffic justifies it. Plan still in session 8 handover.
- [ ] **Container name rename** — docker-compose.yml has appmanager->dockfolio rename NOT deployed. See warning below.

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

## Git State
- **Branch:** master
- **Latest commit:** `e784c89` (Sharpen launch posts and gitignore ACCOUNTS.md)
- **Remote:** pushed to `dockfolio` (github.com/dockfolio/dockfolio)
- **Working tree:** clean

## Files Modified This Session

### appManager repo
| File | What Changed |
|------|-------------|
| `LAUNCH.md` | Rewrote Show HN + r/selfhosted posts, fixed awesome-selfhosted category |
| `.gitignore` | Added ACCOUNTS.md |
| `handover.md` | Updated for session 9 |

### Crelvo website (C:\Users\kreyh\Projekte\slebständig)
| File | What Changed |
|------|-------------|
| `src/components/Projects.astro` | Added Creative Programmer + AgoraHoch3 (now 12 projects) |
| `src/components/Hero.astro` | Changed "6" to "12" Live Products |

## Key URLs

| Resource | URL |
|----------|-----|
| Dashboard | https://admin.crelvo.dev (admin / appmanager2024) |
| Landing page | https://dockfolio.dev |
| GitHub (public) | https://github.com/dockfolio/dockfolio |
| Crelvo | https://crelvo.dev |
