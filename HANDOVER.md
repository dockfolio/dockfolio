# Session Handover

**Date:** 2026-04-09 (Session 12)
**Duration:** ~45 minutes
**Goal:** Read session 11 handover, remove all games from crelvo.dev and VM, remove all cross-promotion ads (crosslinks + banners) from all websites, update Orb to OrbEdge.

## Summary

Session focused on three major cleanup operations across the entire portfolio.

First, removed all 8 standalone browser games (Grimhollow, Diplomancy, Lufthafen, World Control, CreatureForge, Kettenreaktion, Hunting Dragons, Forgelands) plus urlGame from production. This meant: removing the games section from crelvo.dev, stopping 4 game containers on the VM, deleting 9 game nginx configs, removing 7 game entries from VM config.yml, deleting the Kettenreaktion backend API route, removing game entries from the social autopilot (app definitions + 5 subreddit monitors), and deleting crosslinks injection scripts. Games will now be developed locally only, with potential future Steam releases.

Second, removed ALL cross-promotion advertising from every website (21+ sites). This included the "Also by Crelvo:" crosslinks widget bar and the BannerForge cross-promo banner ads. Both were injected via nginx `sub_filter` directives. Cleaned 23 nginx configs on the VM. Also removed the crosslinks widget.js endpoint from the dashboard code. Found 4 sites (abschlusscheck, promoforge, bewerbungsfotos-ai, bannerforge) had embed.js hardcoded in their app source code — fixed those in local repos and committed. The nginx proxy_pass blocks for banners were also removed, so even the hardcoded references 404 now.

Third, removed the "Client Work" section (AgoraHoch3) from crelvo.dev and renamed Orb to OrbEdge with the new domain orbedge.de.

## What Got Done

- [x] **All games removed from crelvo.dev** — Games array + entire Games Section HTML removed from Projects.astro
- [x] **All games removed from VM** — 4 containers stopped, 9 nginx configs deleted, 7 config.yml entries removed, game directories cleaned
- [x] **Kettenreaktion backend removed** — Deleted `dashboard/routes/kettenreaktion.js`, removed import/registration/CSRF/public paths from server.js
- [x] **Game entries removed from social autopilot** — 7 game app definitions + urlGame removed, 5 game subreddit monitors removed
- [x] **Game crosslinks scripts deleted** — `inject-crosslinks-games.py` and `inject-crosslinks-proxy.py` both deleted
- [x] **Client Work section removed from crelvo.dev** — clientWork array + HTML section removed
- [x] **Orb renamed to OrbEdge** — Updated to `orbedge.de` on crelvo.dev
- [x] **All crosslinks removed from all sites** — nginx sub_filter for `crosslinks/widget.js` removed from 23 configs
- [x] **All banner ads removed from all sites** — nginx sub_filter for `banners/embed.js` removed from 23 configs, proxy_pass blocks removed
- [x] **Crosslinks widget endpoint removed** — Deleted from `dashboard/routes/marketing.js`, removed from PUBLIC_PATHS
- [x] **Hardcoded embed.js removed from 4 app repos** — abschlusscheck, headshot-ai-pro, promoforge, bannerforge (on VM)
- [x] **CLAUDE.md nginx template updated** — Removed banner/crosslinks injection from the new-site template
- [x] **Dashboard restarted** — Picked up new config.yml (no game apps, no crosslinks)
- [x] **All changes deployed** — crelvo.dev rebuilt+deployed 3 times, nginx reloaded, all verified

## What's In Progress

Nothing in progress — all items completed and verified.

## What Didn't Get Done (and Why)

- **Git push** — appManager 4 commits ahead, slebständig 7+ commits ahead. Carried from session 11.
- **AbschlussCheck redeploy** — embed.js fix committed locally but container not rebuilt. Moot: nginx proxy_pass gone so embed.js 404s.
- **HeadshotAI redeploy** — Same as above. Source in `/opt/headshot-ai/` (root-owned). Fix committed locally.
- **PromoForge redeploy** — Same. Source in `/opt/promoforge/` (root-owned). Fix committed locally.
- **BannerForge redeploy** — Attempted rebuild but `npm run build` failed (pre-existing build error). Source fix applied on VM directly. Moot: nginx proxy_pass gone.
- **Social platform credentials** — Carried from sessions 10, 11.
- **Show HN post** — Carried from session 11.

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Game removal scope | Full removal: containers, nginx, config, backend routes, social monitoring | User said "remove ALL games" — clean break for Steam pivot | Keep nginx configs as redirects | Unnecessary complexity, domains are subdomains anyway |
| Ad removal method | Python script to regex-clean nginx configs | 23 configs with varied patterns, manual editing would be error-prone | Manual editing per file | Too many files, too many pattern variations |
| Hardcoded embed.js in 4 apps | Fix source + rely on nginx 404 | nginx proxy_pass removed = embed.js requests 404 regardless | Rebuild all 4 containers | 2 are in /opt/ (root-owned), 1 has build errors. 404 is sufficient |
| Crosslinks widget endpoint | Delete entirely from marketing.js | No sites inject it anymore, dead code | Keep endpoint, just empty response | YAGNI — no sites reference it |

## Mental Model

### How cross-promotion worked (now removed)
Three layers of cross-promotion existed:
1. **Crosslinks widget** — A fixed bottom bar showing "Also by Crelvo:" with random links to other sites. Served as JS from `/api/crosslinks/widget.js` by the dashboard, injected via nginx `sub_filter '</body>'` on every site.
2. **Banner ads** — BannerForge-generated image ads served from `/api/banners/embed.js` + `/api/banners/serve`. Injected same way via nginx sub_filter. Some sites (abschlusscheck, headshot-ai, promoforge, bannerforge) also had it hardcoded in their Next.js/React source via `<Script>` tags.
3. **Banner proxy** — Each site had a `location /api/banners/ { proxy_pass http://127.0.0.1:9091/api/banners/; }` block so the banner requests went to the dashboard.

Removing nginx sub_filter + proxy_pass kills layers 1 and 3 completely. Layer 2 (hardcoded source) still generates `<script>` tags but they 404 since the proxy is gone. Local repos are fixed for next deploy.

### Where games lived
- **Containers**: grimhollow-server, forgelands, diplomancy-quick, diplomancy (4 running)
- **Nginx configs**: 9 files in `/home/deploy/nginx-configs/sites/`
- **VM directories**: `/home/deploy/{game-name}/` (grimhollow had root-owned Docker data files that couldn't be deleted without sudo password — harmless leftovers)
- **Dashboard config**: entries in `/home/deploy/appmanager/dashboard/config.yml`
- **Backend**: kettenreaktion.js had a full API (daily puzzle results, stats, heatmap, streaks)
- **Social autopilot**: game app definitions + 5 game subreddit monitors in social-autopilot.js

### Config.yml gotcha
The VM's config.yml was rewritten by `yaml.dump()` in a previous session. This caused a Forgelands entry to become orphaned at the end of the file, outside the `apps` key. Had to use raw line removal, not YAML parsing, to clean it.

## Known Issues & Risks

- **Grimhollow data dir** — `/home/deploy/grimhollow/data/` has root-owned files (created by Docker). Can't delete without sudo password. Harmless but messy.
- **appManager 4 commits ahead of origin** — `142d127`, `12f0ee5`, plus 2 from session 11. Not pushed.
- **slebständig 7+ commits ahead** — Multiple sessions of unpushed work.
- **3 app repos have unpushed banner removal commits** — abschlusscheck (`ffedac2`), headshot-ai-pro (`0e53dbd`), promoforge (`77c64a4`)
- **BannerForge build broken** — `npm run build` fails on VM. Pre-existing issue, not caused by our changes. embed.js fix was applied via sed on VM source directly.
- **Banner management API still exists in dashboard** — Routes for creating/managing banners still in the codebase. Not injected anywhere, but the code is still there. Could be cleaned up later.

## What Worked Well

- **Python scripts via SSH for bulk nginx edits** — Regex-based cleanup of 23 configs was fast and reliable
- **Two-pass nginx cleanup** — First pass got sub_filter lines, second pass caught remaining proxy_pass blocks with `^~` prefix that first regex missed
- **Verifying via curl HTTP status** — `curl -o /dev/null -w '%{http_code}'` confirmed embed.js 404s on all affected sites without needing browser
- **Parallel tool calls** — Running multiple SSH checks simultaneously saved significant time

## What Didn't Work (Traps to Avoid)

- **Single regex for all nginx patterns** — The banner `location` blocks used different prefixes (`location /api/banners/` vs `location ^~ /api/banners/`). First cleanup script missed the `^~` variant. Always account for nginx location modifiers.
- **yaml.dump creates orphans** — Previous session's yaml.dump left Forgelands orphaned at EOF. When using Python yaml to edit config.yml, verify the output structure matches input.
- **Can't sudo rm on VM** — deploy user has no sudo for rm. Docker-created files in bind mounts may be root-owned. Can only clean deploy-owned files.
- **Can't rebuild /opt/ apps** — headshot-ai and promoforge live in `/opt/` which is root-owned. Can't rebuild without sudo or the original deploy pipeline.

## Next Steps (Priority Order)

1. **Push all repos to origin:**
   - `cd Projekte/appManager && git push` (4 ahead)
   - `cd Projekte/slebständig && git push` (7+ ahead)
   - `cd Projekte/abschlusscheck && git push`
   - `cd Projekte/headshot-ai-pro && git push`
   - `cd Projekte/promoforge && git push`

2. **Deploy abschlusscheck to remove hardcoded embed.js from running container:**
   - `cd Projekte/abschlusscheck && bash scripts/deploy.sh`
   - This is the only one with a deploy script. Others need their pipelines.

3. **Fix BannerForge build** — `npm run build` fails on VM at `/home/deploy/bannerforge`. Investigate and fix so the container can be rebuilt with the embed.js removal.

4. **Configure social platform credentials** (user action needed):
   - Reddit: `REDDIT_CLIENT_ID` + `REDDIT_CLIENT_SECRET`
   - YouTube: `YOUTUBE_API_KEY`
   - Bluesky: `BLUESKY_HANDLE` + `BLUESKY_APP_PASSWORD`

5. **Show HN post** — Draft at `plans/show-hn-draft.md`. User must be online 6 hours.

6. **Clean up dead banner management code** — Banner routes still exist in `dashboard/routes/marketing.js` (create/update/delete/serve banners). Could be removed since no sites use them anymore.

7. **OrbEdge setup** — New domain orbedge.de exists but may need full nginx config, SSL cert, DNS setup. Check if it's already configured on the VM.

## Rollback Plan

- **appManager pre-session:** `83bcefb`. Revert games: `git revert 142d127`. Revert ads: `git revert 12f0ee5`.
- **slebständig pre-session:** `2755817`. Revert all 3 commits: `git revert b41164d b4ae631 e5c7687`
- **Nginx configs** — No git backup. Would need to manually re-add sub_filter lines and proxy_pass blocks per the CLAUDE.md template (but template was also updated, so check git history for old version).
- **VM config.yml** — No git backup. Would need to manually re-add game entries.
- **Kettenreaktion DB table** — `kr_daily_results` table still exists in data.db even though the route is deleted. Data is preserved.

## Files Changed This Session

### appManager repo (this repo)
- `dashboard/routes/kettenreaktion.js` — **Deleted**. Kettenreaktion backend API (submit results, stats, heatmap, streaks).
- `dashboard/routes/social-autopilot.js` — Removed 7 game app definitions, removed urlGame, removed 5 game subreddit monitors.
- `dashboard/routes/marketing.js` — Removed crosslinks widget.js endpoint (~55 lines).
- `dashboard/server.js` — Removed kettenreaktion import/registration, removed `/api/kr` from CSRF_EXEMPT and PUBLIC_PATHS, removed `/api/crosslinks/widget.js` from PUBLIC_PATHS.
- `scripts/inject-crosslinks-games.py` — **Deleted**. Game site crosslinks injection script.
- `scripts/inject-crosslinks-proxy.py` — **Deleted**. Proxy site crosslinks injection script.
- `CLAUDE.md` — Removed Games table, updated nginx template (removed banner/crosslinks injection).
- `HANDOVER.md` — This file.

### slebständig repo (Projekte/slebständig)
- `src/components/Projects.astro` — Removed games array (8 entries), Games Section HTML, clientWork array, Client Work Section HTML. Renamed Orb to OrbEdge with orbedge.de.

### Other local repos (committed, not deployed)
- `Projekte/abschlusscheck/app/layout.tsx` — Removed `<Script src="/api/banners/embed.js">` tag.
- `Projekte/headshot-ai-pro/app/layout.tsx` — Removed `<Script src="/api/banners/embed.js">` tag.
- `Projekte/promoforge/web/index.html` — Removed `<script src="/api/banners/embed.js">` tag.

### VM (not in git)
- `/home/deploy/nginx-configs/sites/*` — 23 configs cleaned: removed crosslinks sub_filter, banner embed.js sub_filter, banner proxy_pass blocks.
- `/home/deploy/appmanager/dashboard/config.yml` — Removed 7 game entries + orphaned Forgelands block.
- `/home/deploy/bannerforge/src/app/layout.tsx` — Removed embed.js Script tag.
- Game containers stopped and removed (grimhollow-server, forgelands, diplomancy-quick, diplomancy).
- 9 game nginx configs deleted.
- Game directories removed (except grimhollow root-owned data files).

## Open Questions

- **OrbEdge (orbedge.de)** — Is the nginx config, SSL cert, and DNS already set up? Or does it need the full new-site deployment process?
- **Banner management code cleanup** — Should the banner API routes be fully removed from the dashboard, or kept for potential future use?
- **DeepResearch** — Still on crelvo.dev but unclear if active. No nginx sub_filter was present for it.
- **KNOWLEDGEBASEhreejs.md** — 82K token Three.js reference, untracked. Commit or keep local?
- **orbedge-landing/** — Untracked directory in appManager. What is it?
- **Dockfolio.dev dual paths** — `/home/deploy/dockfolio-landing/` is the real root, but stale `/home/deploy/dockfolio.dev/` still exists. Carried from session 11.
