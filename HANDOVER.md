# Session Handover

**Date:** 2026-04-09 (Session 11)
**Duration:** ~2 hours
**Goal:** Read session 10 handover, rebuild dockfolio.dev as Three.js experience, update crelvo.dev portfolio, fix misattributed apps.

## Summary

Big session covering Three.js, portfolio management, crosslinks, and deployment fixes across multiple sites.

Started by reading the session 10 handover and verifying git state. Then rebuilt the entire dockfolio.dev marketing site as a full-page immersive Three.js experience — a fixed canvas with 30 instanced Docker container cubes, connection lines, data flow particles, orbital rings, and scroll-driven camera orbit. All original marketing content (features, pricing, comparison, guide, legal pages) preserved as glassmorphic HTML overlay panels. Hit two deployment issues: (1) deployed to wrong nginx root path (`/home/deploy/dockfolio.dev/` instead of `/home/deploy/dockfolio-landing/`), and (2) CSP headers blocking Three.js CDN. Both fixed.

Updated crelvo.dev extensively: separated games from apps into dedicated sections, removed urlGame, added 5 missing projects (DREIRAUM Studio, SurvivorAI, PatternMusic, Forgelands, Orb), created a "Client Work" section for AgoraHoch3, and corrected Orb from being listed as a game to a betting bot tool. Expanded crosslinks widget injection to 4 more nginx sites. Rewrote CLAUDE.md app inventory from an outdated 15-app list to comprehensive 30+ categorized listing with client projects clearly separated.

Also fixed AbschlussCheck — Three.js particle sphere had been committed (`a22cdca`) but never deployed. Ran `scripts/deploy.sh` which rebuilt the Docker image on VM. Three.js now live on abschlusscheck.de.

## What Got Done

- [x] **Dockfolio.dev Three.js rebuild** — Full immersive 3D: 30 instanced container nodes (RoundedBoxGeometry), 2000 ambient particles, 120 data flow particles, connection lines, orbital rings, scroll-driven camera, mouse parallax, glassmorphic content panels. Committed `bc716b3`, deployed live.
- [x] **Dockfolio.dev CSP fix** — Updated nginx Content-Security-Policy to whitelist `cdn.jsdelivr.net`, `plausible.crelvo.dev`, `admin.crelvo.dev`, `googletagmanager.com`, `google-analytics.com`
- [x] **Dockfolio.dev deployment path fix** — Discovered nginx root is `/home/deploy/dockfolio-landing/` not `/home/deploy/dockfolio.dev/`. Copied files to correct path.
- [x] **Crelvo.dev portfolio reorganization** — 3 sections now: Live Projects (20 apps/sites), Games (8 browser games), Client Work (1). 4 commits in `Projekte/slebständig`.
- [x] **Removed urlGame** from crelvo.dev
- [x] **Added missing apps to crelvo.dev** — DREIRAUM Studio, SurvivorAI, PatternMusic, Forgelands, Orb
- [x] **AgoraHoch3 marked as client project** — Separate "Client Work" section on crelvo.dev, `client: true` in VM config.yml, "CLIENT PROJECTS" section in CLAUDE.md
- [x] **Orb corrected** — Moved from games to tools, described as betting bot platform. Local repo: `Projekte/bot`
- [x] **CLAUDE.md app inventory rewrite** — 30+ apps organized: SaaS & Tools (10+), Content & Brands (10), Games (8+), Infrastructure (4), Redirects (2), Client Projects (1)
- [x] **Crosslinks expanded to 4 sites** — agorahoch3.org, dreiraum.studio, survivorai.app, patternmusic.art
- [x] **VM config.yml updated** — Added PatternMusic, Forgelands; marked AgoraHoch3 as client; corrected Orb description
- [x] **AbschlussCheck Three.js restored** — Commit `a22cdca` existed but was never deployed. Ran `scripts/deploy.sh`, rebuilt Docker image, Three.js particle sphere now live.

## What's In Progress

Nothing in progress — all items completed and deployed.

## What Didn't Get Done (and Why)

- **Social platform credentials** — Requires user to create accounts/API keys. Carried from session 10.
- **HN mention draft responses** — Deprioritized for Three.js and portfolio work
- **Show HN post** — Requires user online 6+ hours
- **LeadMe client project** — User mentioned alongside AgoraHoch3 but not found on VM. Needs details.
- **deepresearch.business crosslinks** — No sub_filter in its nginx config, needs full setup
- **Git push** — Both repos (appManager, slebständig) have unpushed commits

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Three.js site architecture | Fixed canvas z-0 + HTML overlay z-1 | Award-winning pattern (Lusion, Igloo). Canvas persists, content scrolls over | Per-section canvases | Multiple renderers, complex sync |
| Container nodes | InstancedMesh + RoundedBoxGeometry via CDN addon | 1 draw call for 30 nodes, rounded edges = Docker container aesthetic | Individual meshes | 30 draw calls, wasteful |
| Three.js loading | CDN importmap (`cdn.jsdelivr.net`) | No build step, matches KISS philosophy | npm + bundler | Project convention = no bundler |
| Scroll camera | Custom parametric orbit via scroll event listener | Lightweight, no extra dependency | GSAP ScrollTrigger | 45KB for a simple orbit path |
| Crelvo project separation | 3 arrays: `projects`, `games`, `clientWork` | Clean separation, different grids and accent colors per section | Tag-based filtering | Harder to style differently |
| Client projects | Dedicated section labeled "Built for others" | Crystal clear ownership distinction | Badge/label in main list | Too easy to confuse |
| AbschlussCheck fix | Full redeploy via `scripts/deploy.sh` | Existing deploy script handles tar + Docker build + restart | Manual Docker build | Script handles all edge cases (Stripe keys, env) |

## Mental Model

### Deployment paths — the critical gotcha map
Each site has its own deployment target. These are NOT always obvious:
- **dockfolio.dev** → `/home/deploy/dockfolio-landing/` (NOT `/home/deploy/dockfolio.dev/`)
- **crelvo.dev** → `/var/www/crelvo/`
- **abschlusscheck.de** → Docker container, deploy via `Projekte/abschlusscheck/scripts/deploy.sh`
- **Most other static sites** → `/home/deploy/DOMAIN/`

Always run `grep 'root' /home/deploy/nginx-configs/sites/SITENAME` before deploying to verify the actual path.

### CSP headers
Several sites have Content-Security-Policy headers in nginx. When adding external scripts (CDN, analytics), you MUST update the CSP. Check: `grep 'Content-Security-Policy' /home/deploy/nginx-configs/sites/SITENAME`.

dockfolio.dev CSP currently allows: `cdn.jsdelivr.net`, `plausible.crelvo.dev`, `admin.crelvo.dev`, `googletagmanager.com`, `google-analytics.com`.

### Crelvo site (Projekte/slebständig)
Astro 4.16. Projects in `src/components/Projects.astro` as 3 arrays:
- `projects` (20 entries) — apps, tools, SaaS, content sites
- `games` (8 entries) — all on `*.crelvo.dev` subdomains
- `clientWork` (1 entry) — AgoraHoch3

Build: `npm run build` → `dist/`. Deploy: `scp -r dist/* deploy@91.99.104.132:/var/www/crelvo/`

### Key app corrections this session
- **Orb** (orb.crelvo.dev) = betting bot tool, NOT a game. Local repo: `Projekte/bot`
- **AgoraHoch3** (agorahoch3.org) = CLIENT project, NOT Crelvo-owned
- **urlGame** = removed from portfolio (user: "its shit")

## Known Issues & Risks

- **Plausible 404 on dockfolio.dev** — `/js/script.js` returns 404 (no Plausible proxy block in nginx). Analytics still works via direct Plausible domain. Low impact.
- **Stale `/home/deploy/dockfolio.dev/` directory** — Contains old files, not served. Could confuse future deploys. Should symlink or remove.
- **appManager 2 commits ahead of origin** — `bc716b3` + `401e944` not pushed
- **slebständig 4 commits ahead of origin** — `c2cae49`, `4d3489f`, `7a19838`, `2755817` not pushed
- **Systemd nginx still enabled** — Inherited issue. Manual nginx config used via custom path.
- **Reddit 403 from Hetzner** — Needs OAuth credentials. Inherited from session 10.

## What Worked Well

- **Playwright MCP for live testing** — Caught CSP blocking Three.js immediately on the real production URL
- **Cross-referencing VM config.yml with site listings** — Found 4+ missing apps efficiently
- **Python one-liners via SSH** — Far more reliable than sed for editing nginx configs (avoids shell quoting hell)
- **AbschlussCheck deploy script** — One command, handles everything: tests, tar, Docker build, restart, health check

## What Didn't Work (Traps to Avoid)

- **Deploying to wrong path** — `/home/deploy/dockfolio.dev/` vs `/home/deploy/dockfolio-landing/`. ALWAYS check nginx root before deploying.
- **sed for nginx sub_filter edits** — Quoting inside single quotes inside double quotes inside SSH = nightmare. Failed multiple times, had to fix manually. Use `ssh ... "python3 -c '...'"` instead.
- **Not checking CSP before deploying external CDN scripts** — Three.js from jsdelivr was blocked. Check CSP FIRST when adding any external script.
- **Assuming deployment = container rebuilt** — AbschlussCheck had Three.js committed but never rebuilt. Git commit != deployed. Always verify the running container matches HEAD.

## Next Steps (Priority Order)

1. **Push both repos to origin:**
   - `cd Projekte/appManager && git push`
   - `cd Projekte/slebständig && git push`

2. **Configure social platform credentials** (user action):
   - Reddit: reddit.com/prefs/apps → `REDDIT_CLIENT_ID` + `REDDIT_CLIENT_SECRET`
   - YouTube: console.cloud.google.com → YouTube Data API v3 → `YOUTUBE_API_KEY`
   - Bluesky: bsky.app → Settings > App Passwords → `BLUESKY_HANDLE` + `BLUESKY_APP_PASSWORD`

3. **Draft responses for top HN mentions** — 69 mentions in DB. Use `GET /api/social/mentions?status=new`, then `POST /api/social/mentions/:id/draft` for AI drafts.

4. **Post Show HN** — Draft at `plans/show-hn-draft.md`. Title: "Show HN: I run 25+ apps on one $12/month server as a solo dev". User must be online 6 hours.

5. **Clean up dockfolio.dev paths** — Either `ln -sfn /home/deploy/dockfolio-landing /home/deploy/dockfolio.dev` or change nginx root to `/home/deploy/dockfolio.dev/`

6. **Add LeadMe as client project** — User mentioned it. Not on VM. Ask for domain/details.

7. **deepresearch.business crosslinks** — Needs sub_filter added to nginx config.

## Rollback Plan

- **appManager pre-session:** `e11131a`. Revert Three.js: `git revert bc716b3`. Restore old site: `ssh deploy@91.99.104.132 "git -C /home/deploy/appmanager show e11131a:marketing/index.html > /home/deploy/dockfolio-landing/index.html"`
- **Crelvo pre-session:** `9af2603` in `Projekte/slebständig`. Revert all: `git revert 2755817 7a19838 4d3489f c2cae49`
- **AbschlussCheck:** Container was rebuilt. To revert Three.js: `cd Projekte/abschlusscheck && git revert a22cdca && bash scripts/deploy.sh`
- **Nginx CSP:** Revert to `"default-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self';"` in dockfolio.dev.conf, reload nginx

## Files Changed This Session

### appManager repo (this repo)
- `marketing/index.html` — Complete rewrite to immersive Three.js (committed `bc716b3`)
- `CLAUDE.md` — Rewrote app inventory: 30+ apps categorized, client projects separated, Orb corrected
- `HANDOVER.md` — This file

### Crelvo repo (Projekte/slebständig)
- `src/components/Projects.astro` — 4 commits: games separated (8), apps (20), client work (1), urlGame removed, 5 apps added, Orb moved from games to tools

### AbschlussCheck repo (Projekte/abschlusscheck)
- No code changes — redeployed existing Three.js commit `a22cdca` that was never built

### VM (not in git)
- `/home/deploy/dockfolio-landing/index.html` + `fonts/` — Three.js marketing page
- `/home/deploy/nginx-configs/sites/dockfolio.dev.conf` — CSP updated for Three.js CDN + analytics
- `/home/deploy/nginx-configs/sites/agorahoch3` — Added crosslinks + analytics sub_filter
- `/home/deploy/nginx-configs/sites/dreiraum.studio` — Added crosslinks to existing sub_filter
- `/home/deploy/nginx-configs/sites/survivorai` — Added crosslinks to existing sub_filter
- `/home/deploy/nginx-configs/sites/patternmusic.art` — Added full sub_filter block
- `/home/deploy/appmanager/dashboard/config.yml` — Added PatternMusic + Forgelands, marked AgoraHoch3 as client, corrected Orb
- `/var/www/crelvo/` — Updated Crelvo site with new portfolio sections
- AbschlussCheck Docker container rebuilt with Three.js

## Open Questions

- **LeadMe** — User mentioned as client project alongside AgoraHoch3. Not found on VM. What domain? What tech? Needs to be added.
- **DeepResearch** — On crelvo.dev but unclear if still active. No nginx sub_filter. Investigate.
- **Forgelands domain** — Currently bare IP port 8080. Should it get `forgelands.crelvo.dev`?
- **KNOWLEDGEBASEhreejs.md** — 82K token Three.js reference, untracked. Commit or keep local?
- **Dockfolio.dev dual paths** — Symlink or change nginx root?
