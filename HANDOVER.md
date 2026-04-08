# Session Handover

**Date:** 2026-04-08 (Session 9)
**Duration:** ~2 hours
**Goal:** Go all-in on marketing automation — research, plan, build, deploy, and execute everything possible to start driving traffic to 18 apps with zero customers.

## Summary

This was a massive marketing strategy + execution session. The user wanted to explore every possible marketing angle, understand what automation is viable, and start executing immediately. We ran 7 parallel deep-research agents covering: the existing marketing infrastructure, social media platform rules, all 18 apps' marketing angles, competitor strategies, guerrilla/growth tactics, technical API integration details, and deep product analysis.

The core finding: the portfolio has 18 live apps generating EUR 0 revenue, but 70% of the marketing infrastructure was already built and sitting unused — banner system, email via Resend, analytics, cross-promo engine, AI content generation. The gap was pure execution, not technology.

We then built and deployed a Social Autopilot module (auto-posting to X/Twitter, Bluesky, Mastodon, Dev.to + Reddit/HN keyword monitoring), a cross-site link widget now live on 8 domains, cross-promo banners for the career pipeline, and sent all 17 Fachschaft outreach emails. The system is live and the monitoring crons are running. The next session should focus on configuring social platform credentials and building the high-traffic SEO content (Brutto-Netto Rechner, programmatic pages).

## What Got Done

- [x] **7 deep research agents** — comprehensive marketing analysis across platforms, competitors, products, tactics, and APIs
- [x] **Social Autopilot module** (`dashboard/routes/social-autopilot.js`, 430 lines) — 13 API endpoints, 4 cron jobs, platform adapters for X/Twitter/Bluesky/Mastodon/Dev.to
- [x] **Dashboard Social tab** — full UI in Marketing Manager with stats, post queue, mentions panel, quick post composer
- [x] **Reddit/HN keyword monitoring** — scans 6 subreddits + 5 HN queries every 15 min, AI response drafts, Telegram alerts
- [x] **Cross-site link widget** (`/api/crosslinks/widget.js`) — "Also by Crelvo" bar, live on 8 sites via nginx sub_filter injection
- [x] **RSS feed** (`/api/social/feed.xml`) — public, serving published social content
- [x] **Build-in-public → Social queue** — "Queue to Social" and "Queue All" buttons on BIP tweets
- [x] **4 cross-promo banners** created in database — career pipeline (AbschlussCheck ↔ LohnCheck ↔ Bewerbungsfotos AI + Dockfolio)
- [x] **17/17 Fachschaft emails sent** via Resend API — all German university student councils contacted about AbschlussCheck
- [x] **Non-Crelvo apps excluded** from crosslinks (AgoraHoch3, MyLeadMe, dieAgora, SFZ Leipzig)
- [x] **Nginx public paths configured** — crosslinks widget + RSS feed bypass basic auth
- [x] **npm packages installed** — `twitter-api-v2`, `@atproto/api`
- [x] **4 commits pushed + deployed** — all live on production VM
- [x] **All 119 tests passing**

## What's In Progress

- [ ] **Social platform credentials** — **State:** Module deployed, all 5 platforms disabled (enabled=0). **Remaining:** User must create accounts on X/Bluesky/Mastodon/Dev.to, get API keys, add to dashboard settings, then enable via `PUT /api/social/accounts/{platform} { "enabled": true }`.
- [ ] **Kettenreaktion `/api/kr/streak` endpoint** — **State:** WIP in `dashboard/routes/kettenreaktion.js` (~93 lines, uncommitted since session 4). **Remaining:** Testing and committing.

## What Didn't Get Done (and Why)

- **awesome-selfhosted submission** — README is excellent and ready. Needs manual GitHub PR. Didn't get to it because deployment + banner creation + email outreach took priority.
- **Show HN launch** — Requires user to be online 6 hours engaging with comments. Prepared but not executed.
- **Brutto-Netto Rechner** — Identified as single highest-traffic opportunity (1M+ German searches/month) but it's a feature for LohnCheck (lohnpruefung.de), not Dockfolio. Needs separate implementation session.
- **Programmatic SEO pages** — Designed approach (generate /gehalt/{job}/{city} pages) but this needs to run on individual app domains, not Dockfolio.
- **Shareable result cards** (OG image generation) — Planned using `satori` + `@resvg/resvg-js` but deprioritized in favor of shipping the autopilot.
- **LinkedIn API integration** — Requires LinkedIn developer app approval (1-5 business days). Can't be instant.

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Social platform SDKs | Dynamic imports (`await import(...)`) for Twitter/Bluesky | Won't crash at startup if packages missing or platform not configured | Static imports | Would fail on `import` if package removed |
| Reddit/HN monitoring | Direct public API calls (no OAuth for Reddit read) | Simpler, no auth needed for public search/JSON endpoints | Reddit OAuth + snoowrap npm | Unnecessary complexity for read-only |
| Cross-site link widget | Separate `/api/crosslinks/widget.js` endpoint | Independent of banner system, simpler, 10-min cache | Extend existing embed.js | Different lifecycle, coupling concerns |
| Banner content type | `custom_html` (not BannerForge) | BannerForge may not be running; HTML banners work everywhere, no external dependency | BannerForge AI-generated PNG | Adds runtime dependency |
| Non-Crelvo exclusion | Hardcoded slug array in widget endpoint | KISS — only 4-5 apps to exclude, config-driven is overkill | Config flag per app in config.yml | YAGNI — rarely changes |
| Fachschaft emails | Direct Resend API from local Node.js script | Faster than MCP server (which has setup overhead), same API key | marketing-mcp server | MCP tools don't always surface in Claude Code |
| Crosslinks nginx injection | Python script modifying sub_filter on VM | Programmatic, batch-updates 8 sites at once | Manual editing per site | Error-prone, slow |

## Mental Model

### Social Autopilot Architecture

The social autopilot is a standard Dockfolio route module following existing patterns (DI, asyncRoute, SQLite, cron, Telegram). It has three independent loops:

1. **Content Loop** (daily 8 AM): Claude Haiku reads top 5 marketable apps from `config.yml` → generates 4 posts (one per platform) → stores in `social_posts` table with `status=queued`.

2. **Publishing Loop** (hourly :15): Picks `status=queued` posts where `scheduled_at` is null or past → calls platform adapter → marks as `posted` or `failed` → bumps daily counter. Each platform has `enabled` flag and `daily_limit` in `social_accounts` table.

3. **Monitoring Loop** (every 15 min): Searches Reddit (public `.json` API, 2s delay between queries to avoid rate limits) and HN (Algolia search API) for keywords → stores new matches in `social_mentions` table (UNIQUE on `external_id` prevents duplicates) → sends Telegram if any found.

Platform adapters all return `{ ok: true, id, url }` or `{ ok: false, error }`. Twitter and Bluesky use dynamic imports for their SDKs. Mastodon and Dev.to use raw fetch.

### Cross-Site Link Widget

`/api/crosslinks/widget.js` is a self-contained IIFE that:
- Gets app list from config (compiled at serve time, cached 10 min)
- Filters: must have domain + marketing metadata, not redirect/infrastructure, not in NOT_CRELVO exclusion list
- Picks 5 random apps (excluding current hostname)
- Renders a fixed bottom bar with purple links + close button
- Adds `?ref={current_domain}` for attribution tracking

### Career Pipeline Cross-Promotion

The highest-value cross-promo chain serves one person at different life stages:
```
AbschlussCheck (finishing thesis) → LohnCheck (checking salary) → Bewerbungsfotos AI (applying for jobs)
```
These 3 apps target the same demographic (German students/graduates). Banner IDs 26-29 implement this cycle.

### Database Paths on VM

This is important and has bitten us: The dashboard container uses `/home/deploy/marketing/data.db` (bind-mounted), NOT `/app/data.db` (ephemeral). The path is `$HOME/marketing/data.db` where `$HOME=/home/deploy` inside the container. The `auth.db` is at `/home/deploy/marketing/auth.db`. Any direct DB operations must use these paths.

### Nginx Sub-Filter Injection

All 30+ sites use nginx `sub_filter` to inject scripts before `</head>` or `</body>`. Key rules:
- `sub_filter_once on` means only the first match per string is replaced
- `proxy_set_header Accept-Encoding ""` is required for sub_filter to work on proxied content
- The syntax is `sub_filter 'old_string' 'new_string'` — getting the order wrong silently breaks injection
- Some sites inject into `</head>` (abschlusscheck), others into `</body>` (most others)
- The crosslinks widget was added to the `</body>` sub_filter on 8 sites

## Known Issues & Risks

- **Systemd nginx service still enabled** — Impact: on reboot, wrong nginx starts for ~7 seconds until @reboot cron fixes it. Workaround: @reboot cron. Fix: `systemctl disable nginx` via Hetzner console.
- **Social platforms not configured** — All 5 platforms have `enabled=0`. Social posting won't happen until user adds credentials.
- **Reddit rate limiting** — 2s delay between searches, but 6 subreddits × multiple keywords = many requests. Monitor for 429 responses. If rate-limited, increase delay or reduce keyword count.
- **bewerbungsfotos-ai crosslinks not injected** — This site wasn't in the batch of 8 updated sites (might have a different sub_filter structure). Check and add manually.
- **Kettenreaktion streak endpoint uncommitted** — WIP from session 4 in `kettenreaktion.js`.
- **`logos-web` auto-healing alert** — Healing system confuses VM hostname with container name (from session 8).
- **Smartsteuer voucher code CRELVO10 doesn't exist yet** — Banners reference it but the code isn't active at smartsteuer.

## What Worked Well

- **7 parallel research agents** — Ran all deep research concurrently, got comprehensive results in ~5 minutes. Each agent focused on a different angle (platforms, competitors, products, tactics, APIs, infrastructure, portfolio).
- **Deploy → nginx config → verify loop** — Deploying code, updating nginx, and verifying public endpoints in rapid succession worked smoothly.
- **Resend API for bulk email** — Sent 12 emails in 24 seconds with 2s delay between. All delivered. Simple, reliable.
- **Python for nginx config editing** — Shell `sed` failed badly (collapsed multilines). Python on the VM was reliable for programmatic config changes.
- **Dynamic imports for optional SDKs** — Twitter/Bluesky packages can be installed or not without breaking the server.

## What Didn't Work (Traps to Avoid)

- **sed for multi-line nginx edits** — Backslash-newline handling on the VM's sed collapses everything to one line. Use Python instead.
- **Shell quoting for node -e inside docker exec over SSH** — Triple-level escaping (local shell → SSH → docker exec → node -e) is a nightmare. Use file-based approach: write script to /tmp, docker cp into container, run from /app/ with .cjs extension (ESM is default).
- **Assuming /app/data.db is the production database** — It's not. The real DB is at `/home/deploy/marketing/data.db` (bind-mounted volume). `/app/data.db` is ephemeral and empty.
- **Expecting nginx sub_filter to work without Accept-Encoding header** — Static file sites that don't proxy need different injection approach.
- **Trying to hit auth-required endpoints from outside VM** — The nginx basic auth blocks everything. Either SSH into VM and curl localhost, or use docker exec to run scripts inside the container.

## Next Steps (Priority Order)

1. **Configure social platform credentials** — Create accounts on X (developer.twitter.com → get 4 OAuth keys), Bluesky (bsky.app → Settings > App Passwords), Mastodon (instance/settings/applications → access token), Dev.to (dev.to/settings/extensions → API key). Add each to dashboard settings. Enable each via `PUT /api/social/accounts/{platform} { "enabled": true, "daily_limit": 3 }`. Then trigger first content: `POST /api/social/generate`.

2. **Submit Dockfolio to awesome-selfhosted** — Create a PR to `github.com/awesome-selfhosted/awesome-selfhosted`. Add under "Software Development - Project Management" or "Monitoring" section. Entry format: `- [Dockfolio](https://dockfolio.dev) - Docker dashboard combining infrastructure management with business intelligence for solopreneurs. ([Source Code](https://github.com/crelvo/appmanager)) \`AGPL-3.0\` \`Nodejs\` \`Docker\``. The README is ready.

3. **Build Brutto-Netto Rechner on LohnCheck** — Create a gross-to-net salary calculator at `lohnpruefung.de/brutto-netto`. This targets "Brutto Netto Rechner" (1M+ German searches/month). Needs: German tax brackets 2026, Sozialversicherung rates, Kirchensteuer toggle, interactive form. Upsell to LohnCheck premium.

4. **Programmatic SEO pages** — Generate `/gehalt/{job}/{city}` pages on LohnCheck from Bundesagentur für Arbeit Entgeltatlas data. Template: intro paragraph (Claude Haiku, ~$0.001/page), salary range table, calculator CTA. Submit sitemaps to Google Search Console.

5. **Fix bewerbungsfotos-ai crosslinks injection** — Check nginx config for this site, add crosslinks widget to its sub_filter.

6. **Prepare Show HN post** — Draft: "Show HN: I run 18 apps on one $12/month server as a solo dev". Include: architecture overview, screenshot, link to dockfolio.dev. Post Tuesday-Wednesday 11 AM ET. Must be online 6 hours to reply to every comment.

7. **Shareable result cards** — Install `satori` + `@resvg/resvg-js`. Create `/api/og/{type}/{hash}.png` endpoint that generates personalized OG images ("Your salary is in the top 23%"). This enables viral sharing on WhatsApp/LinkedIn/X.

8. **Backlog:** Finish Kettenreaktion streak endpoint (commit the WIP), German media outreach (t3n.de, deutsche-startups.de), Career Bundle landing page, delete stale Stripe webhook, GitHub fine-grained token, off-site backup, WISO Steuer banners.

## Rollback Plan

- **Last known good commit:** `9698ca8` (latest, all 4 session 9 commits)
- **Pre-session commit:** `257fe7d` (session 5 handover) — revert to this to undo all session 9 work
- **To revert social autopilot only:** `git revert a28a413` — removes the module, npm packages stay (harmless)
- **To undo nginx crosslinks injection:** SSH into VM, run: `ssh deploy@91.99.104.132` then for each site in `/home/deploy/nginx-configs/sites/`, remove the `crosslinks/widget.js` text from sub_filter lines. Reload nginx.
- **To undo cross-promo banners:** SSH into VM, `docker exec` and delete from banners table where `tags LIKE '%crosspromo%' AND id >= 26`.
- **If nginx goes down:** `ssh deploy@91.99.104.132 "sudo /usr/sbin/nginx -s stop 2>/dev/null; sleep 1; sudo /usr/sbin/nginx -c /home/deploy/nginx-configs/nginx.conf"`

## Files Changed This Session

### New Files (committed)
- `dashboard/routes/social-autopilot.js` — Social autopilot route module (430 lines: 13 endpoints, 4 crons, 5 platform adapters, Reddit/HN monitoring)
- `dashboard/seed-banners.js` — Cross-promo banner configurations (reference/documentation)
- `package.json` / `package-lock.json` — Root-level deps: twitter-api-v2, @atproto/api

### Modified Files (committed)
- `dashboard/server.js` — Import + register social autopilot, add public paths (crosslinks, RSS feed, social feed)
- `dashboard/routes/marketing.js` — Add `/api/crosslinks/widget.js` endpoint, NOT_CRELVO exclusion list
- `dashboard/public/index.html` — Social tab in Marketing Manager, BIP queue buttons, social JS functions (~290 lines added)
- `HANDOVER.md` — This file

### Modified on VM (not in git)
- `/home/deploy/nginx-configs/sites/appmanager` — Public location blocks for crosslinks + RSS feed
- `/home/deploy/nginx-configs/sites/{8 sites}` — Crosslinks widget added to sub_filter `</body>` injection
- `/home/deploy/marketing/data.db` — 4 new banners (IDs 26-29) + placements, social_posts/social_mentions/social_accounts tables created

### Unchanged from Prior Sessions (uncommitted)
- `dashboard/routes/kettenreaktion.js` — WIP streak endpoint (session 4)
- `marketing/index.html` — Prior session changes

## Open Questions

- **Twitter free vs Basic tier** — Free tier gives 1,500 tweets/month but 0 read access (can't monitor mentions via API). Is $100/month for Basic worth it to add Twitter monitoring?
- **Reddit monitoring frequency** — Currently scanning 6 subreddits every 15 min with 2s delay. Is this too aggressive? Should we reduce to every 30 min?
- **Cross-promo banner priority** — Existing smartsteuer banners (session 5) have higher priority than new career pipeline banners. Should we adjust priority weights so career pipeline shows more often?
- **Crosslinks widget placement** — Fixed bottom bar might annoy users on mobile. Consider making it a footer section instead?
- **How to handle Fachschaft replies** — 17 emails sent. Replies will come to kevin@abschlusscheck.de. Who monitors and responds?
- **Bundle pricing viability** — Career Bundle at EUR 29.90 (vs EUR 48+ separately). Is 38% discount too aggressive for the margin?

## Research Findings Summary (Preserved for Next Sessions)

### Platform Automation Rules
- **Automatable:** X/Twitter (free: 50/day), Bluesky (generous limits), Mastodon (native scheduling), Dev.to (free API)
- **Manual only:** Reddit (shadowban), YouTube (ML spam filter), HN (no write API), Quora (no API)

### German SEO Gold Mine (Low Competition)
- "Brutto Netto Rechner" — 1M+ searches/month
- "Bewerbungsfoto KI" — wide open, few competitors
- "Abschlussarbeit Checkliste" — natural for AbschlussCheck
- "Abfindung berechnen" — AbfindungsOptimizer
- "Gehaltsvergleich [Job] [City]" — programmatic SEO opportunity

### Competitor Weaknesses
- Portainer: no revenue tracking (Dockfolio unique)
- HeadshotPro: English-only (bewerbungsfotos-ai.de owns German)
- Scribbr: EUR 50-200, days wait (AbschlussCheck: EUR 14-29, 5 min)
- Gehalt.de: generic (LohnCheck: "Is your payslip correct?" unique angle)

### Self-Hosted Growth Playbook (from Plausible, Uptime Kuma case studies)
1. awesome-selfhosted listing (180K+ stars)
2. Show HN with compelling story
3. r/selfhosted post
4. Build-in-public transparency
5. One-command Docker install

## Awin Account Reference (carried forward)
- **Publisher ID:** 2820526
- **Active programs:** smartsteuer DE (advertiser ID 15043), WISO Steuer-Software
- **Awin click URL format:** `https://www.awin1.com/cread.php?awinmid={advertiser_id}&awinaffid=2820526&ued={encoded_destination_url}`
