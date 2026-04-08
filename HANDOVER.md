# Handover

**Date:** 2026-04-08 (Session 9)

## Summary

Session 9 was a **massive marketing strategy + implementation session**. The user wanted to go all-in on marketing automation. We ran 7 parallel deep-research agents covering: existing marketing infrastructure, social media automation landscape, app portfolio analysis, competitor strategies, guerrilla marketing tactics, technical API details, and deep product analysis.

Key finding: **18 apps, EUR 0 revenue, but 70% of marketing infrastructure already built and sitting unused.** The gap isn't technical — it's execution.

Built and committed: Social Autopilot module (automated posting to X/Twitter, Bluesky, Mastodon, Dev.to + Reddit/HN monitoring), dashboard UI panel, cross-site link widget, RSS feed, build-in-public → social queue integration, and cross-promo banner seed configs.

**Most important for next session:** Configure platform credentials (Twitter API keys, Bluesky app password, etc.) and deploy. The monitoring crons start immediately on deployment. Then focus on: Fachschaft email outreach, awesome-selfhosted submission, programmatic SEO pages, and Show HN launch.

## Completed

### Session 9: Marketing Autopilot
- [x] Deep research: 7 parallel agents covering all marketing angles (social platforms, APIs, competitors, guerrilla tactics, product analysis)
- [x] Built `dashboard/routes/social-autopilot.js` — 420+ lines, 13 API endpoints, 4 cron jobs
- [x] Platform adapters: X/Twitter (`twitter-api-v2`), Bluesky (`@atproto/api`), Mastodon (raw fetch), Dev.to (raw fetch)
- [x] Reddit monitoring: 6 subreddits (selfhosted, Finanzen, StudiumDE, arbeitsleben, docker, webdev)
- [x] Hacker News monitoring: 5 keyword queries via Algolia API
- [x] AI content generation: Claude Haiku generates daily social posts from app portfolio context
- [x] AI response drafts: Generate contextual, non-salesy replies to relevant mentions
- [x] Telegram alerts on new keyword mentions
- [x] RSS feed at `/api/social/feed.xml` (public, no auth)
- [x] Dashboard UI: "Social" tab in Marketing Manager with stats, post queue, mentions, quick post
- [x] Build-in-public → Social queue: "Queue to Social" and "Queue All" buttons on BIP tweets
- [x] Cross-site link widget: `/api/crosslinks/widget.js` — embeddable "Also by Crelvo" bar
- [x] Cross-promo banner seed configs: 6 banners for career pipeline (AbschlussCheck ↔ LohnCheck ↔ Bewerbungsfotos AI + Dockfolio)
- [x] npm packages installed: `twitter-api-v2`, `@atproto/api`
- [x] CLAUDE.md updated with new endpoints + cron jobs
- [x] All tests passing (119/119)
- [x] Committed: `a28a413`

### Carried Forward
- [x] All sites restored after nginx outage (session 8)
- [x] Watchdog + @reboot cron hardened (session 8)
- [x] Smartsteuer affiliate banners live (session 5)

## In Progress

- [ ] **Kettenreaktion `/api/kr/streak` endpoint** — WIP in `dashboard/routes/kettenreaktion.js` (~93 lines added, uncommitted from session 4)
- [ ] **Cross-promo banner deployment** — Seed configs written in `dashboard/seed-banners.js`, need to POST to `/api/marketing/banners` after deployment
- [ ] **Crosslinks widget injection** — Widget built at `/api/crosslinks/widget.js`, needs adding to nginx site configs

## What Didn't Get Done (and Why)

- **Programmatic SEO pages** — Designed but not built. Needs landing pages on individual app domains (lohnpruefung.de, etc.), not on Dockfolio. Requires per-app implementation.
- **Brutto-Netto Rechner** — Identified as highest-traffic opportunity (1M+ German searches/month), but it's a new feature for LohnCheck, not Dockfolio
- **Show HN launch** — Requires deployment + preparation, can't do from local
- **awesome-selfhosted submission** — Manual PR, needs doing from GitHub

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Platform SDKs | Dynamic imports (`await import(...)`) for Twitter/Bluesky | Won't crash at startup if packages missing or not configured | Static imports | Would fail if packages removed |
| Reddit/HN monitoring | Direct API calls, no OAuth for Reddit read | Simpler, no auth needed for public search endpoints | Reddit OAuth + `snoowrap` npm | Unnecessary complexity for read-only monitoring |
| Cross-site widget | Separate `/api/crosslinks/widget.js` endpoint | Independent of banner system, simpler, cacheable | Extend existing `embed.js` | Banner system has different lifecycle, would couple concerns |
| Banner content | `custom_html` type, not BannerForge | BannerForge may not be running; HTML banners work everywhere | BannerForge AI-generated | Adds external dependency for simple text banners |
| Social post queue | SQLite table with status field | Matches existing pattern (email_queue), simple, reliable | Redis queue or external service | YAGNI, SQLite is sufficient |

## Mental Model

### Social Autopilot Architecture

The social autopilot is a single route module that follows existing Dockfolio patterns:

1. **Content generation** (daily 8 AM cron): Claude Haiku reads app portfolio context from `config.yml`, generates 4 posts (one per platform: twitter, bluesky, mastodon, linkedin)
2. **Post queue** (`social_posts` table): Posts sit in queue with `status=queued`, `scheduled_at` optional
3. **Publishing** (hourly :15 cron): Picks queued posts, calls platform adapters, marks as posted/failed
4. **Monitoring** (every 15 min cron): Searches Reddit (public JSON API) + HN (Algolia API) for keywords, stores new matches in `social_mentions` table
5. **Response drafts**: On demand, Claude Haiku drafts a genuine reply based on the mention context
6. **Telegram alerts**: New mentions trigger Telegram notification

Platform adapters return `{ ok: true, id, url }` or `{ ok: false, error }`. Each platform has a daily limit (configurable per-platform via `social_accounts` table).

### Cross-Site Link Widget

`/api/crosslinks/widget.js` is a public, cacheable JavaScript file that:
- Reads app list from `config.yml` (compiled at serve time, cached 10 min)
- Filters out current domain, infrastructure, and redirects
- Shows 5 random related apps in a fixed bottom bar
- User can dismiss with X button
- Adds `?ref=` tracking param for analytics

### Cross-Promo Strategy

The "career pipeline" is the highest-value cross-promo chain:
```
AbschlussCheck (thesis) → LohnCheck (salary) → Bewerbungsfotos AI (job photos)
```
These serve the same person at different life stages. Banner configs in `seed-banners.js`.

## Known Issues & Risks

- **Systemd nginx service still enabled** — see session 8 (needs Hetzner console root access)
- **No platform credentials configured yet** — Social autopilot won't post until Twitter/Bluesky/Mastodon keys are added to settings
- **Reddit rate limiting** — 2-second delay between searches, but heavy monitoring could still trigger Reddit's anti-bot detection. Monitor for 429 responses.
- **Kettenreaktion streak endpoint uncommitted** — WIP from session 4
- **Cross-site widget not yet in nginx configs** — Need to add `<script src="https://admin.crelvo.dev/api/crosslinks/widget.js"></script>` to each site's nginx config
- **Seed banners not yet created** — Config ready in `seed-banners.js`, need to POST to API after deployment

## Next Steps (Priority Order)

1. **Deploy** — `bash deploy.sh --rebuild` to activate all new features
2. **Configure social platform credentials** in dashboard settings:
   - Twitter: Create app at developer.twitter.com, get 4 keys (app key, app secret, access token, access secret)
   - Bluesky: Create account, generate app password at Settings > App Passwords
   - Mastodon: Create app at instance/settings/applications, get access token
   - Dev.to: Get API key from dev.to/settings/extensions
3. **Enable platforms** via `PUT /api/social/accounts/twitter { "enabled": true }`
4. **Create cross-promo banners** — POST the configs from `seed-banners.js` to `/api/marketing/banners`
5. **Add crosslinks widget to nginx** — Add `<script src="https://admin.crelvo.dev/api/crosslinks/widget.js"></script>` to each site's `sub_filter` in nginx config
6. **Send remaining 12 Fachschaft emails** — via marketing-mcp (`market abschlusscheck`)
7. **Submit Dockfolio to awesome-selfhosted** — GitHub PR to github.com/awesome-selfhosted/awesome-selfhosted
8. **Show HN launch** — Prepare post: "Show HN: I run 18 apps on one $12 server as a solo dev"

### High-Impact Marketing Actions (post-deployment)

9. **Build Brutto-Netto Rechner** on lohnpruefung.de (1M+ monthly German searches)
10. **Programmatic SEO** — Generate `/gehalt/{job}/{city}` pages on LohnCheck from public salary data
11. **Parasite SEO** — Publish on Medium, Dev.to, GitHub targeting German finance keywords
12. **Shareable result cards** — OG image generation for LohnCheck/AbschlussCheck results
13. **Career Bundle landing page** on crelvo.dev
14. **German media outreach** — t3n.de, deutsche-startups.de, Heise

### Backlog (carried forward)
- Systemd nginx override (needs root access)
- Delete stale Stripe webhook
- GitHub fine-grained token
- Off-site backup
- og:image files for all apps
- WISO Steuer banners
- Smartsteuer voucher codes

## Rollback Plan

- **Last commit:** `a28a413` (Social autopilot module)
- **Previous safe commit:** `257fe7d` (Session 5 handover)
- **To undo social autopilot:** `git revert a28a413` — removes the module cleanly
- **npm packages:** `twitter-api-v2` and `@atproto/api` are optional (dynamic imports), removing them won't break the server
- **Database tables:** `social_posts`, `social_mentions`, `social_accounts` are new — dropping them has no side effects
- **If nginx goes down:** `ssh deploy@91.99.104.132 "sudo /usr/sbin/nginx -s stop 2>/dev/null; sleep 1; sudo /usr/sbin/nginx -c /home/deploy/nginx-configs/nginx.conf"`

## Files Changed This Session

### New Files
- `dashboard/routes/social-autopilot.js` — Social autopilot route module (420+ lines)
- `dashboard/seed-banners.js` — Cross-promo banner seed configurations
- `package.json` / `package-lock.json` — Root-level deps for twitter-api-v2, @atproto/api

### Modified Files
- `dashboard/server.js` — Import + register social autopilot, add public paths
- `dashboard/routes/marketing.js` — Add `/api/crosslinks/widget.js` endpoint
- `dashboard/public/index.html` — Social tab UI, BIP queue buttons
- `CLAUDE.md` — New API endpoints + cron jobs documented (gitignored)

### Unchanged from Prior Sessions
- `dashboard/routes/kettenreaktion.js` — WIP streak endpoint (uncommitted, session 4)
- `marketing/index.html` — Prior session changes (uncommitted)
- `HANDOVER.md` — This file

## Research Findings (Key Insights)

### Platform Automation Reality
| Platform | Auto-post? | Auto-comment? | Best approach |
|----------|-----------|---------------|---------------|
| X/Twitter | Yes (free: 50/day) | Risky | Schedule 2-3 posts/day |
| Bluesky | Yes (bot-friendly) | Yes if disclosed | Mirror X content |
| Mastodon | Yes (native scheduling) | Yes if bot-flagged | Technical content |
| Dev.to | Yes (free API) | N/A | Cross-post with canonical URLs |
| Reddit | NO (shadowban) | NO | Manual helpful answers only |
| YouTube | Uploads yes | NO (ML spam filter) | Create Shorts demos |
| HN | NO (no write API) | NO | Show HN = highest leverage |

### Highest-Impact Marketing Actions
1. Brutto-Netto Rechner on LohnCheck (1M+ German searches/month)
2. Programmatic SEO pages across German tools
3. Show HN: "18 apps, 1 server, $12/month" (community launch)
4. awesome-selfhosted submission for Dockfolio
5. Cross-promo banners across career pipeline
6. Fachschaft email outreach (12 remaining)

### German Market Keyword Opportunities (Low Competition)
- "Bewerbungsfoto KI" — bewerbungsfotos-ai.de
- "Gehaltsrechner Deutschland 2026" — lohnpruefung.de
- "Abschlussarbeit Checkliste" — abschlusscheck.de
- "Abfindung berechnen" — abfindungsoptimizer.de
- "Schenkungssteuer Freibetrag" — schenkungsplaner.eu

### Competitor Weaknesses We Can Exploit
- Portainer: no revenue tracking, no marketing tools (Dockfolio unique angle)
- HeadshotPro/Aragon: English-only, no German-language SEO (bewerbungsfotos-ai.de wide open)
- Scribbr.de: expensive (EUR 50-200), slow (days). We: EUR 14-29, 5 minutes
- Gehalt.de: generic, StepStone-owned. LohnCheck: "Is your payslip correct?" = unique angle

## Open Questions

- **Reddit monitoring rate limits** — How aggressive can we poll Reddit's public JSON API? Currently 2s delay between queries. May need to increase if we get 429s.
- **Twitter free tier** — 1,500 tweets/month (50/day) is sufficient, but read access is 0 on free tier. Worth $100/month for Basic to enable monitoring?
- **Crosslinks widget placement** — Should it be a fixed bottom bar or a footer section? Fixed bar is more visible but might annoy users.
- **Bundle pricing** — Career Bundle at EUR 29.90 (vs EUR 48+ separately) — is the discount too aggressive?

## Awin Account Reference (carried forward)
- **Publisher ID:** 2820526
- **Active programs:** smartsteuer DE (advertiser ID 15043), WISO Steuer-Software
- **Awin click URL format:** `https://www.awin1.com/cread.php?awinmid={advertiser_id}&awinaffid=2820526&ued={encoded_destination_url}`
