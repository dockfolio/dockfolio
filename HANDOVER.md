# Session Handover

**Date:** 2026-04-10 (Session 16)
**Duration:** ~1 hour, driven by a short chain of "keep going" prompts
**Goal:** Continue from session 15's handover and work down the autonomous priority list.

## Summary

Session 16 shipped **four small rounds** with clean commits, two live deploys, three nginx reloads, zero rollbacks. The session's signature move was small-scope, high-leverage wins that cleaned up lingering round-8 follow-ups and made the Marketing Brain's proxy-layer state visible in the UI for the first time. It also caught two factual errors in session 15's handover that would have misled any future session, and explicitly refused to rip 500 lines of "dead code" that is, in fact, still actively wired to the UI.

**Round 1 — daily cost cap lowered from $5 to $2** (commit `2b03929`). User said "max 2 dollas". `DAILY_COST_CAP_USD` in `dashboard/routes/marketing-brain.js:84` was hardcoded to `$5.00`. Changed to default `$2.00` and made it env-configurable via `BRAIN_DAILY_COST_CAP_USD`. Actual steady-state brain spend is ~$0.30–0.40/day (18 Haiku cron briefs + weekly Sonnet deep dives), so the new cap is comfortable headroom not a throttle. `.env.example` documents the new variable. Verified live: `docker exec dockfolio-dashboard node -e '...default cap: 2.00'`.

**Round 2 — SEO cache warming (round 9 of the Marketing Brain)** (commit `f8aa374`). Session 15's round 8 extracted `refreshRevenueCache()` and `refreshAnalyticsCache()` as shared helpers but explicitly left SEO as a known follow-up. The daily 1:30 AM SEO cron was auditing 10 apps and writing to the `seo_audits` DB table but discarding the in-memory `cachedSEO`, so `ctx.seo` in brain cycles was always null. Round 9 completes the pattern: extracted `refreshSeoCache()` as a module-local helper, HTTP handler `/api/marketing/seo` reuses it, daily cron reuses it, `cache.refreshSeo()` + `cache.warm()` now cover all three layers. **Verification:** startup log now reads `[STARTUP] Marketing cache warmed: {"revenue":true,"analytics":true,"seo":true}` — the first time SEO has been `true` on boot. Next brain cycle will see `ctx.seo.score/grade/issues` populated for every marketable app.

**Round 3 — nginx admin_tracking sub_filter fixes** (VM-only, no git commit). Session 15 flagged abschlusscheck, orbedge, and best-age as missing `admin_tracking`. Session 16 verified reality:

| App | s15 claim | Reality | Action |
|---|---|---|---|
| promoforge.app | missing | **missing, confirmed** | nginx sub_filter edited |
| abschlusscheck.de | missing | **already has it** — s15 was wrong | none |
| orbedge.de | missing | **has it inline in `index.html`** — brain false-negative | none |
| best-age.de | missing | **missing, confirmed** | nginx sub_filter edited |

Applied `sed` injection of `<script defer src="https://admin.crelvo.dev/api/analytics/track.js" data-app="SLUG"></script>` into the existing `</head>` sub_filter replacement string on promoforge and best-age.de. Nginx reload OK (only pre-existing benign warnings remain). Verified live via `curl https://promoforge.app/ | grep track.js` and same for best-age.de — both return the tag.

**Cleanup byproduct:** moved `promoforge.bak.20260410-s215` (a leftover from session 15 that was still being loaded by nginx and causing `conflicting server name` warnings) out of `/home/deploy/nginx-configs/sites/` and into a new `/home/deploy/nginx-configs/backups/` directory. Session 16's own `.bak.s16` backups also live there from the start.

**Round 4 — portfolio infra_state UI panel** (commit `a7b173b`). The Marketing Brain scanned nginx config files into `ctx.infra_state` during round 7 (session 15) but the 8 proxy-layer flags were only visible inside brain cycles. Session 16 surfaces them in the dashboard UI:

- New endpoint `GET /api/brain/infra-state` returns every marketable app's 8 flags (`plausible_injected`, `admin_tracking`, `banner_injection`, `crosslinks_widget`, `csp_header`, `gzip_on`, `long_cache`, `ssl_letsencrypt`) plus a portfolio-wide summary count per flag. Reads the same 60s-cached infra map that brain cycles use, so it's essentially free.
- New Brain tab UI panel (bottom-right column) renders the state as per-app cards with colored flag badges: green = detected, grey outline = missing. Tooltips explain each flag's meaning. The summary header shows `AT 18/22`-style counts so you can see at a glance which flags are widely adopted and which are rare.
- Verified from inside the container that the mount picks up round 3's nginx edits: `promoforge admin_tracking via nginx mount: true`, `best-age.de admin_tracking via nginx mount: true`, `files scanned: 30`.

After a full reload of the Brain tab at admin.crelvo.dev, the infra state panel will show all marketable apps with green AT badges everywhere except wherever admin tracking is still actually missing.

**Refused work:** the handover's "Banner management dead code cleanup (~500 lines in `marketing.js`)" item was investigated and rejected. Grep showed `/api/marketing/banners` + `/api/marketing/placements` (v2) has 10+ active references in `public/index.html` for an admin panel, and `/api/crosspromo/*` (v1 legacy) has 28 references backing an entire "Cross-Promo" tab. Neither system is actually dead. The handover item was stale — probably based on "no nginx site injects the v2 banner embed script" (which is true) being conflated with "the v2 banner code is unused" (which is false). Ripping 500 lines would have broken live UI. Session 16 declined and wrote this up instead of inventing make-work.

## What Got Done

### Round 1 — Cost cap lowered (1 commit, 1 deploy, pushed)

- [x] **`DAILY_COST_CAP_USD` made env-configurable** with default `2.00` — reads `process.env.BRAIN_DAILY_COST_CAP_USD`, falls back to `2.00` if missing or invalid
- [x] **`.env.example` documents the variable** with clear explanation of what it covers (all brain cycles, Haiku + Sonnet)
- [x] **Tests pass** — 119/119 unchanged
- [x] **Deploy** — green health check
- [x] **Verified in-container** — default cap confirmed as `2.00`
- [x] **Committed `2b03929`**, pushed to origin/master

### Round 2 — Round 9: SEO cache warming (1 commit, 1 deploy, pushed)

- [x] **`refreshSeoCache()` helper extracted** in `marketing.js` — runs the 10-app audit loop, populates `cachedSEO`, writes to `seo_audits` + `metrics_daily` DB tables, all in one place
- [x] **HTTP handler `GET /api/marketing/seo` simplified** — respects TTL, delegates to the helper
- [x] **Daily 1:30 AM cron simplified** — was duplicating the audit loop inline with no cache write, now calls `refreshSeoCache()` with proper logging
- [x] **`cache.refreshSeo()` exposed** on the marketing cache object, TTL-aware like the others
- [x] **`cache.warm()` now covers SEO too** — the startup warm and the 6h revenue/analytics cron's cache warm both now include SEO for free
- [x] **Startup log verified** — `{"revenue":true,"analytics":true,"seo":true}` — first time SEO has been `true`
- [x] **Tests pass** — 119/119
- [x] **Deploy** — green health check
- [x] **Committed `f8aa374`**, pushed to origin/master

### Round 3 — nginx admin_tracking fixes (VM-only, not in git)

- [x] **Audited all 4 apps s15 flagged** — found only 2 were actually missing admin_tracking, 1 was already fixed, 1 had inline HTML tracking
- [x] **`sed` edit to `promoforge` nginx config** — added admin track.js script before `</head>` in the existing sub_filter replacement string, `data-app="promoforge"`
- [x] **`sed` edit to `best-age.de` nginx config** — same pattern, `data-app="best-age"`
- [x] **Backups created** as `.bak.s16` and moved out of `sites/` to `/home/deploy/nginx-configs/backups/` before nginx test (so they wouldn't cause `conflicting server name` warnings)
- [x] **Cleaned up stale session 15 backup** — `promoforge.bak.20260410-s215` was still in `sites/` and causing conflicts; moved it to `backups/` too
- [x] **`nginx -t` clean** — only pre-existing benign warnings (`http2` option redefinition, `duplicate MIME type` etc.)
- [x] **Nginx reload OK**
- [x] **Verified live** — `curl https://promoforge.app/ | grep track.js` returns the tag; same for best-age.de
- [x] **Corrected 2 factual errors in session 15's handover** — abschlusscheck.de already has admin_tracking (s15 said missing), and orbedge.de has inline HTML admin tracking (s15 said missing, and the brain still reports `admin_tracking: false` because `readInfraState` only scans nginx files — known false-negative, not worth fixing)

### Round 4 — Portfolio infra_state UI panel (1 commit, 1 deploy, pushed)

- [x] **`GET /api/brain/infra-state` endpoint** — new, wired in `marketing-brain.js` right before the cron registration block. Returns `{total, summary, flags, apps[]}` where each app has `{slug, name, domain, nginx_file, flags{}}`. Uses `getMarketableApps(config.apps)` so it matches the brain's own app pool. Reads the same 60s-cached `loadInfraCache()` the brain cycles read.
- [x] **UI panel added to Brain tab** (`public/index.html`) — new div `#brainInfraState` in the bottom-right column, right after `#brainLearningsList`. Section header has a tooltip explaining what "proxy-layer state" means.
- [x] **`brainRenderInfraState()` function added** — renders a summary-badge header (`AT 18/22`) followed by per-app cards with colored flag badges. Uses `FLAG_META` for short labels (`PL`, `AT`, `BN`, `CL`, `CSP`, `GZ`, `CA`, `SSL`) and tooltip-full names. Green when `true`, outlined grey when `false`, muted grey when `null` (unknown — usually means the domain isn't in the nginx map at all).
- [x] **`brainLoadAll()` updated** — adds `/api/brain/infra-state` to the `Promise.allSettled` batch, stores in `brainState.infra`, calls `brainRenderInfraState()` after the other renders
- [x] **`brainState` initializer updated** — now includes `infra: null`
- [x] **Tests pass** — 119/119
- [x] **Deploy** — green health check
- [x] **Verified from inside container** — `files scanned: 30`, `promoforge admin_tracking via nginx mount: true`, `best-age.de admin_tracking via nginx mount: true`
- [x] **Committed `a7b173b`**, pushed to origin/master

### Refused work: banner dead code cleanup

- [x] **Investigated** via grep against `public/index.html`
- [x] **Found**: `/api/marketing/banners` and `/api/marketing/placements` (v2) have 10+ UI references (Banners admin panel, BannerForge regenerate, placement CRUD, embed code generation). `/api/crosspromo/*` (v1 legacy) has 28 references backing a full "Cross-Promo" tab.
- [x] **Concluded**: the handover item was stale and wrong. Neither system is dead. Session 16 refused to rip 500 lines and potentially break live UI features.
- [x] **Documented** here so future sessions don't get tricked into retrying it

### Git state

- [x] **Committed `2b03929`** — "Lower Marketing Brain daily cost cap to $2, make env-configurable" (2 files, +11/-2)
- [x] **Committed `f8aa374`** — "Marketing Brain round 9 — warm SEO cache (follow-up to round 8)" (1 file, +36/-34)
- [x] **Committed `a7b173b`** — "Marketing Brain — portfolio infra_state UI panel + endpoint" (2 files, +80/-2)
- [x] **All pushed to origin/master** — working tree clean

### Brain state snapshot (end of session 16)

| Metric | Value |
|--------|-------|
| Daily cost cap | **$2.00** (was $5.00) |
| Brain cache layers warmed on boot | **3** (revenue + analytics + SEO) — was 2 |
| Apps with nginx `admin_tracking` | **+2** (promoforge, best-age.de now injected) |
| New UI panels | **1** (portfolio infra_state grid) |
| Briefs today | 22 (unchanged from session 15 — no new cycles ran during this session) |
| Brain cost today | $0.58 (unchanged — 22 briefs from s15) |

## What's In Progress

Nothing. All 4 rounds committed, deployed, pushed. Working tree clean.

## What Didn't Get Done (and Why)

- **Banner dead code cleanup** — REFUSED. See "Refused work" above. The item was stale; both v1 crosspromo and v2 banners/placements are actively wired to the UI. Future sessions should remove this from the priority list or rewrite it as "audit whether ANY banner code path is unused" rather than "rip 500 lines".

- **`BRAIN_MORNING_EMAIL` activation** — STILL INERT. Unchanged since session 14. Still needs user's destination email address. Code path is live, just needs the env var set on VM and container restart. 5 minutes of user action.

- **Triage of ~85 open brain actions** — Human task, unchanged. With the s15 fix layers all live, future cycles will produce cleaner actions and the backlog will drift toward more signal.

- **Monday weekly deep cron verification** — Time-blocked. Today is Friday 2026-04-10. Monday 6 AM cron fires in 3 days.

- **Deep cycles on promoforge / sacredlens** — Session 15 ran these already (briefs #21 and #22). The s15 handover listed them as "next steps" but they were actually already done by the time that handover was written. Stale item.

- **BannerForge build fix** — Unknown scope, skipped for autonomous work because debugging a broken build usually needs error messages the AI can't trigger without user context.

- **`dockfolio.dev` dual paths deletion** — Session 13 carryover, scope still unclear from handovers. Needs a session that starts with "show me what's in both paths and decide what to cut".

- **Social platform credentials (Reddit/YouTube/Bluesky)** — User action.

- **Show HN post** — User action.

- **`promoforge` stale GitHub remote URL** — Cosmetic, trivially fixable, but no user value in doing it autonomously. 30 seconds if the user asks.

- **Track VM `docker-compose.yml` in git** — Policy call about whether to expose internal paths in the public repo. Not an AI decision.

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Cost cap default | $2.00, env-overridable | User explicitly said "max 2 dollas". Env var gives wiggle room for tuning without code change. Default matches stated preference, not historical burn | $1.00 default; keep $5.00 but rename the env var; separate caps for Haiku vs Sonnet | $1 would cap the weekly Sonnet deep cycle's budget to the point one cycle nearly exhausts the day. $5 ignores the stated request. Separate caps add complexity for a single-user system |
| SEO cache warming approach | Extract `refreshSeoCache()` shared helper, mirror rounds 8's pattern exactly | Round 8 already established the idiom (extract helper, use in HTTP handler + cron + `cache.warm()`). Consistency > novelty | Read SEO from `seo_audits` DB table in `collectAppContext` as a fallback; warm cache only on demand | DB fallback adds a second code path for brain cycles (cache OR DB) which is worse than always-cache. On-demand warming defeats the purpose — brain cycles would still see null SEO on the first invocation |
| Which nginx apps to fix in round 3 | Only the 2 that were actually missing (promoforge, best-age.de) | Reality > inherited wisdom. s15's list was a manual audit that had 2 errors out of 4. Fix what's broken, skip what isn't, document the errors so future sessions don't retry them | Fix all 4 anyway ("safe"); skip all 4 (wait for user direction) | Fixing abschlusscheck (which already has it) would have double-injected and broken the page. Skipping all 4 abandons the easy wins |
| How to handle orbedge's inline HTML tracking | Leave nginx alone, accept the brain false-negative | orbedge.de embeds `<script src="admin.crelvo.dev/api/analytics/track.js">` directly in `index.html`, not via nginx sub_filter. Adding a nginx sub_filter would double-inject the script. The brain's `readInfraState` will keep reporting `admin_tracking: false` for orbedge, but a human looking at the page source sees it's there. Cost of the false-negative: brain might propose "add admin tracking" for orbedge; user knows to reject it | Move the script from HTML to nginx; extend `readInfraState` to also scan `index.html` files | Moving breaks orbedge's static-site deploy flow and risks missing the change on next deploy. Scanning HTML adds a whole new code path and conflicts with Next.js dynamic HTML |
| Where to surface infra_state in UI | Bottom-right column of Brain tab, under learnings | Lowest-scroll area of an existing panel. Doesn't need a new tab or keyboard shortcut. Users looking at the brain's actions/briefs will naturally see it | New tab; separate Infra page; summary row at top of Brain tab | New tab is overweight for one small panel. Separate page requires routing. Top-row summary competes with the brain stats row for visual priority |
| Flag badge labels | 2-3 letter codes (`PL`, `AT`, `BN`, `CL`, `CSP`, `GZ`, `CA`, `SSL`) with tooltips | Compact enough to fit 8 badges on one row per app across 22 apps without wrapping. Tooltips carry the full meaning for anyone who doesn't memorize them | Full names (`Plausible`, `Admin Tracking`, etc.); icons only; color-only | Full names wrap to 3 rows per app — unreadable at portfolio scale. Icons would require an icon font or inline SVGs. Color-only loses meaning for color-blind users |
| Refusing to rip the banner code | Document the refusal in the handover, pivot to the handover itself | Session 16 was shipping high-velocity small wins. Breaking live UI on an "it said do it" misread would erase the round's credibility. The right move on an ambiguous instruction with high blast radius is to investigate, document, and stop | Rip the code anyway; ask the user; rip only the crosspromo v1 code | Ripping anyway is reckless. Asking the user violates "work autonomously" — and the answer is "don't rip it". Ripping just v1 is exactly what the reckless option looks like but with a narrower blast radius — v1 is still wired to a full UI tab |

## Mental Model

### Rounds 1–4 as a unit: "cleaning up the edges of rounds 7+8"

Session 15 shipped two big rounds (7 + 8) and validated them with three deep cycles. Those rounds were load-bearing architecture changes: nginx infra awareness and cache shape/warming. They landed clean, but every load-bearing change leaves small follow-ups around its edges. Session 16 was the cleanup shift:

1. **Cost cap** — round 8 made the brain see real data for the first time; it's appropriate to tighten the financial leash once you trust the output more. $2/day is enough to run the whole cron schedule with headroom for a few manual cycles
2. **SEO warming** — round 8 explicitly punted this with a "follow-up" note. Closing it means all three cache layers are now symmetric, and future brain cycles will have access to SEO scores/grades/issues when scoring content opportunities
3. **nginx admin_tracking** — round 7 added visibility, round 3 of session 16 adds the actual pixel to 2 apps that were missing it. Visibility without action would be observability theater; now the brain AND the operator both see + fix
4. **infra_state UI panel** — round 7 put the nginx scan into brain cycles, round 4 puts it into the operator's eyes. Same data, new consumer. Makes it possible to look at one page and say "promoforge is missing X" without running a brain cycle

The whole session reinforces one pattern: **when you add a new data source, make it visible in as many places as possible — brain prompts, UI panels, API endpoints**. Each surface you add increases the chance someone (AI or human) will act on it.

### Two errors caught in session 15's handover

Future sessions that read s15 handover should treat the "Session 15 → Known Issues → promoforge live nginx is missing `admin_tracking`" section with light skepticism:

- It was CORRECT about promoforge and best-age
- It was WRONG about abschlusscheck (already had it)
- It was WRONG about orbedge (has it inline in HTML, not in nginx — brain will report false-negative forever unless `readInfraState` is extended to scan HTML, which isn't worth it)

Session 16's UI panel will make these errors obvious: anyone looking at the Brain tab's infra state panel will see orbedge with a grey AT badge, think "that's wrong", and either fix it at the nginx layer or extend the detection. Surfacing the false-negative is itself a debugging aid.

### The cost cap is not the burn

Session 16's round 1 dropped the cap from $5 to $2. That's a hard ceiling change, not a burn-rate change. Actual cron burn:

- **6 tactical cycles/day** (every 4h :15) × **3 apps/cycle** = 18 Haiku briefs/day. Each brief: ~$0.014–0.018. Daily: **~$0.30**
- **Weekly Monday 6 AM** × **2 apps** = 2 Sonnet deep briefs/week. Each: ~$0.08. Daily average: **~$0.02**
- **Total steady state: ~$0.32/day**

So the cap at $2 gives ~6x headroom for manual cycles, failed retries, and deep cycles outside the weekly cron. $1 would probably be fine too but risks hitting the cap during manual deep-dive sessions. $2 is the conservative middle.

### What the infra_state UI panel tells you at a glance

After session 16, any operator loading admin.crelvo.dev → Brain tab can now see:

- **How many apps have each proxy-layer feature** (header summary)
- **Which specific apps are missing each feature** (per-app cards)
- **Whether a recent nginx edit has propagated** (60s cache, so within 60s of edit + reload)

Typical operational questions the panel answers without SQL or SSH:

- "Did promoforge pick up the admin_tracking fix?" → green AT badge on promoforge card
- "Which apps are missing gzip?" → scan for grey GZ badges
- "How widespread is banner injection?" → summary shows `BN 0/22`, which means the v2 banner embed system is wired to nginx on zero sites (i.e. it's waiting to be turned on)
- "What's orbedge's nginx state?" → everything green except AT, because AT is actually in HTML not nginx

This is the kind of at-a-glance operational UI that the session 13 "portfolio dashboard" vision was reaching for, scoped down to the one dimension (infra flags) where the data is cheap and structured.

## Known Issues & Risks

- **Round 2 (SEO warming) adds to startup latency** — Impact: boot warmth now audits 10 marketable apps' SEO in parallel on top of revenue + analytics. Total startup warm is ~20 seconds. Non-blocking (fires 10s after `listen`) so the health check still passes instantly, but cron fires that happen within the first ~30 seconds of boot might not see SEO in the cache yet. | Mitigation: already handled by TTL fallback — `runBrainCycle` calls `cache.warm()` before `collectAppContext`, which re-runs any refresh that isn't populated. No action needed
- **Round 3 nginx edits are not in git** — Impact: `/home/deploy/nginx-configs/sites/promoforge` and `/home/deploy/nginx-configs/sites/best-age.de` have live changes that don't exist in the appManager repo. If the VM is ever restored from a pristine backup, these edits disappear silently. | Mitigation: same structural issue as the s15 docker-compose mount. nginx configs should be either tracked or scripted in a post-deploy hook, but that's a policy decision for the user
- **`.bak.s16` files in `/home/deploy/nginx-configs/backups/`** — Impact: none during nginx reload (they're outside the `sites/` dir now, so they aren't included). But they accumulate across sessions. | Mitigation: `/home/deploy/nginx-configs/backups/` should get a retention policy (delete after 30 days), or just manual cleanup next session
- **The orbedge false-negative** — Impact: the brain will keep seeing `orbedge.de.admin_tracking = false` forever because `readInfraState` only scans nginx, and orbedge has the tracking inline in HTML. Cost: occasional proposal like "add admin tracking to orbedge" which the operator knows is wrong. | Mitigation: document it (done here), accept the false-negative, or extend `readInfraState` to scan `index.html` for static sites. Not worth doing unless more static sites develop the same pattern
- **The banner dead-code refusal leaves the code in place** — Impact: ~500 lines of v1 crosspromo and v2 banners/placements code remain in `marketing.js` (~2200 lines total), some of which may be genuinely stale even if the UI still references it. Future cleanup could be targeted (e.g. verify the v1 crosspromo banner serve endpoint gets zero traffic for 30 days, then rip it). | Mitigation: a proper audit pass would need traffic data from access logs, which the brain doesn't have. Not this session's fight
- **All session 15 known issues carry unchanged** except:
  - **SEO cache is never warmed** — ✅ FIXED in round 2 of this session
  - **promoforge nginx missing admin_tracking** — ✅ FIXED in round 3 of this session
- **brain-smoketest.mjs is still ephemeral in container** — unchanged since session 14. `deploy.sh` still doesn't sync it. Unchanged known issue

## What Worked Well

- **Reading the previous handover's "What Worked Well" and "What Didn't Work" sections before starting** — Session 15 explicitly warned "read the traps section, not just the priorities". Session 16 did, and it paid off immediately when round 3's sed-on-nginx-sub_filter task required escaping the exact kind of JS-in-quotes pattern that session 15 had already burned a deploy cycle on. Knowing that substring matches beat regex for these strings saved time
- **Verifying handover claims against reality, not trusting them** — Session 15 said 4 apps were missing admin_tracking. Session 16 checked all 4 and found only 2 were. The other 2 would have been fixed "successfully" with no-op edits, polluting the git log and maybe (in the abschlusscheck case) double-injecting the script into the HTML. Always verify the premise before acting on it
- **Moving backup files out of `sites/` before running `nginx -t`** — Initial attempt left `.bak.s16` in `sites/` and triggered `conflicting server name` warnings that the user would have treated as a regression. Catching it in the test step and fixing by `mv`-ing to a new `backups/` directory turned "almost-broken" into "cleaner than before"
- **The refusal to rip 500 lines of banner code** — The handover said "do it". The reality said "don't". Session 16 picked reality. A 1-minute grep audit prevented 20+ minutes of cleanup work followed by rollback and an embarrassing session note about "broke the Banners admin panel". The right autonomous move on a high-blast-radius instruction is to verify first and refuse second if verification fails
- **Keeping rounds small and independently committable** — 4 commits instead of 1. Each round was rolled out, verified, and pushed before starting the next. If round 4 had broken the dashboard somehow, rounds 1–3 would still be good. This is the "cheap rollback" discipline from sessions 13–14 continuing to pay off
- **Running both `nginx -t` AND a live `curl` to verify round 3** — syntax passing doesn't mean the sub_filter is matching. A curl against the live site was the only real proof. Always verify the output of a config change, not just the config's syntactic validity

## What Didn't Work (Traps to Avoid)

- **First `nginx -t` had conflicting server names from the fresh `.bak.s16` files** — Left the backups in `sites/` by habit. nginx includes every file in the directory, so any backup with `server_name` directives becomes a live conflict. **Rule: ALWAYS put nginx config backups in a sibling directory, never in `sites/`**. This session caught it during the test step, but it's the kind of thing that could pass a lax test and then 502 the site under load
- **Attempted to verify `/api/brain/infra-state` via HTTPS with basic auth** — The `.env` file on the VM doesn't have `BASIC_AUTH_USERNAME` / `BASIC_AUTH_PASSWORD`. The nginx `auth_basic` uses `.htpasswd` which the deploy user can't read without sudo. Wasted a couple minutes chasing a red herring. **Rule: for live endpoint verification, use `docker exec ... node -e '...'` to call the endpoint's underlying function directly, or use `docker exec ... curl http://127.0.0.1:3000/...` with the internal Express port (which bypasses nginx auth_basic)**. The internal curl needs a valid session cookie OR the endpoint needs to be in `PUBLIC_PATHS`, so the underlying-function approach is usually cleaner
- **Read `fs.existsSync` + iteration in `node -e` worked fine** but for more complex verification (like calling `registerMarketingBrainRoutes` with mock args), the brain-smoketest.mjs approach from session 14/15 is still the right tool. It's ephemeral but reliable
- **Cost cap env var name** — used `BRAIN_DAILY_COST_CAP_USD` which matches the existing `BRAIN_MORNING_EMAIL` prefix pattern. Future session should NOT rename this to something shorter or more generic; consistency with the existing `BRAIN_*` family is worth more than brevity

## Next Steps (Priority Order)

1. **Activate `BRAIN_MORNING_EMAIL` on VM** — UNCHANGED from sessions 14 and 15. 5 minutes. Needs user email address. Highest-value user-unblocked item remaining
2. **Trigger / verify the morning rollup email path works** — Once #1 is set, `POST /api/brain/morning/send-test?to=<email>` confirms delivery. 30 seconds
3. **Triage the ~85 open brain actions** — Human task via the Brain tab UI. With rounds 7, 8, 9 live, new actions will be higher-signal; drain the pre-round-7 backlog of stale proposals. 20-30 minutes
4. **Verify Monday 6 AM weekly deep cron on Monday** — Time-blocked. Confirm 2 new briefs appear in the DB and in the Brain tab's "Recent briefs" list
5. **Look at the new infra_state UI panel and decide what to do with the grey badges** — This is the most valuable use of the session 16 UI addition. Load admin.crelvo.dev → Brain tab → scroll down. Any widely-grey flag (e.g. `BN 0/22` = no banner injection anywhere) is a policy question: turn it on, or formally kill that system. Any scattered grey (e.g. missing gzip on 2 apps) is a trivial nginx fix
6. **Run deep cycles on whichever apps the user wants prioritized** — Session 15 already ran promoforge, sacredlens, abschlusscheck. Remaining marketable apps without a Sonnet brief: whatever is left in `pickNextDeepApps(N)`. Each costs ~$0.08 and produces a strategic brief. User chooses the list; AI runs them
7. **Clean up `/home/deploy/nginx-configs/backups/` periodically** — Not urgent. When the count exceeds ~20 files, delete the older half. Could be a weekly cron but not worth building
8. **Scoped audit of banner code's actual usage** — If the user genuinely wants dead code removed from `marketing.js`, the right approach is: (a) turn on access logging for the v1 crosspromo endpoints for 30 days, (b) query which endpoints got zero traffic, (c) confirm the corresponding UI paths are unreachable, (d) rip those specific paths only. NOT a blind 500-line cleanup
9. **Session 13/14/15 carry-overs** — all still deferred:
   - BannerForge build fix (needs interactive debug)
   - dockfolio.dev dual paths deletion (needs scoping)
   - Social platform credentials (user action)
   - Show HN post (user action)
   - promoforge stale GitHub remote URL (cosmetic)

## Rollback Plan

- **Last known good state before session 16:** `3cc6067 Session 15 handover — extend to cover rounds 7+8 + 3 deep cycles`
- **To revert all 4 rounds:** `git revert a7b173b f8aa374 2b03929 && bash deploy.sh --rebuild`
- **Round 1 only (cost cap):** `git revert 2b03929 && bash deploy.sh --rebuild` — OR simpler: set `BRAIN_DAILY_COST_CAP_USD=5.00` in the VM's `/home/deploy/appmanager/docker-compose.yml` dashboard environment and `docker compose up -d dashboard`
- **Round 2 only (SEO warming):** `git revert f8aa374 && bash deploy.sh --rebuild` — safe, nothing downstream depends on `cache.refreshSeo()` existing
- **Round 3 only (nginx admin_tracking):** on VM, copy `/home/deploy/nginx-configs/backups/promoforge.bak.s16` over `/home/deploy/nginx-configs/sites/promoforge` and `best-age.de.bak.s16` over `best-age.de`, then `sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload`
- **Round 4 only (infra_state UI):** `git revert a7b173b && bash deploy.sh --rebuild` — UI panel + new endpoint both removed, no data loss
- **Nothing touches the database this session** — no migrations, no schema changes, no DB rollback needed
- **Nothing on the brain's history is touched** — all 22 briefs from session 15 persist untouched

## Files Changed This Session

### appManager repo (tracked, committed, pushed)

- `dashboard/routes/marketing-brain.js` — round 1: made `DAILY_COST_CAP_USD` env-configurable with default 2.00 (line 82-88). Round 4: added `GET /api/brain/infra-state` endpoint with portfolio summary + per-app flag breakdown (right before the cron block, ~30 lines)
- `dashboard/routes/marketing.js` — round 2: extracted `refreshSeoCache()` helper, simplified HTTP handler, simplified daily cron, added `cache.refreshSeo()` + made `cache.warm()` cover SEO
- `dashboard/public/index.html` — round 4: added `#brainInfraState` div in Brain tab bottom-right column, added `brainRenderInfraState()` function, wired it into `brainLoadAll()` + `brainState.infra`
- `.env.example` — round 1: documented `BRAIN_DAILY_COST_CAP_USD` under the existing "Marketing Brain (optional)" section

### VM (not in git)

- `/home/deploy/nginx-configs/sites/promoforge` — round 3: added `<script defer src="https://admin.crelvo.dev/api/analytics/track.js" data-app="promoforge"></script>` inside the existing `</head>` sub_filter replacement string
- `/home/deploy/nginx-configs/sites/best-age.de` — round 3: same pattern with `data-app="best-age"`
- `/home/deploy/nginx-configs/backups/` — new directory created. Contains `promoforge.bak.s16`, `best-age.de.bak.s16` (session 16's own backups), and `promoforge.bak.20260410-s215` (leftover from session 15, moved out of `sites/` to stop nginx warnings)

### Remote pushes

- appManager: `3cc6067..a7b173b` pushed to `origin/master` (3 commits)

### Not touched

- `docker-compose.prod.yml` (tracked) — unchanged
- `docker-compose.yml` on VM — unchanged since session 15's nginx-configs mount was added
- `dashboard/config.yml` — unchanged
- `dashboard/brain-smoketest.mjs` — unchanged
- `server.js` — unchanged (round 8's 10s startup warm is still the right hook; now covers SEO for free via `cache.warm()`)

## Open Questions

- **Does the user want to trim the infra_state flag set?** 8 flags is comprehensive but the panel's visual density gets busy on a wide portfolio. Could drop `crosslinks_widget` (legacy), `csp_header` (nobody has it), and `long_cache` (too noisy) to get 5 flags on a cleaner grid. Low priority
- **Should the UI panel group apps by marketability tier (SaaS vs Tool vs Static)?** Currently alphabetical within the `getMarketableApps` list. Grouping would help compare similar apps. ~10 minutes if the user wants it
- **Is the $2/day cap right, or should it be $1?** Steady state is ~$0.32/day so either is fine. $2 gives headroom, $1 forces the user to manually approve deep cycles. User preference
- **What's the actual fate of the banner system?** The refused cleanup surfaces a policy question: v1 crosspromo has an active UI but nobody posts anything. v2 banners/placements has an active UI but no nginx sites inject the embed. Both are technically alive, functionally dormant. Future session could decide: (a) turn them on (write some banners, wire them up to sites), (b) kill them (remove the tabs and the routes), or (c) leave them as pre-built product features for a future launch. Not this AI's call
- **Extend `readInfraState` to scan `index.html` files for static sites?** Would fix the orbedge false-negative. Adds a whole new code path (read HTML, parse for `<script src="...">` tags, match against the flags). ~30 minutes. Value: removes 1 known false-negative + covers future static sites with the same pattern. Worth it only if a second static site develops the same issue

## For Future AIs: The Big Picture

Session 16 was the "cleanup after a big session" shift. Session 15 landed two heavy rounds (nginx infra awareness + cache shape/warming) and session 16 picked up all the small loose threads they left: the cost cap that was still set to the pre-brain default, the SEO cache that round 8 punted on, the two nginx sites that the audit identified as missing admin_tracking, and the UI visibility for the infra state data that was so far only visible inside brain prompts.

The session also demonstrated three important autonomous-work principles:

1. **Verify handover claims before acting on them.** Session 15 got 2 out of 4 admin_tracking flags wrong; blind execution would have silently introduced bugs. The audit took 30 seconds and changed the action list from "fix 4" to "fix 2, skip 2, document the audit errors".

2. **Refuse ambiguous instructions with high blast radius.** The "rip 500 lines of banner dead code" item in the handover was wrong — the code is not dead. Investigating that took 1 minute and prevented an expensive mistake. Documenting the refusal is important: it prevents future sessions from retrying the same failed analysis.

3. **Small rounds, each independently valuable.** 4 commits, each with a clear scope, each tested and deployed before the next starts. If any single round had failed, the others would still be shipped. This is the opposite of "one big refactor that either lands or rolls back entirely".

The Marketing Brain's architecture is now essentially complete at the infrastructure level:
- **Closed feedback loop** (round 6): learnings persist from executed outcomes
- **Infra awareness** (round 7): nginx state is visible in prompts
- **Cache shape + warming** (round 8): real traffic/revenue numbers flow
- **SEO cache warming** (round 9): third data layer symmetric with the other two
- **Infra state in UI** (session 16 round 4): operator can see what the brain sees

What remains is operational: activate the morning email, triage the backlog, run targeted deep cycles, and watch the infra_state panel for policy decisions (turn on banners, kill features, add missing gzip). None of these are architecture work. The brain is done being built. Now it's about being used.

The operating principle from sessions 13–16 still holds: **"work like a good employee, know what's best, u decide all, document clearly for future AIs."** Session 16 honored it by refusing to do the wrong thing even when the instructions said to do it, and by writing this handover instead of faking productivity with make-work.

The portfolio arc remains: **30+ products, near-zero revenue, Marketing Brain as the autonomous productization engine.** Session 16 didn't move the revenue needle directly. It made the brain's output easier to trust and the operator's view into the brain's reasoning more direct. Both of those are preconditions for the brain's output ever being acted on.
