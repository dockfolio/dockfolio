# Session Handover

**Date:** 2026-06-29 (Session 28)
**Duration:** ~1 session, research-heavy
**Goal:** Find the existing "how we get customers / website views" knowledgebase, verify that LohnCheck is genuinely our biggest view-getter, then deep-research + brainstorm + evaluate NEW simple websites we could build to capture views and ad money — "things people ask AIs about, that AIs then recommend a tool/site for." Add it all to the knowledgebase, verified, 100% sure.

> Session 27 (AI-search/GEO audit + 12 GSC verifications + dockfolio fix) and session 26 (Telegram/Stripe sale notifications) are both complete and in git history. This file supersedes session 27's handover. Files 01-05 of the GEO knowledgebase are session 27's; **file 06 + its appendix are this session's addition.**

## Summary

The user asked me to locate the knowledgebase about getting views/customers (it turned out to be the 5-file `plans/ai-search-geo/` GEO knowledgebase from session 27), confirm that LohnCheck (lohnpruefung.de) is our biggest organic-traffic success, and then brainstorm + deep-research new "view-magnet" sites on the same model — simple sites that get huge traffic and host ads. Mid-session the user added two sharp steers: (1) the discovery channel to optimize for is **AI-first** — people ask ChatGPT/Perplexity an interesting question, the AI researches the web and cites OUR site; (2) the monetization is **display ads** on the page they land on. Goal = views × ad RPM.

The biggest surprise was verifying the premise. Plausible analytics says LohnCheck got only **92 visitors in 6 months** — which would have made it look like a failure. But the server-side nginx logs show **~6,426 requests/day, #2 in the whole portfolio.** The gap is because LohnCheck's privacy-conscious German payslip-checking audience blocks client-side JS analytics at extreme rates (the tool itself advertises "nothing is sent to our servers," self-selecting for tracker-blockers). The user separately confirmed that oldworldlogos.com's higher Plausible number (1,612) was a one-off Telegram-channel promotion, not organic. So the premise holds when measured server-side, and a permanent lesson dropped out: **measure these tools via nginx logs, never Plausible.**

I distilled the LohnCheck model, integrated the user's steer as the governing strategy, and ran **five parallel deep-research agents** (German finance Rechner, German health/life calculators, AI/GEO global tools, monetization economics, English AI-cited ad content). I synthesized everything into a new knowledgebase file (`06-view-magnet-site-ideas.md`) with a ranked two-track build plan, plus a raw-research appendix, updated the README, and committed + pushed (`ee95a5c`). The session ended cleanly; the only open thread is the user's last question: "Want me to scope the actual multi-tool platform?" — unanswered, that's Next Step 1.

## What Got Done

- [x] **Located + read the full existing knowledgebase** — `plans/ai-search-geo/` files 01-05 (landscape, GEO playbook, portfolio audit, GSC findings, next-actions) from session 27.
- [x] **Verified LohnCheck traffic premise with live data** — pulled Plausible (via one clean SSH → `docker exec dockfolio-dashboard node` probe) AND server-side nginx `all-visits.log` host breakdown. Proved Plausible undercounts ~50-100x; server-side LohnCheck = #2 portfolio-wide. Confirmed oldworldlogos = Telegram push (user-stated).
- [x] **Distilled the LohnCheck model** — 8-property repeatable recipe (evergreen head query, single narrow job, free/no-signup, 100% browser-side, official-source-anchored, freshness, SEO+GEO, ads/affiliate/funnel on top).
- [x] **Ran 5 parallel research clusters** (A-E) via background subagents, each returning a scored/ranked findings table with sources.
- [x] **Wrote `plans/ai-search-geo/06-view-magnet-site-ideas.md`** — the synthesis: verified premise, model, governing strategy (AI-first + ads-first + the two zero-click/adblock constraints), selection scorecard, ranked two-track build plan, recommendation, verification/caveats.
- [x] **Wrote `plans/ai-search-geo/06-appendix-research-clusters.md`** — raw cluster tables + sources preserved in-repo.
- [x] **Updated `plans/ai-search-geo/README.md`** — registered files 04, 05, 06, 06-appendix.
- [x] **Committed + pushed** as `ee95a5c` (rebased over 36 incoming commits from a parallel session; no conflicts).

## What's In Progress

- [ ] **Scoping the multi-tool platform** — **State:** not started; it's the natural next step and the user's final question. **Remaining:** propose repo structure, the shared vanilla-JS tool engine, and the first tool to build (recommendation: English finance calculator suite or QR generator). See Next Steps.

## What Didn't Get Done (and Why)

- **No code/site was built** — by design. This was a research + knowledgebase session; the user asked to "analyse, evaluate, brainstorm, add to knowledgebase, suggest." Building is the next session.
- **Exact keyword search volumes not validated** — all volumes in file 06 are directional triangulations because exact MSV sits behind paid Keyword Planner / Ahrefs logins. Flagged explicitly in the doc; validation is a pre-build step the user must do (needs their login).

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| How to verify "LohnCheck gets a ton of views" | Server-side nginx `all-visits.log` as truth; Plausible treated as unreliable | Plausible (client-side JS) is blocked by this audience; nginx logs everything | Trust Plausible | Would have falsely concluded LohnCheck is dead (92 visitors/6mo) |
| Primary monetization track | Two tracks: English ACTION tools = ads; German finance Rechner = affiliate | User wants ads, but German display is crippled (~49% adblock, €1-3 RPM); finance affiliate pays ~1000x more per session | Single track (ads-only German calcs) | German ads economics don't support an ads-first goal |
| Which tools to build | ACTION tools (render/recompute/file/big-surface) only | ~68% zero-click + AIO 8% CTR; COMPUTE/fact tools earn citation but no view/ad | COMPUTE tools (percentage, BMI, unit convert) | AI answers them inline → citation without clickthrough → no ad impression |
| Research method | 5 parallel background subagents, structured deliverables | "Deep research" requested; parallel = fast; keeps raw web dumps out of main context | One big sequential research pass | Slower, context-heavy, less coverage |
| Where to commit | `plans/` is gitignored → `git add -f` only MY files | Files 01-05 + README were force-added the same way; another AI is editing other files locally | `git add -A` | Would have swept up the parallel session's WIP |

## Mental Model

**The portfolio's discovery problem in 2026, in one frame:** classic Google SEO still drives ~88% of clicks, but a fast-growing slice of research happens inside AI answer engines that synthesize an answer and cite a few sources. Files 01-05 are the "how to get found/cited" layer. File 06 is the "what to build so there's something worth finding" layer.

**The LohnCheck insight that powers file 06:** our single best organic asset is a free, no-signup, 100%-browser-side German salary calculator anchored to an official government formula (BMF PAP), updated yearly ("für 2026"). It's cheap to run (static + client JS = ~€0/tool), has zero data liability (nothing sensitive touches the server), scales infinitely, and ranks/gets-cited because of the official-source authority. That's a **repeatable recipe**, not a one-off.

**The two constraints that decide which new sites are worth building (this is the "trick"):**
1. **Zero-click.** If the AI (or Google's inline widget) can fully answer in the chat box, you get the citation but no page-view and no ad. So only build things the model **cannot serialize into chat**: a rendered image (QR), a recompute from the user's own inputs (multi-input calculator), a big sortable/filterable surface (cost-of-living table), a downloadable file (spreadsheet), a visual sequence (knot animation), or live freshness (today's rates). This is the **ACTION-tool vs COMPUTE-tool** split — build ACTION, avoid COMPUTE.
2. **German ads are broken.** ~49% adblock + low RPM → German privacy tools net ~€1-3 per 1000 views. For an ads-first goal, go **English/international** (3-5x RPM, ~32% adblock, bigger TAM). Keep German calculators as a separate **affiliate** engine (one finance lead = €25-370 = thousands of ad-views) that reuses the LohnCheck code and funnels to the existing €9.99 paid tools.

**Measurement trap to remember:** for any free browser-side tool aimed at a privacy/German/dev audience, Plausible/GA undercount catastrophically. Use the nginx `all-visits.log` host breakdown for true scale.

## Known Issues & Risks

- **Directional search volumes** — Impact: a build picked purely on the doc's numbers could chase a smaller-than-stated niche. Workaround: the *relative* rankings are robust. Fix: validate final 2-3 picks in Google Keyword Planner / Ahrefs (needs user login) before committing build hours.
- **A parallel AI/session is editing this repo** — Likelihood: high (rebase pulled 36 commits: fiscanto.de, Selfcheck, GSC work). Impact: push races + risk of `git add -A` grabbing their WIP. Mitigation: always `git fetch` + `git pull --rebase dockfolio master` before pushing; stage only your own files explicitly (never `git add -A`).
- **`plans/` is gitignored** — Impact: new knowledgebase files silently won't be tracked. Mitigation: use `git add -f plans/ai-search-geo/<file>` (that's how 01-05 + README got in).

## What Worked Well

- **Parallel background research agents** — 5 clusters in the time of one, each returning a clean scored table + sources. Saving each cluster to scratchpad as it landed, then assembling, kept main context lean.
- **Verifying the premise before building strategy on it** — the Plausible-vs-nginx discrepancy was the single most valuable finding and would have been missed by trusting the dashboard.
- **One-shot SSH probe** — `ssh deploy@... "cat > /tmp/probe.js && docker cp ... && docker exec dockfolio-dashboard node /tmp/probe.js"` pulled Plausible stats in a single connection (fail2ban-safe). The Plausible API key was in the dashboard container's env; aggregate endpoint is `http://plausible-plausible-1:8000/api/v1/stats/aggregate?site_id=DOMAIN&period=6mo&metrics=visitors,pageviews,bounce_rate,visit_duration` with `Authorization: Bearer <key>`. Per-domain server-side scale: `grep -oiE '<domain regex>' /home/deploy/visit-logs/all-visits.log | sort | uniq -c | sort -rn`.

## What Didn't Work (Traps to Avoid)

- **Trusting Plausible** — see above; it said LohnCheck was nearly dead. Don't.
- **`git push` without rebasing first** — failed (remote was 36 commits ahead from the parallel session). Always rebase first in this repo.
- **`better-sqlite3` inside an ad-hoc `node -e` in the container** — the module isn't resolvable from `/tmp`; the Plausible key was in `process.env` anyway so it didn't matter, but don't rely on requiring app modules from outside the app dir.
- **Reading volumes as gospel** — every SEO source hedges; XOVI/Google both warn Keyword Planner buckets are ranges. Treat as order-of-magnitude.

## Next Steps (Priority Order)

1. **Answer the user's open question: scope the English multi-tool platform.** Propose (a) repo structure for a no-build vanilla-JS multi-tool site (one shared tool-engine + shared template, each tool on its own URL, cross-linked), (b) the GEO scaffolding per tool (definition-first opener, rule/HowTo block, `SoftwareApplication`+`HowTo`+`FAQPage` JSON-LD, "updated 2026"), (c) the first tool to build. **Recommended first build: the finance calculator suite (mortgage/loan/compound) OR the QR generator** — both top the Track-1 ranking in file 06 §4. Do NOT build until the user confirms direction and validates volume.
2. **Before any build, have the user pull exact volumes** for the chosen 2-3 tools in Keyword Planner/Ahrefs (their login). This de-risks the whole bet.
3. **Optional infra win (from file 06 §0): a Dockfolio "true views" panel** that reads nginx `all-visits.log` per domain — ad-block-proof server-side view counts, since Plausible is unreliable for this portfolio. Small, high-value, on-brand for the dashboard.
4. **Track 2 (parallel, when ready): first German finance Rechner** — Pfändungsrechner is the top effort×volume×money pick (pure table-lookup), or extend the LohnCheck PAP engine for Pendlerpauschale/Stundenlohn.

## Rollback Plan

- **Last known good state:** `ee95a5c` (this session's only commit) is purely additive — 2 new files + 1 README edit, all under `plans/ai-search-geo/`. Nothing else touched.
- **If you want to undo this session:** `git revert ee95a5c` (or `git rm` the two 06 files + revert the README hunk). No code, config, or infra was changed, so there is nothing to break.
- **Safe reset (local only, if needed):** `git reset --hard 451fff4` returns to the session-27 tip. Do NOT force-push — the parallel session shares this branch.

## Files Changed This Session

- `plans/ai-search-geo/06-view-magnet-site-ideas.md` — NEW. The main deliverable: LohnCheck model, governing AI-first/ads-first strategy, ranked two-track build plan, recommendation, caveats.
- `plans/ai-search-geo/06-appendix-research-clusters.md` — NEW. Raw findings tables + sources from the 5 research clusters (A-E).
- `plans/ai-search-geo/README.md` — registered files 04, 05, 06, 06-appendix in the file index.
- *(No code, config, or VM changes. One read-only SSH probe for traffic data — no server state altered.)*

## Open Questions

- **Did the user want me to BUILD, or just suggest?** This session delivered the suggestion. The final message offered to scope the platform — awaiting a yes/no + which tool first.
- **English-first vs German-first for the first build?** The doc recommends English (ads) but the user's existing strength + code is German (LohnCheck). Worth a direct decision before building.
- **Where would a new multi-tool platform be hosted/deployed?** Same Hetzner VM + nginx pattern (CLAUDE.md has the static-site deploy guide), but the domain + slug aren't chosen yet.
- **What's the parallel AI session working on**, and is there any coordination risk on shared files? It's editing fiscanto.de + Selfcheck + GSC config; no overlap with `plans/ai-search-geo/` so far.
