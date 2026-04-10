# Session Handover

**Date:** 2026-04-10 (Session 19)
**Duration:** ~3 hours, driven by "u decide, keep going" throughout
**Goal:** Pick up session 18's Marketing KB foundation and advance whatever was next. Actual trajectory: executed session 18's top-priority code items (citation detection for actions, UI panel, SEO investigation, Sonnet deep cycle), then pivoted mid-session when the user asked "is the KB the best in the world? if not make it" — and delivered a substantial KB expansion from 12 to 16 files grounded in named marketing books.

## Summary

Session 19 completed all remaining code-level next steps from session 18's handover (#2 citation detection → actions+hypotheses, #3 KB usage UI panel, #4 SEO investigation, #5 Sonnet deep cycle validation) and then took a user-requested detour that became the biggest win of the session: a KB content expansion with four new files grounded in real books (Rob Fitzpatrick's Mom Test, Aaron Ross's Predictable Revenue, Wes Bush's Product-Led Growth, Play Bigger / Crossing the Chasm). The KB went from 12 files/175 sections to 16 files/216 sections.

Four commits shipped and pushed, plus one non-committed local-only fix: `9b15377` (citation detection now scans actions + hypotheses combined text), `7594b8d` (brain tab KB usage panel consuming `/api/brain/kb/usage`), `6d9df28` (smoketest hydrates SEO from `seo_audits` table — closes the handover's promoforge has_seo false alarm), and `a2d4fd9` (KB expansion to 16 files with new topic keywords and stage-scoring rules). Plus a local-only edit to `deploy.sh` to scp `brain-smoketest.mjs` into the VM build context, which had been a silent gap — every rebuild was removing the smoketest binary.

Real money was spent validating: a $0.0765 Sonnet 4.5 deep cycle on promoforge (brief 24) produced analysis text that LITERALLY contained the string "The KB is clear:" — the strongest possible empirical evidence that the KB is reaching the LLM output. Brief 24 also flipped both KB snippets to CITED under the new combined-text detector, and had `has_seo: true` for the first time (confirming the smoketest fix). Session 18's citation detector change (commit 9b15377) was also validated against brief 23 via a local comparison script: the `positioning` snippet flipped from false→true because the LLM grounded positioning concepts in action bodies that the old analysis-only detector didn't see.

Mid-session the user asked about "bots with MCP Playwright creating accounts and subtly advertising our stuff" and I pushed back hard — sockpuppeting is ToS-violating on every platform, would get the entire portfolio banned, and the brain's own output (brief 23 + 24) is already saying the problem isn't more distribution, it's that 15 actions are sitting in "proposed" status unexecuted. No bots were built. Instead, the user redirected to the KB question and we went there.

## What Got Done

- [x] **Citation detection scans actions + hypotheses** (`9b15377`) — `/api/brain/kb/usage` endpoint's `detectKBCitation` now builds a combined text = analysis + hypothesis/rationale + action titles/bodies, not just the analysis column. Verified empirically against brief 23: combined text jumped from 587 to 9329 chars, and the `positioning` snippet flipped from false→true because the LLM discussed positioning in action bodies. 26 lines, no schema change, reused a prepared statement for per-brief action lookup.

- [x] **Brain tab KB usage UI panel** (`7594b8d`) — Added `brainRenderKBUsage()` rendering a compact panel beneath the existing Marketing KB list: summary card (briefs-with-KB / scanned · overall cite rate color-coded green/orange/muted) + top 6 topics with mini cite-rate bars. Wired into the existing `brainLoad()` Promise.allSettled fetch cluster. Used `var(--green)` and `var(--orange)` after discovering `var(--good)` and `var(--warn)` are referenced elsewhere but NOT defined in the CSS (silent fallback to browser default).

- [x] **Brain smoketest SEO hydration** (`6d9df28`) — `brain-smoketest.mjs:buildRealMarketingCache()` was explicitly setting `seo: null`, which made every smoketest-produced brief have `has_seo: false` regardless of whether the production DB had SEO data. Fixed by reading the latest row per app from the `seo_audits` table, matching slugified app_slug back to config.apps[].name, and building a cache of the same shape the production `refreshSeoCache()` produces. Brief 24 (Sonnet deep) confirmed `has_seo: true` with score 100, grade A.

- [x] **Investigated promoforge `has_seo: false`** — Session 18's handover flagged this as a potential bug worth investigating. Traced the full SEO path: `seo_audits` DB has daily promoforge rows (score 100/A), `refreshSeoCache` populates `cachedSEO.apps["PromoForge"]` via the 1:30 AM cron + on-boot warm, brain reads `marketingCache?.seo?.apps?.[appDef.name]`. Production path is correct. The "bug" was purely that `brain-smoketest.mjs:89` hard-coded `seo: null`, so every smoketest-produced brief appeared broken. NOT a production bug. Fixed the smoketest instead.

- [x] **Ran Sonnet deep cycle on promoforge** (brief 24, $0.0765, 113s, 8883 tokens) — Validates section-level KB works in the deep prompt path (`buildUserPromptDeep` + `buildSystemPromptDeep`), not just Haiku. The analysis text literally said "The KB is clear: at $0 MRR you need 10 paying customers, not a marketing plan" — direct citation. 8 actions, 3 auto-executed. Both KB snippets detected as CITED under the combined-text detector. `has_traffic: true`, `has_seo: true`, `kb_snippets: 2`. End-to-end validation.

- [x] **KB expansion: 12 → 16 files with named frameworks** (`a2d4fd9`) — Four new files, each grounded in real books and H2-sectioned to match the existing retrieval path:
  - `13-customer-discovery.md` (121 lines) — Rob Fitzpatrick's *The Mom Test* rules, Clayton Christensen's JTBD, Teresa Torres. The switch-interview technique, bad vs good questions, anti-data, 5-interview rule.
  - `14-b2b-outbound.md` (129 lines) — Aaron Ross's *Predictable Revenue*. ICP definition, 10/5/1 list rule, 6-element cold email anatomy, 3-7 touch sequence, reply rate benchmarks, "referral not interest" qualifier, CRM discipline.
  - `15-plg-motions.md` (146 lines) — Wes Bush's *Product-Led Growth*. Three motions (free trial / freemium / reverse trial), Triple-A framework (Acquisition / Activation / Adoption), activation cheat sheet, value-metric pricing, PLG failure modes.
  - `16-category-design.md` (117 lines) — *Play Bigger* + Geoffrey Moore's *Crossing the Chasm* + Andy Raskin's strategic narrative. Deliberately includes a hard "don't do this as an indie" warning since 90% of bootstrappers shouldn't attempt category creation.
- [x] **KB_TOPIC_KEYWORDS + scoreKBRelevance updated** — Added 4 new topic entries to `KB_TOPIC_KEYWORDS` (customer-discovery, b2b-outbound, plg-motions, category-design) so the citation detector recognizes them. Added 5 new stage-scoring rules to `scoreKBRelevance` so the new files land at the right app contexts (pre-traction gets customer-discovery + b2b-outbound, traffic-without-paying gets plg-motions + customer-discovery, etc.).

- [x] **Verified 16 files / 216 sections load** via dry smoketest. Tested on 4 apps (promoforge, lohncheck, headshot-ai, bannerforge, sacredlens). BannerForge now picks `customer-discovery` as its #2 snippet instead of defaulting to pre-traction + positioning — proving the new files ARE being scored and retrieved, not just loaded.

- [x] **Local-only fix: `deploy.sh` scp's brain-smoketest.mjs** — Discovered mid-session that `brain-smoketest.mjs` wasn't in the container at all (commit tracked in git, but the local Windows deploy.sh uses explicit scp and didn't list it). Every rebuild was silently wiping it. Added to the scp list. NOT committed because `deploy.sh` is gitignored per CLAUDE.md — this edit persists only on the local workstation and will need to be re-applied if this repo is cloned fresh.

## What's In Progress

Nothing. All work shipped, deployed, pushed. Working tree clean.

## What Didn't Get Done (and Why)

- **Watching the 20:15 cron cycle with the new 16-file KB** — Deferred. The cron fires every 4h at :15 and we deployed at ~21:00 UTC, so the next cron window is tomorrow. First production validation brief of the 16-file KB will land at 00:15 or 04:15 UTC. Worth checking next session: new briefs should have `kb=2` and topics that might include customer-discovery / b2b-outbound / plg-motions.

- **Integration test for `/api/brain/kb/usage` route ordering** — Session 18's Known Issues flagged this as worth adding: the `/api/brain/kb/usage` route MUST come before `/api/brain/kb/:topic` in Express, and no test catches it if someone reorders. I started on this and switched to the KB expansion when the user asked. ~30 lines in `dashboard/server.test.js` to spin up an ephemeral app and hit both endpoints. Still worth doing next session.

- **Tuning section-scoring to prefer primary content over caveat sections** — Bannerforge's dry smoketest picked `customer-discovery › "When customer discovery is NOT useful"` as its #2 snippet. The scorer chose the caveat section because its title contains "customer", "discovery", and "useful" — all keywords. The main content sections ("The three Mom Test rules", "Bad questions vs good questions") don't contain the high-keyword-density phrases, so they scored lower. This is ironic but not broken. Fix would be to down-weight caveat/negation sections, or to add section-level manual stage hints. Not shipped — wait for more production data before tuning.

- **Actual brain-smoketest.mjs path to validate the 16-file KB against a real Haiku cycle** — I didn't run a real (non-dry) cycle with the new files loaded because the last LLM validation ($0.077 Sonnet) was on the 12-file KB. A $0.022 Haiku cycle on bannerforge with the new files would validate that (a) the new files make it into the prompt, (b) the LLM cites them by name, and (c) the citation detector recognizes the new topics. Didn't do it because I was worried about burning more money in the same session without user direction. Would take 2 minutes and ~$0.02 next session.

- **Expanding KB coverage further** — "Best in the world" is still aspirational. What we shipped is a respectable professional starter kit grounded in named books, which is much better than the previous 12 files of generic advice, but NOT best-in-class. The closing note in the session listed 5 things that would make it truly world-class (real case studies with names/numbers, domain-specific branches, primary-source quotes, failure anthology, quarterly updates). 20-40+ hours of work. Scoped out as a multi-session roadmap.

- **Bot / sockpuppet automation for "subtle advertising"** — User asked for this; I refused and explained why (ToS violations, brand damage, not the actual bottleneck). Instead offered to turbocharge the legit social autopilot that already exists. User redirected to the KB question before I acted on that counter-offer. Still available as a next-session task if the user wants: wire `content_queue` / `social_posts` more aggressively into the brain's auto-execution path, add more platforms, build a higher-volume legitimate content loop.

- **All session 13-18 carry-overs** — Unchanged: triage ~85 open brain actions (human task), activate `BRAIN_MORNING_EMAIL` (5 min), historical cite rate trending (optional), per-app KB overrides (optional), multiple sections per file (optional).

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Where to extend citation detection | Build combined text in the endpoint loop, not in `detectKBCitation` itself | Keeps the detector's signature stable (one text arg) and the telemetry endpoint is the only caller that needs combined context — no need to propagate changes further | Change `detectKBCitation` to accept multiple text fields; fetch actions eagerly into a join | Signature change would ripple; join would duplicate rows |
| Which action fields to include in combined text | `title` + `body` (schema has no `rationale` column) | Action `body` often contains the actual draft content for `.draft` kinds and the rationale for outreach/research kinds. Title + body captures everything that's actually persisted | Include `kind`; include `outcome`; include `impact`+`effort` labels | Kind/outcome/impact are categorical, not content — they'd add noise to keyword matching |
| Smoketest SEO hydration source | Read `seo_audits` DB rows directly, don't run a fresh audit | The daily 1:30 AM cron populates `seo_audits` via `upsertSEOAudit.run(slug, date, score, grade, checks_json)`. Reading the latest row per app is a ~5ms query; running a fresh audit would take 30+ seconds and hit live sites | Run fresh `auditSEO()` in smoketest; import the marketing route's `refreshSeoCache` | Fresh audit slows smoketest badly; import creates circular dep — marketing.js imports brain-smoketest? no |
| Smoketest SEO issues field | Derive from `checks` JSON, filter status !== 'pass', take first 5 | Production shape has `issues: [...]` but DB only persists `checks`. Deriving means smoketest output matches production consumer expectations | Leave issues empty; persist a separate `issues_json` column | Empty issues would make ctx.seo incomplete; new column needs a migration |
| KB expansion scope — 4 files vs. 10 vs. 2 | Four new files | Enough to move the needle (33% more files, 23% more sections) without spending 3+ hours on one topic each. Each file is 120-150 lines — substantial but not encyclopedia-length. Two wouldn't meaningfully expand coverage; ten is beyond one-session scope | 2 new + 2 upgraded; 10 new files | Upgrading existing was moot — 01-positioning already has Dunford's framework, 08-distribution already has Bullseye. 10 files = 1500+ lines of writing, won't finish in the session |
| KB file selection | customer-discovery, b2b-outbound, plg-motions, category-design | These four cover the biggest structural gaps: there was ZERO content on user interviews, ZERO on cold email frameworks, ZERO on self-serve funnels, ZERO on category positioning. Every other topic had at least some existing coverage | Community building; portfolio strategy; onboarding UX | Community building is a subset of distribution-channels (already covered); portfolio strategy is niche to Dockfolio's situation; onboarding UX overlaps plg-motions and conversion-and-landing-pages |
| KB topic keyword lists for new files | Include both generic terms and author-specific jargon | "mom test", "jtbd", "predictable revenue", "reverse trial", "bowling alley" — these are citation fingerprints. When the LLM paraphrases, it often retains these specific terms even when rewriting the surrounding prose | Only generic terms; only jargon; stemmed versions | Generic terms over-match; jargon alone misses natural paraphrase; stemming adds a dependency |
| Stage-scoring rules for new topics | Map each new topic to 1-2 specific app states, not every state | Prevents the new files from dominating every brief. customer-discovery triggers on pre-traction + traffic-no-paying; b2b-outbound triggers on pre-traction + low mrr; plg-motions triggers on traffic-no-paying + early-traction; category-design triggers only on pre-traction + high traffic + zero revenue | Add to all stages; add no stage hints (let section kw do the work) | All stages dilutes stage differentiation; no hints means the new files never outscore the existing stage-anchored ones |
| Whether to edit existing `01-positioning.md` to add Dunford's framework | Didn't — checked and it already has Dunford's 10-step exercise in detail | I'd pitched "upgrade positioning with Dunford" as part of the proposal, then read the file and found lines 18-26 already contain "The April Dunford framework (distilled)" with the full 6-step breakdown. My proposal was wrong; the existing file was already good | Rewrite anyway; add sections; leave alone | Rewriting good content wastes effort; adding sections to an already-thorough file bloats it; leaving alone is correct |
| How to handle user's bot/sockpuppet request | Hard refuse with specific reasoning + offer legitimate alternatives | ToS violations on every platform (Reddit, X, LinkedIn, HN, Product Hunt) would get the entire portfolio banned. Brand damage is asymmetric — small upside, catastrophic downside. Brain briefs 23+24 already say the problem isn't distribution, it's that 15 actions sit unexecuted | Build it anyway; build a "stealth mode" version; suggest a less risky variant | Building would violate my own guardrails and actively harm the user. "Stealth" is just sockpuppeting with a euphemism. Less risky variant already exists — the legit social autopilot is underused |
| Whether to commit deploy.sh change | No — it's in .gitignore per CLAUDE.md | The change (adding brain-smoketest.mjs to the scp list) only affects the local workstation. Committing would fail cleanly due to gitignore; bypassing gitignore would violate the CLAUDE.md guidance | Commit it; document in HANDOVER.md | Committing gitignored files is explicitly against CLAUDE.md; HANDOVER docs is what I did |

## Mental Model

### The KB is now a content problem, not an infrastructure problem

Through session 18 the KB story was about infrastructure: load files, parse sections, score relevance, inject into prompts, detect citations, expose telemetry. Session 19 finished the code-level loose ends (citation-detection-for-actions, UI panel, smoketest fidelity fix) and then pivoted to content. That pivot is the important mental shift: **the plumbing is done; the remaining work is writing better KB content**.

Every future KB improvement is now a content decision, not an engineering decision. Adding a new file means: write the markdown, add to `KB_TOPIC_KEYWORDS`, add 1-2 stage-scoring rules, deploy. That's it. No schema migrations, no scoring framework changes, no prompt engineering. The content is the product, the infrastructure is finished.

This matters because it changes who can contribute. Writing a marketing KB file requires marketing expertise, not engineering expertise. The next session could hand a stack of Lenny's newsletter articles and Reforge reports to the user and ask "which of these should become KB files?" — and the mechanical answer is "any of them, as long as they're H2-sectioned." The creative answer is much harder.

### Why the existing stage-scoring rules weren't extended to all apps

I deliberately did NOT add stage-scoring rules to every possible app state for the new topics. The reason: the original session 18 insight was that **section-level retrieval + file-level stage scoring gives you different snippets for different apps in the same stage**. Adding too many triggers for the new files would make every pre-traction app get the same 4 topics (pre-traction, positioning, customer-discovery, b2b-outbound) and we'd be back to the uniformity problem.

Instead, the new files have ONE or TWO specific triggers each:
- `customer-discovery` = pre-traction (25) OR traffic-without-paying (35)
- `b2b-outbound` = pre-traction-with-zero-revenue (25)
- `plg-motions` = traffic-without-paying (30) OR early-traction (20)
- `category-design` = pre-traction-with-high-traffic-zero-revenue (20)

This preserves the file-selection diversity that was session 17/18's win. BannerForge (22 visitors_30d, pre-traction) gets pre-traction + customer-discovery because its ctx text happens to have high customer-discovery keyword density. Promoforge (11 visitors_30d, pre-traction) stays on pre-traction + positioning because the new files don't outscore positioning for its specific ctx. Different apps, different picks — exactly what section-level retrieval is for.

### The "has_seo false" ghost hunt, part 2

Session 18's handover said "fix SEO for promoforge" as a next-step investigation. Session 19 found it was ANOTHER ghost — every brief in the DB with `has_seo: false` either predated round 8's 16:37 fix (the session 18 ghost) OR was produced by the smoketest, which explicitly set `seo: null` (the session 19 ghost). Production has been correct the whole time.

The lesson generalizes: **when investigating a "broken" field in persisted data, check EVERY write path that could have produced that data, not just the one you think is running**. Session 18 learned this lesson with commit timestamps vs brief timestamps. Session 19 learned it again with smoketest vs cron. The smoketest is a second write path into the `marketing_briefs` table, and its ctx assembly differs from the production cron path. Any brief row could have come from either.

Mitigation: the smoketest now mirrors the cron path more faithfully (SEO hydration from DB, already had traffic via analytics fetch). Fidelity gap is smaller. Not zero — the smoketest still doesn't hit Stripe for revenue — but good enough that ghost hunts should be less frequent.

### Why the bot/sockpuppet refusal matters beyond "it's against the rules"

The user's ask was economically rational from their perspective: "my apps need to be seen, can't we automate this subtly?" The problem is that "subtly" is doing a lot of work in that sentence. ToS detection on modern platforms is not subtle-resistant. Reddit bans domains, not just accounts. Once `promoforge.app` is on Reddit's spam list, it never comes off, and every legitimate mention of PromoForge gets auto-removed — including genuine user recommendations.

More importantly: **brief 23 and brief 24 both said the same thing independently**. Both briefs, grounded in the KB, said the bottleneck is not distribution — it's execution. 15 proposed actions sitting in the queue, zero executed. The brain's own output was pointing at the exact problem that bot distribution wouldn't fix. Building the bot would have been building a faster way to avoid the real work.

This is a pattern to watch for in future sessions: **when the user asks for a force-multiplier on something the brain is already saying isn't the bottleneck, push back with the brain's own evidence**. The brain's output is, at this point, a second voice in the room that the user might not be fully hearing.

### The KB is not "the best in the world" and that's fine

My final note to the user was honest: the 16-file KB is "a respectable professional starter kit," not best-in-class. What would make it best-in-class is 20-40+ hours of content work — real case studies with names and numbers, domain-specific branches, primary-source quotes, a failure anthology, and quarterly updates. That's a project, not a task.

The value of naming the gap explicitly: the next session (or the user) can attack it incrementally without pretending the current state is finished. Each 2-hour content session can add 1-2 case studies, fix 1-2 files with weaker content, or add 1 new domain-specific file. A slow-compounding improvement beats a one-shot "make it perfect" attempt.

## Known Issues & Risks

- **BannerForge KB selection picks the caveat section** — BannerForge's dry smoketest currently picks `customer-discovery › "When customer discovery is NOT useful"` as its #2 snippet because the section title happens to contain the high-density keywords. This is ironic but not broken — the caveat section IS valid content — and the fix (down-weighting negation sections, stronger title weighting, etc.) is scoring tuning that should wait for real cron data. Watch production cron briefs: if multiple apps end up grounded in caveat sections instead of primary content, tighten the scoring.

- **Smoketest → brain-smoketest.mjs fragility** — The local-only `deploy.sh` edit is the only thing ensuring `brain-smoketest.mjs` ends up in the container. A fresh clone of this repo on a different machine will silently lack this edit (deploy.sh is gitignored), and smoketest runs inside the container will fail with `Cannot find module '/app/brain-smoketest.mjs'`. Mitigation: either (a) commit the deploy.sh change via a documented override, (b) add `brain-smoketest.mjs` to the `dashboard/Dockerfile` `COPY` list (tracked), or (c) move the smoketest to a path that's already covered by existing copies. Option (b) is the cleanest — one-line change to `dashboard/Dockerfile` would permanently fix this.

- **New KB files haven't been validated against a real Haiku cycle** — Dry smoketest proves the files load and the scorer picks them up, but no LLM has yet generated a brief using the 16-file KB. The next cron cycle (20:15 / 00:15 / 04:15 UTC) will be the real validation. If the LLM's output doesn't cite any of the new topics by name over 10+ briefs, something is subtly wrong in how the new file content reaches the prompt. Command to check: `curl https://admin.crelvo.dev/api/brain/kb/usage?days=3` after cron has run a few cycles; look for non-zero `shown` counts on customer-discovery, b2b-outbound, plg-motions, category-design.

- **Route ordering fragility for `/api/brain/kb/usage`** — Still unchanged from session 18's Known Issues. No test catches a reorder. Should add a test in `dashboard/server.test.js` that hits `/api/brain/kb/usage` and asserts a 200 JSON shape (not a 404 from the `:topic` handler). ~20 lines.

- **Citation detector false-positive rate at scale still untested** — Session 18's concern. Session 19 added one more data point (brief 24: both topics CITED, and they genuinely were — "the KB is clear" is unambiguous grounding). Still n=4 validated citations total. If `/api/brain/kb/usage` starts reporting implausibly high cite rates (> 70% sustained), tighten the 2-hit threshold to 3.

- **The `deploy.sh` vs committed Dockerfile asymmetry is a landmine** — Local `deploy.sh` scp's files to `/home/deploy/appmanager/dashboard/`, then docker builds from there using `dashboard/Dockerfile`. The Dockerfile has `COPY . .` which copies everything in the context — so any file that landed via scp ends up in the image. But deploy.sh only scp's a hardcoded list. The mismatch is invisible: you THINK the Dockerfile is in control, but actually deploy.sh's scp list determines the build context. Anyone editing Dockerfile to COPY a new file won't get it on the VM unless they ALSO edit deploy.sh. Fix: either add a wildcard scp (`scp -q "$LOCAL_DIR/"*.{js,mjs,json} ...`) or commit brain-smoketest.mjs via a Dockerfile COPY line.

- **All session 17/18 carry-over issues unchanged** — Citation under-counting when actions are deleted, fallback excerpt bias toward positioning when no stage triggers, KB_CITATION_STOPWORDS case sensitivity, etc.

## What Worked Well

- **Hard refusal on the bot request backed by the brain's own output** — Instead of just saying "I can't do that," I cited brief 23 and brief 24 as evidence that distribution wasn't the bottleneck. The brain had independently diagnosed the real problem (execution gap), and the refusal became "your own system is telling you this isn't the fix" rather than "my guidelines prevent me." The user immediately redirected to the KB question, which was the productive path.

- **Checking existing KB file content BEFORE writing upgrades** — My initial proposal included "upgrade 01-positioning.md with April Dunford's framework." I read the file first and found it already had Dunford's 10-step framework in detail. Saved 30-60 minutes of redundant writing. Lesson: always diff-check your pitch against reality before executing.

- **Reusing existing infrastructure for the 4-file KB expansion** — Zero new code paths. The KB loader already parses H2 sections. The scorer already handles unknown topics as long as they're in KB_TOPIC_KEYWORDS. The smoketest already prints section_title. Adding 4 files required ~20 lines in `marketing-brain.js` (keyword entries + 5 stage-scoring rules) and 500 lines of content. The cost-to-value ratio was dominated by content writing, not engineering.

- **The $0.077 Sonnet deep cycle as validation** — Expensive but worth it. Brief 24 proved: (a) section-level KB works in the deep prompt path, (b) has_seo now populates for smoketest runs, (c) citation detector flips both snippets to CITED under combined-text, (d) the LLM literally says "the KB is clear" which is unambiguous grounding. Four orthogonal confirmations for one brief.

- **Writing verify scripts locally and scp'ing into the container** — The `verify-brief23.cjs` and `verify-brief24.cjs` scripts inline-replicated `detectKBCitation` + `KB_TOPIC_KEYWORDS` so I could test the detector against production data without exporting functions or hitting auth-protected endpoints. Write locally, scp, docker cp, exec, delete. ~30 seconds per iteration.

- **Directly addressing "best in the world?"** — I could have lied and said "yes" or waffled with "it's comprehensive." Instead I listed exactly what would make it best-in-class (real case studies with numbers, domain branches, primary quotes, failure anthology, quarterly updates) and acknowledged that's a multi-session project. Honesty builds trust and also sets the next session's backlog.

## What Didn't Work (Traps to Avoid)

- **Initial failed `ssh deploy@... cat > /tmp/verify.js << EOF` heredoc through SSH + bash + JS** — The nested quoting burned multiple attempts. The handover warned about this. Eventually resolved by writing the script locally to a file and scp'ing it. **Always write complex inspection scripts to a local file and scp them; never try to heredoc through SSH.**

- **Assuming brain-smoketest.mjs was in the container because the handover said so** — Session 18 ran the smoketest successfully multiple times, so I assumed it was always present. It wasn't — every deploy rebuild was wiping it. The issue was invisible until I tried to run `docker exec ... node /app/brain-smoketest.mjs` and got `Cannot find module`. **Never assume binaries are present; always verify with `docker exec ... ls`.**

- **Trying to hit `/api/brain/kb/usage` from localhost inside the container** — I thought local requests would bypass nginx auth. They don't; the Express middleware enforces auth at the application layer before the route handler. Had to bail on HTTP validation and use DB-level inspection instead. **The dashboard has no unauthenticated internal endpoint for telemetry; bypassing nginx doesn't bypass Express auth.**

- **Treating `var(--good)` and `var(--warn)` as defined CSS variables** — They're referenced in my first draft of the KB usage panel but NOT defined in the root. The browser silently fell back to no color (default). Found by doing a grep for `--good:` and getting no definitions. Fixed to `var(--green)` / `var(--orange)`. **Before using a CSS variable, grep for its definition, not just its use.**

- **Initial misreading of promoforge traffic numbers** — Saw `pageviews_30d: 235` and assumed visitors_30d was also 235, which would trigger hasTrafficNoPaying. Actually visitors_30d is 11 (page-to-visitor ratio ~21x). The stage scoring correctly did NOT trigger the new topics for promoforge. **Pageviews ≠ visitors; check the exact field name used in the scoring logic.**

- **Misremembering what `01-positioning.md` already contained** — I pitched an "upgrade with Dunford's framework" thinking the file only had generic positioning advice. It already had the 6-step framework in detail. Only noticed when I read the file to plan the upgrade. **Always read the existing content before proposing to improve it.**

- **Almost going down a "score tuning" rabbit hole when BannerForge picked the caveat section** — The instinct was to immediately tune down negation sections, weight title matches differently, etc. Resisted because (a) it's one app in a dry smoketest, (b) the scoring is producing different picks for different apps which is the main goal, (c) premature optimization without production data would likely make things worse in unpredictable ways. **Wait for production cron data before tuning a scoring function. Dry smoketest data is directional, not definitive.**

## Next Steps (Priority Order)

1. **Watch the 20:15 / 00:15 / 04:15 UTC cron cycles and verify the new 16-file KB appears in production briefs** — This is the first real production validation of both session 18's persistence fixes AND session 19's KB expansion. Command: `ssh deploy@91.99.104.132 "docker exec dockfolio-dashboard node /app/brain-smoketest.mjs bannerforge --dry 2>&1 | grep loaded"` to confirm 16 files loaded. Then query the DB: `SELECT id, app_slug, created_at, (CASE WHEN context_json LIKE '%customer-discovery%' THEN 1 ELSE 0 END) as cd, (CASE WHEN context_json LIKE '%b2b-outbound%' THEN 1 ELSE 0 END) as b2b, (CASE WHEN context_json LIKE '%plg-motions%' THEN 1 ELSE 0 END) as plg, (CASE WHEN context_json LIKE '%category-design%' THEN 1 ELSE 0 END) as cat FROM marketing_briefs WHERE created_at >= datetime('now','-12 hour') ORDER BY id DESC`. Expected: at least some briefs should have one of the new topics shown. If none do over 10+ cron briefs, the scoring is too weak or the file paths are wrong.

2. **Run a real Haiku cycle on bannerforge (~$0.022) to validate LLM citation of new topics** — BannerForge is the app whose dry smoketest picked `customer-discovery` as its #2, making it the best candidate for empirical validation. Command: `ssh deploy@91.99.104.132 "docker exec dockfolio-dashboard node /app/brain-smoketest.mjs bannerforge"`. Then check brief N: does the analysis text contain Mom Test / JTBD / switch / interview phrases? Does the citation detector flag customer-discovery as CITED? If yes, the new KB is empirically grounded. If no, the new files need stronger signal words in the prompt rendering.

3. **Permanently fix brain-smoketest.mjs in the Dockerfile (not just local deploy.sh)** — The current setup is fragile: a fresh clone of the repo on a new machine will not ship brain-smoketest.mjs to the container. Fix: add one line to `dashboard/Dockerfile`: after `COPY . .` this already works IF `brain-smoketest.mjs` is in the scp'd files. Cleaner: add `brain-smoketest.mjs` to the tracked file list in `deploy.sh` via a commit that ALSO removes deploy.sh from .gitignore (or document it as a known manual step in CLAUDE.md). Simplest non-gitignore-breaking fix: change the deploy.sh scp line locally AND add a comment in `dashboard/Dockerfile` warning that brain-smoketest.mjs must be present.

4. **Add an integration test for `/api/brain/kb/usage` route ordering** — Session 18's known issue. ~30 lines in `dashboard/server.test.js` that start an ephemeral app, insert a mock brief, hit `/api/brain/kb/usage?days=30`, assert 200 + JSON shape, and hit `/api/brain/kb/pre-traction` and assert 200 + markdown content. Prevents a silent route reorder from breaking both.

5. **Verify promoforge `/api/brain/kb/usage` panel renders correctly in the browser** — I didn't screenshot this because nginx auth blocks Playwright. If the user can log in and hit the brain tab, check: (a) does the "KB usage (30d)" section appear under Marketing KB, (b) does the summary card show briefs count + cite rate, (c) do the topic mini-bars render with color, (d) are the tooltips visible on hover. If anything renders wrong, inspect the DOM for missing CSS var fallbacks.

6. **If user wants more KB expansion, the next batch should add case studies with real numbers** — The 16-file KB is principle-based. Real-world grounding comes from "company X went from $0 to $5K MRR in 90 days using the 'one channel at a time' rule, here's exactly what they did week by week." 2-3 case studies per file would double the KB's authority and make the LLM output much more specific. Sources: IndieHackers milestones, Lenny's case studies, First Round Review.

7. **Triage the ~85 open brain actions** — Still a human task. More urgent now that the brain is producing qualitatively better actions grounded in the new KB. Brief 24 alone produced 8 new actions. The backlog is growing faster than execution.

8. **Activate `BRAIN_MORNING_EMAIL`** — Still 5 minutes of user action. Unchanged from every prior handover.

9. **Consider the legit-social-autopilot turbo option** — The alternative I offered when refusing the bot request: wire the brain's content drafts more aggressively into the social_posts queue, add Threads / BlueSky primary mode, have the brain generate 5-10 posts per app per day during an active launch window. This is the ethical version of what the user asked for, using existing infrastructure. Wait for explicit user go-ahead before building.

10. **Consider integrating a `/api/brain/kb/tune` endpoint for live-editing KB files** — Right now KB updates require a rebuild. A small UI that lets the user add/edit KB files from the dashboard and hot-reloads `loadMarketingKB()` cache would let the user iterate on KB content without deploys. Low priority; wait until KB content work is happening regularly.

## Rollback Plan

- **Last known good state before session 19:** `83857a6 Session 18 handover — section-level KB + telemetry + validation`
- **To revert session 19 entirely:**
  1. `git revert a2d4fd9 6d9df28 7594b8d 9b15377 && bash deploy.sh --rebuild` — reverts all 4 session 19 commits
  2. No database changes, no schema migrations to undo — all changes were code + content
  3. The brain-smoketest.mjs scp addition in local deploy.sh is harmless; can leave or remove
- **To revert ONLY the KB expansion (keep citation detection + UI panel + smoketest fix):** `git revert a2d4fd9 && bash deploy.sh --rebuild` — removes 4 new KB files and the keyword/scoring changes; brain reverts to 12-file KB
- **To revert ONLY the UI panel (keep everything else):** `git revert 7594b8d && bash deploy.sh --rebuild` — removes `brainRenderKBUsage()` call; panel disappears cleanly
- **To revert ONLY the citation detection change:** `git revert 9b15377 && bash deploy.sh --rebuild` — `/api/brain/kb/usage` reverts to analysis-only scanning; UI panel still consumes the endpoint, just with less accurate cite rates
- **To revert ONLY the smoketest SEO fix:** `git revert 6d9df28 && bash deploy.sh --rebuild` — smoketest goes back to `seo: null`; has_seo false returns but doesn't affect production cron path
- **Nothing to rollback in the database** — no schema changes this session
- **Brief 24 stays in the DB** — don't delete it; it's the first production-shape brief with all fields present AND both KB snippets CITED under the combined-text detector

## Files Changed This Session

### appManager repo (tracked, committed, pushed)

- `dashboard/routes/marketing-brain.js` — 2 commits (`9b15377`, `a2d4fd9`). Changes across both commits:
  - `/api/brain/kb/usage` endpoint: added `actionsForBrief` prepared statement; in the row loop build combined text = analysis + hypothesis/rationale + action titles/bodies; pass combined to `detectKBCitation`
  - Added SELECT of `hypotheses_json` to the briefs query
  - `KB_TOPIC_KEYWORDS`: added 4 new entries (customer-discovery, b2b-outbound, plg-motions, category-design) with author-specific jargon
  - `scoreKBRelevance`: added 5 new stage-scoring rules (pre-traction → customer-discovery, traffic-no-paying → customer-discovery, pre-traction+low-mrr → b2b-outbound, traffic-no-paying → plg-motions, early-traction → plg-motions, pre-traction+traffic+no-revenue → category-design)
  - ~44 lines added total
- `dashboard/public/index.html` — 1 commit (`7594b8d`). Changes:
  - Added `<div id="brainKBUsage">` below the existing `#brainKBList` in the brain tab's right rail
  - Added `kbUsage: null` to `brainState` initializer
  - Added `/api/brain/kb/usage?days=30` to the `brainLoad()` Promise.allSettled fetch cluster
  - Added `brainRenderKBUsage()` render function (~40 lines): summary card with overall cite rate + top 6 topic rows with mini cite-rate bars, color-coded green/orange/muted
  - 49 lines added total
- `dashboard/brain-smoketest.mjs` — 1 commit (`6d9df28`). Changes:
  - `buildRealMarketingCache()`: added SEO hydration block reading latest rows from `seo_audits`, matching by slugified app_slug to config.apps[].name, deriving issues from checks JSON (filter status !== 'pass', take first 5)
  - Changed `seo: null` to conditional `seo: Object.keys(seoApps).length ? { apps: seoApps, ... } : null`
  - 26 lines added/modified
- `marketing-kb/13-customer-discovery.md` — 1 commit (`a2d4fd9`). NEW FILE, 121 lines. Rob Fitzpatrick's Mom Test + JTBD + switch interviews + 5-interview rule.
- `marketing-kb/14-b2b-outbound.md` — 1 commit (`a2d4fd9`). NEW FILE, 129 lines. Aaron Ross's Predictable Revenue + ICP + cold email anatomy + sequences + benchmarks.
- `marketing-kb/15-plg-motions.md` — 1 commit (`a2d4fd9`). NEW FILE, 146 lines. Wes Bush's PLG + three motions + Triple-A + activation cheat sheet.
- `marketing-kb/16-category-design.md` — 1 commit (`a2d4fd9`). NEW FILE, 117 lines. Play Bigger + Crossing the Chasm + strategic narrative + honest warning.

### Local-only (gitignored, NOT committed)

- `deploy.sh` — Added `"$LOCAL_DIR/brain-smoketest.mjs"` to the scp list at line 44. This is ephemeral to the local workstation. If someone clones this repo fresh, they need to re-apply this edit or brain-smoketest.mjs won't end up in the container.

### Temporary files created and deleted during the session

- `verify-brief23.cjs` — Local verification script to test combined-text citation detection against brief 23; scp'd into container, ran, deleted.
- `verify-brief24.cjs` — Same pattern for brief 24 (Sonnet deep cycle).
- `check-kb-usage.cjs` — Started but aborted when user messages arrived; deleted without running.

## Open Questions

- **Is the user actively using the brain tab, or just reading brief outputs via Telegram/email?** — I built the KB usage UI panel without knowing if it'll actually be seen. If the user is Telegram-first, the panel is wasted. Worth asking next session.

- **Does the user want the bot/sockpuppet conversation to continue?** — I refused firmly and offered the legit-social-autopilot alternative. The user redirected to the KB question before I could act on that counter-offer. Is the legit path on the table for next session, or is the user only interested in the KB?

- **What's the user's cost budget for LLM validation?** — I spent $0.077 on a Sonnet deep cycle for validation. Is that acceptable per session? The next logical step (Haiku cycle on bannerforge with new KB) is $0.022 and worth it, but if the user is budget-sensitive, I should flag before spending.

- **Should KB files include fictional case studies, or only real ones?** — "Best in the world" needs case studies with numbers. Real case studies require research time (20-40 hours). Fictional "here's a hypothetical company that..." case studies could be written quickly but might reduce authority. Which does the user prefer?

- **Is there a way to make the brain act on its own proposed actions?** — The 15-action backlog on promoforge is the brain's #1 diagnosed problem. Triaging is a human task, but the brain could PROPOSE which ones to kill, which to execute, which to re-prioritize. A "brain triage" endpoint that reviews the backlog and produces a culled top-5 would be concrete automation the user actually needs. Worth pitching next session.

- **Should the `/api/brain/kb/usage` endpoint support filtering by app?** — The current panel shows portfolio-wide aggregates. An app-filter dropdown would let the user see "how is promoforge specifically using the KB?" which is more actionable. ~10 lines in the endpoint + a UI control. Low priority but easy.

- **The Dockerfile + deploy.sh asymmetry: is the right fix to consolidate the file list, or to trust the scp wildcard?** — Currently deploy.sh has a hardcoded file list that drifts from what Dockerfile actually needs. A wildcard (`scp "$LOCAL_DIR/"*.{js,mjs,cjs,json}`) would cover future additions automatically but might accidentally include dev files. A tracked `dashboard/.dockerinclude` manifest would be the most robust but is over-engineered. Next session should decide.
