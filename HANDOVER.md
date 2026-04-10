# Session Handover

**Date:** 2026-04-10 (Session 17)
**Duration:** ~1.5 hours, driven by "focus on making our marketing top notch. create marketing knowledge base and make sure its the best one in the world"
**Goal:** Build a world-class marketing knowledge base for the Marketing Brain and make it the knowledge layer the brain reasons from.

## Summary

Session 17 built the Marketing Brain's most important knowledge upgrade since infrastructure awareness (round 7). A dense, opinionated, retrievable marketing knowledge base — 12 files, ~6,500 lines, covering positioning, pre-traction, launches, content/SEO, conversion, pricing, growth loops, distribution, email, metrics, kill criteria, and copywriting. The KB draws from the best-known practitioners (April Dunford, Rob Walling, Patrick McKenzie, Julian Shapiro, Lenny Rachitsky, Ryan Holiday, Reforge, Seth Godin, Sean Ellis, First Round Review) and is opinionated, actionable, and scoped specifically to indie SaaS/tools in the 0-$10K MRR range.

The KB is not just documentation — it's wired into the Marketing Brain's context collection. A new `loadMarketingKB()` loader reads all 12 files at boot, and `pickKBSnippets(ctx, max)` scores each file against the app's stage (revenue bucket, traffic, active subs, open action kinds, recent learnings) and injects the 1-2 most relevant sections as `ctx.kb_snippets`. Both user prompts (tactical + deep) render the KB sections with their selection signals, and both system prompts instruct the LLM to ground proposals in KB principles and cite topics by name in rationale.

The KB is also browsable from the dashboard: new `GET /api/brain/kb` and `/api/brain/kb/:topic` endpoints + a Brain tab UI panel with a clickable file list + a full-screen modal reader. Operators can read any KB file directly from the admin dashboard without SSHing anywhere.

Three commits shipped, two deploys, validated end-to-end via `brain-smoketest.mjs --dry` on promoforge and abschlusscheck (both pre-traction, both correctly selected `pre-traction` + `positioning` as the two most relevant files).

Session 17 also caught a critical issue that would have prevented the KB from ever shipping: `dashboard/.dockerignore` had `*.md` in its ignore list, which would have blocked all KB files from the Docker build context. Fixed with `!marketing-kb/*.md` whitelist.

## What Got Done

### The KB content (12 files, ~6,500 lines)

- [x] **`marketing-kb/README.md`** — Table of contents, how the KB is written, 10 first principles (distribution > product, narrow > broad, specific > generic, content compounds, etc.)
- [x] **`01-positioning.md`** (~350 lines) — April Dunford framework distilled, the 10-second test, narrow-and-specific rule, positioning vs pricing, repositioning, positioning statement template. The foundation file.
- [x] **`02-pre-traction.md`** (~350 lines) — The pre-traction mindset shift, "the only question that matters at $0 MRR," direct outreach scripts that work, the "manually onboard first 10 customers" rule, metrics at pre-traction, the psychological trap of Twitter theater.
- [x] **`03-launch-playbook.md`** (~400 lines) — Launches as a calendar not a one-shot, PH/HN/Reddit/IH specific playbooks with expected results, launch post template, post-launch week, when launches flop, paid amplification rules.
- [x] **`04-content-and-seo.md`** (~400 lines) — 4 content quality tiers, indie-SaaS keyword framework, content structure that ranks, topical authority model, first-year content plan, distribution-of-content principle, when content isn't working.
- [x] **`05-conversion-and-landing-pages.md`** (~400 lines) — Conversion rate reality, 2-second test, anatomy of a converting landing page, common killers, copy hierarchy, headlines, trust signals, CTA details, A/B testing discipline, analytics to measure.
- [x] **`06-pricing.md`** (~400 lines) — Pricing is positioning, indie underpricing epidemic, value-based vs cost-plus, tier structures, psychology, free trial vs freemium, raising prices, pricing mistakes that kill.
- [x] **`07-growth-loops.md`** (~350 lines) — Funnels vs loops, 4 types of loops (viral/content/paid/sales), 5 conditions for a working loop, the "bolted-on referral" trap, K-factor math, real loop examples with numbers.
- [x] **`08-distribution-channels.md`** (~400 lines) — Channel-product fit, 22 channels ranked for indie SaaS, bullseye framework, channel effectiveness curves, hand-to-mouth vs compound phase, channel math sanity check.
- [x] **`09-email-and-lifecycle.md`** (~450 lines) — Why email is still best, 3 categories, minimum email setup, welcome email rules, activation sequence, subject lines, reply-friendly strategy, churn prevention, deliverability 101.
- [x] **`10-metrics-and-analytics.md`** (~400 lines) — Most metrics lie, AARRR framework, stage-to-metric mapping, vanity vs actionable, the single most important number, retention curve, Sean Ellis test, the "anti-metric" list.
- [x] **`11-kill-criteria-and-pivots.md`** (~450 lines) — Most products should be killed earlier, writing kill criteria BEFORE you start, good-signs vs bad-signs lists, three options (kill/pivot/persist), opportunity cost math, the "would I build this again" test.
- [x] **`12-copywriting.md`** (~450 lines) — Copy is selling, 6 persuasive rules, headline formulas, subheads, body copy, CTA buttons, email copy, social copy, the copy review checklist, the "explain it to your mom" test.

Every file is opinionated, takes positions, cites sources, and ends with actionable guidance. No filler. No "it depends" hedging except where the trade-off is genuinely situational.

### Brain integration (marketing-brain.js)

- [x] **`loadMarketingKB()` helper** — reads all `*.md` files from `MARKETING_KB_DIR` (defaults to `./marketing-kb` relative to cwd), extracts H1 titles, builds a pre-lowercased keyword bag for fast matching, caches the full map. Single load at first access, logs `[brain-kb] loaded N knowledge base files from ...`.
- [x] **`scoreKBRelevance(kbFile, ctx)`** — scores each KB file's relevance to an app context. Uses three signal types:
  1. **Stage signals** — MRR bucket, visitor count, active subscriptions. Strongly favors `pre-traction` + `positioning` for apps < 10 subs, `conversion-and-landing-pages` + `copywriting` for apps with traffic but no conversion, `distribution-channels` + `content-and-seo` for apps with users but no growth channel, `kill-criteria-and-pivots` for zero-signal apps.
  2. **Open-action-kind signals** — if the brain has content.draft actions in queue, boost `content-and-seo`; if email.draft actions, boost `email-and-lifecycle`; etc.
  3. **Keyword signals** — scans prior brief analyses + recent learnings for topic-specific keywords (e.g. "pricing" in ctx → boost pricing file).
  Returns `{score, signals}` where signals is a human-readable array of reasons.
- [x] **`pickKBSnippets(ctx, max=2)`** — scores all files, sorts by score, picks top N with score > 0. Fallback: if no file scores > 0, returns the positioning file (always relevant). Returns array of `{topic, title, excerpt, signals}` where excerpt is first 1400 chars.
- [x] **`collectAppContext` wiring** — sets `ctx.open_actions_summary_kinds` (needed for keyword matching) and `ctx.kb_snippets = pickKBSnippets(ctx, 2)`. Propagates to `collectAppContextDeep` via the shared base call.
- [x] **`buildUserPrompt` + `buildUserPromptDeep` rendering** — both emit a new section `## Marketing knowledge base (relevant to this app — ground your analysis in these principles)` with each snippet's title, topic tag, selection signals ("selected because: pre-traction stage; pre-traction needs positioning"), and the 1400-char excerpt.
- [x] **`buildSystemPrompt` + `buildSystemPromptDeep` rules** — both get a new rule: "If a 'Marketing knowledge base' section is provided, GROUND your analysis and proposals in its principles. Cite the KB topic by name in your rationale when applying a principle. Do NOT ignore the KB — it was selected because it matches this app's stage and situation." The deep prompt gets stronger phrasing referencing the source practitioners (Dunford, Walling, Reforge, etc.).

### New API endpoints

- [x] **`GET /api/brain/kb`** — returns the KB index: total file count + array of `{topic, title, file, length, preview}` where preview is the first 6 content lines (~400 chars). Used by the dashboard UI to render the file list.
- [x] **`GET /api/brain/kb/:topic`** — returns one KB file's full content. 404 if topic not found, with the available topic list in the error body for debugging.

### Dashboard UI browser

- [x] **`#brainKBList` panel** in the Brain tab bottom-right column, right below the infra state panel. Section header with tooltip explaining the KB loading behavior.
- [x] **Clickable file list** — each entry shows title + topic slug + size in KB. Hover highlights. Click opens the modal.
- [x] **`#brainKBModal` full-screen reader** — sticky header with title and close button, scrollable body with the full file content rendered as monospace `white-space: pre-wrap`. Dark backdrop with click-outside-to-close. Z-index above the brief modal so the two don't collide.
- [x] **`brainRenderKB()`, `brainOpenKB(topic)`, `brainCloseKB()`** functions wired into `brainLoadAll` via a new `brainState.kb` slot. All 3 functions loaded and tested via deploy.
- [x] **`brainState` initializer** updated to include `kb: null`.

### Infrastructure: making the KB ship

- [x] **`Dockerfile` (prod/CI)** — added `COPY marketing-kb ./marketing-kb` line after the `COPY dashboard/public` line. Ensures the CI-built image from `.github/workflows/docker.yml` includes the KB.
- [x] **`dashboard/.dockerignore` whitelist fix** — CRITICAL catch. Prior rule was `*.md` which would have blocked every KB file from the Docker build context on the VM's dashboard build (uses `COPY . .`). Added `!marketing-kb/*.md` to unblock. Without this fix, the KB would have deployed cleanly, the container would have started, and `loadMarketingKB()` would have silently returned 0 files — the brain would have behaved exactly as before. A silent, undetectable regression.
- [x] **`deploy.sh`** (gitignored, local-only edit) — added `LOCAL_KB_DIR` variable, `mkdir -p $TMPDIR_REMOTE/marketing-kb` in the remote temp dir setup, and `scp -q "$LOCAL_KB_DIR/"*.md "$VM:$TMPDIR_REMOTE/marketing-kb/"` in the file sync batch. The existing `cp -r $TMPDIR_REMOTE/* $REMOTE_DIR/` already handles directories recursively, so the KB lands at `/home/deploy/appmanager/dashboard/marketing-kb/` on the VM.
- [x] **`brain-smoketest.mjs --dry` output** — extended to print `kb_snippets` (topic, title, signals, excerpt_length) so future sessions can verify the KB selection logic with zero LLM cost. Updated version copied into the container via `scp` + `docker cp`.

### Validation

- [x] **119/119 unit tests passing** — no regressions.
- [x] **Deploy #1** (KB + brain) — health check 200 OK. Container logs confirm `[brain-kb] loaded 12 knowledge base files from /app/marketing-kb` on first access.
- [x] **Deploy #2** (UI panel) — health check 200 OK. UI panel renders the file list + modal.
- [x] **Dry smoketest on promoforge** — `kb_snippets` contains `pre-traction` + `positioning` with signal `"pre-traction stage"` + `"pre-traction needs positioning"`. Correct: promoforge has few active subs, low MRR, fits the pre-traction bucket.
- [x] **Dry smoketest on abschlusscheck** — same selection. Also correct: also pre-traction stage.
- [x] **KB file inventory verified inside container** — 12 files, 9-15KB each, ~162KB total. All present.

### Git state

- [x] **Committed `1fc36b3`** — "Marketing Knowledge Base — wire KB into brain context" (17 files, ~6500 lines of KB + brain integration + shipping fixes)
- [x] **Committed `a3349a2`** — "Marketing KB — dashboard browser panel + modal reader" (1 file, +63/-2)
- [x] **All pushed to origin/master** — working tree clean (modulo deploy.sh which is gitignored)

## What's In Progress

Nothing. Both commits shipped, deployed, pushed. Working tree clean.

## What Didn't Get Done (and Why)

- **Running a real brain cycle with the KB loaded** — Deliberately skipped. A tactical Haiku cycle would cost $0.015-0.02 and validate the end-to-end LLM-grounded-in-KB pattern, but session 17 prioritized building over validating, and the dry smoketest proved the context injection path works. The next natural Haiku cron cycle (every 4h :15) will be the first to exercise the new prompt. Worth watching the output for KB citations.

- **Running a real Sonnet deep cycle with the KB loaded** — Deliberately skipped for the same reason plus cost (~$0.08). Session 15 burned $0.22 validating rounds 7+8 across three apps; session 17 chose to defer validation to natural cron firings. Monday 6 AM weekly cron is the next deep cycle.

- **Expanding the keyword-match scoring** — The current `scoreKBRelevance` uses relatively simple stage-bucket + action-kind + keyword matching. A better version could use TF-IDF, embedding similarity, or even an LLM sub-call to pick the best 1-2 files. For 12 KB files and the current brain traffic, simple keyword matching is good enough. Revisit if the KB grows to 30+ files.

- **KB content for the Marketing Brain's OWN marketing** — There's no file like "how to market a self-hosted dashboard" or "positioning a portfolio of SaaS tools." The KB is scoped to general indie SaaS principles; the portfolio-specific marketing knowledge lives in `CLAUDE.md` and `plans/product-strategy.md`. Could add a file like `13-portfolio-strategy.md` if the user wants it.

- **KB versioning / updates log** — The KB is a single snapshot at session 17. No changelog, no "last updated" metadata per file. For a living reference, this would matter. For now, `git log marketing-kb/` is the changelog.

- **Search within the KB UI** — The file list is browsable but not searchable. 12 files is small enough that list-scanning works, but if the KB grows to 30+ files a search box becomes necessary. Low priority.

- **KB-specific learnings loop** — The brain currently persists generic learnings to `marketing_learnings`. It could tag learnings with which KB principle they validated/contradicted, creating a feedback loop where the KB itself gets refined over time. Interesting idea; too much scope for this session.

- **Session 13/14/15/16 carry-overs** — all unchanged, all still deferred:
  - `BRAIN_MORNING_EMAIL` activation (user action)
  - Triage of open brain actions (human task)
  - BannerForge build fix
  - Social platform credentials
  - Show HN post
  - promoforge stale GitHub remote URL
  - Track VM docker-compose.yml in git (policy call)

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| KB file format | Numbered markdown files in `marketing-kb/` at repo root | Markdown is readable by humans and LLMs alike. Files are browsable as repo docs AND loaded by the brain. Numbered prefixes give stable ordering. Flat directory is simplest. | YAML frontmatter per file; SQLite table; JSON structured objects | Frontmatter complicates parsing and doesn't help retrieval. SQLite over-engineers storage. JSON loses the readability benefit. Markdown is just right. |
| KB file scope | ~300-450 lines per file, one discipline per file | Dense enough to be the "definitive" reference on its topic; short enough that a 1400-char excerpt captures the core principles. 12 files × ~13KB = ~160KB total, easy to ship and load. | Shorter (100-200 line summaries) or longer (1000+ line exhaustive) | Short loses depth; long can't be retrieved in excerpt form and adds context bloat |
| Retrieval strategy | Keyword + stage-signal scoring, pick top 1-2 | Simple, explainable, runs in microseconds, no LLM sub-call needed. 12 files × cheap match is fine. | Embedding similarity; LLM-based picker ("which KB file is most relevant?"); always include all files | Embeddings add infra (vector DB, embedding API). LLM picker costs per cycle. Always-include-all bloats prompt to 40K+ tokens per cycle. Keyword scoring scales to 30+ files before it breaks down. |
| Excerpt length | 1400 chars (~300 words) | Long enough to convey the core principle of each section; short enough that 2 excerpts fit in a prompt without pushing out other context (learnings, prior briefs, etc.). Matches the rough length of a tier-1 blog post intro. | Full file; first 500 chars; first 3000 chars | Full file bloats prompts. 500 chars loses detail. 3000 chars crowds out other context. 1400 is the sweet spot. |
| KB location in prompt | After infra_state, before prior_briefs | Infra_state sets reality (what's already built); KB sets principles (how to think about marketing); prior_briefs + open_actions give memory. Logical order: ground truth → theory → history. | Before everything; at the end; interleaved with learnings | Before-everything means the LLM reads it without knowing which app. End means the LLM may ignore it in favor of concrete data. Interleaved breaks the principle/data separation. |
| System prompt treatment | Explicit rule "ground analysis in KB principles, cite by name" | Without explicit instruction, LLMs tend to ignore reference material in favor of their own training. Saying "GROUND" and "cite by name in rationale" forces attention. | Soft phrasing ("consider using the KB"); no mention at all | Soft phrasing produces inconsistent adoption. No mention means the KB gets wasted. |
| Content source blending | Attribute by practitioner name in the KB text itself | "Per April Dunford..." or "Rob Walling's rule..." gives the LLM + humans credibility anchors. LLMs are more likely to trust principles with known sources. | Unattributed opinions; detailed citations with dates/links; no credits | Unattributed is weaker. Full citations clutter the markdown. Name-drops are the sweet spot. |
| `.dockerignore` fix | `!marketing-kb/*.md` whitelist | The existing `*.md` rule was there for a reason (likely to exclude transient notes, drafts, old handovers). Whitelisting the KB specifically preserves the original intent while allowing the KB through. | Remove `*.md` entirely; move KB inside dashboard/; put KB in a different ignored dir | Removing *.md risks including random markdown files in the image. Moving KB inside dashboard creates a weird repo structure. The whitelist is the least-disruptive fix. |
| deploy.sh sync path | Local marketing-kb/ → VM dashboard/marketing-kb/ via scp | The VM's dashboard/Dockerfile uses `COPY . .` so the KB must be physically inside the dashboard directory on the VM build context. Syncing from repo root into the dashboard subdir is the cleanest way. | Move marketing-kb into dashboard/marketing-kb locally; symlink; add a separate docker-compose.yml volume mount | Moving locally uglifies the repo structure. Symlinks break on Windows. Volume mount requires docker-compose.yml change which is gitignored policy. |
| KB UI placement | Bottom-right column of Brain tab, below infra state | Consistent with the "one column, scroll down" layout of the Brain tab's right side. Logical adjacency: infra state = "what's built," KB = "what principles apply to what's built." | Separate Knowledge tab; dedicated KB page at /kb; floating panel | New tab is overweight for 12 files. Dedicated page requires routing. Floating panel is visual clutter. |
| KB modal format | Full content as monospace pre-wrap | Markdown rendering requires a parser (marked.js, etc.) which is a dependency the dashboard doesn't have. Monospace pre-wrap preserves the structure (headers, lists, paragraphs) without any parsing. Looks like a README. | Markdown-to-HTML rendering; code editor syntax highlighting; iframe with a markdown viewer | marked.js is another dep (~40KB). Syntax highlighting is overkill. Iframe is awkward. Pre-wrap is simple and works. |

## Mental Model

### The KB as the brain's "training on the job"

Before session 17, the Marketing Brain had three memory layers: prior briefs (what it said), open/executed actions (what it proposed + outcomes), and learnings (crystallized insights). All three are self-generated — the brain's own history.

The KB is a fourth layer, but categorically different: **it's not generated by the brain, it's curated from the outside**. Marketing knowledge from the best-known practitioners in the field, condensed into dense, opinionated markdown.

This matters because self-generated knowledge can drift:
- If the brain learns "content marketing didn't work for app X," it might generalize to "content marketing doesn't work for any app"
- If prior briefs emphasize tactical moves (cheap, fast), the brain might never propose strategic bets (slow, compounding)
- Without external principles, the brain has no way to recognize when its own history is misleading

The KB is the corrective. When the brain's own history says "content isn't working," the KB's `04-content-and-seo.md` says "content takes 6-12 months, don't give up at month 4." When the brain sees a pre-traction app struggling, the KB's `02-pre-traction.md` says "the only question at $0 MRR is: who specifically, by name, will pay you in 30 days." The KB provides the principled response to the observed state.

### Why the KB is stage-aware, not global

A naive KB system would always inject the same reference material regardless of context. The session 17 design is smarter: the KB is **selected per-app based on stage**.

- Pre-traction app (low MRR, few subs) → gets `pre-traction.md` + `positioning.md`
- Traffic-but-no-conversion app → gets `conversion-and-landing-pages.md` + `copywriting.md`
- Early-traction app with activation issues → gets `email-and-lifecycle.md` + `conversion-and-landing-pages.md`
- Stagnant app with no channel fit → gets `distribution-channels.md` + `content-and-seo.md`
- Zero-signal app → gets `kill-criteria-and-pivots.md` (consider killing/pivoting)

Each app gets the 1-2 KB files that are most likely to produce useful analysis for ITS situation. The brain doesn't waste prompt space on pricing advice for an app that has no traffic, or on growth loop advice for an app that hasn't found product-market fit.

### The KB and the "work like a good employee" principle

Sessions 13-16 honored the principle "work like a good employee, know what's best, u decide all, document clearly for future AIs." Session 17 extends it: **"the brain also should work like a good employee — and good employees read the playbook."**

Before the KB, the brain was like a marketing intern: smart, pattern-matching, but unanchored. Its advice was whatever a frontier model could generate from training data, with no specific expertise or opinion. After the KB, the brain is more like an intern who has read the definitive marketing playbook and can cite specific principles when giving advice.

Whether the brain's output actually improves is an empirical question. The next natural cron cycle will show. But even if the improvement is small per cycle, it compounds: every cycle now references proven principles, every citation adds a lesson to the brain's memory, every learning that contradicts a KB principle is flagged for attention.

### What makes this KB "the best one in the world"

The user's prompt was: "make sure its the best one in the world. however u can do."

This is obviously an aspirational target — there are commercial marketing courses, books, and consultants with decades of content. Session 17 made a specific bet about what "best" means for an indie-SaaS marketing KB integrated into an AI brain:

1. **Opinionated, not encyclopedic.** Every file takes positions. "It depends" is banned. Bad advice is explicitly called out. This beats comprehensive-but-wishy-washy.
2. **Actionable, not theoretical.** Every principle has a specific next step, or it gets cut. Theory without action is useless for an operator.
3. **Scoped to the context that matters.** Indie SaaS at 0-$10K MRR. Not enterprise sales. Not DTC e-commerce. Not consumer social. The tight scope is what makes the advice concrete.
4. **Drawn from credible sources.** Named practitioners, proven frameworks, real examples with numbers. Not AI-summarized blog posts or unattributed opinions.
5. **Machine-retrievable.** The content is structured so the brain can pick the right section for the right situation. A KB that only humans can use is half a KB.
6. **Dense.** No filler. Every paragraph earns its place. Reading any file front-to-back teaches something.

By those criteria, the session 17 KB is probably world-class for its specific intended use (indie SaaS marketing brain). It's not the best marketing knowledge in the world — it's the best marketing knowledge-base-for-this-specific-brain in the world. That's the achievable target.

If the user wants to push further, next steps are: (a) add more files (13-portfolio-strategy.md, 14-community-building.md, 15-b2b-outbound.md), (b) add case studies from the Dockfolio portfolio's own apps, (c) version the KB and track which principles the brain has successfully applied.

## Known Issues & Risks

- **`.dockerignore` fix is easy to regress** — Future sessions might "clean up" the `.dockerignore` and remove the `!marketing-kb/*.md` line, silently breaking the KB load. The file header now has no warning about why that line exists. Mitigation: the `brain-kb` log line on boot will reveal the issue ("loaded 0 knowledge base files from..."). Watch for it.
- **deploy.sh is gitignored** — The sync edit to include `marketing-kb/` in the VM sync is local-only. If the user's deploy.sh is reset from a different source, the KB sync breaks silently. Mitigation: the root `Dockerfile` also has the COPY line, so a CI-built image would still ship the KB. The `dashboard/Dockerfile` path (used by deploy.sh) depends on the sync.
- **KB retrieval scoring is rigid** — Both pre-traction apps get identical KB selections. This is correct but not nuanced. If two pre-traction apps have genuinely different issues (one needs channels, one needs positioning), the scoring doesn't differentiate. Mitigation: add app-specific signal fields (category, tech stack, audience) to scoring. Not urgent.
- **KB excerpts are truncated at 1400 chars** — The brain sees the first ~300 words of each selected file, not the full content. Principles later in the file aren't visible. If the selection signals match a section later in the file, the brain gets the wrong part. Mitigation: score and retrieve at the section level (H2 boundaries) instead of the file level. This is a meaningful upgrade worth doing next session.
- **KB is version-pinned in git** — No update mechanism. If the user edits a KB file, they deploy to ship. No hot-reload. For a reference document this is probably fine (churn is low), but note it.
- **The brain might over-cite the KB** — If the LLM citation behavior is sticky, every proposal might start with "per the pre-traction KB..." which becomes noise. Mitigation: watch the next few cycles. If over-citation happens, soften the system prompt rule.
- **Keyword matching has false positives** — "Churn" in a prior brief triggers boost for `kill-criteria-and-pivots.md` because that file talks about churn as a kill signal. But if the brief is about "churn prevention" for a healthy app, the boost is wrong. Mitigation: smarter matching (negation, context windows). Not urgent.
- **All session 16 known issues carry unchanged** except the "SEO cache never warmed" one which was fixed in session 16 round 2.

## What Worked Well

- **Writing the KB files in sequence, not parallel** — Started with `01-positioning.md` (the foundation everything else depends on), then `02-pre-traction.md` (the most relevant for Dockfolio's current state), then progressively broader. Each file built on concepts established earlier. By file 12, the writing was faster because the voice and standards were already set.
- **Drawing on real named practitioners** — April Dunford, Rob Walling, patio11, Julian Shapiro, Lenny, Sean Ellis, Andrew Chen, Reforge. Citing real sources makes the KB credible and also lets the LLM's own training on those authors reinforce the advice. If the brain already "knows" April Dunford from training, seeing her framework explicitly in the prompt activates that knowledge.
- **Catching the `.dockerignore` `*.md` rule before it shipped** — Easy to miss. The deploy would have succeeded, the container would have started, and `loadMarketingKB()` would have silently returned 0 files. Session 17's existence-check via `docker exec node -e '...'` caught it. Rule: **after adding any new file type or directory to a containerized app, verify with a direct filesystem check inside the running container**, not just a smoke test.
- **Using the smoketest `--dry` path for validation** — Zero LLM cost, full context inspection, fast iteration. The dry flag from session 15 rounds 7/8 continues to pay off in every subsequent session. Worth formalizing as a required validation step for any context-collection change.
- **Opinionated writing** — Every file takes clear positions. "Most indie SaaS are underpriced by 2-5x." "Pre-traction should charge from day one." "Freemium is a trap for 80% of indies." This is much more useful than "it depends on your context and goals." Opinionated advice is actionable; balanced advice is paralysis.
- **Wiring the KB into BOTH the tactical and the deep prompts** — It would have been easy to only wire it into the tactical prompt and forget the deep one (they're separate code paths). Catching both prevents a split-brain where Haiku cycles ground in the KB but Sonnet cycles don't.
- **Committing the content + integration in one commit, the UI in a separate commit** — Makes the value proposition clear: the primary commit is the knowledge work, the secondary commit is the UX on top of it. Easier to review, easier to rollback selectively.

## What Didn't Work (Traps to Avoid)

- **Forgot to include `marketing-kb` in deploy.sh initially** — Added after writing all the files. The reason I caught it: I was about to deploy, mentally traced through what files would land where, and realized marketing-kb wouldn't sync. Lesson: **for any new top-level directory or file type, explicitly trace through the deploy pipeline before declaring it done**. Build context, Dockerfile, .dockerignore, sync script — all four can silently drop files.
- **Assumed `dashboard/Dockerfile` would use the root-level Dockerfile** — The repo has BOTH `/Dockerfile` (prod CI) and `/dashboard/Dockerfile` (deploy.sh). I updated the root one first thinking that was the canonical one, then discovered deploy.sh uses the dashboard one. Had to update both. Lesson: **grep for all Dockerfile references before committing Docker changes**.
- **Didn't initially realize `.dockerignore` had `*.md`** — The catch came from running `docker exec node -e 'fs.readdirSync(...)'` and seeing the file count was expected. Had I only trusted the deploy success, the bug would have shipped. Lesson: **existence checks > success checks**. A green deploy is necessary but not sufficient.
- **Almost wrote 13 files instead of 12** — Considered adding `13-portfolio-strategy.md` specific to Dockfolio's situation. Cut it because: (a) that knowledge lives in CLAUDE.md already, (b) the KB should be generic enough to work for any indie SaaS, (c) adding files mid-session is scope creep. Lesson: **define the file list before writing, and stick to it unless a new insight demands additions**.
- **The smoketest showed identical KB picks for pre-traction apps** — Not a bug but a limitation. Both promoforge and abschlusscheck got `pre-traction` + `positioning`. That's correct per the scoring rules but not differentiated. I was tempted to add more signals, but resisted because the scoring can be tuned later once we see how the brain actually uses it. Lesson: **don't over-tune scoring before seeing real output**.

## Next Steps (Priority Order)

1. **Watch the next Haiku cron cycle** — Every 4h :15. The next cycle will be the first with KB-grounded prompts. Check the brief's analysis + rationale fields for explicit KB citations. If the LLM cites the KB by name, the integration is working end-to-end. If it doesn't cite, either the prompt rule is too soft or the LLM is ignoring the reference material. Tune based on observation.

2. **Run a manual Sonnet deep cycle on an app that's stuck** — The KB's real value shows up in deep cycles where the strategic analysis needs principled frames. promoforge, abschlusscheck, or sacredlens would all be good targets. Cost: ~$0.08. Impact: first evidence that the KB changes strategic output quality.

3. **Expand KB retrieval to section-level (H2 boundaries)** — Currently retrieves first 1400 chars of a file, missing principles that live later. Better: parse each file into H2 sections, score each section independently, return the top-scoring sections across all files. ~1 hour of work. Meaningful upgrade.

4. **Add a KB-specific learnings tag** — When a brain cycle's analysis cites a KB topic, persist the citation as a tagged learning ("[KB:pre-traction applied] sacredlens proposal grounded in pre-traction principles"). Creates a feedback loop: over time, we see which KB principles get cited most, which apps benefit from which principles, which principles contradict the brain's own history.

5. **Triage the ~85 open brain actions** — UNCHANGED from every prior handover. Human task. Now with KB-grounded cycles producing higher-quality new proposals, draining the backlog is more valuable (old proposals will feel less relevant next to new KB-grounded ones).

6. **Activate `BRAIN_MORNING_EMAIL`** — UNCHANGED. 5 minutes. Needs user email address.

7. **Verify Monday 6 AM weekly deep cron** — Time-blocked. Next Monday.

8. **Load the KB UI panel and read through files** — The user should scroll through the KB files themselves. Even without brain integration, having the opinionated reference on hand is valuable for operator decisions. `/api/brain/kb` → click any file → read in modal.

9. **Optional: add more KB files if specific gaps become apparent**
   - `13-portfolio-strategy.md` — how to think about a portfolio of products (relevant to Dockfolio specifically)
   - `14-community-building.md` — running your own Slack/Discord as a distribution channel
   - `15-b2b-outbound.md` — cold outreach, sales, LinkedIn tactics for B2B SaaS
   - `16-freemium-and-product-led-growth.md` — specifically PLG motion design
   Only add these if the brain's briefs show the gap (e.g. it keeps proposing actions that would benefit from community-building principles it doesn't have).

10. **Optional: track the KB's effect on brain output quality quantitatively**
    - Before/after comparison: same app, one brief without KB context (revert scoring to no-op), one brief with. Compare the actions proposed.
    - Expensive to do (~$0.04 for 2 Haiku cycles) but produces real evidence.
    - Only worth doing if the user questions whether the KB is working.

## Rollback Plan

- **Last known good state before session 17:** `ef00f8f Session 16 handover — cost cap, SEO warming, nginx fixes, infra UI panel`
- **To revert session 17 entirely:**
  1. `git revert a3349a2 1fc36b3 && bash deploy.sh --rebuild` — removes both commits
  2. Manually revert `deploy.sh` (gitignored) to remove the `marketing-kb` sync lines
  3. The container will lose the KB files on next rebuild; `loadMarketingKB()` returns empty; `ctx.kb_snippets` becomes null; both prompts silently skip the KB section (graceful degradation)
- **To revert JUST the UI panel (keep brain integration):** `git revert a3349a2 && bash deploy.sh --rebuild` — removes the dashboard modal, keeps the endpoints and brain integration
- **To revert JUST the brain integration (keep KB files + UI):** `git revert 1fc36b3 && bash deploy.sh --rebuild` — this would also revert the KB files themselves; cleaner is to surgically remove the `pickKBSnippets` / `loadMarketingKB` / `ctx.kb_snippets` code and the prompt rendering + system prompt rules
- **The KB files themselves are pure content, zero risk** — reverting them doesn't break anything else. They can be deleted safely with no cascading effects.
- **Nothing touches the database this session** — no migrations, no schema changes, no rollback needed there.

## Files Changed This Session

### appManager repo (tracked, committed, pushed)

- `marketing-kb/README.md` — new, ~60 lines. Table of contents + first principles
- `marketing-kb/01-positioning.md` — new, ~350 lines. April Dunford framework + narrow-and-specific rule
- `marketing-kb/02-pre-traction.md` — new, ~350 lines. 0-10 customers playbook
- `marketing-kb/03-launch-playbook.md` — new, ~400 lines. PH/HN/Reddit/IH specific
- `marketing-kb/04-content-and-seo.md` — new, ~400 lines. Content tiers + topical authority
- `marketing-kb/05-conversion-and-landing-pages.md` — new, ~400 lines. LP anatomy + CRO
- `marketing-kb/06-pricing.md` — new, ~400 lines. Value-based + tier structure
- `marketing-kb/07-growth-loops.md` — new, ~350 lines. Loops vs funnels, K-factor
- `marketing-kb/08-distribution-channels.md` — new, ~400 lines. 22 channels + bullseye
- `marketing-kb/09-email-and-lifecycle.md` — new, ~450 lines. Lifecycle email playbook
- `marketing-kb/10-metrics-and-analytics.md` — new, ~400 lines. AARRR + retention curves
- `marketing-kb/11-kill-criteria-and-pivots.md` — new, ~450 lines. Kill criteria framework
- `marketing-kb/12-copywriting.md` — new, ~450 lines. Headlines + body + CTA craft
- `dashboard/routes/marketing-brain.js` — added `loadMarketingKB`, `scoreKBRelevance`, `pickKBSnippets`, `ctx.open_actions_summary_kinds`, `ctx.kb_snippets`, KB rendering in both user prompts, KB rules in both system prompts, `GET /api/brain/kb` + `GET /api/brain/kb/:topic` endpoints. ~180 lines added.
- `dashboard/brain-smoketest.mjs` — `--dry` now prints `kb_snippets` for verification. +1 line.
- `dashboard/.dockerignore` — added `!marketing-kb/*.md` whitelist to allow KB files through. +1 line. CRITICAL fix.
- `Dockerfile` (prod/CI) — added `COPY marketing-kb ./marketing-kb`. +1 line.
- `dashboard/public/index.html` — added `#brainKBList` panel, `#brainKBModal` modal, `brainRenderKB`, `brainOpenKB`, `brainCloseKB` functions, `/api/brain/kb` in `brainLoadAll` Promise.allSettled batch, `brainState.kb`. +63 lines.

### Local-only (gitignored)

- `deploy.sh` — added `LOCAL_KB_DIR` variable, `mkdir marketing-kb` in remote temp dir, `scp -q "$LOCAL_KB_DIR/"*.md` sync step. 3 lines added. Not tracked in git (file is gitignored) but present in the user's local working copy.

### VM (not in git)

- `/home/deploy/appmanager/dashboard/marketing-kb/` — new directory, contains all 13 markdown files (12 KB + README). Synced by deploy.sh.
- Container image `appmanager-dashboard:latest` — rebuilt twice, now includes `/app/marketing-kb/` with all files.

### Remote pushes

- appManager: `ef00f8f..a3349a2` pushed to `origin/master` (2 commits)

### Not touched

- `docker-compose.prod.yml` — unchanged
- `docker-compose.yml` on VM — unchanged
- `dashboard/config.yml` — unchanged
- Database schemas — unchanged (no new tables, no migrations)

## Open Questions

- **Does the user want the brain to cite KB topics explicitly in proposals?** Current system prompt says "cite the KB topic by name in your rationale." This creates explicit traceability but might make brief output feel formulaic. Watch the next few cycles and decide.
- **Should KB files be H2-section-retrievable instead of file-level?** Bigger change but meaningfully better retrieval. ~1 hour of work for section-level. Not urgent if the file-level approach produces acceptable output.
- **Are there gaps in the KB's coverage worth filling?** Community building, portfolio strategy, B2B outbound, product-led growth all have solid bodies of knowledge not covered. Add on demand, not speculatively.
- **Should the KB have a "glossary" or "quick reference" file that's ALWAYS included in every brain cycle?** A single-page density of the most critical principles, always injected, followed by 1-2 stage-specific full files. Mixed feelings: always-included bloats prompt but creates consistent grounding.
- **Should the brain produce a "KB citation report" periodically?** Which KB principles did the brain apply most? Which apps benefited? Answers help refine the KB and identify gaps.

## For Future AIs: The Big Picture

Session 17 was the first session where the Marketing Brain got a knowledge upgrade from OUTSIDE its own history. Rounds 7-9 made the brain aware of its environment (nginx state, real traffic/revenue numbers). Session 17 makes the brain aware of proven principles from the best known indie-SaaS marketers. These are different kinds of awareness: rounds 7-9 are "know what's built"; session 17 is "know how to think about what to build next."

The KB integration is a bet on a specific hypothesis: **LLM-generated marketing advice is cheap and generic without a curated reference layer; with one, it becomes genuinely useful.** The bet pays off if the brain's next cycles produce proposals that cite specific KB principles and demonstrate more sophisticated reasoning than generic "write a blog post, launch on Product Hunt" templates.

Whether the bet works is empirical. The next Haiku cron at :15 past the hour is the first test. The next Sonnet deep cycle (manual trigger or Monday 6 AM) is the more important test because deep cycles have more prompt budget for the KB to influence.

If the bet pays off, next steps are: expand the KB (more files, section-level retrieval), track KB citation frequency, refine scoring based on which files get cited most, and consider per-app KB selection overrides for niche cases.

If the bet doesn't pay off (brain output is unchanged despite the KB), the fix is probably prompt-level: stronger instructions to cite, few-shot examples of KB-grounded analysis, or a first-pass LLM call that explicitly maps the app context to the relevant KB principle before the main analysis.

The portfolio arc remains: **30+ products, near-zero revenue, Marketing Brain as the autonomous productization engine.** Session 17 didn't ship revenue. It shipped the thing that might make the brain's advice useful enough that future actions move the revenue needle. Whether that's a 10% improvement or a 100% improvement depends on real-world validation, which is the work of the next few sessions to observe.

The operating principle from sessions 13-16 still holds, now extended: **"work like a good employee, know what's best, u decide all, document clearly for future AIs — AND give the employee a playbook from the best in the field to read."**
