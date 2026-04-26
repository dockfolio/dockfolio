# Session Handover

**Date:** 2026-04-26 (Session 22)
**Duration:** ~1 hour, single multi-step task split across two repos
**Goal:** Started by `/read-handover`-ing session 21's queue (Public Brain Play 1 was the keystone next step), but the user immediately pivoted to a fresh portfolio task. Session 22 ended up being a cross-repo content update with zero work in this repo (`appManager`).

## Summary

Session 22 was almost entirely about marketing surface area, not the dashboard backend. The user opened with two adjacent asks: (1) "we have a new website on the VM, theforgottensystem, add it to crelvo.dev" plus the meta-question "or should I do it via the slebständig repo so git is ok?" and (2) "add my two TTS-phase games (SidewalkSimulator and tabletop-siege, uploaded on itch.io) as games made by Crelvo on the website in testphase." Both asks were one repo away from this one — the crelvo.dev source lives at `Projekte/slebständig`, not in `appManager`.

The first half landed cleanly. I added three entries to `slebständig/src/components/Projects.astro` (a flat array of project cards), built with `npm run build`, deployed via `scp ./dist/* deploy@.../var/www/crelvo/`, and pushed `0d7fc0c` to `konradreyhe/crelvo`. Verified the EN and DE pages both serve the new entries (count went 20 → 23 cards, all three names + URLs + badges render correctly), and a Playwright JPEG confirmed the visual layout. One real finding surfaced during verification: **both itch.io URLs return HTTP 403 even with a real Chrome user-agent, in both -L follow-redirect mode and HEAD requests.** This is not a curl artifact. Both games are still set to Draft (or Restricted) on itch.io, so the new links from crelvo.dev hit a "this game is not public" wall. Surfaced as a user action item — no code fix possible.

The second half was the antenna footer cross-link task. I located `Projekte/antenna/site/index.html` (the source for `theforgottensystem.org`), found the `<footer>` at line 1718, and audited for placement. The user wanted three outbound links: oldworldlogos.com, the OWL Telegram channel, and crelvo.dev. I had the first and third confidently; the Telegram URL was nowhere — not in `Projekte/LOGOS`, not in `Projekte/Logosnews`, not on the live oldworldlogos.com page. Per the no-guessing-URLs rule I asked the user, who replied `https://t.me/oldworldlogos`. I then added a new `.related-links` row in the footer (between the existing big-links nav and the build-info line) with a small "RELATED WORK" label and the three external links carrying `target="_blank" rel="noopener"`. Deployed surgically via single-file `scp` (the documented tar-pipe deploy is for full-site rebuilds; for one-file changes scp is faster and atomic). Committed `b257ee7` to `konradreyhe/antenna` `main`, pushed, and Playwright-screenshotted the footer to confirm visual rendering. All three links live, all attributes correct.

Net session impact: 2 commits across 2 OTHER repos, zero in this `appManager` repo. Session 21's priority queue (Public Brain Play 1, etc.) is **completely untouched** and remains the next-session backlog. The Marketing Brain has continued running its 4-hour cron cycles in the background autonomously this session — I did not query the post-cron briefs to validate file 17 grounding (session 21 priority #2). That hourly check is still pending.

## What Got Done

- [x] **Added 3 entries to crelvo.dev /projects** (`slebständig` `0d7fc0c` on `konradreyhe/crelvo` `master`)
  - The Forgotten System → `https://theforgottensystem.org` (badge: "Visual Essay")
  - Commuter Chaos → `https://crelvo.itch.io/commuter-chaos` (badge: "Game · Testphase")
  - Tabletop Siege → `https://crelvo.itch.io/tabletopsiege` (badge: "Game · Testphase")
  - All three follow the existing `Projects.astro` schema (name, url, description, tags, gradient, border, languages). Descriptions written without hyphens per the global no-dashes rule for player-facing text.
  - Built (`npm run build`, 6.4s, 24 pages) and deployed via `scp ./dist/* deploy@.../var/www/crelvo/`. Card count went 20 → 23. Both EN and DE pages render the new entries (verified via curl HTML extraction + Playwright DOM query).

- [x] **Cross-link footer added to theforgottensystem.org** (`antenna` `b257ee7` on `konradreyhe/antenna` `main`)
  - New `<div class="related-links">` row in `<footer>` between big-links nav and build-info line.
  - Three outbound links: `oldworldlogos.com`, `t.me/oldworldlogos`, `crelvo.dev`.
  - All carry `target="_blank" rel="noopener"`.
  - New CSS class `.related-links` added (smaller font than `.big-links`, with a small uppercase "RELATED WORK" label) so the internal nav stays visually primary.
  - Deployed via single-file `scp site/index.html deploy@.../home/deploy/theforgottensystem.org/index.html`. No nginx reload needed (content-only change).
  - Verified live via curl + Playwright screenshot.

- [x] **Identified itch.io 403 blocker** — Both Commuter Chaos and Tabletop Siege return HTTP 403 to public visitors. Re-tested with Chrome user-agent and follow-redirect to rule out curl artifacts. Confirmed real visibility lock on itch.io. Surfaced as a user action item — see Outstanding User Actions below.

- [x] **Cleaned up 2 verification screenshots** from `appManager/` root per the global session-hygiene rule.

## What's In Progress

Nothing. Working tree clean across all three repos touched. All commits pushed to their remotes.

## What Didn't Get Done (and Why)

- **Session 21's entire priority queue** — Not touched this session because the user pivoted to portfolio work the moment I finished `/read-handover`. The full session-21 queue still applies:
  1. Build Public Brain Play 1: `brain.dockfolio.dev` live feed (the keystone, ~60-90 min)
  2. Watch next 2-3 cron cycles for file-17 grounding in production briefs
  3. Run one Haiku smoketest on a portfolio-biased app
  4. (User action) Register social platform credentials
  5. Add `/api/brain/kb/usage` route ordering test
  6. Update Orb source repo with python3 healthcheck
  7. Triage ~95+ open brain actions

- **Cosmetic sweep of existing crelvo.dev project descriptions for the no-dashes rule** — Flagged to the user as out of scope. The 20 pre-existing entries in `Projects.astro` use phrases like "AI-powered", "browser-based", "cross-promo" with hyphens. My 3 new entries comply with the no-dashes rule, but the existing entries don't. A fast `rg` + edit pass would clean it up if the user confirms.

- **Push of session 21's 6 local-only commits to origin** — Session 21 left 5 commits unpushed to `appManager`'s origin. After session 21's handover commit (`dfbb73f`) the count is now 6 commits ahead of `origin/master`. **Session 22 also did not push these.** They sit on local `master`, ready when appropriate.

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Where to make the crelvo.dev edit (source repo vs VM) | `Projekte/slebständig` (the Astro source) | The VM has built `dist/` output at `/var/www/crelvo/` but `./deploy.sh` overwrites it from source on every deploy. Editing on VM = changes vanish next deploy. | Edit `/var/www/crelvo/index.html` on the VM directly | Self-erasing within one deploy cycle. The user explicitly asked the meta-question and the answer is unambiguous. |
| How to add the three crelvo.dev entries | Append to the `projects` array at the end of `Projects.astro` | Existing pattern. Order roughly approximates "newest last." Avoids reordering 20 existing entries (touches more of the diff for no benefit). | Insert after Dockfolio (flagship); insert as a new "Games & Research" sub-section above the grid | Inserting near top would push down 20 entries' position; sub-sections require new component logic and break the uniform card grid. |
| Game metadata representation | Single "Game · Testphase" badge in the `languages` field plus "Currently in open playtest on itch.io" in the description | Compact, signals testphase to visitors at a glance, doesn't require new fields or template changes. | New `status: 'testphase'` field with a colored ribbon overlay; separate "Games" grid section | Premature schema change for two entries; ribbon overlay would clash with the existing hover-gradient effect. |
| How to deploy the antenna single-file change | `scp site/index.html deploy@.../home/deploy/theforgottensystem.org/` | Surgical, atomic, ~1 second. The DEPLOY.md tar pipe is for full-site refreshes (30 MB across 164 files). | Run the full DEPLOY.md tar-pipe; rebuild a CI workflow | Tar pipe is overkill for a one-file content change; CI is YAGNI for a static site with infrequent updates. |
| Telegram URL handling | Asked the user, did NOT guess | The system prompt forbids generating URLs. Searched `Projekte/LOGOS`, `Projekte/Logosnews`, live oldworldlogos.com HTML — zero hits on `t.me/`. | Guess `t.me/oldworldlogos` as the obvious handle | Even if the obvious guess would have been right (it was), guessing violates the explicit rule and risks a dead link in production. |
| Footer styling for new links | New `.related-links` class with smaller font + uppercase label, sibling to existing `.big-links` | Keeps the internal nav (Browse the corpus, etc.) visually primary; outbound links sit clearly in their own row labeled "Related work" so visitors understand the context shift. | Add to existing `.big-links` row inline; create a separate "Friends" section higher in the page; modal | Inline mixing of internal + external links is confusing UX; separate higher section is heavyweight; modal is overkill for three links. |
| Where this HANDOVER.md lives | `appManager/HANDOVER.md` (this repo) | Continuity with session 21 (and 20, 19, etc.) — they all live here. The next `/read-handover` session opens in `appManager` by default. | Write three handovers, one per repo touched | Triplication; the next session won't read three handovers; and slebständig/antenna had only one focused commit each, fully described by the commit message. |

## Mental Model

### The 3-repo portfolio system

This was the conceptual unlock for session 22. The user runs three visible web properties out of three separate local repos, all deploying to the same VM at `91.99.104.132`:

| Repo (local) | Domain | What it is | Deploy method |
|---|---|---|---|
| `Projekte/appManager` | `admin.crelvo.dev` | Dockfolio dashboard (Node + SQLite + Docker, this repo) | `bash deploy.sh --rebuild` (rsync + docker compose) |
| `Projekte/slebständig` | `crelvo.dev` | Crelvo agency / portfolio site (Astro static) | `npm run build && scp dist/* deploy@.../var/www/crelvo/` |
| `Projekte/antenna` | `theforgottensystem.org` | Victorian rooftop research microsite (vanilla HTML + vendored Three.js, no build step) | `tar | ssh tar` (full) or `scp site/<file>` (surgical) |

Plus the games at `Projekte/SidewalkSimulator` (Commuter Chaos) and `Projekte/tabletop-siege` (Tabletop Siege), which deploy to itch.io via `butler push`, not to the VM.

**Critical implication:** when the user says "add X to the crelvo.dev website," they mean the Astro source in `slebständig`. NOT the VM webroot, NOT this `appManager` repo. The Astro source is the canonical truth; the VM is built output that gets overwritten on every deploy. This is the pattern for ALL three repos: edit the source, run the deploy, never touch the VM directly. The exception is "VM-only" infra (nginx configs at `/home/deploy/nginx-configs/sites/`, healthchecks in compose files for containers without local source) — those have to be edited on the VM because they have no source repo here.

### Adding a project card to crelvo.dev is a one-line schema mental model

The whole crelvo.dev portfolio grid is driven by a single flat array in `Projects.astro` (lines 7-188 pre-edit, 7-225 post-edit). Each entry is `{ name, url, description, tags[], gradient, border, languages }`. The `gradient` and `border` are Tailwind utility classes (`from-X-500/20 to-Y-600/20` and `hover:border-X-500/50` respectively). `languages` is a freeform short-string badge that shows above the description (used as a category label, not an actual language list). To add a project: append to the array, pick gradient + border colors that don't clash with adjacent entries, write a description without hyphens (no-dashes rule for player-facing copy), and ship. Total mental cost: ~2 minutes per entry. No DB, no API, no template change.

### The antenna site is intentionally build-step-free

`Projekte/antenna/site/index.html` is 1754 lines of hand-written HTML + inline CSS + vendored Three.js modules. The DEPLOY.md note "Runs from `file://`, no build step" is load-bearing — it means you can open `site/index.html` in a browser locally with no server and it works exactly like the deployed version. This implies: never introduce a build step, never reference a CDN (the CSP is tight per DEPLOY.md), and edit `site/index.html` directly rather than through any framework abstraction. The vendored Three.js lives at `site/explainer/vendor/`. Any new content goes in the same file inline.

### The "verify 100%" pattern: curl for HTML truth, DOM query for attribute truth, screenshot for visual truth

The verification round used three layers:
1. **curl** confirmed the deployed HTML contains the expected strings + element counts.
2. **Playwright DOM query** confirmed the `<a>` elements have correct `href`, `target`, `rel` attributes and the parent grid contains exactly 23 cards.
3. **Playwright JPEG screenshot** confirmed the visual rendering matches the design intent (gradient, badge position, card spacing, no overflow).

Each layer catches different bugs. curl alone wouldn't catch a layout regression; screenshot alone wouldn't catch a wrong `href`; DOM query alone wouldn't catch CSS pixel-pushing issues. Use all three when you need 100% confidence on a UI change.

### Why itch.io 403s are not negotiable

itch.io's project visibility flag has three states: Public, Restricted (link-only), and Draft (owner-only). When a project is Draft or Restricted, every public URL returns 403 regardless of user-agent, regardless of follow-redirect — the page genuinely doesn't exist for non-owners. This means the link from crelvo.dev/projects to `crelvo.itch.io/commuter-chaos` is technically valid but functionally broken: visitors will see itch's "this game is not public" page, which damages the perception that Crelvo's portfolio is real. **The fix is exclusively on the user side** (toggle visibility on itch.io) and has no code component. Worth re-checking on the next session — if visibility hasn't been toggled, consider whether to remove the entries temporarily or add a "soft launch" disclaimer.

## Known Issues & Risks

- **itch.io 403 Forbidden on both game URLs.** Impact: visitors clicking Commuter Chaos or Tabletop Siege from crelvo.dev/projects hit itch's "not public" page. Workaround: none, code-side. **Fix: user toggles both projects to Public (or at minimum Restricted with link-sharing) on itch.io.** Until then, the entries on crelvo.dev are aspirational pointers, not working links. If this isn't fixed within a few days, consider either removing the entries or adding a "Coming soon to itch.io" wording change to the descriptions.

- **Pre-existing crelvo.dev project descriptions violate the no-dashes rule.** Impact: the AI-tell hyphens ("AI-powered", "browser-based", etc.) sit on a public-facing page that contradicts the user's own writing-style policy. Risk: low (visitors won't notice this consciously, but the global CLAUDE.md is explicit). Mitigation: a 5-minute `rg "[a-z]-[a-z]"` sweep + manual hyphenless rewrites of ~20 descriptions. Out of scope for session 22.

- **6 local-only commits in `appManager`** (sessions 21 + this handover commit). Impact: a context crash or machine reboot loses session-21's work. Mitigation: `git push` when appropriate. The user has not asked to push and prior sessions kept them local per "standard practice" but the global "do all" contract step 3 says push immediately. Worth resolving on the next session.

- **slebständig has 3 untracked files** (`.mcp.json`, `KNOWLEDGEBASE.md`, `PLAYWRIGHT-MCP-GUIDE.md`) that pre-existed this session. Likely should be either committed or `.gitignore`d. Not from session-22 work, so left untouched.

- **Session 21 carryover unchanged.** The orb-dashboard fix is still VM-only (Orb source repo not found in `Projekte/`); social autopilot still credential-gated; the 3 underperforming session-19 KB files (b2b-outbound, plg-motions, category-design) still need post-cron-cycle measurement; ~95 brain actions still in the queue. None of these were touched this session.

- **Marketing Brain ran several cron cycles autonomously during this session and was NOT measured.** Session 21 priority #2 (file 17 grounding query) is unverified. Could be running fine, could be silently degrading. Run the SQL query from session 21's HANDOVER.md priority #2 next session.

## What Worked Well

- **Asking for the Telegram URL instead of guessing.** Even though `t.me/oldworldlogos` is the obvious guess and turned out to be correct, asking enforced the no-guessing-URLs rule and took ~30 seconds. The cost of guessing wrong (a dead link in a deployed footer) far exceeds the cost of asking.

- **Three-layer verification (curl + DOM query + screenshot).** Each layer caught a different class of potential bug. The screenshot revealed that Tabletop Siege sits alone on the bottom row (23 cards = 11 pairs + 1 lone) — looks fine but worth knowing for future ordering decisions.

- **Surgical scp for single-file deploys.** Both deploys this session were content-only single-file changes. `scp` was ~1 second each vs the documented tar-pipe (~30 MB transfer). For full-site changes, the tar pipe is still the right choice.

- **Per-repo commit boundaries.** Each repo got exactly one focused commit with a descriptive message. No mixing concerns across repos. Granular rollback is trivial.

- **Surfacing the itch.io 403 finding clearly.** Could have been buried in a "verified, all good" report. Calling it out as a real blocker (with re-test using browser UA to rule out curl artifacts) made the user-side action obvious.

## What Didn't Work (Traps to Avoid)

- **The first `/handover` flow lost the in-flight verification context.** When the user said "verify u did all" mid-stream, then interrupted with the antenna task before I finished the verify, then said "verify u did all" again, I had to disambiguate which verify scope they meant. Lesson: when a verify task gets interrupted, drop a one-line "paused mid-verify, current state is X" before pivoting, so the next "verify" command is unambiguous.

- **Initially missed that crelvo.dev's no-dashes-rule violation predates this session.** I followed the rule for my new entries but didn't note it as a known issue until the user could have read it as inconsistency on my part. Lesson: when a project policy is partially violated by pre-existing code, flag it in the first response, not the second.

- **The nginx -s reload "invalid PID number" warning during the crelvo.dev deploy looks scary.** It's harmless — this VM uses a custom nginx config at `/home/deploy/nginx-configs/nginx.conf` so the default reload command (`sudo nginx -s reload`) can't find the PID file. The actual reload would need `-c /home/deploy/nginx-configs/nginx.conf`. But for static-file changes (no nginx config change), reload is unnecessary anyway — the static files serve the next request directly. The deploy.sh in slebständig does try a reload it doesn't actually need, fails harmlessly, and the deploy still works. Worth noting: future sessions may want to fix slebständig/deploy.sh to either use the right `-c` path or skip the reload entirely for static changes.

- **Don't assume Glob with absolute Windows paths returns reliably.** Grepping `Projekte/**/*.{md,astro,html,ts,js,mdx}` for the Telegram URL via Grep tool returned "No matches found" instantly — but the grep pattern was scoped to a glob that didn't actually match the LOGOS structure. A scoped Grep into a specific directory (`Projekte/LOGOS`) was more reliable. Session 21 also flagged Glob unreliability with absolute Windows paths. Pattern is consistent.

## Next Steps (Priority Order)

The highest priorities are session 21's untouched queue plus two new items from this session.

1. **(USER ACTION, no code) Toggle both itch.io games to Public.** The crelvo.dev entries shipped this session link to `crelvo.itch.io/commuter-chaos` and `crelvo.itch.io/tabletopsiege`, both of which return 403 to the public. Until the user logs into itch.io and flips visibility, these are dead links on a public portfolio. Estimated effort: 60 seconds per game, owner action only. Verify with `curl -sI -A "Mozilla/5.0 ..." https://crelvo.itch.io/commuter-chaos` after — should return 200 instead of 403.

2. **Build Public Brain Play 1: `brain.dockfolio.dev` live feed.** Carryover from session 21 — full implementation plan in session 21's HANDOVER.md "Next Steps" #1 (9-step recipe: cron hook + public API endpoint + nginx auth_basic exemption + HTML feed + DNS + certbot + nginx site + config.yml). Estimated 60-90 minutes. The KB file 17 was written session 21 and the Marketing Brain has been cycling without the infrastructure existing — proposals are piling up unactionable.

3. **Run the file-17 grounding query** to see if the Marketing Brain has been citing `portfolio-and-public-ai` in real Haiku briefs since `3881665` shipped. SQL command is in session 21's HANDOVER.md priority #2 (one-liner SSH + docker exec + better-sqlite3 query). Threshold: file 17 should hit ≥50% of briefs; b2b/plg/cat should start hitting occasionally now that `max=3` opened a third slot. If file 17 is under 30% or b2b/plg/cat are still at zero, deeper scoring tuning is needed.

4. **Run one Haiku smoketest on a portfolio-biased app** (likely `headshot-ai` or `promoforge`, `docker exec dockfolio-dashboard node /app/brain-smoketest.mjs <slug>` — no `--dry`). Cost ~$0.028, 55s. Confirms whether the LLM actually cites file 17, not just receives it. If LLM ignores it, the file's content voice needs rewriting.

5. **(Optional, low-risk) Sweep crelvo.dev project descriptions for hyphens.** All 20 pre-existing entries in `slebständig/src/components/Projects.astro` violate the no-dashes-in-player-text rule from global CLAUDE.md. ~5 minutes of `rg "[a-z]-[a-z]"` + manual hyphenless rewrites. Worth confirming with the user first since this changes 20+ public-facing strings.

6. **Push 6 local-only commits in `appManager` to `origin/master`.** Six commits sit unpushed (5 from session 21 + the session-21 handover + this session-22 handover). The global "do all" contract step 3 says always push after every commit. Trade-off: pushing exposes the work history on GitHub; not pushing risks loss to a context crash. User has declined push in prior sessions.

7. **Carryover from session 21: route ordering test, Orb source repo update, ~95 brain actions triage.** All untouched. Same priority and detail as session 21's HANDOVER.md.

## Rollback Plan

Two repos got new commits this session. Each is independently revertable.

- **slebständig commit `0d7fc0c` (3 crelvo.dev project entries):**
  - Surgical revert: `git -C "C:/Users/kreyh/Projekte/slebständig" revert 0d7fc0c` then `npm run build && scp ./dist/* deploy@.../var/www/crelvo/`. Removes the 3 cards from the portfolio. Safe — no other code depends on these entries.
  - Pre-session safe state on slebständig: `b41164d Rename Orb to OrbEdge with new domain orbedge.de`.

- **antenna commit `b257ee7` (footer cross-links):**
  - Surgical revert: `git -C "C:/Users/kreyh/Projekte/antenna" revert b257ee7` then `scp site/index.html deploy@.../home/deploy/theforgottensystem.org/index.html`. Removes the "Related work" footer row. Safe — no other code depends on the new CSS class.
  - Pre-session safe state on antenna: `061873a` (parent of `b257ee7`).

- **appManager:** No commits this session except this HANDOVER.md update. Safe state is `dfbb73f Session 21 handover` (unchanged from session 21).

- **No infrastructure changes this session.** No nginx configs touched, no DNS records added, no certificates issued, no databases modified. Pure content edits.

## Files Changed This Session

Across three repos:

- **`Projekte/slebständig/src/components/Projects.astro`** — +27 lines. Three new entries appended to the `projects` array: The Forgotten System (Visual Essay), Commuter Chaos (Game · Testphase), Tabletop Siege (Game · Testphase). Committed as `0d7fc0c` on `konradreyhe/crelvo` `master`, pushed.

- **`Projekte/antenna/site/index.html`** — +13 lines. New `<div class="related-links">` row inside `<footer>` with three outbound `<a>` tags (oldworldlogos.com, t.me/oldworldlogos, crelvo.dev) and a "RELATED WORK" label. New CSS class `.related-links` + `.related-links .label` added to the footer styles block. Committed as `b257ee7` on `konradreyhe/antenna` `main`, pushed.

- **`Projekte/appManager/HANDOVER.md`** — Replaced session-21 handover with this session-22 handover. Will be committed as part of the standard handover commit at session end (parent: `dfbb73f`).

- **`/var/www/crelvo/` on VM** — Refreshed full Astro `dist/` via scp.
- **`/home/deploy/theforgottensystem.org/index.html` on VM** — Replaced via scp.

## Open Questions

- **Will the user toggle the itch.io game visibility?** If not within a few days, the dead links damage Crelvo's portfolio credibility. Worth a follow-up nudge in the next session.

- **Should the existing crelvo.dev project descriptions be rewritten for the no-dashes rule?** ~20 strings need hyphenless rewrites. Not a session-22 task but lingering inconsistency.

- **Is there a CI deploy path for slebständig (crelvo.dev)?** Both deploy.sh files (slebständig and antenna's DEPLOY.md) are explicit about manual deploy. No GitHub Actions workflows referenced. Future automation could push on every `master` commit, but YAGNI without a triggering use case.

- **Should the nginx -s reload in slebständig/deploy.sh be fixed?** Currently fails silently with "invalid PID number" because it doesn't pass `-c /home/deploy/nginx-configs/nginx.conf`. Harmless for static-file deploys but may bite if a future deploy actually changes nginx config.

- **Is the Marketing Brain still grounding correctly?** Multiple cron cycles ran autonomously during this session and were not measured. Could be working perfectly, could be silently regressing. Session 21 priority #2 (the SQL query) is the answer.

- **Was the user's intent for the antenna footer mutual cross-linking?** I added antenna → owl + telegram + crelvo. The user did NOT ask for the reverse (owl → antenna, crelvo.dev → antenna would be a side mention, antenna is already a card on crelvo.dev). If reciprocal links were intended, they'd need to be added on oldworldlogos.com source (somewhere in `Projekte/LOGOS`).
