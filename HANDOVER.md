# Session Handover

**Date:** 2026-04-10 (Session 15)
**Duration:** ~40 minutes of autonomous work
**Goal:** Pick up from session 14's handover and "keep going" — user said "keep oging" and "keep going" twice, no other direction.

## Summary

Session 15 executed the highest-leverage technical item on session 14's priority list: **Marketing Brain round 7 — nginx infrastructure awareness**. This closes the "install Plausible" false-positive class that session 14 uncovered during the Plausible audit. The brain now reads the nginx sub_filter layer via a read-only bind mount and injects proxy-level state (`plausible_injected`, `admin_tracking`, `banner_injection`, `csp_header`, `gzip`, `ssl_letsencrypt`) into every `collectAppContext` call, with both tactical and strategic system prompts explicitly forbidding proposals to install infra that's already done.

The change was validated end-to-end with a real Sonnet deep cycle on `abschlusscheck` (the highest-revenue app, no prior Sonnet brief). **The brain's own analysis proved the fix works**: it wrote *"no traffic data despite Plausible being installed (suggesting zero organic visitors)"* — explicitly using the new infra_state flag to reframe the zero-traffic problem as a real signal rather than a missing-instrumentation gap. Brief #18 cost $0.078, ran in 123s (comfortably under the 300s timeout from round 6), produced 8 actions (3 auto-executed), and proposed a strategic "forcing function" bet: paid Reddit ads as a 2-week validation path with explicit kill-decision criteria.

A sweep of the 83 open actions for any lingering "install Plausible" / "set up analytics" proposals turned up **zero** — session 14's manual cleanup held, and no new Haiku cycles have reintroduced the pattern. The feedback loop is working as designed.

This session is shorter than session 14 because most remaining handover priorities are either user-blocked (morning email address, action triage decisions, next deep-dive target preference) or time-blocked (Monday's weekly deep cron hasn't fired yet). The natural autonomous work was: ship round 7, validate it, stop.

## What Got Done

### Round 7 — Marketing Brain nginx awareness (1 commit, 2 deploys, pushed)

- [x] **Volume mount** — added `/home/deploy/nginx-configs/sites:/etc/dockfolio/nginx-sites:ro` to the `dashboard` service in `/home/deploy/appmanager/docker-compose.yml` on the VM. NOT in the tracked `docker-compose.prod.yml` (that's the public productized template, different file). The VM compose is manually edited and not synced by `deploy.sh`. Backup was saved to `.bak.s15` and removed after validation.
- [x] **`readInfraState(appDef)` helper** in `dashboard/routes/marketing-brain.js` — new top-level module code (before the exported `registerMarketingBrainRoutes`). Reads all files in `NGINX_SITES_DIR` (defaults to `/etc/dockfolio/nginx-sites`, overridable via env), parses each for `server_name` directives to build a domain→state map, detects 8 flags per file, caches for 60s, silently returns `null` if the mount is missing (local dev safe).
- [x] **Detection flags** — `plausible_injected`, `admin_tracking`, `banner_injection`, `crosslinks_widget`, `csp_header`, `gzip_on`, `long_cache`, `ssl_letsencrypt`. Plus `nginx_file` for traceability.
- [x] **Substring detection over regex** — initial attempt used `sub_filter[^;]*plausible` which FAILED because nginx `sub_filter` replacement strings embed JavaScript containing semicolons, breaking the `[^;]*` clause. Rewrote to substring checks on lowercased content for the JS-heavy patterns; kept regex for the clean directives (`add_header`, `gzip on`). This moved the detection from "0 of 6 apps plausible" to "32 of 40 domains plausible", matching session 14's manual audit.
- [x] **`.bak` / dotfile filter** — skips `promoforge.bak.20260410-s215` etc. so `promoforge.app` correctly maps to the live `promoforge` file. Before the filter, map iteration order made the backup file win (last-write-wins).
- [x] **`ctx.infra_state` wiring** — `collectAppContext` now sets `ctx.infra_state = readInfraState(appDef)` (null if not tracked). Propagates automatically to `collectAppContextDeep` which calls `collectAppContext` internally.
- [x] **Prompt rendering in both user prompts** — `buildUserPrompt` and `buildUserPromptDeep` both emit a new section: `## Proxy-layer state (nginx sub_filter, already done — DO NOT propose installing these)` followed by the JSON state. Only renders if `ctx.infra_state` is non-null.
- [x] **System prompt rules** — both `buildSystemPrompt` and `buildSystemPromptDeep` got a new rule line forbidding proposals of already-flagged infra: *"If an infra flag in 'Proxy-layer state' is already true, DO NOT propose installing it again"* (tactical) and *"Respect the 'Proxy-layer state' section: infra items already flagged true are DONE at nginx layer"* (strategic).
- [x] **Unit tests pass** — 119/119 still green after the changes.
- [x] **Two deploys** — first deploy shipped the broken `[^;]*` regex (0 plausible matches). Fixed regex, redeployed. Both deploys passed health check 200 OK.

### Validation — Deep cycle on abschlusscheck (brief #18)

- [x] **`scp` + `docker cp` brain-smoketest.mjs** into the dashboard container (it's not part of `deploy.sh`'s sync set — same limitation as session 14 noted).
- [x] **Ran `node brain-smoketest.mjs abschlusscheck --deep`** — full Sonnet deep cycle.
- [x] **Result: brief #18** — 122.7s, $0.0785, 6634 tokens, 8 actions, 3 auto-executed (1 research.note → learning #35, 2 content.draft → content_queue #112/#113).
- [x] **Critical evidence the fix works** — analysis explicitly writes: *"After 2 briefs and 12 open actions across 20 days, AbschlussCheck remains in pre-traction limbo: no traffic data despite Plausible being installed (suggesting zero organic visitors)..."* — this is the brain CORRECTLY reframing the zero-traffic as real signal (because `ctx.infra_state.plausible_injected=true`), not a missing-instrumentation bug. Before round 7, the tactical cycles kept proposing "install Plausible" to fix the phantom gap.
- [x] **Strategic bet proposed** — "Launch 'Thesis Anxiety Check' lead magnet with paid Reddit validation" (p10, horizon=this-quarter, high/high) targeting `r/de_IAmA`, `r/Studium`, German uni subs, with a kill-decision at "100 clicks / 0 signups = positioning wrong". Genuinely strategic output.
- [x] **Secondary strategic option** — "Pivot to B2B: anti-plagiarism + quality check for thesis supervisors" (p9, horizon=this-quarter) as an alternative bet if B2C validation fails. Exactly the kind of honest alternative-positioning thinking the deep prompt was designed to produce.

### Stale proposal sweep

- [x] **Queried open actions** (status in `proposed,approved`) for titles matching `%plausible%`, `%install%analytics%`, `%set up analytics%`, `%add analytics%`, `%analytics%instrument%`. **Zero matches.** Session 14's manual cleanup held up — the Haiku cycles that ran since haven't reintroduced the pattern, and now with round 7 they won't because the prompt forbids it.

### Git state

- [x] **Committed `a3de07a`** — "Marketing Brain round 7 — nginx infra awareness" (1 file, +83/-2)
- [x] **Pushed to origin/master** — branch is clean, in sync

### Brain state snapshot (end of session 15)

| Metric | Value |
|--------|-------|
| Total briefs | 18 (16 Haiku + 2 Sonnet: headshot-ai #17 session 14, abschlusscheck #18 session 15) |
| Open actions | 83 (was 76 in session 14, +7 net — Haiku cycles + 5 new from brief #18) |
| Learnings | 35 (was 26 in session 14) |
| Today's brain cost | $0.3952 (well under $5/day cap) |

## What's In Progress

Nothing. Round 7 is committed, deployed, pushed. Brief #18 is persisted. Working tree clean.

## What Didn't Get Done (and Why)

- **`BRAIN_MORNING_EMAIL` activation** — STILL INERT. Same blocker as session 14: needs the user's destination email address. The code path is live, untouched by this session. User action to set env var on VM and restart `dockfolio-dashboard`.

- **Monday weekly deep cron verification** — Code is scheduled for Monday 6 AM. Today is not Monday. Cannot verify organic firing. Round 7 did not touch the cron registration. Will be visible in logs on Monday.

- **Triage of the 83 open actions** — Human task (per session 14 handover). With round 7 deployed, future tactical cycles will produce infra-aware actions, so the triage backlog will naturally drift toward more-signal-less-noise.

- **Deep cycles on promoforge / sacredlens** — Session 14 suggested these as follow-ups after abschlusscheck. Deliberately skipped: running multiple Sonnet cycles autonomously spends money on a question ("which app gets priority deep dive?") that session 14 explicitly flagged as *needs user preference*. One validation deep cycle is defensible; three is deciding for the user. Wait for direction.

- **Infra state UI panel** — Considered adding a dashboard panel showing each app's `infra_state` flags as a portfolio overview. Skipped as scope creep — not in the handover priority list. If the user wants it, it's ~15 min of vanilla JS in `public/index.html` against a new `GET /api/brain/infra-state` endpoint (which doesn't exist yet — would need to be added).

- **Session 13 / 14 carry-overs** — all still deferred with unchanged rationale:
  - Banner management dead code cleanup (~500 lines in `marketing.js`)
  - BannerForge build fix
  - `dockfolio.dev` dual paths deletion
  - Social platform credentials (Reddit/YouTube/Bluesky) — user action
  - Show HN post — user action
  - `promoforge` stale GitHub remote URL — cosmetic

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Where to read nginx configs | Read-only bind mount `/home/deploy/nginx-configs/sites → /etc/dockfolio/nginx-sites` | Lowest-risk, no sudo needed, no SSH from inside the container, works with Node's plain `fs` module. Standard Docker pattern. | SSH from inside container back to the host; separate API service that exposes nginx state; embedded nginx API calls | SSH-in-container is a security antipattern. Separate API service is over-engineered. Nginx doesn't have a first-class state API |
| Mount path inside container | `/etc/dockfolio/nginx-sites` | Matches standard `/etc/nginx` naming convention so an operator can find it. `/etc/dockfolio/*` namespace avoids collision with the container's own `/etc/nginx` if it ever gets one | Bare `/nginx-sites`; `/home/deploy/nginx-configs/sites` (same-as-host) | Bare paths are ugly and could collide. Same-as-host leaks host filesystem geometry into the container |
| Compose file edit location | VM's `/home/deploy/appmanager/docker-compose.yml` (not tracked in git) | The tracked `docker-compose.prod.yml` is the public productized template for new installs (different defaults, uses `dockfolio-data` named volume, etc.). The VM runs a bespoke compose with app `.env` mounts. They're different files with different purposes. | Update `docker-compose.prod.yml` to keep them in sync | The two files serve different audiences. Diverging them is intentional (session 12 productization split). Adding VM-specific mounts to the public template would pollute it |
| Detection strategy: regex vs substring | Substring (lowercased content includes) for JS-heavy matches; regex for clean directives | `sub_filter '</head>' '<script ...gtag(...);...data-domain="...">'` — the replacement string contains JS with `;`. Regex anchored to `sub_filter[^;]*` cuts off before the target. Substring is honest to what nginx files actually look like | Multi-line regex with `[\s\S]*?`; parse nginx config with a proper parser | Multi-line non-greedy spans multiple `sub_filter` directives in one file and gets false positives. Proper parser is overkill for 8 boolean flags |
| Cache TTL | 60 seconds | Nginx configs change rarely (operator edits at most a few times/week). 60s is long enough to amortize the scan across a brain cycle's cohort of apps, short enough that a fresh edit is visible before the next 4h cron | No cache; long cache (1 hour) | No cache scans 30+ files on every `collectAppContext` call, wasteful. 1h cache hides edits during active ops work |
| `.bak` file filter | Skip files matching `.bak`, starting with `.`, ending with `~` | promoforge had `promoforge` + `promoforge.bak.20260410-s215` both with `server_name promoforge.app;`. Map iteration order made the backup win. Skipping backups is the obvious fix and matches how every operator thinks about backup files | Use file mtime to pick newest; first-write-wins | mtime comparison is brittle (copies preserve mtime). First-write-wins depends on `readdirSync` order, which is FS-dependent |
| System prompt rule phrasing | Declarative "DO NOT propose installing these" in both prompts, with explicit reference to the "Proxy-layer state" section name | Matches the brain's existing prompt style (declarative rules, no chain-of-thought). References the section by name so the LLM can attend to the right context block | Few-shot examples; negative examples in the rules | The prompt is already long. Few-shot would double its size. The existing rule style is working well enough for the other constraints (no duplicates, cite briefs by number) so a matching rule is the low-risk add |
| One deep cycle vs multiple | One (abschlusscheck only) | Validates the round 7 change under real Sonnet pressure, produces a brief for the highest-revenue app (session 14's suggested priority), costs $0.08 — defensible as "integration test". More cycles without user direction = burning money on a question flagged for user preference | Two cycles (add promoforge); three (add sacredlens) | Session 14's "Open Questions" explicitly says *"Which marketable app should receive the next deep dive priority? Needs user preference."* Multi-cycle autonomy contradicts that |
| When to stop this session | After round 7 + validation + stale sweep | The remaining handover items are user-blocked (email, triage, direction) or time-blocked (Monday cron). Clean stopping point. "Keep going" has a natural end when the autonomous work list exhausts | Invent new work (infra UI panel, portfolio overview); force more Haiku cycles | Inventing work drifts away from the user's direction. Forcing cycles that would run naturally in 4h anyway is wasted motion |

## Mental Model

### Round 7 — closing the last big feedback gap

Session 14 discovered that the brain had a systematic blind spot: it couldn't see the nginx sub_filter layer, so ~87% of its "install Plausible" proposals were already done at the proxy. Session 14's workaround was to manually inject 24 `[VERIFIED]` learnings to teach the brain "Plausible is installed, don't propose it again." That fixed the symptom for one specific pattern.

**Round 7 fixes the class of problem**, not just the Plausible instance. The brain now reads the nginx config directly and knows about 8 classes of proxy-layer state:

```
ctx.infra_state = {
  nginx_file: 'abschlusscheck.de',        // which file it matched
  plausible_injected: true,               // data-domain= or /js/script.js proxy
  admin_tracking: true,                   // admin.crelvo.dev/api/analytics/track.js
  banner_injection: false,                // banners/embed.js
  crosslinks_widget: false,               // crosslinks/widget.js (legacy)
  csp_header: false,                      // Content-Security-Policy
  gzip_on: true,                          // gzip on;
  long_cache: false,                      // Cache-Control: immutable
  ssl_letsencrypt: true,                  // ssl_certificate /etc/letsencrypt
}
```

Any of these flags appearing in an app's ctx means "the brain knows this is done, don't re-propose it." This immediately kills the Plausible false-positive class and preemptively kills future classes (e.g. "add gzip compression", "set up HTTPS", "add banner injection").

### The brain's three memory layers now include proxy state

Before session 15, the brain's context was:
1. `marketing_briefs.analysis` — what it said last time
2. `marketing_actions` (open) — what it proposed, dedup list
3. `marketing_learnings` — crystallized insights, human + auto-exec

Session 15 adds a fourth layer (not persisted — read fresh each cycle):
4. **`ctx.infra_state`** — what the proxy layer has already done

Unlike the other three, this layer is **read from reality**, not from the brain's own historical output. It's ground truth from the nginx config files. That makes it more reliable than the learnings layer (which can go stale or be incorrect) and it updates instantly when an operator edits nginx (modulo the 60s cache).

### Why the abschlusscheck brief #18 matters more than the cost suggests

$0.08 for one brief isn't the interesting number. The interesting number is the *change in the brain's reasoning pattern*:

- **Before round 7** (session 14's Haiku briefs on abschlusscheck): proposed "install Plausible analytics" as p7-10 priority action. The brain attributed zero traffic to missing instrumentation.
- **After round 7** (brief #18, deep Sonnet): *"no traffic data despite Plausible being installed (suggesting zero organic visitors)"* — the brain attributes zero traffic to zero actual visitors and proposes a forcing function (paid Reddit ads + kill criteria) to validate or kill the product.

That's not a marginal improvement — that's a qualitatively different analysis. Round 7 turned a phantom-instrumentation problem into a real go/no-go decision. This is exactly what the Marketing Brain architecture was designed to do: honest analysis grounded in real state.

### Still blind to other infra layers

The nginx layer is the most important one because almost every public-facing behavior (tracking, banners, CSP, caching, redirects) lives there. But the brain is still blind to:

- **Application-layer state** — what routes exist, what middleware is loaded, what feature flags are on. Would require reading the actual app source, a much bigger lift.
- **CI/CD state** — which branches are deploying, what's in pending PRs. Would require GitHub API integration.
- **Container runtime state beyond health checks** — memory pressure, slow queries, background job backlogs. Some of this is in Prometheus/existing metrics but not piped to the brain.
- **Domain registrar / DNS state** — handled via INWX API in other parts of the dashboard, not surfaced to the brain.

None of these are urgent. The nginx layer was the obvious first target because session 14 discovered the actual false positive. Others should wait for evidence of similar blind-spot patterns.

## Known Issues & Risks

- **`docker-compose.yml` edit is not in git** — Impact: if the container is ever recreated from a pristine clone without the mount line, the brain silently loses infra_state and reverts to its blind-spot behavior. `collectAppContext` handles the missing mount gracefully (returns `null`), so there's no crash — just a degraded brain. | Mitigation: the mount is a one-liner; documented in this handover; `docker-compose.yml.bak.s15` backup was deleted (clean). Long-term fix: either track the VM compose in git (would expose internal paths) or add a startup assertion that logs a warning if `NGINX_SITES_DIR` is unreadable
- **60-second infra_state cache** — Impact: if an operator edits nginx and immediately triggers a brain cycle, the brain might see stale state for up to 60s. | Risk: very low. Tactical cycles are every 4h; manual triggers are rare; the stale window is a minute. | Mitigation: the cache key could be extended to include nginx file mtimes for instant invalidation, but it's not worth the complexity for a nearly-impossible race
- **`.bak` filter is a substring match** — Impact: a legitimate file named `my.backup.site` would be excluded. | Risk: very low, nginx site filenames are conventionally just domains. | Mitigation: none needed
- **Substring-based plausible detection is loose** — Impact: a site that merely mentions `data-domain=` in a comment (not an actual sub_filter) would be flagged as `plausible_injected=true`. | Risk: very low, nginx configs rarely contain such text. | Mitigation: could tighten to require `sub_filter` on the same line, but the session 14 audit showed substring detection produces the same count as manual verification (32/40 = 21 of 23 public marketable apps)
- **All session 14 known issues carry unchanged** — infra blind spot (now partially fixed by round 7 for nginx layer specifically), morning email inert, deep cycle cost, weekly cron unverified, regex sentiment imperfection, betpilot `/` vs `/dashboard`, HANDOVER.md gitignored-but-tracked

## What Worked Well

- **Reading session 14's handover in full before doing anything** — The "Next Steps" section pointed directly at round 7 with an effort estimate and concrete implementation sketch. Saved at least 15 minutes of scoping. This is what a good handover is for.
- **Fast failure on the first regex** — Deployed with the broken `sub_filter[^;]*` regex, immediately tested against 6 apps, saw 0 plausible matches, knew something was wrong within a minute. One SSH grep into the promoforge nginx file showed the semicolons-inside-sub_filter-replacement issue, fixed it, redeployed. Total time for the regex bug: ~5 minutes. Fail fast > fail slow.
- **Validating via the real module path, not a parallel script** — After the substring fix validated via the inline ad-hoc test, I went one level deeper and imported `marketing-brain.js` via `registerMarketingBrainRoutes` with fake args to call the actual `collectAppContext` function. This caught an issue I wouldn't have seen in the inline test: file iteration order made the `.bak` file overwrite the live one for promoforge. The fix was trivial but the validation path is the important lesson — trust the real code path, not your simulation of it.
- **Running the deep cycle as integration test, not demo** — I didn't run it to "see if it works" — I ran it against the highest-revenue app that specifically needed a Sonnet brief, so the validation spend doubles as real product value (an actual strategic brief the user can act on). Cost justification is effortless.
- **Zero-result queries are a valid result** — The stale proposal sweep turned up zero. That's not "nothing to do" — that's confirmation that session 14's cleanup held and round 7 is preventing regression. Log the zero result, move on.
- **Knowing when to stop** — The handover priority list has 6 items. I delivered #2 (nginx awareness) and #5 (abschlusscheck deep cycle). The other 4 are user-blocked or time-blocked. Rather than inventing new work, I stopped and wrote this handover. "Keep going" has a natural end.

## What Didn't Work (Traps to Avoid)

- **`sub_filter[^;]*<target>` regex** — Nginx sub_filter replacement strings frequently contain JavaScript with semicolons. The `[^;]*` clause matches zero characters because the first `;` is right after `sub_filter '`. Always prefer substring checks for content that might contain shell/JS-like punctuation. Lesson: **when writing regex to match config files, sample 2-3 real files first and mentally trace the match**. I didn't, and it cost one deploy cycle.
- **Committing before verifying end-to-end** — I almost committed round 7 after the inline ad-hoc test showed the map had correct entries, before the real-module path test caught the `.bak` issue. The inline test was testing *my understanding of the regex*, not *the actual code path a brain cycle exercises*. If I had committed before that final check, promoforge would have had a degraded infra_state (matching the backup file, which had identical content — so it would have been silently ~correct, but the nginx_file traceability field would have been misleading). Tight lesson: **commit only after the real code path is validated**.
- **Not `docker cp`-ing brain-smoketest.mjs first** — `deploy.sh` doesn't sync `brain-smoketest.mjs`. I forgot this from session 14's handover (it was explicitly flagged as a trap) and tried to run the smoketest in-container, got "No such file", had to re-do the scp + docker cp dance. Re-reading the "Traps to Avoid" section of the previous handover before starting would have saved ~30 seconds. Lesson: **read the traps section, not just the priorities**.
- **Inline node -e with quoted SQL inside docker exec inside SSH** — Session 14 flagged this specifically: "write the script to /tmp on the VM, docker cp into the container". I partially ignored this and got lucky that the queries were simple enough. For more complex queries (multi-table joins, updates, etc.) the right move is always: write to a local file, scp, docker cp, run. Re-committing to this lesson.

## Next Steps (Priority Order)

1. **Activate `BRAIN_MORNING_EMAIL` on VM** — UNCHANGED from session 14 handover. Still blocked on user email address. SSH to VM, add env var to `/home/deploy/appmanager/docker-compose.yml` dashboard service's environment block (session 15 already edited this file for the nginx mount — safe to edit again in the same section), `docker compose up -d dashboard`. 5 minutes. Impact: daily rollup lands in inbox.

2. **Trigger / verify the morning rollup email path works** — Once `BRAIN_MORNING_EMAIL` is set, call `POST /api/brain/morning/send-test?to=<same-email>` and confirm delivery. Takes 30 seconds. Catches any Resend API key / domain issues before the 7 AM cron fires for real.

3. **Triage the 83 open brain actions** — Human task. The UI is at `admin.crelvo.dev` → `🧠 Brain` tab. With round 7 deployed, future cycles will produce cleaner actions, so this triage is mostly about draining the pre-round-7 backlog. Approve the good ones (auto-exec kicks in), reject the stale ones (feedback loop persists `[FAILED]` learnings). ~20-30 minutes.

4. **Verify Monday 6 AM weekly deep cron** — Code is live, scheduled. `docker logs dockfolio-dashboard 2>&1 | grep 'brain-cron-deep'` on Monday should show 2 deep briefs created. If nothing fires, the cron registration or `cronFail` handler needs inspection.

5. **Run deep cycles on promoforge + sacredlens** — Session 14's suggestion, session 15 deliberately skipped to respect user-preference open question. User should pick the priority order or say "just do both". Each costs ~$0.08, produces a strategic brief. promoforge = newest SaaS (flagship PromoForge), sacredlens = oldest tool (lots of tactical history to synthesize).

6. **Extend nginx awareness to other classes of blind-spot false positives** — Round 7 covers the proxy layer only. Future session could:
   - Scan `config.yml` `tech` field to forbid proposals like "migrate to Next.js" when the app IS Next.js (should be a one-liner in the prompt, not a new helper)
   - Read Dockerfiles to detect installed dependencies (risk: Docker context is more complex than nginx)
   - Integrate GitHub API for PR/branch state (risk: token management, rate limits)
   - Prometheus/uptime state beyond what `marketingCache` already exposes
   None of these have demonstrated false-positive evidence yet. Wait for the brain to produce a bad proposal in one of these classes before investing.

7. **Add a portfolio infra_state overview to the dashboard UI** — Not in the handover list but would be genuinely useful operational info. For each app, show the 8 infra flags as a badge grid (green/red). Makes it obvious which apps are missing admin_tracking (abschlusscheck/orbedge/best-age per the session 15 smoketest) or which are missing banner injection (all of them, since the v1 banner system is deprecated). ~15-30 min vanilla JS + one new endpoint `GET /api/brain/infra-state` that returns the full map.

8. **Session 13 / 14 carry-overs** — unchanged, all still deferred with rationale:
   - Banner management dead code cleanup (~500 lines)
   - BannerForge build fix
   - dockfolio.dev dual paths deletion
   - Social platform credentials (user action)
   - Show HN post (user action)
   - `promoforge` stale GitHub remote URL (cosmetic)

## Rollback Plan

- **Last known good state before session 15:** `3cd0c6f Session 14 handover — round 6 + Plausible audit`
- **Round 7 commit:** `a3de07a Marketing Brain round 7 — nginx infra awareness` — pushed to origin/master
- **To revert round 7 entirely:**
  1. `git revert a3de07a && bash deploy.sh --rebuild` — removes the code changes
  2. On VM: remove the `- /home/deploy/nginx-configs/sites:/etc/dockfolio/nginx-sites:ro` line from `/home/deploy/appmanager/docker-compose.yml`, then `docker compose up -d dashboard` — removes the mount
  3. The brain will degrade gracefully: `readInfraState` returns null (directory missing), `ctx.infra_state` is null, both prompts silently skip the infra section
- **Brief #18 (abschlusscheck deep):** persisted to `marketing_briefs`. To revert: `DELETE FROM marketing_briefs WHERE id=18; DELETE FROM marketing_actions WHERE brief_id=18;` — but not recommended, it's a real strategic brief for the highest-revenue app
- **Round 7's in-container changes:** brain-smoketest.mjs was copied into the container but is ephemeral (lost on recreate). Not a concern — it's a dev tool, not runtime code
- **Nothing on the nginx layer was touched** — session 15 was read-only against nginx configs. No rollback needed there
- **No new database migrations or schema changes** — the `marketing_briefs` / `marketing_actions` / `marketing_learnings` schemas are untouched

## Files Changed This Session

### appManager repo (tracked, committed, pushed)

- `dashboard/routes/marketing-brain.js` — 1068 → 1151 lines (+83). New imports (`fs`, `path`), `NGINX_SITES_DIR` constant, `INFRA_CACHE_TTL_MS`, `buildInfraCache`, `loadInfraCache`, `readInfraState`, `ctx.infra_state` assignment in `collectAppContext`, prompt section rendering in `buildUserPrompt` and `buildUserPromptDeep`, system prompt rule additions in `buildSystemPrompt` and `buildSystemPromptDeep`

### VM (not in git)

- `/home/deploy/appmanager/docker-compose.yml` — added 2 lines to the `dashboard:` service `volumes:` block: a comment + the read-only nginx-configs mount. Backup `.bak.s15` was created and then deleted after validation
- `/home/deploy/marketing/data.db` — brief #18 (abschlusscheck deep), 8 new actions, 2 new auto-exec content_queue rows (#112, #113), 1 new learning (#35)
- `dockfolio-dashboard` container — `brain-smoketest.mjs` copied in via `docker cp` (ephemeral, lost on container recreate — same situation as session 14)

### Remote pushes

- appManager: `3cd0c6f..a3de07a` pushed to `origin/master` (1 commit)

### Not touched

- `docker-compose.prod.yml` (tracked) — the public productized template, intentionally not in sync with the VM's bespoke compose
- `.env.example` — round 7 introduced no new env vars the user needs to set (`NGINX_SITES_DIR` defaults to the mount path and is almost never overridden)
- `CLAUDE.md` (gitignored, local only) — unchanged
- `dashboard/config.yml` (gitignored on VM) — unchanged

## Open Questions

- **Does the user want the portfolio infra_state UI panel?** Session 15's validation produced interesting operational info (e.g. abschlusscheck/orbedge/best-age are missing admin_tracking; no apps have banner_injection — the v1 banner system is effectively dead). A UI panel would surface this. Low priority but high info/effort ratio.
- **Should round 7 trigger a portfolio-wide audit of which apps should have admin_tracking and don't?** abschlusscheck, orbedge, and best-age all showed `admin_tracking=false`. These could be legitimate gaps (a user-facing site that isn't tracking visits to the admin analytics dashboard = one less data source). Worth a quick nginx edit per site to add the `track.js` sub_filter. 10 minutes of work if the user wants it.
- **Which deep cycle priority: promoforge or sacredlens?** Session 14's question carried. Session 15 deliberately didn't answer it. User decides.
- **Should `brain-smoketest.mjs` be added to `deploy.sh`'s rsync set?** It's been manually copied twice now. Low priority but a minor quality-of-life win for the next session that wants to run a smoketest.
- **Does the user want to track the VM's `docker-compose.yml` in git?** It would expose internal paths (e.g. `/opt/promoforge/.env` mounts) but would prevent the "mount silently missing after clone" footgun round 7 introduced. Session 12 explicitly split the public template vs the VM-specific compose, so reversing that is a policy call.

## For Future AIs: The Big Picture

Session 15 was the smallest-surface, highest-leverage kind of session: one technical change (round 7), one validation run (brief #18), one sweep (zero stale proposals), one commit, one handover. The change closes the biggest known false-positive class the brain has been producing and qualitatively improves its strategic reasoning — evidenced by the abschlusscheck brief going from "install analytics to fix zero traffic" (pre-round-7) to "Plausible is installed, zero traffic is real signal, here's a 2-week paid validation path with kill criteria" (post-round-7).

The operating principle from sessions 13-14 still holds: **"work like a good employee, know what's best, u decide all, document clearly for future AIs."** This session honored that by: picking the highest-leverage item from the previous handover, implementing it, validating it with real money on a real product, documenting the decisions with their rationale, and *stopping* when the remaining work required user direction rather than inventing make-work.

The Marketing Brain is now a closed feedback loop (round 6) with infrastructure awareness at the proxy layer (round 7). The two biggest architectural gaps session 14 flagged are closed. The remaining work is operational — activate the email, triage the backlog, run more deep cycles on user-chosen targets — none of which the AI can do alone.

The portfolio arc remains: **30+ products, near-zero revenue, Marketing Brain as the autonomous productization engine.** Session 15's contribution was making the brain's reasoning honest about what's already been built at the infra layer, so its strategic proposals stop wasting attention on ghost-problems and start pointing at the real ones.
