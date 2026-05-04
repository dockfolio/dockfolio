# Session Handover

**Date:** 2026-05-04 (Session 23)
**Duration:** ~30 minutes, three small unrelated tasks
**Goal:** Started by `/read-handover`-ing session 22, but the user pivoted twice — first to "check if lohncheck has any affiliate sales," then to "add the new website on the VM (crypto-tax-engine related) to crelvo.dev and index it on Google via Playwright MCP." Session 23 ended up being a portfolio-and-marketing-ops session with zero work in this `appManager` repo.

## Summary

Session 23 was three short, sequential asks. First, the user asked whether lohncheck (lohnpruefung.de) has any affiliate sales. The smartsteuer/Awin banner was seeded back in session 18 (commit history shows the script `scripts/seed-smartsteuer-banners.js`), and four placements went active on 2026-03-31 across abfindungsoptimizer, schenkungsplaner, lohncheck, and abschlusscheck. Querying the production data.db at `/home/deploy/marketing/data.db` (mounted into `dockfolio-dashboard`) gave the answer: lohncheck has **63 views, 1 click** — by far the best of the four placements (abschlusscheck: 15v/1c, schenkungsplaner: 1v/0c, abfindungsoptimizer: 0v/0c). **Critical caveat:** our DB tracks the click-to-Awin redirect only. Whether that 1 click became a paying sale is **only visible in the Awin publisher dashboard** (advertiser ID 15043, awinaffid 2820526). Surfaced as a user action item — there's no code-side way to know.

Second ask was a portfolio addition: "we have a new website on the VM at `C:\Users\kreyh\Projekte\crypto-tax-engine`, add it to crelvo.dev and index it on Google using MCP Playwright." The user's path pointed at the Python tax engine backend, not a website — but the *associated* website is fiscanto.de (with kryptoaudit.de as a 301 redirect alias). Recent commits in this repo confirm: 7 commits between sessions 22 and 23 are all about fiscanto.de (impressum, datenschutz, selfcheck PDF export, /anwalt landing). I added a `Fiscanto` card to `slebständig/src/components/Projects.astro` (teal/cyan gradient, "Tax Brand" badge, BMF-themed description), built (24 pages, 3.75s), deployed via `scp dist/* deploy@.../var/www/crelvo/`, and pushed `1b86711` to `konradreyhe/crelvo`. Card count went 23 → 24, Fiscanto sits as the last card. Then for Google indexing, I added `https://fiscanto.de` as a URL-prefix property in Search Console, verified via HTML file (created `google3961c4e5a481bc42.html` directly on the VM with deterministic content — no download needed because Google's verification file content is `google-site-verification: <filename>`), requested URL indexing via URL Inspection, and submitted `sitemap.xml`. fiscanto.de was already indexed — so the request was effectively a recrawl prompt for the latest version.

Third ask was "verify 10000%." Ran an 8-layer verification: curl HTML truth (Fiscanto + fiscanto.de strings present), grep card count (27 grep hits → 24 actual cards), Playwright DOM query (totalCards: 24, fiscanto found, href correct, target=_blank, rel=noopener noreferrer, badge "Tax Brand", description starts with BMF), JPEG screenshot (visual confirmation of teal gradient + correct typography), HTTP status (fiscanto.de 200, GSC verification file 200), sitemap content (3 URLs: /, /selfcheck, /anwalt), git push state (1b86711 pushed to origin), working tree state (appManager clean except 3 pre-existing untracked files unrelated to this session). All passed. Test screenshot cleaned up per global session-hygiene rule.

Net session impact: **1 commit in `slebständig`, 1 file deployed to two VM webroots (crelvo.dev and fiscanto.de's GSC verification), 1 new GSC property created with sitemap submitted. Zero commits in this `appManager` repo** apart from this handover. Session 22's queue and session 21's deeper queue (Public Brain Play 1, file-17 grounding, ~95 brain actions) remain untouched.

## What Got Done

- [x] **Answered: LohnCheck affiliate sales status** — Queried production `data.db` for smartsteuer banner placement stats. Lohncheck: 63 views, 1 click since 2026-03-31. Three other sites also have placements (smartsteuer affiliate). Sale conversion data is not in our system; user must check the Awin dashboard. Side finding: abfindungsoptimizer placement is "active" but has 0 views — embed.js injection not firing on that site.

- [x] **Added Fiscanto to crelvo.dev portfolio** (`slebständig` `1b86711` on `konradreyhe/crelvo` `master`)
  - New entry appended to `projects` array in `src/components/Projects.astro`.
  - URL: `https://fiscanto.de`, badge "Tax Brand", gradient teal-500/20 → cyan-600/20, border hover:teal-500/50.
  - Description in German (matches site's audience) noting BMF compliance, wallet-level FIFO per BMF Schreiben 06.03.2025, DStV S 06 24 immutable data path, Anlage SO output.
  - Tags: Static, Three.js, Krypto Steuer, BMF.
  - Built (`npm run build`, 3.75s, 24 pages) and deployed via `scp ./dist/. deploy@.../var/www/crelvo/`. Card count went 23 → 24.

- [x] **Verified fiscanto.de in Google Search Console** — Added as URL-prefix property `https://fiscanto.de`. Verified via HTML file method by creating `/home/deploy/fiscanto.de/google3961c4e5a481bc42.html` on the VM with deterministic content (`google-site-verification: google3961c4e5a481bc42.html`). No download from Google needed.

- [x] **Submitted fiscanto.de for indexing on Google** — Used URL Inspection on the homepage; "Indexierung wurde beantragt" confirmed. Page was already indexed before the request, so this was effectively a recrawl prompt. Submitted `sitemap.xml` separately ("Sitemap wurde eingereicht") for the 3 sitemap URLs (/, /selfcheck, /anwalt).

- [x] **Verified everything 10000%** — 8-layer verification (curl, grep, DOM query, screenshot, HTTP status, sitemap content, git push, working tree). All passed. Test screenshot `verify-fiscanto-card.jpg` cleaned up per global rule.

## What's In Progress

Nothing. All 3 asks closed. Working tree clean (modulo 3 pre-existing untracked files: `.mcp.json`, `KNOWLEDGEBASE.md`, `PLAYWRIGHT-MCP-GUIDE.md` — same set flagged in session 22, not from this session).

## What Didn't Get Done (and Why)

- **Session 22's entire backlog plus session 21's deeper queue** — Not touched. The session-22 handover described 7 priorities (itch.io toggle, Public Brain Play 1, file-17 grounding query, Haiku smoketest, hyphen-sweep, push 6 commits, route ordering test, Orb update, ~95 brain actions). The user pivoted to portfolio/marketing ops the moment I finished `/read-handover`. The full list still applies.

- **Update of session 22's stale HANDOVER.md** — That handover was authored 2026-04-26 and in the 8 days since, 7 fiscanto.de commits landed (`11b598f`, `d8891d5`, `47d6e30`, `f94d1cf`, `de1d96d`, `37052a0`, `788cc52`). All of them were pushed at some point — `git status` says `up to date with origin/master`, contradicting session 22's claim that "6 commits sit unpushed." That was true on 2026-04-26 and is no longer true today. Session 23 replaces session 22's HANDOVER.md with this one, so the staleness is now resolved.

- **Investigation of abfindungsoptimizer banner injection** — Found the symptom (0 views despite "active" placement) but did not investigate. Likely the embed.js script tag is missing from the abfindungsoptimizer.de site, OR the banner injection nginx sub_filter is not firing, OR the placement priority is wrong.

- **Awin sales lookup** — User-side action only (Awin dashboard login required). I cannot answer the actual sales question; only the click count.

## Architecture & Design Decisions

| Decision | Chosen Approach | Why | Alternatives Considered | Why Rejected |
|----------|----------------|-----|------------------------|--------------|
| Mapping "the new website on VM at C:\Users\kreyh\Projekte\crypto-tax-engine" | fiscanto.de (the Python project's marketing site) | The Python repo at `crypto-tax-engine/` contains zero website source code. The website associated with that project is fiscanto.de, deployed at `/home/deploy/fiscanto.de/`, with source at `appManager/fiscanto-landing/`. 7 recent commits in this repo all reference fiscanto.de (BMF, Krypto Steuer, Selfcheck). | Ask the user to clarify; treat the typo as kryptoaudit.de | Ask was an option (low-stakes), but the inference was unambiguous given the commit pattern. kryptoaudit.de is just a 301 redirect to fiscanto.de — same destination either way. |
| Where to add the crelvo.dev portfolio entry | `Projekte/slebständig/src/components/Projects.astro` (Astro source) | Same as session 22's `0d7fc0c`: editing the VM webroot directly is self-erasing on the next deploy. The Astro source at `slebständig` is canonical truth. | Edit `/var/www/crelvo/index.html` on the VM | Self-erasing within one deploy cycle. |
| Position of new Fiscanto card | Append to end of `projects` array | Same convention as session 22's three additions. Avoids reordering 23 existing entries. | Insert after Dockfolio (flagship) for prominence | Reordering creates noisy diffs; visitors scroll the full grid anyway. |
| Fiscanto card visual style | Teal-500/20 → cyan-600/20 gradient, hover:border-teal-500/50, badge "Tax Brand" | Matches fiscanto.de's actual brand palette (teal + gold). The teal/cyan range was unused by neighbors (Tabletop Siege is amber/orange, Commuter Chaos is red/rose), avoiding adjacent-color clash. | Gold gradient (matches fiscanto.de gold accent); slate (neutral); deep blue | Gold collides with Tabletop Siege; slate looks dead next to other vibrant cards; deep blue is too close to existing emerald/blue cards. |
| Fiscanto description language | German (matches site's audience) | The fiscanto.de site is German-only and targets Steuerberater/Anwälte. The portfolio reader is multilingual — but the Astro `[lang]/index.astro` does NOT translate the projects array (these strings are static). Using German is honest about the destination's language. | English description like the other entries | Most other entries also describe English-language sites. fiscanto.de is the first German-language destination; honesty about language matters more than uniformity. |
| GSC verification method | HTML file upload | Deterministic file content (`google-site-verification: <filename>`) means no download step needed — just `ssh deploy@... 'echo ... > /home/deploy/fiscanto.de/<filename>'`. Fully automatable. | DNS TXT record (Domain property); HTML meta tag; Google Analytics; GTM | DNS requires INWX API call + propagation wait; meta tag requires editing fiscanto.de source + redeploy; GA/GTM aren't installed on fiscanto.de. HTML file is fastest. |
| Property type in GSC | URL Prefix (`https://fiscanto.de`) | Allows multiple verification methods including the HTML file path. Domain property requires DNS, which is slower. | Domain property (covers www. + http + https + subdomains) | We don't have www.fiscanto.de or any subdomains anyway; URL prefix is sufficient. |
| Where this HANDOVER.md lives | `appManager/HANDOVER.md` (this repo) | Continuity with sessions 21, 22, etc. The next `/read-handover` opens in `appManager` by default. | Per-repo handovers (slebständig + appManager) | Triplication; the next session won't read multiple handovers. |

## Mental Model

### The 4-repo + 1-marketing-stack mental model

Session 22 described the 3-repo portfolio system (appManager + slebständig + antenna). Session 23 extends that with **a fourth repo and a clarifying point about marketing operations:**

| Repo (local) | Domain | What it is | Deploy method |
|---|---|---|---|
| `Projekte/appManager` | `admin.crelvo.dev` | Dockfolio dashboard (this repo) + landing pages for various Crelvo apps in subdirs (`fiscanto-landing/`, `dockfolio-landing/`, etc.) | `bash deploy.sh --rebuild` for the dashboard; `scp` for the static landing subdirs |
| `Projekte/slebständig` | `crelvo.dev` | Crelvo agency portfolio (Astro static) | `npm run build && scp dist/* deploy@.../var/www/crelvo/` |
| `Projekte/antenna` | `theforgottensystem.org` | Victorian rooftop research microsite (vanilla HTML) | `tar | ssh tar` (full) or `scp site/<file>` (surgical) |
| `Projekte/crypto-tax-engine` | (no public site) | Python backend tax engine for Krypto Selbstanzeigen. **The website associated with this project is fiscanto.de, but its source is in `appManager/fiscanto-landing/`, NOT in `crypto-tax-engine/`.** | N/A (backend tool) — landing deploys via appManager/scripts |

**The trick: when the user says "the website for X project" or "the website on VM at PATH", they're pointing at the *associated marketing site*, not the source code path.** Sometimes the path they give is the backend/internal repo and the website lives elsewhere. Always check `appManager/<project>-landing/` and the recent commit history for clues. This session's user message ("we have a new website on vm C:\Users\kreyh\Projekte\crypto-tax-engine") was a perfect example: the path was the Python project, but the website was fiscanto.de (deployed weeks ago, not "new" on the VM in any technical sense — just newly added to the portfolio).

### Production data.db lives at /home/deploy/marketing/, not in the container

Critical detail that took me 3 SQL attempts to figure out: the `dockfolio-dashboard` container has `/app/data.db` (empty, 0 bytes) AND `/home/deploy/marketing/data.db` (the real one, 68 MB, 60+ tables). The real DB is bind-mounted into the container at the same path as the host. To query it: `docker exec dockfolio-dashboard node -e "const db = require('better-sqlite3')('/home/deploy/marketing/data.db'); ..."`. NOT `/app/data.db`. The local `appManager/dashboard/data.db` is also empty (it's just a dev-local placeholder).

The container does NOT have the `sqlite3` binary in PATH. Always use node + better-sqlite3 for ad-hoc queries. The `dashboard/server.js` connects to `/home/deploy/marketing/data.db` via the env var or hardcoded path; check `server.js` if you need to confirm.

### How the Awin affiliate banner system actually flows

The flow when a visitor on lohncheck (lohnpruefung.de) clicks the smartsteuer banner:

1. Banner is injected via nginx `sub_filter` adding `<script src="https://admin.crelvo.dev/api/banners/embed.js" data-app="lohncheck">` into the page HTML.
2. embed.js fetches `/api/banners/serve?app=lohncheck`, which returns a JSON object with the banner HTML (custom_html in this case) and a `placement_id` of 61 for the active smartsteuer placement.
3. embed.js injects the banner HTML into the page and registers click + view trackers.
4. On view, embed.js POSTs to `/api/banners/61/view` (increments `banner_placements.views`).
5. On click, browser navigates to `GET /api/banners/61/click`, which increments `banner_placements.clicks`, then 302-redirects to the click_url.
6. The click_url is `https://www.awin1.com/cread.php?awinmid=15043&awinaffid=2820526&ued=https%3A%2F%2Fwww.smartsteuer.de` — Awin's tracking redirect.
7. Awin's server registers the click against the publisher (awinaffid 2820526) and 302-redirects to smartsteuer.de with cookies/params for attribution.
8. If the visitor signs up + pays at smartsteuer within the cookie window (typically 30-90 days for Awin), Awin records the sale and credits the publisher.
9. **Sale data flows back to Awin's publisher dashboard. It does NOT flow to our DB.** We see clicks at step 5; everything after is opaque to us.

This is why "any sales?" is unanswerable from our side. We can only say "1 person clicked through to Awin." The user must log into Awin to see whether that 1 click became a sale.

**Why abfindungsoptimizer has 0 views:** likely the nginx sub_filter for embed.js injection is not firing. Three things to check next time: (a) `/etc/nginx/sites-enabled/abfindungsoptimizer.de` (or `/home/deploy/nginx-configs/sites/abfindungsoptimizer.de`) — does it have the `sub_filter '</body>' '<script src="https://admin.crelvo.dev/api/banners/embed.js" data-app="abfindungsoptimizer"></script></body>';` line? (b) Is the abfindungsoptimizer.de page closing tag exactly `</body>` (sub_filter is literal)? (c) Is `proxy_set_header Accept-Encoding ""` set so sub_filter can rewrite the response?

### Google Search Console verification: the deterministic-content trick

The standard GSC HTML file verification flow asks you to download a file like `google3961c4e5a481bc42.html` and upload it to your webroot. **The file content is fully deterministic from the filename:** it's literally one line, `google-site-verification: <filename>`. So you don't need to download anything from Google — just `echo "google-site-verification: google3961c4e5a481bc42.html" > /home/deploy/fiscanto.de/google3961c4e5a481bc42.html` and Google's verification check passes.

This makes the entire add-property → verify flow takes ~30 seconds with Playwright + SSH. The same trick works for other projects: just read the filename Google offers, build the file directly on the server, click Bestätigen.

### "Already indexed" vs "Indexing requested" distinction

When I ran URL Inspection on fiscanto.de, the response was "URL ist auf Google" / "Seite ist indexiert" — meaning Google had already discovered and indexed the homepage (likely via the `<a href="https://fiscanto.de">` link from crelvo.dev/projects, or via the cross-promo banners on other Crelvo sites that include affiliate-style backlinks, or via direct organic discovery). My "Indexierung beantragen" click was a **recrawl prompt** for the latest version, not a fresh index request. The sitemap submission additionally tells Google about /selfcheck and /anwalt, which were not in the existing index. Effective time-to-recrawl is hours-to-days, not instant.

If a future site needs to be indexed and is NOT yet known to Google, the same flow works — but the inspection page will show "URL ist nicht auf Google" instead, and the indexing button means "discover this URL for the first time."

### The "verify 10000%" verification stack

The user's "verify 10000%" command got a 8-layer response. The layers, from cheap to expensive:

1. **curl HTML grep** for keywords ("Fiscanto", "fiscanto.de", "BMF konforme") — cheapest, confirms HTML body contains expected strings.
2. **grep -o pattern count** ("group relative rounded-2xl") — confirms element count went up.
3. **HTTP status** for fiscanto.de + GSC verification file — confirms 200, not 404.
4. **Sitemap content** via curl — confirms sitemap.xml is well-formed and contains expected URLs.
5. **robots.txt** — confirms indexing is not disallowed.
6. **Playwright DOM query** — confirms `<a>` element has correct href, target, rel, h3 text, span text, p text, position-from-end. This catches bugs that text-grep can't (wrong attribute, wrong nesting).
7. **Playwright JPEG screenshot** of just the Fiscanto card — confirms visual rendering: teal gradient visible, badge "Tax Brand" visible, no text overflow, no broken layout.
8. **git status** + **git log** + **git push state** for both repos — confirms work is committed and pushed.

Each layer catches different bugs. Stack them when the user asks for high confidence.

## Known Issues & Risks

- **Awin sales for the lohncheck smartsteuer click are unknown.** Impact: low (1 click is statistically meaningless even if it converted). Mitigation: user logs into Awin publisher dashboard and checks the smartsteuer (advertiser ID 15043) program report.

- **abfindungsoptimizer smartsteuer banner has 0 views** despite 5+ weeks of "active" status. Impact: medium (we're losing a tax-adjacent affiliate placement on what should be a high-fit site for "Abfindung Steueroptimierung"). Likely cause: embed.js injection not firing (missing nginx sub_filter or wrong placement of closing `</body>` tag). Mitigation: investigate next session, ~15 minutes.

- **Session 21's queue is doubly-stale.** Session 22 didn't touch it; session 23 didn't touch it. The Marketing Brain has been running 4-hour cron cycles autonomously for ~14 days now without anyone validating that file 17 (the portfolio-and-public-ai KB file from `3881665`) is being grounded into Haiku briefs. Could be working perfectly, could be silently degrading. Session 21's HANDOVER.md priority #2 SQL query is still the way to find out.

- **fiscanto.de subpages /impressum.html and /datenschutz.html are explicitly Disallowed in robots.txt** — confirmed via curl. This is intentional (they shouldn't appear in search results), but it does mean the sitemap doesn't reference them either. Sitemap only lists /, /selfcheck, /anwalt.

- **3 untracked files in appManager** (`.mcp.json`, `KNOWLEDGEBASE.md`, `PLAYWRIGHT-MCP-GUIDE.md`) — pre-existed this session, called out in session 22 too. Likely should be either committed or `.gitignore`d. Not session-23 work.

- **HANDOVER.md staleness pattern.** Sessions 21 → 22 → 23 each replaced the prior handover without reading the gap between. The 7 fiscanto.de commits from 2026-04-26 to 2026-05-04 (the Selfcheck PDF export, the impressum updates, the /anwalt landing) have no entry in any handover. If the next session needs to understand what happened during that gap, they'll need to read the git log.

- **Session 22's itch.io 403 carryover.** Both Commuter Chaos and Tabletop Siege still return 403 to public visitors. crelvo.dev/projects has dead links to them. Same status as session 22.

## What Worked Well

- **Querying production data.db via node + better-sqlite3 in the running container.** Bypasses the missing `sqlite3` binary and uses the already-loaded better-sqlite3 module. One SSH call, one ad-hoc query, all the affiliate stats in 5 seconds.

- **GSC HTML file verification via deterministic content + SSH.** The "download file from Google then upload to your webroot" flow becomes "echo expected content into webroot" — total time ~5 seconds.

- **8-layer verification when user asks for high confidence.** Curl + grep + HTTP status + sitemap + robots + DOM query + screenshot + git push state. Each layer is cheap; together they catch every class of bug.

- **Loading Playwright MCP tools mid-session via ToolSearch.** Tools are deferred by default. ToolSearch with `select:<name1>,<name2>,...` loads multiple at once. Don't load tools until you need them — keeps the prompt schema small.

- **Reusing session 22's portfolio-card pattern.** Append to array, pick a non-clashing gradient, write description matching site's tone. ~3 minutes total per addition.

- **Confirming the user's intent inference inline** ("Proceeding with assumption: 'the new website' = fiscanto.de. If that's wrong, stop me.") instead of asking. The user-mapping was unambiguous from the commit log; asking would have wasted time.

## What Didn't Work (Traps to Avoid)

- **Initial SQL query targeting /app/data.db inside the container.** The container has TWO data.db paths and the `/app/` one is empty. **Always use `/home/deploy/marketing/data.db` for production queries.**

- **Trying `sqlite3 /app/data.db ...` directly in the container.** The `sqlite3` binary is not installed. Use node + better-sqlite3.

- **Direct navigation to `/search-console/inspect?...` URL.** Returned 404. The correct flow is to land on the property overview page (`?resource_id=...`), then use the search box at the top. Direct inspect URLs require an `id` parameter that's regenerated each session.

- **Using Playwright `browser_take_screenshot` with `target` selector for an element that doesn't have an ID.** First attempt failed with "does not match any elements." Workaround: assign an ID via `browser_evaluate`, then screenshot by `#that-id`. Works reliably.

- **Trusting the session 22 HANDOVER.md's claim of "6 unpushed commits."** That was true on 2026-04-26 but is no longer true today. Always run `git log origin/master..HEAD` to verify push state, don't trust handover claims.

## Next Steps (Priority Order)

1. **(USER ACTION, no code) Check Awin publisher dashboard for smartsteuer sales.** Login at awin.com → publisher → reports → filter by advertiser 15043 (smartsteuer DE). Time period: 2026-03-31 to today. The 1 click from lohncheck is the only data point on our side; whether it converted is only visible there. Estimated effort: 5 minutes.

2. **(USER ACTION, no code) Toggle Commuter Chaos + Tabletop Siege to Public on itch.io.** Carryover from session 22. Both return 403 to crelvo.dev/projects visitors. Owner action only. Verify with `curl -sI -A "Mozilla/5.0 ..." https://crelvo.itch.io/commuter-chaos` after — should return 200 instead of 403.

3. **Investigate abfindungsoptimizer banner injection.** 0 views in 5+ weeks despite "active" placement. Check `/home/deploy/nginx-configs/sites/abfindungsoptimizer.de` for the sub_filter line. Compare with `/home/deploy/nginx-configs/sites/lohnpruefung` (working — 63 views). Fix the diff. Estimated effort: 15 minutes. After fix, confirm via incognito visit + `SELECT views FROM banner_placements WHERE id=59` increment.

4. **Watch Google indexing for fiscanto.de subpages over the next 24-48h.** The sitemap was submitted today; /selfcheck and /anwalt should appear in `site:fiscanto.de` results within a few days. If after 7 days /selfcheck or /anwalt are still not indexed, run URL Inspection on each subpage individually and request indexing explicitly. Subpage indexing is slower than homepage.

5. **Build Public Brain Play 1: `brain.dockfolio.dev` live feed.** Long-running carryover from session 21 — full implementation plan in session 21's HANDOVER.md "Next Steps" #1 (9-step recipe). Estimated 60-90 minutes. KB file 17 was written ~15 days ago and the Marketing Brain has been cycling without the public-feed infrastructure existing — proposals are accumulating unactionable.

6. **Run the file-17 grounding query from session 21 priority #2.** SQL one-liner via SSH + docker exec + better-sqlite3. Threshold: file 17 should hit ≥50% of briefs. If under 30%, the file's content voice needs rewriting. ~14 days of cron data is now available for the analysis.

7. **(Optional) Hyphen sweep of pre-existing crelvo.dev project descriptions.** All ~20 pre-session-22 entries violate the no-dashes rule. ~5 minutes of `rg "[a-z]-[a-z]"` + manual rewrites.

8. **Carryover from sessions 21+22:** route ordering test, Orb source repo update with python3 healthcheck, ~95 brain actions triage. Same priority and detail as session 21's HANDOVER.md.

## Rollback Plan

Two repos got changes this session. Each is independently revertable.

- **slebständig commit `1b86711` (Fiscanto portfolio entry):**
  - Surgical revert: `git -C "C:/Users/kreyh/Projekte/slebständig" revert 1b86711` then `npm run build && scp ./dist/. deploy@.../var/www/crelvo/`. Removes the Fiscanto card. Safe — no other code depends on this entry.
  - Pre-session safe state on slebständig: `dba9368 Remove em and en dashes from player-facing copy`.

- **GSC verification file on VM (`/home/deploy/fiscanto.de/google3961c4e5a481bc42.html`):**
  - Removal: `ssh deploy@... rm /home/deploy/fiscanto.de/google3961c4e5a481bc42.html`. Consequence: Google will un-verify the property after the next verification check (~24h) and remove ownership. Sitemap stays submitted but cannot be re-managed without re-verification. **Don't remove this file unless you intend to delete the GSC property.**

- **GSC property `https://fiscanto.de`:**
  - Removal: GSC UI → Property settings → Remove property. Or just delete the verification file (above) and let Google auto-unverify.

- **appManager:** Only this HANDOVER.md changes. Safe state is `788cc52 Selfcheck Iteration 3: PDF Export Feature`.

- **No infrastructure changes this session.** No nginx configs, no DNS, no certificates, no databases modified beyond reads. Pure portfolio addition + GSC setup.

## Files Changed This Session

Across two repos plus VM:

- **`Projekte/slebständig/src/components/Projects.astro`** — +9 lines. New entry appended to `projects` array: Fiscanto (Tax Brand badge, BMF compliant crypto tax description, teal/cyan gradient). Committed as `1b86711` on `konradreyhe/crelvo` `master`, pushed.

- **`/var/www/crelvo/` on VM** — Refreshed full Astro `dist/` via scp. Now serves 24 portfolio cards.

- **`/home/deploy/fiscanto.de/google3961c4e5a481bc42.html` on VM** — New file, 1 line: `google-site-verification: google3961c4e5a481bc42.html`. Required by Google to maintain GSC ownership.

- **Google Search Console** — New URL-prefix property `https://fiscanto.de` added, verified, sitemap submitted. Not a file change but a state change worth documenting.

- **`Projekte/appManager/HANDOVER.md`** — Replaced session-22 handover with this session-23 handover. Will be committed as part of the standard handover commit at session end (parent: `788cc52`).

## Open Questions

- **Did the 1 lohncheck click convert to a smartsteuer sale?** Only Awin knows. User-side action.

- **Why does abfindungsoptimizer have 0 banner views?** Embed.js injection seems broken. Investigate next session.

- **Should the 7 fiscanto.de commits between sessions 22 and 23 be retroactively documented somewhere?** Right now they're git-log-only. The next person reading session 23's handover may wonder why fiscanto.de exists. The git log explains it but the handover doesn't.

- **Is fiscanto.de's analytics tracking working?** I didn't verify Plausible/admin tracking is firing. The site has the proxy headers in nginx (`/js/script.js` + `/api/event`) presumably; worth confirming via `GET /api/marketing/analytics` after the indexing recrawl pushes some traffic.

- **Should `kryptoaudit.de` (the 301 alias) also be added as a separate GSC property?** Probably not — the redirect means Google consolidates signal into fiscanto.de. But if user wants to track inbound clicks to the kryptoaudit brand specifically, a separate property would help.

- **Will `/selfcheck` and `/anwalt` get indexed within a week?** Sitemap was submitted today. Worth checking next session.

- **Are the 3 untracked appManager files (`.mcp.json`, `KNOWLEDGEBASE.md`, `PLAYWRIGHT-MCP-GUIDE.md`) intentional?** They've been untracked since session 22 at least. Either commit or .gitignore.
