# Session Handover

**Date:** 2026-06-29 (Session 27)
**Topic:** AI search / GEO (Generative Engine Optimization) + portfolio-wide indexing audit and fixes.
**User intent (verbatim spirit):** "Make 1000% sure which websites are on my VM, then check if ALL are indexed intelligently with structured text so they're found in any search engine. Understand AI search (people research via ChatGPT/Perplexity now, not just Google) 10000%, build a knowledgebase, see all indexing 'rejects'." Then repeatedly: "do all", "u decide". User helps with logins (Google, Bing) when asked.

> Session 26's work (Telegram/Stripe sale notifications + visit-watcher watchdog) was verified complete and live at the start of this session. Its handover is in git history. This file supersedes it.

---

## 0. READ THESE FIRST (the real knowledgebase)
All under `plans/ai-search-geo/` (gitignored dir, but these files are force-added/tracked — use `git add -f` for new ones):
- `README.md` — overview + one-paragraph summary
- `01-ai-search-landscape.md` — 2026 research: how ChatGPT/Perplexity/Gemini/AIOverviews retrieve & cite, real numbers, the llms.txt myth
- `02-geo-playbook.md` — the 6 ranked levers to get cited by AI
- `03-portfolio-audit-and-actions.md` — graded SEO scorecard for all 32 content sites
- `04-google-search-console-findings.md` — REAL indexed-vs-rejected data per property (the "rejects")
- `05-next-actions.md` — turnkey checklist (THE to-do list; keep it updated)

This HANDOVER is the orientation; `05-next-actions.md` is the live task list.

---

## 1. The authoritative website inventory (verified live from nginx, NOT config.yml which is stale)
**32 real content sites** (HTTP 200) + **6 pure redirects** (correct 301s) + **3 internal/auth-gated** (admin, betpilot, demo — correctly not indexable).
To regenerate the live list: `ssh deploy@91.99.104.132 'grep -rhoE "server_name\s+[^;]+;" /home/deploy/nginx-configs/sites/'`.
Domains live on the VM but missing from `CLAUDE.md`: deepresearch.business, since1971.org, theforgottensystem.org, slingshot/grimhollow/adhdgame.crelvo.dev, app/studio.patternmusic.art, sacredlens.app, konzept-reyhe.de. (Consider updating CLAUDE.md's app table.)

---

## 2. WHAT IS DONE (verified, committed, pushed)
1. **6-file knowledgebase** (above).
2. **Google Search Console — 12 properties verified this session** (whole 26-property portfolio now has verified ownership + collects data):
   codewithrigor.com, thecreativeprogrammer.dev, thedesigninference.org, theforgottensystem.org, since1971.org, orbedge.de, patternmusic.art, christistrue.org, slingshot.crelvo.dev, deepresearch.business, app.patternmusic.art, studio.patternmusic.art.
3. **dockfolio.dev code fix — LIVE & verified:** added canonical + SoftwareApplication JSON-LD, fixed 3→1 h1. Source: `dockfolio-landing/index.html` (in THIS repo). Deployed via scp to `/home/deploy/dockfolio-landing/`.
4. **Bing Webmaster Tools** — account created (Google SSO, kreyhe12@gmail.com), GSC OAuth connection authorized, 1 site imported (abfindungsoptimizer.de).
5. **nginx** — added GSC-verification `location` blocks to 3 proxied-app configs (deepresearch.business, app.patternmusic.art, studio.patternmusic.art), validated with `nginx -t`, reloaded. All sites healthy, zero downtime.

Git is clean, all pushed to `origin/master`. All sites return 200.

---

## 3. KEY METHODS & CREDENTIALS (so you don't rediscover them)

### SSH / VM
- `ssh deploy@91.99.104.132` (key in ssh-agent, no password). **fail2ban is active — NEVER retry failed auth.** One connection per action. Use `-o BatchMode=yes`.
- Static-site webroots: mostly `/home/deploy/<domain>/` (some `/home/deploy/sites/<name>`, creativeprogrammer is `/opt/creativeprogrammer`). Find with: `grep -hE '^[^#]*root ' /home/deploy/nginx-configs/sites/<cfgfile>`.
- nginx configs: `/home/deploy/nginx-configs/sites/<name>` (filenames don't always equal domain; find with `grep -rlE "server_name[^;]*<domain>" /home/deploy/nginx-configs/sites/`).
- Reload: `sudo nginx -c /home/deploy/nginx-configs/nginx.conf -t && sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload` (certbot/nginx reload are passwordless sudo; arbitrary sudo is NOT).
- **No `rsync` on this Windows Git-Bash shell** — use `scp` for deploys.

### Google Search Console (Playwright browser, logged in as kreyhe12@gmail.com)
- **The HTML-file verification token is per-ACCOUNT, not per-site:** the single file `google3961c4e5a481bc42.html` (content exactly: `google-site-verification: google3961c4e5a481bc42.html`) verifies ANY property for this account. Files are already placed in the verified sites' webroots — DO NOT DELETE.
- **To register a new site:** open `https://search.google.com/search-console/welcome` → type URL into the URL-Präfix textbox → click its "Weiter" → if the token file is reachable it AUTO-verifies ("Inhaberschaft automatisch bestätigt"). So: place the file first, then register.
- **To read indexing data:** `https://search.google.com/search-console/index?resource_id=https%3A%2F%2F<domain>%2F`. Extract compactly via `browser_evaluate` reading `[role=main]` innerText (DON'T full-snapshot — it's huge). Click a rejection reason row → drilldown page lists the exact rejected URLs.

### Bing Webmaster Tools
- Sign in at `bing.com/webmasters` with **Google SSO** (same kreyhe12@gmail.com → enables GSC import).
- Import: site dropdown / welcome → "Import from GSC" → Continue → Google OAuth (user may need to click Allow) → select all → Import. **The importer is FLAKY** (found 26, imported 1, then "0 found" on retries). Each retry needs a FRESH OAuth code (the code is single-use; reusing it = "could not fetch"). Retry the whole flow later; it's idempotent. Then enable **IndexNow** (left nav) for instant crawl pings.

### Deploy / git
- Commits: end with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Work directly on `master` (project convention), commit AND push after each unit.
- `plans/` is gitignored — new knowledgebase files need `git add -f`.

---

## 4. WHAT REMAINS — DO THIS (priority order)

### TASK A — promoforge.app code fix (HIGHEST VALUE; only 2 pages indexed)
Repo: `~/Projekte/promoforge` (React + Remotion + PostgreSQL + Redis, Docker SaaS, port 3000). **Heavy deploy — be careful, verify build.**
GSC data: 2 indexed, 77 not (49 "discovered, not indexed" = a full blog Google won't crawl; 23 crawled-not-indexed). Homepage has **0 h1 and no JSON-LD**.
Do: (1) add a single proper `<h1>` to the homepage hero; (2) add `SoftwareApplication` + `FAQPage` JSON-LD; (3) ensure indexed pages link internally to `/blog` and the `/für/<industry>` landing pages (they exist but Google won't crawl them due to low authority); (4) after deploy, in GSC use URL Inspection → "Request indexing" on `/blog` and 3-4 top posts. Verify homepage h1=1 + JSON-LD live before committing. Find deploy method in the promoforge repo (likely its own deploy.sh / docker compose — READ ITS HANDOVER/CLAUDE.md first).

### TASK B — Retry Bing GSC import + enable IndexNow
See §3 Bing. The connection is already authorized; just re-run the import flow (fresh OAuth) until all 26 land, then turn on IndexNow.

### TASK C — oldworldlogos.com hreflang (208 not indexed!)
Repo: `~/Projekte/LOGOS` (Next.js, 16 languages). GSC: 122 indexed, 208 not (24 duplicates + 82 crawl-rejected + 90 redirects). Root cause: **no `lang` attribute and no `hreflang`** on a 16-language site → Google treats language versions as duplicates. Add `<html lang>` per locale + reciprocal `hreflang` alternates (+ x-default) across all 16 languages. Also add `<h1>` (homepage has 0). Verify, deploy, commit.

### TASK D — bewerbungsfotos-ai.de 404s
Repo: `~/Projekte/headshot-ai-pro` (Next.js, bewerbungsfotos-ai.de). GSC: 6 live 404s Google is trying to index. Pull the exact URLs (GSC index report → "Nicht gefunden (404)" → drilldown), then either fix the broken links/pages or remove them from the sitemap. Verify, deploy, commit.

### TASK E — sacredlens.de empty title bug
The live homepage has an **empty `<title>`** and a literal `meta.desc` template placeholder as its description. Locate the source (no obvious `sacredlens` dir in `~/Projekte` — may be under another name or served from a VM webroot `/home/deploy/sacredlens*`; check `grep root .../sites/sacredlens`). Fix the head template so title + description render. Verify, deploy, commit.

### TASK F — finish 2 GSC registrations
- **survivorai.app**: an nginx `location = /google3961c4e5a481bc42.html {...}` was inserted into `nginx-survivorai.conf` but landed in the WRONG server block (it serves the homepage at that path, so verify fails). Move/add the location inside the `server { ... server_name survivorai.app; ...}` block specifically, `nginx -t`, reload, then register in GSC welcome flow.
- **adhdgame.crelvo.dev**: low-value duplicate of grimhollow (shares the `grimhollow` config). Optional. Add the location to its server block if wanted.

### TASK G — content depth (the real long-term unlock; strategy not a quick fix)
The dominant GSC rejection portfolio-wide is "crawled/discovered – currently not indexed" = Google judging pages low-value. **Schema/robots make pages eligible; only substantively unique, valuable pages get indexed (and thus AI-citable).** For thin programmatic page sets (lohnpruefung's 63 city pages → only 1 indexed; oldworldlogos language variants; blog chapter splits): consolidate or enrich to genuine uniqueness, or `noindex` the filler to concentrate authority. This is what actually moves both Google indexing and AI citation. See `04-...findings.md` §D.

---

## 5. KEY FINDINGS (the data, so you don't re-derive)
- **Bing is the biggest AI-visibility lever**: ChatGPT pulls ~87% of citations from Bing's index; the portfolio was Google-only. (Now half-fixed: Bing account + connection live, import pending.)
- **No site blocks AI crawlers** (good). 2 sites (abschlusscheck, lohnpruefung) explicitly welcome them and are the gold-standard schema templates to copy. 15 ship llms.txt (low priority — llms.txt is a proven dud for AI-search; don't backfill).
- **Flagships barely indexed**: promoforge 2 pages, lohnpruefung 1 page, bewerbungsfotos 5. oldworldlogos 122/208-rejected.
- **Verify before "fixing"**: christistrue.org's homepage `noindex` is INTENTIONAL (language-redirect root; /en/ and /de/ index fine). It was wrongly flagged then corrected. Apply the same caution: audit content pages, not just `/`.

---

## 6. ROLLBACK
- dockfolio.dev: `git revert <the dockfolio commit>`; re-`scp dockfolio-landing/index.html deploy@91.99.104.132:/home/deploy/dockfolio-landing/`.
- nginx location blocks: edit the 3 configs (deepresearch.business, app/studio.patternmusic.art), remove the `location = /google3961c4e5a481bc42.html` line, `nginx -t` + reload. (Harmless to leave — Google requires them to STAY for verification.)
- GSC verifications: harmless; to undo, remove the property in GSC + delete the webroot file.
- All knowledgebase/doc changes are pure additions on master.

---

## 7. GOTCHAS
- Don't full-`browser_snapshot` GSC index pages or `curl` full site HTML into context — both are huge and burn context fast. Use targeted `browser_evaluate` / `grep -o`.
- Bing importer flakiness (see §3). Don't reuse a spent OAuth code.
- When editing nginx via sed/awk: variables don't expand in sed `a\`; use `awk -v`. And check the REAL exit code of `nginx -t` (don't pipe it to `tail` in an `if`). Always back up configs first; restore on `-t` failure; never reload a failing config.
- `plans/` is gitignored → `git add -f` for new files there.
- Screenshot/context budget: this session did ~90 tool calls; do heavy multi-repo deploys one repo per fresh session.
