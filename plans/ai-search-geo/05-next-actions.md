# 05 — Next Actions (turnkey checklist)

State as of 2026-06-29 (session 27). Everything below is ready to execute; the hard analysis is done.

## DONE this session
- 5-file GEO/AI-search knowledgebase (landscape, playbook, audit, GSC findings, this).
- Verified VM inventory: 32 content sites, 6 redirects, 3 internal (all confirmed live).
- Full SEO signal extraction for all 32 sites (title/desc/h1/canonical/OG/JSON-LD/lang/robots).
- AI-crawler policy check: no site blocks AI crawlers; 2 explicitly welcome them; 15 ship llms.txt.
- GSC empirical pull: indexed-vs-rejected + reasons for all 16 verified properties.
- Corrected christistrue.org false alarm (intentional redirect-root noindex).
- **GSC verification completed for codewithrigor.com + thecreativeprogrammer.dev.**

## TODO ③ — Register missing sites in GSC (9 of 14 DONE this session)
Method (proven): per-account file `google3961c4e5a481bc42.html` (content: `google-site-verification: google3961c4e5a481bc42.html`). For STATIC sites: drop the file in the nginx `root`, then GSC → /welcome → URL-prefix `https://<domain>/` → Weiter → auto-verifies.

**✅ VERIFIED 2026-06-29 (12):** codewithrigor.com, thecreativeprogrammer.dev, thedesigninference.org, theforgottensystem.org, since1971.org, orbedge.de, patternmusic.art, christistrue.org, slingshot.crelvo.dev (static, file in webroot) + deepresearch.business, app.patternmusic.art, studio.patternmusic.art (proxied, nginx `location` block added to their configs + reloaded). Do NOT delete the webroot files or the nginx location blocks.

**⏳ REMAINING (2):**
- **survivorai.app** — nginx location was inserted but landed in the wrong server block in the shared `nginx-survivorai.conf` (it served the homepage at the token path, so GSC verify would fail). Fix: place the `location = /google3961c4e5a481bc42.html {...}` inside the `server { ... server_name survivorai.app; ... }` block specifically (not survivorai.de's), `nginx -t`, reload, then add the property in GSC.
- **adhdgame.crelvo.dev** — deliberately skipped (duplicate of grimhollow, low value). Its config is shared with grimhollow; add the location to the adhdgame server block if you want it tracked.

**After verifying each:** GSC → Sitemaps → submit the sitemap; for the worst indexers (promoforge, lohnpruefung) use URL Inspection → "Request indexing" on key pages. Sitemap submission for the 9 just-verified is still pending.

## TODO ④ — Bing Webmaster Tools (STARTED 2026-06-29; importer flaky)
Highest ROI for AI visibility (ChatGPT pulls ~87% of citations from Bing).
- ✅ Bing Webmaster account created (signed in with Google SSO = same kreyhe12@gmail.com → enables GSC import).
- ✅ Bing↔GSC OAuth connection authorized (view-only).
- ⚠️ **GSC import is flaky right now:** first pass found all 26 sites but only **abfindungsoptimizer.de** actually imported; retries alternated between "import failed / fetch error" and "we didn't find any sites from GSC". This is a known Bing-side inconsistency, not a config problem. **Action: retry the import in a few hours** — bing.com/webmasters → site dropdown → Import from GSC → Continue (connection persists, it's idempotent). It usually completes on a later attempt. Alternatively add sites manually (URL + verify; the same per-account verification works, or Bing accepts the existing GSC verification).
- ⏳ **Then enable IndexNow** (Bing left-nav → IndexNow → generate API key) and wire it so new/updated pages ping Bing instantly. This is the compounding win for AI freshness.

## TODO ② — Confirmed code fixes (each in its own repo; confirm before prod deploy)
| Fix | Repo (local) | What | Why (GSC-confirmed) |
|-----|--------------|------|---------------------|
| sacredlens.de empty `<title>` + `meta.desc` placeholder | (locate sacredlens repo) | fix head template | live HTML bug, hurts all engines |
| dockfolio.dev missing canonical + 3×h1 | (dockfolio marketing site) | add canonical, single h1 | GSC: "duplicate, no canonical" |
| oldworldlogos.com no lang/hreflang | LOGOS | add lang + hreflang (16 langs) | GSC: 24 duplicates + 82 crawl-rejected |
| bewerbungsfotos-ai.de 6×404 | headshot-ai-pro | fix broken sitemap/links | GSC: 6 live 404s |
| promoforge.app no h1 + no JSON-LD + blog uncrawled | promoforge | add h1 + SoftwareApplication/FAQ schema + internal links to /blog; request indexing | GSC: only 2 indexed, 49 discovered-not-crawled |
| studio.patternmusic.art raw "Streamlit" page | (streamlit app) | add meta or noindex | no SEO at all |
| adhdgame.crelvo.dev duplicate of grimhollow | (game repo) | canonicalize or differentiate | duplicate content |

## TODO ① content strategy (the real unlock, from file 04 §D)
The dominant rejection portfolio-wide is "crawled/discovered – not indexed" = Google judging pages low-value. Schema does not fix this. For thin programmatic page sets (lohnpruefung city pages, oldworldlogos language variants, blog chapter splits): consolidate or enrich to genuine uniqueness, or noindex the filler. This is what unlocks both Google indexing AND AI citation.

## Note on the verification files
`google3961c4e5a481bc42.html` now lives in codewithrigor + creativeprogrammer webroots. Google requires they STAY for verification to persist. Do not delete.
