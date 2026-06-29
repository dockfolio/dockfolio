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

## TODO ③ — Register the 12 missing sites in GSC (method proven, ~2 min each)
Use the per-account file `google3961c4e5a481bc42.html` (content: `google-site-verification: google3961c4e5a481bc42.html`).
Flow per site: GSC property selector → "Property hinzufügen" → URL-prefix `https://<domain>/` → choose HTML-file method → drop the file in the site's nginx `root` via SSH → "Bestätigen". For proxied apps add `location = /google3961c4e5a481bc42.html { return 200 'google-site-verification: google3961c4e5a481bc42.html'; }` to the nginx site config + reload.

Priority order (content value):
1. thedesigninference.org (static) — strong Article-schema content
2. theforgottensystem.org (static) — research content, good technical SEO
3. since1971.org (static) — data-heavy, ideal for GEO
4. survivorai.app (app) — needs nginx location method
5. orbedge.de, patternmusic.art, app./studio.patternmusic.art, deepresearch.business (Next.js → nginx method), christistrue.org, slingshot/adhdgame.crelvo.dev

After verifying each: submit its sitemap (GSC → Sitemaps), and for the worst indexers use URL Inspection → "Request indexing" on key pages.

## TODO ④ — Bing Webmaster Tools (BLOCKED: needs your Microsoft login)
Highest ROI for AI visibility (ChatGPT pulls ~87% of citations from Bing). Once logged in at bing.com/webmasters, "Import from GSC" pulls all verified properties in one click. Then enable IndexNow.

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
