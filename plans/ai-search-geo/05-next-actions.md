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

**✅ VERIFIED 2026-06-29 (9):** codewithrigor.com, thecreativeprogrammer.dev, thedesigninference.org, theforgottensystem.org, since1971.org, orbedge.de, patternmusic.art, christistrue.org, slingshot.crelvo.dev. (Files already placed in their webroots — do NOT delete.)

**⏳ REMAINING (5, reverse-proxied — need nginx method):** deepresearch.business (Next.js), survivorai.app, app.patternmusic.art, studio.patternmusic.art (Streamlit), adhdgame.crelvo.dev. For each, add to the 443 server block in `/home/deploy/nginx-configs/sites/<file>`:
```nginx
location = /google3961c4e5a481bc42.html { default_type text/plain; return 200 'google-site-verification: google3961c4e5a481bc42.html'; }
```
then `sudo nginx -c /home/deploy/nginx-configs/nginx.conf -t && ... -s reload`, then add the URL-prefix property in GSC as above. (Deferred here because a bad nginx reload affects all 40+ sites; do it deliberately, gated on `nginx -t`.)

**After verifying each:** GSC → Sitemaps → submit the sitemap; for the worst indexers (promoforge, lohnpruefung) use URL Inspection → "Request indexing" on key pages. Sitemap submission for the 9 just-verified is still pending.

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
