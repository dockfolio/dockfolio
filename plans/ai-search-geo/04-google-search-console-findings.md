# 04 — Google Search Console Findings (empirical)

Pulled live from Google Search Console (account: kreyhe12@gmail.com) on **2026-06-29** via Playwright. This is the authoritative "indexed vs rejected, and why" layer that confirms or corrects the structural audit in file 03.

## A. The coverage gap (biggest finding)

GSC only has data for sites that are **registered AND verified** as properties. Two problems:

### Verified properties (16, have data)
abfindungsoptimizer.de, abschlusscheck.de, agorahoch3.org, bannerforge.app, best-age.de, bewerbungsfotos-ai.de, betpilot.crelvo.dev, crelvo.dev, dockfolio.dev, dreiraum.studio, fiscanto.de, lohnpruefung.de, oldworldlogos.com, promoforge.app, sacredlens.de, schenkungsplaner.eu, theadhdmind.org.

### Registered but NOT verified (no usable data — ownership not confirmed)
**codewithrigor.com**, **thecreativeprogrammer.dev** (both real content sites!), plus game subdomains creatureforge / diplomancy / grimhollow / huntingdragons / lufthafen / orb / urlgame / worldcontrol .crelvo.dev, and an unverified `sc-domain:abschlusscheck.de` duplicate. **Action:** re-verify codewithrigor.com and thecreativeprogrammer.dev — right now Google gives you zero performance/coverage data for them.

### Live sites with NO GSC property at all (Google flying blind)
**survivorai.app, orbedge.de, christistrue.org, thedesigninference.org, theforgottensystem.org, since1971.org, deepresearch.business, patternmusic.art, app.patternmusic.art, studio.patternmusic.art, slingshot.crelvo.dev, adhdgame.crelvo.dev.** None are registered. **Action:** add every one as a Domain property (one `sc-domain:` property per root domain covers all subdomains + http/https in a single shot). This is step zero before any indexing work — you can't manage what you can't see.

> Note: most properties are **URL-prefix** (`https://domain/`). Prefer **Domain properties** going forward — they aggregate www/non-www/http/https/subdomains and let you submit one verification per domain.

## B. Indexed vs not-indexed, per verified property

| Property | Indexed | Not indexed | Dominant rejection reason(s) |
|----------|:-------:|:-----------:|------------------------------|
| oldworldlogos.com | 122 | **208** | 90 redirect, 82 crawled-not-indexed, **24 duplicate (no hreflang)**, 10 404 |
| agorahoch3.org | 52 | 205 | 184 canonical-alternate (mostly benign), 16 redirect, 2 404, 3 crawled |
| theadhdmind.org | 45 | 116 | **104 crawled-not-indexed**, 11 canonical, 1 404 |
| promoforge.app | **2** | **77** | **49 discovered-not-indexed**, 23 crawled-not-indexed, 5 canonical |
| lohnpruefung.de | **1** | 65 | **63 crawled-not-indexed** (thin city pages) |
| abschlusscheck.de | 22 | 16 | 13 crawled-not-indexed, 2 canonical, 1 404 |
| bewerbungsfotos-ai.de | 5 | 18 | 11 crawled-not-indexed, **6× 404**, 1 noindex |
| crelvo.dev | 13 | 17 | 13 crawled-not-indexed, 4 redirect |
| sacredlens.de | 3 | 7 | 5 crawled-not-indexed, 2 canonical |
| bannerforge.app | 3 | 7 | 3 crawled, 2 robots-blocked, 2 duplicate (Google chose other canonical) |
| dreiraum.studio | 3 | 1 | 1 redirect |
| schenkungsplaner.eu | 1 | 3 | 3 crawled-not-indexed |
| dockfolio.dev | 1 | 3 | **2 duplicate (no canonical tag)**, 1 crawled |
| best-age.de | 1 | 1 | 1 noindex |
| abfindungsoptimizer.de | 1 | 2 | 1 canonical, 1 discovered |
| fiscanto.de | 1 | 0 | (only homepage; 2 discovered pending) |

## C. What the data confirms (audit ↔ GSC correlations)
- **dockfolio.dev** has no canonical tag (file 03) → GSC shows **"duplicate, no canonical"** rejects. Direct cause/effect.
- **oldworldlogos.com** has no `lang`/`hreflang` on a 16-language site → GSC shows **24 duplicates + 82 crawled-not-indexed**. The i18n gap is provably costing indexing.
- **promoforge.app** has no h1 + no JSON-LD → GSC shows only **2 indexed pages, 49 discovered-but-not-even-crawled**. Google has deprioritized it.
- **bewerbungsfotos-ai.de** → **6 live 404s** Google is trying to index (broken sitemap/internal links to fix).

## D. The single most important lesson (reframes the strategy)
**lohnpruefung.de has the best technical SEO + GEO scaffolding in the portfolio (schema, AI-welcome robots, llms.txt, multi-sitemap) and yet only 1 page is indexed** — 63 city pages were crawled and **rejected as thin/templated**. 

The dominant rejection reason across the whole portfolio is **"Crawled/Discovered – currently not indexed"** (promoforge 72, lohnpruefung 63, theadhdmind 104, oldworldlogos 82, abschlusscheck 13...). This is Google's polite way of saying *"I saw these pages and judged them not worth indexing."* It is a **content-value verdict, not a technical bug.**

**Implication:** schema and robots.txt get you eligible; they do not get you indexed. Indexing (and therefore AI-citation, since ChatGPT/Perplexity/Gemini retrieve from indexed content) requires pages that are **substantively unique and valuable**. For programmatic page sets (city pages, language variants, chapter splits) this means: consolidate thin pages, add genuinely page-specific content, or `noindex` the filler and concentrate authority on fewer strong pages.

## E. Revised priority (merges with file 03 Tier list)
1. **Register the 12 missing sites + re-verify codewithrigor.com & thecreativeprogrammer.dev** in GSC as Domain properties. (Visibility step zero.)
2. **Fix the confirmed technical causes:** dockfolio canonical, oldworldlogos hreflang, bewerbungsfotos 404s, promoforge h1+schema+internal-linking.
3. **Attack "crawled-not-indexed" as a content problem**, worst-first: promoforge (2 indexed!), lohnpruefung (1 indexed, thin cities), then theadhdmind/oldworldlogos. Consolidate or enrich; request indexing after.
4. **Then** do the Bing/IndexNow + GEO structural work from file 02 — it compounds only on pages Google actually indexes.

## F. Still to pull (when useful)
Bing Webmaster Tools coverage (the ChatGPT-relevant index) for the same domains; per-page "crawled-not-indexed" URL lists (GSC → click each reason → export) to target specific consolidations; and Performance/query data to see which pages already earn impressions.
