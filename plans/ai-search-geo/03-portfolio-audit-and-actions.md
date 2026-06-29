# 03 — Portfolio Audit & Action Plan

All data gathered live from the VM on **2026-06-29** (raw curl of each homepage + robots.txt + llms.txt, direct from the server). This is ground truth, not from config.yml (which is stale).

## A. Verified VM inventory (the 1000%-sure list)

Pulled from the actual nginx `server_name` directives + live HTTP probes. **Authoritative.**

**32 real content sites** (HTTP 200, serve content) — audited below.

**6 pure redirects** (correct 301s, no audit needed): `kryptoaudit.de`→fiscanto.de, `promoforge.de`→promoforge.app, `sacredlens.app`→sacredlens.de, `survivorai.de`→survivorai.app, `konradreyhe.de`→crelvo.dev, `konzept-reyhe.de`→konzeptreyhe.de.

**3 internal / auth-gated** (correctly NOT indexable, return 401/login): `admin.crelvo.dev`, `betpilot.crelvo.dev`, `demo.dockfolio.dev`.

**Live on the VM but NOT documented in CLAUDE.md** (flagged for doc update): `deepresearch.business`, `since1971.org`, `slingshot.crelvo.dev`, `grimhollow.crelvo.dev`, `adhdgame.crelvo.dev`, `theforgottensystem.org`, `app.patternmusic.art`, `studio.patternmusic.art`, `sacredlens.app`, `konzept-reyhe.de`.

## B. AI-crawler access (the GEO precondition)
- **No site blocks AI crawlers.** No own-goals. Good.
- **2 sites explicitly welcome every AI engine** (`abschlusscheck.de`, `lohnpruefung.de`) — gold-standard robots.txt; copy them.
- **15 of 32 ship `llms.txt`**, 14 don't. Per file 01, this is low-priority (llms.txt has ~zero proven AI-search impact); don't spend effort backfilling it except for dev/docs sites.

## C. Scorecard (32 sites)

Signals: Title, Meta description, H1 count (want exactly 1), Canonical, Open Graph, JSON-LD types, `lang`, robots-meta. Grade reflects AI-readiness + classic SEO health.

| Site | Grade | JSON-LD | Key issues |
|------|:----:|---------|-----------|
| **lohnpruefung.de** | A+ | FAQ, WebApplication, Organization, WebSite | Gold standard. AI-welcome robots + llms.txt + multi-sitemap. Template for the rest. |
| **bewerbungsfotos-ai.de** | A | FAQ, Product, HowTo, Offer, Organization, WebSite, Brand | Excellent. Only gap: no Bing verification (lever 1). |
| **abschlusscheck.de** | A | FAQ, SoftwareApplication, AggregateOffer, Q&A | Exemplary AI-welcome robots. Add visible h1 check. |
| **theforgottensystem.org** | A | Organization, WebSite | Full robots-meta (max-image-preview:large). Add Article schema to posts. |
| **dreiraum.studio** | A- | FAQ, ProfessionalService, Offer, OfferCatalog, PostalAddress | Strong. Verify Three.js homepage exposes indexable text. |
| **bannerforge.app** | A- | ContactPoint, Offer, Organization, WebApplication | Solid. No llms.txt (low priority). |
| **theadhdmind.org** | A- | WebSite, SearchAction | Add Article/BlogPosting schema + dateModified to posts. |
| **thecreativeprogrammer.dev** | A- | WebSite, SearchAction | Same as above. Strong content base for Perplexity. |
| **thedesigninference.org** | A- | Article, Person, WebSite | Good. Push freshness + stats density. |
| **since1971.org** | A- | Organization, WebSite | Data-heavy topic = ideal for GEO; add tables + Article schema. |
| **codewithrigor.com** | B+ | Organization, WebSite | Generic title ("Code With Rigor"); sitemap.xml 404 (uses index). Add FAQ. |
| **grimhollow.crelvo.dev** | B+ | VideoGame, Offer | Great schema. Missing canonical. |
| **crelvo.dev** | B | NONE | Agency site with no Organization schema + no `sameAs`. Add it (entity-building). |
| **best-age.de** | B- | WebSite only | HTML entities leaking into title/desc; thin schema. Add tool-specific schema. |
| **agorahoch3.org** | B- | NONE | Generic "Home \| agorahoch3" title; no schema. |
| **fiscanto.de** | B- | NONE | No schema; OG missing image. Finance topic needs FAQ + Organization. |
| **abfindungsoptimizer.de** | B- | Offer, Organization, WebApplication | SPA, **h1:0**; umlauts written ae/ue. Verify prerendered content. |
| **schenkungsplaner.eu** | B- | Offer, Organization, WebApplication | SPA, **h1:0**. Same as above. |
| **survivorai.app** | C+ | NONE | No schema; OG missing image/locale. Add SoftwareApplication. |
| **orbedge.de** | C+ | NONE | No canonical, no schema. Trading EA = add Product/FAQ. |
| **promoforge.app** | C | NONE | **h1:0**, no schema on a flagship SaaS. High-value fix. |
| **dockfolio.dev** | C | NONE | **3x h1**, no canonical, no SoftwareApplication schema. |
| **oldworldlogos.com** | D | NONE | **16-language site with no `lang` attr and no hreflang** + h1:0. Big i18n SEO miss. |
| **patternmusic.art** | D | NONE | robots.txt + sitemap 404; no canonical/schema. Add CreativeWork/MusicAlbum. |
| **app.patternmusic.art** | D | NONE | robots.txt + sitemap 404; thin meta. |
| **sacredlens.de** | D | FAQ, SoftwareApplication, Organization | **BUG: empty `<title>` + literal `meta.desc` placeholder as description.** Fix template now. |
| **adhdgame.crelvo.dev** | D | VideoGame, Offer | **Duplicate of grimhollow** (identical content) → duplicate-content risk. |
| **christistrue.org** | B+ | NONE (on /en/,/de/) | CORRECTED: homepage `/` noindex is INTENTIONAL (language-redirect root, canonical→/en/). Real pages `/en/` + `/de/` are `index,follow` ✓. Not a bug. Could add Article/Organization schema. Not in GSC yet. |
| **deepresearch.business** | F | NONE | **No robots.txt, no sitemap, no canonical, no OG, no schema.** Full baseline missing. |
| **studio.patternmusic.art** | F | NONE | **Raw "Streamlit" default page** — no title/meta/schema. Add meta or noindex. |
| **slingshot.crelvo.dev** | F | NONE | Bare placeholder ("Slingshot", no desc/OG/canonical). Build it out or noindex. |
| **orb.crelvo.dev** | N/A | NONE | Internal trading monitor; robots.txt 404. Should be **noindexed**, not public. |

## D. Prioritized action plan

### Tier 0 — Bugs costing visibility right now (this week)
1. ~~christistrue.org noindex~~ — VERIFIED NOT A BUG (intentional language-redirect root; /en/ and /de/ index fine).
2. **sacredlens.de** — fix empty `<title>` + `meta.desc` placeholder template bug.
3. **deepresearch.business** — add robots.txt, sitemap, canonical, OG, Organization+SoftwareApplication schema.
4. **studio.patternmusic.art** — add real meta or `noindex` (don't let a "Streamlit" page represent the brand).
5. **adhdgame.crelvo.dev vs grimhollow** — decide canonical; differentiate or 301/canonical-tag the duplicate.
6. **orb.crelvo.dev** — add `noindex` (internal tool leaking to the open web).

### Tier 1 — Portfolio-wide multiplier (this month)
7. **Bing Webmaster Tools + IndexNow for all 32 domains** (lever 1). Single highest ROI for AI visibility. Bulk-import from GSC.
8. **Set up AI-referral tracking** (lever 6) — add AI hostname detection to the dashboard's analytics ingestion + a Dockfolio "AI referrals" panel. Lets you *measure* everything below.

### Tier 2 — Structured data sweep (rolling)
9. Add correct JSON-LD to the 12 sites missing it entirely, copying patterns from lohnpruefung.de / bewerbungsfotos-ai.de / dreiraum.studio. Priority order by revenue/traffic: promoforge.app → fiscanto.de → survivorai.app → crelvo.dev → dockfolio.dev → orbedge.de → agorahoch3.org → oldworldlogos.com → patternmusic.art.
10. Fix h1 issues (promoforge, abfindungsoptimizer, schenkungsplaner, oldworldlogos, dockfolio).
11. **oldworldlogos.com i18n**: add `lang` + `hreflang` for all 16 languages (currently invisible as a multilingual site).

### Tier 3 — Content & entity (ongoing, compounding)
12. Definition-first openings + stats density + visible dates on all marketing/blog pages (lever 3). Biggest payoff on the content blogs.
13. Article/BlogPosting schema with `author`/`datePublished`/`dateModified` across all Astro blogs.
14. Off-site presence (lever 5): Reddit participation, third-party mentions, `sameAs` entity binding, directories.
15. Monthly AI Share-of-Voice prompt test across the 4 engines per flagship product.

## E. What still needs YOU (Google login)
The **authoritative** "what's indexed vs excluded, and *why* each page was rejected" lives in **Google Search Console** (Pages/Coverage report) and **Bing Webmaster Tools** — both require login. When you're ready, open Playwright and authenticate (or paste a GSC service-account key) and the audit can be extended with: exact excluded-page reasons ("crawled, not indexed" / "discovered, not indexed" / "duplicate, Google chose different canonical"), impressions/clicks per page, and the real Bing coverage gap. This is the empirical layer that confirms the structural findings above.
