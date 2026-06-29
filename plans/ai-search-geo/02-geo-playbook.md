# 02 — The GEO Playbook (how to actually get cited)

Ranked by leverage. Do them top-down. Each lever says *why it works*, *what to do*, and *who in the portfolio needs it most* (see file 03 for the full scorecard).

## Lever 1 — Get indexed in Bing + wire IndexNow  ★ highest ROI, portfolio-wide
**Why:** ChatGPT and Copilot read **Bing's index**, not Google's. ~87% of ChatGPT citations come from Bing's top organic results. No Bing index = no ChatGPT visibility, full stop. Most sites here are tuned for Google and have probably never been submitted to Bing.
**Do:**
1. Create/verify every domain in **Bing Webmaster Tools** (bulk import from Google Search Console is one click).
2. Submit each sitemap to Bing.
3. Implement **IndexNow** (Bing + Yandex + others honor it): on publish/update, ping the IndexNow API so new content is crawled in hours not weeks. Cloudflare can auto-enable it; or a tiny server hook.
4. Confirm coverage with `site:domain.com` on Bing.
**Who:** ALL 32 sites. This is the one action that moves the entire portfolio at once.

## Lever 2 — Structured data (schema.org JSON-LD)  ★ high, uneven across portfolio
**Why:** JSON-LD is machine-readable fact extraction. It was a top-5 feature correlated with higher LLM citation rates. FAQPage labels Q&A pairs, Product/SoftwareApplication declares what you sell, Organization/Person builds the entity the engine reasons about, Article gives author+date.
**Do:** Every page should declare the right type:
- SaaS/tools → `SoftwareApplication` or `WebApplication` + `Offer`/`AggregateOffer` + `FAQPage`.
- Content/blog → `Article`/`BlogPosting` with `author`, `datePublished`, `dateModified`.
- Brand/agency → `Organization` (+ `sameAs` links to socials/Wikipedia/LinkedIn — this binds your entity in the knowledge graph).
- Games → `VideoGame` + `Offer` (grimhollow already nails this).
**Who (missing JSON-LD entirely):** promoforge.app, fiscanto.de, deepresearch.business, oldworldlogos.com, survivorai.app, crelvo.dev, dockfolio.dev, patternmusic.art, agorahoch3.org, orbedge.de, christistrue.org, slingshot. **Best-in-class to copy:** bewerbungsfotos-ai.de, lohnpruefung.de, dreiraum.studio.

## Lever 3 — Write the way LLMs extract  ★ high, cheap, content-level
**Why:** When an engine retrieves your page, the **first 150-200 tokens carry disproportionate weight**, and sections with **3+ statistics per 300 words get ~2.1x more citations**. Definition-first openings get materially higher impression scores.
**Do (per important page):**
- Open with a **one-sentence definitional answer** to the page's core question ("X is a Y that does Z for W"). No throat-clearing hero copy first.
- Add a **TL;DR** / key-takeaways block near the top.
- Convert claims into **specific, dated, sourced statistics** and **data tables** (engines love quoting tables).
- Add **Q&A sections** with real questions buyers ask (these double as FAQPage schema).
- Show **author + published date + "updated 2026"** visibly — freshness is a citation signal (AI-surfaced URLs run ~26% fresher than classic).
**Who:** Every marketing/content page, but especially the blogs (theadhdmind, thecreativeprogrammer, codewithrigor, since1971, thedesigninference) where Q&A + stats + freshness directly win Perplexity/Overview citations.

## Lever 4 — Fix the crawl/index basics first  ★ blocking issues, do immediately
**Why:** None of the above matters if the page can't be indexed or has broken meta. These are bugs, not optimizations.
**Do (specific live bugs found 2026-06-29):**
- ~~christistrue.org noindex~~ — VERIFIED a false alarm: the `/` noindex is intentional (language-redirect root, canonical→/en/); the real `/en/` and `/de/` pages are `index,follow`. No action needed. (Lesson: audit content pages, not just `/`.)
- **sacredlens.de** ships an **empty `<title>`** and a literal `meta.desc` template placeholder as its description → catastrophic for every engine. Fix the template.
- **deepresearch.business**: no robots.txt, no sitemap, no canonical, no OG, no JSON-LD → add the full SEO baseline.
- **studio.patternmusic.art** serves the raw **"Streamlit"** default page (no title/meta) → either add proper meta or `noindex` it.
- **adhdgame.crelvo.dev** serves **identical content to grimhollow.crelvo.dev** (duplicate) → canonicalize or differentiate.
- **patternmusic.art / app.patternmusic.art**: robots.txt + sitemap both 404.
- Missing `<h1>`: promoforge.app, abfindungsoptimizer.de, schenkungsplaner.eu, oldworldlogos.com, dockfolio.dev(has 3, should be 1).
- Missing canonical: dockfolio.dev, patternmusic.art, orbedge.de, deepresearch.business.

## Lever 5 — Off-site entity & community presence  ★ high, slow, compounding
**Why:** Engines trust corroboration. **Wikipedia ≈ 26% of all AI citations**; **Reddit** is cited by Perplexity 6.6-46.5% of the time. Being mentioned on trusted third-party sites is often what gets *you* cited, even if the answer links elsewhere.
**Do:**
- Earn mentions on 5-10 trusted industry publications per product (founder bylines, guest posts, expert quotes — relationship-driven, not blast PR).
- Maintain genuine, non-spammy **Reddit** presence in the relevant subreddits (the marketing-mcp already tracks subreddit targets — repurpose for authentic participation, not link-dropping).
- Get the company/products into structured directories (G2, Product Hunt, relevant German Verzeichnisse) and, where genuinely notable, a Wikipedia/Wikidata entity.
- Add `sameAs` schema linking each brand to its socials so engines fuse the identity.

## Lever 6 — Measure AI visibility & referral traffic  ★ do early so you can see lever 1-5 working
**Why:** You can't improve what you can't see, and GA4 hides most AI traffic by default (ChatGPT apps send no referrer → shows as "Direct"; GA4's native "AI Assistant" channel still misses 35-70% of AI sessions).
**Do:**
- In GA4, build a custom channel group "AI Traffic" with a regex over referrer hostnames: `chatgpt.com, chat.openai.com, openai.com, perplexity.ai, claude.ai, gemini.google.com, copilot.microsoft.com, bing.com, deepseek.com, grok.com, meta.ai, you.com`.
- **Better for this portfolio:** the visit-watcher / nginx visit-logs already capture `Referer`. Add the same hostname set to the dashboard's own analytics ingestion so AI referrals are tracked first-party (no GA4 blind spot, no Plausible gap). This is a natural Dockfolio feature: an "AI referrals" panel.
- For citation tracking (are we *mentioned* even without a click), run a monthly **AI Share of Voice** test: 50-100 representative buyer prompts across ChatGPT/Perplexity/Gemini/Claude, count brand mentions vs competitors. Tools like Peec.ai, Scrunch.ai, Otterly exist, but a scripted prompt-set against the APIs is cheap and on-brand for this stack.

## The 3-layer mental model (tape this to the wall)
1. **Google SEO** — still ~88% of clicks. The foundation. Keep doing it.
2. **Bing SEO** — the key to ChatGPT + Copilot. Currently the portfolio's biggest blind spot.
3. **GEO** — structure (schema + definition-first + stats + freshness) so any LLM can chunk and cite you, + off-site entity presence so it trusts you.

Do all three. They reinforce each other: a well-structured, Bing-indexed, organically-ranking, Reddit-discussed page is the page that wins the citation.
