# 01 — The AI Search Landscape (2026)

Research compiled 2026-06-29 from live web sources. Figures are directional (every vendor measures differently) but the *shape* of the trend is consistent across sources.

## 1. Where the traffic actually is (the honest numbers)

The hype says "nobody googles anymore." The data says something more nuanced and more useful:

- **Google still sends ~87.6% of all search referral clicks** (May 2026). All AI engines *combined* send roughly **0.29%** of referral clicks today. So if you only chase AI and abandon classic SEO, you starve.
- **But AI search is the fastest-growing channel by far**: AI-referred traffic grew ~**527% year over year**, reportedly ~165x faster than organic. The base is small; the slope is steep.
- **The quality gap is the real story**: traffic arriving from ChatGPT/Perplexity converts at roughly **4x the rate of organic** (one Adobe study: 4.4x; ChatGPT referrals measured at ~14.2% conversion vs ~2.8% organic). These are high-intent users who already read a synthesized recommendation and clicked through to act.
- **Google AI Overviews are the sleeping giant**: they now appear on ~**60% of US queries** (up from ~25% in late 2025). When Google's full **AI Mode** is on, zero-click jumps to ~93% and click-through on the summarized pages drops ~61%. This is happening *inside Google*, to the pages that already rank. You can lose clicks even while ranking #1.

**Takeaway:** Don't abandon SEO. Layer AI visibility on top of it. The near-term ROI of AI is conversion quality and Overview citations, not raw volume — yet.

## 2. How each engine finds and cites sources

They are NOT the same system. A page cited by ChatGPT is often invisible to Perplexity: studies find only ~**11% of domains are cited by both**. Optimize per engine.

### ChatGPT (Search + browsing) — biggest user base (~883M MAU, ~2B queries/day)
- **Runs on Bing's index.** ~**87% of ChatGPT citations come from Bing's top organic results**; ChatGPT Search results overlap ~73% with Bing.
- **Practical law:** *if you are not indexed in Bing, you do not exist in ChatGPT* — regardless of Google rank. This is the single biggest lever for the portfolio (see playbook lever 1).
- Heavily cites **Wikipedia** (~8-27% of citations) and other high-authority entities.

### Perplexity — citation-obsessed, real-time
- Runs its own crawler (PerplexityBot) + live web search, strong preference for **fresh, recently updated** content.
- Cites **Reddit heavily** (6.6-46.5% of responses) — community discussion is a real ranking surface here.
- Most transparent about sources; being a clean, quotable, well-structured page pays off directly.

### Google Gemini / AI Overviews / AI Mode — draws on Google's index
- **AI Overviews elevate passages from pages that already have organic visibility**: ~76% of cited pages rank in Google's top 10. Strong classic SEO is the price of entry, though ~14% of cited pages don't rank organically at all (so structure can win you a citation without a top rank).
- **AI Mode uses "query fan-out"**: it silently fires many sub-queries, then synthesizes. It cites *different* URLs than AI Overviews ~86% of the time despite reaching the same conclusion — so coverage breadth matters.
- Favors **freshness**: AI-surfaced URLs are ~25.7% fresher than classic results.

### Claude (with web search) & Microsoft Copilot
- Claude is now a meaningful B2B referral source (~18.5% of measurable AI referrals in early 2026). Uses ClaudeBot / Claude-User / Claude-SearchBot crawlers.
- Copilot rides Bing too — so the Bing-indexing lever covers Copilot as well.

### Market share of AI referrals (early-mid 2026, B2B-weighted)
ChatGPT ~62%, Claude ~18%, Gemini ~11%, Perplexity ~7%. ChatGPT's share is *falling* (was ~89% eight months earlier) as the others grow — so a multi-engine strategy is correct, not ChatGPT-only.

## 3. The myths to ignore

### llms.txt is mostly a dud (for AI search visibility)
This matters because two portfolio sites already ship one and 15 of 32 have the file. The honest 2026 evidence:
- Adoption ~10% of domains; only ~0.3% of the top 1,000 sites use it. Google, Meta, Amazon don't.
- In a 90-day study of 500M+ AI bot visits, only **408 fetched llms.txt** — statistically zero. GPTBot, ClaudeBot, PerplexityBot, OAI-SearchBot, Google-Extended overwhelmingly **skip it and crawl HTML directly**.
- Google's Gary Illyes confirmed Google does **not** support it and has no plans to. No major LLM vendor has committed to it as a ranking signal.
- Statistical + ML analysis: **no measurable effect** on citation frequency.

**So:** llms.txt is *not* an SEO/GEO play. It IS a real **Business-to-Agent** play: IDE coding agents (Cursor, Windsurf, Claude Code, Copilot, Cline, Aider) DO fetch `/llms.txt` and `/llms-full.txt` when pointed at docs. Keep it where it costs nothing (it's already there), don't expect AI-search lift from it, and never prioritize it over Bing indexing or structured data. For a docs-heavy or developer-facing site (dockfolio.dev, code-with-rigor) it has genuine niche value.

### "Block the AI crawlers to protect content"
Blocking GPTBot/ClaudeBot etc. does **not** reliably keep you out of AI answers (engines still surface you via other paths) but **does** forfeit citation/attribution and referral clicks. For a portfolio that *wants* to be discovered, blocking is an own-goal. The portfolio correctly blocks none. (Note: this is the opposite tension from the visit-watcher bot filter in session 26 — there we filter AI crawlers out of *human-visitor notifications*, which is correct; we are NOT blocking them at robots.txt, which is also correct.)

## 4. Sources

- [2026 AI Search Traffic Report — Goodie](https://higoodie.com/blog/ai-search-traffic-report-2026/)
- [AI Search Market Share 2026 — Sedestral](https://sedestral.com/en/blog/ai-search-market-share-2026)
- [Search Engine Market Share 2026 (Google 87.6%) — TechnologyChecker](https://technologychecker.io/blog/search-engine-market-share)
- [AI Search Statistics 2025-2026 — Omnibound](https://www.omnibound.ai/blog/ai-search-statistics)
- [GEO 2026 Guide — LLMrefs](https://llmrefs.com/generative-engine-optimization)
- [Getting cited in ChatGPT/Claude/Perplexity 2026 — AI Magicx](https://www.aimagicx.com/blog/generative-engine-optimization-chatgpt-perplexity-2026)
- [Why Bing indexing matters more than Google for AI — DocDigital](https://docdigitalsem.com/bing-indexing-for-ai-search/)
- [87% of ChatGPT citations from Bing — Conbersa](https://www.conbersa.ai/learn/bing-indexing-optimization-for-chatgpt)
- [Google AI Overviews ranking factors — Wellows](https://wellows.com/blog/google-ai-overviews-ranking-factors/)
- [Google AI Mode GEO stats 2026 — AEO Vision](https://aeovision.ai/articles/google-ai-mode-geo-statistics-2026/)
- [llms.txt zero usage — AEO Engine](https://aeoengine.ai/blog/llms-txt-zero-usage-ai-bots-ignore)
- [Google says llms.txt does nothing for rankings — DigitalApplied](https://www.digitalapplied.com/blog/google-llms-txt-no-seo-value-lighthouse-audit-2026)
- [OtterlyAI llms.txt experiment](https://otterly.ai/blog/the-llms-txt-experiment/)
