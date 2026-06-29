# 06 — View-Magnet Sites: the LohnCheck model + new build ideas

**Created:** 2026-06-29 (session 28). **Status:** Living. **Companion to:** files 01-05 (those are the "how to get found" layer; this is the "what to build next" layer).

This file answers a specific question: *given that our single best organic-traffic site is a free calculator, what NEW sites should we build to capture huge view volume and ad money, and how do we verify the demand is real?* It is grounded in five parallel deep-research passes (clusters A-E below) plus live traffic measurement done 2026-06-29.

---

## 0. The verified premise (measured 2026-06-29, ground truth)

The intuition — "LohnCheck is our biggest success at getting views" — is **correct, but only when measured correctly.** This matters because the obvious dashboard (Plausible) says the opposite, and acting on Plausible would have killed the right strategy.

| Source | lohnpruefung.de reading | Verdict |
|--------|------------------------|---------|
| **Plausible (6 months)** | 92 visitors / 133 pageviews | **WRONG — massive undercount.** Plausible is client-side JS. LohnCheck's audience is privacy-conscious German employees checking payslips — the heaviest script/ad-blocking demographic on earth. The tool literally advertises "all calculations run in your browser, nothing is sent to our servers," which actively selects for tracker-blockers. |
| **Server-side nginx logs (~1 day)** | **6,426 requests — #2 in the whole portfolio**, behind only promoforge's app traffic and ahead of every other content site | **RIGHT.** nginx logs every request; nothing can block it. This is the true scale. |

**Three load-bearing lessons:**
1. **For free browser-side tools, measure traffic SERVER-SIDE (nginx visit-logs), never via Plausible/GA.** Client-side analytics undercounts this audience ~50-100x. Any "this tool is dead" call based on Plausible is probably wrong. *(Build candidate: a Dockfolio panel reading nginx logs per domain — true, ad-block-proof views.)*
2. **The oldworldlogos.com Plausible spike (1,612 visitors) was a one-off Telegram-channel push (owned channel), not organic** — confirmed by the user. Discount owned-channel spikes when judging which model *scales on its own*. LohnCheck's traffic is self-sustaining; oldworldlogos' was pushed.
3. **GSC cross-check (file 04): lohnpruefung.de has only 1 page indexed in Google** — its 63 programmatic city pages were rejected as thin. So the 6,426 daily hits come from the **homepage calculator** ranking for the head term + direct/AI/branded, NOT the programmatic long tail. **One excellent tool on a head term beats 63 thin templated pages. Build depth, not page-count.**

## 1. The LohnCheck model, distilled (the repeatable recipe)

Every property is a reason it works. Copy ALL of them.

1. **Evergreen, ultra-high-volume head query.** "Brutto Netto Rechner" is searched forever, every month, no trend risk.
2. **Single, narrow, universal job.** One input form, one answer. The narrower the promise, the higher the rank and the AI-citation odds.
3. **Free, no registration, no friction.** Nothing between visitor and answer. Ad/funnel monetization needs no accounts.
4. **100% browser-side compute.** All upside compounds: near-zero hosting cost (one tool ≈ one nginx vhost), **zero data liability / trivial GDPR** (no salary/health data touches the server), infinite spike-scaling, and "your data never leaves your browser" is itself a trust/citation lever for sensitive topics.
5. **Authoritative core.** LohnCheck implements the *official BMF Programmablaufplan*. Anchor every tool to an official/canonical source — that authority earns the rank and the AI citation.
6. **Freshness as a feature.** "...für 2026", updated yearly. Google + AI both reward freshness; an annually-updated official-rate tool is freshness on autopilot.
7. **Engineered for SEO + GEO from day one.** lohnpruefung.de is the A+ site: FAQ + WebApplication + Organization schema, AI-welcome robots, multi-sitemap, definition-first copy. Apply every file-02 lever.
8. **Monetization stacked on top, never gating.** Ads + affiliate hand-off + funnel to paid micro-tools. The free tool is the top of the funnel.

---

## 2. THE GOVERNING STRATEGY (user steer, session 28)

The user set the target explicitly: **discovery = AI-first** (a person asks ChatGPT/Perplexity/Gemini an interesting question → the AI researches the web → it cites OUR site → the user clicks through), and **monetization = display ads** on the page they land on. Goal = **views × ad RPM.**

This creates **two hard constraints that must drive niche selection** (both confirmed by research):

### Constraint 1 — AI answers are mostly ZERO-CLICK. Build only what the model can't finish in the chat box.
US Google is now **~68% zero-click**; with an AI Overview present, clickthrough drops to **~8%**, and **<1%** click links *inside* the AIO. **88% of AIO-triggered queries are informational** — simple-fact content earns the citation but loses the view (and the ad impression). The monetizable wedge is anything the model **cannot serialize into a chat reply**:
- a **rendered image/file** (QR code, compressed PDF, exported palette),
- a **recompute from the user's own inputs** (multi-input calculator with sliders/scenarios),
- a **sortable/filterable surface too large to inline** (cost-of-living table, visa matrix, GPU decider),
- a **downloadable file** (spreadsheet template),
- a **visual sequence or gallery** (knot animation, interior-design gallery, "how X works" simulation),
- **freshness the model's training can't hold** (today's savings rates, live tariffs).

→ This is exactly the **ACTION-tool vs COMPUTE-tool** split (Cluster C): build ACTION tools, avoid COMPUTE tools the AI answers inline. **Avoid the volume traps:** BMI, percentage, unit/currency conversion, age/date, hex↔rgb, "what is X" — high volume, citation without clickthrough, zero ad revenue.

### Constraint 2 — Display ads in Germany are crippled. For an ads-first goal, go ENGLISH/international.
Germany has ~**49% adblock** (world's highest) + low DE RPM → a German privacy-tool nets **~€1-3 effective RPM** (Cluster D). US/English traffic is **3-5x better RPM and ~32% adblock**, with a far bigger TAM. So:
- **Track 1 (PRIMARY, the ads play):** English/international ACTION tools + interactive content. This is what the user asked for.
- **Track 2 (PARALLEL, the affiliate play):** German finance Rechner monetize via **lead-gen/affiliate, not ads** — one finance lead = €25-370 = thousands of ad-views (Cluster D). Different engine, higher €/session, reuses the existing LohnCheck asset. Keep it, but don't confuse it with the ads goal.

**And don't abandon Google SEO** — still ~88% of all clicks, and it *feeds* AI citation (a Bing-indexed, organically-ranked, well-structured page is the page that gets cited). The AI layer sits ON TOP of SEO. Encouraging for a new site: AI citation tracks **topical depth, not Domain Authority** (DA correlates only r≈0.18 with being cited; only ~38% of AIO citations now come from top-10 rankers) — a small, deep, well-structured tool can win the citation.

## 3. Selection scorecard for a new view-magnet site

Score each candidate 1-5; build the high totals first.

| Axis | What "5" looks like |
|------|---------------------|
| **Search/ask volume** | Six-figure evergreen monthly demand on a head term/topic |
| **Clickthrough-resistance** | The AI/Google *cannot* fully answer inline — needs a render, recompute, big surface, file, gallery, or live data |
| **Ad RPM of the topic** | English finance/health/home/tech audience that advertisers pay for (avoid trivia/dev = low RPM) |
| **Build simplicity** | Pure browser-side, official formula/data public, shippable in days |
| **AI-citation winnability** | A small, structured, authoritative page can realistically become the cited answer |
| **Low adblock audience** | Casual/consumer (teachers, DIYers, parents) not privacy-geeks/devs |
| **Asset reuse / funnel fit** | Reuses a shared engine, or funnels to a paid €9.99 tool |

**Anti-pattern (from our own GSC data):** never ship hundreds of thin programmatic variants hoping volume adds up — Google rejects them and AI won't cite them. One deep, genuinely useful tool > 63 templated stubs.

---

## 4. THE RANKED BUILD PLAN (synthesis of all five clusters)

### Architecture recommendation (applies to both tracks)
Build **one multi-tool platform**, not 30 separate sites: a shared vanilla-JS tool engine + shared template, **each tool on its own URL** (so each can rank and be the single cited result for its exact query), all cross-linked. This concentrates domain authority, reuses code, and lets high-volume/low-value tools funnel into high-value ones. Two German engines unlock most of Track 2: the **BMF PAP brutto→netto engine** (spawns Stundenlohn, Überstunden, Pendlerpauschale, Steuererstattung…) and **one annuity/amortization engine** (spawns Tilgung, Annuität, Budget, Umschuldung).

### TRACK 1 — English ACTION tools (the ads engine, the user's primary goal)
Ranked by views × clickthrough-resistance × ad RPM × build-simplicity:

1. **Finance calculator suite — mortgage / loan / compound-interest** (sliders + amortization chart). Top-RPM niche (finance $30-55 RPM premium), enormous evergreen volume ("mortgage calculator" ~1.5-2.5M/mo; "calculator" 21M/mo US), pure client-side build. The slider-drag + amortization schedule is exactly what a one-number chat answer can't give. Win the long-tail vs Bankrate/NerdWallet.
2. **QR code generator** (logo + SVG, no signup). The model *physically cannot* emit a scannable image inline → cleanest forced render+download click. Low build (qrcode.js), broad low-adblock audience. Beat the "dynamic QR" paywall incumbents by being truly free.
3. **TDEE / macro / calorie calculator** (goal-date timeline). Biggest *proven* traffic in the set (incumbent proxy 456k organic/mo), Low build, 6+ inputs defeat the generic inline answer, top health RPM (weight-loss advertisers $15-35).
4. **Color palette generator / explorer** (prompt-to-palette, WCAG contrast, lock-and-reroll). **16.8 pages/visit = ad goldmine** (Coolors proxy 1.47M/mo). AI lists hex as text; users want to SEE/copy swatches. Win on Tailwind/WCAG niche + zero paywall.
5. **PDF toolkit — merge / split / compress / convert** (browser-side, pdf-lib). ~1-2M/mo each × ~8 sub-tools, can't be done inline, "files never leave your device" is a citation magnet. Freemium upsell available.
6. **Image convert / compress / resize family** ("png to webp", "heic to jpg", "compress jpg to 200kb"). Huge splinter of low-competition long-tails, all Low build (Canvas/Squoosh wasm), one template → hundreds of pages.
7. **Random wheel / decision spinner** (per-niche). Under-rated ceiling (~7M/mo category, wheelofnames proxy), casual teacher/streamer/giveaway audience that **doesn't ad-block**, repeat use, animation the AI can't fake.
8. **Cost-of-living two-city comparator.** ~5M/mo interactive demand that *survived* AI (Numbeo proxy); swap-and-recompute is inherently un-inlineable; good relocation/travel RPM. (Data upkeep is the cost.)

**Bench / portfolio fillers (Low build, real demand, lower priority):** material/coverage calculators (paint/concrete/mulch), budget/spreadsheet-template gallery (no-signup — download click structurally forced), sleep-cycle calculator, CSS gradient generator, password generator, background remover, timezone meeting-overlap planner, visa/passport matrix, GPU/laptop decider, "how X works" interactive explainers (backlink magnets). **Tariff/import-duty calculator** is a high-upside *fast-mover* (400× YoY search surge, thinnest SERP, top RPM) — build if we can keep the HTS rate table current. **Dev-utility cluster** (JSON formatter, subnet, regex) wins citations cheaply but the dev audience ad-blocks → authority/brand-halo play, not a revenue centerpiece.

### TRACK 2 — German finance Rechner (the affiliate engine, higher €/session, reuses LohnCheck)
Ranked by volume × low build × monetization × beatability (affiliate/lead-gen, NOT ads):

1. **Pfändungsrechner / Pfändungstabelle** — best effort×volume×money: Low build (table lookup, yearly update), 50-80k cluster, high-CPC (Schuldnerberatung €40/lead + Umschuldung 1.85-5.5%), dated SERP.
2. **Kfz-Steuer-Rechner** — highest volume (100-165k head) × richest affiliate (Kfz-Versicherung, Check24 €125+/policy) on a fixed public KraftStG formula. Win long-tail per-model + insurance CTA.
3. **"Wie viel Haus kann ich leisten" + Grunderwerbsteuer + Kaufnebenkosten bundle** — Low build (static 16-state table) → highest German lead values (€32-110/Baufi lead, €3-6k/closed loan). Beat content-site incumbents with a no-email-gate tool.
4. **Pflegegrad-Rechner (NBA Punkte)** — biggest pension-half volume (30-60k), public §15 SGB XI quiz, thin incumbents, **highest AI-citation**; care-affiliate (pflege.de, Treppenlift) monetized.
5. **Pendlerpauschale-Rechner** — trivial build × 25-60k seasonal × live **2026 flat €0,38/km freshness moat** most incumbents haven't updated; tax-software affiliate.
6. **Zinseszins / ETF-Sparplan-Rechner** — 30-50k, trivial math, highest AI-citation, routes to richest evergreen monetization (depot lead-gen, Consorsbank €80/sale, Trade Republic ~€36/lead).
7. **Erwerbsminderungs- / Witwenrente-Rechner** — 12-30k high-anxiety queries where incumbents show only the crude headline and omit the income-offset math; funnels to highest-value insurance leads (BU €39-100).
8. **Gewerbesteuerrechner** — best B2B ROI: €55/lead accounting + business-banking CPA; per-Gemeinde Hebesatz table = data moat + AI-citation hook (Hebesätze aren't in LLM memory).

**Funnel to existing paid tools:** free Abfindungs-/Fünftelregelungs-Rechner → paid **AbfindungsOptimizer** (€9.99); free Erbschaft-/Schenkungsteuer-Rechner → paid **SchenkungsPlaner** (€9.99). Rule: free tools whose answer is *"you might owe/lose a lot of money"* convert to paid; *"here's a number"* tools don't.

**The single AI-citation pattern that wins everywhere (both tracks):** render the **rule table + a dated worked example** ("Stand: Jul 2026" / "Updated 2026") next to the tool, lead with a one-sentence definitional answer in the first 40-60 words, add `SoftwareApplication`(price=0) + `HowTo` + `FAQPage` schema (FAQPage → ~3.2x more likely to appear in AI Overviews), and answer the exact natural-language questions people type into ChatGPT. One tool = one URL, static + fast, real single `<h1>`.

---

## 5. Recommendation in one paragraph

If the goal is **views monetized by ads**, build **Track 1: an English, multi-tool platform of ACTION tools** — start with the **finance calculator suite, QR generator, calorie/TDEE calculator, and color-palette explorer** (highest views × ad RPM × clickthrough-resistance × build-simplicity), all on one cross-linked domain, each tool on its own URL, structured hard for AI citation. These survive AI zero-click because the AI can't render the image, recompute the user's numbers, or show the interactive surface in chat. Run **Track 2 (German finance Rechner)** in parallel as a higher-€/session **affiliate** engine that reuses the LohnCheck PAP/annuity code and funnels to the existing €9.99 paid tools — but recognize it as an affiliate play, not the ads play. Keep classic SEO underneath both; the AI citation rides on top of it. **Before committing build hours, validate the final 2-3 picks' exact search volumes in Google Keyword Planner / Ahrefs** (all volumes below are directional triangulations, not precise).

## 6. Verification status & caveats (be 100% sure)

- **Verified live (2026-06-29):** LohnCheck traffic scale (nginx server-side #2 portfolio-wide), Plausible undercount, oldworldlogos = owned-channel push, LohnCheck product model (free, browser-side, BMF PAP, free pricing), GSC 1-page-indexed paradox.
- **Verified from cited live sources:** zero-click/CTR stats, German adblock rate, affiliate payout figures (financeAds/CHECK24/Tarifcheck program pages), official data sources for each German tool, incumbent traffic (Similarweb/StatShow).
- **Directional, NOT verified:** all keyword search volumes (exact MSV sits behind paid Keyword Planner/Ahrefs logins) — triangulated from SERP density, incumbent traffic, and advertiser bids. The *relative* rankings are robust; the absolute numbers need a paid-tool check before build commitment.

---

## 7. Appendix — the five research clusters (condensed)

The full per-cluster findings tables, ranked top-8/10 lists, and source URLs live in the session-28 research and are summarized here. (A) German Finance/Tax/Legal Rechner, (B) German Health/Life/Education calculators, (C) AI/GEO global evergreen tools (the ACTION-vs-COMPUTE thesis), (D) Monetization & advertiser economics (RPM + affiliate payout tables), (E) English AI-cited ad-monetized content & tools (the zero-click-survival thesis). Key cross-cluster syntheses are folded into sections 2-4 above. For the raw tables and the full source lists, see the cluster research outputs; the load-bearing primary sources are SparkToro, Similarweb, Pew, Ahrefs, Semrush, BrightEdge, Mediavine/Raptive, financeAds/CHECK24/Tarifcheck, and the official German statutory sources (gesetze-im-internet.de, BMF, DRV, GKV).
