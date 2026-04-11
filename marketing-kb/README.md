# Marketing Knowledge Base

A dense, opinionated reference for indie SaaS, tools, and productivity apps in the pre-traction to early-traction phase (0 → 100 customers).

## How this KB is used

1. **By the Marketing Brain** — `loadMarketingKB()` in `dashboard/routes/marketing-brain.js` reads these files at startup. Each brain cycle retrieves the 1-3 most relevant sections for the app being analyzed (based on its stage, open actions, and recent learnings) and injects them as `ctx.kb_snippet` into the LLM prompt. The brain is instructed to ground its proposals in KB principles when they apply.
2. **By the operator** — The dashboard's Brain tab has a KB browser. You can also just read these files directly for human reference.

## How this KB is written

- **Opinionated.** It takes positions. "It depends" is banned except where the trade-off is genuinely situational.
- **Actionable.** Every principle has a specific next step, or it gets cut.
- **Credible.** Draws from the best-known practitioners: April Dunford, Rob Walling, Patrick McKenzie (patio11), Julian Shapiro, Lenny Rachitsky, Ryan Holiday, Seth Godin, Andrew Chen, Sean Ellis, First Round Review, Reforge, Ahrefs, Lincoln Murphy.
- **Dense.** No filler. Every paragraph earns its place.
- **Honest about trade-offs.** Good marketing advice acknowledges what it costs. Anything that promises upside with no downside is a red flag.
- **Scoped to the indie SaaS context.** Enterprise sales, consumer-social virality, and D2C e-commerce tactics are mostly absent. This KB is for people building $10-100/mo tools alone or in tiny teams.

## Files

| # | Topic | When to read it |
|---|-------|-----------------|
| 01 | `positioning.md` | Before writing ANY marketing copy. The foundation. If positioning is wrong, everything downstream is wasted effort. |
| 02 | `pre-traction.md` | 0-10 customers. How to get the first ones. |
| 03 | `launch-playbook.md` | Product Hunt, HN, Reddit, Twitter, Indie Hackers. The public launch day. |
| 04 | `content-and-seo.md` | When you've decided content is a channel. Keyword research, writing, ranking, distribution. |
| 05 | `conversion-and-landing-pages.md` | When traffic exists but doesn't convert. Landing page architecture, copy, CRO. |
| 06 | `pricing.md` | Pricing is positioning. How to set it, when to change it, what to charge. |
| 07 | `growth-loops.md` | Beyond funnels: how self-reinforcing growth actually works. |
| 08 | `distribution-channels.md` | Where to spend the marketing budget. Evaluating and picking channels. |
| 09 | `email-and-lifecycle.md` | Activation, onboarding, retention. Email as the highest-ROI channel. |
| 10 | `metrics-and-analytics.md` | What to measure, what NOT to measure, and how to know if things are working. |
| 11 | `kill-criteria-and-pivots.md` | How to decide whether to kill, pivot, or persist. |
| 12 | `copywriting.md` | Sentence-level craft: headlines, CTAs, body copy, value props. |
| 13 | `customer-discovery.md` | The Mom Test, Jobs-to-be-Done, switch interviews, 5-interview rule. |
| 14 | `b2b-outbound.md` | ICP, cold email anatomy, sequences, reply-rate benchmarks, CRM discipline. |
| 15 | `plg-motions.md` | Self-serve funnels, freemium, reverse trial, Triple-A, activation metrics. |
| 16 | `category-design.md` | Creating a new category vs competing in one. Mostly a warning for indies. |
| 17 | `portfolio-and-public-ai.md` | For founders with 5+ products AND an autonomous AI engine. Portfolio-as-brand + the Public Brain playbook. |

## First principles

These run through every file and are the KB's bedrock:

1. **Distribution > product.** A mediocre product with great distribution beats a great product with no distribution, every time. Build distribution muscles before (or alongside) the product, not after.
2. **Narrow beats broad.** "For everyone" is for no one. A product that's 10/10 for a narrow group beats a product that's 6/10 for a broad group.
3. **Specific beats generic.** "Invoicing software for freelance plumbers in the UK" outperforms "invoicing software for small businesses."
4. **Distribution channels stack, they don't replace.** You don't pick one channel. You pick the ONE that works now and start there, then add more. But most indies pick five at once and execute none well.
5. **Content compounds, paid doesn't.** $1 spent on content in month 1 keeps paying back in month 36. $1 spent on ads in month 1 is gone by month 2. Both have their place, but founders underestimate the compounding.
6. **Talk to users.** Every week. For an hour. Not surveys — actual conversations. The next best marketing insight is always one user interview away.
7. **The best marketing is a product people want to share.** Not virality hacks — actual word-of-mouth, the kind that happens when a product solves a real problem better than alternatives.
8. **Ship faster than you think you should.** Your launch is not your one shot. Ship v1, get feedback, ship v2. "Perfect" is a defense mechanism against the fear of being seen.
9. **Positioning is expensive to change.** Product is cheap. Code is cheap. Positioning is expensive because it lives in customers' heads and is the slowest thing to update. Pick it carefully.
10. **Your competitors aren't who you think they are.** Your real competitor is "status quo" — the customer doing nothing. Most products lose to status quo, not to other products.
