# 10 — Metrics & Analytics

**When to use:** When setting up any product, before launching anything, when deciding what to optimize, when you suspect you're measuring the wrong things.

**Primary sources:** Sean Ellis (growth metrics), Dave McClure (AARRR / Pirate Metrics), Andrew Chen (DAU/MAU, retention curves), Eric Ries (*The Lean Startup* on vanity vs. actionable metrics), Alistair Croll & Benjamin Yoskovitz (*Lean Analytics*).

## First principle: most metrics lie

Not maliciously — structurally. Metrics can:
- Be technically correct but miss the point (vanity metrics)
- Lag so far behind reality that they're useless (MRR in a 2-week-old product)
- Be so high-variance they're noise (DAU for 10 users)
- Measure the wrong thing (pageviews when you care about signups)
- Look good while the business dies (growth on declining retention)

Your job with metrics is NOT to measure everything. It's to identify the 3-5 numbers that actually tell you whether you're winning. Everything else is noise that consumes attention.

## The AARRR framework (still the best mental model)

Dave McClure's "Pirate Metrics" from 2007. Still the clearest framework for SaaS.

1. **Acquisition** — how users find you (traffic sources, visits, reach)
2. **Activation** — % of new users who experience core value (the "aha" moment)
3. **Retention** — % of users who come back repeatedly
4. **Revenue** — users who pay
5. **Referral** — users who bring more users

The critical insight: **these are not equally important at every stage.** You focus on them in order, roughly. A pre-traction indie SaaS should obsess over activation; a growing one should obsess over retention; a mature one can optimize revenue and referral.

## The stage-to-metric mapping

| Stage | MRR | Focus metric | Why |
|-------|-----|--------------|-----|
| Pre-launch | $0 | Conversations with target users | You don't know if the problem is real yet |
| Early launch | $0-500 | Paying customers (count) | You need proof-of-concept |
| Early traction | $500-2K | Week-over-week new customers | Growth rate reveals channel fit |
| Growing | $2-10K | Activation rate + retention curve | Now you need efficiency |
| Scaling | $10-50K | MRR growth rate + churn rate | Unit economics matter |
| Sustainable | $50K+ | LTV:CAC ratio | Decide what to invest where |

Measuring MRR growth rate when you have $200 MRR is noise. Measuring LTV:CAC when you have 12 customers is astrology.

## Vanity metrics (skip these)

- **Pageviews, visitors, impressions** (without context) — you can 10x these by buying cheap ads and nothing improves
- **Total signups ever** — monotonically increasing; doesn't tell you anything about current state
- **Followers, subscribers** — only valuable if they convert
- **Downloads** (for non-mobile products) — doesn't mean usage
- **App store ranking** — moves around daily
- **Email list size** — only valuable paired with open + click rates
- **"Engagement"** (undefined) — usually means nothing specific
- **MRR ARR "to the moon" charts** — meaningless before you have real retention data

Why these are bad: you can game them, they don't correlate with business health, and they create satisfaction without progress.

## Actionable metrics (measure these)

### Pre-traction and early traction

**Paying customers (total).** The only metric that matters at $0 MRR. Goal: +1 per week. Full stop.

**Conversion rate (specific funnel stage).** Landing page → trial, trial → paid, email → click. Pick the stage that's the current bottleneck.

**Customer interviews per week.** Target: 3-5. Not a vanity metric because the insight from one good interview beats a week of analytics watching.

**Time from signup to first payment.** If it's measured in hours or days, the product is activating quickly. If it's weeks, something is slow or broken.

### Growing ($2-10K MRR)

**Activation rate.** % of new signups who take the core action within X days. The "aha" moment. Slack: "sent 2000 team messages." Dropbox: "installed on 2 devices." Aim for > 30%, elite is > 60%.

**Retention curve (cohort retention).** Plot % of signups who are still active at day 1, 7, 14, 30, 60, 90. For SaaS, you want the curve to **flatten** after day 30 — not drop to zero. A flat tail means you have a core of users who stuck around.

**Week-over-week new customer count.** If it's going up consistently, you have channel fit. If it's flat or down, re-evaluate.

**Revenue churn rate.** % of MRR lost per month to cancellations + downgrades. Aim for < 5%/mo for SMB SaaS; < 2% for larger. Anything above 10% is a leaky bucket that will sink you.

**Net Revenue Retention (NRR).** (MRR at end of month − new MRR) / MRR at start of month. 100%+ means existing customers grow enough to offset churn (expansion revenue). Elite = 120%+.

### Scaling ($10K+ MRR)

**LTV (Lifetime Value).** Average revenue per customer × average customer lifetime. Simple formula: ARPU / churn rate. At 5% monthly churn + $30 ARPU, LTV = $600.

**CAC (Customer Acquisition Cost).** Total marketing + sales spend / new customers acquired. Must include your time if you're the founder doing the work (estimate at $50-100/hr).

**LTV:CAC ratio.** Good: 3:1+. Elite: 5:1+. Under 1:1: you're losing money on every customer; fix immediately.

**Payback period.** Months to recoup CAC from a new customer. Target < 12 months for SMB; < 6 is elite.

**MRR growth rate (monthly).** 10% monthly MRR growth is "good" for early-stage SaaS; 20%+ is excellent. Below 5% you're stagnating.

## The single most important number (for most indie SaaS)

**Monthly recurring revenue (MRR), week over week.**

It captures: paying customers, average price, churn, expansion, contraction, all in one number. And unlike most metrics, it's directly tied to whether the business is viable.

Track weekly (not daily — too noisy, not monthly — too slow). Visualize as a line chart over the last 90 days. If it's going up, you're winning. If it's flat, diagnose why. If it's down, emergency.

That's it. One number, weekly cadence, gut-level understanding.

## The retention curve (the most underrated chart)

The single most informative chart in SaaS. Here's how to build it:

1. Take all users who signed up in a specific week (a "cohort").
2. For each day after signup (1, 7, 14, 30, 60, 90), count what % of the cohort is still "active" (logged in, took core action, etc. — you define "active").
3. Plot the curve.

What good looks like:
- Sharp drop in first 7 days (expected — bad-fit users leave)
- Gradual decline from day 7 to day 30
- **Flattens** from day 30 onward, ideally around 20-40% for SMB SaaS, 50%+ for products with strong retention

What bad looks like:
- Curve keeps dropping linearly past day 30 — nobody is sticking
- Drops to < 10% by day 60 — you have acquisition but not retention, a leaky bucket
- Flatlines at day 0 — you have vanity signups that never activate

Fixing a bad retention curve is almost always a product problem, not a marketing problem. Marketing can't save a product users don't stick with.

## The Sean Ellis test (product-market fit measurement)

Ask your active users: "How would you feel if you could no longer use [product]?"
- Very disappointed
- Somewhat disappointed
- Not disappointed

**Rule: If > 40% say "very disappointed," you have product-market fit.** Below that, you don't yet.

This test works because it captures emotional attachment, not just transactional use. It's also cheap: 30-50 users surveyed once is enough signal.

Most pre-PMF products score 10-25%. The jump to 40% is the moment to start pouring fuel on growth. Before that, focus on product, not marketing.

## The "leading vs. lagging" indicator distinction

**Lagging indicators** tell you what happened. Examples: MRR, revenue, churn rate.
**Leading indicators** predict what will happen. Examples: new signups, trial-to-paid conversion rate, activation rate, email reply rate.

Most indies obsess over lagging indicators (MRR charts) and ignore leading indicators. This is backwards. By the time MRR tells you there's a problem, the problem happened weeks ago.

**Rule:** spend 80% of metric-watching attention on leading indicators. Lagging indicators are for quarterly reviews.

Leading indicators to watch weekly:
- New signups
- Activation rate
- Trial-to-paid conversion rate
- Customer replies/interviews (qualitative but leading)
- Week-over-week active users (not total, new-active)

## Setting up analytics cheaply

For indie SaaS under $10K MRR, this stack covers 95% of needs:

1. **Plausible or Fathom** ($9-14/mo) — privacy-friendly web analytics. Page views, referrers, top pages, goals. Replaces Google Analytics.
2. **Microsoft Clarity** (free) — heatmaps, session recordings, funnel analysis. The session recordings alone are worth it.
3. **Stripe dashboard** (free) — revenue, MRR, churn, customer list. Don't build this yourself.
4. **A simple DB query or Metabase** (free/cheap) — custom metrics from your own product data (activation rate, retention curves, cohort analysis).
5. **Customer.io or Loops or Drip** ($25-100/mo) — lifecycle email + behavioral data.

What you DON'T need at this stage:
- Mixpanel or Amplitude ($500+/mo)
- Heap ($1000+/mo)
- Full-blown BI stacks (Looker, Tableau, etc.)
- Dedicated data warehouse
- Dedicated analytics engineer

Those tools become worth it around $100K+ ARR when the custom-query approach stops scaling. Not before.

## The "one number a week" discipline

Instead of building a dashboard with 30 metrics, pick ONE number to track this week.

- Week 1: "I want to raise my activation rate from 25% to 35%."
- Week 2: "I want to get 5 trial-to-paid conversions this week."
- Week 3: "I want < 3 churn events this week."

Focus is power. A scattered 30-metric dashboard creates the illusion of understanding while actually dispersing attention. One focused number + one experiment to move it = real progress.

## Cohort analysis (the "real" analytics discipline)

If you do nothing else sophisticated, do cohort analysis:

1. Group users by the week they signed up.
2. For each cohort, track:
   - % still paying at week 1, 4, 8, 12, 24
   - Average revenue per user at each point
   - Churn rate within the cohort

Cohorts reveal things aggregate metrics hide:
- "Our January cohort is worth 2x our April cohort" — something changed in April (pricing? positioning? channel?)
- "Cohorts activated via paid ads churn faster than organic cohorts" — paid may not be profitable
- "Users who trial 14-day plan retain better than 7-day plan" — pricing lesson

SQL query or a tool like Metabase can pull this cheaply. Worth doing monthly.

## The "goodhart's law" warning

**When a measure becomes a target, it ceases to be a good measure.**

If you tell the team "maximize signups," the team starts gaming signup counts — dark patterns, incentivized fake emails, bait-and-switch offers. The number goes up, the business gets worse.

Protection: measure multiple things at once. Never optimize a single metric in isolation. Pair signups with trial-to-paid conversion, paid retention, and customer satisfaction. If signups go up but the paired metrics drop, you're gaming the number, not growing the business.

## What NOT to report publicly (yet)

Indie Twitter culture encourages public MRR tweets. Risks:
- You give competitors intel
- You create pressure to grow monotonically, even through false hype
- You attract copycats
- You feel obligated to report even when things are down, which is psychologically hard
- Public numbers can be used against you in negotiations (partnerships, acquisitions)

If you report publicly, do it with intention: "I report MRR monthly on the 1st to keep myself accountable and share learnings." Not because every indie does it.

Most indie founders would benefit from reporting to ONE accountability partner instead of the public.

## The measurement stack audit (quarterly)

Every quarter, audit:

1. **What metrics am I looking at weekly?**
2. **Which of those actually drove a decision in the last 4 weeks?**
3. **Which did I look at and then ignore?**
4. **What decisions did I make WITHOUT metrics that I should have used metrics for?**
5. **What's the simplest version of my dashboard that answers: am I winning?**

If a metric hasn't driven a decision in 4 weeks, either it's too slow (move to quarterly), or it's the wrong metric (delete it). A metric you're not acting on is a metric that's not earning its place.

## The "anti-metric" list

Metrics that actively hurt indie founders when tracked:
- **Daily check on MRR.** Creates anxiety, reveals nothing (too slow).
- **Social media follower count.** Dopamine without value.
- **Product Hunt rank after launch day.** Irrelevant after day 1.
- **"Industry benchmarks."** Your context is different; benchmarks are distracting.
- **Competitor MRR (guessed).** You have no real data.
- **Hacker News points on a post.** Moves fast, doesn't predict sustained traffic.

Remove these from whatever dashboard you use. They create noise and emotional reactions without informing decisions.
