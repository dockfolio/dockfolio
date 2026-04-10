# 06 — Pricing

**When to use:** Before launch. Before any pricing change. When your current pricing isn't producing the revenue you expected. When you're undercharging and know it (most indies are).

**Primary sources:** Patrick Campbell (ProfitWell research), Madhavan Ramanujam (*Monetizing Innovation*), Lincoln Murphy (SaaS pricing), patio11's essays on SaaS pricing, Corey Haines, Price Intelligently research.

## First principle: pricing is positioning

Price is the fastest positioning signal a customer sees. Before using your product, before reading your copy, they look at the price and form an opinion.

- $5/mo → "Indie side project, might disappear, toy."
- $29/mo → "Small business tool, prosumer, real."
- $99/mo → "Serious business tool, ROI-justified purchase."
- $299/mo → "Professional operator tool, used for work."
- $999/mo → "Company buys it, not individual."
- Custom / "Contact sales" → "Enterprise, expensive, long sales cycle."

Pricing BELOW your positioning confuses buyers. A "serious business tool" at $5/mo smells wrong. Raise the price or change the positioning — both are better than keeping them mismatched.

## The indie SaaS underpricing epidemic

Nearly every indie SaaS is underpriced by 2-5x. Reasons:
- Founders are engineers, not salespeople; they pattern-match to "cheap = fair"
- They compare themselves to consumer tools (Spotify, Netflix) instead of business tools
- They fear price will scare customers away
- They don't know who their ideal customer is, so they price for the marginal customer (who's always the most price-sensitive)

**If you're charging less than $19/mo for a B2B tool, you are almost certainly underpricing.** The founders who'd disagree are the ones making less than $5K MRR, which is evidence the cheap pricing isn't working.

## Value-based vs. cost-plus pricing

Cost-plus pricing: "My hosting costs $5/mo so I'll charge $15/mo." WRONG. Nobody cares what your costs are.

Value-based pricing: "My product saves a freelancer 10 hours/month at $75/hr, so it delivers $750/mo in value. I'll charge 10% of that = $75/mo." RIGHT. Price is a function of value delivered, not cost incurred.

For indie SaaS, the value-based target is typically **5-15% of the value you deliver**. Below 5% and you're leaving money on the table; above 15% and the ROI feels too thin.

Example: An invoicing tool that saves 5 hours/month of admin work for a freelancer billing $100/hr = $500/mo of value. Appropriate price: $25-75/mo.

## The pricing tier structure

Most indie SaaS should have 2-3 tiers. Not 1 (leaves money on the table) and not 5 (choice paralysis).

### Two-tier structure ("hobby + pro")
Works for products where the hobbyist/individual and the business buyer are different people with different needs.
- **Tier 1 — Free or $5-15/mo.** Hobbyist, single user, limited volume. Purpose: get users in the door, prove the concept, word-of-mouth.
- **Tier 2 — $29-99/mo.** Prosumer or small team. Full features, higher limits. This is where ~80% of revenue comes from.

### Three-tier structure ("starter + growth + business")
Works when you have clear usage tiers or team-size distinctions.
- **Starter — $15-29/mo.** Individuals or tiny teams. Core features.
- **Growth — $49-99/mo.** Growing teams. More users, more features, more volume. *Highlight this one* as "most popular" — 40-60% of buyers will pick the highlighted tier.
- **Business — $199-499/mo.** Larger teams. Advanced features (SSO, audit logs, custom contracts). Lower volume but higher ACV.

### The "contact sales" tier
Add this ONLY if you're serving real enterprises (>100 employees, procurement process, custom contracts). For indie SaaS selling to SMB/prosumer, skip it — it's a conversion killer that signals "we're not sure how to price this for you."

## The anchor price trick

In a 3-tier layout, the highest tier's job is partly to make the middle tier look reasonable by comparison. This is the "anchor" effect — well-documented in behavioral economics.

Example:
- Starter: $19
- Pro: $49 (← most people pick this)
- Business: $199

Without the $199 tier, $49 feels expensive. With it, $49 feels reasonable. This is not manipulation if the $199 tier delivers real additional value; it's just acknowledging how humans perceive prices.

## Pricing psychology: specific numbers matter

- **Charm pricing ($9 vs. $10).** Works for consumer products, less important for business tools. For B2B, $19 and $20 convert similarly; don't sweat it.
- **Round numbers signal premium.** $100 feels "serious." $99.99 feels "discount." For positioning, round numbers win for higher tiers.
- **Monthly vs. annual display.** Show monthly prices on the page even if you prefer annual billing ("$19/mo billed annually"). Monthly is easier to compare; annual feels like a commitment.
- **Annual discounts.** Offer 15-20% off for annual. Don't exceed 25% — it signals desperation. 2 months free on annual (~17% discount) is the sweet spot.
- **Avoid "starting at"** unless you have usage-based pricing. "Starting at $9" makes buyers suspicious about the hidden true cost.

## Free trial vs. freemium vs. paid-only

**Free trial (7-30 days, credit card required or not):**
- Best for: products where value is clear within the trial window
- Credit card required → higher conversion to paid but lower trial starts
- No credit card → more trial starts but lower conversion
- Default recommendation: 14-day trial, no credit card, for most indie SaaS

**Freemium (free tier forever with limits):**
- Best for: products with viral/network effects (the free user attracts more users)
- Best for: products where the free tier is genuinely useful but the paid tier is where power users go
- Worst for: products with no natural usage limit (e.g., no natural "this feature is only for pro" split)
- Rule: DO NOT do freemium unless you can answer "why would a free user ever upgrade?" with a specific feature or limit

**Paid-only (no free tier, no free trial):**
- Best for: products with high trust and clear value
- Best for: products where the trial itself is too expensive to offer (high compute costs, manual onboarding)
- Worst for: products buyers need to experience before trusting
- Uncommon but valid for high-ticket ($500+/mo) products

**For indie SaaS under $50/mo, free trial beats freemium 80% of the time.** Freemium is attractive in theory (bigger top of funnel) but in practice creates a massive unprofitable user base that burns support resources and never upgrades.

## Usage-based vs. flat pricing

Flat pricing ("$29/mo for everything"):
- Pros: predictable, easy to communicate, easy to compare
- Cons: leaves money on the table with power users; may overcharge light users

Usage-based ("$0.01 per API call"):
- Pros: scales with customer value; high-volume users pay appropriately
- Cons: unpredictable bills scare buyers; harder to forecast revenue

Hybrid ("$29/mo includes 10K API calls, $0.005 per additional call"):
- Most common for developer tools and AI products
- Balances predictability with fair scaling
- Complicated to explain — requires clear pricing table

For non-technical buyers, flat pricing almost always wins. For developer tools and AI products, hybrid is becoming standard.

## The 9-9-9 rule (for SaaS price ladders)

Not literal — the idea: each tier should be ~2-3x the previous tier.

- $9 → $29 → $99 → $299 → $999
- $15 → $49 → $199
- $19 → $79 → $249

Why: buyers at different budgets don't see $19 and $29 as meaningfully different tiers. They DO see $19 and $49 as different. The 2-3x gap creates meaningful differentiation.

Indie founders often make the mistake of having 3 tiers at $9, $15, and $29. These feel like the same tier with minor differences. Spread them out: $9, $29, $79.

## Raising prices

The scariest marketing move indie founders resist. Reality:
- Most price increases of 20-40% have near-zero churn impact
- New customers pay the new price from day 1; existing customers grandfather or ramp
- Revenue goes up immediately
- Positioning gets stronger (higher price = more serious tool)

How to do it:
1. **Decide the new price.** Often 2x the current price if current price is < $20. 1.5x if $20-50. 1.25x if > $50.
2. **Grandfather existing customers** (keep their price forever) OR **notice them 30+ days in advance** of a new price. Don't surprise them.
3. **Change the landing page.** Everyone coming to the site sees the new price from day 1.
4. **Watch conversion for 2-4 weeks.** If conversion drops proportionally to the price increase, revenue is flat. If conversion holds, revenue goes up. Usually conversion drops less than proportionally.
5. **If revenue drops, you went too high.** Roll back or add a cheaper tier. This is rare.

Most indies should raise prices at least once a year.

## The "pricing is not fixed" mindset

Indies treat pricing as permanent. It's not. Facebook/Netflix/Spotify change pricing multiple times per year. Your prices are allowed to be wrong at launch and change later.

Permission slip: **your launch pricing will be wrong. Change it when you learn better.** Not "will be right if I think hard enough." Wrong, and that's fine.

## Customizing pricing per market

If you sell internationally, consider:
- **PPP (Purchasing Power Parity) discounts.** 50% off for buyers in India, Brazil, Indonesia, etc. Common with tools like Gumroad and SaaS products. Grows your TAM without cannibalizing high-income markets.
- **Currency display.** Show EUR for EU visitors, GBP for UK, USD for US. Tools like Stripe and Paddle handle this automatically.
- **VAT-inclusive pricing in EU.** EU buyers see prices with VAT by default; adding VAT at checkout feels like a bait-and-switch.

PPP pricing alone can add 10-30% to total revenue at almost zero incremental cost.

## Annual discount psychology

Offering annual at 10-20% off month-to-month:
- Increases LTV (customers pay upfront)
- Reduces churn (harder to cancel mid-year)
- Improves cash flow (money now, not later)
- Converts 20-40% of new customers (varies by market)

Rules:
- Default to MONTHLY billing in the pricing table (don't force annual)
- Show the monthly equivalent of annual: "$190/year (that's $15.83/mo, save 15%)"
- Offer annual during the onboarding flow, not just on the pricing page
- Offer a one-time "upgrade to annual" prompt in month 2-3 of a monthly subscription

## Pricing research that actually works

**The Van Westendorp model (Price Sensitivity Meter):**
Ask 4 questions in a survey:
1. At what price would you consider it so expensive you wouldn't buy it? (Too expensive)
2. At what price would you consider it so cheap you'd doubt its quality? (Too cheap)
3. At what price would you start to think it's expensive but would still consider it? (Expensive/acceptable)
4. At what price would it be a bargain? (Cheap/good value)

Plot these and find the intersection. The "optimal" price is where "too cheap" and "expensive" cross.

This takes 50-100 survey responses and gives you a real data-driven price range. Most indies never do this and guess instead.

**The "would you pay $X" test:**
In cold outreach or user interviews, ask: "If this were $49/mo, would you pay?" Then: "What about $99? $29?" You'll quickly find the ceiling for your specific buyer.

This is imprecise but way better than nothing.

## Pricing mistakes that kill indie SaaS

1. **Undercharging out of fear.** Most common. Costs: 50-80% of potential revenue.
2. **Too many tiers.** 5+ tiers paralyzes buyers. Cap at 3, usually.
3. **Hidden fees at checkout.** Setup fee, support fee, "onboarding fee." Destroys trust. Add it to the base price or kill it.
4. **Pricing page that requires math.** "We charge $0.001 per API call, with a $5 base fee, plus $2 per user, with a 10% discount if you pay annually." Nobody can calculate that. Flat pricing or simple tiers.
5. **"Contact sales" for small budgets.** Indie buyers want to buy themselves; sales calls are a conversion killer unless the buyer explicitly wants one.
6. **Never raising prices.** Inflation alone means your 2021 price is worth ~20% less in 2025.
7. **Dropping prices to compete.** Price wars are a race to zero. Differentiate on value, not price.
8. **Different prices in different places.** Landing page says $29, pricing page says $49, checkout says $39. Pick one. Make it consistent everywhere.

## When to offer discounts

Discounts are a tool, not a permanent strategy.

**Good discounts:**
- Annual discount (10-20%, permanent)
- Founder/early-bird pricing (50% off for first 50 customers, permanent for them)
- Nonprofit / student discount (30-50%, verified)
- PPP discount (40-60%, by country)
- Black Friday / holiday promo (once a year, 20-30%)
- Churn-prevention discount ("Stay for 50% off one more month")

**Bad discounts:**
- Permanent "welcome" discounts (trains buyers to wait)
- Random one-off promos with no reason
- Discounts on the landing page as a default
- "Limited time!" urgency without actually being limited

A discount should feel rare. If your base price is always discounted, that's just your real price with extra steps.

## The "what to charge" decision shortcut

Don't overthink it. If you're stuck, use this shortcut:

1. Look at 3-5 direct competitors' pricing.
2. Take the median price.
3. Charge slightly more than the median (10-20% higher).
4. If you can't explain why you're worth more than the median, improve the product OR fix your positioning (not your price).
5. Revisit in 6 months.

This beats analysis paralysis 90% of the time. You can optimize later.
