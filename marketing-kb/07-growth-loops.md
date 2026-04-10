# 07 — Growth Loops

**When to use:** When you've exhausted linear channels (outreach, content, launch) and need something that compounds. When traction is real but plateauing. When you want growth that keeps working while you sleep.

**Primary sources:** Reforge (Brian Balfour, Casey Winters, Andrew Chen). The "Loops not Funnels" framework. Lenny Rachitsky on growth loops. Andrew Chen's *The Cold Start Problem*.

## Funnels vs. loops: why this matters

Traditional marketing thinks in funnels:
```
Awareness → Interest → Consideration → Trial → Paid
```
Funnels are LINEAR. You put traffic in the top, some comes out the bottom, and you pay for it forever. Stop spending, traffic stops.

Loops are CIRCULAR. Output of one cycle feeds input to the next cycle. Example:
```
User signs up → User creates a project → Project shows a "Built with X" badge → 
Badge visitor clicks → New user sees signup page → New user signs up → ...
```
Each cycle grows the top of the next cycle. This is how Calendly, Superhuman, Canva, Dropbox, and Slack all scaled — not via "marketing," but via loops baked into the product.

## The four types of growth loops

Per Reforge's framework, loops come in four flavors. Most products support 1-2; few support more.

### 1. Viral loops (user → user)

A user invites or exposes another user as a natural part of using the product.

Examples:
- **Dropbox referrals** ("Invite friends, get more storage") — mechanical, incentive-driven.
- **Calendly scheduling links** — every time a Calendly user schedules a meeting, the other person sees Calendly branding and learns it exists.
- **Slack workspace invites** — impossible to use Slack alone, so every user pulls others in.
- **Email signatures** ("Sent from Superhuman") — every email is marketing.
- **Built-with badges** ("Powered by Typeform") — every form is an ad.

Viral loops require **sharing to be natural or required**. Forcing it (mandatory referrals before you can use the product) backfires.

Math: Viral coefficient (K) = (invites per user) × (conversion rate of invites). K > 1 means exponential growth; K = 0.5 means linear; K < 0.1 is just acquisition assistance.

**Realistic K for indie SaaS:** 0.05-0.2. A K of 0.5+ is extremely rare and usually requires a consumer or network product.

### 2. Content loops (content → traffic → content)

Users generate content that becomes SEO traffic that brings more users that generate more content.

Examples:
- **Yelp** — users write reviews that rank in Google for "best pizza [city]"
- **Stack Overflow** — users ask and answer questions that rank for every programming query
- **Pinterest** — user-created pins rank in image search
- **Reddit** — threads rank for every conceivable niche question
- **GitHub** — repos rank for "[language] [library name]"

For indie SaaS, content loops work when:
- Users create things worth finding (analyses, templates, public pages)
- You give those things a public URL
- The URL is SEO-optimized (clear title, good meta, structured content)
- Google indexes them

Example of an indie content loop: **Linktree**. Each user's Linktree page is a public landing page with "Powered by Linktree" branding. Every page that ranks = free marketing.

### 3. Paid loops (money → users → money)

Rare for indies because they require positive unit economics. If CAC < LTV × 0.3, you can reinvest revenue into ads profitably and the loop compounds.

Examples:
- Most DTC brands (Warby Parker, Casper, Allbirds)
- Some SaaS with high LTV (e.g., HubSpot, Shopify)
- Mobile games with strong retention

For indie SaaS at < $10K MRR, paid loops rarely work. CAC is usually higher than your tier-1 subscription monthly revenue, and the loop doesn't cycle fast enough. Skip until you have clear unit economics data.

### 4. Sales-led loops (customer → referral → customer)

Not automated — customers refer peers because the product genuinely helps. Works for high-ACV products in tight-knit communities.

Examples:
- **Notion** (early days) — every designer told every other designer
- **Figma** (early days) — collaborative nature made sharing mandatory
- **Linear** — product people recommended to product people
- **Cursor** — developer-to-developer recommendation

Indie SaaS can build this by:
- Making the product so delightful that users WANT to share (rare)
- Adding explicit referral programs (cash reward, feature unlock, credit)
- Building into communities where customers peer-recommend (Slack groups, Discord, subreddits)

## The five conditions for a working loop

Not every product has a viable loop. A loop works when all five are true:

1. **Natural share trigger.** A moment in the product when sharing makes sense for the user (sending a Calendly link, inviting a teammate to Slack, sharing a Typeform).
2. **Low friction to share.** One click. No copy-paste. No "let me find my friend's email."
3. **High value to recipient.** The recipient gets real value, not spam. Calendly link = "I can schedule a meeting with this person." High value.
4. **Clear attribution.** When the recipient converts, you can trace it back to the sharer. Without this, you can't optimize the loop.
5. **Loop is faster than churn.** If users take 60 days to churn but the loop cycles every 90 days, you lose users faster than you gain them. The loop must cycle faster than the churn rate.

Most indie SaaS fail condition 1 or 3. Their product has no natural share trigger, so they bolt on artificial referral programs that don't work.

## The "bolted-on referral program" trap

Every indie founder tries this: "Give a friend 20% off, you get $10 credit." Adoption: <1%. Conversion: <1% of that. Result: near-zero.

Why it fails: the referral isn't natural. There's no moment in the product where sharing makes sense. Users have to stop, think about who to send it to, copy a link, and convince their friend. That's work, and $10 isn't enough motivation.

When referral programs DO work:
- The referrer gets MASSIVE value (Dropbox gave real storage; Robinhood gave real stocks)
- The recipient gets something they actually want at the moment
- The referral is one click, not "copy this code and share it"
- The product has enough reach that many users have friends who'd want it
- There's a social context where sharing feels natural (e.g., "everyone on our team should use this")

If you're not hitting all five, skip the referral program. It's a distraction.

## The "publish their work" loop (content loop for B2B SaaS)

This is the most underused loop pattern for B2B indie SaaS. The idea:
1. Users create something in your product (a report, a template, a dashboard, a calculation)
2. You let them publish it publicly (on a subdomain or public URL)
3. The public URL is SEO-optimized
4. When others find it via Google, they see "Made with [your product]" and sign up

Examples you can copy:
- **Notion templates** — public pages users share; SEO for "best notion template for X"
- **Airtable bases** — public bases discoverable via search
- **Typeform forms** — every live form is a public page
- **Gumroad product pages** — every product is SEO-indexed
- **Canva templates** — user-created templates in the library

For indie SaaS: if your product creates ANYTHING (content, dashboards, pages, reports), consider adding a "publish" option. Most indies skip this because it feels like extra work. It's the cheapest growth loop you can build.

## The "onboarding to activation" bottleneck

Loops only work if users reach the "share" moment. Most users don't. They sign up, poke around, leave, and never return. A loop with a broken onboarding is a loop with no input.

Focus on **activation** before scale:
- What's the one action a new user must do to experience the product's value? (For Slack: send 2000 team messages. For Dropbox: install on two devices. For Calendly: schedule one meeting.)
- What % of new users currently do that action?
- Where do they drop off?
- What's the 3-step shortest path from signup to activation?

If activation rate is < 30%, your loop can't compound because most users never reach the share trigger. Fix activation first, then optimize the loop.

## The network effect vs. growth loop distinction

They're related but different.
- **Growth loop:** a mechanism that makes acquisition self-reinforcing.
- **Network effect:** a product gets BETTER the more users it has.

Slack has both: more users in a workspace → more valuable for each user (network effect), AND each workspace pulls more users in (growth loop).

Calendly has a growth loop but limited network effect: more Calendly users doesn't make your Calendly experience better.

Dropbox has a growth loop AND a network effect in its shared-folder features.

For indie SaaS, build the growth loop first. Network effects are harder and often require scale you don't have. A good growth loop without a network effect still compounds.

## Loop metrics that matter

For any loop you're trying to build, measure:

1. **Loop conversion rate** — of users who see the "share" moment, what % share?
2. **Invite acceptance rate** — of shares sent, what % convert to new users?
3. **Cycle time** — how long from user signup to next user signup via this loop?
4. **K-factor** — (loop conversion × invite acceptance × invites per sharing user). K > 1 = exponential; K < 1 = decay-toward-zero.
5. **Loop retention** — do invited users stick around longer, the same, or less than organic users?

K = 0.2 feels tiny but over 12 months of stacking with other channels, it meaningfully reduces CAC. K = 0.5 is good. K = 1.0 is viral. K = 1.5 is hyperviral (extremely rare).

## When NOT to bet on loops

Loops are attractive but not always achievable. Skip them when:
- Your product has no natural share trigger (e.g., password manager, personal finance tool)
- Your users are deeply individual (nobody shares their journal app)
- Sharing would be awkward or unprofessional (e.g., therapy app, HR tool)
- Your audience is too small for even a working loop to matter
- You don't have product-market fit yet (no loop compounds on a product nobody wants)

For these products, grow via content, SEO, paid, and direct outreach. No shame in it; loops are just one tool.

## Building a loop from scratch (the MVP approach)

Don't start by redesigning the whole product around a loop. Start by testing ONE loop hypothesis cheaply.

Example test: "Users want to show off their [thing]."
- Add a single "Share publicly" button to one existing feature.
- Make the public page look nice with minimal "Made with X" branding.
- Measure: how many users click share, how many pages get public visitors, how many visitors sign up.
- If the metrics work, invest more. If not, remove the button and try another hypothesis.

One month, one hypothesis, one decision. Iterate.

## The "dead loop" warning

A loop that used to work can stop working. Causes:
- Platform change (Twitter API lockdown killed many viral loops)
- Market saturation (everyone who'd invite friends already has)
- Audience shift (original users churned, new users are different)
- Competitive pressure (alternatives added the same sharing)

Audit your loop's K-factor quarterly. If it's dropping, something changed and you need to find out what.

## Loop compound examples (real numbers)

- **Calendly (estimated, pre-unicorn era):** K ~0.3. Each user exposed ~3 new people to the brand, ~10% of those eventually signed up. Compounded to $100M+ ARR with minimal ad spend.
- **Typeform (estimated):** K ~0.2. Every form shown to a respondent = potential new user. Content loop + viral loop hybrid.
- **Dropbox referral (2009-2012):** K ~0.5. Doubled user base in 15 months. The canonical referral-loop case study.
- **Linktree:** Effectively K ~1.0 for a period, because every page in the Linktree directory had their branding visible. Later reduced due to unbundling.

These are the top-tier. Most indie loops top out at K = 0.05-0.2. Still worth building — 0.1 K over 3 years is substantial.

## The loop audit for an existing product

Ask these questions of your current product:

1. Is there any moment where a user naturally exposes this product to another person? If yes, describe it.
2. When that exposure happens, is there any signal that this exposure led to a new user? (I.e., can you attribute?)
3. What's the conversion rate on that exposure?
4. How many exposures per user per month?
5. Could you 2x the number of exposures by making one product change?

If you can answer all 5 and the math works out to K > 0.1, optimize that loop. If you can't answer any, you don't have a loop — and building one requires product work, not marketing work.
