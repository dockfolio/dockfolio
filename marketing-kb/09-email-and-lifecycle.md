# 09 — Email & Lifecycle Marketing

**When to use:** When you have signups but they don't activate. When they activate but churn. When you need to communicate with users at scale. When you want the highest-ROI marketing channel that exists.

**Primary sources:** Val Geisler (email copywriter), Brennan Dunn (lifecycle email), Joanna Wiebe (Copyhackers), Lincoln Murphy (customer success), the ConvertKit/Buttondown/Mailchimp blogs, Patrick McKenzie on lifecycle email at Stripe.

## Why email is still the best channel

Email's ROI is the highest of any marketing channel, consistently, across every study for the last 20 years. Typical numbers:
- Email marketing ROI: $36-$42 per $1 spent (DMA research)
- SEO: $22 per $1 (variable, long horizon)
- Social media: $8-12 per $1 (declining over time)
- Paid ads: $2-5 per $1 (for most verticals)

Reasons:
- **Owned audience.** Nobody can deplatform you from your email list.
- **Direct access.** Email goes directly to users' inboxes; no algorithm between you and them.
- **High intent.** People who give you their email have opted in; they WANT to hear from you.
- **Lifecycle coverage.** Email can touch users at every stage: welcome, activation, expansion, reactivation, win-back.
- **Compounds.** A list of 1,000 is useful; a list of 10,000 is 10x useful. Social followers don't scale the same way.

**Key point:** For most indie SaaS, email isn't a "should I do it" question. It's "how fast can I set it up."

## The three categories of email

Don't mix these up. Each has a different purpose, different strategy, different tool.

### 1. Transactional emails

Automated, 1:1, triggered by a user action. Examples: receipt, password reset, welcome email, invoice, failed payment notification, weekly summary.

- **Goal:** confirm an action, reduce anxiety, provide utility.
- **Sender:** automated system (SendGrid, Postmark, Resend, SES).
- **Volume:** 1 per user action. Hundreds to thousands per week.
- **Metric:** delivery rate (should be > 99%), open rate (50-80% for critical ones).

Transactional email is infrastructure, not marketing. But treat it AS marketing: the welcome email is the highest-opened email a user will ever receive from you. Don't waste it on "Thanks for signing up."

### 2. Lifecycle / behavioral emails

Automated, triggered by user behavior or stage in the funnel. Examples: onboarding sequence, activation nudges, upgrade prompts, churn prevention, win-back.

- **Goal:** move users through the funnel.
- **Sender:** automation platform (ConvertKit, Customer.io, Loops, Drip).
- **Volume:** triggered per user per stage; 3-10 emails per lifecycle.
- **Metric:** conversion rate (email → target action).

This is where most of email marketing's ROI lives. Underused by indie SaaS.

### 3. Broadcast / newsletter emails

Manually created, sent to many at once. Examples: weekly newsletter, product update, blog post announcement, event invite, promo.

- **Goal:** stay top of mind, drive repeat visits, share content.
- **Sender:** ConvertKit, Buttondown, Substack, Beehiiv.
- **Volume:** 1 per week at most for most audiences.
- **Metric:** open rate (20-50% is decent), click rate (1-5%), reply rate (rare signal but valuable).

Newsletters are optional. Lifecycle emails are not.

## The minimum email setup for indie SaaS

At a minimum, send these emails. Skip any of them and you're leaving revenue on the table:

1. **Welcome email (immediate after signup)**
2. **Activation nudge (24h after signup, if not activated)**
3. **Day 3 progress check**
4. **Day 7 "how's it going + specific feature tip"**
5. **Day 14 "quick question about your experience"**
6. **Day 28 "pre-churn" email before end of trial or month 2**
7. **Paid upgrade email (if on freemium)**
8. **Billing receipt (after each payment)**
9. **Failed payment notification**
10. **Cancellation confirmation + win-back offer**

That's 10 emails, mostly automated, covering the full lifecycle. If you have these, you're ahead of ~80% of indie SaaS.

## Writing the welcome email

This is the single most important email you'll ever send. Rules:

**Subject line:** Personal, not "Welcome to [Product]." Try: "Quick question, [First name]" or "Here's how to get your first [outcome]" or just "Thanks for signing up — a few things."

**Opening:** From a real person, not "The [Product] Team." Use the founder's name and email.

**Body:**
1. Thank them (one sentence, genuine)
2. Set expectations: "Here's what you'll get from me."
3. ONE next action: "The fastest way to see value is to [specific action]. Here's a 30-second video showing how: [link]."
4. ONE question: "Reply and tell me what brought you here. I read every reply and usually reply back within 24 hours."

**Length:** 150-200 words. Short. Not a manifesto.

**Signature:** Real name. Email address (not no-reply). Personal photo if you have one.

Goal: Drive the user to ONE next action AND start a conversation. Replies to welcome emails are gold — they tell you what users actually came for.

## The activation email sequence

"Activation" = the moment a user experiences the product's core value for the first time. For Slack: sending 2,000 team messages. For Dropbox: installing on two devices. For an indie invoicing tool: creating their first invoice.

A new user who doesn't activate is essentially lost — they churn at 80-95% rates. Activation emails exist to drag users to activation.

**Email 1 (T+24 hours if not activated):**
- Subject: "Did you get stuck?"
- Body: Acknowledge they signed up but haven't taken the core action. Offer help. Link to a help article or 2-min video. Ask if they need anything.

**Email 2 (T+72 hours if still not activated):**
- Subject: Specific pain point related to the product
- Body: Educational. Share 1-2 tips OR a case study of a user like them who succeeded. Link back to the product with a clear next step.

**Email 3 (T+7 days if still not activated):**
- Subject: "Is [product] not right for you?"
- Body: Admit it might not be a fit. Ask why. Offer to answer questions. This gets replies; replies give you data on why people bounce.

**Email 4 (T+14 days if still not activated):**
- Subject: "Last thing from me"
- Body: One final offer — a personal call, a discount, a custom setup. Then either stop emailing or move them to a less-frequent nurture track.

This 4-email sequence typically recovers 10-25% of otherwise-lost signups. Doing it is easy; not doing it is a mistake.

## The "segment-of-one" principle

Every email should read like it was written for one specific person. Not "Hi valued customer" — "Hi [First name]." Not "Users who haven't used feature X" — "You haven't tried [specific feature] yet."

Personalization is NOT just "{{first_name}}" merge tags. Real personalization:
- References their actual behavior ("You created 3 invoices last week, here's a template for your fourth")
- References their stage ("Since you're in the trial, here's what most trial users need next")
- References their industry or use case if known
- Omits sections that don't apply to them

Tools that make this easy: Customer.io, Loops, Drip. ConvertKit for newsletters + basic lifecycle. For < $100/mo, Loops or Drip give you most of what you need.

## Subject lines that get opened

Subject line determines open rate. Open rate determines everything downstream. Rules:

1. **Short.** 30-50 characters. Long ones get truncated on mobile.
2. **Specific.** "Your new invoice template is ready" > "A new feature for you."
3. **Personal.** "Quick question, [First name]" feels like a human wrote it.
4. **Curiosity, not clickbait.** "Here's why most [audience] fail at [thing]" vs. "You won't believe this one weird trick."
5. **Avoid spam triggers.** "FREE," "URGENT," excessive punctuation!!!!, all caps, "$$$". Spam filters flag these.
6. **Preview text matters.** The first 80 characters of body show as preview text on mobile. Use them to extend the subject line, not waste on "View in browser."

Good subject lines, real examples:
- "One thing I want you to try in [product]"
- "A small mistake I see freelancers make constantly"
- "Did [feature] break for you?"
- "Our pricing is going up next week"
- "You + [product]: how's it going?"

Bad subject lines:
- "Newsletter #47"
- "Product update"
- "Check this out!"
- "Exciting news from [company]"
- "February 2025 digest"

## The "reply-friendly" email strategy

Most indie SaaS email is broadcast-shaped: sent from `no-reply@`, written in corporate voice, designed for one-way communication. This is a mistake.

Reply-friendly email is sent from the founder, written conversationally, explicitly asks for replies, and handles replies personally.

Benefits:
- Replies give you direct customer feedback at scale
- Replies train your email deliverability (conversation = trusted sender)
- Replies build personal relationships with customers
- Replies convert support issues into product improvements

Downside: you have to actually read and reply. That's the point.

Rule: every non-transactional email from a founder-led indie SaaS should ask a question and invite a reply. If you're not reading and replying to your user emails, you're wasting your highest-leverage insight source.

## Churn prevention emails

When a user is about to churn, you often get warning signs:
- No login in 14+ days
- Decreasing usage
- Cancelled annual → monthly
- Failed payment
- Support ticket with frustration
- Cancel button viewed but not clicked

Each of these is a trigger for a specific email:

**No login in 14+ days:**
Subject: "Everything ok with [Product]?"
Body: Short. "Noticed you haven't logged in in a while. Is there something wrong, or just busy? If there's something we could improve, I'd love to hear it."

**Failed payment:**
Subject: "Quick action needed"
Body: Warm, not threatening. "Looks like your card didn't go through — no big deal, happens all the time. Here's the link to update it: [link]. We'll try again in 3 days."

**Post-cancellation:**
Subject: "Thanks for using [Product]"
Body: Genuine thanks. Ask ONE question: "If you have 30 seconds, I'd love to know what made you cancel. I read every reply." Offer 1-month free to come back.

Churn prevention emails typically recover 10-20% of otherwise-lost revenue. High ROI for the effort.

## Newsletter strategy for indie SaaS

The question: should you have a newsletter? Answer: only if you'll commit to sending consistently.

A weekly newsletter that goes dark after 6 weeks is worse than no newsletter. Subscribers lose trust, unsubscribe rates spike, and you've burned a real asset.

If you DO run a newsletter:

1. **Pick a cadence you'll actually hit.** Weekly is ideal. Bi-weekly is fine. Monthly is OK. Irregular is bad.
2. **Pick a format and stick to it.** Every issue the same structure. Readers learn what to expect. Example format: one story, one tactic, one link, one ask.
3. **Focus on ONE audience.** Your newsletter is for your ideal customer, not everyone who signed up. Narrow beats broad.
4. **Don't just promote your product.** 70% useful content, 20% product mentions, 10% explicit calls-to-action.
5. **Measure what matters.** Open rate (aim for > 30%), click rate (aim for > 3%), reply rate (aim for > 0.5%), unsubscribe rate (< 0.5%).

## Lead magnets and list building

Building the email list is the pre-requisite to everything above. Tactics that work:

1. **Free tool as lead magnet.** Create a free calculator, generator, or mini-tool. Require email to use it. HubSpot built $1B+ this way.
2. **Downloadable template or checklist.** PDF or Notion template. "Email list growth checklist," "SEO audit template." Effective because it feels concrete.
3. **Email course.** "7-day email course on [topic]." Drips one lesson per day. Good for top-of-funnel.
4. **Newsletter itself as the lead magnet.** "Get our weekly newsletter with [specific value]." Works if the newsletter is genuinely valuable.
5. **Content upgrade.** At the bottom of a blog post, offer a related asset in exchange for email. Converts 10-30% of readers vs. 1-3% for sidebar signup forms.
6. **Webinar or workshop.** Live event, register with email. Good for B2B products.

What DOESN'T work:
- "Subscribe to our newsletter" with no compelling reason
- Popups that block content without a strong offer
- "Enter your email to read more" unless the content is worth it

## Deliverability 101

Don't skip this or your emails hit spam:

1. **SPF, DKIM, DMARC.** These are DNS records that prove you own your sending domain. Set them up ONCE via your email platform's instructions; don't skip.
2. **Warm up a new domain.** Don't blast 10,000 emails from a new domain on day 1. Ramp: 50/day → 200/day → 1000/day over 2 weeks. Spam filters watch sending volume.
3. **Use a subdomain for marketing.** `hello@go.yourproduct.com` not `hello@yourproduct.com`. Keeps marketing deliverability separate from transactional.
4. **Prune unengaged subscribers.** If someone hasn't opened an email in 6 months, remove them. Spam filters penalize low engagement rates.
5. **Clean your list.** Remove bounces, invalids, role-based addresses (info@, admin@). Use a tool like NeverBounce before big sends.
6. **Don't buy lists.** Ever. It poisons your deliverability for years.
7. **Include unsubscribe link.** Legally required (CAN-SPAM, GDPR) and practically necessary.
8. **Monitor bounce + spam complaint rates.** Bounce > 2% or spam > 0.1% = something is wrong.

## The email-to-revenue measurement

Measure email's revenue contribution with:
- **Attribution UTM params** on every link (`?utm_source=email&utm_campaign=welcome`)
- **Conversion events** in your analytics tool (signup, trial, paid)
- **Segment-based comparison** (users who got email X vs. control)
- **Monthly revenue from email** (tag all email-sourced customers)

Without measurement, you'll never know which emails work and which don't. Start measurement from day 1.

## The "don't build the list before the product" exception

Some gurus say "start your email list before the product." This is fine IF:
- You have something valuable to send (weekly content, advice, a community)
- You know who you're building for
- You'll commit to consistent sending

It's bad advice if:
- You have nothing to send
- The "list" is just a waiting list for a product that may never ship
- You'll abandon it when the product launches

A list of 500 true fans of your content converts better than a list of 5000 "we're launching soon" subscribers.
