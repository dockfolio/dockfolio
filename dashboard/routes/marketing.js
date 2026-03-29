import { existsSync } from 'fs';
import { asyncRoute, slugify, safeJSON, parseEnvFile, getMarketableApps, todayString, formatDateISO, callAnthropic, parseId, hashValue } from '../utils.js';

// SEO check definitions
const SEO_CHECKS = [
  { id: 'title', label: 'Page Title', weight: 15 },
  { id: 'title_length', label: 'Title Length (50-60 chars)', weight: 5 },
  { id: 'meta_desc', label: 'Meta Description', weight: 15 },
  { id: 'meta_desc_length', label: 'Description Length (120-160 chars)', weight: 5 },
  { id: 'og_title', label: 'OG Title', weight: 8 },
  { id: 'og_desc', label: 'OG Description', weight: 8 },
  { id: 'og_image', label: 'OG Image', weight: 10 },
  { id: 'canonical', label: 'Canonical URL', weight: 5 },
  { id: 'viewport', label: 'Viewport Meta', weight: 5 },
  { id: 'lang', label: 'HTML lang Attribute', weight: 4 },
  { id: 'sitemap', label: 'Sitemap.xml', weight: 8 },
  { id: 'robots', label: 'Robots.txt', weight: 7 },
  { id: 'favicon', label: 'Favicon', weight: 5 },
];

async function auditSEO(domain, TIMEOUT_STANDARD, TIMEOUT_QUICK) {
  const results = {};
  const issues = [];

  try {
    const res = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
      headers: { 'User-Agent': 'AppManager-SEO-Audit/1.0' },
    });
    const html = await res.text();

    const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/is);
    const title = titleMatch ? titleMatch[1].trim() : '';
    results.title = !!title;
    if (!title) issues.push({ severity: 'high', msg: 'Missing page title' });

    const titleLen = title.length;
    results.title_length = titleLen >= 30 && titleLen <= 65;
    if (title && !results.title_length) {
      issues.push({ severity: 'medium', msg: `Title length ${titleLen} chars (aim for 50-60)` });
    }

    const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i)
      || html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i);
    const desc = descMatch ? descMatch[1].trim() : '';
    results.meta_desc = !!desc;
    if (!desc) issues.push({ severity: 'high', msg: 'Missing meta description' });

    const descLen = desc.length;
    results.meta_desc_length = descLen >= 100 && descLen <= 170;
    if (desc && !results.meta_desc_length) {
      issues.push({ severity: 'medium', msg: `Description length ${descLen} chars (aim for 120-160)` });
    }

    const ogTitle = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i);
    results.og_title = !!(ogTitle && ogTitle[1]);
    if (!results.og_title) issues.push({ severity: 'medium', msg: 'Missing og:title' });

    const ogDesc = html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["']/i);
    results.og_desc = !!(ogDesc && ogDesc[1]);
    if (!results.og_desc) issues.push({ severity: 'medium', msg: 'Missing og:description' });

    const ogImage = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["']/i);
    results.og_image = !!(ogImage && ogImage[1]);
    if (!results.og_image) issues.push({ severity: 'high', msg: 'Missing og:image (critical for social sharing)' });

    const canonical = html.match(/<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']*)["']/i);
    results.canonical = !!(canonical && canonical[1]);
    if (!results.canonical) issues.push({ severity: 'low', msg: 'Missing canonical URL' });

    const viewport = html.match(/<meta[^>]*name=["']viewport["']/i);
    results.viewport = !!viewport;
    if (!viewport) issues.push({ severity: 'high', msg: 'Missing viewport meta (mobile unfriendly)' });

    const lang = html.match(/<html[^>]*lang=["']([^"']*)["']/i);
    results.lang = !!(lang && lang[1]);
    if (!results.lang) issues.push({ severity: 'low', msg: 'Missing lang attribute on <html>' });

    const favicon = html.match(/<link[^>]*rel=["'](icon|shortcut icon)["'][^>]*/i);
    results.favicon = !!favicon;
    if (!favicon) issues.push({ severity: 'low', msg: 'Missing favicon link tag' });

  } catch (err) {
    issues.push({ severity: 'high', msg: `Failed to fetch homepage: ${err.message}` });
  }

  try {
    const sRes = await fetch(`https://${domain}/sitemap.xml`, {
      signal: AbortSignal.timeout(TIMEOUT_QUICK),
      method: 'HEAD',
    });
    results.sitemap = sRes.ok;
    if (!sRes.ok) issues.push({ severity: 'medium', msg: 'No sitemap.xml found' });
  } catch {
    results.sitemap = false;
    issues.push({ severity: 'medium', msg: 'No sitemap.xml found' });
  }

  try {
    const rRes = await fetch(`https://${domain}/robots.txt`, {
      signal: AbortSignal.timeout(TIMEOUT_QUICK),
      method: 'HEAD',
    });
    results.robots = rRes.ok;
    if (!rRes.ok) issues.push({ severity: 'medium', msg: 'No robots.txt found' });
  } catch {
    results.robots = false;
    issues.push({ severity: 'medium', msg: 'No robots.txt found' });
  }

  let earned = 0;
  let total = 0;
  for (const check of SEO_CHECKS) {
    total += check.weight;
    if (results[check.id]) earned += check.weight;
  }
  const score = Math.round((earned / total) * 100);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return { score, grade, checks: results, issues };
}

// --- Stripe helpers ---

const STRIPE_API = 'https://api.stripe.com/v1';

function stripeHeaders(secretKey) {
  return { 'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64') };
}

async function paginateStripe(secretKey, endpoint, extraParams = '', maxPages = 50, TIMEOUT_MEDIUM) {
  const headers = stripeHeaders(secretKey);
  const results = [];
  let startingAfter = null;
  let pages = 0;

  do {
    let url = `${STRIPE_API}/${endpoint}?limit=100`;
    if (extraParams) url += '&' + extraParams;
    if (startingAfter) url += '&starting_after=' + startingAfter;
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MEDIUM) });
    if (!res.ok) {
      console.error(`[Stripe] ${endpoint} page ${pages} failed: ${res.status}`);
      break;
    }
    const data = await res.json();
    results.push(...(data.data || []));
    startingAfter = data.has_more ? data.data[data.data.length - 1]?.id : null;
    pages++;
    if (pages >= maxPages) break;
  } while (startingAfter);

  return results;
}

async function fetchStripeCustomers(secretKey, TIMEOUT_MEDIUM) {
  return paginateStripe(secretKey, 'customers', '', 50, TIMEOUT_MEDIUM);
}

async function fetchStripeSubscriptionsMRR(secretKey, TIMEOUT_MEDIUM) {
  const subs = await paginateStripe(secretKey, 'subscriptions', 'status=active', 50, TIMEOUT_MEDIUM);
  const mrrMap = new Map();
  for (const sub of subs) {
    const custId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id;
    if (!custId) continue;
    let mrr = 0;
    for (const item of (sub.items?.data || [])) {
      const amount = item.price?.unit_amount || 0;
      const interval = item.price?.recurring?.interval;
      if (interval === 'month') mrr += amount;
      else if (interval === 'year') mrr += Math.round(amount / 12);
    }
    mrrMap.set(custId, (mrrMap.get(custId) || 0) + mrr);
  }
  return mrrMap;
}

async function fetchStripeData(secretKey, TIMEOUT_STANDARD) {
  const headers = {
    'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64'),
  };
  const opts = { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) };

  try {
    const [balanceRes, chargesRes] = await Promise.all([
      fetch(`${STRIPE_API}/balance`, opts),
      fetch(`${STRIPE_API}/charges?limit=10`, opts),
    ]);

    const balance = balanceRes.ok ? await balanceRes.json() : null;
    const charges = chargesRes.ok ? await chargesRes.json() : null;

    const subsRes = await fetch(`${STRIPE_API}/subscriptions?status=active&limit=100`, opts);
    const subs = subsRes.ok ? await subsRes.json() : null;

    let mrr = 0;
    if (subs?.data) {
      for (const sub of subs.data) {
        for (const item of sub.items?.data || []) {
          const amount = item.price?.unit_amount || 0;
          const interval = item.price?.recurring?.interval;
          if (interval === 'month') mrr += amount;
          else if (interval === 'year') mrr += Math.round(amount / 12);
        }
      }
    }

    const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 86400;
    const revenueRes = await fetch(`${STRIPE_API}/charges?limit=100&created[gte]=${thirtyDaysAgo}`, opts);
    const revenueData = revenueRes.ok ? await revenueRes.json() : null;

    let revenue30d = 0;
    let chargeCount30d = 0;
    if (revenueData?.data) {
      for (const c of revenueData.data) {
        if (c.paid && !c.refunded) {
          revenue30d += c.amount;
          chargeCount30d++;
        }
      }
    }

    return {
      balance: balance?.available?.[0]?.amount || 0,
      pending: balance?.pending?.[0]?.amount || 0,
      currency: balance?.available?.[0]?.currency || 'eur',
      mrr,
      revenue30d,
      chargeCount30d,
      recentCharges: (charges?.data || []).slice(0, 5).map(c => ({
        amount: c.amount,
        currency: c.currency,
        status: c.paid ? (c.refunded ? 'refunded' : 'paid') : 'failed',
        created: c.created,
        description: c.description || c.metadata?.product || '',
      })),
      activeSubscriptions: subs?.data?.length || 0,
    };
  } catch (err) {
    return { error: err.message };
  }
}

// --- Plausible helpers ---

async function fetchPlausibleStats(domain, period = '30d', getPlausibleUrl, getPlausibleApiKey, cbPlausible, TIMEOUT_STANDARD) {
  try {
    const baseUrl = `${getPlausibleUrl()}/api/v1/stats`;
    const apiKey = getPlausibleApiKey();
    const headers = apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {};
    const opts = { signal: AbortSignal.timeout(TIMEOUT_STANDARD), headers };

    const [realtimeRes, aggregateRes, topPagesRes, topSourcesRes] = await Promise.all([
      fetch(`${baseUrl}/realtime/visitors?site_id=${domain}`, opts),
      fetch(`${baseUrl}/aggregate?site_id=${domain}&period=${period}&metrics=visitors,pageviews,bounce_rate,visit_duration`, opts),
      fetch(`${baseUrl}/breakdown?site_id=${domain}&period=${period}&property=event:page&limit=5&metrics=visitors`, opts),
      fetch(`${baseUrl}/breakdown?site_id=${domain}&period=${period}&property=visit:source&limit=5&metrics=visitors`, opts),
    ]);

    const realtime = realtimeRes.ok ? await realtimeRes.text() : '0';
    const aggregate = aggregateRes.ok ? await aggregateRes.json() : null;
    const topPages = topPagesRes.ok ? await topPagesRes.json() : null;
    const topSources = topSourcesRes.ok ? await topSourcesRes.json() : null;

    return {
      realtime: parseInt(realtime) || 0,
      visitors: aggregate?.results?.visitors?.value || 0,
      pageviews: aggregate?.results?.pageviews?.value || 0,
      bounceRate: aggregate?.results?.bounce_rate?.value || 0,
      visitDuration: aggregate?.results?.visit_duration?.value || 0,
      topPages: (topPages?.results || []).map(p => ({ page: p.page, visitors: p.visitors })),
      topSources: (topSources?.results || []).map(s => ({ source: s.source, visitors: s.visitors })),
    };
  } catch (err) {
    return { error: err.message, visitors: 0, pageviews: 0 };
  }
}

// --- Content pipeline helpers ---

const CONTENT_PROMPTS = {
  meta_description: (keyword, appDef) =>
    `Write a compelling meta description (150-160 chars) for "${appDef.domain}" targeting the keyword "${keyword}". Include a clear value proposition and call to action.`,
  title: (keyword, appDef) =>
    `Write an SEO-optimized page title (50-60 chars) for "${appDef.domain}" targeting "${keyword}". Make it compelling and include the brand name.`,
  blog_outline: (keyword, appDef) =>
    `Create a detailed blog post outline for an article targeting "${keyword}" for ${appDef.name} (${appDef.description || ''}). Include 5-7 H2 sections with 2-3 H3 sub-points each. Output as markdown headings only, no full content.`,
  faq_schema: (keyword, appDef) =>
    `Generate 5 FAQ questions and concise answers about "${keyword}" for ${appDef.name}. Format as a numbered list with Q: and A: prefixes. Questions should target common user queries.`,
  comparison_page: (keyword, appDef) =>
    `Outline a comparison page for "${appDef.name} vs alternatives" targeting "${keyword}". List 6-8 comparison criteria with brief notes on differentiators. Format as a markdown table outline.`,
};

function buildContentSystemPrompt(appDef, seoData) {
  const issues = seoData?.issues?.map(i => `- ${i.msg}`).join('\n') || 'No known issues';
  const m = appDef.marketing || {};
  return `You are an SEO content specialist for ${appDef.name}, a ${appDef.description || 'web application'}.
Target audience: ${m.targetAudience || 'general users'}
Tagline: ${m.tagline || ''}
Languages: ${(m.languages || ['en']).join(', ')}
Domain: ${appDef.domain}

Current SEO issues:
${issues}

Write in the primary language listed above. Be concise and conversion-focused. Output only the requested content with no meta-commentary or preamble.`;
}

function formatContentTitle(contentType, keyword) {
  return `${contentType.replace(/_/g, ' ')}: ${keyword}`;
}

function deriveKeywords(appDef) {
  const m = appDef.marketing || {};
  const keywords = [];
  if (m.tagline) keywords.push(m.tagline);
  if (m.targetAudience) {
    for (const seg of m.targetAudience.split(',')) {
      const trimmed = seg.trim();
      if (trimmed) keywords.push(`${appDef.name} for ${trimmed}`);
    }
  }
  if (appDef.description) keywords.push(appDef.description);
  return keywords.slice(0, 3);
}

// --- Email helpers ---

const EMAIL_OBFUSCATION_KEY = process.env.EMAIL_OBFUSCATION_KEY || 'dockfolio-email-obfuscate-2026';

function deobfuscateEmail(encoded) {
  const decoded = Buffer.from(encoded, 'base64').toString();
  const chars = [];
  for (let i = 0; i < decoded.length; i++) {
    chars.push(String.fromCharCode(decoded.charCodeAt(i) ^ EMAIL_OBFUSCATION_KEY.charCodeAt(i % EMAIL_OBFUSCATION_KEY.length)));
  }
  return chars.join('');
}

const DEFAULT_SEQUENCES = [
  {
    name: 'New Paid Welcome',
    segment: 'new_paid',
    app_slug: null,
    steps: [
      { delay_days: 0, subject: 'Welcome to {{appName}}!', template_key: 'new_paid_day0' },
      { delay_days: 3, subject: 'Quick tip: Get more from {{appName}}', template_key: 'new_paid_day3' },
      { delay_days: 14, subject: 'How is {{appName}} working for you?', template_key: 'new_paid_day14' },
    ]
  },
  {
    name: 'At Risk Re-engagement',
    segment: 'at_risk',
    app_slug: null,
    steps: [
      { delay_days: 0, subject: 'We miss you at {{appName}}', template_key: 'at_risk_day0' },
      { delay_days: 7, subject: 'Anything we can improve?', template_key: 'at_risk_day7' },
    ]
  },
  {
    name: 'Churned Win-Back',
    segment: 'churned',
    app_slug: null,
    steps: [
      { delay_days: 3, subject: 'We are sorry to see you go', template_key: 'churned_day3' },
      { delay_days: 14, subject: 'A special offer to come back to {{appName}}', template_key: 'churned_day14' },
    ]
  },
  {
    name: 'Cross-Sell Introduction',
    segment: 'established',
    app_slug: null,
    steps: [
      { delay_days: 30, subject: 'Discover more tools from our portfolio', template_key: 'crosssell_day30' },
    ]
  },
];

const EMAIL_TEMPLATES = new Map([
  ['new_paid_day0', {
    subject: 'Welcome to {{appName}}!',
    html: `<h2>Welcome aboard!</h2><p>Thank you for choosing {{appName}}. We are excited to have you.</p><p>Here are some tips to get started:</p><ul><li>Explore the main features</li><li>Check out our documentation</li><li>Reach out if you need help</li></ul><p>Best regards,<br>The {{appName}} Team</p>`,
  }],
  ['new_paid_day3', {
    subject: 'Quick tip: Get more from {{appName}}',
    html: `<h2>Did you know?</h2><p>Many of our users get the most value from {{appName}} by exploring all available features.</p><p>Take a moment to discover what else {{appName}} can do for you.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['new_paid_day14', {
    subject: 'How is {{appName}} working for you?',
    html: `<h2>Quick check-in</h2><p>You have been using {{appName}} for 2 weeks now. How is it going?</p><p>We would love to hear your feedback. Simply reply to this email.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['at_risk_day0', {
    subject: 'We miss you at {{appName}}',
    html: `<h2>It has been a while!</h2><p>We noticed you have not used {{appName}} recently. Is everything okay?</p><p>We have made some improvements that you might like. Come check them out!</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['at_risk_day7', {
    subject: 'Anything we can improve?',
    html: `<h2>Your feedback matters</h2><p>We want to make {{appName}} better for you. If there is something we can improve, please let us know by replying to this email.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['churned_day3', {
    subject: 'We are sorry to see you go',
    html: `<h2>We are sorry to see you leave</h2><p>We noticed you cancelled your {{appName}} subscription. We understand, and we hope you got value from the product.</p><p>If you ever want to come back, we will be here.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['churned_day14', {
    subject: 'A special offer to come back to {{appName}}',
    html: `<h2>Come back to {{appName}}</h2><p>We have been working hard to improve {{appName}} since you left. Would you like to give it another try?</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['crosssell_day30', {
    subject: 'Discover more tools from our portfolio',
    html: `<h2>More tools for you</h2><p>Since you enjoy {{appName}}, you might also like our other products.${process.env.BRAND_URL ? ` Check them out at ${process.env.BRAND_URL}!` : ''}</p><p>Best,<br>The ${process.env.BRAND_NAME || 'Dockfolio'} Team</p>`,
  }],
]);

// --- Playbook helpers ---

function buildPlaybookPrompt(appDef, seoAudit, revenueData) {
  return `You are a marketing strategist for a portfolio of SaaS/tool apps.
Generate a marketing playbook for ${appDef.name} (${appDef.domain}).

App details:
- Description: ${appDef.description}
- Tech: ${appDef.tech || 'Unknown'}
- Target audience: ${appDef.marketing?.targetAudience || 'General'}
- Languages: ${(appDef.marketing?.languages || ['en']).join(', ')}
- Tagline: ${appDef.marketing?.tagline || 'N/A'}
${seoAudit ? `- Current SEO score: ${seoAudit.score}/100 (Grade: ${seoAudit.grade})` : '- SEO: not yet audited'}
${revenueData ? `- Recent revenue data: ${revenueData.value}` : '- Revenue: no data yet'}

Generate 6 sections. For each section, output a JSON object on its own line with fields: section, title, content (markdown).

Sections needed:
1. section:"strategy" Positioning, key differentiator, 3-month goals (3-5 bullets each)
2. section:"channels" Ranked marketing channels with effort/impact ratings
3. section:"content" 5 blog post topics, 3 social media angles, video ideas
4. section:"seo" Specific SEO action items based on current score
5. section:"email" Onboarding (3 emails), activation (2 emails), retention (2 emails), just subject lines + timing
6. section:"crosssell" How to cross-promote with related apps in the portfolio

Output ONLY a JSON array of 6 objects, no other text. Each object: {"section":"...", "title":"...", "content":"..."}`;
}

function parseAIJsonArray(text) {
  text = text.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();
  const jsonMatch = text.match(/\[[\s\S]*\]/);
  let jsonStr = jsonMatch ? jsonMatch[0] : text;
  try {
    return JSON.parse(jsonStr);
  } catch (_) {
    jsonStr = jsonStr.replace(/,\s*\{[^}]*$/, '').replace(/,\s*$/, '');
    if (!jsonStr.endsWith(']')) jsonStr += ']';
    return JSON.parse(jsonStr);
  }
}

export default function registerMarketingRoutes({
  app, db, config, cron,
  findAppBySlug, getSetting, getEnvKeyFromApps, getBannerForgeUrl, setCORS,
  cbStripe, cbPlausible, cbAnthropic,
  rlBannerServe, rlBannerTrack,
  upsertMetric, upsertSEOAudit, qLatestMetric, qLatestSEO,
  cronFail, sendTelegram,
  TIMEOUT_QUICK, TIMEOUT_STANDARD, TIMEOUT_MEDIUM, TIMEOUT_AI,
  MS_PER_HOUR, MS_PER_DAY,
}) {
  // --- Shared mutable state ---
  let cachedSEO = null;
  let lastSEOUpdate = 0;
  const SEO_TTL = MS_PER_HOUR;

  let cachedRevenue = null;
  let lastRevenueUpdate = 0;
  const REVENUE_TTL = 300_000;

  let cachedAnalytics = null;
  let lastAnalyticsUpdate = 0;
  const ANALYTICS_TTL = 300_000;

  // Expose cache getters for other modules (e.g. briefing)
  const cache = {
    get seo() { return cachedSEO; },
    get revenue() { return cachedRevenue; },
    get analytics() { return cachedAnalytics; },
  };

  function getAnthropicKey() { return getEnvKeyFromApps('ANTHROPIC_API_KEY'); }
  function getResendKey() { return getEnvKeyFromApps('RESEND_API_KEY'); }

  function getPlausibleUrl() { return getSetting('PLAUSIBLE_URL') || process.env.PLAUSIBLE_URL || 'http://plausible-plausible-1:8000'; }
  function getPlausibleApiKey() { return getSetting('PLAUSIBLE_API_KEY') || process.env.PLAUSIBLE_API_KEY || ''; }

  function getStripeKeys() {
    const keys = new Map();
    const appKeys = new Map();
    for (const appDef of config.apps) {
      if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
      const vars = parseEnvFile(appDef.envFile);
      const sk = vars.find(v => v.key === 'STRIPE_SECRET_KEY' && v.value);
      if (sk) {
        appKeys.set(appDef.name, sk.value);
        if (!keys.has(sk.value)) keys.set(sk.value, []);
        keys.get(sk.value).push(appDef.name);
      }
    }
    if (keys.size === 0) {
      const dbKey = getSetting('STRIPE_SECRET_KEY');
      if (dbKey) {
        keys.set(dbKey, ['(global)']);
        appKeys.set('(global)', dbKey);
      }
    }
    return { keys, appKeys };
  }

  async function generateContent(appSlug, contentType, keyword) {
    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) throw new Error('No Anthropic API key found in any app .env file');

    const appDef = findAppBySlug(appSlug);
    if (!appDef) throw new Error(`App not found: ${appSlug}`);

    const promptFn = CONTENT_PROMPTS[contentType];
    if (!promptFn) throw new Error(`Unknown content type: ${contentType}`);

    const seoData = cachedSEO?.apps?.[appDef.name];
    const systemPrompt = buildContentSystemPrompt(appDef, seoData);
    const userPrompt = promptFn(keyword, appDef);

    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      model: 'claude-sonnet-4-20250514', maxTokens: 1024, timeout: TIMEOUT_AI,
      system: systemPrompt, messages: [{ role: 'user', content: userPrompt }],
    }));

    return { body: ai.text, tokenCount: ai.tokens };
  }

  function getEmailTemplate(templateKey, appSlug) {
    const template = EMAIL_TEMPLATES.get(templateKey);
    if (!template) return { subject: 'Update from your app', html: '<p>Hello!</p>' };
    const appDef = findAppBySlug(appSlug);
    const appName = appDef?.name || appSlug;
    return {
      subject: template.subject.replace(/\{\{appName\}\}/g, appName),
      html: template.html.replace(/\{\{appName\}\}/g, appName),
    };
  }

  function seedDefaultSequences() {
    const count = db.prepare('SELECT COUNT(*) as n FROM email_sequences').get().n;
    if (count > 0) return;
    const insert = db.prepare('INSERT INTO email_sequences (name, segment, app_slug, active, steps) VALUES (?, ?, ?, ?, ?)');
    for (const seq of DEFAULT_SEQUENCES) {
      insert.run(seq.name, seq.segment, seq.app_slug, 0, JSON.stringify(seq.steps));
    }
    console.log(`[STARTUP] Seeded ${DEFAULT_SEQUENCES.length} default email sequences (all inactive)`);
  }
  seedDefaultSequences();

  async function sendEmail(toEmail, subject, htmlBody, appSlug) {
    const resendKey = getResendKey();
    if (!resendKey) throw new Error('No Resend API key found');

    const today = todayString();
    const sentToday = db.prepare(
      "SELECT COUNT(*) as n FROM email_queue WHERE status='sent' AND sent_at >= ?"
    ).get(today + 'T00:00:00Z').n;
    if (sentToday >= 95) throw new Error('Daily email cap reached (95/100)');

    const appDef = findAppBySlug(appSlug);
    const fromName = appDef?.name || 'Dockfolio';
    const fromDomain = process.env.EMAIL_FROM_DOMAIN || appDef?.domain;
    if (!fromDomain) {
      throw new Error('No email domain configured (set EMAIL_FROM_DOMAIN or add domain to app config)');
    }

    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${resendKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `${fromName} <noreply@${fromDomain}>`,
        to: [toEmail],
        subject,
        html: htmlBody,
      }),
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || `Resend error ${res.status}`);
    }
    return await res.json();
  }

  const upsertCustomer = db.prepare(`
    INSERT INTO customer_graph (email_hash, app_slug, stripe_customer_id, stripe_key_hash, mrr, first_seen, last_active, plan_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(email_hash, app_slug) DO UPDATE SET
      mrr = excluded.mrr, last_active = excluded.last_active, plan_name = excluded.plan_name
  `);

  async function collectCustomerGraph() {
    console.log('[CRON] Collecting customer graph...');
    const { keys } = getStripeKeys();
    const today = todayString();
    let totalCustomers = 0;

    for (const [stripeKey, appNames] of keys) {
      try {
        const keyHash = hashValue(stripeKey);
        const [customers, mrrMap] = await Promise.all([
          fetchStripeCustomers(stripeKey, TIMEOUT_MEDIUM),
          fetchStripeSubscriptionsMRR(stripeKey, TIMEOUT_MEDIUM)
        ]);

        for (const customer of customers) {
          if (!customer.email) continue;
          const emailHash = hashValue(customer.email.toLowerCase(), 64);
          const mrr = mrrMap.get(customer.id) || 0;
          const firstSeen = new Date(customer.created * 1000).toISOString().slice(0, 10);

          for (const appName of appNames) {
            upsertCustomer.run(emailHash, slugify(appName), customer.id, keyHash, mrr, firstSeen, today, null);
          }
          totalCustomers++;
        }
      } catch (err) {
        console.error(`[CRON] Customer graph error for ${appNames.join(',')}:`, err.message);
      }
    }

    console.log(`[CRON] Customer graph updated: ${totalCustomers} customers processed`);
  }

  // =============================================
  // SEO Routes
  // =============================================

  app.get('/api/marketing/seo', asyncRoute(async (req, res) => {
    const now = Date.now();
    const force = req.query.force === 'true';
    if (!force && cachedSEO && (now - lastSEOUpdate) < SEO_TTL) {
      return res.json(cachedSEO);
    }

    const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const results = {};

    await Promise.all(marketableApps.map(async (appDef) => {
      const audit = await auditSEO(appDef.domain, TIMEOUT_STANDARD, TIMEOUT_QUICK);
      results[appDef.name] = {
        domain: appDef.domain,
        ...audit,
        marketing: appDef.marketing || null,
      };
    }));

    const scores = Object.values(results).map(r => r.score);
    const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    const totalIssues = Object.values(results).reduce((sum, r) => sum + r.issues.length, 0);

    cachedSEO = {
      apps: results,
      summary: { avgScore, totalIssues, appCount: scores.length },
      timestamp: new Date().toISOString(),
    };
    lastSEOUpdate = now;
    res.json(cachedSEO);
  }));

  // =============================================
  // Overview
  // =============================================

  app.get('/api/marketing/overview', asyncRoute(async (_req, res) => {
    const overview = config.apps.map(appDef => {
      const slug = slugify(appDef.name);

      const mrrRow = qLatestMetric.get(slug, 'mrr');
      const revRow = qLatestMetric.get(slug, 'revenue');
      const trafficData = cachedAnalytics?.apps?.[appDef.name] || null;
      const secRow = db.prepare('SELECT overall_score as score, grade FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
      const seoRow = qLatestSEO.get(slug);
      const openTasks = db.prepare("SELECT COUNT(*) as n FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.n || 0;
      const doneTasks = db.prepare("SELECT COUNT(*) as n FROM project_tasks WHERE app_slug = ? AND status = 'done'").get(slug)?.n || 0;
      const roadmapItems = db.prepare("SELECT COUNT(*) as n FROM project_roadmap WHERE app_slug = ?").get(slug)?.n || 0;
      const roadmapShipped = db.prepare("SELECT COUNT(*) as n FROM project_roadmap WHERE app_slug = ? AND status = 'shipped'").get(slug)?.n || 0;
      const bannerCount = db.prepare("SELECT COUNT(*) as n FROM banner_placements WHERE app_slug = ? AND status = 'active'").get(slug)?.n || 0;
      const meta = db.prepare('SELECT lifecycle, priority, revenue_goal_mrr as revenue_goal, traffic_goal_mpv as traffic_goal, user_goal FROM project_meta WHERE app_slug = ?').get(slug);

      return {
        name: appDef.name, slug, type: appDef.type, domain: appDef.domain,
        description: appDef.description, marketing: appDef.marketing || null,
        revenue: { mrrCents: mrrRow?.value || 0, revenue30dCents: revRow?.value || 0 },
        traffic: {
          visitors30d: trafficData?.visitors || 0,
          pageviews30d: trafficData?.pageviews || 0,
          realtime: trafficData?.realtime || 0,
        },
        security: secRow ? { score: secRow.score, grade: secRow.grade } : null,
        seo: seoRow ? { score: seoRow.score } : null,
        tasks: { open: openTasks, done: doneTasks },
        roadmap: { total: roadmapItems, shipped: roadmapShipped },
        bannerPlacements: bannerCount,
        project: meta || null,
      };
    });

    const totalMRR = overview.reduce((s, a) => s + (a.revenue.mrrCents || 0), 0);
    const totalRevenue30d = overview.reduce((s, a) => s + (a.revenue.revenue30dCents || 0), 0);
    const totalVisitors30d = overview.reduce((s, a) => s + (a.traffic.visitors30d || 0), 0);
    const totalOpenTasks = overview.reduce((s, a) => s + a.tasks.open, 0);

    res.json({
      apps: overview,
      totals: {
        appCount: overview.length,
        mrrCents: totalMRR,
        revenue30dCents: totalRevenue30d,
        visitors30d: totalVisitors30d,
        openTasks: totalOpenTasks,
      },
      timestamp: new Date().toISOString(),
    });
  }));

  // =============================================
  // Revenue
  // =============================================

  app.get('/api/marketing/revenue', asyncRoute(async (req, res) => {
    const now = Date.now();
    const force = req.query.force === 'true';
    if (!force && cachedRevenue && (now - lastRevenueUpdate) < REVENUE_TTL) {
      return res.json(cachedRevenue);
    }

    const { keys, appKeys } = getStripeKeys();
    const results = {};
    let totalMRR = 0, totalRevenue30d = 0, totalBalance = 0;

    const keyResults = new Map();
    for (const [key, appNames] of keys) {
      const data = await cbStripe.call(() => fetchStripeData(key, TIMEOUT_STANDARD));
      keyResults.set(key, data);
    }

    for (const [appName, key] of appKeys) {
      const data = keyResults.get(key);
      if (!data) continue;
      const appsWithKey = keys.get(key);
      results[appName] = {
        ...data,
        shared: appsWithKey.length > 1,
        sharedWith: appsWithKey.filter(n => n !== appName),
      };
      if (appsWithKey[0] === appName) {
        totalMRR += data.mrr || 0;
        totalRevenue30d += data.revenue30d || 0;
        totalBalance += data.balance || 0;
      }
    }

    cachedRevenue = {
      apps: results,
      totals: {
        mrr: totalMRR,
        revenue30d: totalRevenue30d,
        balance: totalBalance,
        currency: 'eur',
      },
      timestamp: new Date().toISOString(),
    };
    lastRevenueUpdate = now;

    const today = todayString();
    try {
      upsertMetric.run('_total', today, 'mrr', totalMRR / 100, null);
      upsertMetric.run('_total', today, 'revenue_30d', totalRevenue30d / 100, null);
      for (const [appName, data] of Object.entries(results)) {
        if (data.mrr != null) upsertMetric.run(slugify(appName), today, 'mrr', data.mrr / 100, null);
      }
    } catch (err) { console.error('[METRICS] Revenue snapshot failed:', err.message); }

    res.json(cachedRevenue);
  }));

  // =============================================
  // Analytics (Plausible)
  // =============================================

  app.get('/api/marketing/analytics', asyncRoute(async (req, res) => {
    const now = Date.now();
    const force = req.query.force === 'true';
    if (!force && cachedAnalytics && (now - lastAnalyticsUpdate) < ANALYTICS_TTL) {
      return res.json(cachedAnalytics);
    }

    const trackableApps = config.apps.filter(a =>
      (a.type === 'saas' || a.type === 'tool' || a.type === 'static') && a.domain
    );

    const results = {};
    let totalVisitors = 0, totalPageviews = 0, totalRealtime = 0;

    await Promise.all(trackableApps.map(async (appDef) => {
      const stats = await cbPlausible.call(() => fetchPlausibleStats(appDef.domain, '30d', getPlausibleUrl, getPlausibleApiKey, cbPlausible, TIMEOUT_STANDARD));
      results[appDef.name] = { domain: appDef.domain, ...stats };
      totalVisitors += stats.visitors || 0;
      totalPageviews += stats.pageviews || 0;
      totalRealtime += stats.realtime || 0;
    }));

    cachedAnalytics = {
      apps: results,
      totals: { visitors: totalVisitors, pageviews: totalPageviews, realtime: totalRealtime },
      timestamp: new Date().toISOString(),
    };
    lastAnalyticsUpdate = now;

    const today = todayString();
    try {
      upsertMetric.run('_total', today, 'visitors', totalVisitors, null);
      upsertMetric.run('_total', today, 'pageviews', totalPageviews, null);
      for (const [appName, data] of Object.entries(results)) {
        if (data.visitors != null) upsertMetric.run(slugify(appName), today, 'visitors', data.visitors, null);
      }
    } catch (err) { console.error('[METRICS] Analytics snapshot failed:', err.message); }

    res.json(cachedAnalytics);
  }));

  // =============================================
  // Trends
  // =============================================

  app.get('/api/marketing/trends', asyncRoute((req, res) => {
    const days = Math.min(parseInt(req.query.days) || 30, 365);
    const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);

    const rows = db.prepare(`
      SELECT app_slug, date, metric_type, value
      FROM metrics_daily
      WHERE date >= ?
      ORDER BY date ASC
    `).all(cutoff);

    const grouped = {};
    for (const row of rows) {
      const key = `${row.app_slug}::${row.metric_type}`;
      if (!grouped[key]) grouped[key] = { app: row.app_slug, metric: row.metric_type, data: [] };
      grouped[key].data.push({ date: row.date, value: row.value });
    }

    res.json({ trends: Object.values(grouped), days });
  }));

  // =============================================
  // Charts
  // =============================================

  app.get('/api/charts/revenue', asyncRoute((req, res) => {
    const days = Math.min(parseInt(req.query.days) || 30, 365);
    const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);
    const rows = db.prepare(`
      SELECT app_slug, date, value FROM metrics_daily
      WHERE metric_type = 'mrr' AND date >= ?
      ORDER BY date ASC
    `).all(cutoff);
    const apps = {};
    const labels = new Set();
    for (const row of rows) {
      labels.add(row.date);
      if (!apps[row.app_slug]) apps[row.app_slug] = {};
      apps[row.app_slug][row.date] = row.value / 100;
    }
    const sortedLabels = [...labels].sort();
    const datasets = Object.entries(apps).map(([slug, data]) => ({
      label: slug,
      data: sortedLabels.map(d => data[d] || 0)
    }));
    const totalData = sortedLabels.map(d => datasets.reduce((sum, ds) => sum + (ds.data[sortedLabels.indexOf(d)] || 0), 0));
    res.json({ labels: sortedLabels, datasets, total: totalData });
  }));

  app.get('/api/charts/traffic', asyncRoute((req, res) => {
    const days = Math.min(parseInt(req.query.days) || 30, 365);
    const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);
    const rows = db.prepare(`
      SELECT app_slug, date, visitors, pageviews FROM analytics_daily
      WHERE date >= ?
      ORDER BY date ASC
    `).all(cutoff);
    const labels = new Set();
    const visitors = {};
    const pageviews = {};
    for (const row of rows) {
      labels.add(row.date);
      if (!visitors[row.app_slug]) { visitors[row.app_slug] = {}; pageviews[row.app_slug] = {}; }
      visitors[row.app_slug][row.date] = row.visitors || 0;
      pageviews[row.app_slug][row.date] = row.pageviews || 0;
    }
    const sortedLabels = [...labels].sort();
    const visitorDatasets = Object.entries(visitors).map(([slug, data]) => ({
      label: slug, data: sortedLabels.map(d => data[d] || 0)
    }));
    const totalVisitors = sortedLabels.map(d => visitorDatasets.reduce((sum, ds) => sum + (ds.data[sortedLabels.indexOf(d)] || 0), 0));
    res.json({ labels: sortedLabels, visitors: visitorDatasets, totalVisitors });
  }));

  app.get('/api/charts/errors', asyncRoute((req, res) => {
    const days = Math.min(parseInt(req.query.days) || 7, 365);
    const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);
    const rows = db.prepare(`
      SELECT date(timestamp) as day, severity, COUNT(*) as count
      FROM error_events
      WHERE timestamp >= ?
      GROUP BY day, severity
      ORDER BY day ASC
    `).all(cutoff);
    const labels = new Set();
    const bySeverity = {};
    for (const row of rows) {
      labels.add(row.day);
      if (!bySeverity[row.severity]) bySeverity[row.severity] = {};
      bySeverity[row.severity][row.day] = row.count;
    }
    const sortedLabels = [...labels].sort();
    const datasets = Object.entries(bySeverity).map(([sev, data]) => ({
      label: sev, data: sortedLabels.map(d => data[d] || 0)
    }));
    res.json({ labels: sortedLabels, datasets });
  }));

  app.get('/api/charts/latency', asyncRoute((req, res) => {
    const hours = Math.min(parseInt(req.query.hours) || 168, 8760);
    const cutoff = new Date(Date.now() - hours * MS_PER_HOUR).toISOString().slice(0, 13);
    const rows = db.prepare(`
      SELECT hour, SUM(request_count) as requests,
             AVG(p50_ms) as p50, AVG(p95_ms) as p95, AVG(p99_ms) as p99
      FROM perf_metrics
      WHERE hour >= ?
      GROUP BY hour
      ORDER BY hour ASC
    `).all(cutoff);
    res.json({
      labels: rows.map(r => r.hour),
      p50: rows.map(r => Math.round(r.p50 || 0)),
      p95: rows.map(r => Math.round(r.p95 || 0)),
      p99: rows.map(r => Math.round(r.p99 || 0)),
      requests: rows.map(r => r.requests)
    });
  }));

  app.get('/api/charts/uptime', asyncRoute((req, res) => {
    const days = Math.min(parseInt(req.query.days) || 7, 365);
    const cutoff = new Date(Date.now() - days * MS_PER_DAY).toISOString();
    const rows = db.prepare(`
      SELECT app_slug, strftime('%Y-%m-%d %H:00', checked_at) as hour,
             SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count,
             SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END) as down_count,
             AVG(response_ms) as avg_response
      FROM uptime_history
      WHERE checked_at >= ?
      GROUP BY app_slug, hour
      ORDER BY hour ASC
    `).all(cutoff);
    const apps = {};
    for (const row of rows) {
      if (!apps[row.app_slug]) apps[row.app_slug] = [];
      apps[row.app_slug].push({
        hour: row.hour,
        status: row.down_count > 0 ? 'down' : 'up',
        avgMs: Math.round(row.avg_response || 0)
      });
    }
    res.json({ apps, days });
  }));

  app.get('/api/charts/sparklines', asyncRoute((req, res) => {
    const cutoff = new Date(Date.now() - 24 * MS_PER_HOUR).toISOString();
    const rows = db.prepare(`
      SELECT container_name, app_slug, ts, cpu, memory
      FROM container_metrics
      WHERE ts >= ?
      ORDER BY ts ASC
    `).all(cutoff);
    const containers = {};
    for (const row of rows) {
      if (!containers[row.container_name]) containers[row.container_name] = { app_slug: row.app_slug, cpu: [], memory: [] };
      containers[row.container_name].cpu.push(row.cpu);
      containers[row.container_name].memory.push(row.memory);
    }
    res.json(containers);
  }));

  // =============================================
  // Health
  // =============================================

  app.get('/api/marketing/health', asyncRoute(async (req, res) => {
    const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const scores = {};

    for (const appDef of marketableApps) {
      let score = 50;
      const factors = {};

      if (cachedSEO?.apps?.[appDef.name]) {
        const seoScore = cachedSEO.apps[appDef.name].score;
        factors.seo = seoScore;
        score += (seoScore - 50) * 0.3;
      }

      if (cachedRevenue?.apps?.[appDef.name]) {
        const rev = cachedRevenue.apps[appDef.name];
        if (rev.mrr > 0) {
          factors.mrr = rev.mrr / 100;
          score += 15;
        }
        if (rev.activeSubscriptions > 0) {
          factors.subscriptions = rev.activeSubscriptions;
          score += 5;
        }
      }

      if (cachedAnalytics?.apps?.[appDef.name]) {
        const analytics = cachedAnalytics.apps[appDef.name];
        if (analytics.visitors > 100) score += 10;
        else if (analytics.visitors > 10) score += 5;
        factors.visitors = analytics.visitors;
      }

      scores[appDef.name] = {
        score: Math.max(0, Math.min(100, Math.round(score))),
        factors,
      };
    }

    const avgScore = Object.values(scores).length > 0
      ? Math.round(Object.values(scores).reduce((s, v) => s + v.score, 0) / Object.values(scores).length)
      : 0;

    res.json({ apps: scores, avgScore, timestamp: new Date().toISOString() });
  }));

  // =============================================
  // Content Pipeline
  // =============================================

  app.get('/api/marketing/content', asyncRoute((_req, res) => {
    const { app_slug, status } = _req.query;
    let where = '1=1';
    const params = [];
    if (app_slug) { where += ' AND app_slug = ?'; params.push(app_slug); }
    if (status) { where += ' AND status = ?'; params.push(status); }

    const items = db.prepare(`SELECT * FROM content_queue WHERE ${where} ORDER BY created_at DESC LIMIT 100`).all(...params);
    const counts = db.prepare(`SELECT status, COUNT(*) as count FROM content_queue GROUP BY status`).all();
    const countMap = {};
    for (const c of counts) countMap[c.status] = c.count;

    res.json({ items, counts: countMap });
  }));

  app.post('/api/marketing/content/generate', asyncRoute(async (req, res) => {
    const { app_slug, content_type, keyword } = req.body;
    if (!app_slug || !content_type || !keyword) {
      return res.status(400).json({ error: 'app_slug, content_type, and keyword are required' });
    }

    console.log(`[CONTENT] Generating ${content_type} for ${app_slug} (keyword: ${keyword})`);
    const { body, tokenCount } = await generateContent(app_slug, content_type, keyword);
    const title = formatContentTitle(content_type, keyword);

    const result = db.prepare(`
      INSERT INTO content_queue (app_slug, content_type, keyword, title, body, token_count)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(app_slug, content_type, keyword, title, body, tokenCount);

    console.log(`[CONTENT] Generated id=${result.lastInsertRowid}, tokens=${tokenCount}`);
    res.json({ ok: true, id: result.lastInsertRowid, body, tokenCount });
  }));

  app.patch('/api/marketing/content/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid content ID' });

    const { status, published_at } = req.body;
    const validStatuses = ['draft', 'approved', 'published', 'rejected'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` });
    }

    if (status === 'published' && published_at) {
      db.prepare('UPDATE content_queue SET status = ?, published_at = ? WHERE id = ?').run(status, published_at, id);
    } else {
      db.prepare('UPDATE content_queue SET status = ? WHERE id = ?').run(status, id);
    }

    res.json({ ok: true });
  }));

  app.delete('/api/marketing/content/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid content ID' });
    const result = db.prepare('DELETE FROM content_queue WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Content not found' });
    res.json({ ok: true });
  }));

  // =============================================
  // Cohorts
  // =============================================

  app.get('/api/marketing/cohorts', asyncRoute((_req, res) => {
    const totalUnique = db.prepare('SELECT COUNT(DISTINCT email_hash) as n FROM customer_graph').get().n;
    const multiApp = db.prepare(`
      SELECT email_hash, COUNT(DISTINCT app_slug) as app_count, GROUP_CONCAT(DISTINCT app_slug) as apps
      FROM customer_graph GROUP BY email_hash HAVING app_count >= 2
    `).all();

    const singleAppCustomers = totalUnique - multiApp.length;
    const powerUsers = multiApp.filter(r => r.app_count >= 3).length;

    const overlapMatrix = {};
    for (const row of multiApp) {
      const apps = row.apps.split(',');
      for (let i = 0; i < apps.length; i++) {
        for (let j = i + 1; j < apps.length; j++) {
          if (!overlapMatrix[apps[i]]) overlapMatrix[apps[i]] = {};
          if (!overlapMatrix[apps[j]]) overlapMatrix[apps[j]] = {};
          overlapMatrix[apps[i]][apps[j]] = (overlapMatrix[apps[i]][apps[j]] || 0) + 1;
          overlapMatrix[apps[j]][apps[i]] = (overlapMatrix[apps[j]][apps[i]] || 0) + 1;
        }
      }
    }

    const lastUpdated = db.prepare('SELECT MAX(last_active) as d FROM customer_graph').get()?.d;

    res.json({
      summary: {
        totalUniqueCustomers: totalUnique,
        singleAppCustomers,
        multiAppCustomers: multiApp.length,
        powerUsers,
        lastUpdated,
      },
      overlapMatrix,
    });
  }));

  app.get('/api/marketing/cohorts/crosssell', asyncRoute((_req, res) => {
    const appCustomerCounts = db.prepare(
      'SELECT app_slug, COUNT(DISTINCT email_hash) as customers FROM customer_graph GROUP BY app_slug'
    ).all();
    const countMap = Object.fromEntries(appCustomerCounts.map(r => [r.app_slug, r.customers]));

    const multiApp = db.prepare(`
      SELECT email_hash, GROUP_CONCAT(DISTINCT app_slug) as apps
      FROM customer_graph GROUP BY email_hash HAVING COUNT(DISTINCT app_slug) >= 2
    `).all();

    const pairOverlap = {};
    for (const row of multiApp) {
      const apps = row.apps.split(',');
      for (let i = 0; i < apps.length; i++) {
        for (let j = i + 1; j < apps.length; j++) {
          const key = [apps[i], apps[j]].sort().join('|');
          pairOverlap[key] = (pairOverlap[key] || 0) + 1;
        }
      }
    }

    const marketableSlugs = getMarketableApps(config.apps).map(a => slugify(a.name));
    const opportunities = [];

    for (let i = 0; i < marketableSlugs.length; i++) {
      for (let j = i + 1; j < marketableSlugs.length; j++) {
        const a = marketableSlugs[i], b = marketableSlugs[j];
        const key = [a, b].sort().join('|');
        const overlap = pairOverlap[key] || 0;
        const aCount = countMap[a] || 0;
        const bCount = countMap[b] || 0;
        if (aCount === 0 && bCount === 0) continue;

        const potentialReach = Math.max(0, (aCount - overlap)) + Math.max(0, (bCount - overlap));
        if (potentialReach === 0) continue;

        const appA = config.apps.find(x => slugify(x.name) === a);
        const appB = config.apps.find(x => slugify(x.name) === b);

        opportunities.push({
          label: `${appA?.name || a} ↔ ${appB?.name || b}`,
          apps: [appA?.name || a, appB?.name || b],
          reason: overlap > 0
            ? `${overlap} shared customers already — high cross-sell affinity`
            : `No overlap yet — untapped cross-sell potential`,
          existingOverlap: overlap,
          potentialReach,
        });
      }
    }

    opportunities.sort((a, b) => b.existingOverlap - a.existingOverlap || b.potentialReach - a.potentialReach);

    res.json({ opportunities });
  }));

  // =============================================
  // Email Sequences
  // =============================================

  app.get('/api/marketing/emails/sequences', asyncRoute((_req, res) => {
    const sequences = db.prepare('SELECT * FROM email_sequences ORDER BY id').all();

    const queueCounts = db.prepare(
      'SELECT sequence_id, status, COUNT(*) as n FROM email_queue GROUP BY sequence_id, status'
    ).all();
    const countsBySeq = {};
    for (const row of queueCounts) {
      if (!countsBySeq[row.sequence_id]) countsBySeq[row.sequence_id] = {};
      countsBySeq[row.sequence_id][row.status] = row.n;
    }

    const result = sequences.map(seq => ({
      ...seq,
      steps: safeJSON(seq.steps, []),
      active: !!seq.active,
      queuedCount: countsBySeq[seq.id]?.pending || 0,
      sentCount: countsBySeq[seq.id]?.sent || 0,
    }));
    res.json({ sequences: result });
  }));

  app.get('/api/marketing/emails/queue', asyncRoute((req, res) => {
    const status = req.query.status || 'pending';
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;

    const queue = db.prepare(
      'SELECT * FROM email_queue WHERE status = ? ORDER BY scheduled_at ASC LIMIT ? OFFSET ?'
    ).all(status, limit, offset);

    const counts = {};
    for (const row of db.prepare('SELECT status, COUNT(*) as n FROM email_queue GROUP BY status').all()) {
      counts[row.status] = row.n;
    }

    const today = todayString();
    const dailySentToday = db.prepare(
      "SELECT COUNT(*) as n FROM email_queue WHERE status='sent' AND sent_at >= ?"
    ).get(today + 'T00:00:00Z').n;

    res.json({ queue, counts, dailySentToday, dailyLimit: 100 });
  }));

  app.post('/api/marketing/emails/send-test', asyncRoute(async (req, res) => {
    const { template_key, app_slug, to_email } = req.body;
    if (!template_key || !app_slug || !to_email) {
      return res.status(400).json({ error: 'template_key, app_slug, and to_email are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to_email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }

    console.log(`[EMAIL] Sending test email to ${to_email} (template: ${template_key}, app: ${app_slug})`);
    const template = getEmailTemplate(template_key, app_slug);
    const result = await sendEmail(to_email, template.subject, template.html, app_slug);
    console.log(`[EMAIL] Test email sent, messageId=${result.id}`);
    res.json({ ok: true, messageId: result.id });
  }));

  app.get('/api/marketing/emails/analytics', asyncRoute(async (_req, res) => {
    const totalSent = db.prepare("SELECT COUNT(*) as n FROM email_queue WHERE status = 'sent'").get().n;
    const totalPending = db.prepare("SELECT COUNT(*) as n FROM email_queue WHERE status = 'pending'").get().n;
    const totalFailed = db.prepare("SELECT COUNT(*) as n FROM email_queue WHERE status = 'failed'").get().n;

    const byApp = db.prepare(`
      SELECT app_slug, status, COUNT(*) as count
      FROM email_queue
      GROUP BY app_slug, status
      ORDER BY app_slug
    `).all();

    const appStats = {};
    for (const row of byApp) {
      if (!appStats[row.app_slug]) appStats[row.app_slug] = { sent: 0, pending: 0, failed: 0 };
      appStats[row.app_slug][row.status] = (appStats[row.app_slug][row.status] || 0) + row.count;
    }

    const dailyVolume = db.prepare(`
      SELECT date(sent_at) as day, COUNT(*) as count
      FROM email_queue
      WHERE status = 'sent' AND sent_at >= datetime('now', '-30 days')
      GROUP BY date(sent_at)
      ORDER BY day ASC
    `).all();

    const byTemplate = db.prepare(`
      SELECT template_key, COUNT(*) as count
      FROM email_queue
      WHERE status = 'sent'
      GROUP BY template_key
      ORDER BY count DESC
      LIMIT 10
    `).all();

    let resendDomains = null;
    try {
      const resendKey = getSetting('RESEND_FULL_ACCESS_KEY') || getResendKey();
      if (resendKey) {
        const r = await fetch('https://api.resend.com/domains', {
          headers: { Authorization: `Bearer ${resendKey}` },
          signal: AbortSignal.timeout(5000),
        });
        if (r.ok) {
          const data = await r.json();
          resendDomains = (data.data || []).map(d => ({
            name: d.name, status: d.status, region: d.region, created: d.created_at,
          }));
        }
      }
    } catch { /* Resend API unavailable */ }

    res.json({
      totals: { sent: totalSent, pending: totalPending, failed: totalFailed },
      byApp: appStats,
      dailyVolume,
      byTemplate,
      resendDomains,
      timestamp: new Date().toISOString(),
    });
  }));

  app.post('/api/marketing/emails/sequences', asyncRoute((req, res) => {
    const { name, app_slug, segment, steps, active } = req.body;
    if (!name || !segment || !steps) return res.status(400).json({ error: 'name, segment, and steps are required' });
    const result = db.prepare('INSERT INTO email_sequences (name, segment, app_slug, active, steps) VALUES (?, ?, ?, ?, ?)').run(name, segment || 'all', app_slug || null, active ? 1 : 0, typeof steps === 'string' ? steps : JSON.stringify(steps));
    res.json({ ok: true, id: result.lastInsertRowid });
  }));

  app.put('/api/marketing/emails/sequences/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });
    const { name, app_slug, segment, steps, active } = req.body;
    const existing = db.prepare('SELECT * FROM email_sequences WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Sequence not found' });
    db.prepare('UPDATE email_sequences SET name = ?, segment = ?, app_slug = ?, active = ?, steps = ? WHERE id = ?')
      .run(name || existing.name, segment || existing.segment, app_slug ?? existing.app_slug, active !== undefined ? (active ? 1 : 0) : existing.active, steps ? (typeof steps === 'string' ? steps : JSON.stringify(steps)) : existing.steps, id);
    res.json({ ok: true });
  }));

  app.delete('/api/marketing/emails/sequences/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });
    db.prepare('DELETE FROM email_queue WHERE sequence_id = ?').run(id);
    const result = db.prepare('DELETE FROM email_sequences WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Sequence not found' });
    res.json({ ok: true });
  }));

  // =============================================
  // Cross-Promo
  // =============================================

  app.options('/api/crosspromo/:path', (_req, res) => {
    setCORS(res);
    res.sendStatus(204);
  });

  app.get('/api/marketing/crosspromo', asyncRoute((_req, res) => {
    const campaigns = db.prepare('SELECT * FROM crosspromo_campaigns ORDER BY created_at DESC').all();
    campaigns.forEach(c => { c.banner_data = safeJSON(c.banner_data); });
    res.json(campaigns);
  }));

  app.post('/api/marketing/crosspromo', asyncRoute(async (req, res) => {
    const { name, source_app, target_app, headline, cta_text } = req.body;
    if (!name || !source_app || !target_app) {
      return res.status(400).json({ error: 'name, source_app, target_app required' });
    }
    if (source_app === target_app) {
      return res.status(400).json({ error: 'source_app and target_app must be different' });
    }

    const sourceApp = findAppBySlug(source_app);
    const targetApp = findAppBySlug(target_app);
    if (!sourceApp || !targetApp) {
      return res.status(400).json({ error: 'Unknown app slug' });
    }

    const campaignHeadline = headline || targetApp.marketing?.tagline || targetApp.description || targetApp.name;
    const campaignCta = cta_text || 'Learn More';

    const insertCampaign = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO crosspromo_campaigns (name, source_app, target_app, headline, cta_text, cta_url, status)
        VALUES (?, ?, ?, ?, ?, ?, 'draft')
      `).run(name, source_app, target_app, campaignHeadline, campaignCta, 'https://' + targetApp.domain);
      const campaignId = result.lastInsertRowid;
      const ctaUrl = `https://${targetApp.domain}?utm_source=${encodeURIComponent(source_app)}&utm_medium=crosspromo&utm_campaign=${campaignId}`;
      db.prepare('UPDATE crosspromo_campaigns SET cta_url = ? WHERE id = ?').run(ctaUrl, campaignId);
      return campaignId;
    });
    const campaignId = insertCampaign();

    let bannerData = null;
    try {
      const bannerforgeUrl = getBannerForgeUrl();
      if (!bannerforgeUrl) throw new Error('BannerForge not configured');
      const brandColors = ['#1a1a2e', '#e94560', '#0f3460'];
      const sizes = [
        { name: 'leaderboard', width: 728, height: 90 },
        { name: 'medium-rectangle', width: 300, height: 250 },
        { name: 'square', width: 1080, height: 1080 },
      ];

      const banners = [];
      for (const size of sizes) {
        try {
          const renderResp = await fetch(bannerforgeUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              layout: 'centered-bold',
              brand: { companyName: targetApp.name, colors: brandColors, tagline: campaignHeadline },
              copy: { headline: campaignHeadline, cta: campaignCta },
              size: { width: size.width, height: size.height },
              format: 'png',
            }),
            signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
          });

          if (renderResp.ok) {
            const renderResult = await renderResp.json();
            banners.push({ ...size, dataUrl: renderResult.dataUrl || renderResult.url || null });
          }
        } catch (renderErr) {
          console.log(`BannerForge render failed for ${size.name}: ${renderErr.message}`);
        }
      }

      if (banners.length > 0) {
        bannerData = JSON.stringify({ sizes: banners });
      }
    } catch (bfErr) {
      console.log(`BannerForge integration unavailable: ${bfErr.message}`);
    }

    if (!bannerData) {
      const fallbackBanners = [
        { name: 'leaderboard', width: 728, height: 90, html: true },
        { name: 'medium-rectangle', width: 300, height: 250, html: true },
      ];
      bannerData = JSON.stringify({ sizes: fallbackBanners, fallback: true });
    }

    db.prepare('UPDATE crosspromo_campaigns SET banner_data = ? WHERE id = ?').run(bannerData, campaignId);

    const campaign = db.prepare('SELECT * FROM crosspromo_campaigns WHERE id = ?').get(campaignId);
    campaign.banner_data = safeJSON(campaign.banner_data);
    res.json(campaign);
  }));

  app.patch('/api/marketing/crosspromo/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const { status } = req.body;
    if (!['draft', 'active', 'paused', 'ended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    db.prepare('UPDATE crosspromo_campaigns SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run(status, id);
    const campaign = db.prepare('SELECT * FROM crosspromo_campaigns WHERE id = ?').get(id);
    if (!campaign) return res.status(404).json({ error: 'Not found' });
    campaign.banner_data = safeJSON(campaign.banner_data);
    res.json(campaign);
  }));

  app.delete('/api/marketing/crosspromo/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const result = db.prepare('DELETE FROM crosspromo_campaigns WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  }));

  // Public cross-promo endpoints

  app.get('/api/crosspromo/embed.js', (_req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=300');
    setCORS(res);
    res.send(`(function(){
  var s=document.currentScript;
  var app=s&&s.getAttribute('data-app');
  if(!app)return;
  var base=s.src.replace(/\\/api\\/crosspromo\\/embed\\.js(\\?.*)?$/,'');
  fetch(base+'/api/crosspromo/banner?app='+encodeURIComponent(app))
    .then(function(r){if(!r.ok)throw new Error();return r.json()})
    .then(function(d){
      if(!d||!d.id)return;
      try{
        var key='crosspromo_'+d.id;
        if(!sessionStorage.getItem(key)){
          fetch(base+'/api/crosspromo/'+d.id+'/view',{method:'POST'});
          sessionStorage.setItem(key,'1');
        }
      }catch(e){}
      function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
      var el=document.getElementById('crosspromo')||document.createElement('div');
      if(!el.id){el.id='crosspromo';document.body.appendChild(el);}
      el.innerHTML='<a href="'+base+'/api/crosspromo/'+d.id+'/click" target="_blank" rel="noopener" '
        +'style="display:inline-block;text-decoration:none;background:linear-gradient(135deg,#1a1a2e,#0f3460);'
        +'color:#fff;padding:12px 24px;border-radius:8px;font-family:system-ui;font-size:14px;">'
        +'<strong>'+esc(d.headline)+'</strong> &mdash; '+esc(d.cta_text)+' &rarr;</a>';
    }).catch(function(){});
})();`);
  });

  app.get('/api/crosspromo/banner', rlBannerServe, asyncRoute((req, res) => {
    setCORS(res);
    const app = req.query.app;
    if (!app) return res.status(400).json({ error: 'app query param required' });
    const campaign = db.prepare(
      'SELECT id, headline, cta_text, cta_url, banner_data FROM crosspromo_campaigns WHERE source_app = ? AND status = \'active\' ORDER BY created_at DESC LIMIT 1'
    ).get(app);
    if (!campaign) return res.json(null);
    campaign.banner_data = safeJSON(campaign.banner_data);
    res.json(campaign);
  }));

  app.post('/api/crosspromo/:id/view', rlBannerTrack, asyncRoute((req, res) => {
    setCORS(res);
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare('UPDATE crosspromo_campaigns SET views = views + 1 WHERE id = ?').run(id);
    res.json({ ok: true });
  }));

  app.get('/api/crosspromo/:id/click', rlBannerTrack, (req, res) => {
    try {
      const id = parseId(req.params.id);
      if (isNaN(id)) return res.redirect('/');
      const campaign = db.prepare('SELECT cta_url FROM crosspromo_campaigns WHERE id = ?').get(id);
      if (!campaign) return res.redirect('/');
      db.prepare('UPDATE crosspromo_campaigns SET clicks = clicks + 1 WHERE id = ?').run(id);
      res.redirect(campaign.cta_url);
    } catch (err) {
      res.redirect('/');
    }
  });

  // =============================================
  // Banner Management System
  // =============================================

  app.options('/api/banners/:path', (_req, res) => {
    setCORS(res);
    res.sendStatus(204);
  });
  app.options('/api/banners/:id/:action', (_req, res) => {
    setCORS(res);
    res.sendStatus(204);
  });

  app.get('/api/marketing/banners', asyncRoute((_req, res) => {
    const banners = db.prepare('SELECT * FROM banners ORDER BY created_at DESC').all();
    const placements = db.prepare('SELECT * FROM banner_placements ORDER BY created_at DESC').all();
    banners.forEach(b => {
      b.bannerforge_config = safeJSON(b.bannerforge_config);
      b.placements = placements.filter(p => p.banner_id === b.id);
      b.total_views = b.placements.reduce((s, p) => s + p.views, 0);
      b.total_clicks = b.placements.reduce((s, p) => s + p.clicks, 0);
    });
    res.json(banners);
  }));

  app.post('/api/marketing/banners', asyncRoute(async (req, res) => {
    const { name, type, width, height, click_url, tags, content: rawContent, bannerforge_config } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });

    const bannerType = type || 'bannerforge';
    const w = Math.max(1, Math.min(10000, parseInt(width) || 728));
    const h = Math.max(1, Math.min(10000, parseInt(height) || 90));
    let content = rawContent || '';
    let bfConfig = null;

    if (bannerType === 'bannerforge') {
      const bfc = bannerforge_config || {};
      bfConfig = JSON.stringify(bfc);
      const bfUrl = getBannerForgeUrl();
      if (!bfUrl) return res.status(400).json({ error: 'BannerForge not configured. Set BANNERFORGE_URL or add BannerForge to your apps.' });
      try {
        const defaultColors = { primary: '#1a1a2e', secondary: '#e94560', accent: '#0f3460', background: '#ffffff', text: '#1a1a2e' };
        const renderResp = await fetch(bfUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            layout: bfc.layout || 'centered-bold',
            brand: bfc.brand || { name, tagline: name, description: '', colors: defaultColors, logoUrl: null, screenshotUrl: null, ctas: ['Learn More'], headlines: [name], favicon: null },
            copy: bfc.copy || { headline: name, subheading: '', cta: 'Learn More', emotionalAngle: 'curiosity' },
            size: { name: `${w}x${h}`, width: w, height: h },
            colors: bfc.colors || defaultColors,
            format: 'png',
          }),
          signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
        });
        if (renderResp.ok) {
          const result = await renderResp.json();
          content = result.dataUrl || result.url || '';
        }
      } catch (bfErr) {
        console.log(`BannerForge render failed: ${bfErr.message}`);
      }
      if (!content) {
        const colors = bfc.brand?.colors || ['#1a1a2e', '#e94560'];
        const headline = bfc.copy?.headline || name;
        const cta = bfc.copy?.cta || 'Learn More';
        content = `<div style="width:${w}px;height:${h}px;background:linear-gradient(135deg,${colors[0]},${colors[1] || colors[0]});display:flex;align-items:center;justify-content:center;color:#fff;font-family:system-ui;border-radius:8px;padding:12px"><strong>${headline}</strong>&nbsp;&mdash;&nbsp;${cta}</div>`;
      }
    } else if (bannerType === 'image_url') {
      if (!content) return res.status(400).json({ error: 'content (image URL) required for image_url type' });
    } else if (bannerType === 'custom_html') {
      if (!content) return res.status(400).json({ error: 'content (HTML) required for custom_html type' });
    } else {
      return res.status(400).json({ error: 'type must be bannerforge, image_url, or custom_html' });
    }

    const result = db.prepare(`
      INSERT INTO banners (name, type, width, height, content, bannerforge_config, click_url, tags)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(name, bannerType, w, h, content, bfConfig, click_url || null, tags || null);

    const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(result.lastInsertRowid);
    banner.bannerforge_config = safeJSON(banner.bannerforge_config);
    banner.placements = [];
    banner.total_views = 0;
    banner.total_clicks = 0;
    res.json(banner);
  }));

  app.put('/api/marketing/banners/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    if (!banner) return res.status(404).json({ error: 'Not found' });

    const { name, click_url, tags } = req.body;
    db.prepare(`UPDATE banners SET name = ?, click_url = ?, tags = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(name || banner.name, click_url !== undefined ? click_url : banner.click_url, tags !== undefined ? tags : banner.tags, id);
    const updated = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    updated.bannerforge_config = safeJSON(updated.bannerforge_config);
    res.json(updated);
  }));

  app.delete('/api/marketing/banners/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare('DELETE FROM banner_placements WHERE banner_id = ?').run(id);
    const result = db.prepare('DELETE FROM banners WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  }));

  app.post('/api/marketing/banners/:id/regenerate', asyncRoute(async (req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    if (!banner) return res.status(404).json({ error: 'Not found' });
    if (banner.type !== 'bannerforge') return res.status(400).json({ error: 'Only BannerForge banners can be regenerated' });

    const bfc = safeJSON(banner.bannerforge_config, {});
    const bfUrl = getBannerForgeUrl();
    if (!bfUrl) return res.status(400).json({ error: 'BannerForge not configured. Set BANNERFORGE_URL or add BannerForge to your apps.' });
    const defaultColors = { primary: '#1a1a2e', secondary: '#e94560', accent: '#0f3460', background: '#ffffff', text: '#1a1a2e' };
    const renderResp = await fetch(bfUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        layout: bfc.layout || 'centered-bold',
        brand: bfc.brand || { name: banner.name, tagline: banner.name, description: '', colors: defaultColors, logoUrl: null, screenshotUrl: null, ctas: ['Learn More'], headlines: [banner.name], favicon: null },
        copy: bfc.copy || { headline: banner.name, subheading: '', cta: 'Learn More', emotionalAngle: 'curiosity' },
        size: { name: `${banner.width}x${banner.height}`, width: banner.width, height: banner.height },
        colors: bfc.colors || defaultColors,
        format: 'png',
      }),
      signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
    });

    if (!renderResp.ok) throw new Error('BannerForge render failed');
    const result = await renderResp.json();
    const content = result.dataUrl || result.url || '';
    if (!content) throw new Error('BannerForge returned empty result');

    db.prepare(`UPDATE banners SET content = ?, updated_at = datetime('now') WHERE id = ?`).run(content, id);
    const updated = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    updated.bannerforge_config = safeJSON(updated.bannerforge_config);
    res.json(updated);
  }));

  // Placements

  app.get('/api/marketing/placements', asyncRoute((req, res) => {
    const appFilter = req.query.app;
    let placements;
    if (appFilter) {
      placements = db.prepare('SELECT bp.*, b.name as banner_name, b.type as banner_type, b.width, b.height FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id WHERE bp.app_slug = ? ORDER BY bp.priority DESC, bp.created_at DESC').all(appFilter);
    } else {
      placements = db.prepare('SELECT bp.*, b.name as banner_name, b.type as banner_type, b.width, b.height FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id ORDER BY bp.priority DESC, bp.created_at DESC').all();
    }
    res.json(placements);
  }));

  app.post('/api/marketing/placements', asyncRoute((req, res) => {
    const { banner_id, app_slug, position, weight, click_url, start_date, end_date } = req.body;
    if (!banner_id || !app_slug) return res.status(400).json({ error: 'banner_id and app_slug required' });

    const banner = db.prepare('SELECT id FROM banners WHERE id = ?').get(banner_id);
    if (!banner) return res.status(400).json({ error: 'Banner not found' });

    const appDef = findAppBySlug(app_slug);
    if (!appDef) return res.status(400).json({ error: 'Unknown app slug' });

    const result = db.prepare(`
      INSERT INTO banner_placements (banner_id, app_slug, position, weight, click_url, start_date, end_date)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(banner_id, app_slug, position || 'default', parseInt(weight) || 100, click_url || null, start_date || null, end_date || null);

    const placement = db.prepare('SELECT * FROM banner_placements WHERE id = ?').get(result.lastInsertRowid);
    res.json(placement);
  }));

  app.patch('/api/marketing/placements/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const placement = db.prepare('SELECT * FROM banner_placements WHERE id = ?').get(id);
    if (!placement) return res.status(404).json({ error: 'Not found' });

    const { status, weight, priority, click_url, start_date, end_date } = req.body;
    if (status && !['draft', 'active', 'paused', 'ended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    db.prepare(`UPDATE banner_placements SET
      status = ?, weight = ?, priority = ?, click_url = ?, start_date = ?, end_date = ?, updated_at = datetime('now')
      WHERE id = ?`).run(
      status || placement.status,
      weight !== undefined ? parseInt(weight) : placement.weight,
      priority !== undefined ? parseInt(priority) : placement.priority,
      click_url !== undefined ? click_url : placement.click_url,
      start_date !== undefined ? start_date : placement.start_date,
      end_date !== undefined ? end_date : placement.end_date,
      id
    );

    const updated = db.prepare('SELECT * FROM banner_placements WHERE id = ?').get(id);
    res.json(updated);
  }));

  app.delete('/api/marketing/placements/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const result = db.prepare('DELETE FROM banner_placements WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  }));

  // Public banner serve endpoints

  app.get('/api/banners/embed.js', (_req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=300');
    setCORS(res);
    res.send(`(function(){
  var s=document.currentScript;
  var app=s&&s.getAttribute('data-app');
  if(!app)return;
  var pos=s.getAttribute('data-position')||'default';
  var base=s.src.replace(/\\/api\\/banners\\/embed\\.js(\\?.*)?$/,'');
  fetch(base+'/api/banners/serve?app='+encodeURIComponent(app)+'&pos='+encodeURIComponent(pos))
    .then(function(r){if(!r.ok)throw new Error();return r.json()})
    .then(function(d){
      if(!d||!d.placement_id)return;
      try{
        var key='banner_'+d.placement_id;
        if(!sessionStorage.getItem(key)){
          fetch(base+'/api/banners/'+d.placement_id+'/view',{method:'POST'});
          sessionStorage.setItem(key,'1');
        }
      }catch(e){}
      function esc(t){return String(t||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
      var w=parseInt(d.width)||728,h=parseInt(d.height)||90;
      var el=document.getElementById('dockfolio-banner')||document.createElement('div');
      if(!el.id){el.id='dockfolio-banner';document.body.appendChild(el);}
      var link=base+'/api/banners/'+parseInt(d.placement_id)+'/click';
      if(d.type==='image_url'){
        el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener"><img src="'+esc(d.content)+'" width="'+w+'" height="'+h+'" style="border:0;max-width:100%;height:auto" alt="'+esc(d.name)+'"></a>';
      }else if(d.type==='custom_html'){
        el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener" style="display:inline-block;text-decoration:none">'+esc(d.content)+'</a>';
      }else{
        if(d.content&&d.content.indexOf('data:image')===0){
          el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener"><img src="'+esc(d.content)+'" width="'+w+'" height="'+h+'" style="border:0;max-width:100%;height:auto" alt="'+esc(d.name)+'"></a>';
        }else{
          el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener" style="display:inline-block;text-decoration:none;color:#fff;background:linear-gradient(135deg,#1a1a2e,#0f3460);padding:12px 24px;border-radius:8px;font-family:system-ui;font-size:14px"><strong>'+esc(d.name)+'</strong> &rarr;</a>';
        }
      }
    }).catch(function(){});
})();`);
  });

  app.get('/api/banners/serve', rlBannerServe, asyncRoute((req, res) => {
    setCORS(res);
    const app = req.query.app;
    const pos = req.query.pos || 'default';
    if (!app) return res.status(400).json({ error: 'app query param required' });

    const now = new Date().toISOString();
    const placements = db.prepare(`
      SELECT bp.id as placement_id, bp.weight, bp.click_url as placement_click_url,
             b.id as banner_id, b.name, b.type, b.width, b.height, b.content, b.click_url as banner_click_url
      FROM banner_placements bp
      JOIN banners b ON bp.banner_id = b.id
      WHERE bp.app_slug = ? AND bp.status = 'active'
        AND (bp.position = ? OR bp.position = 'default')
        AND (bp.start_date IS NULL OR bp.start_date <= ?)
        AND (bp.end_date IS NULL OR bp.end_date >= ?)
      ORDER BY bp.priority DESC
    `).all(app, pos, now, now);

    if (placements.length === 0) return res.json(null);

    let selected = placements[0];
    if (placements.length > 1) {
      const totalWeight = placements.reduce((s, p) => s + p.weight, 0);
      if (totalWeight > 0) {
        let rand = Math.random() * totalWeight;
        for (const p of placements) {
          rand -= p.weight;
          if (rand <= 0) { selected = p; break; }
        }
      } else {
        selected = placements[Math.floor(Math.random() * placements.length)];
      }
    }

    res.json({
      placement_id: selected.placement_id,
      banner_id: selected.banner_id,
      name: selected.name,
      type: selected.type,
      width: selected.width,
      height: selected.height,
      content: selected.content,
      click_url: selected.placement_click_url || selected.banner_click_url || '#',
    });
  }));

  app.post('/api/banners/:placementId/view', rlBannerTrack, asyncRoute((req, res) => {
    setCORS(res);
    const id = parseId(req.params.placementId);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare('UPDATE banner_placements SET views = views + 1 WHERE id = ?').run(id);
    res.json({ ok: true });
  }));

  app.get('/api/banners/:placementId/click', rlBannerTrack, (req, res) => {
    try {
      const id = parseId(req.params.placementId);
      if (isNaN(id)) return res.redirect('/');
      const placement = db.prepare(`
        SELECT bp.click_url as p_url, b.click_url as b_url
        FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id
        WHERE bp.id = ?
      `).get(id);
      if (!placement) return res.redirect('/');
      db.prepare('UPDATE banner_placements SET clicks = clicks + 1 WHERE id = ?').run(id);
      res.redirect(placement.p_url || placement.b_url || '/');
    } catch (err) {
      res.redirect('/');
    }
  });

  app.get('/api/banners/injection-status', asyncRoute(async (_req, res) => {
    const results = [];
    for (const appDef of config.apps || []) {
      if (!appDef.domain || appDef.type === 'infra' || appDef.type === 'redirect') continue;
      const slug = slugify(appDef.name);
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), TIMEOUT_QUICK);
        const resp = await fetch(`https://${appDef.domain}/`, {
          headers: { 'Accept-Encoding': '' },
          signal: controller.signal,
        });
        clearTimeout(timeout);
        const html = await resp.text();
        const injected = html.includes('banners/embed.js') && html.includes(`data-app="${slug}"`);
        const proxyWorks = html.includes('/api/banners/embed.js');
        results.push({ slug, domain: appDef.domain, injected, proxyWorks });
      } catch {
        results.push({ slug, domain: appDef.domain, injected: null, error: 'unreachable' });
      }
    }
    res.json(results);
  }));

  // =============================================
  // Marketing Playbooks
  // =============================================

  app.get('/api/marketing/playbooks', asyncRoute((req, res) => {
    const appSlug = req.query.app;
    let entries;
    if (appSlug) {
      entries = db.prepare('SELECT * FROM marketing_playbooks WHERE app_slug = ? ORDER BY section, priority DESC, created_at').all(appSlug);
    } else {
      entries = db.prepare('SELECT * FROM marketing_playbooks ORDER BY app_slug, section, priority DESC, created_at').all();
    }
    res.json(entries);
  }));

  app.post('/api/marketing/playbooks', asyncRoute((req, res) => {
    const { app_slug, section, title, content, status, priority } = req.body;
    if (!app_slug || !section || !title || !content) {
      return res.status(400).json({ error: 'app_slug, section, title, content required' });
    }
    const validSections = ['strategy', 'channels', 'content', 'seo', 'email', 'crosssell', 'notes'];
    if (!validSections.includes(section)) {
      return res.status(400).json({ error: `Invalid section. Must be one of: ${validSections.join(', ')}` });
    }

    const result = db.prepare(`
      INSERT INTO marketing_playbooks (app_slug, section, title, content, status, priority)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(app_slug, section, title, content, status || 'draft', parseInt(priority) || 0);

    const entry = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(result.lastInsertRowid);
    res.json(entry);
  }));

  app.put('/api/marketing/playbooks/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const entry = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(id);
    if (!entry) return res.status(404).json({ error: 'Not found' });

    const { title, content, status, priority } = req.body;
    db.prepare(`UPDATE marketing_playbooks SET title = ?, content = ?, status = ?, priority = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(title || entry.title, content || entry.content, status || entry.status, priority !== undefined ? parseInt(priority) : entry.priority, id);

    const updated = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(id);
    res.json(updated);
  }));

  app.delete('/api/marketing/playbooks/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const result = db.prepare('DELETE FROM marketing_playbooks WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  }));

  app.post('/api/marketing/playbooks/:appSlug/generate', asyncRoute(async (req, res) => {
    const appSlug = req.params.appSlug;
    const appDef = findAppBySlug(appSlug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });

    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return res.status(500).json({ error: 'No Anthropic API key available' });

    const slug = slugify(appDef.name);
    const seoAudit = qLatestSEO.get(slug);
    const revenueData = qLatestMetric.get(slug, 'revenue');

    const prompt = buildPlaybookPrompt(appDef, seoAudit, revenueData);
    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      maxTokens: 4096, timeout: TIMEOUT_AI, messages: [{ role: 'user', content: prompt }],
    }));

    const sections = parseAIJsonArray(ai.text || '[]');

    const insertPlaybook = db.transaction(() => {
      db.prepare('DELETE FROM marketing_playbooks WHERE app_slug = ?').run(slug);
      for (const s of sections) {
        if (s.section && s.title && s.content) {
          db.prepare('INSERT INTO marketing_playbooks (app_slug, section, title, content, status) VALUES (?, ?, ?, ?, ?)')
            .run(slug, s.section, s.title, s.content, 'draft');
        }
      }
    });
    insertPlaybook();

    const entries = db.prepare('SELECT * FROM marketing_playbooks WHERE app_slug = ? ORDER BY section, priority DESC').all(slug);
    res.json({ entries, tokens: ai.tokens, generated: new Date().toISOString() });
  }));

  // =============================================
  // Cross-Promo Pairings (config-driven)
  // =============================================

  // GET pairings from config.yml crossPromo section
  app.get('/api/marketing/crosspromo/pairings', asyncRoute((_req, res) => {
    const pairings = config.crossPromo || [];
    const result = pairings.map(p => {
      const sourceApp = findAppBySlug(p.source);
      const targetApps = (p.targets || []).map(t => {
        const app = findAppBySlug(t);
        return { slug: t, name: app?.name || t, domain: app?.domain || null };
      });
      return {
        source: p.source,
        sourceName: sourceApp?.name || p.source,
        sourceDomain: sourceApp?.domain || null,
        targets: targetApps,
      };
    });
    res.json(result);
  }));

  // Provision banners + placements from config pairings.
  // Creates a text banner per target app (if not exists) and a placement per source→target pair.
  // Dry-run by default; pass { "activate": true } to set placements to active.
  app.post('/api/marketing/crosspromo/provision', asyncRoute((_req, res) => {
    const pairings = config.crossPromo || [];
    if (pairings.length === 0) return res.status(400).json({ error: 'No crossPromo pairings in config.yml' });

    const activate = _req.body.activate === true;
    const created = { banners: [], placements: [] };
    const skipped = { banners: [], placements: [] };

    // Collect all unique target slugs that need banners
    const targetSlugs = new Set();
    for (const p of pairings) {
      for (const t of (p.targets || [])) targetSlugs.add(t);
    }

    // Ensure a banner exists for each target app (tagged with "crosspromo,{slug}")
    const bannerMap = new Map(); // slug -> banner id
    for (const slug of targetSlugs) {
      const tag = `crosspromo,${slug}`;
      const existing = db.prepare("SELECT id FROM banners WHERE tags LIKE ?").get(`%${tag}%`);
      if (existing) {
        bannerMap.set(slug, existing.id);
        skipped.banners.push(slug);
        continue;
      }

      const appDef = findAppBySlug(slug);
      const name = appDef?.name || slug;
      const domain = appDef?.domain || '#';
      const tagline = appDef?.marketing?.tagline || name;
      const colors = ['#1a1a2e', '#0f3460'];
      const content = `<div style="width:728px;height:90px;background:linear-gradient(135deg,${colors[0]},${colors[1]});display:flex;align-items:center;justify-content:center;color:#fff;font-family:system-ui;border-radius:8px;padding:12px"><strong>${tagline}</strong>&nbsp;&mdash;&nbsp;Check it out &rarr;</div>`;

      const result = db.prepare(`
        INSERT INTO banners (name, type, width, height, content, click_url, tags)
        VALUES (?, 'custom_html', 728, 90, ?, ?, ?)
      `).run(`Cross-promo: ${name}`, content, `https://${domain}`, tag);
      bannerMap.set(slug, result.lastInsertRowid);
      created.banners.push({ slug, bannerId: result.lastInsertRowid });
    }

    // Create placements for each source→target pair
    for (const p of pairings) {
      for (const target of (p.targets || [])) {
        const bannerId = bannerMap.get(target);
        if (!bannerId) continue;

        const existing = db.prepare(
          "SELECT id FROM banner_placements WHERE banner_id = ? AND app_slug = ?"
        ).get(bannerId, p.source);
        if (existing) {
          skipped.placements.push({ source: p.source, target });
          continue;
        }

        const status = activate ? 'active' : 'draft';
        const result = db.prepare(`
          INSERT INTO banner_placements (banner_id, app_slug, position, status, weight)
          VALUES (?, ?, 'default', ?, 100)
        `).run(bannerId, p.source, status);
        created.placements.push({ source: p.source, target, placementId: result.lastInsertRowid, status });
      }
    }

    res.json({ created, skipped, activate });
  }));

  // =============================================
  // Cron Jobs
  // =============================================

  // Every 6 hours: collect revenue + analytics
  cron.schedule('0 */6 * * *', async () => {
    console.log('[CRON] Collecting revenue data...');
    try {
      const { keys, appKeys } = getStripeKeys();
      const today = todayString();
      let totalMRR = 0;
      const keyResults = new Map();
      for (const [key, appNames] of keys) {
        const data = await cbStripe.call(() => fetchStripeData(key, TIMEOUT_STANDARD));
        keyResults.set(key, data);
        if (data.mrr) totalMRR += data.mrr;
      }
      upsertMetric.run('_total', today, 'mrr', totalMRR / 100, null);
      for (const [appName, key] of appKeys) {
        const data = keyResults.get(key);
        if (data?.mrr != null) upsertMetric.run(slugify(appName), today, 'mrr', data.mrr / 100, null);
      }
      console.log('[CRON] Revenue data collected');
    } catch (err) {
      cronFail('Revenue refresh', err);
    }
  });

  // Daily at 1:30 AM: run SEO audits and store
  cron.schedule('30 1 * * *', async () => {
    console.log('[CRON] Running daily SEO audits...');
    try {
      const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
      const today = todayString();
      for (const appDef of marketableApps) {
        const audit = await auditSEO(appDef.domain, TIMEOUT_STANDARD, TIMEOUT_QUICK);
        upsertSEOAudit.run(slugify(appDef.name), today, audit.score, audit.grade, JSON.stringify(audit.checks));
        upsertMetric.run(slugify(appDef.name), today, 'seo_score', audit.score, null);
      }
      console.log('[CRON] SEO audits stored');
    } catch (err) {
      cronFail('SEO audit', err);
    }
  });

  // Weekly content generation cron — Sunday 3AM
  cron.schedule('0 3 * * 0', async () => {
    console.log('[CRON] Starting weekly content generation...');
    try {
      const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
      const insertContent = db.prepare(`
        INSERT INTO content_queue (app_slug, content_type, keyword, title, body, token_count)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      const contentTypes = ['meta_description', 'blog_outline', 'title'];
      let generated = 0;

      for (const appDef of marketableApps) {
        const slug = slugify(appDef.name);
        const keywords = deriveKeywords(appDef);

        for (let i = 0; i < Math.min(contentTypes.length, keywords.length); i++) {
          try {
            const { body, tokenCount } = await generateContent(slug, contentTypes[i], keywords[i]);
            const title = formatContentTitle(contentTypes[i], keywords[i]);
            insertContent.run(slug, contentTypes[i], keywords[i], title, body, tokenCount);
            generated++;
            await new Promise(r => setTimeout(r, 2000));
          } catch (err) {
            console.error(`[CRON] Content gen failed for ${slug}/${contentTypes[i]}:`, err.message);
          }
        }
      }
      console.log(`[CRON] Weekly content generation done: ${generated} items created`);
    } catch (err) {
      cronFail('Content generation', err);
    }
  });

  // Customer graph cron — daily 3:30AM
  cron.schedule('30 3 * * *', async () => {
    try {
      await collectCustomerGraph();
    } catch (err) {
      cronFail('Customer graph', err);
    }
  });

  // Process email queue — hourly cron
  cron.schedule('0 * * * *', async () => {
    console.log('[CRON] Processing email queue...');
    try {
      const now = new Date().toISOString();
      const due = db.prepare(`
        SELECT eq.*, s.email_encrypted FROM email_queue eq
        JOIN subscribers s ON eq.recipient_hash = s.email_hash AND eq.app_slug = s.app_slug
        WHERE eq.status = 'pending' AND eq.scheduled_at <= ?
        ORDER BY eq.scheduled_at ASC LIMIT 20
      `).all(now);

      if (due.length === 0) {
        console.log('[CRON] No emails due');
        return;
      }

      const updateSent = db.prepare("UPDATE email_queue SET status='sent', sent_at=? WHERE id=?");
      const updateFailed = db.prepare("UPDATE email_queue SET status='failed', error=? WHERE id=?");
      let sent = 0, failed = 0;

      for (const item of due) {
        try {
          const toEmail = deobfuscateEmail(item.email_encrypted);
          const template = getEmailTemplate(item.template_key, item.app_slug);
          await sendEmail(toEmail, template.subject, template.html, item.app_slug);
          updateSent.run(new Date().toISOString(), item.id);
          sent++;
        } catch (err) {
          updateFailed.run(err.message, item.id);
          failed++;
        }
      }

      console.log(`[CRON] Email queue processed: ${sent} sent, ${failed} failed`);
    } catch (err) {
      cronFail('Email queue', err);
    }
  });

  return { cache, auditSEO: (domain) => auditSEO(domain, TIMEOUT_STANDARD, TIMEOUT_QUICK), getStripeKeys };
}
