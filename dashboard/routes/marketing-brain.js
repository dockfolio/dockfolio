// Marketing Brain — autonomous per-app analysis + action generation loop.
// Runs on a cron, rotates through all marketable apps, produces briefs and
// proposes concrete actions. See plans/marketing-brain.md for design.

import fs from 'node:fs';
import path from 'node:path';
import { asyncRoute, callAnthropic, getMarketableApps, safeJSON, parseId, slugify } from '../utils.js';

// Read-only view of /home/deploy/nginx-configs/sites mounted into the container.
// Lets collectAppContext see proxy-layer state (plausible injection, banner
// injection, CSP, etc.) so the brain stops proposing infra work that's already
// done. See session 14 handover: the "install Plausible" false-positive class.
const NGINX_SITES_DIR = process.env.NGINX_SITES_DIR || '/etc/dockfolio/nginx-sites';
const INFRA_CACHE_TTL_MS = 60_000;
let infraCache = null;
let infraCacheAt = 0;

function buildInfraCache() {
  const map = {};
  let files;
  try { files = fs.readdirSync(NGINX_SITES_DIR); }
  catch { return map; }
  for (const f of files) {
    if (f.includes('.bak') || f.startsWith('.') || f.endsWith('~')) continue;
    const full = path.join(NGINX_SITES_DIR, f);
    let content;
    try {
      const stat = fs.statSync(full);
      if (!stat.isFile() || stat.size > 200_000) continue;
      content = fs.readFileSync(full, 'utf8');
    } catch { continue; }
    const domains = new Set();
    for (const m of content.matchAll(/server_name\s+([^;]+);/g)) {
      for (const d of m[1].trim().split(/\s+/)) {
        if (d && d !== '_') domains.add(d.replace(/^www\./, '').toLowerCase());
      }
    }
    // Substring checks (not regex-anchored to sub_filter) — nginx sub_filter
    // replacement strings contain JS with semicolons, which breaks [^;]* clauses.
    // Presence of the marker string anywhere is the honest signal.
    const lower = content.toLowerCase();
    const state = {
      nginx_file: f,
      plausible_injected: lower.includes('data-domain=') || /proxy_pass\s+http:\/\/[^\s;]*plausible/i.test(content) || /location\s*=?\s*\/js\/script\.js/i.test(content),
      admin_tracking: lower.includes('admin.crelvo.dev/api/analytics/track.js'),
      banner_injection: lower.includes('/api/banners/embed.js'),
      crosslinks_widget: lower.includes('/api/crosslinks/widget.js'),
      csp_header: /add_header\s+content-security-policy/i.test(content),
      gzip_on: /\bgzip\s+on\s*;/i.test(content),
      long_cache: /cache-control[^"'\n]*immutable/i.test(content),
      ssl_letsencrypt: content.includes('ssl_certificate /etc/letsencrypt'),
    };
    for (const d of domains) map[d] = state;
  }
  return map;
}

function loadInfraCache() {
  const now = Date.now();
  if (infraCache && now - infraCacheAt < INFRA_CACHE_TTL_MS) return infraCache;
  infraCache = buildInfraCache();
  infraCacheAt = now;
  return infraCache;
}

function readInfraState(appDef) {
  const domain = appDef?.domain?.replace(/^www\./, '').toLowerCase();
  if (!domain) return null;
  const map = loadInfraCache();
  return map[domain] || null;
}

// ---------- Marketing Knowledge Base ----------
// Dense, opinionated marketing reference material (positioning, launch,
// content/SEO, pricing, conversion, growth loops, distribution, email,
// metrics, kill criteria, copywriting) stored as markdown in marketing-kb/.
// Loaded once at boot. Each file is parsed into H2 sections so the brain
// can retrieve the most relevant SECTION of the most relevant file per
// cycle instead of always the first 1400 chars of a whole file.

const MARKETING_KB_DIR = process.env.MARKETING_KB_DIR ||
  path.join(process.cwd(), 'marketing-kb');
let marketingKB = null;

// Split a KB file's markdown content into H2-bounded sections. The text
// before the first H2 is captured as the "(intro)" section. Very short
// sections (< 200 chars of body) are dropped as noise — they're usually
// section headers with no content yet, or tiny transitions.
function parseKBSections(content) {
  const lines = content.split('\n');
  const sections = [];
  let current = { title: '(intro)', body: [] };
  for (const line of lines) {
    const m = line.match(/^##\s+(.+?)\s*$/);
    if (m) {
      const bodyText = current.body.join('\n').trim();
      if (bodyText.length >= 200) {
        sections.push({
          title: current.title,
          body: bodyText,
          bag: bodyText.toLowerCase(),
        });
      }
      current = { title: m[1].trim(), body: [] };
    } else {
      current.body.push(line);
    }
  }
  const tailBody = current.body.join('\n').trim();
  if (tailBody.length >= 200) {
    sections.push({
      title: current.title,
      body: tailBody,
      bag: tailBody.toLowerCase(),
    });
  }
  return sections;
}

function loadMarketingKB() {
  if (marketingKB) return marketingKB;
  const kb = [];
  let files;
  try { files = fs.readdirSync(MARKETING_KB_DIR); }
  catch { marketingKB = []; return marketingKB; }
  for (const f of files.sort()) {
    if (!f.endsWith('.md') || f === 'README.md') continue;
    const full = path.join(MARKETING_KB_DIR, f);
    let content;
    try { content = fs.readFileSync(full, 'utf8'); }
    catch { continue; }
    // Extract title from first H1, topic from filename (01-positioning -> positioning)
    const h1 = content.match(/^#\s+(.+)$/m);
    const topic = f.replace(/^\d+-/, '').replace(/\.md$/, '');
    const sections = parseKBSections(content);
    kb.push({
      file: f,
      topic,
      title: h1 ? h1[1].trim() : topic,
      content,
      // Pre-compute lowercased keyword bag for fast matching
      bag: content.toLowerCase(),
      sections,
    });
  }
  marketingKB = kb;
  const totalSections = kb.reduce((n, f) => n + (f.sections?.length || 0), 0);
  console.log(`[brain-kb] loaded ${kb.length} knowledge base files (${totalSections} sections) from ${MARKETING_KB_DIR}`);
  return marketingKB;
}

// Per-topic keyword bag used for both file-level stage scoring and
// section-level relevance scoring. Hoisted to module scope so the section
// scorer can reuse it without duplicating the list.
const KB_TOPIC_KEYWORDS = {
  'positioning': ['positioning', 'messaging', 'category', 'who it', 'unique value', 'target'],
  'pre-traction': ['zero', 'no customers', 'first customer', 'cold outreach', 'pre-traction'],
  'launch-playbook': ['launch', 'product hunt', 'hacker news', 'show hn', 'reddit launch'],
  'content-and-seo': ['seo', 'blog', 'content', 'keyword', 'ranking', 'google'],
  'conversion-and-landing-pages': ['landing page', 'conversion', 'bounce', 'trial', 'signup rate'],
  'pricing': ['pricing', 'price', 'tier', 'free trial', 'freemium', 'underpricing'],
  'growth-loops': ['viral', 'referral', 'loop', 'network effect', 'share'],
  'distribution-channels': ['channel', 'distribution', 'paid ads', 'partnership', 'community'],
  'email-and-lifecycle': ['email', 'newsletter', 'welcome', 'activation email', 'drip'],
  'metrics-and-analytics': ['metric', 'mrr', 'churn', 'retention', 'activation', 'cohort'],
  'kill-criteria-and-pivots': ['kill', 'pivot', 'dead', 'sunset', 'quit', 'churn'],
  'copywriting': ['copy', 'headline', 'cta', 'button', 'subject line', 'hero copy'],
};

// Build a single lowercased blob of app-specific text the brain has
// accumulated — recent learnings, prior brief summaries, open action
// titles, SEO issues. Used for keyword scoring at both file and section
// level. Kept short (<5000 chars) to bound scoring cost.
function extractKBCtxText(ctx) {
  const parts = [];
  for (const l of (ctx.recent_learnings || [])) {
    if (l.learning) parts.push(String(l.learning).slice(0, 300));
  }
  for (const l of (ctx.learnings || [])) {
    if (l.learning) parts.push(String(l.learning).slice(0, 300));
  }
  for (const b of (ctx.prior_briefs || [])) {
    if (b.analysis_summary) parts.push(String(b.analysis_summary).slice(0, 300));
  }
  for (const a of (ctx.open_actions || [])) {
    if (a.title) parts.push(String(a.title).slice(0, 200));
  }
  if (ctx.seo?.issues) {
    try { parts.push(JSON.stringify(ctx.seo.issues).slice(0, 300)); } catch {}
  }
  return parts.join(' ').toLowerCase().slice(0, 5000);
}

// Score a KB file's relevance to an app context based on stage signals
// (MRR bucket, traffic, active subs) and what's already in the action
// queue. Returns a number >= 0; this is the file's base score that every
// section in the file inherits before section-level keyword scoring.
function scoreKBRelevance(kbFile, ctx) {
  let score = 0;
  const signals = [];

  const mrr30 = Number(ctx.revenue?.revenue30d || 0) / 100;
  const visitors30 = Number(ctx.traffic?.visitors_30d || 0);
  const activeSubs = Number(ctx.revenue?.activeSubscriptions || 0);
  const isPreTraction = activeSubs < 10 && mrr30 < 500;
  const isEarlyTraction = activeSubs >= 10 && activeSubs < 50;
  const hasTrafficNoPaying = visitors30 > 200 && activeSubs < 3;
  const hasPayingNoGrowth = activeSubs >= 5 && visitors30 < 100;

  if (isPreTraction && kbFile.topic === 'pre-traction') { score += 50; signals.push('pre-traction stage'); }
  if (isPreTraction && kbFile.topic === 'positioning') { score += 30; signals.push('pre-traction needs positioning'); }
  if (isEarlyTraction && kbFile.topic === 'conversion-and-landing-pages') { score += 30; signals.push('early traction → optimize conversion'); }
  if (isEarlyTraction && kbFile.topic === 'email-and-lifecycle') { score += 25; signals.push('early traction → lifecycle email'); }
  if (hasTrafficNoPaying && kbFile.topic === 'conversion-and-landing-pages') { score += 40; signals.push('traffic but no conversion'); }
  if (hasTrafficNoPaying && kbFile.topic === 'copywriting') { score += 25; signals.push('traffic but no conversion'); }
  if (hasPayingNoGrowth && kbFile.topic === 'distribution-channels') { score += 30; signals.push('users but no growth channel'); }
  if (hasPayingNoGrowth && kbFile.topic === 'content-and-seo') { score += 25; signals.push('needs compounding channel'); }
  if (mrr30 === 0 && visitors30 === 0 && kbFile.topic === 'kill-criteria-and-pivots') { score += 20; signals.push('no signal — consider kill/pivot'); }
  if (mrr30 === 0 && kbFile.topic === 'launch-playbook') { score += 15; signals.push('no revenue → launch more'); }

  // Open-action-kind signals — match KB topic to what's already in the queue
  const actionKinds = new Set((ctx.open_actions_summary_kinds || []).map(k => String(k).toLowerCase()));
  if (actionKinds.has('content.draft') && kbFile.topic === 'content-and-seo') { score += 10; signals.push('content actions in queue'); }
  if (actionKinds.has('social.draft') && kbFile.topic === 'distribution-channels') { score += 8; signals.push('social actions in queue'); }
  if (actionKinds.has('email.draft') && kbFile.topic === 'email-and-lifecycle') { score += 10; signals.push('email actions in queue'); }
  if (actionKinds.has('seo') && kbFile.topic === 'content-and-seo') { score += 10; signals.push('SEO actions in queue'); }
  if (actionKinds.has('landing') && kbFile.topic === 'conversion-and-landing-pages') { score += 10; signals.push('landing actions in queue'); }
  if (actionKinds.has('landing') && kbFile.topic === 'copywriting') { score += 8; signals.push('landing actions in queue'); }

  return { score, signals };
}

// Score one section's keyword relevance against the app's ctx text.
// Counts hits for the section's parent-topic keywords that appear in
// BOTH the ctx text and the section body. Title hits count double
// (if the section explicitly addresses a topic the ctx is discussing,
// that's a strong signal). Returns {score, hits} where score is the
// raw keyword points to ADD to the file-level score.
function scoreKBSection(section, topic, ctxText) {
  const kw = KB_TOPIC_KEYWORDS[topic] || [];
  if (!kw.length || !ctxText) return { score: 0, hits: 0 };
  const bag = section.bag;
  const titleLower = section.title.toLowerCase();
  let hits = 0;
  for (const k of kw) {
    if (!ctxText.includes(k)) continue;
    if (titleLower.includes(k)) hits += 2;
    else if (bag.includes(k)) hits += 1;
  }
  return { score: hits * 3, hits };
}

// Given an app context, pick the most relevant KB SECTIONS (not whole
// files) and return compact snippets for prompt injection. For each
// file: compute its stage-based score, then pick its best-scoring
// section (file_score + section_keyword_score). Dedupe across files
// so at most one section per file can land in the final result. This
// lets the brain see the actually-relevant part of a file instead of
// always the first 1400 chars.
function pickKBSnippets(ctx, max = 2) {
  const kb = loadMarketingKB();
  if (!kb.length) return null;

  const ctxText = extractKBCtxText(ctx);
  const candidates = [];

  for (const file of kb) {
    const { score: fileScore, signals: fileSignals } = scoreKBRelevance(file, ctx);
    const sections = file.sections?.length ? file.sections : null;
    if (!sections) {
      // Fallback for files with no parsable sections: use the whole file.
      if (fileScore > 0) {
        candidates.push({
          file,
          section: { title: '(full file)', body: file.content },
          total: fileScore,
          signals: fileSignals,
        });
      }
      continue;
    }

    // Score each section; keep the best one for this file.
    let best = null;
    for (const section of sections) {
      const { score: kwScore, hits } = scoreKBSection(section, file.topic, ctxText);
      const total = fileScore + kwScore;
      if (!best || total > best.total) best = { section, total, hits };
    }
    if (!best || best.total <= 0) continue;

    const signals = [...fileSignals];
    if (best.hits > 0) {
      signals.push(`section match: "${best.section.title}" (${best.hits} keyword hits)`);
    }
    candidates.push({
      file,
      section: best.section,
      total: best.total,
      signals,
    });
  }

  candidates.sort((a, b) => b.total - a.total);
  const picked = candidates.slice(0, max);

  if (!picked.length) {
    // Fallback: always inject the positioning foundation section
    const positioning = kb.find(f => f.topic === 'positioning');
    if (!positioning) return null;
    const sec = positioning.sections?.[0] || { title: '(intro)', body: positioning.content };
    return [{
      topic: positioning.topic,
      title: positioning.title,
      section_title: sec.title,
      excerpt: sec.body.slice(0, 1400),
      signals: ['fallback: positioning is always relevant'],
    }];
  }

  return picked.map(p => ({
    topic: p.file.topic,
    title: p.file.title,
    section_title: p.section.title,
    excerpt: p.section.body.slice(0, 1400),
    signals: p.signals,
  }));
}

// Approximate cost per 1M tokens for Claude Haiku 4.5 (input / output). Rough.
const HAIKU_COST_IN = 1.00 / 1_000_000;
const HAIKU_COST_OUT = 5.00 / 1_000_000;
const SONNET_COST_IN = 3.00 / 1_000_000;
const SONNET_COST_OUT = 15.00 / 1_000_000;

const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';
const DEEP_MODEL = 'claude-sonnet-4-5-20250929';

// Hard cap: max spend per day across all brain cycles. Cron checks this before running.
// Manual triggers via HTTP can override by passing ?force=1.
// Override via env BRAIN_DAILY_COST_CAP_USD (e.g. "1.50").
const DAILY_COST_CAP_USD = (() => {
  const raw = parseFloat(process.env.BRAIN_DAILY_COST_CAP_USD);
  return Number.isFinite(raw) && raw > 0 ? raw : 2.00;
})();

// Only kinds we can safely and meaningfully materialize into downstream queues.
// email.draft stays advisory because email_queue is per-recipient-per-template, not a draft store.
const AUTO_EXECUTABLE_KINDS = new Set(['content.draft', 'social.draft', 'research.note']);

function costForUsage(model, tokensIn, tokensOut) {
  if (model.includes('sonnet')) return tokensIn * SONNET_COST_IN + tokensOut * SONNET_COST_OUT;
  return tokensIn * HAIKU_COST_IN + tokensOut * HAIKU_COST_OUT;
}

export default function registerMarketingBrainRoutes({
  app, db, config, cron,
  marketingCache,
  getEnvKeyFromApps,
  cbAnthropic,
  cronFail, sendTelegram,
}) {

  function getAnthropicKey() { return getEnvKeyFromApps('ANTHROPIC_API_KEY'); }

  // ---------- Context collection ----------

  // Deep context pulls wider history for Sonnet cycles: 10 prior briefs vs 3,
  // all open + recently-executed actions vs 10, 15 learnings vs 5, and 30-day
  // brief cadence so the strategic prompt can reason about pacing.
  function collectAppContextDeep(appSlug) {
    const ctx = collectAppContext(appSlug);
    try {
      const prior = db.prepare(
        `SELECT id, created_at, analysis, hypotheses_json FROM marketing_briefs
         WHERE app_slug = ? ORDER BY created_at DESC LIMIT 10`
      ).all(appSlug);
      ctx.prior_briefs = prior.map(b => ({
        id: b.id,
        created_at: b.created_at,
        analysis_summary: (b.analysis || '').slice(0, 400),
        hypotheses: safeJSON(b.hypotheses_json, []).slice(0, 5),
      }));
    } catch {}
    try {
      ctx.open_actions = db.prepare(
        `SELECT id, kind, title, priority, status, created_at FROM marketing_actions
         WHERE app_slug = ? AND status IN ('proposed','approved') ORDER BY priority DESC LIMIT 25`
      ).all(appSlug);
    } catch {}
    try {
      ctx.executed_actions = db.prepare(
        `SELECT kind, title, outcome, executed_at FROM marketing_actions
         WHERE app_slug = ? AND status = 'executed' AND outcome IS NOT NULL
         ORDER BY executed_at DESC LIMIT 15`
      ).all(appSlug);
    } catch { ctx.executed_actions = []; }
    try {
      ctx.learnings = db.prepare(
        `SELECT learning, confidence, created_at FROM marketing_learnings
         WHERE app_slug = ? ORDER BY created_at DESC LIMIT 15`
      ).all(appSlug);
    } catch {}
    try {
      const cadence = db.prepare(
        `SELECT COUNT(*) as n, MIN(created_at) as first, MAX(created_at) as last
         FROM marketing_briefs WHERE app_slug = ? AND created_at >= datetime('now','-30 day')`
      ).get(appSlug);
      ctx.cadence_30d = cadence;
    } catch {}
    return ctx;
  }

  function collectAppContext(appSlug) {
    const appDef = config.apps.find(a => slugify(a.name) === appSlug);
    if (!appDef) throw new Error(`Unknown app: ${appSlug}`);

    const ctx = {
      slug: appSlug,
      name: appDef.name,
      domain: appDef.domain,
      type: appDef.type,
      description: appDef.description || '',
      tech: appDef.tech || '',
      marketing: appDef.marketing || null,
      tagline: appDef.marketing?.tagline || '',
      category: appDef.marketing?.category || appDef.type || 'unknown',
    };

    // Traffic (from marketing cache if available).
    // Cache shape (from marketing.js:842): { apps: { "AppName": { domain, realtime,
    // visitors, pageviews, bounceRate, visitDuration, topPages, topSources } } }.
    // This is a 30d snapshot, not a dual 7d/30d rollup — older brain code
    // expected suffixed fields that never existed.
    try {
      const row = marketingCache?.analytics?.apps?.[appDef.name];
      if (row && !row.error) {
        ctx.traffic = {
          visitors_30d: row.visitors ?? 0,
          pageviews_30d: row.pageviews ?? 0,
          bounce_rate: row.bounceRate ?? null,
          visit_duration_s: row.visitDuration ?? null,
          realtime: row.realtime ?? 0,
          top_pages: Array.isArray(row.topPages) ? row.topPages.slice(0, 3) : [],
          top_sources: Array.isArray(row.topSources) ? row.topSources.slice(0, 3) : [],
        };
      }
    } catch {}

    // Revenue (from marketing cache). Cache shape: { apps: { "AppName":
    // { mrr, revenue30d, chargeCount30d, activeSubscriptions, balance,
    // currency, recentCharges } } }. Amounts are in minor units (cents).
    try {
      const row = marketingCache?.revenue?.apps?.[appDef.name];
      if (row && !row.error) {
        ctx.revenue = {
          mrr: row.mrr ?? 0,
          revenue_30d: row.revenue30d ?? 0,
          charge_count_30d: row.chargeCount30d ?? 0,
          active_subscriptions: row.activeSubscriptions ?? 0,
          currency: row.currency || 'eur',
        };
      }
    } catch {}

    // SEO audit (from marketing cache). Cache shape: { apps: { "AppName":
    // { score, grade, issues, ... } } }.
    try {
      const row = marketingCache?.seo?.apps?.[appDef.name];
      if (row && !row.error) {
        ctx.seo = {
          score: row.score ?? null,
          grade: row.grade ?? null,
          issues: Array.isArray(row.issues) ? row.issues.slice(0, 5) : [],
        };
      }
    } catch {}

    // Recent mentions from social_mentions
    try {
      const mentions = db.prepare(
        `SELECT platform, title, url, created_at FROM social_mentions
         WHERE (keyword LIKE ? OR title LIKE ? OR body LIKE ?)
         ORDER BY created_at DESC LIMIT 5`
      ).all(`%${appDef.name}%`, `%${appDef.name}%`, `%${appDef.name}%`);
      ctx.recent_mentions = mentions;
    } catch { ctx.recent_mentions = []; }

    // Last N briefs for this app — so the brain sees its own memory
    try {
      const prior = db.prepare(
        `SELECT id, created_at, analysis, hypotheses_json FROM marketing_briefs
         WHERE app_slug = ? ORDER BY created_at DESC LIMIT 3`
      ).all(appSlug);
      ctx.prior_briefs = prior.map(b => ({
        id: b.id,
        created_at: b.created_at,
        analysis_summary: (b.analysis || '').slice(0, 280),
        hypotheses: safeJSON(b.hypotheses_json, []).slice(0, 3),
      }));
    } catch { ctx.prior_briefs = []; }

    // Open actions queue for this app
    try {
      const openActions = db.prepare(
        `SELECT id, kind, title, priority, status FROM marketing_actions
         WHERE app_slug = ? AND status IN ('proposed','approved') ORDER BY priority DESC LIMIT 10`
      ).all(appSlug);
      ctx.open_actions = openActions;
    } catch { ctx.open_actions = []; }

    // Learnings
    try {
      const learnings = db.prepare(
        `SELECT learning, confidence FROM marketing_learnings
         WHERE app_slug = ? ORDER BY created_at DESC LIMIT 5`
      ).all(appSlug);
      ctx.learnings = learnings;
    } catch { ctx.learnings = []; }

    // Proxy-layer infra state (nginx sub_filter, CSP, etc.). Null if mount missing.
    ctx.infra_state = readInfraState(appDef);

    // Summary of open action kinds for KB keyword matching
    try {
      const kindRows = db.prepare(
        `SELECT DISTINCT kind FROM marketing_actions
         WHERE app_slug = ? AND status IN ('proposed','approved')`
      ).all(appSlug);
      ctx.open_actions_summary_kinds = kindRows.map(r => r.kind);
    } catch { ctx.open_actions_summary_kinds = []; }

    // Marketing knowledge base snippets — picks 1-2 most-relevant sections
    // from marketing-kb/*.md based on the app's stage, open actions, learnings.
    // Injected into the prompt so the brain can ground proposals in proven
    // indie-SaaS marketing principles instead of generic advice.
    ctx.kb_snippets = pickKBSnippets(ctx, 2);

    return ctx;
  }

  // ---------- Prompt crafting ----------

  function buildSystemPrompt() {
    return `You are an expert marketing strategist and growth operator for a small indie SaaS portfolio.
Your job: analyze the current state of a single product and propose concrete, specific, actionable marketing moves.

You are NOT vague. You are NOT generic. Every hypothesis and action is specific to THIS product, its niche, its audience, and its current state. You cite evidence from the context when possible.

Respond ONLY with a raw JSON object. Do NOT wrap in markdown code fences. Do NOT prefix with prose. Start your response with { and end with }. The shape must be exactly:
{
  "analysis": "2-4 sentences of brutally honest assessment of the product's current marketing state and the single biggest opportunity or blocker",
  "hypotheses": [
    { "hypothesis": "specific testable claim", "rationale": "why you believe it", "confidence": "low|medium|high" }
  ],
  "actions": [
    {
      "kind": "content.draft|social.draft|email.draft|seo|outreach|landing|research.note",
      "title": "short actionable title",
      "body": "detailed description OR draft content (for .draft kinds, include the actual draft text)",
      "priority": 1-10,
      "effort": "low|medium|high",
      "impact": "low|medium|high",
      "rationale": "why this action now"
    }
  ]
}

Rules:
- Produce 3-6 actions. Mix kinds. Prioritize cheap+high-impact first.
- For content.draft: write the actual blog post draft headline + outline, not just "write a blog post"
- For social.draft: write the actual tweet/thread text, ready to post
- For email.draft: write the actual subject + body
- For seo: name the specific fix (missing meta description on /pricing, etc.)
- For outreach: name the specific target (a subreddit, a newsletter, a Fachschaft, a competitor's audience) with channel + approach
- For research.note: a crisp insight to remember for future cycles
- Reference prior briefs and avoid proposing duplicates of open actions
- Acknowledge learnings when relevant
- If an infra flag in "Proxy-layer state" is already true, DO NOT propose installing it again (e.g. do not propose "install Plausible" when plausible_injected=true)
- If a "Marketing knowledge base" section is provided, GROUND your analysis and proposals in its principles. Cite the KB topic by name in your rationale when applying a principle (e.g. "per the pre-traction KB, direct outreach beats content for <$500 MRR stage"). Do NOT ignore the KB — it was selected because it matches this app's stage and situation.`;
  }

  function buildSystemPromptDeep() {
    return `You are a senior marketing strategist doing a DEEP quarterly review for a single indie SaaS product. This is not a tactical cycle — this is strategic synthesis. You have access to the full brain memory for this product: every prior brief, every executed action with its outcome, every learning. Use it.

Your job: synthesize patterns across history, identify the ONE strategic bet worth making in the next 6-12 weeks, and produce a mix of strategic actions and tactical follow-ups.

You are BRUTALLY HONEST. If prior actions failed, say so by name. If the product has no traction after N cycles, name it. If the positioning is wrong, propose a repositioning. Do not repeat what has already been tried without new evidence.

Respond ONLY with a raw JSON object (no markdown fences). Shape:
{
  "analysis": "4-8 sentences of strategic synthesis — what the data actually shows after N cycles, what has and hasn't worked, what the single biggest bet is for the next 6-12 weeks",
  "hypotheses": [
    { "hypothesis": "specific testable claim grounded in the history", "rationale": "evidence from prior briefs/outcomes/learnings", "confidence": "low|medium|high" }
  ],
  "actions": [
    {
      "kind": "content.draft|social.draft|email.draft|seo|outreach|landing|research.note",
      "title": "short actionable title",
      "body": "detailed description OR draft content (for .draft kinds, include the actual draft text)",
      "priority": 1-10,
      "effort": "low|medium|high",
      "impact": "low|medium|high",
      "rationale": "why this action now, referencing history explicitly",
      "horizon": "this-week|this-month|this-quarter"
    }
  ]
}

Rules:
- Produce 4-8 actions. Include at least one STRATEGIC action (horizon=this-quarter, impact=high) — a repositioning move, a new channel experiment, a pricing test, a partnership pitch, etc.
- Explicitly reference prior briefs or executed actions by what they revealed (e.g. "Prior brief #124 tested X and learned Y")
- If learnings tagged [WORKED] exist, propose how to scale them. If learnings tagged [FAILED] exist, propose a different angle or a kill decision
- Do NOT propose duplicates of still-open actions
- For content.draft / social.draft / email.draft: write the actual draft content, production-ready
- For outreach: name the exact target (specific subreddit, newsletter, conference, person)
- Respect the "Proxy-layer state" section: infra items already flagged true are DONE at nginx layer — do not propose reinstalling them
- A "Marketing knowledge base" section is provided with dense principles from world-class indie-SaaS marketers (April Dunford, Rob Walling, Reforge, Julian Shapiro, etc.). GROUND the strategic analysis in these principles — cite the KB topic by name in your rationale. The KB was selected because it matches this app's stage, so ignoring it means ignoring the best available advice.`;
  }

  function buildUserPromptDeep(ctx) {
    const lines = [];
    lines.push(`## Product: ${ctx.name} (${ctx.domain})`);
    lines.push(`Type: ${ctx.type} | Category: ${ctx.category}`);
    lines.push(`Tagline: ${ctx.tagline || '(none)'}`);
    lines.push(`Description: ${ctx.description}`);
    lines.push(`Tech: ${ctx.tech}`);
    lines.push('');
    lines.push('## Current metrics');
    if (ctx.traffic) lines.push(`Traffic (Plausible 30d): ${JSON.stringify(ctx.traffic)}`);
    else lines.push('Traffic: cache empty (Plausible reachable but /api/marketing/analytics not yet called this cycle)');
    if (ctx.revenue) lines.push(`Revenue (Stripe): MRR €${(ctx.revenue.mrr / 100).toFixed(2)}, 30d €${(ctx.revenue.revenue_30d / 100).toFixed(2)}, active subs ${ctx.revenue.active_subscriptions}, charges 30d ${ctx.revenue.charge_count_30d}`);
    else lines.push('Revenue: none yet');
    if (ctx.seo) lines.push(`SEO score: ${ctx.seo.score}/100 (${ctx.seo.grade || '?'}). Top issues: ${JSON.stringify(ctx.seo.issues)}`);
    if (ctx.infra_state) {
      lines.push('');
      lines.push('## Proxy-layer state (nginx sub_filter, already done — DO NOT propose installing these)');
      lines.push(JSON.stringify(ctx.infra_state));
    }
    lines.push('');
    if (ctx.kb_snippets?.length) {
      lines.push('## Marketing knowledge base (relevant to this app — ground your analysis in these principles)');
      for (const s of ctx.kb_snippets) {
        const secLabel = s.section_title && s.section_title !== '(intro)' ? ` › ${s.section_title}` : '';
        lines.push(`### KB: ${s.title} [${s.topic}]${secLabel}`);
        if (s.signals?.length) lines.push(`(selected because: ${s.signals.join('; ')})`);
        lines.push(s.excerpt);
        lines.push('');
      }
    }
    if (ctx.cadence_30d) {
      lines.push(`## Brain cadence (30d)`);
      lines.push(`${ctx.cadence_30d.n} briefs between ${ctx.cadence_30d.first || '(none)'} and ${ctx.cadence_30d.last || '(none)'}`);
      lines.push('');
    }
    if (ctx.recent_mentions?.length) {
      lines.push('## Recent mentions');
      for (const m of ctx.recent_mentions) lines.push(`- [${m.platform}] ${m.title}`);
      lines.push('');
    }
    if (ctx.prior_briefs?.length) {
      lines.push('## Prior briefs (full history — do not repeat)');
      for (const b of ctx.prior_briefs) {
        lines.push(`- #${b.id} @ ${b.created_at}: ${b.analysis_summary}`);
        if (b.hypotheses?.length) {
          for (const h of b.hypotheses.slice(0, 2)) {
            lines.push(`    hypothesis: ${h.hypothesis || h}`);
          }
        }
      }
      lines.push('');
    }
    if (ctx.executed_actions?.length) {
      lines.push('## Previously executed actions + outcomes (ground truth signal)');
      for (const a of ctx.executed_actions) {
        lines.push(`- [${a.kind}] ${a.title} → ${a.outcome}`);
      }
      lines.push('');
    }
    if (ctx.open_actions?.length) {
      lines.push('## Currently open actions (do not duplicate)');
      for (const a of ctx.open_actions) lines.push(`- #${a.id} [${a.kind}] ${a.title} (p${a.priority}, ${a.status})`);
      lines.push('');
    }
    if (ctx.learnings?.length) {
      lines.push('## Accumulated learnings (use these, do not contradict without evidence)');
      for (const l of ctx.learnings) lines.push(`- [${l.confidence}] ${l.learning}`);
      lines.push('');
    }
    lines.push('Synthesize the history. Propose the strategic bet. Produce the JSON response now.');
    return lines.join('\n');
  }

  function buildUserPrompt(ctx) {
    const lines = [];
    lines.push(`## Product: ${ctx.name} (${ctx.domain})`);
    lines.push(`Type: ${ctx.type} | Category: ${ctx.category}`);
    lines.push(`Tagline: ${ctx.tagline || '(none)'}`);
    lines.push(`Description: ${ctx.description}`);
    lines.push(`Tech: ${ctx.tech}`);
    lines.push('');
    lines.push('## Current state');
    if (ctx.traffic) {
      lines.push(`Traffic (Plausible 30d): ${JSON.stringify(ctx.traffic)}`);
    } else lines.push('Traffic: cache empty (Plausible reachable but /api/marketing/analytics not yet called this cycle)');
    if (ctx.revenue) {
      lines.push(`Revenue (Stripe): MRR €${(ctx.revenue.mrr / 100).toFixed(2)}, 30d €${(ctx.revenue.revenue_30d / 100).toFixed(2)}, active subs ${ctx.revenue.active_subscriptions}, charges 30d ${ctx.revenue.charge_count_30d}`);
    } else lines.push('Revenue: unknown (no Stripe data — likely no paid product or no sales yet)');
    if (ctx.seo) {
      lines.push(`SEO score: ${ctx.seo.score}/100 (${ctx.seo.grade || '?'}). Top issues: ${JSON.stringify(ctx.seo.issues)}`);
    } else lines.push('SEO: unknown');
    if (ctx.infra_state) {
      lines.push('');
      lines.push('## Proxy-layer state (nginx sub_filter, already done — DO NOT propose installing these)');
      lines.push(JSON.stringify(ctx.infra_state));
    }
    lines.push('');
    if (ctx.kb_snippets?.length) {
      lines.push('## Marketing knowledge base (relevant to this app — ground your analysis in these principles)');
      for (const s of ctx.kb_snippets) {
        const secLabel = s.section_title && s.section_title !== '(intro)' ? ` › ${s.section_title}` : '';
        lines.push(`### KB: ${s.title} [${s.topic}]${secLabel}`);
        if (s.signals?.length) lines.push(`(selected because: ${s.signals.join('; ')})`);
        lines.push(s.excerpt);
        lines.push('');
      }
    }
    if (ctx.recent_mentions?.length) {
      lines.push('## Recent mentions');
      for (const m of ctx.recent_mentions) lines.push(`- [${m.platform}] ${m.title}`);
      lines.push('');
    }
    if (ctx.prior_briefs?.length) {
      lines.push('## Prior brain briefs (do not repeat these)');
      for (const b of ctx.prior_briefs) lines.push(`- ${b.created_at}: ${b.analysis_summary}`);
      lines.push('');
    }
    if (ctx.open_actions?.length) {
      lines.push('## Currently open actions (do not duplicate)');
      for (const a of ctx.open_actions) lines.push(`- [${a.kind}] ${a.title} (p${a.priority})`);
      lines.push('');
    }
    if (ctx.learnings?.length) {
      lines.push('## Learnings so far');
      for (const l of ctx.learnings) lines.push(`- [${l.confidence}] ${l.learning}`);
      lines.push('');
    }
    lines.push('Produce the JSON response now.');
    return lines.join('\n');
  }

  // ---------- JSON parsing with fallback ----------

  function parseBrainOutput(text) {
    const t = (text || '').trim();
    try { return JSON.parse(t); } catch {}
    // Strip markdown fences (with or without closing fence)
    const fenceOpen = t.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceOpen) { try { return JSON.parse(fenceOpen[1]); } catch {} }
    const fenceOnlyOpen = t.match(/```(?:json)?\s*([\s\S]*)$/);
    if (fenceOnlyOpen) { try { return JSON.parse(fenceOnlyOpen[1]); } catch {} }
    // Greedy outer brace match
    const braceStart = t.indexOf('{');
    const braceEnd = t.lastIndexOf('}');
    if (braceStart >= 0 && braceEnd > braceStart) {
      try { return JSON.parse(t.slice(braceStart, braceEnd + 1)); } catch {}
    }
    // Last-ditch: if JSON was truncated mid-string, try progressively trimming from the end
    // and auto-closing open arrays/objects. Only effective when stop_reason was max_tokens.
    if (braceStart >= 0) {
      const head = t.slice(braceStart);
      for (let i = head.length; i > 200; i -= 100) {
        const chunk = head.slice(0, i);
        // Count unclosed braces/brackets and append closers
        let open = 0, openArr = 0, inStr = false, esc = false;
        for (const ch of chunk) {
          if (esc) { esc = false; continue; }
          if (ch === '\\') { esc = true; continue; }
          if (ch === '"') { inStr = !inStr; continue; }
          if (inStr) continue;
          if (ch === '{') open++; else if (ch === '}') open--;
          else if (ch === '[') openArr++; else if (ch === ']') openArr--;
        }
        if (inStr) continue;
        // Trim to last comma or opening brace to avoid broken trailing value
        const lastComma = chunk.lastIndexOf(',');
        const lastBrace = chunk.lastIndexOf('{');
        const trimAt = Math.max(lastComma, lastBrace);
        if (trimAt < 0) continue;
        const fixed = chunk.slice(0, trimAt).replace(/,\s*$/, '') +
          ']'.repeat(Math.max(0, openArr)) + '}'.repeat(Math.max(0, open));
        try { return JSON.parse(fixed); } catch {}
      }
    }
    return null;
  }

  // ---------- Persistence ----------

  const insertBrief = db.prepare(`INSERT INTO marketing_briefs
    (app_slug, context_json, analysis, hypotheses_json, model, tokens_in, tokens_out, cost_usd, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  const insertAction = db.prepare(`INSERT INTO marketing_actions
    (brief_id, app_slug, kind, title, body, priority, effort, impact, auto_executable)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);

  // Prepared statements for downstream queue writes
  const insertContentDraft = db.prepare(`INSERT INTO content_queue
    (app_slug, content_type, title, body, status, ai_model, token_count)
    VALUES (?, ?, ?, ?, 'draft', ?, ?)`);

  const insertSocialDraft = db.prepare(`INSERT INTO social_posts
    (platform, content, post_type, status, scheduled_at)
    VALUES (?, ?, 'short', 'draft', NULL)`);

  const insertLearning = db.prepare(`INSERT INTO marketing_learnings
    (app_slug, learning, evidence_json, confidence) VALUES (?, ?, ?, ?)`);

  // Heuristic: infer social platform from the draft body. Falls back to 'draft-multi'.
  function inferSocialPlatform(title, body) {
    const s = `${title} ${body}`.toLowerCase();
    if (s.includes('linkedin')) return 'linkedin';
    if (s.includes('bluesky')) return 'bluesky';
    if (s.includes('mastodon')) return 'mastodon';
    if (s.includes('dev.to') || s.includes('devto')) return 'devto';
    if (s.includes('twitter') || s.includes('x.com') || s.includes('x thread') || /\/x\s/.test(s)) return 'twitter';
    return 'draft-multi';
  }

  // Materialize an auto-executable action into its downstream queue. Idempotent
  // per (app_slug, title) within the last 7 days to avoid duplicates from repeat cycles.
  function autoExecuteAction({ appSlug, kind, title, body, model, tokenCount, confidence }) {
    try {
      if (kind === 'content.draft') {
        const dupe = db.prepare(
          `SELECT id FROM content_queue WHERE app_slug = ? AND title = ? AND created_at >= datetime('now','-7 day') LIMIT 1`
        ).get(appSlug, title);
        if (dupe) return { status: 'skipped-duplicate', target: 'content_queue', id: dupe.id };
        const r = insertContentDraft.run(appSlug, 'blog-brain', title, body, model || DEFAULT_MODEL, tokenCount || 0);
        return { status: 'inserted', target: 'content_queue', id: r.lastInsertRowid };
      }
      if (kind === 'social.draft') {
        const dupe = db.prepare(
          `SELECT id FROM social_posts WHERE content = ? AND created_at >= datetime('now','-7 day') LIMIT 1`
        ).get(body);
        if (dupe) return { status: 'skipped-duplicate', target: 'social_posts', id: dupe.id };
        const platform = inferSocialPlatform(title, body);
        const r = insertSocialDraft.run(platform, body);
        return { status: 'inserted', target: 'social_posts', id: r.lastInsertRowid };
      }
      if (kind === 'research.note') {
        const learning = `${title}: ${body}`.slice(0, 2000);
        const evidence = JSON.stringify({ source: 'brain', app_slug: appSlug });
        const r = insertLearning.run(appSlug, learning, evidence, confidence || 'medium');
        return { status: 'inserted', target: 'marketing_learnings', id: r.lastInsertRowid };
      }
      return { status: 'skipped-kind-not-executable', target: null };
    } catch (e) {
      console.error(`[brain] auto-exec ${kind} failed for ${appSlug}:`, e.message);
      return { status: 'error', error: e.message };
    }
  }

  function persistBrief(appSlug, ctx, parsed, model, usage, durationMs) {
    const analysis = parsed.analysis || '(no analysis)';
    const hypotheses = Array.isArray(parsed.hypotheses) ? parsed.hypotheses : [];
    const actions = Array.isArray(parsed.actions) ? parsed.actions : [];
    const cost = costForUsage(model, usage.inputTokens || 0, usage.outputTokens || 0);

    const result = insertBrief.run(
      appSlug,
      JSON.stringify(ctx),
      analysis,
      JSON.stringify(hypotheses),
      model,
      usage.inputTokens || 0,
      usage.outputTokens || 0,
      cost,
      durationMs,
    );
    const briefId = result.lastInsertRowid;

    let inserted = 0;
    let autoExecuted = 0;
    const autoExecResults = [];
    const updateActionExecuted = db.prepare(
      `UPDATE marketing_actions SET status = 'executed', executed_at = datetime('now'), outcome = ? WHERE id = ?`
    );
    for (const a of actions) {
      if (!a || !a.kind || !a.title || !a.body) continue;
      const kind = String(a.kind).slice(0, 32);
      const autoExec = AUTO_EXECUTABLE_KINDS.has(kind) ? 1 : 0;
      const title = String(a.title).slice(0, 280);
      const body = String(a.body).slice(0, 8000);
      try {
        const result = insertAction.run(
          briefId,
          appSlug,
          kind,
          title,
          body,
          Math.max(1, Math.min(10, parseInt(a.priority) || 5)),
          ['low', 'medium', 'high'].includes(a.effort) ? a.effort : 'medium',
          ['low', 'medium', 'high'].includes(a.impact) ? a.impact : 'medium',
          autoExec,
        );
        inserted++;

        // If the action is auto-executable, materialize it into a downstream queue
        // right now and mark the action as executed with the insert location in outcome.
        if (autoExec) {
          const execResult = autoExecuteAction({
            appSlug, kind, title, body,
            model, tokenCount: usage.outputTokens || 0,
            confidence: a.confidence,
          });
          if (execResult.status === 'inserted' || execResult.status === 'skipped-duplicate') {
            updateActionExecuted.run(
              `auto-exec ${execResult.status}: ${execResult.target}#${execResult.id}`,
              result.lastInsertRowid
            );
            if (execResult.status === 'inserted') autoExecuted++;
          }
          autoExecResults.push({ action_id: result.lastInsertRowid, ...execResult });
        }
      } catch (e) {
        console.error('[brain] action insert failed:', e.message);
      }
    }
    return { briefId, actionsInserted: inserted, autoExecuted, autoExecResults };
  }

  // ---------- Core cycle ----------

  function getTodayCostUsd() {
    const row = db.prepare(
      `SELECT COALESCE(SUM(cost_usd), 0) as total FROM marketing_briefs WHERE created_at >= datetime('now','-1 day')`
    ).get();
    return row.total || 0;
  }

  async function runBrainCycle(appSlug, { model = DEFAULT_MODEL, force = false, deep = false } = {}) {
    const apiKey = getAnthropicKey();
    if (!apiKey) throw new Error('ANTHROPIC_API_KEY not found in any app .env');
    if (!force) {
      const todayCost = getTodayCostUsd();
      if (todayCost >= DAILY_COST_CAP_USD) {
        const err = new Error(`Daily cost cap reached: $${todayCost.toFixed(2)} >= $${DAILY_COST_CAP_USD.toFixed(2)}. Use ?force=1 to override.`);
        err.code = 'COST_CAP';
        throw err;
      }
    }

    // Ensure marketing caches are warm before reading context. No-op within TTL
    // (5 min), so this is free on back-to-back cycles and only does work if a
    // cycle fires before the 6h cron or startup warm has populated the cache.
    if (marketingCache?.warm) {
      try { await marketingCache.warm(); }
      catch (err) { console.error('[BRAIN] cache warm failed (proceeding with stale):', err.message); }
    }

    const started = Date.now();
    const ctx = deep ? collectAppContextDeep(appSlug) : collectAppContext(appSlug);
    const system = deep ? buildSystemPromptDeep() : buildSystemPrompt();
    const user = deep ? buildUserPromptDeep(ctx) : buildUserPrompt(ctx);

    const resp = await cbAnthropic.call(() => callAnthropic(apiKey, {
      model,
      system,
      messages: [{ role: 'user', content: user }],
      // Sonnet generates ~40-70 tok/s; 8000 tokens needs 120-200s of headroom.
      // Haiku is 3-4x faster so 6000 fits comfortably in 60s.
      maxTokens: deep ? 8000 : 6000,
      timeout: deep ? 300_000 : 60_000,
    }));

    const parsed = parseBrainOutput(resp.text);
    if (!parsed) {
      console.error('[brain] parse fail — raw response:\n', resp.text?.slice(0, 2000));
      throw new Error('Failed to parse brain JSON response');
    }

    const durationMs = Date.now() - started;
    const usage = { inputTokens: resp.inputTokens, outputTokens: resp.outputTokens };
    const { briefId, actionsInserted, autoExecuted, autoExecResults } = persistBrief(appSlug, ctx, parsed, model, usage, durationMs);

    return {
      briefId,
      appSlug,
      actionsInserted,
      autoExecuted,
      autoExecResults,
      analysis: parsed.analysis,
      model,
      deep,
      tokens: resp.tokens,
      cost_usd: costForUsage(model, usage.inputTokens || 0, usage.outputTokens || 0),
      duration_ms: durationMs,
    };
  }

  // ---------- Rotation helper ----------

  function pickNextAppsToAnalyze(count) {
    const marketable = getMarketableApps(config.apps);
    // Order by days-since-last-brief, ascending = most-stale first
    const rows = db.prepare(
      `SELECT app_slug, MAX(created_at) AS last FROM marketing_briefs GROUP BY app_slug`
    ).all();
    const lastMap = new Map(rows.map(r => [r.app_slug, r.last]));
    const scored = marketable.map(a => {
      const slug = slugify(a.name);
      const last = lastMap.get(slug);
      const ageMs = last ? Date.now() - new Date(last).getTime() : Infinity;
      return { slug, ageMs };
    });
    scored.sort((a, b) => b.ageMs - a.ageMs);
    return scored.slice(0, count).map(s => s.slug);
  }

  // ---------- HTTP endpoints ----------

  app.get('/api/brain/briefs', asyncRoute((req, res) => {
    const appSlug = req.query.app;
    const limit = Math.min(100, parseInt(req.query.limit) || 25);
    const rows = appSlug
      ? db.prepare(`SELECT id, app_slug, created_at, analysis, model, tokens_in, tokens_out, cost_usd, duration_ms
                    FROM marketing_briefs WHERE app_slug = ? ORDER BY created_at DESC LIMIT ?`).all(appSlug, limit)
      : db.prepare(`SELECT id, app_slug, created_at, analysis, model, tokens_in, tokens_out, cost_usd, duration_ms
                    FROM marketing_briefs ORDER BY created_at DESC LIMIT ?`).all(limit);
    res.json(rows);
  }));

  app.get('/api/brain/briefs/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    const brief = db.prepare(`SELECT * FROM marketing_briefs WHERE id = ?`).get(id);
    if (!brief) return res.status(404).json({ error: 'Not found' });
    brief.context = safeJSON(brief.context_json, {});
    brief.hypotheses = safeJSON(brief.hypotheses_json, []);
    delete brief.context_json;
    delete brief.hypotheses_json;
    brief.actions = db.prepare(`SELECT * FROM marketing_actions WHERE brief_id = ? ORDER BY priority DESC`).all(id);
    res.json(brief);
  }));

  app.post('/api/brain/run/:appSlug', asyncRoute(async (req, res) => {
    const deep = req.query.deep === '1' || req.body?.deep === true;
    const force = req.query.force === '1' || req.body?.force === true;
    const model = deep ? DEEP_MODEL : DEFAULT_MODEL;
    try {
      const result = await runBrainCycle(req.params.appSlug, { model, force, deep });
      res.json(result);
    } catch (e) {
      const status = e.code === 'COST_CAP' ? 429 : 500;
      res.status(status).json({ error: e.message, code: e.code });
    }
  }));

  app.post('/api/brain/run-batch', asyncRoute(async (req, res) => {
    const count = Math.min(8, parseInt(req.body?.count) || 3);
    const force = req.query.force === '1' || req.body?.force === true;
    const slugs = pickNextAppsToAnalyze(count);
    const results = [];
    for (const slug of slugs) {
      try { results.push(await runBrainCycle(slug, { force })); }
      catch (e) {
        results.push({ appSlug: slug, error: e.message, code: e.code });
        if (e.code === 'COST_CAP') break; // stop iterating if we hit the cap
      }
    }
    res.json({ count: results.length, results });
  }));

  app.get('/api/brain/actions', asyncRoute((req, res) => {
    const status = req.query.status || 'proposed';
    const appSlug = req.query.app;
    const kind = req.query.kind;
    const limit = Math.min(200, parseInt(req.query.limit) || 50);
    const clauses = ['status = ?'];
    const params = [status];
    if (appSlug) { clauses.push('app_slug = ?'); params.push(appSlug); }
    if (kind) { clauses.push('kind = ?'); params.push(kind); }
    params.push(limit);
    const rows = db.prepare(
      `SELECT * FROM marketing_actions WHERE ${clauses.join(' AND ')} ORDER BY priority DESC, created_at DESC LIMIT ?`
    ).all(...params);
    res.json(rows);
  }));

  // Heuristic: classify an outcome string as positive / neutral / negative to decide
  // whether it's worth persisting as a durable learning. Keeps the feedback loop
  // honest — we only learn from actions that actually moved a metric.
  function classifyOutcome(outcome) {
    const s = String(outcome || '').toLowerCase();
    if (!s.trim()) return { sentiment: 'none', confidence: 'low' };
    const positive = /(worked|success|converted|signups?|signup|subscribed|purchase|sales?|revenue|\+\d|\bup\b|grew|growth|viral|trending|ranked|upvot|engagement|reply|replies|leads?|opened|clicked|ctr|traffic|visit|impress|retweet|share|follow|like|featured|published|accepted|approved|indexed)/;
    const negative = /(failed|fail|no response|no replies|ignored|rejected|removed|banned|flagged|bounce|error|dropped|down|declined|lost|churn|unsubscri|deleted|spam|zero|nothing|flop)/;
    if (positive.test(s) && !negative.test(s)) return { sentiment: 'positive', confidence: 'medium' };
    if (negative.test(s) && !positive.test(s)) return { sentiment: 'negative', confidence: 'medium' };
    if (positive.test(s) && negative.test(s)) return { sentiment: 'mixed', confidence: 'low' };
    return { sentiment: 'neutral', confidence: 'low' };
  }

  // Extract a durable learning from an executed action. Skips neutral outcomes —
  // those add noise without signal. Returns the inserted learning id, or null.
  function extractLearningFromAction(action, outcome) {
    const { sentiment, confidence } = classifyOutcome(outcome);
    if (sentiment === 'none' || sentiment === 'neutral') return null;
    const prefix = sentiment === 'positive' ? 'WORKED' : sentiment === 'negative' ? 'FAILED' : 'MIXED';
    const learning = `[${prefix}] ${action.kind}: ${action.title} — ${outcome}`.slice(0, 2000);
    const evidence = JSON.stringify({
      source: 'feedback-loop',
      action_id: action.id,
      brief_id: action.brief_id,
      kind: action.kind,
      sentiment,
    });
    try {
      const r = insertLearning.run(action.app_slug, learning, evidence, confidence);
      return r.lastInsertRowid;
    } catch (e) {
      console.error('[brain] learning extract failed:', e.message);
      return null;
    }
  }

  app.patch('/api/brain/actions/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    const { status, outcome } = req.body || {};
    const allowed = ['proposed', 'approved', 'executed', 'rejected', 'superseded'];
    if (!allowed.includes(status)) return res.status(400).json({ error: `status must be one of ${allowed.join(', ')}` });
    const executedAt = status === 'executed' ? new Date().toISOString() : null;
    db.prepare(`UPDATE marketing_actions SET status = ?, outcome = COALESCE(?, outcome), executed_at = COALESCE(?, executed_at) WHERE id = ?`)
      .run(status, outcome || null, executedAt, id);
    const updated = db.prepare(`SELECT * FROM marketing_actions WHERE id = ?`).get(id);

    // Feedback loop: when an action is marked executed with a non-empty outcome,
    // attempt to extract a durable learning so future brain cycles see the signal.
    let learningId = null;
    if (status === 'executed' && outcome) {
      learningId = extractLearningFromAction(updated, outcome);
    }
    res.json({ ...updated, learning_id: learningId });
  }));

  app.get('/api/brain/learnings', asyncRoute((req, res) => {
    const appSlug = req.query.app;
    const limit = Math.min(200, parseInt(req.query.limit) || 50);
    const rows = appSlug
      ? db.prepare(`SELECT id, app_slug, learning, evidence_json, confidence, created_at
                    FROM marketing_learnings WHERE app_slug = ? ORDER BY created_at DESC LIMIT ?`).all(appSlug, limit)
      : db.prepare(`SELECT id, app_slug, learning, evidence_json, confidence, created_at
                    FROM marketing_learnings ORDER BY created_at DESC LIMIT ?`).all(limit);
    for (const r of rows) { r.evidence = safeJSON(r.evidence_json, {}); delete r.evidence_json; }
    res.json(rows);
  }));

  app.get('/api/brain/morning', asyncRoute((_req, res) => {
    const topActions = db.prepare(
      `SELECT id, app_slug, kind, title, priority, impact, effort, created_at
       FROM marketing_actions WHERE status = 'proposed' ORDER BY priority DESC, created_at DESC LIMIT 10`
    ).all();
    const recentBriefs = db.prepare(
      `SELECT id, app_slug, created_at, analysis FROM marketing_briefs ORDER BY created_at DESC LIMIT 8`
    ).all();
    const staleness = db.prepare(
      `SELECT a.slug, MAX(b.created_at) as last_brief FROM (
         SELECT json_each.value AS slug FROM (SELECT '[]' as v)
       ) a LEFT JOIN marketing_briefs b ON b.app_slug = a.slug GROUP BY a.slug`
    ).all().catch(() => []);
    const marketable = getMarketableApps(config.apps);
    const staleRows = db.prepare(`SELECT app_slug, MAX(created_at) AS last FROM marketing_briefs GROUP BY app_slug`).all();
    const lastMap = new Map(staleRows.map(r => [r.app_slug, r.last]));
    const missingBriefs = marketable
      .map(a => ({ slug: slugify(a.name), name: a.name, last: lastMap.get(slugify(a.name)) || null }))
      .filter(a => !a.last || (Date.now() - new Date(a.last).getTime()) > 48 * 3600_000);
    res.json({ topActions, recentBriefs, missingBriefs });
  }));

  app.get('/api/brain/stats', asyncRoute((_req, res) => {
    const today = db.prepare(`SELECT COUNT(*) as n, SUM(cost_usd) as cost FROM marketing_briefs WHERE created_at >= datetime('now','-1 day')`).get();
    const week = db.prepare(`SELECT COUNT(*) as n, SUM(cost_usd) as cost FROM marketing_briefs WHERE created_at >= datetime('now','-7 day')`).get();
    const actionsByStatus = db.prepare(`SELECT status, COUNT(*) as n FROM marketing_actions GROUP BY status`).all();
    const actionsByKind = db.prepare(`SELECT kind, COUNT(*) as n FROM marketing_actions WHERE status = 'proposed' GROUP BY kind ORDER BY n DESC`).all();
    const totalBriefs = db.prepare(`SELECT COUNT(*) as n FROM marketing_briefs`).get();
    const costToday = today.cost || 0;
    res.json({
      briefs_today: today.n, cost_today: costToday,
      briefs_week: week.n, cost_week: week.cost || 0,
      briefs_total: totalBriefs.n,
      daily_cap_usd: DAILY_COST_CAP_USD,
      cap_remaining_usd: Math.max(0, DAILY_COST_CAP_USD - costToday),
      cap_pct_used: Math.round((costToday / DAILY_COST_CAP_USD) * 100),
      actions_by_status: actionsByStatus,
      proposed_actions_by_kind: actionsByKind,
    });
  }));

  // Marketing knowledge base browsing: list all KB files with titles + topics,
  // or fetch the full content of one file by topic slug. Powers the dashboard
  // KB browser UI. Read-only; KB files are checked into git and loaded at boot.
  app.get('/api/brain/kb', asyncRoute((_req, res) => {
    const kb = loadMarketingKB();
    res.json({
      total: kb.length,
      files: kb.map(f => ({
        topic: f.topic,
        title: f.title,
        file: f.file,
        length: f.content.length,
        preview: f.content.split('\n').slice(2, 8).join('\n').slice(0, 400),
      })),
    });
  }));

  app.get('/api/brain/kb/:topic', asyncRoute((req, res) => {
    const kb = loadMarketingKB();
    const topic = String(req.params.topic || '').toLowerCase();
    const file = kb.find(f => f.topic === topic);
    if (!file) return res.status(404).json({ error: `KB topic not found: ${topic}`, available: kb.map(f => f.topic) });
    res.json({ topic: file.topic, title: file.title, file: file.file, content: file.content });
  }));

  // Portfolio-wide infra_state map: for every marketable app, return the
  // 8 proxy-layer flags that readInfraState detected from nginx configs,
  // plus a summary count of how many apps have each flag set. Used by the
  // dashboard UI to surface which apps are missing admin_tracking, which
  // are missing banner injection, etc. Reads the same 60s-cached infra map
  // that brain cycles use, so this is essentially free.
  app.get('/api/brain/infra-state', asyncRoute((_req, res) => {
    const marketable = getMarketableApps(config.apps);
    const FLAGS = [
      'plausible_injected', 'admin_tracking', 'banner_injection',
      'crosslinks_widget', 'csp_header', 'gzip_on', 'long_cache', 'ssl_letsencrypt',
    ];
    const apps = marketable.map(a => {
      const state = readInfraState(a);
      return {
        slug: slugify(a.name),
        name: a.name,
        domain: a.domain || null,
        nginx_file: state?.nginx_file || null,
        flags: FLAGS.reduce((acc, f) => { acc[f] = state ? !!state[f] : null; return acc; }, {}),
      };
    });
    const summary = FLAGS.reduce((acc, f) => {
      acc[f] = apps.filter(a => a.flags[f] === true).length;
      return acc;
    }, {});
    res.json({ total: apps.length, summary, flags: FLAGS, apps });
  }));

  // ---------- Cron ----------

  // Every 4 hours, rotate through 3 stalest apps
  cron.schedule('15 */4 * * *', async () => {
    const started = Date.now();
    try {
      const todayCost = getTodayCostUsd();
      if (todayCost >= DAILY_COST_CAP_USD) {
        console.log(`[brain-cron] skipping cycle — daily cost cap reached ($${todayCost.toFixed(2)}/$${DAILY_COST_CAP_USD.toFixed(2)})`);
        return;
      }
      const slugs = pickNextAppsToAnalyze(3);
      console.log(`[brain-cron] starting cycle for ${slugs.length} apps: ${slugs.join(', ')} (spent today: $${todayCost.toFixed(2)})`);
      for (const slug of slugs) {
        try {
          const r = await runBrainCycle(slug);
          console.log(`[brain-cron] ${slug}: brief ${r.briefId}, ${r.actionsInserted} actions (${r.autoExecuted} auto-exec), $${r.cost_usd.toFixed(4)}, ${r.duration_ms}ms`);
        } catch (e) {
          if (e.code === 'COST_CAP') {
            console.log(`[brain-cron] cost cap hit mid-cycle, stopping`);
            break;
          }
          console.error(`[brain-cron] ${slug} failed:`, e.message);
          cronFail?.('marketing-brain-cycle', e);
        }
      }
      console.log(`[brain-cron] cycle done in ${Date.now() - started}ms`);
    } catch (e) {
      console.error('[brain-cron] cycle error:', e.message);
      cronFail?.('marketing-brain-cycle', e);
    }
  });

  // Picks apps that most need a deep strategic review. Preference:
  //   1. Apps that have never received a Sonnet deep cycle
  //   2. Apps whose last deep cycle is oldest
  // Limited to marketable apps (same pool as regular cycles).
  function pickNextDeepApps(count) {
    const marketable = getMarketableApps(config.apps);
    const rows = db.prepare(
      `SELECT app_slug, MAX(created_at) AS last FROM marketing_briefs
       WHERE model LIKE '%sonnet%' GROUP BY app_slug`
    ).all();
    const lastMap = new Map(rows.map(r => [r.app_slug, r.last]));
    const scored = marketable.map(a => {
      const slug = slugify(a.name);
      const last = lastMap.get(slug);
      const ageMs = last ? Date.now() - new Date(last).getTime() : Infinity;
      return { slug, ageMs };
    });
    scored.sort((a, b) => b.ageMs - a.ageMs);
    return scored.slice(0, count).map(s => s.slug);
  }

  // Weekly Monday 6 AM: deep strategic review of the 2 apps that most need it.
  // Sonnet 4.5 with full-history context. ~$0.10-0.20 per cycle. Bounded by the
  // same daily cost cap as the tactical cycles. Runs BEFORE the morning rollup
  // so fresh strategic insights show up in today's email.
  cron.schedule('0 6 * * 1', async () => {
    const started = Date.now();
    try {
      const todayCost = getTodayCostUsd();
      if (todayCost >= DAILY_COST_CAP_USD) {
        console.log(`[brain-cron-deep] skipping — daily cost cap reached ($${todayCost.toFixed(2)}/$${DAILY_COST_CAP_USD.toFixed(2)})`);
        return;
      }
      const slugs = pickNextDeepApps(2);
      console.log(`[brain-cron-deep] weekly deep-dive for ${slugs.length} apps: ${slugs.join(', ')}`);
      for (const slug of slugs) {
        try {
          const r = await runBrainCycle(slug, { model: DEEP_MODEL, deep: true });
          console.log(`[brain-cron-deep] ${slug}: brief ${r.briefId}, ${r.actionsInserted} actions, $${r.cost_usd.toFixed(4)}, ${r.duration_ms}ms`);
        } catch (e) {
          if (e.code === 'COST_CAP') {
            console.log(`[brain-cron-deep] cost cap hit mid-cycle, stopping`);
            break;
          }
          console.error(`[brain-cron-deep] ${slug} failed:`, e.message);
          cronFail?.('marketing-brain-deep-cycle', e);
        }
      }
      console.log(`[brain-cron-deep] weekly cycle done in ${Date.now() - started}ms`);
    } catch (e) {
      console.error('[brain-cron-deep] cycle error:', e.message);
      cronFail?.('marketing-brain-deep-cycle', e);
    }
  });

  // ---------- Morning rollup (Telegram + optional email) ----------

  function buildMorningRollup() {
    const topActions = db.prepare(
      `SELECT id, app_slug, kind, title, priority, impact, effort FROM marketing_actions
       WHERE status = 'proposed' ORDER BY priority DESC, created_at DESC LIMIT 5`
    ).all();
    const queueCount = db.prepare(
      `SELECT COUNT(*) as n FROM marketing_actions WHERE status = 'proposed'`
    ).get().n;
    const briefs24h = db.prepare(
      `SELECT COUNT(*) as n, COALESCE(SUM(cost_usd), 0) as cost FROM marketing_briefs WHERE created_at >= datetime('now','-1 day')`
    ).get();
    const recentLearnings = db.prepare(
      `SELECT app_slug, learning, confidence FROM marketing_learnings
       WHERE created_at >= datetime('now','-1 day') ORDER BY created_at DESC LIMIT 5`
    ).all();
    return { topActions, queueCount, briefs24h, recentLearnings };
  }

  function renderRollupText({ topActions, queueCount, briefs24h, recentLearnings }) {
    const lines = ['🧠 Marketing Brain — morning rollup'];
    lines.push(`${briefs24h.n} briefs in last 24h ($${(briefs24h.cost || 0).toFixed(3)}) • ${queueCount} actions in queue`);
    lines.push('');
    lines.push('Top 5 proposed actions:');
    for (const a of topActions) {
      lines.push(`• [${a.app_slug}] ${a.title} (p${a.priority}, ${a.kind}, ${a.impact || '?'}/${a.effort || '?'})`);
    }
    if (recentLearnings.length) {
      lines.push('');
      lines.push('Fresh learnings (last 24h):');
      for (const l of recentLearnings) lines.push(`• [${l.app_slug}] ${l.learning.slice(0, 140)}`);
    }
    lines.push('');
    lines.push('See /api/brain/morning for the full picture.');
    return lines.join('\n');
  }

  function escHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function renderRollupHtml({ topActions, queueCount, briefs24h, recentLearnings }) {
    const actionItems = topActions.map(a => `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;font-family:system-ui,sans-serif;font-size:13px;color:#6b7280;">${escHtml(a.app_slug)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;font-family:system-ui,sans-serif;font-size:14px;color:#111;">${escHtml(a.title)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;font-family:system-ui,sans-serif;font-size:12px;color:#6b7280;">p${a.priority} · ${escHtml(a.kind)}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #eee;font-family:system-ui,sans-serif;font-size:12px;color:#6b7280;">${escHtml(a.impact || '?')} / ${escHtml(a.effort || '?')}</td>
      </tr>
    `).join('');

    const learningItems = recentLearnings.length
      ? `<h3 style="margin:24px 0 8px;font-family:system-ui,sans-serif;font-size:14px;color:#374151;">Fresh learnings (last 24h)</h3>
         <ul style="margin:0;padding-left:20px;font-family:system-ui,sans-serif;font-size:13px;color:#4b5563;">
         ${recentLearnings.map(l => `<li style="margin-bottom:4px;"><strong>${escHtml(l.app_slug)}</strong>: ${escHtml(l.learning.slice(0, 200))}</li>`).join('')}
         </ul>`
      : '';

    return `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f9fafb;">
  <div style="max-width:640px;margin:0 auto;background:white;border-radius:12px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.05);">
    <div style="font-family:system-ui,sans-serif;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span style="font-size:24px;">🧠</span>
        <h1 style="margin:0;font-size:20px;color:#111;">Marketing Brain — morning rollup</h1>
      </div>
      <p style="margin:0 0 24px;color:#6b7280;font-size:13px;">
        ${briefs24h.n} briefs in last 24h · $${(briefs24h.cost || 0).toFixed(3)} spent · ${queueCount} actions in queue
      </p>
      <h2 style="margin:0 0 8px;font-size:14px;color:#374151;">Top 5 proposed actions</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:8px;">
        <thead>
          <tr>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #e5e7eb;font-family:system-ui,sans-serif;font-size:11px;text-transform:uppercase;color:#9ca3af;">App</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #e5e7eb;font-family:system-ui,sans-serif;font-size:11px;text-transform:uppercase;color:#9ca3af;">Action</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #e5e7eb;font-family:system-ui,sans-serif;font-size:11px;text-transform:uppercase;color:#9ca3af;">Priority</th>
            <th style="text-align:left;padding:8px 12px;border-bottom:2px solid #e5e7eb;font-family:system-ui,sans-serif;font-size:11px;text-transform:uppercase;color:#9ca3af;">Impact/Effort</th>
          </tr>
        </thead>
        <tbody>${actionItems || '<tr><td colspan="4" style="padding:16px;text-align:center;color:#9ca3af;font-family:system-ui,sans-serif;font-size:13px;">No actions in queue</td></tr>'}</tbody>
      </table>
      ${learningItems}
      <p style="margin:24px 0 0;padding-top:16px;border-top:1px solid #e5e7eb;font-family:system-ui,sans-serif;font-size:12px;color:#9ca3af;">
        Open the dashboard at <a href="https://admin.crelvo.dev/#marketing" style="color:#6366f1;">admin.crelvo.dev</a> to review, approve, or reject actions.
      </p>
    </div>
  </div>
</body></html>`;
  }

  async function sendRollupEmail(toEmail, subject, text, html) {
    const resendKey = getEnvKeyFromApps('RESEND_API_KEY');
    if (!resendKey) return { skipped: 'no-resend-key' };
    const fromDomain = process.env.EMAIL_FROM_DOMAIN || 'abschlusscheck.de';
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${resendKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `Marketing Brain <noreply@${fromDomain}>`,
        to: [toEmail],
        subject,
        html,
        text,
      }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.message || `Resend error ${res.status}`);
    }
    return await res.json();
  }

  app.post('/api/brain/morning/send-test', asyncRoute(async (req, res) => {
    const to = req.query.to || req.body?.to || process.env.BRAIN_MORNING_EMAIL;
    if (!to) return res.status(400).json({ error: 'No destination (pass ?to= or set BRAIN_MORNING_EMAIL)' });
    const rollup = buildMorningRollup();
    const subject = `🧠 Brain rollup — ${rollup.topActions.length} actions, $${(rollup.briefs24h.cost || 0).toFixed(3)} today`;
    const text = renderRollupText(rollup);
    const html = renderRollupHtml(rollup);
    try {
      const result = await sendRollupEmail(to, subject, text, html);
      res.json({ ok: true, to, ...result });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }));

  // Daily 7am: morning rollup via Telegram + optional email
  cron.schedule('0 7 * * *', async () => {
    try {
      const rollup = buildMorningRollup();
      if (!rollup.topActions.length) return;

      const text = renderRollupText(rollup);
      sendTelegram?.(text);

      const to = process.env.BRAIN_MORNING_EMAIL;
      if (to) {
        try {
          const subject = `🧠 Brain rollup — ${rollup.topActions.length} actions, $${(rollup.briefs24h.cost || 0).toFixed(3)} today`;
          const html = renderRollupHtml(rollup);
          const r = await sendRollupEmail(to, subject, text, html);
          if (r.skipped) {
            console.log(`[brain-cron] morning email skipped: ${r.skipped}`);
          } else {
            console.log(`[brain-cron] morning email sent to ${to}`);
          }
        } catch (e) {
          console.error('[brain-cron] morning email failed:', e.message);
          cronFail?.('marketing-brain-morning-email', e);
        }
      }
    } catch (e) {
      console.error('[brain-cron] morning rollup error:', e.message);
      cronFail?.('marketing-brain-morning-rollup', e);
    }
  });

  return {
    runBrainCycle,
    collectAppContext,
    collectAppContextDeep,
    pickNextAppsToAnalyze,
    pickNextDeepApps,
  };
}
