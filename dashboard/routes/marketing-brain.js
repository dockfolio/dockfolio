// Marketing Brain — autonomous per-app analysis + action generation loop.
// Runs on a cron, rotates through all marketable apps, produces briefs and
// proposes concrete actions. See plans/marketing-brain.md for design.

import { asyncRoute, callAnthropic, getMarketableApps, safeJSON, parseId } from '../utils.js';

// Approximate cost per 1M tokens for Claude Haiku 4.5 (input / output). Rough.
const HAIKU_COST_IN = 1.00 / 1_000_000;
const HAIKU_COST_OUT = 5.00 / 1_000_000;
const SONNET_COST_IN = 3.00 / 1_000_000;
const SONNET_COST_OUT = 15.00 / 1_000_000;

const DEFAULT_MODEL = 'claude-haiku-4-5-20251001';
const DEEP_MODEL = 'claude-sonnet-4-5-20250929';

const AUTO_EXECUTABLE_KINDS = new Set(['content.draft', 'social.draft', 'email.draft', 'research.note']);

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

  function collectAppContext(appSlug) {
    const appDef = config.apps.find(a => (a.slug || a.name?.toLowerCase()) === appSlug);
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

    // Traffic (from marketing cache if available)
    try {
      const analytics = marketingCache?.analytics;
      if (analytics && Array.isArray(analytics.apps)) {
        const row = analytics.apps.find(a => a.slug === appSlug || a.name === appDef.name);
        if (row) {
          ctx.traffic = {
            visitors_7d: row.visitors_7d ?? null,
            pageviews_7d: row.pageviews_7d ?? null,
            bounce_rate: row.bounce_rate ?? null,
            visitors_30d: row.visitors_30d ?? null,
            trend: row.trend ?? null,
          };
        }
      }
    } catch {}

    // Revenue (from marketing cache)
    try {
      const revenue = marketingCache?.revenue;
      if (revenue && Array.isArray(revenue.apps)) {
        const row = revenue.apps.find(a => a.slug === appSlug || a.name === appDef.name);
        if (row) {
          ctx.revenue = {
            mrr: row.mrr ?? 0,
            revenue_30d: row.revenue_30d ?? 0,
            customer_count: row.customer_count ?? 0,
            currency: row.currency || 'eur',
          };
        }
      }
    } catch {}

    // SEO (latest audit row from cache)
    try {
      const seo = marketingCache?.seo;
      if (seo && Array.isArray(seo.audits)) {
        const row = seo.audits.find(a => a.slug === appSlug || a.domain === appDef.domain);
        if (row) {
          ctx.seo = {
            score: row.score ?? null,
            issues: Array.isArray(row.issues) ? row.issues.slice(0, 5) : [],
            meta_ok: row.meta_ok ?? null,
          };
        }
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
- Acknowledge learnings when relevant`;
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
      lines.push(`Traffic (Plausible): ${JSON.stringify(ctx.traffic)}`);
    } else lines.push('Traffic: unknown (Plausible data unavailable)');
    if (ctx.revenue) {
      lines.push(`Revenue (Stripe): MRR €${(ctx.revenue.mrr / 100).toFixed(2)}, 30d €${(ctx.revenue.revenue_30d / 100).toFixed(2)}, customers ${ctx.revenue.customer_count}`);
    } else lines.push('Revenue: unknown (no Stripe data — likely no paid product or no sales yet)');
    if (ctx.seo) {
      lines.push(`SEO score: ${ctx.seo.score}/100. Top issues: ${JSON.stringify(ctx.seo.issues)}`);
    } else lines.push('SEO: unknown');
    lines.push('');
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
    for (const a of actions) {
      if (!a || !a.kind || !a.title || !a.body) continue;
      const kind = String(a.kind).slice(0, 32);
      const autoExec = AUTO_EXECUTABLE_KINDS.has(kind) ? 1 : 0;
      try {
        insertAction.run(
          briefId,
          appSlug,
          kind,
          String(a.title).slice(0, 280),
          String(a.body).slice(0, 8000),
          Math.max(1, Math.min(10, parseInt(a.priority) || 5)),
          ['low', 'medium', 'high'].includes(a.effort) ? a.effort : 'medium',
          ['low', 'medium', 'high'].includes(a.impact) ? a.impact : 'medium',
          autoExec,
        );
        inserted++;
      } catch (e) {
        console.error('[brain] action insert failed:', e.message);
      }
    }
    return { briefId, actionsInserted: inserted };
  }

  // ---------- Core cycle ----------

  async function runBrainCycle(appSlug, { model = DEFAULT_MODEL } = {}) {
    const apiKey = getAnthropicKey();
    if (!apiKey) throw new Error('ANTHROPIC_API_KEY not found in any app .env');

    const started = Date.now();
    const ctx = collectAppContext(appSlug);
    const system = buildSystemPrompt();
    const user = buildUserPrompt(ctx);

    const resp = await cbAnthropic.call(() => callAnthropic(apiKey, {
      model,
      system,
      messages: [{ role: 'user', content: user }],
      maxTokens: 6000,
      timeout: 60_000,
    }));

    const parsed = parseBrainOutput(resp.text);
    if (!parsed) {
      console.error('[brain] parse fail — raw response:\n', resp.text?.slice(0, 2000));
      throw new Error('Failed to parse brain JSON response');
    }

    const durationMs = Date.now() - started;
    const usage = { inputTokens: resp.inputTokens, outputTokens: resp.outputTokens };
    const { briefId, actionsInserted } = persistBrief(appSlug, ctx, parsed, model, usage, durationMs);

    return {
      briefId,
      appSlug,
      actionsInserted,
      analysis: parsed.analysis,
      model,
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
      const slug = a.slug || a.name?.toLowerCase();
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
    const model = deep ? DEEP_MODEL : DEFAULT_MODEL;
    try {
      const result = await runBrainCycle(req.params.appSlug, { model });
      res.json(result);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }));

  app.post('/api/brain/run-batch', asyncRoute(async (req, res) => {
    const count = Math.min(8, parseInt(req.body?.count) || 3);
    const slugs = pickNextAppsToAnalyze(count);
    const results = [];
    for (const slug of slugs) {
      try { results.push(await runBrainCycle(slug)); }
      catch (e) { results.push({ appSlug: slug, error: e.message }); }
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

  app.patch('/api/brain/actions/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    const { status, outcome } = req.body || {};
    const allowed = ['proposed', 'approved', 'executed', 'rejected', 'superseded'];
    if (!allowed.includes(status)) return res.status(400).json({ error: `status must be one of ${allowed.join(', ')}` });
    const executedAt = status === 'executed' ? new Date().toISOString() : null;
    db.prepare(`UPDATE marketing_actions SET status = ?, outcome = COALESCE(?, outcome), executed_at = COALESCE(?, executed_at) WHERE id = ?`)
      .run(status, outcome || null, executedAt, id);
    const updated = db.prepare(`SELECT * FROM marketing_actions WHERE id = ?`).get(id);
    res.json(updated);
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
      .map(a => ({ slug: a.slug || a.name?.toLowerCase(), name: a.name, last: lastMap.get(a.slug || a.name?.toLowerCase()) || null }))
      .filter(a => !a.last || (Date.now() - new Date(a.last).getTime()) > 48 * 3600_000);
    res.json({ topActions, recentBriefs, missingBriefs });
  }));

  app.get('/api/brain/stats', asyncRoute((_req, res) => {
    const today = db.prepare(`SELECT COUNT(*) as n, SUM(cost_usd) as cost FROM marketing_briefs WHERE created_at >= datetime('now','-1 day')`).get();
    const week = db.prepare(`SELECT COUNT(*) as n, SUM(cost_usd) as cost FROM marketing_briefs WHERE created_at >= datetime('now','-7 day')`).get();
    const actionsByStatus = db.prepare(`SELECT status, COUNT(*) as n FROM marketing_actions GROUP BY status`).all();
    const actionsByKind = db.prepare(`SELECT kind, COUNT(*) as n FROM marketing_actions WHERE status = 'proposed' GROUP BY kind ORDER BY n DESC`).all();
    const totalBriefs = db.prepare(`SELECT COUNT(*) as n FROM marketing_briefs`).get();
    res.json({
      briefs_today: today.n, cost_today: today.cost || 0,
      briefs_week: week.n, cost_week: week.cost || 0,
      briefs_total: totalBriefs.n,
      actions_by_status: actionsByStatus,
      proposed_actions_by_kind: actionsByKind,
    });
  }));

  // ---------- Cron ----------

  // Every 4 hours, rotate through 3 stalest apps
  cron.schedule('15 */4 * * *', async () => {
    const started = Date.now();
    try {
      const slugs = pickNextAppsToAnalyze(3);
      console.log(`[brain-cron] starting cycle for ${slugs.length} apps: ${slugs.join(', ')}`);
      for (const slug of slugs) {
        try {
          const r = await runBrainCycle(slug);
          console.log(`[brain-cron] ${slug}: brief ${r.briefId}, ${r.actionsInserted} actions, $${r.cost_usd.toFixed(4)}, ${r.duration_ms}ms`);
        } catch (e) {
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

  // Daily 7am: morning rollup via Telegram
  cron.schedule('0 7 * * *', async () => {
    try {
      const topActions = db.prepare(
        `SELECT app_slug, kind, title, priority FROM marketing_actions
         WHERE status = 'proposed' ORDER BY priority DESC, created_at DESC LIMIT 5`
      ).all();
      if (!topActions.length) return;
      const lines = ['🧠 Marketing Brain — top 5 actions for today:'];
      for (const a of topActions) lines.push(`• [${a.app_slug}] ${a.title} (p${a.priority}, ${a.kind})`);
      const stats = db.prepare(
        `SELECT COUNT(*) as n FROM marketing_actions WHERE status = 'proposed'`
      ).get();
      lines.push(`\n${stats.n} actions in queue. See /api/brain/morning`);
      sendTelegram?.(lines.join('\n'));
    } catch (e) {
      console.error('[brain-cron] morning rollup error:', e.message);
    }
  });

  return {
    runBrainCycle,
    collectAppContext,
    pickNextAppsToAnalyze,
  };
}
