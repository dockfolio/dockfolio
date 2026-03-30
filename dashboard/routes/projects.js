import { asyncRoute, slugify, callAnthropic, todayString, containerName, parseId } from '../utils.js';

export default function registerProjectsRoutes({ app, db, docker, config, cron, findAppBySlug, qLatestMetric, qLatestSEO, getAnthropicKey, getPlausibleUrl, getPlausibleApiKey, cbAnthropic, sendTelegram, cronFail, TIMEOUT_QUICK, MS_PER_DAY }) {

  const MS_PER_HOUR = 3_600_000;

  // Initialize project_meta defaults for all apps in config.yml
  function initProjectDefaults() {
    const lifecycleByType = { saas: 'launched', tool: 'launched', infra: 'mature', static: 'mature', redirect: 'deprecated' };
    const priorityByType = { saas: 1, tool: 1, infra: 2, static: 3, redirect: 4 };
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const existing = db.prepare('SELECT id FROM project_meta WHERE app_slug = ?').get(slug);
      if (!existing) {
        db.prepare('INSERT INTO project_meta (app_slug, lifecycle, priority) VALUES (?, ?, ?)').run(slug, lifecycleByType[appDef.type] || 'launched', priorityByType[appDef.type] || 2);
      }
    }
  }
  try { initProjectDefaults(); } catch (err) { console.error('[PROJECTS] Init error:', err.message); }

  // --- Overview: All apps enriched with meta + live KPIs ---
  app.get('/api/projects/overview', asyncRoute(async (req, res) => {
    const allMeta = db.prepare('SELECT * FROM project_meta').all();
    const metaMap = Object.fromEntries(allMeta.map(m => [m.app_slug, m]));
    const today = todayString();

    const apps = config.apps.map(appDef => {
      const slug = slugify(appDef.name);
      const meta = metaMap[slug] || {};

      // Open task count
      const taskCounts = db.prepare("SELECT status, COUNT(*) as count FROM project_tasks WHERE app_slug = ? GROUP BY status").all(slug);
      const taskMap = Object.fromEntries(taskCounts.map(t => [t.status, t.count]));
      const openTasks = (taskMap.todo || 0) + (taskMap.in_progress || 0) + (taskMap.blocked || 0);
      const doneTasks = taskMap.done || 0;
      const overdueTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND due_date < ? AND status NOT IN ('done','cancelled')").get(slug, today)?.count || 0;

      // Roadmap counts
      const roadmapCounts = db.prepare("SELECT status, COUNT(*) as count FROM project_roadmap WHERE app_slug = ? GROUP BY status").all(slug);
      const rmMap = Object.fromEntries(roadmapCounts.map(r => [r.status, r.count]));

      // Latest SEO score
      const seo = qLatestSEO.get(slug);

      // Latest security findings count for this app
      const secFindings = db.prepare("SELECT COUNT(*) as count FROM security_findings WHERE app_slug = ? AND status = 'open'").get(slug);

      // Latest MRR from metrics_daily
      const mrrRow = qLatestMetric.get(slug, 'mrr');

      return {
        slug, name: appDef.name, type: appDef.type, domain: appDef.domain,
        description: appDef.description, tech: appDef.tech,
        lifecycle: meta.lifecycle || 'launched',
        priority: meta.priority || 2,
        revenue_goal_mrr: meta.revenue_goal_mrr,
        traffic_goal_mpv: meta.traffic_goal_mpv,
        user_goal: meta.user_goal,
        notes: meta.notes,
        mrr: mrrRow?.value || 0,
        seo_score: seo?.score || null, seo_grade: seo?.grade || null,
        security_findings: secFindings?.count || 0,
        tasks: { open: openTasks, done: doneTasks, overdue: overdueTasks },
        roadmap: { idea: rmMap.idea || 0, planned: rmMap.planned || 0, in_progress: rmMap.in_progress || 0, shipped: rmMap.shipped || 0 },
      };
    });

    // Portfolio totals
    const totalOpenTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE status NOT IN ('done','cancelled')").get()?.count || 0;
    const totalOverdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today)?.count || 0;
    const thisWeekDone = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE completed_at >= datetime('now', '-7 days')").get()?.count || 0;

    res.json({ apps, totals: { openTasks: totalOpenTasks, overdueTasks: totalOverdue, completedThisWeek: thisWeekDone } });
  }));

  // --- Update project meta ---
  app.put('/api/projects/meta/:slug', asyncRoute((req, res) => {
    const slug = req.params.slug;
    const { lifecycle, priority, revenue_goal_mrr, traffic_goal_mpv, user_goal, notes } = req.body;
    const ALLOWED_PROJECT_META_FIELDS = ['lifecycle', 'priority', 'revenue_goal_mrr', 'traffic_goal_mpv', 'user_goal', 'notes'];
    const existing = db.prepare('SELECT id FROM project_meta WHERE app_slug = ?').get(slug);
    if (!existing) {
      db.prepare('INSERT INTO project_meta (app_slug, lifecycle, priority, revenue_goal_mrr, traffic_goal_mpv, user_goal, notes) VALUES (?, ?, ?, ?, ?, ?, ?)').run(slug, lifecycle || 'launched', priority || 2, revenue_goal_mrr || null, traffic_goal_mpv || null, user_goal || null, notes || null);
    } else {
      const fields = [];
      const values = [];
      if (lifecycle !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('lifecycle')) { fields.push('lifecycle = ?'); values.push(lifecycle); }
      if (priority !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('priority')) { fields.push('priority = ?'); values.push(priority); }
      if (revenue_goal_mrr !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('revenue_goal_mrr')) { fields.push('revenue_goal_mrr = ?'); values.push(revenue_goal_mrr); }
      if (traffic_goal_mpv !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('traffic_goal_mpv')) { fields.push('traffic_goal_mpv = ?'); values.push(traffic_goal_mpv); }
      if (user_goal !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('user_goal')) { fields.push('user_goal = ?'); values.push(user_goal); }
      if (notes !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('notes')) { fields.push('notes = ?'); values.push(notes); }
      if (fields.length > 0) {
        fields.push("updated_at = datetime('now')");
        values.push(slug);
        db.prepare(`UPDATE project_meta SET ${fields.join(', ')} WHERE app_slug = ?`).run(...values);
      }
    }
    res.json({ ok: true });
  }));

  // --- Tasks CRUD ---
  app.get('/api/projects/tasks', asyncRoute((req, res) => {
    const { app, status, priority } = req.query;
    let sql = 'SELECT * FROM project_tasks WHERE 1=1';
    const params = [];
    if (app) { sql += ' AND app_slug = ?'; params.push(app); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (priority) { sql += ' AND priority = ?'; params.push(priority); }
    sql += ' ORDER BY CASE priority WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 END, due_date ASC NULLS LAST, created_at DESC';
    res.json(db.prepare(sql).all(...params));
  }));

  app.post('/api/projects/tasks', asyncRoute((req, res) => {
    const { app_slug, title, description, priority, due_date, reminder_at, tags } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });
    const result = db.prepare('INSERT INTO project_tasks (app_slug, title, description, priority, due_date, reminder_at, tags) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
      app_slug || null, title, description || null, priority || 'medium', due_date || null, reminder_at || null, tags ? JSON.stringify(tags) : null
    );
    res.json({ ok: true, id: result.lastInsertRowid });
  }));

  app.put('/api/projects/tasks/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid task ID' });
    const { title, description, status, priority, due_date, reminder_at, tags, app_slug } = req.body;
    const ALLOWED_TASK_FIELDS = ['title', 'description', 'status', 'priority', 'due_date', 'reminder_at', 'tags', 'app_slug'];
    const fields = [];
    const values = [];
    if (title !== undefined && ALLOWED_TASK_FIELDS.includes('title')) { fields.push('title = ?'); values.push(title); }
    if (description !== undefined && ALLOWED_TASK_FIELDS.includes('description')) { fields.push('description = ?'); values.push(description); }
    if (status !== undefined && ALLOWED_TASK_FIELDS.includes('status')) { fields.push('status = ?'); values.push(status); }
    if (priority !== undefined && ALLOWED_TASK_FIELDS.includes('priority')) { fields.push('priority = ?'); values.push(priority); }
    if (due_date !== undefined && ALLOWED_TASK_FIELDS.includes('due_date')) { fields.push('due_date = ?'); values.push(due_date); }
    if (reminder_at !== undefined && ALLOWED_TASK_FIELDS.includes('reminder_at')) { fields.push('reminder_at = ?'); values.push(reminder_at); fields.push('reminder_sent = 0'); }
    if (tags !== undefined && ALLOWED_TASK_FIELDS.includes('tags')) { fields.push('tags = ?'); values.push(JSON.stringify(tags)); }
    if (app_slug !== undefined && ALLOWED_TASK_FIELDS.includes('app_slug')) { fields.push('app_slug = ?'); values.push(app_slug); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push("updated_at = datetime('now')");
    values.push(id);
    const result = db.prepare(`UPDATE project_tasks SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    if (result.changes === 0) return res.status(404).json({ error: 'Task not found' });
    res.json({ ok: true });
  }));

  app.delete('/api/projects/tasks/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid task ID' });
    const result = db.prepare('DELETE FROM project_tasks WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Task not found' });
    res.json({ ok: true });
  }));

  app.post('/api/projects/tasks/:id/complete', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid task ID' });
    const result = db.prepare("UPDATE project_tasks SET status = 'done', completed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?").run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Task not found' });
    res.json({ ok: true });
  }));

  app.get('/api/projects/tasks/overdue', asyncRoute((_req, res) => {
    const today = todayString();
    const tasks = db.prepare("SELECT * FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled') ORDER BY due_date ASC").all(today);
    res.json(tasks);
  }));

  app.get('/api/projects/tasks/today', asyncRoute((_req, res) => {
    const today = todayString();
    const tasks = db.prepare("SELECT * FROM project_tasks WHERE (due_date <= ? OR due_date IS NULL) AND status NOT IN ('done','cancelled') ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END, due_date ASC").all(today);
    res.json(tasks);
  }));

  app.post('/api/projects/tasks/import', asyncRoute((req, res) => {
    const { text, app_slug } = req.body;
    if (!text) return res.status(400).json({ error: 'text is required' });
    const lines = text.split('\n');
    let created = 0;
    for (const line of lines) {
      const doneMatch = line.match(/^[-*]\s+\[x\]\s+(.+)/i);
      const todoMatch = line.match(/^[-*]\s+\[\s?\]\s+(.+)/i);
      if (doneMatch) {
        db.prepare("INSERT INTO project_tasks (app_slug, title, status, completed_at) VALUES (?, ?, 'done', datetime('now'))").run(app_slug || null, doneMatch[1].trim());
        created++;
      } else if (todoMatch) {
        db.prepare("INSERT INTO project_tasks (app_slug, title, status) VALUES (?, ?, 'todo')").run(app_slug || null, todoMatch[1].trim());
        created++;
      }
    }
    res.json({ ok: true, created });
  }));

  // --- Roadmap CRUD ---
  app.get('/api/projects/roadmap', asyncRoute((req, res) => {
    const { app, status } = req.query;
    let sql = 'SELECT * FROM project_roadmap WHERE 1=1';
    const params = [];
    if (app) { sql += ' AND app_slug = ?'; params.push(app); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += " ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'planned' THEN 1 WHEN 'idea' THEN 2 WHEN 'shipped' THEN 3 WHEN 'cancelled' THEN 4 END, target_date ASC NULLS LAST";
    res.json(db.prepare(sql).all(...params));
  }));

  app.post('/api/projects/roadmap', asyncRoute((req, res) => {
    const { app_slug, title, description, type, status, target_date, impact, effort } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required' });
    const result = db.prepare('INSERT INTO project_roadmap (app_slug, title, description, type, status, target_date, impact, effort) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      app_slug || null, title, description || null, type || 'feature', status || 'planned', target_date || null, impact || 'medium', effort || 'medium'
    );
    res.json({ ok: true, id: result.lastInsertRowid });
  }));

  app.put('/api/projects/roadmap/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid roadmap ID' });
    const { title, description, type, status, target_date, impact, effort, app_slug } = req.body;
    const fields = [];
    const values = [];
    if (title !== undefined) { fields.push('title = ?'); values.push(title); }
    if (description !== undefined) { fields.push('description = ?'); values.push(description); }
    if (type !== undefined) { fields.push('type = ?'); values.push(type); }
    if (status !== undefined) { fields.push('status = ?'); values.push(status); }
    if (target_date !== undefined) { fields.push('target_date = ?'); values.push(target_date); }
    if (impact !== undefined) { fields.push('impact = ?'); values.push(impact); }
    if (effort !== undefined) { fields.push('effort = ?'); values.push(effort); }
    if (app_slug !== undefined) { fields.push('app_slug = ?'); values.push(app_slug); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
    fields.push("updated_at = datetime('now')");
    values.push(id);
    const result = db.prepare(`UPDATE project_roadmap SET ${fields.join(', ')} WHERE id = ?`).run(...values);
    if (result.changes === 0) return res.status(404).json({ error: 'Roadmap item not found' });
    res.json({ ok: true });
  }));

  app.post('/api/projects/roadmap/:id/ship', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid roadmap ID' });
    const result = db.prepare("UPDATE project_roadmap SET status = 'shipped', shipped_date = datetime('now'), updated_at = datetime('now') WHERE id = ?").run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Roadmap item not found' });
    res.json({ ok: true });
  }));

  // DELETE /api/projects/roadmap/:id — Delete roadmap item
  app.delete('/api/projects/roadmap/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid roadmap ID' });
    const result = db.prepare('DELETE FROM project_roadmap WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Roadmap item not found' });
    res.json({ ok: true });
  }));

  // --- AI Insights ---
  app.get('/api/projects/insights/:slug', asyncRoute(async (req, res) => {
    const slug = req.params.slug;
    const type = req.query.type || 'next_actions';
    const force = req.query.force === 'true';

    if (!force) {
      const cached = db.prepare('SELECT * FROM project_ai_insights WHERE app_slug = ? AND insight_type = ?').get(slug, type);
      if (cached) {
        const age = Date.now() - new Date(cached.generated_at).getTime();
        const maxAge = type === 'weekly_summary' ? 7 * MS_PER_DAY : 72 * MS_PER_HOUR;
        if (age < maxAge) return res.json({ content: cached.content, generated_at: cached.generated_at, cached: true });
      }
    }

    const appDef = config.apps.find(a => slugify(a.name) === slug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });

    const meta = db.prepare('SELECT * FROM project_meta WHERE app_slug = ?').get(slug) || {};
    const openTasks = db.prepare("SELECT title FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled') LIMIT 5").all(slug);
    const roadmapItems = db.prepare("SELECT title, status FROM project_roadmap WHERE app_slug = ? AND status IN ('planned','in_progress') LIMIT 5").all(slug);
    const seo = qLatestSEO.get(slug);
    const mrrRow = qLatestMetric.get(slug, 'mrr');

    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return res.status(503).json({ error: 'No Anthropic API key available' });

    const prompt = `You are an indie SaaS advisor for a solo founder. Given:
- App: ${appDef.name} (${appDef.type}) — ${appDef.description}
- Lifecycle: ${meta.lifecycle || 'launched'}
- MRR: €${((mrrRow?.value || 0) / 100).toFixed(0)} ${meta.revenue_goal_mrr ? `(goal: €${(meta.revenue_goal_mrr / 100).toFixed(0)})` : '(no goal set)'}
- SEO score: ${seo?.score ?? 'unknown'}/100 (${seo?.grade || 'N/A'})
- Open tasks: ${openTasks.length > 0 ? openTasks.map(t => t.title).join(', ') : 'none'}
- Roadmap: ${roadmapItems.length > 0 ? roadmapItems.map(r => `${r.title} (${r.status})`).join(', ') : 'none'}
- Tech: ${appDef.tech || 'unknown'}
- Domain: ${appDef.domain || 'none'}

${type === 'next_actions' ? 'Output 3-5 specific, immediately actionable next steps. Be direct. No fluff. Each step should be doable in under a day. Format as a markdown bullet list.' : 'Write a concise weekly status summary in 3 short paragraphs: 1) current state, 2) progress this week, 3) recommended focus for next week.'}`;

    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { messages: [{ role: 'user', content: prompt }] }));

    db.prepare('INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES (?, ?, ?, ?, datetime(\'now\')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at').run(slug, type, ai.text || 'No insight generated', ai.outputTokens);

    res.json({ content: ai.text || 'No insight generated', generated_at: new Date().toISOString(), cached: false });
  }));

  app.get('/api/projects/insights/portfolio/summary', asyncRoute(async (req, res) => {
    const force = req.query.force === 'true';
    if (!force) {
      const cached = db.prepare("SELECT * FROM project_ai_insights WHERE app_slug = '_portfolio' AND insight_type = 'summary'").get();
      if (cached) {
        const age = Date.now() - new Date(cached.generated_at).getTime();
        if (age < 24 * MS_PER_HOUR) return res.json({ content: cached.content, generated_at: cached.generated_at, cached: true });
      }
    }

    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return res.status(503).json({ error: 'No Anthropic API key available' });

    const saasApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const appSummaries = saasApps.map(a => {
      const slug = slugify(a.name);
      const meta = db.prepare('SELECT lifecycle, priority FROM project_meta WHERE app_slug = ?').get(slug) || {};
      const openTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.count || 0;
      const mrr = qLatestMetric.get(slug, 'mrr')?.value || 0;
      return `- ${a.name}: lifecycle=${meta.lifecycle || 'launched'}, MRR=€${(mrr / 100).toFixed(0)}, ${openTasks} open tasks`;
    }).join('\n');

    const today = todayString();
    const totalOverdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today)?.count || 0;
    const weekDone = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE completed_at >= datetime('now', '-7 days')").get()?.count || 0;

    const prompt = `You are an indie SaaS portfolio advisor. Here is the current state of a solo founder's app portfolio:

${appSummaries}

Portfolio stats: ${totalOverdue} overdue tasks, ${weekDone} tasks completed this week.

Write a concise 3-paragraph portfolio briefing: 1) overall health assessment, 2) what to focus on this week, 3) one strategic recommendation. Be direct, specific, actionable.`;

    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { messages: [{ role: 'user', content: prompt }] }));

    db.prepare("INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES ('_portfolio', 'summary', ?, ?, datetime('now')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at").run(ai.text || 'No summary generated', ai.outputTokens);

    res.json({ content: ai.text || 'No summary generated', generated_at: new Date().toISOString(), cached: false });
  }));

  // --- Projects Cron Jobs ---

  // Every 15 min: check for due reminders, send Telegram
  cron.schedule('*/15 * * * *', async () => {
    try {
      const now = new Date().toISOString();
      const dueTasks = db.prepare("SELECT * FROM project_tasks WHERE reminder_at <= ? AND reminder_sent = 0 AND status NOT IN ('done','cancelled')").all(now);
      if (dueTasks.length === 0) return;

      for (const task of dueTasks) {
        const appName = config.apps.find(a => slugify(a.name) === task.app_slug)?.name || 'Portfolio';
        await sendTelegram(`📋 Reminder — ${appName}\nTask: ${task.title}${task.due_date ? `\nDue: ${task.due_date}` : ''}`);
        db.prepare('UPDATE project_tasks SET reminder_sent = 1 WHERE id = ?').run(task.id);
      }
      console.log(`[PROJECTS] Sent ${dueTasks.length} reminder(s)`);
    } catch (err) { cronFail('Task reminders', err); }
  });

  // Daily 8 AM: overdue task alert
  cron.schedule('0 8 * * *', async () => {
    try {
      const today = todayString();
      const overdue = db.prepare("SELECT * FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled') ORDER BY due_date ASC LIMIT 10").all(today);
      if (overdue.length === 0) return;

      const lines = overdue.map(t => {
        const appName = config.apps.find(a => slugify(a.name) === t.app_slug)?.name || 'Portfolio';
        const daysLate = Math.ceil((new Date(today) - new Date(t.due_date)) / MS_PER_DAY);
        return `• ${appName}: ${t.title} (${daysLate}d late)`;
      });
      await sendTelegram(`⚠ Overdue Tasks — ${overdue.length} task${overdue.length > 1 ? 's' : ''} past due:\n${lines.join('\n')}`);
      console.log(`[PROJECTS] Overdue alert sent (${overdue.length} tasks)`);
    } catch (err) { cronFail('Overdue tasks', err); }
  });

  // Weekly Monday 6 AM: snapshot per-app KPIs
  cron.schedule('0 6 * * 1', async () => {
    try {
      const snapDate = todayString();
      for (const appDef of config.apps) {
        const slug = slugify(appDef.name);
        const mrr = qLatestMetric.get(slug, 'mrr')?.value || null;
        const openTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.count || 0;
        const doneTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status = 'done'").get(slug)?.count || 0;
        const shipped = db.prepare("SELECT COUNT(*) as count FROM project_roadmap WHERE app_slug = ? AND status = 'shipped'").get(slug)?.count || 0;
        const seo = qLatestSEO.get(slug)?.score || null;
        let secScore = null;
        try {
          const findings = db.prepare("SELECT severity FROM security_findings WHERE app_slug = ? AND scan_id = (SELECT id FROM security_scans ORDER BY timestamp DESC LIMIT 1) AND status != 'dismissed'").all(slug);
          const crit = findings.filter(f => f.severity === 'critical').length;
          const high = findings.filter(f => f.severity === 'high').length;
          secScore = Math.max(0, 100 - crit * 25 - high * 15 - findings.length * 3);
        } catch { /* no security data */ }

        // Plausible traffic (30d visitors)
        let traffic30d = null;
        const plausibleKey = getPlausibleApiKey();
        if (appDef.domain && plausibleKey) {
          try {
            const tRes = await fetch(
              `${getPlausibleUrl()}/api/v1/stats/aggregate?site_id=${appDef.domain}&period=30d&metrics=visitors`,
              { headers: { Authorization: `Bearer ${plausibleKey}` }, signal: AbortSignal.timeout(TIMEOUT_QUICK) }
            );
            if (tRes.ok) {
              const tData = await tRes.json();
              traffic30d = tData?.results?.visitors?.value || 0;
            }
          } catch { /* Plausible may not track all sites */ }
        }

        // Container health
        let healthStatus = 'unknown';
        if (appDef.containers?.length > 0) {
          try {
            const containers = await docker.listContainers({ all: true });
            const appContainers = containers.filter(c => appDef.containers.includes(containerName(c)));
            if (appContainers.length === 0) healthStatus = 'unknown';
            else if (appContainers.every(c => c.State === 'running')) healthStatus = 'healthy';
            else healthStatus = 'degraded';
          } catch { healthStatus = 'unknown'; }
        }

        db.prepare(`INSERT INTO project_snapshots (app_slug, snapshot_date, mrr_cents, traffic_30d, task_count_open, task_count_done, roadmap_shipped, security_score, seo_score, health_status)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(app_slug, snapshot_date) DO UPDATE SET
          mrr_cents = excluded.mrr_cents, traffic_30d = excluded.traffic_30d, task_count_open = excluded.task_count_open, task_count_done = excluded.task_count_done,
          roadmap_shipped = excluded.roadmap_shipped, security_score = excluded.security_score, seo_score = excluded.seo_score, health_status = excluded.health_status`).run(
          slug, snapDate, mrr, traffic30d, openTasks, doneTasks, shipped, secScore, seo, healthStatus
        );
      }
      console.log(`[PROJECTS] Weekly snapshot completed for ${config.apps.length} apps`);
    } catch (err) { cronFail('Project snapshots', err); }
  });

  // Weekly Sunday 4 AM: generate AI weekly summaries
  cron.schedule('0 4 * * 0', async () => {
    try {
      const anthropicKey = getAnthropicKey();
      if (!anthropicKey) return;
      const saasApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
      for (const appDef of saasApps) {
        const slug = slugify(appDef.name);
        try {
          const meta = db.prepare('SELECT * FROM project_meta WHERE app_slug = ?').get(slug) || {};
          const openTasks = db.prepare("SELECT title FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled') LIMIT 5").all(slug);
          const mrrRow = qLatestMetric.get(slug, 'mrr');
          const prompt = `Write a concise weekly status for ${appDef.name} (${appDef.type}): lifecycle=${meta.lifecycle}, MRR=€${((mrrRow?.value || 0) / 100).toFixed(0)}, ${openTasks.length} open tasks${openTasks.length > 0 ? ': ' + openTasks.map(t => t.title).join(', ') : ''}. 3 short paragraphs: state, progress, next focus.`;
          const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { maxTokens: 400, messages: [{ role: 'user', content: prompt }] }));
          if (ai.text) {
            db.prepare("INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES (?, 'weekly_summary', ?, ?, datetime('now')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at").run(slug, ai.text, ai.outputTokens);
          }
        } catch (appErr) { console.error(`[PROJECTS] AI summary error for ${slug}:`, appErr.message); }
      }
      console.log(`[PROJECTS] Weekly AI summaries generated for ${saasApps.length} apps`);
    } catch (err) { cronFail('AI project summary', err); }
  });

}
