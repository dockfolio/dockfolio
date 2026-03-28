import { asyncRoute, slugify } from '../utils.js';

export default function registerAlertRoutes({ app, db, config, cron, qLatestMetric, sendTelegram, guardedCron, cronFail, isInMaintenanceWindow, TIMEOUT_QUICK }) {

  // --- Webhook / Alert Rules ---

  app.get('/api/alerts/rules', asyncRoute((_req, res) => {
    const rules = db.prepare('SELECT * FROM alert_rules ORDER BY created_at DESC').all();
    res.json({ rules });
  }));

  app.post('/api/alerts/rules', asyncRoute((req, res) => {
    const { appSlug, metric, operator, threshold, windowMinutes, action } = req.body;
    if (!metric || !operator || !threshold) return res.status(400).json({ error: 'metric, operator, and threshold are required' });

    const validOperators = ['>', '<', '>=', '<=', '==', '!=', 'contains'];
    if (!validOperators.includes(operator)) return res.status(400).json({ error: 'Invalid operator' });

    const validActions = ['telegram', 'webhook', 'email'];
    const act = action || 'telegram';
    if (!validActions.includes(act.split(':')[0])) return res.status(400).json({ error: 'Invalid action. Use: telegram, webhook:URL, or email:ADDRESS' });

    const result = db.prepare(
      'INSERT INTO alert_rules (app_slug, metric, operator, threshold, window_minutes, action) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(appSlug || null, metric, operator, String(threshold), windowMinutes || 5, act);

    res.json({ id: result.lastInsertRowid, message: 'Rule created' });
  }));

  app.put('/api/alerts/rules/:id', asyncRoute((req, res) => {
    const { id } = req.params;
    const { enabled, metric, operator, threshold, windowMinutes, action } = req.body;

    const rule = db.prepare('SELECT * FROM alert_rules WHERE id = ?').get(id);
    if (!rule) return res.status(404).json({ error: 'Rule not found' });

    db.prepare(
      'UPDATE alert_rules SET metric = ?, operator = ?, threshold = ?, window_minutes = ?, action = ?, enabled = ? WHERE id = ?'
    ).run(
      metric || rule.metric,
      operator || rule.operator,
      threshold != null ? String(threshold) : rule.threshold,
      windowMinutes || rule.window_minutes,
      action || rule.action,
      enabled != null ? (enabled ? 1 : 0) : rule.enabled,
      id
    );

    res.json({ message: 'Rule updated' });
  }));

  app.delete('/api/alerts/rules/:id', asyncRoute((req, res) => {
    const result = db.prepare('DELETE FROM alert_rules WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Rule not found' });
    res.json({ message: 'Rule deleted' });
  }));

  // --- Scheduled Maintenance Windows ---

  app.get('/api/maintenance', asyncRoute((_req, res) => {
    const rows = db.prepare('SELECT * FROM maintenance_windows ORDER BY day_of_week, start_hour, start_minute').all();
    const result = rows.map(w => {
      const appDef = config.apps.find(a => slugify(a.name) === w.app_slug);
      return { ...w, app_name: appDef ? appDef.name : w.app_slug };
    });
    res.json({ windows: result });
  }));

  app.post('/api/maintenance', asyncRoute((req, res) => {
    const { app_slug, day_of_week, start_hour, start_minute, duration_minutes, suppress_alerts, auto_restart } = req.body;

    if (!app_slug) return res.status(400).json({ error: 'app_slug is required' });
    const day = parseInt(day_of_week, 10);
    const hour = parseInt(start_hour, 10);
    const minute = parseInt(start_minute || 0, 10);
    const duration = parseInt(duration_minutes || 120, 10);

    if (isNaN(day) || day < 0 || day > 6) return res.status(400).json({ error: 'day_of_week must be 0-6 (0=Sunday)' });
    if (isNaN(hour) || hour < 0 || hour > 23) return res.status(400).json({ error: 'start_hour must be 0-23' });
    if (isNaN(minute) || minute < 0 || minute > 59) return res.status(400).json({ error: 'start_minute must be 0-59' });
    if (isNaN(duration) || duration <= 0) return res.status(400).json({ error: 'duration_minutes must be > 0' });

    const result = db.prepare(
      'INSERT INTO maintenance_windows (app_slug, day_of_week, start_hour, start_minute, duration_minutes, suppress_alerts, auto_restart) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(app_slug, day, hour, minute, duration, suppress_alerts ? 1 : 0, auto_restart ? 1 : 0);

    res.json({ id: result.lastInsertRowid, message: 'Maintenance window created' });
  }));

  app.delete('/api/maintenance/:id', asyncRoute((req, res) => {
    const result = db.prepare('DELETE FROM maintenance_windows WHERE id = ?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Maintenance window not found' });
    res.json({ message: 'Maintenance window deleted' });
  }));

  // Evaluate alert rules against current metrics
  async function evaluateAlertRules() {
    const rules = db.prepare('SELECT * FROM alert_rules WHERE enabled = 1').all();
    if (rules.length === 0) return;

    // Gather current values
    const currentValues = {};

    // System metrics
    const sysRow = db.prepare("SELECT * FROM system_snapshots ORDER BY ts DESC LIMIT 1").get();
    if (sysRow) {
      currentValues['cpu'] = sysRow.cpu_percent;
      currentValues['memory_percent'] = sysRow.mem_total_bytes > 0 ? (sysRow.mem_used_bytes / sysRow.mem_total_bytes * 100) : 0;
      currentValues['disk_percent'] = sysRow.disk_total_bytes > 0 ? (sysRow.disk_used_bytes / sysRow.disk_total_bytes * 100) : 0;
      currentValues['load'] = sysRow.load_1m;
    }

    // Per-app MRR
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const row = qLatestMetric.get(slug, 'mrr');
      if (row) currentValues[`${slug}.mrr`] = row.value / 100;
      const pv = qLatestMetric.get(slug, 'pageviews_30d');
      if (pv) currentValues[`${slug}.traffic`] = pv.value;
    }

    for (const rule of rules) {
      // Skip if app is in a scheduled maintenance window
      if (rule.app_slug) {
        const mw = isInMaintenanceWindow(rule.app_slug);
        if (mw.inMaintenance && mw.window.suppress_alerts) {
          console.log(`[ALERTS] Suppressed rule ${rule.id} for ${rule.app_slug} — scheduled maintenance window`);
          continue;
        }
      }

      // Cooldown check
      if (rule.last_fired_at) {
        const lastFired = new Date(rule.last_fired_at + 'Z').getTime();
        if (Date.now() - lastFired < rule.window_minutes * 60 * 1000) continue;
      }

      const metricKey = rule.app_slug ? `${rule.app_slug}.${rule.metric}` : rule.metric;
      const value = currentValues[metricKey];
      if (value == null) continue;

      const threshold = parseFloat(rule.threshold);
      let triggered = false;

      switch (rule.operator) {
        case '>': triggered = value > threshold; break;
        case '<': triggered = value < threshold; break;
        case '>=': triggered = value >= threshold; break;
        case '<=': triggered = value <= threshold; break;
        case '==': triggered = value === threshold; break;
        case '!=': triggered = value !== threshold; break;
        case 'contains': triggered = String(value).includes(rule.threshold); break;
      }

      if (triggered) {
        db.prepare('UPDATE alert_rules SET last_fired_at = datetime(\'now\') WHERE id = ?').run(rule.id);

        const msg = `Alert: ${rule.metric}${rule.app_slug ? ` (${rule.app_slug})` : ''} is ${value} (${rule.operator} ${rule.threshold})`;

        const actionType = rule.action.split(':')[0];
        const actionTarget = rule.action.slice(actionType.length + 1);

        if (actionType === 'telegram') {
          sendTelegram(`🔔 <b>Alert Rule Triggered</b>\n${msg}`);
        } else if (actionType === 'webhook' && actionTarget) {
          fetch(actionTarget, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert: msg, metric: rule.metric, value, threshold, app: rule.app_slug, timestamp: new Date().toISOString() }),
            signal: AbortSignal.timeout(TIMEOUT_QUICK),
          }).catch(() => {});
        }
      }
    }
  }

  // Evaluate alert rules every 5 minutes
  cron.schedule('*/5 * * * *', guardedCron('alert-rules', async () => {
    await evaluateAlertRules().catch(err => cronFail('Alert rules evaluation', err));
  }));
}
