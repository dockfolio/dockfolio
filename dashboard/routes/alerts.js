import { asyncRoute, slugify, assertSafeUrl } from '../utils.js';

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
          try { assertSafeUrl(actionTarget); } catch { continue; }
          fetch(actionTarget, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert: msg, metric: rule.metric, value, threshold, app: rule.app_slug, timestamp: new Date().toISOString() }),
            signal: AbortSignal.timeout(TIMEOUT_QUICK),
          }).catch(err => { console.error(`[ALERTS] Webhook delivery failed for ${actionTarget}:`, err.message); });
        }
      }
    }
  }

  // Evaluate alert rules every 5 minutes
  cron.schedule('*/5 * * * *', guardedCron('alert-rules', async () => {
    await evaluateAlertRules().catch(err => cronFail('Alert rules evaluation', err));
  }));

  // --- Predictive Resource Alerts ---

  // Simple linear regression: returns { slope, intercept } from array of {x, y}
  function linearRegression(points) {
    const n = points.length;
    if (n < 2) return null;
    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    for (const { x, y } of points) {
      sumX += x; sumY += y; sumXY += x * y; sumXX += x * x;
    }
    const denom = n * sumXX - sumX * sumX;
    if (denom === 0) return null;
    const slope = (n * sumXY - sumX * sumY) / denom;
    const intercept = (sumY - slope * sumX) / n;
    return { slope, intercept };
  }

  function checkPredictiveAlerts() {
    const rows = db.prepare(
      "SELECT ts, disk_used_bytes, disk_total_bytes, mem_used_bytes, mem_total_bytes, cpu_percent FROM system_snapshots WHERE ts > datetime('now', '-7 days') ORDER BY ts ASC"
    ).all();
    if (rows.length < 20) return; // need enough data points

    const MS_PER_HOUR = 3600000;
    const t0 = new Date(rows[0].ts + 'Z').getTime();
    const now = Date.now();
    const alerts = [];

    // Disk prediction
    if (rows[0].disk_total_bytes > 0) {
      const points = rows.filter(r => r.disk_total_bytes > 0).map(r => ({
        x: (new Date(r.ts + 'Z').getTime() - t0) / MS_PER_HOUR,
        y: r.disk_used_bytes / r.disk_total_bytes * 100,
      }));
      const reg = linearRegression(points);
      if (reg && reg.slope > 0) {
        const currentPct = points[points.length - 1].y;
        const hoursTo90 = (90 - currentPct) / reg.slope;
        if (hoursTo90 > 0 && hoursTo90 <= 72) {
          const days = Math.round(hoursTo90 / 24 * 10) / 10;
          const rate = Math.round(reg.slope * 24 * 100) / 100;
          alerts.push(`Disk at ${currentPct.toFixed(1)}%, growing ${rate}%/day — projected to hit 90% in ${days} days`);
        }
      }
    }

    // Memory prediction
    if (rows[0].mem_total_bytes > 0) {
      const points = rows.filter(r => r.mem_total_bytes > 0).map(r => ({
        x: (new Date(r.ts + 'Z').getTime() - t0) / MS_PER_HOUR,
        y: r.mem_used_bytes / r.mem_total_bytes * 100,
      }));
      const reg = linearRegression(points);
      if (reg && reg.slope > 0) {
        const currentPct = points[points.length - 1].y;
        const hoursTo90 = (90 - currentPct) / reg.slope;
        if (hoursTo90 > 0 && hoursTo90 <= 48) {
          const days = Math.round(hoursTo90 / 24 * 10) / 10;
          const rate = Math.round(reg.slope * 24 * 100) / 100;
          alerts.push(`Memory at ${currentPct.toFixed(1)}%, growing ${rate}%/day — projected to hit 90% in ${days} days`);
        }
      }
    }

    // CPU sustained high prediction
    const recentCpu = rows.slice(-12); // last ~3 hours (15-min intervals)
    const avgCpu = recentCpu.reduce((s, r) => s + (r.cpu_percent || 0), 0) / recentCpu.length;
    if (avgCpu > 80) {
      alerts.push(`CPU sustained high: ${avgCpu.toFixed(0)}% average over last ${recentCpu.length} snapshots`);
    }

    if (alerts.length === 0) return;

    // Cooldown: only send predictive alerts once per 6 hours
    const lastPredictive = db.prepare("SELECT value FROM settings WHERE key = 'last_predictive_alert'").get();
    if (lastPredictive) {
      const elapsed = now - new Date(lastPredictive.value + 'Z').getTime();
      if (elapsed < 6 * MS_PER_HOUR) return;
    }

    db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_predictive_alert', datetime('now'))").run();
    sendTelegram(`📈 <b>Predictive Resource Alert</b>\n${alerts.join('\n')}`);
  }

  // GET /api/alerts/predictions — current resource projections
  app.get('/api/alerts/predictions', asyncRoute((_req, res) => {
    const rows = db.prepare(
      "SELECT ts, disk_used_bytes, disk_total_bytes, mem_used_bytes, mem_total_bytes, cpu_percent FROM system_snapshots WHERE ts > datetime('now', '-7 days') ORDER BY ts ASC"
    ).all();
    if (rows.length < 20) return res.json({ predictions: [], message: 'Not enough data (need 7 days of snapshots)' });

    const t0 = new Date(rows[0].ts + 'Z').getTime();
    const predictions = [];

    for (const [label, extract, threshold] of [
      ['disk', r => r.disk_total_bytes > 0 ? r.disk_used_bytes / r.disk_total_bytes * 100 : null, 90],
      ['memory', r => r.mem_total_bytes > 0 ? r.mem_used_bytes / r.mem_total_bytes * 100 : null, 90],
    ]) {
      const points = rows.map(r => { const y = extract(r); return y !== null ? { x: (new Date(r.ts + 'Z').getTime() - t0) / 3600000, y } : null; }).filter(Boolean);
      const reg = linearRegression(points);
      if (!reg) continue;
      const current = points[points.length - 1].y;
      const hoursToThreshold = reg.slope > 0 ? (threshold - current) / reg.slope : null;
      predictions.push({
        metric: label,
        current: Math.round(current * 100) / 100,
        slope_per_day: Math.round(reg.slope * 24 * 100) / 100,
        threshold,
        hours_to_threshold: hoursToThreshold ? Math.round(hoursToThreshold) : null,
        days_to_threshold: hoursToThreshold ? Math.round(hoursToThreshold / 24 * 10) / 10 : null,
        trend: reg.slope > 0.01 ? 'rising' : reg.slope < -0.01 ? 'falling' : 'stable',
      });
    }

    res.json({ predictions, data_points: rows.length, timestamp: new Date().toISOString() });
  }));

  // Run predictive checks every 6 hours
  cron.schedule('0 */6 * * *', guardedCron('predictive-alerts', () => {
    try { checkPredictiveAlerts(); } catch (err) { cronFail('Predictive resource alerts', err); }
  }));
}
