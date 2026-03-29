import { asyncRoute, slugify, htmlEscape } from '../utils.js';

export default function registerStatusRoutes({ app, db, docker, config, rlPublicRead, TIMEOUT_QUICK, MS_PER_DAY }) {

  // GET /api/status — public status summary
  app.get('/api/status', rlPublicRead, asyncRoute(async (_req, res) => {
    const results = [];
    const dayAgo = new Date(Date.now() - MS_PER_DAY).toISOString();
    for (const a of config.apps) {
      let status = 'unknown';
      let response_ms = null;
      try {
        if (a.health && a.domain) {
          const healthUrl = `https://${a.domain}${a.health}`;
          const start = Date.now();
          const r = await fetch(healthUrl, { signal: AbortSignal.timeout(TIMEOUT_QUICK) });
          response_ms = Date.now() - start;
          status = r.ok ? 'up' : 'degraded';
        } else {
          status = 'up';
        }
      } catch { status = 'down'; }
      const checks = db.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as up_count FROM uptime_history WHERE app_slug = ? AND checked_at > ?').get('up', slugify(a.name), dayAgo);
      const uptime_24h = checks.total > 0 ? Math.round((checks.up_count / checks.total) * 10000) / 100 : null;
      results.push({ name: a.name, domain: a.domain, status, response_ms, uptime_24h });
    }
    res.json({ generated_at: new Date().toISOString(), apps: results });
  }));

  // GET /api/status-page — detailed status page data
  app.get('/api/status-page', asyncRoute(async (_req, res) => {
    // Batch DB queries to avoid N+1 per app
    const allUptime = db.prepare("SELECT app_slug, status FROM uptime_history WHERE checked_at > datetime('now', '-30 days')").all();
    const uptimeByApp = {};
    for (const row of allUptime) {
      if (!uptimeByApp[row.app_slug]) uptimeByApp[row.app_slug] = [];
      uptimeByApp[row.app_slug].push(row);
    }

    const allIncidents = db.prepare("SELECT app_slug, condition, action_taken, result, timestamp FROM healing_log WHERE timestamp > datetime('now', '-7 days') ORDER BY timestamp DESC").all();
    const incidentsByApp = {};
    for (const row of allIncidents) {
      if (!incidentsByApp[row.app_slug]) incidentsByApp[row.app_slug] = [];
      incidentsByApp[row.app_slug].push(row);
    }

    // Collect all container names and inspect in parallel
    const { containerName } = await import('../utils.js');
    const appDefs = config.apps.filter(a => a.domain);
    const containerNames = new Set();
    for (const appDef of appDefs) {
      for (const cName of (appDef.containers || [])) containerNames.add(cName);
    }
    const inspectResults = {};
    const inspectPromises = [...containerNames].map(async (cName) => {
      try {
        const info = await docker.getContainer(cName).inspect();
        inspectResults[cName] = info;
      } catch {
        inspectResults[cName] = null;
      }
    });
    await Promise.all(inspectPromises);

    const apps = [];
    for (const appDef of appDefs) {
      const slug = slugify(appDef.name);
      const containers = appDef.containers || [];
      let status = 'operational';
      let statusText = 'Operational';

      for (const cName of containers) {
        const info = inspectResults[cName];
        if (!info) {
          status = 'unknown';
          statusText = 'Unknown';
          continue;
        }
        const state = info.State;
        if (!state.Running) {
          status = 'down';
          statusText = 'Down';
          break;
        }
        if (state.Health && state.Health.Status !== 'healthy') {
          status = 'degraded';
          statusText = 'Degraded';
        }
      }

      if (containers.length === 0 && appDef.domain) {
        status = 'operational';
        statusText = 'Static Site';
      }

      const uptimeRows = uptimeByApp[slug] || [];
      const totalChecks = uptimeRows.length;
      const upChecks = uptimeRows.filter(r => r.status === 'up' || r.status === 'healthy').length;
      const uptimePct = totalChecks > 0 ? +(upChecks / totalChecks * 100).toFixed(2) : null;

      const incidents = (incidentsByApp[slug] || []).slice(0, 5);

      apps.push({
        name: appDef.name,
        slug,
        domain: appDef.domain,
        status,
        statusText,
        uptimePct,
        incidents: incidents.map(i => ({
          condition: i.condition,
          action: i.action_taken,
          result: i.result,
          time: i.timestamp,
        })),
      });
    }

    res.json({
      apps,
      generatedAt: new Date().toISOString(),
    });
  }));

  // GET /status — public status page HTML
  app.get('/status', (_req, res) => {
    res.send(generateStatusPageHTML());
  });

  function generateStatusPageHTML() {
    const allUptime = db.prepare("SELECT app_slug, status FROM uptime_history WHERE checked_at > datetime('now', '-30 days')").all();
    const uptimeByApp = {};
    for (const row of allUptime) {
      if (!uptimeByApp[row.app_slug]) uptimeByApp[row.app_slug] = [];
      uptimeByApp[row.app_slug].push(row);
    }

    const allIncidents = db.prepare("SELECT app_slug, condition, timestamp FROM healing_log WHERE timestamp > datetime('now', '-7 days') ORDER BY timestamp DESC").all();
    const incidentsByApp = {};
    for (const row of allIncidents) {
      if (!incidentsByApp[row.app_slug]) incidentsByApp[row.app_slug] = [];
      incidentsByApp[row.app_slug].push(row);
    }

    const apps = [];
    for (const appDef of config.apps) {
      if (!appDef.domain) continue;
      const slug = slugify(appDef.name);

      const uptimeRows = uptimeByApp[slug] || [];
      const totalChecks = uptimeRows.length;
      const upChecks = uptimeRows.filter(r => r.status === 'up' || r.status === 'healthy').length;
      const uptimePct = totalChecks > 0 ? (upChecks / totalChecks * 100).toFixed(2) : null;

      const recentIncidents = (incidentsByApp[slug] || []).slice(0, 3);

      apps.push({ name: appDef.name, domain: appDef.domain, uptimePct, incidents: recentIncidents });
    }

    const allOperational = apps.every(a => !a.incidents.length);
    const overallStatus = allOperational ? 'All Systems Operational' : 'Some Systems Have Recent Incidents';
    const overallColor = allOperational ? '#22c55e' : '#eab308';

    let appRows = '';
    for (const app of apps) {
      const uptime = app.uptimePct ? `${app.uptimePct}%` : 'N/A';
      const color = !app.uptimePct ? '#6b7280' : app.uptimePct >= 99.9 ? '#22c55e' : app.uptimePct >= 99 ? '#eab308' : '#ef4444';
      const statusDot = app.incidents.length > 0 ? '#eab308' : '#22c55e';
      appRows += `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #1f2937">
          <div>
            <div style="font-weight:600;font-size:14px">${htmlEscape(app.name)}</div>
            <div style="font-size:12px;color:#9ca3af">${htmlEscape(app.domain)}</div>
          </div>
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:13px;color:${color};font-weight:500">${uptime}</span>
            <span style="width:10px;height:10px;border-radius:50%;background:${statusDot};display:inline-block"></span>
          </div>
        </div>`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>System Status — Dockfolio</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
    .container{max-width:640px;margin:0 auto;padding:40px 20px}
    .header{text-align:center;margin-bottom:32px}
    .header h1{font-size:24px;font-weight:700;margin-bottom:8px}
    .status-badge{display:inline-block;padding:6px 16px;border-radius:20px;font-size:14px;font-weight:600}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px 20px;margin-bottom:16px}
    .footer{text-align:center;margin-top:32px;font-size:12px;color:#64748b}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>System Status</h1>
      <div class="status-badge" style="background:${overallColor}20;color:${overallColor}">${overallStatus}</div>
    </div>
    <div class="card">
      <h2 style="font-size:14px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">Services</h2>
      ${appRows}
    </div>
    <div class="footer">
      <p>Last updated: ${new Date().toISOString().replace('T', ' ').split('.')[0]} UTC</p>
      <p style="margin-top:4px">Powered by <a href="https://github.com/Crelvo/appManager" style="color:#60a5fa;text-decoration:none">Dockfolio</a></p>
    </div>
  </div>
</body>
</html>`;
  }
}
