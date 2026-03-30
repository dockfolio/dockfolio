import { asyncRoute, slugify, htmlEscape } from '../utils.js';

export default function registerStatusRoutes({ app, db, docker, config, rlPublicRead, calculateAppReportCard, TIMEOUT_QUICK, MS_PER_DAY }) {

  // GET /api/status — public status summary
  app.get('/api/status', rlPublicRead, asyncRoute(async (_req, res) => {
    const dayAgo = new Date(Date.now() - MS_PER_DAY).toISOString();
    const uptimeStmt = db.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status = ? THEN 1 ELSE 0 END) as up_count FROM uptime_history WHERE app_slug = ? AND checked_at > ?');

    const results = await Promise.all(config.apps.map(async (a) => {
      let status = 'unknown';
      let response_ms = null;
      try {
        if (a.health && a.domain && !/^\d+\.\d+\.\d+\.\d+$/.test(a.domain)) {
          const healthUrl = `https://${a.domain}${a.health}`;
          const start = Date.now();
          const r = await fetch(healthUrl, { signal: AbortSignal.timeout(TIMEOUT_QUICK) });
          response_ms = Date.now() - start;
          status = r.ok ? 'up' : 'degraded';
        } else {
          status = 'up';
        }
      } catch { status = 'down'; }
      const checks = uptimeStmt.get('up', slugify(a.name), dayAgo);
      const uptime_24h = checks.total > 0 ? Math.round((checks.up_count / checks.total) * 10000) / 100 : null;
      return { name: a.name, domain: a.domain, status, response_ms, uptime_24h };
    }));

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

  // GET /api/status/heatmap — 90-day uptime heatmap data per app
  app.get('/api/status/heatmap', rlPublicRead, asyncRoute(async (req, res) => {
    const days = Math.min(parseInt(req.query.days) || 90, 365);
    const slug = req.query.app;

    const rows = db.prepare(`
      SELECT app_slug, date(checked_at) as day, COUNT(*) as total,
        SUM(CASE WHEN status IN ('up','healthy') THEN 1 ELSE 0 END) as up_count
      FROM uptime_history
      WHERE checked_at > datetime('now', '-' || ? || ' days')
      ${slug ? 'AND app_slug = ?' : ''}
      GROUP BY app_slug, day
      ORDER BY app_slug, day
    `).all(...(slug ? [days, slug] : [days]));

    const heatmap = {};
    for (const row of rows) {
      if (!heatmap[row.app_slug]) heatmap[row.app_slug] = [];
      heatmap[row.app_slug].push({
        date: row.day,
        uptime: +(row.up_count / row.total * 100).toFixed(2),
        checks: row.total,
      });
    }

    res.json({ days, generated_at: new Date().toISOString(), apps: heatmap });
  }));

  // GET /status — public status page HTML
  app.get('/status', (_req, res) => {
    res.send(generateStatusPageHTML());
  });

  function generateSystemHealthSection(db) {
    try {
      const row = db.prepare("SELECT * FROM system_snapshots ORDER BY ts DESC LIMIT 1").get();
      if (!row) return '';
      const diskPct = row.disk_total_bytes > 0 ? (row.disk_used_bytes / row.disk_total_bytes * 100).toFixed(1) : null;
      const memPct = row.mem_total_bytes > 0 ? (row.mem_used_bytes / row.mem_total_bytes * 100).toFixed(1) : null;
      const cpuPct = row.cpu_percent || 0;

      const bar = (label, pct) => {
        if (pct === null) return '';
        const color = pct < 60 ? '#22c55e' : pct < 80 ? '#eab308' : '#ef4444';
        return `<div style="margin-bottom:8px">
          <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px">
            <span>${label}</span><span style="color:${color};font-weight:600">${pct}%</span>
          </div>
          <div style="background:#0f172a;border-radius:4px;height:6px;overflow:hidden">
            <div style="width:${Math.min(pct, 100)}%;height:100%;background:${color};border-radius:4px;transition:width 0.3s"></div>
          </div>
        </div>`;
      };

      return `<div class="card" style="margin-bottom:16px">
        <h2 style="font-size:14px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">Infrastructure</h2>
        ${bar('CPU', cpuPct)}
        ${bar('Memory', memPct)}
        ${bar('Disk', diskPct)}
      </div>`;
    } catch { return ''; }
  }

  function generateRecentIncidentsSection(db, config) {
    try {
      const incidents = db.prepare(
        "SELECT app_slug, condition, action_taken, result, timestamp FROM healing_log WHERE timestamp > datetime('now', '-7 days') ORDER BY timestamp DESC LIMIT 10"
      ).all();
      if (incidents.length === 0) return '';

      let rows = '';
      for (const inc of incidents) {
        const appDef = config.apps.find(a => slugify(a.name) === inc.app_slug);
        const name = appDef ? htmlEscape(appDef.name) : htmlEscape(inc.app_slug);
        const time = inc.timestamp.replace('T', ' ').split('.')[0];
        const resultColor = inc.result === 'executed' ? '#22c55e' : inc.result === 'failed' ? '#ef4444' : '#eab308';
        rows += `<div style="padding:8px 0;border-bottom:1px solid #1f2937;font-size:13px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span><b>${name}</b> — ${htmlEscape(inc.condition)}</span>
            <span style="color:${resultColor};font-size:11px;font-weight:600">${htmlEscape(inc.result)}</span>
          </div>
          <div style="color:#64748b;font-size:11px;margin-top:2px">${time} UTC</div>
        </div>`;
      }

      return `<div class="card" style="margin-bottom:16px">
        <h2 style="font-size:14px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">Recent Incidents (7 days)</h2>
        ${rows}
      </div>`;
    } catch { return ''; }
  }

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

    // Latest response times per app
    const latestRt = {};
    const rtRows = db.prepare("SELECT app_slug, response_ms FROM uptime_history WHERE response_ms IS NOT NULL AND checked_at > datetime('now', '-1 hour') ORDER BY checked_at DESC").all();
    for (const row of rtRows) {
      if (!latestRt[row.app_slug]) latestRt[row.app_slug] = row.response_ms;
    }

    // Daily uptime for 90-day heatmap bars
    const dailyUptime = db.prepare(`
      SELECT app_slug, date(checked_at) as day, COUNT(*) as total,
        SUM(CASE WHEN status IN ('up','healthy') THEN 1 ELSE 0 END) as up_count
      FROM uptime_history WHERE checked_at > datetime('now', '-90 days')
      GROUP BY app_slug, day ORDER BY day
    `).all();
    const dailyByApp = {};
    for (const row of dailyUptime) {
      if (!dailyByApp[row.app_slug]) dailyByApp[row.app_slug] = {};
      dailyByApp[row.app_slug][row.day] = +(row.up_count / row.total * 100).toFixed(1);
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

      let healthScore = null;
      if (calculateAppReportCard) {
        try { healthScore = calculateAppReportCard(slug); } catch { /* ignore */ }
      }

      const responseMs = latestRt[slug] || null;
      apps.push({ name: appDef.name, domain: appDef.domain, slug, uptimePct, incidents: recentIncidents, daily: dailyByApp[slug] || {}, healthScore, responseMs });
    }

    const allOperational = apps.every(a => !a.incidents.length);
    const overallStatus = allOperational ? 'All Systems Operational' : 'Some Systems Have Recent Incidents';
    const overallColor = allOperational ? '#22c55e' : '#eab308';

    // Portfolio summary stats
    const healthScores = apps.map(a => a.healthScore?.overall).filter(s => typeof s === 'number');
    const avgHealth = healthScores.length > 0 ? Math.round(healthScores.reduce((a, b) => a + b, 0) / healthScores.length) : null;
    const uptimes = apps.map(a => parseFloat(a.uptimePct)).filter(u => !isNaN(u));
    const avgUptime = uptimes.length > 0 ? (uptimes.reduce((a, b) => a + b, 0) / uptimes.length).toFixed(2) : null;

    // Generate 90 dates for heatmap
    const heatmapDates = [];
    for (let i = 89; i >= 0; i--) {
      const d = new Date(Date.now() - i * MS_PER_DAY);
      heatmapDates.push(d.toISOString().split('T')[0]);
    }

    let appRows = '';
    for (const app of apps) {
      const uptime = app.uptimePct ? `${app.uptimePct}%` : 'N/A';
      const color = !app.uptimePct ? '#6b7280' : app.uptimePct >= 99.9 ? '#22c55e' : app.uptimePct >= 99 ? '#eab308' : '#ef4444';
      const statusDot = app.incidents.length > 0 ? '#eab308' : '#22c55e';

      // Build heatmap bars
      let bars = '';
      for (const date of heatmapDates) {
        const pct = app.daily[date];
        const barColor = pct === undefined ? '#1e293b' : pct >= 99.9 ? '#22c55e' : pct >= 99 ? '#86efac' : pct >= 95 ? '#eab308' : '#ef4444';
        bars += `<span class="hm" style="background:${barColor}" title="${date}: ${pct !== undefined ? pct + '%' : 'no data'}"></span>`;
      }

      // Health score badge
      const hs = app.healthScore;
      const gradeBadge = hs ? (() => {
        const gc = hs.grade === 'A' ? '#22c55e' : hs.grade === 'B' ? '#86efac' : hs.grade === 'C' ? '#eab308' : hs.grade === 'D' ? '#f97316' : '#ef4444';
        return `<span style="font-size:11px;font-weight:700;padding:2px 6px;border-radius:4px;background:${gc}20;color:${gc};margin-left:8px" title="Health: ${hs.overall}/100">${hs.grade}</span>`;
      })() : '';

      appRows += `
        <div style="padding:12px 0;border-bottom:1px solid #1f2937">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <div>
              <div style="font-weight:600;font-size:14px">${htmlEscape(app.name)}${gradeBadge}</div>
              <a href="https://${htmlEscape(app.domain)}" target="_blank" rel="noopener" style="font-size:12px;color:#60a5fa;text-decoration:none">${htmlEscape(app.domain)}</a>
            </div>
            <div style="display:flex;align-items:center;gap:12px">
              ${app.responseMs ? `<span style="font-size:11px;color:#64748b">${app.responseMs}ms</span>` : ''}
              <span style="font-size:13px;color:${color};font-weight:500">${uptime}</span>
              <span style="width:10px;height:10px;border-radius:50%;background:${statusDot};display:inline-block"></span>
            </div>
          </div>
          <div class="heatmap">${bars}</div>
        </div>`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>System Status — Dockfolio</title>
  <meta http-equiv="refresh" content="60">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
    .container{max-width:640px;margin:0 auto;padding:40px 20px}
    .header{text-align:center;margin-bottom:32px}
    .header h1{font-size:24px;font-weight:700;margin-bottom:8px}
    .status-badge{display:inline-block;padding:6px 16px;border-radius:20px;font-size:14px;font-weight:600}
    .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:16px 20px;margin-bottom:16px}
    .heatmap{display:flex;gap:1px;height:12px;border-radius:2px;overflow:hidden}
    .hm{flex:1;min-width:0;border-radius:1px}
    .footer{text-align:center;margin-top:32px;font-size:12px;color:#64748b}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>System Status</h1>
      <div class="status-badge" style="background:${overallColor}20;color:${overallColor}">${overallStatus}</div>
      ${avgHealth !== null || avgUptime !== null ? `<div style="display:flex;justify-content:center;gap:24px;margin-top:12px;font-size:13px;color:#94a3b8">
        <span>${apps.length} services</span>
        ${avgUptime !== null ? `<span>Avg uptime: <b style="color:#e2e8f0">${avgUptime}%</b></span>` : ''}
        ${avgHealth !== null ? `<span>Avg health: <b style="color:#e2e8f0">${avgHealth}/100</b></span>` : ''}
      </div>` : ''}
    </div>
    <div class="card">
      <h2 style="font-size:14px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">Services</h2>
      ${appRows}
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#64748b;padding:0 4px;margin-bottom:16px">
      <span>90 days ago</span>
      <div style="display:flex;align-items:center;gap:6px">
        <span style="width:8px;height:8px;background:#22c55e;border-radius:1px;display:inline-block"></span>99.9%+
        <span style="width:8px;height:8px;background:#86efac;border-radius:1px;display:inline-block"></span>99%+
        <span style="width:8px;height:8px;background:#eab308;border-radius:1px;display:inline-block"></span>95%+
        <span style="width:8px;height:8px;background:#ef4444;border-radius:1px;display:inline-block"></span>&lt;95%
      </div>
      <span>Today</span>
    </div>
    ${generateSystemHealthSection(db)}
    ${generateRecentIncidentsSection(db, config)}
    <div class="footer">
      <p>Last updated: ${new Date().toISOString().replace('T', ' ').split('.')[0]} UTC</p>
      <p style="margin-top:4px">Powered by <a href="https://github.com/Crelvo/appManager" style="color:#60a5fa;text-decoration:none">Dockfolio</a></p>
    </div>
  </div>
</body>
</html>`;
  }
}
