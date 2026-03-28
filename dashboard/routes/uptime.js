import { asyncRoute, containerName, slugify } from '../utils.js';

// Cache variables
let cachedUptime = null;
let lastUptimeUpdate = 0;
const UPTIME_TTL = 60_000;

let cachedUptimeTimeline = null;
let lastUptimeTimelineUpdate = 0;
const UPTIME_TIMELINE_TTL = 300_000; // 5 min cache

export default function registerUptimeRoutes({ app, docker, db, config, TIMEOUT_QUICK, TIMEOUT_STANDARD, MS_PER_DAY }) {

  // GET /api/uptime — proxy Uptime Kuma status page data
  app.get('/api/uptime', asyncRoute(async (_req, res) => {
    const now = Date.now();
    if (cachedUptime && (now - lastUptimeUpdate) < UPTIME_TTL) {
      return res.json(cachedUptime);
    }

    const kumaBase = process.env.UPTIME_KUMA_URL || 'http://dockfolio-uptime-kuma:3001';
    const kumaOpts = { signal: AbortSignal.timeout(TIMEOUT_QUICK) };
    const [statusResult, heartbeatResult] = await Promise.allSettled([
      fetch(`${kumaBase}/api/status-page/status`, kumaOpts),
      fetch(`${kumaBase}/api/status-page/heartbeat/status`, kumaOpts),
    ]);

    if (statusResult.status === 'rejected' && heartbeatResult.status === 'rejected') {
      return res.status(503).json({ error: 'Uptime Kuma unavailable', details: statusResult.reason?.message });
    }
    const statusData = statusResult.status === 'fulfilled' ? await statusResult.value.json() : { publicGroupList: [] };
    const heartbeatData = heartbeatResult.status === 'fulfilled' ? await heartbeatResult.value.json() : { heartbeatList: {} };

    // Map monitor data: id -> { name, uptime24h, avgPing, status }
    const monitors = {};
    const groups = statusData.publicGroupList || [];
    for (const group of groups) {
      for (const mon of group.monitorList || []) {
        const beats = heartbeatData.heartbeatList?.[String(mon.id)] || [];
        const lastBeat = beats[beats.length - 1];
        const pings = beats.filter(b => b.ping > 0).map(b => b.ping);
        const avgPing = pings.length > 0 ? Math.round(pings.reduce((a, b) => a + b, 0) / pings.length) : null;
        const uptime24 = heartbeatData.uptimeList?.[`${mon.id}_24`];

        // Last 24 heartbeats for sparkline (sampled)
        const totalBeats = beats.length;
        const sampleSize = 24;
        const step = Math.max(1, Math.floor(totalBeats / sampleSize));
        const sparkline = [];
        for (let i = 0; i < totalBeats; i += step) {
          sparkline.push(beats[i].status === 1 ? 'up' : beats[i].status === 0 ? 'down' : 'pending');
        }

        // Ping history for response time chart (last 30 points)
        const pingHistory = beats
          .filter(b => b.ping > 0)
          .slice(-30)
          .map(b => b.ping);

        monitors[mon.name] = {
          id: mon.id,
          status: lastBeat?.status === 1 ? 'up' : lastBeat?.status === 0 ? 'down' : 'pending',
          uptime24h: uptime24 != null ? Math.round(uptime24 * 10000) / 100 : null,
          avgPing,
          lastPing: lastBeat?.ping || null,
          sparkline: sparkline.slice(-24),
          pingHistory,
        };
      }
    }

    cachedUptime = { monitors, timestamp: new Date().toISOString() };
    lastUptimeUpdate = now;
    res.json(cachedUptime);
  }));

  // GET /api/uptime/timeline — 24h container uptime timeline
  app.get('/api/uptime/timeline', asyncRoute(async (_req, res) => {
    const now = Date.now();
    if (cachedUptimeTimeline && (now - lastUptimeTimelineUpdate) < UPTIME_TIMELINE_TTL) {
      return res.json(cachedUptimeTimeline);
    }

    const periodEnd = Math.floor(now / 1000);
    const periodStart = periodEnd - 86400; // 24 hours ago

    // Fetch Docker events for the last 24 hours
    const stream = await docker.getEvents({
      since: periodStart,
      until: periodEnd,
      filters: JSON.stringify({
        type: ['container'],
        event: ['start', 'stop', 'die', 'restart', 'health_status'],
      }),
    });

    const chunks = [];
    await new Promise((resolve) => {
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('end', resolve);
      stream.on('error', () => resolve());
      setTimeout(() => { stream.destroy(); resolve(); }, TIMEOUT_STANDARD);
    });

    const raw = Buffer.concat(chunks).toString();
    const events = raw.split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);

    // Get current container statuses
    const runningContainers = await docker.listContainers({ all: true });
    const currentStatusMap = new Map();
    for (const c of runningContainers) {
      const name = containerName(c);
      if (name) currentStatusMap.set(name, c.State);
    }

    // Build container-to-app mapping from config
    const containerToApp = new Map();
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      for (const cName of (appDef.containers || [])) {
        containerToApp.set(cName, slug);
      }
    }

    // Group events by container name
    const containerEvents = new Map();
    for (const e of events) {
      const name = e.Actor?.Attributes?.name;
      if (!name) continue;
      if (!containerEvents.has(name)) containerEvents.set(name, []);
      containerEvents.get(name).push({
        time: e.time || Math.floor(e.timeNano / 1e9),
        action: (e.Action || e.status || '').replace('health_status: ', ''),
      });
    }

    // Build timeline for each known container
    const containers = {};
    const allContainerNames = new Set([
      ...containerToApp.keys(),
      ...containerEvents.keys(),
    ]);

    for (const name of allContainerNames) {
      const appSlug = containerToApp.get(name) || null;
      const evts = (containerEvents.get(name) || []).sort((a, b) => a.time - b.time);
      const currentStatus = currentStatusMap.get(name) || 'unknown';

      // Calculate uptime: walk through events to determine running/stopped segments
      // Infer initial state from first event type or current status
      let wasRunning;
      if (evts.length === 0) {
        wasRunning = currentStatus === 'running';
      } else {
        const firstAction = evts[0].action;
        wasRunning = firstAction === 'stop' || firstAction === 'die' || firstAction === 'unhealthy';
      }

      let runningSeconds = 0;
      let lastTransition = periodStart;

      for (const evt of evts) {
        const evtTime = Math.max(evt.time, periodStart);
        if (wasRunning) {
          runningSeconds += evtTime - lastTransition;
        }
        lastTransition = evtTime;

        if (evt.action === 'start' || evt.action === 'restart' || evt.action === 'healthy') {
          wasRunning = true;
        } else if (evt.action === 'stop' || evt.action === 'die' || evt.action === 'unhealthy') {
          wasRunning = false;
        }
      }

      // Account for time from last event to period end
      if (wasRunning) {
        runningSeconds += periodEnd - lastTransition;
      }

      const totalSeconds = periodEnd - periodStart;
      const uptimePercent = Math.round((runningSeconds / totalSeconds) * 1000) / 10;

      containers[name] = {
        app: appSlug,
        currentStatus,
        events: evts,
        uptimePercent,
      };
    }

    const result = {
      containers,
      period: {
        start: new Date(periodStart * 1000).toISOString(),
        end: new Date(periodEnd * 1000).toISOString(),
      },
    };

    cachedUptimeTimeline = result;
    lastUptimeTimelineUpdate = now;
    res.json(result);
  }));

  // --- Uptime History ---
  app.get('/api/uptime/history', asyncRoute((req, res) => {
    const { app: appSlug, range = '24h' } = req.query;
    const ranges = { '24h': 1, '7d': 7, '30d': 30 };
    const days = ranges[range] || 1;
    const since = new Date(Date.now() - days * MS_PER_DAY).toISOString();
    let sql = 'SELECT * FROM uptime_history WHERE checked_at > ?';
    const params = [since];
    if (appSlug) { sql += ' AND app_slug = ?'; params.push(appSlug); }
    sql += ' ORDER BY checked_at DESC LIMIT 2000';
    const rows = db.prepare(sql).all(...params);
    // Calculate per-app uptime
    const byApp = {};
    for (const r of rows) {
      if (!byApp[r.app_slug]) byApp[r.app_slug] = { total: 0, up: 0 };
      byApp[r.app_slug].total++;
      if (r.status === 'up') byApp[r.app_slug].up++;
    }
    const uptime = {};
    for (const [slug, data] of Object.entries(byApp)) {
      uptime[slug] = Math.round((data.up / data.total) * 10000) / 100;
    }
    res.json({ range, since, uptime, data: rows });
  }));

  // --- Uptime Streaks ---
  // Track consecutive days of 100% uptime per app
  app.get('/api/uptime/streaks', asyncRoute((_req, res) => {
    const streaks = {};
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      if (!appDef.domain) { streaks[slug] = { current: 0, best: 0 }; continue; }

      // Get daily uptime status for last 90 days
      const days = db.prepare(`
        SELECT date(checked_at) as day,
               COUNT(*) as checks,
               SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_checks
        FROM uptime_history
        WHERE app_slug = ? AND checked_at > datetime('now', '-90 days')
        GROUP BY date(checked_at)
        ORDER BY day DESC
      `).all(slug);

      let current = 0, best = 0, streakBroken = false;
      for (const d of days) {
        const perfect = d.checks > 0 && d.up_checks === d.checks;
        if (perfect && !streakBroken) {
          current++;
        } else {
          streakBroken = true;
        }
        // Calculate best streak (scan all days)
      }
      // Best streak requires full scan
      let tempStreak = 0;
      for (let i = days.length - 1; i >= 0; i--) {
        const d = days[i];
        if (d.checks > 0 && d.up_checks === d.checks) {
          tempStreak++;
          if (tempStreak > best) best = tempStreak;
        } else {
          tempStreak = 0;
        }
      }
      streaks[slug] = { current, best, totalDaysTracked: days.length };
    }
    res.json({ streaks, timestamp: new Date().toISOString() });
  }));

  // --- Uptime Heatmap Calendar (GitHub-style, 90 days) ---
  app.get('/api/uptime/heatmap', asyncRoute((_req, res) => {
    const heatmap = {};

    for (const appDef of config.apps) {
      if (!appDef.domain) continue;
      const slug = slugify(appDef.name);
      const days = db.prepare(`
        SELECT date(checked_at) as day,
               COUNT(*) as total,
               SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count
        FROM uptime_history
        WHERE app_slug = ? AND checked_at > datetime('now', '-90 days')
        GROUP BY date(checked_at)
        ORDER BY day ASC
      `).all(slug);

      heatmap[slug] = days.map(d => ({
        date: d.day,
        uptime: d.total > 0 ? +(d.up_count / d.total * 100).toFixed(1) : null,
        checks: d.total,
      }));
    }

    res.json({ heatmap, timestamp: new Date().toISOString() });
  }));

  // --- SLO / Error Budget Tracking ---
  app.get('/api/slo', asyncRoute((_req, res) => {
    const slos = [];
    const daysInMonth = 30;
    const minutesInMonth = daysInMonth * 24 * 60;

    for (const appDef of config.apps) {
      if (!appDef.domain) continue;
      const slug = slugify(appDef.name);

      // Default SLO: 99.9% uptime
      const targetUptime = 99.9;
      const allowedDowntimeMinutes = +(minutesInMonth * (1 - targetUptime / 100)).toFixed(1); // ~43.2 min

      // Calculate actual uptime from uptime_history (last 30 days)
      const stats = db.prepare(`
        SELECT COUNT(*) as total,
               SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count
        FROM uptime_history
        WHERE app_slug = ? AND checked_at > datetime('now', '-30 days')
      `).get(slug);

      const actualUptime = stats.total > 0 ? +(stats.up_count / stats.total * 100).toFixed(3) : 100;
      const failedChecks = stats.total - (stats.up_count || 0);
      // Each check is ~5 min apart
      const downMinutes = failedChecks * 5;
      const budgetUsedPct = allowedDowntimeMinutes > 0 ? +(downMinutes / allowedDowntimeMinutes * 100).toFixed(1) : 0;
      const budgetRemaining = +(allowedDowntimeMinutes - downMinutes).toFixed(1);

      // Response time SLO: p95 < 1000ms
      const perfRow = db.prepare(`
        SELECT AVG(p95_ms) as avg_p95
        FROM perf_metrics
        WHERE app_slug = ? AND hour > datetime('now', '-7 days')
      `).get(slug);
      const avgP95 = perfRow?.avg_p95 ? Math.round(perfRow.avg_p95) : null;

      // Burn rate: budget consumption rate vs expected
      const daysSoFar = Math.max(1, Math.min(30, Math.round((Date.now() - new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).getTime()) / (24 * 60 * 60 * 1000))));
      const expectedBurnPct = +(daysSoFar / daysInMonth * 100).toFixed(1);
      const burnRate = expectedBurnPct > 0 ? +(budgetUsedPct / expectedBurnPct).toFixed(2) : 0;

      slos.push({
        slug,
        name: appDef.name,
        uptime: {
          target: targetUptime,
          actual: actualUptime,
          met: actualUptime >= targetUptime,
          allowedDowntime: allowedDowntimeMinutes,
          usedDowntime: downMinutes,
          budgetUsedPct,
          budgetRemaining: Math.max(0, budgetRemaining),
          burnRate,
          burnRateStatus: burnRate > 2 ? 'critical' : burnRate > 1.5 ? 'warning' : 'healthy',
        },
        responseTime: avgP95 ? {
          target: 1000,
          actual: avgP95,
          met: avgP95 <= 1000,
        } : null,
        totalChecks: stats.total,
      });
    }

    res.json({ slos, timestamp: new Date().toISOString() });
  }));
}
