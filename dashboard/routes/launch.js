import { readFileSync } from 'fs';
import { asyncRoute, slugify, containerName } from '../utils.js';

export default function registerLaunchRoutes({ app, docker, db, config, findAppBySlug, auditLog, sendTelegram, cachedRevenue }) {
  let launchMode = null;

  app.post('/api/launch/start', asyncRoute(async (req, res) => {
    const { slug } = req.body;
    if (!slug) return res.status(400).json({ error: 'slug is required' });
    const appDef = findAppBySlug(slug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });

    if (launchMode?.intervalId) clearInterval(launchMode.intervalId);

    launchMode = { slug, appName: appDef.name, startedAt: new Date().toISOString(), stats: [] };
    auditLog(req, 'launch.start', slug);

    sendTelegram(`🚀 <b>Launch Mode Activated!</b>\n${appDef.name} (${appDef.domain || slug})\nMonitoring every 30 seconds.`);

    launchMode.intervalId = setInterval(async () => {
      if (!launchMode || launchMode.slug !== slug) return;
      try {
        const snapshot = { ts: new Date().toISOString() };

        const containers = await docker.listContainers({ all: true });
        const appContainers = (appDef.containers || []).map(name => {
          const c = containers.find(ct => containerName(ct) === name);
          return { name, state: c?.State || 'not found' };
        });
        snapshot.containers = appContainers;
        snapshot.allHealthy = appContainers.every(c => c.state === 'running');

        const recentVisits = db.prepare("SELECT COUNT(*) as count FROM page_views WHERE app_slug = ? AND created_at >= datetime('now', '-5 minutes')").get(slug);
        snapshot.visitors5m = recentVisits?.count || 0;

        const rev = cachedRevenue();
        if (rev?.apps) {
          const appRev = Object.entries(rev.apps).find(([name]) => slugify(name) === slug);
          if (appRev) snapshot.revenue = { mrr: (appRev[1].mrr / 100).toFixed(2), charges30d: appRev[1].chargeCount30d };
        }

        try {
          const loadLine = readFileSync('/proc/loadavg', 'utf8').trim().split(' ');
          snapshot.load = parseFloat(loadLine[0]);
        } catch { snapshot.load = null; }

        launchMode.stats.push(snapshot);
        if (launchMode.stats.length > 600) launchMode.stats.shift();

        if (!snapshot.allHealthy) {
          const down = appContainers.filter(c => c.state !== 'running').map(c => c.name).join(', ');
          sendTelegram(`⚠️ <b>Launch Alert!</b>\n${appDef.name}: Container(s) not running: ${down}`);
        }
      } catch (err) {
        console.error('[LAUNCH] Stats collection error:', err.message);
      }
    }, 30_000);

    res.json({ ok: true, app: appDef.name, slug });
  }));

  app.post('/api/launch/stop', asyncRoute(async (req, res) => {
    if (!launchMode) return res.json({ ok: true, message: 'Launch mode was not active' });
    const duration = Math.round((Date.now() - new Date(launchMode.startedAt).getTime()) / 60000);
    sendTelegram(`🏁 <b>Launch Mode Ended</b>\n${launchMode.appName}\nDuration: ${duration} minutes\nSnapshots collected: ${launchMode.stats.length}`);
    if (launchMode.intervalId) clearInterval(launchMode.intervalId);
    auditLog(req, 'launch.stop', launchMode.slug);
    launchMode = null;
    res.json({ ok: true });
  }));

  app.get('/api/launch/status', asyncRoute(async (req, res) => {
    if (!launchMode) return res.json({ active: false });

    const appDef = findAppBySlug(launchMode.slug);
    const duration = Math.round((Date.now() - new Date(launchMode.startedAt).getTime()) / 60000);
    const recentStats = launchMode.stats.slice(-20);
    const totalVisitors = launchMode.stats.reduce((sum, s) => sum + (s.visitors5m || 0), 0);
    const latestSnapshot = launchMode.stats[launchMode.stats.length - 1] || {};

    res.json({
      active: true,
      slug: launchMode.slug,
      appName: launchMode.appName,
      domain: appDef?.domain || null,
      startedAt: launchMode.startedAt,
      durationMinutes: duration,
      snapshotCount: launchMode.stats.length,
      totalVisitors,
      latestSnapshot,
      recentStats,
    });
  }));
}
