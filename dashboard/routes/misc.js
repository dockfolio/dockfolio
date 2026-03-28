import { asyncRoute, slugify } from '../utils.js';
import { readFileSync } from 'fs';

export default function registerMiscRoutes({
  app, db, docker, config,
  auditLog, resolveContainerApp, getSetting,
  qLatestMetric, calculateAppReportCard,
  marketingCache,
  perfRing, slowRequests,
  setCORS,
  MS_PER_HOUR, MS_PER_DAY,
}) {

  // --- Perf metrics ---
  app.get('/api/perf', (_req, res) => {
    const fiveMinAgo = Date.now() - 5 * 60 * 1000;
    const recent = perfRing.filter(e => e && new Date(e.timestamp).getTime() > fiveMinAgo);
    const durations = recent.map(e => e.durationMs).sort((a, b) => a - b);
    const count = durations.length;
    const avgMs = count > 0 ? Math.round(durations.reduce((s, d) => s + d, 0) / count) : 0;
    const p95Ms = count > 0 ? durations[Math.floor(count * 0.95)] : 0;
    const p99Ms = count > 0 ? durations[Math.floor(count * 0.99)] : 0;
    const maxMs = count > 0 ? durations[count - 1] : 0;
    res.json({
      requests5m: { count, avgMs, p95Ms, p99Ms, maxMs },
      slowRequests: slowRequests.slice(-10),
    });
  });

  // --- Notification Center ---
  app.get('/api/notifications', (req, res) => {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const unreadOnly = req.query.unread === 'true';
    const category = req.query.category || null;

    let sql = 'SELECT * FROM notifications';
    const conditions = [];
    const params = [];

    if (unreadOnly) { conditions.push('read = 0'); }
    if (category) { conditions.push('category = ?'); params.push(category); }

    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limit);

    const rows = db.prepare(sql).all(...params);
    res.json({ notifications: rows });
  });

  app.get('/api/notifications/count', (_req, res) => {
    const { n } = db.prepare('SELECT COUNT(*) as n FROM notifications WHERE read = 0').get();
    res.json({ unread: n });
  });

  app.post('/api/notifications/:id/read', (req, res) => {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(id);
    res.json({ ok: true });
  });

  app.post('/api/notifications/read-all', (_req, res) => {
    db.prepare('UPDATE notifications SET read = 1 WHERE read = 0').run();
    res.json({ ok: true });
  });

  // --- Audit Log ---
  app.get('/api/audit', asyncRoute((_req, res) => {
    const limit = Math.min(parseInt(_req.query.limit) || 100, 500);
    const offset = parseInt(_req.query.offset) || 0;
    const user = _req.query.user;
    const method = _req.query.method;

    let sql = 'SELECT * FROM audit_log WHERE 1=1';
    const params = [];

    if (user) { sql += ' AND user = ?'; params.push(user); }
    if (method) { sql += ' AND method = ?'; params.push(method.toUpperCase()); }

    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const entries = db.prepare(sql).all(...params);
    const total = db.prepare('SELECT COUNT(*) as count FROM audit_log').get().count;

    res.json({ entries, total, limit, offset });
  }));

  // --- Playground / Route Listing ---
  app.get('/api/playground/routes', (_req, res) => {
    const routes = [];
    const seen = new Set();

    function categorize(path) {
      if (/^\/api\/auth\//.test(path)) return 'Auth';
      if (/^\/api\/(apps|containers|docker)/.test(path)) return 'Docker & Infrastructure';
      if (/^\/api\/(system|health|uptime|ssl|events|disk|backups)/.test(path)) return 'System';
      if (/^\/api\/marketing\//.test(path)) return 'Marketing';
      if (/^\/api\/security\//.test(path)) return 'Security';
      if (/^\/api\/config\//.test(path)) return 'Configuration';
      if (/^\/api\/healing\//.test(path)) return 'Auto-Healing';
      if (/^\/api\/ai\//.test(path)) return 'AI';
      if (/^\/api\/(predictions|cost-analysis|deploys)/.test(path)) return 'Analytics';
      if (/^\/api\/banners\//.test(path)) return 'Banners';
      if (/^\/api\/crosspromo\//.test(path)) return 'Cross-Promotion';
      if (/^\/api\/playground\//.test(path)) return 'Playground';
      if (/^\/api\//.test(path)) return 'Other';
      return null;
    }

    if (app._router && app._router.stack) {
      for (const layer of app._router.stack) {
        if (layer.route) {
          const path = layer.route.path;
          const methods = Object.keys(layer.route.methods).filter(m => layer.route.methods[m]).map(m => m.toUpperCase());
          for (const method of methods) {
            const key = method + ' ' + path;
            if (!seen.has(key) && path.startsWith('/api/')) {
              seen.add(key);
              const category = categorize(path);
              if (category) {
                const params = (path.match(/:(\w+)/g) || []).map(p => p.slice(1));
                routes.push({ method, path, category, params });
              }
            }
          }
        }
      }
    }

    const grouped = {};
    for (const route of routes) {
      if (!grouped[route.category]) grouped[route.category] = [];
      grouped[route.category].push(route);
    }

    const order = ['Auth', 'Docker & Infrastructure', 'System', 'Configuration', 'Marketing', 'Banners', 'Cross-Promotion', 'Security', 'Auto-Healing', 'AI', 'Analytics', 'Playground', 'Other'];
    const sorted = {};
    for (const cat of order) {
      if (grouped[cat]) sorted[cat] = grouped[cat];
    }
    for (const cat of Object.keys(grouped)) {
      if (!sorted[cat]) sorted[cat] = grouped[cat];
    }

    res.json({ routes: sorted, total: routes.length });
  });

  // --- Domain Overview ---
  app.get('/api/domains/overview', asyncRoute(async (_req, res) => {
    const { promises: dnsPromises } = await import('dns');
    const domains = [];

    for (const appDef of config.apps) {
      if (!appDef.domain) continue;
      const slug = slugify(appDef.name);
      const domain = appDef.domain;
      const entry = { domain, slug, name: appDef.name, type: appDef.type };

      // DNS
      try {
        const addrs = await dnsPromises.resolve4(domain);
        entry.dns = { ok: addrs.includes('91.99.104.132'), addresses: addrs };
      } catch { entry.dns = { ok: false, addresses: [] }; }

      // SEO (from cache)
      const cachedSEO = marketingCache?.seo;
      if (cachedSEO?.apps) {
        const seoEntry = Object.entries(cachedSEO.apps).find(([name]) => slugify(name) === slug);
        if (seoEntry) entry.seo = { score: seoEntry[1].score, grade: seoEntry[1].grade };
      }

      // Traffic
      try {
        const pv = qLatestMetric.get(slug, 'pageviews_30d');
        entry.traffic = pv ? { pageviews30d: pv.value } : { pageviews30d: 0 };
      } catch { entry.traffic = { pageviews30d: 0 }; }

      // Revenue
      try {
        const mrr = qLatestMetric.get(slug, 'mrr');
        entry.revenue = mrr ? { mrr: mrr.value / 100 } : { mrr: 0 };
      } catch { entry.revenue = { mrr: 0 }; }

      // Uptime
      try {
        const stats = db.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count FROM uptime_history WHERE app_slug = ? AND checked_at > datetime('now', '-24 hours')").get(slug);
        entry.uptime = stats.total > 0 ? { pct: +(stats.up_count / stats.total * 100).toFixed(1), checks: stats.total } : { pct: null, checks: 0 };
      } catch { entry.uptime = { pct: null, checks: 0 }; }

      // Container status
      try {
        const containers = await docker.listContainers({ all: true });
        const appContainers = (appDef.containers || []).map(name => {
          const c = containers.find(ct => {
            const cNames = ct.Names?.map(n => n.replace(/^\//, '')) || [];
            return cNames.includes(name);
          });
          return c?.State || 'not found';
        });
        entry.containers = { total: appContainers.length, running: appContainers.filter(s => s === 'running').length };
      } catch { entry.containers = { total: 0, running: 0 }; }

      // Health score
      try {
        const card = calculateAppReportCard(slug);
        if (card) entry.healthScore = { score: card.overall, grade: card.grade };
      } catch { /* skip */ }

      domains.push(entry);
    }

    domains.sort((a, b) => (a.healthScore?.score || 0) - (b.healthScore?.score || 0));

    res.json({ domains, timestamp: new Date().toISOString() });
  }));
}
