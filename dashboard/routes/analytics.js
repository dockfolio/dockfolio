import { asyncRoute, slugify, todayString, formatDateISO, hashValue, safeJSON, isBot } from '../utils.js';

export default function registerAnalyticsRoutes({
  app, db, cron,
  rlPublicRead, TRANSPARENT_GIF,
  cronFail,
  MS_PER_HOUR, MS_PER_DAY,
}) {

  // Public: tracking pixel
  app.get('/api/analytics/pixel.gif', rlPublicRead, (req, res) => {
    const { app: appSlug, url, ref } = req.query;
    if (!appSlug) { res.setHeader('Content-Type', 'image/gif'); return res.send(TRANSPARENT_GIF); }
    const ua = req.headers['user-agent'] || '';
    if (isBot(ua)) { res.setHeader('Content-Type', 'image/gif'); return res.send(TRANSPARENT_GIF); }
    const sessionId = hashValue(req.ip + ua + todayString(), 16);
    const country = req.headers['cf-ipcountry'] || req.headers['x-country'] || null;
    try {
      db.prepare('INSERT INTO page_views (app_slug, url, referrer, user_agent, country, session_id) VALUES (?, ?, ?, ?, ?, ?)')
        .run(appSlug, url || '/', ref || null, ua.slice(0, 200), country, sessionId);
    } catch (err) { console.error('[ANALYTICS]', err.message); }
    res.setHeader('Content-Type', 'image/gif');
    res.setHeader('Cache-Control', 'no-store');
    res.send(TRANSPARENT_GIF);
  });

  // Public: JS tracking snippet
  app.get('/api/analytics/track.js', rlPublicRead, (req, res) => {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    const host = process.env.DASHBOARD_URL || req.get('host');
    res.send(`(function(){var s=document.currentScript&&document.currentScript.dataset.app;if(!s)return;var i=new Image();i.src='https://${host}/api/analytics/pixel.gif?app='+s+'&url='+encodeURIComponent(location.pathname)+'&ref='+encodeURIComponent(document.referrer);})();`);
  });

  // Public: POST-based tracker for SPAs
  app.post('/api/analytics/event', rlPublicRead, asyncRoute(async (req, res) => {
    const { app: appSlug, url, referrer } = req.body || {};
    if (!appSlug) return res.status(400).json({ error: 'app required' });
    const ua = req.headers['user-agent'] || '';
    if (isBot(ua)) return res.json({ ok: true });
    const sessionId = hashValue(req.ip + ua + todayString(), 16);
    const country = req.headers['cf-ipcountry'] || req.headers['x-country'] || null;
    try {
      db.prepare('INSERT INTO page_views (app_slug, url, referrer, user_agent, country, session_id) VALUES (?, ?, ?, ?, ?, ?)')
        .run(appSlug, url || '/', referrer || null, ua.slice(0, 200), country, sessionId);
    } catch (err) { console.error('[ANALYTICS]', err.message); }
    res.json({ ok: true });
  }));

  // Authenticated: analytics overview
  app.get('/api/analytics/overview', asyncRoute(async (req, res) => {
    const period = req.query.period || '30d';
    const days = period === '7d' ? 7 : period === '90d' ? 90 : 30;
    const since = formatDateISO(Date.now() - days * MS_PER_DAY);
    const rows = db.prepare('SELECT app_slug, SUM(visitors) as visitors, SUM(pageviews) as pageviews FROM analytics_daily WHERE date >= ? GROUP BY app_slug ORDER BY visitors DESC').all(since);
    const total = rows.reduce((s, r) => ({ visitors: s.visitors + (r.visitors || 0), pageviews: s.pageviews + (r.pageviews || 0) }), { visitors: 0, pageviews: 0 });
    res.json({ period, total, apps: rows });
  }));

  // Authenticated: per-app analytics
  app.get('/api/analytics/:slug', asyncRoute(async (req, res) => {
    const slug = req.params.slug;
    const days = parseInt(req.query.days) || 30;
    const since = formatDateISO(Date.now() - days * MS_PER_DAY);
    const daily = db.prepare('SELECT * FROM analytics_daily WHERE app_slug = ? AND date >= ? ORDER BY date').all(slug, since);
    const latest = daily[daily.length - 1];
    res.json({ slug, days, daily, topPages: safeJSON(latest?.top_pages, []), topReferrers: safeJSON(latest?.top_referrers, []), countries: safeJSON(latest?.countries, {}) });
  }));

  // Authenticated: realtime visitors (last 5 min)
  app.get('/api/analytics/realtime', asyncRoute(async (_req, res) => {
    const rows = db.prepare("SELECT app_slug, COUNT(DISTINCT session_id) as active FROM page_views WHERE created_at >= datetime('now', '-5 minutes') GROUP BY app_slug").all();
    res.json(rows);
  }));

  // Streaks endpoint (for ADHD mode gamification)
  app.get('/api/streaks', asyncRoute(async (_req, res) => {
    let streak = 0;
    try {
      const days = db.prepare(`
        SELECT date(checked_at) as d, COUNT(DISTINCT app_slug) as apps,
          SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count
        FROM uptime_history WHERE checked_at >= datetime('now', '-90 days')
        GROUP BY date(checked_at) ORDER BY d DESC
      `).all();
      for (const day of days) {
        if (day.up_count === day.apps && day.apps > 0) streak++;
        else break;
      }
    } catch { streak = 0; }
    let securityGrade = '--';
    try {
      const sec = db.prepare("SELECT score FROM security_scans ORDER BY scanned_at DESC LIMIT 1").get();
      if (sec) securityGrade = sec.score >= 90 ? 'A' : sec.score >= 80 ? 'B' : sec.score >= 70 ? 'C' : sec.score >= 60 ? 'D' : 'F';
    } catch { /* ok */ }
    res.json({ streak, securityGrade });
  }));

  // ========== ANALYTICS CRONS ==========

  // Hourly :05 — roll up page_views into analytics_hourly
  cron.schedule('5 * * * *', () => {
    try {
      const prevHour = new Date(Date.now() - MS_PER_HOUR);
      const hour = prevHour.toISOString().slice(0, 13);
      const start = hour + ':00:00';
      const nextHour = new Date(prevHour.getTime() + MS_PER_HOUR).toISOString().slice(0, 13) + ':00:00';
      const rows = db.prepare('SELECT app_slug, COUNT(*) as pageviews, COUNT(DISTINCT session_id) as visitors FROM page_views WHERE created_at >= ? AND created_at < ? GROUP BY app_slug').all(start, nextHour);
      const upsert = db.prepare('INSERT INTO analytics_hourly (app_slug, hour, visitors, pageviews) VALUES (?, ?, ?, ?) ON CONFLICT(app_slug, hour) DO UPDATE SET visitors = excluded.visitors, pageviews = excluded.pageviews');
      for (const r of rows) upsert.run(r.app_slug, hour, r.visitors, r.pageviews);
      if (rows.length) console.log(`[ANALYTICS] Hourly rollup: ${rows.length} apps for ${hour}`);
    } catch (err) { cronFail('Analytics hourly rollup', err); }
  });

  // Daily 1:30 AM — roll up into analytics_daily + prune raw page_views >7 days
  cron.schedule('30 1 * * *', () => {
    try {
      const yesterday = new Date(Date.now() - MS_PER_DAY).toISOString().slice(0, 10);
      const rows = db.prepare(`
        SELECT app_slug, COUNT(*) as pageviews, COUNT(DISTINCT session_id) as visitors
        FROM page_views WHERE date(created_at) = ? GROUP BY app_slug
      `).all(yesterday);
      const upsert = db.prepare(`INSERT INTO analytics_daily (app_slug, date, visitors, pageviews) VALUES (?, ?, ?, ?)
        ON CONFLICT(app_slug, date) DO UPDATE SET visitors = excluded.visitors, pageviews = excluded.pageviews`);
      for (const r of rows) upsert.run(r.app_slug, yesterday, r.visitors, r.pageviews);
      for (const r of rows) {
        const pages = db.prepare("SELECT url, COUNT(*) as c FROM page_views WHERE app_slug = ? AND date(created_at) = ? GROUP BY url ORDER BY c DESC LIMIT 10").all(r.app_slug, yesterday);
        const refs = db.prepare("SELECT referrer, COUNT(*) as c FROM page_views WHERE app_slug = ? AND date(created_at) = ? AND referrer IS NOT NULL AND referrer != '' GROUP BY referrer ORDER BY c DESC LIMIT 10").all(r.app_slug, yesterday);
        const countries = db.prepare("SELECT country, COUNT(*) as c FROM page_views WHERE app_slug = ? AND date(created_at) = ? AND country IS NOT NULL GROUP BY country ORDER BY c DESC").all(r.app_slug, yesterday);
        const countryObj = {};
        for (const c of countries) countryObj[c.country] = c.c;
        db.prepare("UPDATE analytics_daily SET top_pages = ?, top_referrers = ?, countries = ? WHERE app_slug = ? AND date = ?")
          .run(JSON.stringify(pages.map(p => p.url)), JSON.stringify(refs.map(r => r.referrer)), JSON.stringify(countryObj), r.app_slug, yesterday);
      }
      const pruned = db.prepare("DELETE FROM page_views WHERE created_at < datetime('now', '-7 days')").run();
      console.log(`[ANALYTICS] Daily rollup for ${yesterday}: ${rows.length} apps, pruned ${pruned.changes} old events`);
    } catch (err) { cronFail('Analytics daily rollup', err); }
  });
}
