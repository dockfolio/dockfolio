import { randomUUID } from 'crypto';
import express from 'express';
import { asyncRoute, safeJSON, parseId } from '../utils.js';

export default function registerErrorRoutes({ app, db, ingestError, rlErrorIngest }) {

  // Public: Accept error reports from apps
  app.post('/api/errors/ingest', rlErrorIngest, asyncRoute(async (req, res) => {
    const { app: appSlug, message, stack, severity, url, method, breadcrumbs, extra } = req.body;
    const result = ingestError({ app: appSlug, message, stack, severity, source: 'sdk', url, method, breadcrumbs, extra });
    res.status(result.ok ? 200 : 400).json(result);
  }));

  // Public: Sentry SDK envelope compatibility
  app.post('/api/errors/envelope', rlErrorIngest, express.text({ type: '*/*', limit: '64kb' }), asyncRoute(async (req, res) => {
    try {
      const lines = (typeof req.body === 'string' ? req.body : '').split('\n').filter(Boolean);
      if (lines.length < 2) return res.status(400).json({ error: 'invalid envelope' });

      const header = JSON.parse(lines[0]);
      let appSlug = 'unknown';
      if (header.dsn) {
        const dsnPath = new URL(header.dsn).pathname.replace(/^\//, '');
        if (dsnPath) appSlug = dsnPath;
      }

      for (let i = 1; i < lines.length - 1; i += 2) {
        const itemHeader = JSON.parse(lines[i]);
        if (itemHeader.type !== 'event' && itemHeader.type !== 'error') continue;
        const payload = JSON.parse(lines[i + 1]);

        const exc = payload.exception?.values?.[0];
        const message = exc ? `${exc.type || 'Error'}: ${exc.value || ''}` : payload.message || 'Unknown error';
        const stack = exc?.stacktrace?.frames
          ? exc.stacktrace.frames.reverse().map(f => `  at ${f.function || '?'} (${f.filename || '?'}:${f.lineno || 0}:${f.colno || 0})`).join('\n')
          : null;

        ingestError({
          app: appSlug, message, stack, severity: payload.level || 'error',
          source: 'sentry_sdk', url: payload.request?.url, method: payload.request?.method,
          breadcrumbs: payload.breadcrumbs?.values, extra: payload.extra
        });
      }
      res.json({ id: randomUUID() });
    } catch (err) {
      res.status(400).json({ error: 'failed to parse envelope' });
    }
  }));

  // Public: Lightweight browser error SDK
  app.get('/api/errors/sdk.js', (_req, res) => {
    res.type('application/javascript').send(`(function(){
  var s=document.currentScript,app=s&&s.getAttribute('data-app')||'unknown',
      url=(s&&s.getAttribute('data-url'))||s.src.replace(/\\/api\\/errors\\/sdk\\.js.*/,'/api/errors/ingest');
  function send(d){try{navigator.sendBeacon(url,JSON.stringify(d))}catch(e){}}
  window.addEventListener('error',function(e){
    send({app:app,message:e.message,stack:e.error&&e.error.stack||'',severity:'error',url:location.href});
  });
  window.addEventListener('unhandledrejection',function(e){
    var msg=e.reason&&e.reason.message||String(e.reason||'Unhandled rejection');
    send({app:app,message:msg,stack:e.reason&&e.reason.stack||'',severity:'error',url:location.href});
  });
  window.dockfolio={reportError:function(err,extra){
    send({app:app,message:err.message||String(err),stack:err.stack||'',severity:'error',url:location.href,extra:extra});
  }};
})();`);
  });

  // Authenticated: List error issues
  app.get('/api/errors/issues', asyncRoute((_req, res) => {
    const { app: appFilter, status, severity, limit = '50' } = _req.query;
    let sql = 'SELECT * FROM error_issues WHERE 1=1';
    const params = [];
    if (appFilter) { sql += ' AND app_slug = ?'; params.push(appFilter); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (severity) { sql += ' AND severity = ?'; params.push(severity); }
    sql += ' ORDER BY last_seen DESC LIMIT ?';
    params.push(Math.min(parseInt(limit) || 50, 200));
    const issues = db.prepare(sql).all(...params);
    issues.forEach(i => { i.metadata = safeJSON(i.metadata); });
    res.json({ issues });
  }));

  // Authenticated: Single issue with recent events
  app.get('/api/errors/issues/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
    const issue = db.prepare('SELECT * FROM error_issues WHERE id = ?').get(id);
    if (!issue) return res.status(404).json({ error: 'not found' });
    issue.metadata = safeJSON(issue.metadata);
    const events = db.prepare('SELECT * FROM error_events WHERE issue_id = ? ORDER BY timestamp DESC LIMIT 50').all(id);
    events.forEach(e => { e.breadcrumbs = safeJSON(e.breadcrumbs, []); e.extra = safeJSON(e.extra); });
    res.json({ issue, events });
  }));

  // Authenticated: Resolve/ignore/reopen
  app.patch('/api/errors/issues/:id', asyncRoute((req, res) => {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'invalid id' });
    const { status } = req.body;
    if (!['open', 'resolved', 'ignored'].includes(status)) return res.status(400).json({ error: 'status must be open/resolved/ignored' });
    const resolvedAt = status === 'resolved' ? new Date().toISOString() : null;
    db.prepare('UPDATE error_issues SET status = ?, resolved_at = ? WHERE id = ?').run(status, resolvedAt, id);
    res.json({ ok: true });
  }));

  // POST /api/errors/issues/bulk — Bulk update issues
  app.post('/api/errors/issues/bulk', asyncRoute((req, res) => {
    const { ids, status } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids array required' });
    if (!['open', 'resolved', 'ignored'].includes(status)) return res.status(400).json({ error: 'status must be open/resolved/ignored' });
    const resolvedAt = status === 'resolved' ? new Date().toISOString() : null;
    const update = db.prepare('UPDATE error_issues SET status = ?, resolved_at = ? WHERE id = ?');
    const tx = db.transaction(() => { for (const id of ids) update.run(status, resolvedAt, id); });
    tx();
    res.json({ ok: true, updated: ids.length });
  }));

  // Authenticated: Recent events
  app.get('/api/errors/events', asyncRoute((req, res) => {
    const { app: appFilter, issue_id, limit = '50', offset = '0' } = req.query;
    let sql = 'SELECT e.*, i.title as issue_title, i.severity FROM error_events e JOIN error_issues i ON e.issue_id = i.id WHERE 1=1';
    const params = [];
    if (appFilter) { sql += ' AND e.app_slug = ?'; params.push(appFilter); }
    if (issue_id) { sql += ' AND e.issue_id = ?'; params.push(parseInt(issue_id)); }
    sql += ' ORDER BY e.timestamp DESC LIMIT ? OFFSET ?';
    params.push(Math.min(parseInt(limit) || 50, 200), parseInt(offset) || 0);
    const events = db.prepare(sql).all(...params);
    events.forEach(e => { e.breadcrumbs = safeJSON(e.breadcrumbs, []); e.extra = safeJSON(e.extra); });
    res.json({ events });
  }));

  // Authenticated: Error stats
  app.get('/api/errors/stats', asyncRoute((_req, res) => {
    const byApp = db.prepare("SELECT app_slug, COUNT(*) as count, SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical, SUM(CASE WHEN severity='error' THEN 1 ELSE 0 END) as errors, SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END) as warnings FROM error_issues WHERE status = 'open' GROUP BY app_slug").all();
    const bySeverity = db.prepare("SELECT severity, COUNT(*) as count FROM error_issues WHERE status = 'open' GROUP BY severity").all();
    const totalOpen = db.prepare("SELECT COUNT(*) as count FROM error_issues WHERE status = 'open'").get();
    const last24h = db.prepare("SELECT COUNT(*) as count FROM error_events WHERE timestamp >= datetime('now', '-24 hours')").get();
    const last7d = db.prepare("SELECT date(timestamp) as day, COUNT(*) as count FROM error_events WHERE timestamp >= datetime('now', '-7 days') GROUP BY day ORDER BY day").all();
    const noisiest = db.prepare("SELECT id, app_slug, title, severity, occurrence_count, last_seen FROM error_issues WHERE status = 'open' ORDER BY occurrence_count DESC LIMIT 5").all();
    res.json({ byApp, bySeverity, totalOpen: totalOpen?.count || 0, last24h: last24h?.count || 0, last7d, noisiest });
  }));

  // Authenticated: Full-text search
  app.get('/api/errors/search', asyncRoute((req, res) => {
    const q = req.query.q;
    if (!q || q.length < 2) return res.status(400).json({ error: 'query too short' });
    const pattern = `%${q}%`;
    const issues = db.prepare('SELECT * FROM error_issues WHERE title LIKE ? OR app_slug LIKE ? ORDER BY last_seen DESC LIMIT 50').all(pattern, pattern);
    issues.forEach(i => { i.metadata = safeJSON(i.metadata); });
    res.json({ issues });
  }));

  // Authenticated: Performance metrics
  app.get('/api/errors/perf', asyncRoute((req, res) => {
    const hours = Math.min(parseInt(req.query.hours) || 24, 168);
    const metrics = db.prepare(`SELECT endpoint, SUM(request_count) as requests,
      CAST(AVG(p50_ms) AS INTEGER) as avg_p50, CAST(AVG(p95_ms) AS INTEGER) as avg_p95,
      CAST(AVG(p99_ms) AS INTEGER) as avg_p99, SUM(error_count) as errors
      FROM perf_metrics WHERE hour >= datetime('now', '-' || ? || ' hours')
      GROUP BY endpoint ORDER BY requests DESC`).all(hours);
    res.json({ metrics, hours });
  }));
}
