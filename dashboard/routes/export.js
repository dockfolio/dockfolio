import { asyncRoute, toCsv } from '../utils.js';

function sendExport(res, rows, name, format) {
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${name}-${new Date().toISOString().slice(0,10)}.csv"`);
    return res.send(toCsv(rows));
  }
  res.json({ entity: name, exported_at: new Date().toISOString(), count: rows.length, data: rows });
}

export default function registerExportRoutes({ app, db, config }) {

app.get('/api/export/:entity', asyncRoute((req, res) => {
  const entity = req.params.entity;
  const format = req.query.format || 'json';
  let rows;
  switch (entity) {
    case 'errors': rows = db.prepare('SELECT i.*, (SELECT COUNT(*) FROM error_events WHERE issue_id = i.id) as event_count FROM error_issues i ORDER BY i.last_seen DESC LIMIT 1000').all(); break;
    case 'security': rows = db.prepare("SELECT * FROM security_findings WHERE status != 'dismissed' ORDER BY id DESC LIMIT 1000").all(); break;
    case 'tasks': rows = db.prepare('SELECT * FROM project_tasks ORDER BY due_date ASC LIMIT 1000').all(); break;
    case 'roadmap': rows = db.prepare('SELECT * FROM project_roadmap ORDER BY id DESC LIMIT 1000').all(); break;
    case 'metrics': rows = db.prepare('SELECT * FROM metrics_daily ORDER BY date DESC LIMIT 2000').all(); break;
    case 'seo': rows = db.prepare('SELECT * FROM seo_audits ORDER BY date DESC LIMIT 500').all(); break;
    case 'audit': rows = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 1000').all(); break;
    default: return res.status(400).json({ error: `Unknown entity: ${entity}. Valid: errors, security, tasks, roadmap, metrics, seo, audit` });
  }
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${entity}-export.csv"`);
    return res.send(toCsv(rows));
  }
  res.json({ entity, count: rows.length, data: rows });
}));

app.get('/api/export/metrics', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 30;
  const format = req.query.format || 'json';
  const rows = db.prepare("SELECT * FROM metrics_daily WHERE date >= date('now', '-' || ? || ' days') ORDER BY date DESC").all(days);
  sendExport(res, rows, 'metrics', format);
}));

app.get('/api/export/errors', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 7;
  const format = req.query.format || 'json';
  const rows = db.prepare(`
    SELECT e.id, e.issue_id, e.app_slug, e.timestamp, e.message, e.source, e.container_name,
           e.request_url, e.request_method, i.severity, i.status, i.title as issue_title, i.fingerprint
    FROM error_events e
    LEFT JOIN error_issues i ON e.issue_id = i.id
    WHERE e.timestamp >= datetime('now', '-' || ? || ' days')
    ORDER BY e.timestamp DESC
  `).all(days);
  sendExport(res, rows, 'errors', format);
}));

app.get('/api/export/healing', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 30;
  const format = req.query.format || 'json';
  const rows = db.prepare("SELECT * FROM healing_log WHERE timestamp >= datetime('now', '-' || ? || ' days') ORDER BY timestamp DESC").all(days);
  sendExport(res, rows, 'healing', format);
}));

app.get('/api/export/notifications', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 30;
  const format = req.query.format || 'json';
  const rows = db.prepare("SELECT * FROM notifications WHERE timestamp >= datetime('now', '-' || ? || ' days') ORDER BY timestamp DESC").all(days);
  sendExport(res, rows, 'notifications', format);
}));

app.get('/api/export/deploys', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 30;
  const format = req.query.format || 'json';
  const rows = db.prepare("SELECT * FROM deploy_log WHERE timestamp >= datetime('now', '-' || ? || ' days') ORDER BY timestamp DESC").all(days);
  sendExport(res, rows, 'deploys', format);
}));

app.get('/api/export/system', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 7;
  const format = req.query.format || 'json';
  const rows = db.prepare("SELECT * FROM system_snapshots WHERE ts >= datetime('now', '-' || ? || ' days') ORDER BY ts DESC").all(days);
  sendExport(res, rows, 'system', format);
}));

app.get('/api/export/container-metrics', asyncRoute((req, res) => {
  const format = req.query.format || 'json';
  const rows = db.prepare("SELECT * FROM container_metrics WHERE ts >= datetime('now', '-48 hours') ORDER BY ts DESC").all();
  sendExport(res, rows, 'container-metrics', format);
}));

app.get('/api/export/all', asyncRoute((req, res) => {
  const format = req.query.format || 'json';
  if (format === 'csv') return res.status(400).json({ error: 'Full export only available as JSON' });
  const bundle = {
    exported_at: new Date().toISOString(),
    metrics: db.prepare("SELECT * FROM metrics_daily ORDER BY date DESC").all(),
    errors: db.prepare(`
      SELECT e.id, e.issue_id, e.app_slug, e.timestamp, e.message, e.source, e.container_name,
             e.request_url, e.request_method, i.severity, i.status, i.title as issue_title, i.fingerprint
      FROM error_events e LEFT JOIN error_issues i ON e.issue_id = i.id ORDER BY e.timestamp DESC
    `).all(),
    healing: db.prepare("SELECT * FROM healing_log ORDER BY timestamp DESC").all(),
    notifications: db.prepare("SELECT * FROM notifications ORDER BY timestamp DESC").all(),
    deploys: db.prepare("SELECT * FROM deploy_log ORDER BY timestamp DESC").all(),
    system_snapshots: db.prepare("SELECT * FROM system_snapshots ORDER BY ts DESC").all(),
    container_metrics: db.prepare("SELECT * FROM container_metrics WHERE ts >= datetime('now', '-48 hours') ORDER BY ts DESC").all(),
    app_config: config.apps
  };
  res.setHeader('Content-Disposition', `attachment; filename="dockfolio-export-${new Date().toISOString().slice(0,10)}.json"`);
  res.json(bundle);
}));

}
