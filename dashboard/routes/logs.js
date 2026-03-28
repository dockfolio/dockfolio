import { asyncRoute } from '../utils.js';

export default function registerLogRoutes({ app, db }) {

// GET /api/logs/search — Full-text search across all container logs
app.get('/api/logs/search', asyncRoute(async (req, res) => {
  const { q, container, app: appSlug, stream, since, until } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 200, 1000);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);

  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Query must be at least 2 characters' });
  }

  // Use FTS5 for search
  let sql = `SELECT cl.id, cl.container_name, cl.app_slug, cl.stream, cl.line, cl.logged_at
    FROM container_logs_fts fts
    JOIN container_logs cl ON cl.id = fts.rowid
    WHERE container_logs_fts MATCH ?`;
  const params = [q.trim()];

  if (container) { sql += ' AND cl.container_name = ?'; params.push(container); }
  if (appSlug) { sql += ' AND cl.app_slug = ?'; params.push(appSlug); }
  if (stream) { sql += ' AND cl.stream = ?'; params.push(stream); }
  if (since) { sql += ' AND cl.logged_at >= ?'; params.push(since); }
  if (until) { sql += ' AND cl.logged_at <= ?'; params.push(until); }

  sql += ' ORDER BY cl.logged_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  try {
    const results = db.prepare(sql).all(...params);

    // Get total count for pagination
    let countSql = `SELECT COUNT(*) as total FROM container_logs_fts fts JOIN container_logs cl ON cl.id = fts.rowid WHERE container_logs_fts MATCH ?`;
    const countParams = [q.trim()];
    if (container) { countSql += ' AND cl.container_name = ?'; countParams.push(container); }
    if (appSlug) { countSql += ' AND cl.app_slug = ?'; countParams.push(appSlug); }
    if (stream) { countSql += ' AND cl.stream = ?'; countParams.push(stream); }
    if (since) { countSql += ' AND cl.logged_at >= ?'; countParams.push(since); }
    if (until) { countSql += ' AND cl.logged_at <= ?'; countParams.push(until); }
    const total = db.prepare(countSql).get(...countParams).total;

    res.json({ results, total, limit, offset, query: q.trim() });
  } catch (err) {
    if (err.message.includes('fts5')) {
      return res.status(400).json({ error: 'Invalid search query. Use simple keywords or "quoted phrases".' });
    }
    throw err;
  }
}));

// GET /api/logs/recent — Recent logs (no search, just tail)
app.get('/api/logs/recent', asyncRoute(async (req, res) => {
  const { container, app: appSlug } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);

  let sql = 'SELECT id, container_name, app_slug, stream, line, logged_at FROM container_logs WHERE 1=1';
  const params = [];

  if (container) { sql += ' AND container_name = ?'; params.push(container); }
  if (appSlug) { sql += ' AND app_slug = ?'; params.push(appSlug); }

  sql += ' ORDER BY logged_at DESC LIMIT ?';
  params.push(limit);

  const results = db.prepare(sql).all(...params);
  res.json({ results });
}));

// GET /api/logs/patterns — Detect recurring error patterns
app.get('/api/logs/patterns', asyncRoute(async (req, res) => {
  const hours = Math.min(parseInt(req.query.hours) || 6, 24);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();

  // Find error-like lines and group by normalized message
  const errorLines = db.prepare(`
    SELECT container_name, app_slug, line, logged_at
    FROM container_logs
    WHERE logged_at >= ?
    AND (line LIKE '%error%' OR line LIKE '%Error%' OR line LIKE '%ERROR%'
      OR line LIKE '%exception%' OR line LIKE '%Exception%'
      OR line LIKE '%fatal%' OR line LIKE '%FATAL%'
      OR line LIKE '%failed%' OR line LIKE '%FAILED%')
    ORDER BY logged_at DESC
    LIMIT 5000
  `).all(since);

  // Group by normalized pattern (strip numbers, timestamps, IDs)
  const patternMap = new Map();
  for (const row of errorLines) {
    const normalized = row.line
      .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\dZ]*/g, '<TS>')
      .replace(/\b[0-9a-f]{8,}\b/gi, '<ID>')
      .replace(/\b\d+\.\d+\.\d+\.\d+\b/g, '<IP>')
      .replace(/\b\d{4,}\b/g, '<N>')
      .replace(/:\d+/g, ':<PORT>')
      .trim()
      .slice(0, 200);

    const existing = patternMap.get(normalized);
    if (existing) {
      existing.count++;
      if (row.logged_at < existing.first_seen) existing.first_seen = row.logged_at;
      if (row.logged_at > existing.last_seen) existing.last_seen = row.logged_at;
      if (!existing.containers.includes(row.container_name)) existing.containers.push(row.container_name);
      if (row.app_slug && !existing.apps.includes(row.app_slug)) existing.apps.push(row.app_slug);
    } else {
      patternMap.set(normalized, {
        pattern: normalized,
        sample: row.line.slice(0, 300),
        count: 1,
        first_seen: row.logged_at,
        last_seen: row.logged_at,
        containers: [row.container_name],
        apps: row.app_slug ? [row.app_slug] : [],
      });
    }
  }

  // Sort by count descending
  const patterns = [...patternMap.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 50);

  res.json({ patterns, hours, total_error_lines: errorLines.length });
}));

// GET /api/logs/stats — Log volume stats per container
app.get('/api/logs/stats', asyncRoute(async (req, res) => {
  const stats = db.prepare(`
    SELECT container_name, app_slug, COUNT(*) as line_count,
      MIN(logged_at) as oldest, MAX(logged_at) as newest
    FROM container_logs
    GROUP BY container_name
    ORDER BY line_count DESC
  `).all();

  const total = db.prepare('SELECT COUNT(*) as count FROM container_logs').get().count;

  res.json({ stats, total });
}));

}
