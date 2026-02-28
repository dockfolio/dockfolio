// Pure utility functions — extracted for testability (DRY, KISS, SOLID)
import { createHash } from 'crypto';
import { existsSync, readFileSync } from 'fs';

export function slugify(name) {
  return name.toLowerCase().replace(/\s+/g, '-');
}

export function containerName(c) {
  return c.Names?.[0]?.replace(/^\//, '') || '';
}

export function hashValue(value, length = 16) {
  return createHash('sha256').update(value).digest('hex').slice(0, length);
}

export function todayString() {
  return new Date().toISOString().slice(0, 10);
}

export function percent(used, total) {
  return total > 0 ? Math.round((used / total) * 100) : 0;
}

export function safeJSON(str, fallback = null) {
  if (!str) return fallback;
  try { return JSON.parse(str); } catch { return fallback; }
}

export function letterGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export function maskValue(value) {
  if (!value || value.length <= 12) return '***';
  return value.slice(0, 8) + '...' + value.slice(-4);
}

export function parseEnvFile(filePath) {
  if (!existsSync(filePath)) return [];
  const content = readFileSync(filePath, 'utf8');
  const vars = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx);
    let value = trimmed.slice(eqIdx + 1);
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    vars.push({ key, value });
  }
  return vars;
}

export function serializeEnvVars(vars) {
  return vars.map(v => `${v.key}=${v.value}`).join('\n') + '\n';
}

export function getMarketableApps(apps) {
  return apps.filter(a => a.type === 'saas' || a.type === 'tool');
}

export function getAppsWithEnv(apps) {
  return apps.filter(a => a.envFile && existsSync(a.envFile));
}

// Worry score component calculators (extracted from calculateWorryScore for testability)
export function diskScore(pct) {
  if (pct >= 90) return 15;
  if (pct >= 80) return 10;
  if (pct >= 70) return 5;
  return 0;
}

export function securityScore(score) {
  if (score < 40) return 10;
  if (score < 60) return 7;
  if (score < 75) return 4;
  return 0;
}

export function seoScore(avg) {
  if (avg < 40) return 5;
  if (avg < 60) return 3;
  return 0;
}

// Parse integer route param, returns NaN for invalid
export function parseId(raw) {
  const n = parseInt(raw, 10);
  return isNaN(n) ? NaN : n;
}

// Express async route wrapper — eliminates try/catch boilerplate
export function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(err => {
    console.error(`[${req.method} ${req.path}]`, err.message);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  });
}

// Error fingerprinting — groups same logical error across deployments
export function errorFingerprint(message, stackTrace, appSlug) {
  const normalizedMsg = (message || '')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>') // UUIDs
    .replace(/\b0x[0-9a-f]+\b/gi, '<hex>')     // hex addresses
    .replace(/\b\d{4,}\b/g, '<num>')            // numbers with 4+ digits
    .replace(/\/[^\s/]+\.[a-z]{2,4}:\d+/gi, '<file>') // file paths with line numbers
    .trim();

  // Extract top 3 stack frames, strip absolute paths and line numbers
  let frames = '';
  if (stackTrace) {
    frames = stackTrace
      .split('\n')
      .filter(l => /^\s*at\s/.test(l))
      .slice(0, 3)
      .map(f => f.replace(/\(.*[/\\]/g, '(').replace(/:\d+:\d+\)?$/, ')').trim())
      .join('|');
  }

  const input = `${appSlug || 'unknown'}:${normalizedMsg}:${frames}`;
  return createHash('sha256').update(input).digest('hex').slice(0, 32);
}

// In-memory rate limiter middleware (no external dependency)
export function rateLimit(maxPerWindow = 60, windowMs = 60000) {
  const hits = new Map();
  // Cleanup stale entries every 5 minutes
  setInterval(() => {
    const now = Date.now();
    for (const [key, rec] of hits) if (now > rec.resetAt) hits.delete(key);
  }, 300000).unref();

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    let rec = hits.get(key);
    if (!rec || now > rec.resetAt) {
      rec = { count: 0, resetAt: now + windowMs };
    }
    rec.count++;
    hits.set(key, rec);
    if (rec.count > maxPerWindow) return res.status(429).json({ error: 'Rate limit exceeded' });
    next();
  };
}

// Convert array of objects to CSV string
export function toCsv(rows) {
  if (!rows || rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const escape = v => {
    const s = String(v ?? '');
    return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [headers.join(',')];
  for (const row of rows) lines.push(headers.map(h => escape(row[h])).join(','));
  return lines.join('\n');
}

// Error score for worry score integration
export function errorScore(criticalCount, errorCount) {
  const criticalPoints = Math.min(criticalCount * 5, 10);
  const errorPoints = Math.min(Math.floor(errorCount / 10), 5);
  return Math.min(criticalPoints + errorPoints, 10);
}
