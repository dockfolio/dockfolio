import express from 'express';
import Docker from 'dockerode';
import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdirSync, statSync, readdirSync, unlinkSync } from 'fs';
import yaml from 'js-yaml';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID, createHmac } from 'crypto';
import Database from 'better-sqlite3';
import cron from 'node-cron';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { monitorEventLoopDelay } from 'perf_hooks';
import {
  slugify, containerName, hashValue, todayString, formatDateISO, percent, safeJSON,
  letterGrade, maskValue, parseEnvFile, serializeEnvVars,
  getMarketableApps, getAppsWithEnv, diskScore, securityScore, seoScore,
  parseId, asyncRoute, errorFingerprint, errorScore, rateLimit, toCsv,
  isBot, callAnthropic, htmlEscape
} from './utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const docker = process.env.DOCKER_SOCKET
  ? new Docker({ socketPath: process.env.DOCKER_SOCKET })
  : new Docker({ host: process.env.DOCKER_HOST || 'docker-proxy', port: parseInt(process.env.DOCKER_PORT || '2375') });
const BACKUP_DIR = process.env.BACKUP_DIR || join(process.env.HOME || '/home/deploy', 'backups');

// --- Timeout & Rate Limit Constants (ms) ---
const TIMEOUT_QUICK    = 5_000;     // Health checks, uptime polls (5s)
const TIMEOUT_STANDARD = 10_000;    // Shell commands, API fetches (10s)
const TIMEOUT_MEDIUM   = 15_000;    // Email sends, banner generation (15s)
const TIMEOUT_AI       = 30_000;    // Anthropic API calls (30s)
const TIMEOUT_HEAVY    = 60_000;    // Docker prune, batch operations (60s)
const TIMEOUT_BUILD    = 300_000;   // Git pull + docker build (5min)
const TIMEOUT_SHUTDOWN = 10_000;    // Graceful shutdown deadline (10s)
const TIMEOUT_TLS      = 8_000;    // TLS certificate checks (8s)
const RATE_WINDOW      = 60_000;   // Rate limit window (1min)
const MS_PER_HOUR      = 3_600_000;
const MS_PER_DAY       = 86_400_000;
const STRIPE_API = 'https://api.stripe.com/v1';

// --- Event Loop Lag Monitor ---
const eventLoopHistogram = monitorEventLoopDelay({ resolution: 20 });
eventLoopHistogram.enable();
let eventLoopLagAlertedAt = 0; // dedup: max 1 alert per hour

// Reset histogram every 5 minutes to keep readings fresh
setInterval(() => { eventLoopHistogram.reset(); }, 5 * 60_000);

function getEventLoopMetrics() {
  return {
    min:  Math.round(eventLoopHistogram.min / 1e6 * 100) / 100,
    max:  Math.round(eventLoopHistogram.max / 1e6 * 100) / 100,
    mean: Math.round(eventLoopHistogram.mean / 1e6 * 100) / 100,
    p99:  Math.round(eventLoopHistogram.percentile(99) / 1e6 * 100) / 100,
  };
}

const rlErrorIngest = rateLimit(30, RATE_WINDOW);   // 30 req/min
const rlBannerServe = rateLimit(120, RATE_WINDOW);  // 120 req/min
const rlBannerTrack = rateLimit(60, RATE_WINDOW);   // 60 req/min
const rlPublicRead  = rateLimit(30, RATE_WINDOW);   // 30 req/min

// --- Circuit Breaker ---
function createCircuitBreaker(name, { failThreshold = 3, resetMs = 600000 } = {}) {
  let failures = 0, lastFailure = 0, state = 'closed'; // closed | open | half-open
  return {
    get state() { return state; },
    async call(fn) {
      if (state === 'open') {
        if (Date.now() - lastFailure > resetMs) { state = 'half-open'; }
        else throw new Error(`Circuit breaker '${name}' is open`);
      }
      try {
        const result = await fn();
        if (state === 'half-open') { state = 'closed'; failures = 0; }
        return result;
      } catch (err) {
        failures++;
        lastFailure = Date.now();
        if (failures >= failThreshold) { state = 'open'; console.error(`[CIRCUIT] '${name}' opened after ${failures} failures`); }
        throw err;
      }
    },
  };
}

const cbStripe = createCircuitBreaker('stripe');
const cbPlausible = createCircuitBreaker('plausible');
const cbAnthropic = createCircuitBreaker('anthropic');
const cbGitHub = createCircuitBreaker('github');

// --- Cron Overlap Guard ---
const cronRunning = new Map();
function guardedCron(name, fn) {
  return async () => {
    if (cronRunning.get(name)) { console.log(`[CRON] Skipping '${name}' — previous run still active`); return; }
    cronRunning.set(name, true);
    try { await fn(); } finally { cronRunning.set(name, false); }
  };
}

// --- Shell Helpers ---
function getDiskParts() {
  return execSync('df -B1 / | tail -1', { timeout: TIMEOUT_STANDARD }).toString().trim().split(/\s+/);
}

function getDiskPercent() {
  return parseInt(getDiskParts()[4]);
}

function getLatestFile(dir) {
  return execSync(`ls -t "${dir}" 2>/dev/null | head -1`, { timeout: TIMEOUT_STANDARD }).toString().trim();
}

// Load app config
const configPath = join(__dirname, 'config.yml');
const config = yaml.load(readFileSync(configPath, 'utf8'));

// --- Config Helpers ---
function resolveContainerApp(containerName) {
  const appDef = config.apps?.find(a => (a.containers || [containerName]).some(cn => containerName.includes(cn || slugify(a.name))));
  return appDef ? { appDef, slug: slugify(appDef.name) } : null;
}

function getAuditDomains() {
  return (config.apps || []).filter(a => a.domain && a.type !== 'redirect').map(a => ({ domain: a.domain, slug: slugify(a.name) }));
}

// Cache for container stats (refreshed every 30s)
let cachedStats = null;
let lastStatsUpdate = 0;
const STATS_TTL = 30_000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    }
  }
}));
app.use(express.json({ limit: '1mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(cookieParser());

// --- Request duration ring buffer ---
const PERF_RING_SIZE = 100;
const SLOW_REQUEST_THRESHOLD_MS = 2000;
const perfRing = [];         // last 100 request durations {method, path, durationMs, timestamp}
let perfRingIdx = 0;
const slowRequests = [];     // last 10 slow requests (> 2000ms)

// --- Request logging & tracing ---
app.use((req, res, next) => {
  const requestId = randomUUID();
  req.id = requestId;
  res.setHeader('X-Request-ID', requestId);
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.DEBUG && req.path.startsWith('/api/')) {
      console.log(`[REQ] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
    }
    // Track API request durations in ring buffer
    if (req.path.startsWith('/api/')) {
      const entry = { method: req.method, path: req.path, durationMs: duration, timestamp: new Date().toISOString() };
      if (perfRing.length < PERF_RING_SIZE) {
        perfRing.push(entry);
      } else {
        perfRing[perfRingIdx % PERF_RING_SIZE] = entry;
      }
      perfRingIdx++;
      if (duration > SLOW_REQUEST_THRESHOLD_MS) {
        console.log(`[SLOW] ${req.method} ${req.path} took ${duration}ms`);
        slowRequests.push(entry);
        if (slowRequests.length > 10) slowRequests.shift();
      }
    }
  });
  next();
});

// --- CSRF protection (double-submit cookie) ---
app.use((req, res, next) => {
  // Set CSRF token cookie if not present
  if (!req.cookies._csrf) {
    const csrfToken = randomUUID();
    res.cookie('_csrf', csrfToken, { httpOnly: false, sameSite: 'Strict', secure: process.env.NODE_ENV === 'production' });
  }
  // Validate on state-changing methods (skip public paths and static assets)
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const normalizedPath = req.path.replace(/\/\.\.+/g, '').replace(/\/+/g, '/');
    const CSRF_EXEMPT = ['/api/auth/login', '/api/auth/setup', '/api/banners/', '/api/crosspromo/', '/api/errors/ingest', '/api/errors/envelope', '/api/analytics/', '/api/webhooks/'];
    if (!CSRF_EXEMPT.some(p => normalizedPath.startsWith(p))) {
      const headerToken = req.headers['x-csrf-token'];
      const cookieToken = req.cookies._csrf;
      if (!headerToken || !cookieToken || headerToken !== cookieToken) {
        return res.status(403).json({ error: 'CSRF token mismatch' });
      }
    }
  }
  next();
});

// --- Auth Database (separate from marketing DB, initialized early) ---
const AUTH_DB_PATH = process.env.AUTH_DB_PATH || join(__dirname, 'auth.db');
const authDb = new Database(AUTH_DB_PATH);
authDb.pragma('journal_mode = WAL');
authDb.pragma('busy_timeout = 5000');
authDb.pragma('synchronous = NORMAL');
authDb.pragma('cache_size = -16000');   // 16MB (auth DB is small)
authDb.pragma('temp_store = MEMORY');
authDb.pragma('mmap_io = 67108864');    // 64MB

authDb.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
`);

// Clean expired sessions on startup and every hour
function cleanExpiredSessions() {
  authDb.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
}
cleanExpiredSessions();
setInterval(cleanExpiredSessions, MS_PER_HOUR);

const SESSION_TTL_DAYS = 30;

function createSession(userId) {
  const token = randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * MS_PER_DAY).toISOString();
  authDb.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expiresAt);
  return { token, expiresAt };
}

function getSessionUser(token) {
  if (!token) return null;
  const row = authDb.prepare(`
    SELECT u.id, u.username, u.role FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > datetime('now')
  `).get(token);
  return row || null;
}

function isSetupComplete() {
  const count = authDb.prepare('SELECT COUNT(*) as c FROM users').get();
  return count.c > 0;
}

// --- Auth Middleware ---
const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/setup', '/api/auth/status', '/health', '/api/health', '/api/crosspromo', '/api/banners', '/api/errors/ingest', '/api/errors/envelope', '/api/errors/sdk.js', '/api/status', '/status', '/api/status-page', '/api/analytics/pixel.gif', '/api/analytics/track.js', '/api/analytics/event', '/api/webhooks'];

function authMiddleware(req, res, next) {
  // Normalize path to prevent traversal bypass (e.g. /api/crosspromo/../marketing/crosspromo)
  const normalizedPath = req.path.replace(/\/\.\.+/g, '').replace(/\/+/g, '/');
  // Allow public paths
  if (PUBLIC_PATHS.some(p => normalizedPath === p || normalizedPath.startsWith(p + '/'))) return next();
  // Allow static assets for login page
  if (req.path.match(/\.(css|js|ico|svg|png|jpg|woff2?)$/)) return next();

  const token = req.cookies?.session;
  const user = getSessionUser(token);

  if (!user) {
    // API calls get 401, page requests get redirect
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }

  req.user = user;
  next();
}

app.use(authMiddleware);

// --- Audit Log Middleware ---
const AUDIT_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const AUDIT_SKIP = ['/api/auth/login', '/api/auth/status', '/api/analytics/', '/api/errors/', '/api/banners/'];
let _insertAudit = null;
function getInsertAudit() {
  if (!_insertAudit) {
    // Ensure columns exist (table may predate these columns)
    try { db.exec("ALTER TABLE audit_log ADD COLUMN method TEXT"); } catch { /* already exists */ }
    try { db.exec("ALTER TABLE audit_log ADD COLUMN path TEXT"); } catch { /* already exists */ }
    try { db.exec("ALTER TABLE audit_log ADD COLUMN status INTEGER"); } catch { /* already exists */ }
    try { db.exec("ALTER TABLE audit_log ADD COLUMN detail TEXT"); } catch { /* already exists */ }
    _insertAudit = db.prepare('INSERT INTO audit_log (user, action, method, path, status, ip, detail) VALUES (?, ?, ?, ?, ?, ?, ?)');
  }
  return _insertAudit;
}

app.use((req, res, next) => {
  if (!AUDIT_METHODS.has(req.method)) return next();
  if (AUDIT_SKIP.some(p => req.path.startsWith(p))) return next();

  const originalEnd = res.end;
  res.end = function (...args) {
    try {
      const user = req.user?.username || 'anonymous';
      const ip = req.ip || req.connection?.remoteAddress || '';
      const detail = req.body ? JSON.stringify(req.body).slice(0, 500) : null;
      const action = `${req.method} ${req.path}`;
      getInsertAudit().run(user, action, req.method, req.path, res.statusCode, ip, detail);
    } catch { /* best-effort */ }
    originalEnd.apply(res, args);
  };
  next();
});

// --- Demo Mode ---
const DEMO_MODE = process.env.DEMO_MODE === 'true';
const DEMO_ALLOW_WRITES = ['/api/auth/', '/api/errors/', '/api/analytics/', '/api/banners/', '/api/crosspromo/', '/api/webhooks/'];
if (DEMO_MODE) {
  app.use((req, res, next) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      if (DEMO_ALLOW_WRITES.some(p => req.path.startsWith(p))) return next();
      return res.status(403).json({ error: 'Demo mode is read-only. Deploy your own instance to make changes.' });
    }
    next();
  });
}

// --- Login Page ---
app.get('/login', (_req, res) => {
  const setup = !isSetupComplete();
  res.send(loginPageHTML(setup));
});

// --- Rate Limiting (auth endpoints) ---
const loginAttempts = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW = 15 * 60_000; // 15 minutes

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }
  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) return false;
  return true;
}

// Clean rate limit map every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now > entry.resetAt) loginAttempts.delete(ip);
  }
}, 30 * 60_000);

// --- Demo Mode: auto-create demo user ---
if (DEMO_MODE && isSetupComplete() === false) {
  const hash = bcrypt.hashSync('demo1234', 12);
  authDb.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run('demo', hash, 'admin');
  console.log('[demo] Created demo user (demo / demo1234)');
}

// --- Auth API ---
app.get('/api/auth/status', (_req, res) => {
  res.json({ setupComplete: isSetupComplete(), demoMode: DEMO_MODE });
});

app.post('/api/auth/setup', asyncRoute(async (req, res) => {
  if (isSetupComplete()) {
    return res.status(400).json({ error: 'Setup already completed' });
  }
  const clientIp = req.ip || req.socket.remoteAddress;
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  const { username, password } = req.body;
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'Username required, password must be 8+ characters' });
  }
  const hash = bcrypt.hashSync(password, 12);
  const result = authDb.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(username.trim(), hash, 'admin');
  const session = createSession(result.lastInsertRowid);
  res.cookie('session', session.token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: SESSION_TTL_DAYS * MS_PER_DAY });
  res.json({ ok: true });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const clientIp = req.ip || req.socket.remoteAddress;
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
  }
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  const user = authDb.prepare('SELECT id, username, password_hash FROM users WHERE username = ?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const session = createSession(user.id);
  res.cookie('session', session.token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: SESSION_TTL_DAYS * MS_PER_DAY });
  res.json({ ok: true, username: user.username });
}));

app.post('/api/auth/logout', asyncRoute(async (req, res) => {
  const token = req.cookies?.session;
  if (token) {
    authDb.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  res.clearCookie('session');
  res.json({ ok: true });
}));

app.get('/api/auth/me', (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// --- Login/Setup Page HTML ---
function loginPageHTML(isSetup) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dockfolio ${isSetup ? 'Setup' : 'Login'}</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%230a0a0f'/><circle cx='30' cy='35' r='8' fill='%2322c55e'/><circle cx='70' cy='35' r='8' fill='%2322c55e'/><circle cx='50' cy='65' r='8' fill='%233b82f6'/><line x1='30' y1='43' x2='50' y2='57' stroke='%232a2a3a' stroke-width='3'/><line x1='70' y1='43' x2='50' y2='57' stroke='%232a2a3a' stroke-width='3'/></svg>">
  <style>
    :root { --bg: #0a0a0f; --surface: #12121a; --surface2: #1a1a25; --border: #2a2a3a; --text: #e4e4ed; --text-dim: #8888a0; --green: #22c55e; --red: #ef4444; --blue: #3b82f6; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .login-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 40px; width: 380px; }
    .login-card h1 { font-size: 20px; font-weight: 600; margin-bottom: 4px; }
    .login-card .subtitle { color: var(--text-dim); font-size: 13px; margin-bottom: 28px; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 12px; color: var(--text-dim); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em; }
    .form-group input { width: 100%; padding: 10px 12px; background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 14px; outline: none; transition: border-color 0.15s; }
    .form-group input:focus { border-color: var(--blue); }
    .btn { width: 100%; padding: 10px; background: var(--green); color: #000; font-size: 14px; font-weight: 600; border: none; border-radius: 6px; cursor: pointer; transition: opacity 0.15s; margin-top: 8px; }
    .btn:hover { opacity: 0.9; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .error { color: var(--red); font-size: 12px; margin-top: 12px; display: none; }
    .logo { text-align: center; margin-bottom: 24px; font-size: 32px; }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">${isSetup ? '&#x1f6e0;' : '&#x1f512;'}</div>
    <h1>${isSetup ? 'Create Admin Account' : 'Sign In'}</h1>
    <p class="subtitle">${isSetup ? 'Set up your Dockfolio admin account' : 'Sign in to your Dockfolio dashboard'}</p>
    <form id="authForm" onsubmit="return handleAuth(event)">
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="username" name="username" required autocomplete="username" autofocus>
      </div>
      <div class="form-group">
        <label>Password${isSetup ? ' (8+ characters)' : ''}</label>
        <input type="password" id="password" name="password" required autocomplete="${isSetup ? 'new-password' : 'current-password'}" minlength="${isSetup ? 8 : 1}">
      </div>
      <button type="submit" class="btn" id="submitBtn">${isSetup ? 'Create Account' : 'Sign In'}</button>
      <div class="error" id="errorMsg"></div>
    </form>
  </div>
  <script>
    const isSetup = ${isSetup};
    async function handleAuth(e) {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      const errEl = document.getElementById('errorMsg');
      btn.disabled = true;
      errEl.style.display = 'none';
      try {
        const res = await fetch(isSetup ? '/api/auth/setup' : '/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
          })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed');
        window.location.href = '/';
      } catch (err) {
        errEl.textContent = err.message;
        errEl.style.display = 'block';
        btn.disabled = false;
      }
    }
  </script>
</body>
</html>`;
}

app.use(express.static(join(__dirname, 'public')));

// --- Env file utilities ---
const SENSITIVE_PATTERN = /SECRET|KEY|TOKEN|PASSWORD|PRIVATE|DSN|ROLE/i;

function findAppBySlug(slug) {
  return config.apps.find(a => slugify(a.name) === slug);
}

// === Maintenance Mode ===
// In-memory Map: slug -> { enabled, reason, duration, startedAt, expiresAt }
const maintenanceMode = new Map();

function loadMaintenanceState() {
  try {
    const raw = getSetting('maintenance_mode');
    if (raw) {
      const parsed = JSON.parse(raw);
      for (const [slug, state] of Object.entries(parsed)) {
        if (state.enabled) {
          // Check if expired
          if (state.expiresAt && Date.now() > state.expiresAt) continue;
          maintenanceMode.set(slug, state);
        }
      }
    }
  } catch { /* silent — first boot or corrupt data */ }
}

function persistMaintenanceState() {
  const obj = Object.fromEntries(maintenanceMode);
  upsertSettingStmt.run('maintenance_mode', JSON.stringify(obj));
}

function isInMaintenance(slug) {
  const state = maintenanceMode.get(slug);
  if (!state || !state.enabled) return false;
  // Auto-expire if duration elapsed
  if (state.expiresAt && Date.now() > state.expiresAt) {
    maintenanceMode.delete(slug);
    persistMaintenanceState();
    console.log(`[MAINTENANCE] Auto-expired maintenance mode for ${slug}`);
    return false;
  }
  return true;
}

function setMaintenance(slug, enabled, reason, durationMinutes) {
  if (enabled) {
    const now = Date.now();
    const expiresAt = durationMinutes ? now + durationMinutes * 60 * 1000 : null;
    maintenanceMode.set(slug, { enabled: true, reason: reason || '', duration: durationMinutes || null, startedAt: now, expiresAt });
  } else {
    maintenanceMode.delete(slug);
  }
  persistMaintenanceState();
}

function isInMaintenanceWindow(appSlug) {
  const now = new Date();
  const dayOfWeek = now.getUTCDay(); // 0=Sunday
  const minutesSinceMidnight = now.getUTCHours() * 60 + now.getUTCMinutes();
  const windows = db.prepare('SELECT * FROM maintenance_windows WHERE app_slug = ?').all(appSlug);
  for (const w of windows) {
    if (w.day_of_week !== dayOfWeek) continue;
    const windowStart = w.start_hour * 60 + w.start_minute;
    const windowEnd = windowStart + w.duration_minutes;
    if (minutesSinceMidnight >= windowStart && minutesSinceMidnight < windowEnd) {
      return { inMaintenance: true, window: w };
    }
  }
  return { inMaintenance: false, window: null };
}

function getBannerForgeUrl() {
  const dbVal = getSetting('BANNERFORGE_URL');
  if (dbVal) return dbVal;
  if (process.env.BANNERFORGE_URL) return process.env.BANNERFORGE_URL;
  const bf = config.apps.find(a => slugify(a.name) === 'bannerforge');
  if (bf?.port) return `http://localhost:${bf.port}/api/render`;
  return null;
}

// --- Shared helpers (config-dependent, not in utils.js) ---

function setCORS(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function addNotification(category, severity, title, message, appSlug) {
  try {
    db.prepare(
      'INSERT INTO notifications (category, severity, title, message, app_slug) VALUES (?, ?, ?, ?, ?)'
    ).run(category, severity, (title || '').slice(0, 500), (message || '').slice(0, 2000), appSlug || null);
  } catch (err) {
    console.error('[NOTIFY] Failed to insert notification:', err.message);
  }
}

function parseNotificationFromTelegram(msg) {
  const plain = msg.replace(/<[^>]+>/g, ''); // strip HTML tags
  const lines = plain.split('\n').filter(l => l.trim());
  const title = (lines[0] || 'Alert').slice(0, 500);
  const message = lines.slice(1).join('\n').slice(0, 2000) || null;
  const lower = plain.toLowerCase();

  let category = 'system';
  if (/heal|auto-heal/i.test(lower)) category = 'healing';
  else if (/error|spike|bug|recurring critical/i.test(lower)) category = 'error';
  else if (/ssl|certificate/i.test(lower)) category = 'ssl';
  else if (/backup|stale backup/i.test(lower)) category = 'backup';
  else if (/security|drift/i.test(lower)) category = 'security';
  else if (/predict|forecast/i.test(lower)) category = 'prediction';
  else if (/deploy/i.test(lower)) category = 'deploy';
  else if (/down|degraded|up.*back/i.test(lower)) category = 'system';
  else if (/cron|event loop|lag/i.test(lower)) category = 'system';
  else if (/key rotation|rotation/i.test(lower)) category = 'security';
  else if (/overdue|reminder|task/i.test(lower)) category = 'system';

  let severity = 'info';
  if (/critical|down|failed|spike|overdue/i.test(lower)) severity = 'critical';
  else if (/warning|degraded|expir|stale|needs approval|drift/i.test(lower)) severity = 'warning';

  // Try to extract app slug from message
  let appSlug = null;
  const appMatch = plain.match(/App:\s*(\S+)/i) || plain.match(/(?:New \w+|Reopened|Recurring critical):\s*(\S+)/);
  if (appMatch) appSlug = appMatch[1];

  return { category, severity, title, message, appSlug };
}

async function sendTelegram(message) {
  const token = getSetting('TELEGRAM_BOT_TOKEN') || process.env.TELEGRAM_BOT_TOKEN;
  const chatId = getSetting('TELEGRAM_CHAT_ID') || process.env.TELEGRAM_CHAT_ID;

  // Always add to notification center, even if Telegram is not configured
  let parsedSlug = null;
  try {
    const parsed = parseNotificationFromTelegram(message);
    parsedSlug = parsed.appSlug;
    addNotification(parsed.category, parsed.severity, parsed.title, parsed.message, parsed.appSlug);
  } catch { /* silent */ }

  // Suppress Telegram alert if the app is in maintenance mode (notification is still stored above)
  if (parsedSlug && isInMaintenance(parsedSlug)) return;

  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' }),
      signal: AbortSignal.timeout(TIMEOUT_QUICK)
    });
  } catch { /* silent — Telegram is best-effort */ }
}

// Rate-limited cron failure alerter (max 1 alert per cron per hour)
const cronFailAlerted = new Map(); // cronName -> timestamp
function cronFail(cronName, err) {
  console.error(`[CRON] ${cronName} error:`, err.message || err);
  const now = Date.now();
  const last = cronFailAlerted.get(cronName) || 0;
  if (now - last > MS_PER_HOUR) {
    cronFailAlerted.set(cronName, now);
    sendTelegram(`⚠️ Cron failed: ${cronName}\n${(err.message || String(err)).slice(0, 200)}`);
  }
}


// GET /api/apps — all apps with their container status
app.get('/api/apps', asyncRoute(async (_req, res) => {
  const containers = await docker.listContainers({ all: true });
  const containerMap = new Map();
  for (const c of containers) {
    const name = containerName(c);
    if (name) containerMap.set(name, c);
  }

  const apps = config.apps.map(appDef => {
    const containerStatuses = (appDef.containers || []).map(name => {
      const c = containerMap.get(name);
      if (!c) return { name, status: 'not_found', health: 'unknown' };
      const health = c.Status?.includes('healthy') ? 'healthy'
        : c.Status?.includes('unhealthy') ? 'unhealthy'
        : c.Status?.includes('Restarting') ? 'restarting'
        : c.State === 'running' ? 'running'
        : 'stopped';
      return {
        name,
        status: c.State,
        health,
        image: c.Image,
        uptime: c.Status,
        ports: c.Ports?.map(p => p.PublicPort).filter(Boolean),
      };
    });

    const overallHealth = containerStatuses.length === 0
      ? 'static'
      : containerStatuses.every(c => c.health === 'healthy') ? 'healthy'
      : containerStatuses.some(c => c.health === 'restarting') ? 'restarting'
      : containerStatuses.some(c => c.health === 'unhealthy') ? 'unhealthy'
      : containerStatuses.every(c => c.status === 'running' || c.health === 'running') ? 'running'
      : 'degraded';

    // Check for Sentry DSN in env file
    let hasSentry = false;
    let hasEnvFile = !!appDef.envFile;
    if (appDef.envFile && existsSync(appDef.envFile)) {
      const envVars = parseEnvFile(appDef.envFile);
      const sentryVar = envVars.find(v => v.key === 'SENTRY_DSN' || v.key === 'NEXT_PUBLIC_SENTRY_DSN');
      hasSentry = !!(sentryVar && sentryVar.value);
    }

    const appSlug = appDef.slug || slugify(appDef.name);
    const maintenance = isInMaintenance(appSlug) ? maintenanceMode.get(appSlug) : null;

    return {
      ...appDef,
      containerStatuses,
      overallHealth,
      hasSentry,
      hasEnvFile,
      maintenance: maintenance || null,
    };
  });

  res.json(apps);
}));

// GET /api/system — system metrics
app.get('/api/system', asyncRoute(async (_req, res) => {
  const meminfo = readFileSync('/proc/meminfo', 'utf8');
  const parse = key => {
    const match = meminfo.match(new RegExp(`${key}:\\s+(\\d+)`));
    return match ? parseInt(match[1], 10) : 0;
  };

  const memTotal = parse('MemTotal');
  const memAvailable = parse('MemAvailable');
  const swapTotal = parse('SwapTotal');
  const swapFree = parse('SwapFree');

  // Disk usage
  const dfParts = getDiskParts();
  const diskTotal = parseInt(dfParts[1], 10);
  const diskUsed = parseInt(dfParts[2], 10);

  // Load average
  const loadavg = readFileSync('/proc/loadavg', 'utf8').split(' ');
  const cpuCount = parseInt(execSync('nproc', { timeout: TIMEOUT_QUICK }).toString().trim(), 10);

  // Uptime
  const uptimeRaw = readFileSync('/proc/uptime', 'utf8').split(' ')[0];
  const uptimeSeconds = parseFloat(uptimeRaw);

  res.json({
    memory: {
      total: memTotal * 1024,
      available: memAvailable * 1024,
      used: (memTotal - memAvailable) * 1024,
      percent: Math.round(((memTotal - memAvailable) / memTotal) * 100),
    },
    swap: {
      total: swapTotal * 1024,
      used: (swapTotal - swapFree) * 1024,
      percent: swapTotal > 0 ? Math.round(((swapTotal - swapFree) / swapTotal) * 100) : 0,
    },
    disk: {
      total: diskTotal,
      used: diskUsed,
      percent: Math.round((diskUsed / diskTotal) * 100),
    },
    load: {
      avg1: parseFloat(loadavg[0]),
      avg5: parseFloat(loadavg[1]),
      avg15: parseFloat(loadavg[2]),
      cpuCount,
    },
    uptime: uptimeSeconds,
    eventLoop: getEventLoopMetrics(),
  });
}));

// GET /api/containers/stats — container resource usage
app.get('/api/containers/stats', asyncRoute(async (_req, res) => {
  const now = Date.now();
  if (cachedStats && (now - lastStatsUpdate) < STATS_TTL) {
    return res.json(cachedStats);
  }

  const containers = await docker.listContainers();
  const stats = {};

  await Promise.all(containers.map(async (c) => {
    const name = containerName(c);
    try {
      const container = docker.getContainer(c.Id);
      const s = await container.stats({ stream: false });
      const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
      const systemDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
      const cpuCount = s.cpu_stats.online_cpus || 1;
      const cpuPercent = systemDelta > 0 ? (cpuDelta / systemDelta) * cpuCount * 100 : 0;

      stats[name] = {
        cpu: Math.round(cpuPercent * 100) / 100,
        memory: s.memory_stats.usage || 0,
        memoryLimit: s.memory_stats.limit || 0,
        netRx: s.networks ? Object.values(s.networks).reduce((sum, n) => sum + n.rx_bytes, 0) : 0,
        netTx: s.networks ? Object.values(s.networks).reduce((sum, n) => sum + n.tx_bytes, 0) : 0,
      };
    } catch {
      stats[name] = { cpu: 0, memory: 0, memoryLimit: 0, netRx: 0, netTx: 0 };
    }
  }));

  cachedStats = stats;
  lastStatsUpdate = now;
  res.json(stats);
}));

// GET /api/containers/graph — container dependency graph by shared Docker networks
let cachedGraph = null;
let lastGraphUpdate = 0;
const GRAPH_TTL = 300_000; // 5 minutes

app.get('/api/containers/graph', asyncRoute(async (_req, res) => {
  const now = Date.now();
  if (cachedGraph && (now - lastGraphUpdate) < GRAPH_TTL) {
    return res.json(cachedGraph);
  }

  const containers = await docker.listContainers({ all: true });
  const networkMap = {}; // networkName -> [containerInfo]
  const nodes = [];

  for (const c of containers.slice(0, 50)) {
    const name = containerName(c);
    const networks = Object.keys(c.NetworkSettings?.Networks || {});
    const slug = (config.apps || []).find(a =>
      (a.containers || []).some(cn => name.includes(cn))
    );
    const appSlug = slug ? slugify(slug.name) : null;

    nodes.push({
      id: name,
      app: appSlug,
      status: c.State || 'unknown',
      networks,
    });

    for (const net of networks) {
      if (!networkMap[net]) networkMap[net] = [];
      networkMap[net].push(name);
    }
  }

  const edgeSet = new Set();
  const edges = [];
  for (const [net, members] of Object.entries(networkMap)) {
    for (let i = 0; i < members.length; i++) {
      for (let j = i + 1; j < members.length; j++) {
        const key = [members[i], members[j]].sort().join('|||') + '|||' + net;
        if (!edgeSet.has(key)) {
          edgeSet.add(key);
          edges.push({ source: members[i], target: members[j], network: net });
        }
      }
    }
  }

  cachedGraph = {
    nodes,
    edges,
    networks: Object.keys(networkMap),
    timestamp: new Date().toISOString(),
  };
  lastGraphUpdate = now;
  res.json(cachedGraph);
}));

// GET /api/containers/:name/logs — last N lines of container logs
app.get('/api/containers/:name/logs', asyncRoute(async (req, res) => {
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === req.params.name);
  if (!target) return res.status(404).json({ error: 'Container not found' });

  const container = docker.getContainer(target.Id);
  const logs = await container.logs({
    stdout: true,
    stderr: true,
    tail: Math.min(parseInt(req.query.lines) || 100, 5000),
    timestamps: true,
  });

  // Strip Docker stream headers (8-byte prefix per line)
  const clean = logs.toString('utf8')
    .split('\n')
    .map(line => line.length > 8 ? line.slice(8) : line)
    .join('\n');

  res.type('text/plain').send(clean);
}));

// GET /api/docker/overview — Docker disk usage summary
app.get('/api/docker/overview', asyncRoute(async (_req, res) => {
  const [imagesResult, containersResult, volumesResult] = await Promise.allSettled([
    docker.listImages(),
    docker.listContainers({ all: true }),
    docker.listVolumes(),
  ]);

  const images = imagesResult.status === 'fulfilled' ? imagesResult.value : [];
  const containers = containersResult.status === 'fulfilled' ? containersResult.value : [];
  const volumes = volumesResult.status === 'fulfilled' ? volumesResult.value : { Volumes: [] };

  if (imagesResult.status === 'rejected') console.error('[DOCKER] listImages failed:', imagesResult.reason?.message);
  if (containersResult.status === 'rejected') console.error('[DOCKER] listContainers failed:', containersResult.reason?.message);
  if (volumesResult.status === 'rejected') console.error('[DOCKER] listVolumes failed:', volumesResult.reason?.message);

  const imageList = images.map(i => ({
    id: i.Id?.slice(7, 19),
    tags: i.RepoTags || [],
    size: i.Size,
    created: i.Created,
  })).sort((a, b) => b.size - a.size);

  const totalImageSize = images.reduce((s, i) => s + i.Size, 0);

  res.json({
    images: { count: images.length, totalSize: totalImageSize, list: imageList },
    containers: { count: containers.length, running: containers.filter(c => c.State === 'running').length },
    volumes: { count: volumes.Volumes?.length || 0 },
  });
}));

// === Feature: Docker Image Update Checker ===
let cachedImageUpdates = null;
let lastImageUpdatesCheck = 0;
const IMAGE_UPDATES_TTL = 6 * MS_PER_HOUR; // 6 hours

async function checkImageUpdates() {
  const containers = await docker.listContainers();
  const images = [];
  const summary = { total: 0, upToDate: 0, updatesAvailable: 0, skipped: 0, error: 0 };

  // Collect unique image references from running containers
  const imageMap = new Map(); // image ref -> [container names]
  for (const c of containers) {
    const name = containerName(c);
    const image = c.Image || '';
    if (!imageMap.has(image)) imageMap.set(image, []);
    imageMap.get(image).push(name);
  }

  // Rate limit: process max 10 at a time
  const entries = [...imageMap.entries()];
  for (let i = 0; i < entries.length; i += 10) {
    const batch = entries.slice(i, i + 10);
    const results = await Promise.allSettled(batch.map(async ([imageRef, containerNames]) => {
      // Parse image reference into registry, name, tag
      const parsed = parseImageRef(imageRef);

      // Skip private/non-Hub registries
      if (parsed.registry && parsed.registry !== 'docker.io' && parsed.registry !== 'registry.hub.docker.com') {
        for (const cn of containerNames) {
          images.push({ container: cn, image: imageRef, status: 'skipped', reason: 'private registry' });
          summary.skipped++;
          summary.total++;
        }
        return;
      }

      // Skip images without a real tag (only SHA digest)
      if (!parsed.tag || parsed.tag.startsWith('sha256:')) {
        for (const cn of containerNames) {
          images.push({ container: cn, image: imageRef, status: 'skipped', reason: 'no tag (digest only)' });
          summary.skipped++;
          summary.total++;
        }
        return;
      }

      // Get local image digest
      let localDigest = '';
      try {
        const inspectData = await docker.getImage(imageRef).inspect();
        // RepoDigests contains the pullable digest e.g. ["redis@sha256:abc..."]
        const repoDigest = (inspectData.RepoDigests || []).find(d => d.includes('@sha256:'));
        if (repoDigest) {
          localDigest = repoDigest.split('@')[1] || '';
        }
      } catch (_e) {
        // image inspect failed
      }

      // Check Docker Hub for remote digest
      let remoteDigest = '';
      let hasUpdate = false;
      let status = 'up_to_date';

      try {
        const hubPath = parsed.isOfficial
          ? `library/${parsed.name}`
          : `${parsed.owner}/${parsed.name}`;

        // Get auth token (Docker Hub requires token even for public images on v2 manifest)
        const tokenUrl = `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${hubPath}:pull`;
        const tokenController = new AbortController();
        const tokenTimeout = setTimeout(() => tokenController.abort(), TIMEOUT_STANDARD);
        const tokenRes = await fetch(tokenUrl, { signal: tokenController.signal });
        clearTimeout(tokenTimeout);
        const tokenData = await tokenRes.json();
        const token = tokenData.token;

        if (token) {
          const manifestUrl = `https://registry-1.docker.io/v2/${hubPath}/manifests/${parsed.tag}`;
          const manifestController = new AbortController();
          const manifestTimeout = setTimeout(() => manifestController.abort(), TIMEOUT_STANDARD);
          const manifestRes = await fetch(manifestUrl, {
            headers: {
              'Accept': 'application/vnd.docker.distribution.manifest.v2+json',
              'Authorization': `Bearer ${token}`,
            },
            signal: manifestController.signal,
          });
          clearTimeout(manifestTimeout);

          if (manifestRes.ok) {
            // Docker-Content-Digest header contains the manifest digest
            remoteDigest = manifestRes.headers.get('docker-content-digest') || '';
          }
        }
      } catch (_e) {
        // Registry check failed — mark as error
      }

      if (!remoteDigest) {
        status = 'check_failed';
        for (const cn of containerNames) {
          images.push({ container: cn, image: imageRef, currentDigest: localDigest, status, reason: 'registry check failed' });
          summary.error++;
          summary.total++;
        }
        return;
      }

      if (localDigest && remoteDigest && localDigest !== remoteDigest) {
        hasUpdate = true;
        status = 'update_available';
      } else if (localDigest && remoteDigest && localDigest === remoteDigest) {
        hasUpdate = false;
        status = 'up_to_date';
      } else {
        // No local digest to compare
        status = 'unknown';
      }

      for (const cn of containerNames) {
        images.push({ container: cn, image: imageRef, currentDigest: localDigest, remoteDigest, hasUpdate, status });
        if (status === 'update_available') summary.updatesAvailable++;
        else if (status === 'up_to_date') summary.upToDate++;
        else summary.skipped++;
        summary.total++;
      }
    }));

    // Log errors from batch
    for (const r of results) {
      if (r.status === 'rejected') {
        console.error('[IMAGE-UPDATES] Batch error:', r.reason?.message);
      }
    }
  }

  // Sort: updates first, then up_to_date, then skipped/error
  const statusOrder = { update_available: 0, unknown: 1, check_failed: 2, up_to_date: 3, skipped: 4 };
  images.sort((a, b) => (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9));

  return { images, summary, checkedAt: new Date().toISOString() };
}

function parseImageRef(ref) {
  // Remove sha256 digests appended with @
  const cleanRef = ref.split('@')[0];
  let registry = '';
  let owner = '';
  let name = '';
  let tag = 'latest';

  const parts = cleanRef.split('/');

  if (parts.length === 1) {
    // e.g. "redis:7-alpine" — official Docker Hub image
    const [n, t] = parts[0].split(':');
    name = n;
    tag = t || 'latest';
    return { registry: 'docker.io', owner: 'library', name, tag, isOfficial: true };
  }

  if (parts.length === 2) {
    // Could be "owner/image:tag" (Docker Hub) or "registry/image:tag"
    if (parts[0].includes('.') || parts[0].includes(':')) {
      // It's a registry like ghcr.io
      registry = parts[0];
      const [n, t] = parts[1].split(':');
      name = n;
      tag = t || 'latest';
      return { registry, owner: '', name, tag, isOfficial: false };
    }
    // Docker Hub user image
    owner = parts[0];
    const [n, t] = parts[1].split(':');
    name = n;
    tag = t || 'latest';
    return { registry: 'docker.io', owner, name, tag, isOfficial: false };
  }

  if (parts.length >= 3) {
    // e.g. "ghcr.io/user/app:tag"
    registry = parts[0];
    owner = parts.slice(1, -1).join('/');
    const [n, t] = parts[parts.length - 1].split(':');
    name = n;
    tag = t || 'latest';
    return { registry, owner, name, tag, isOfficial: false };
  }

  return { registry, owner, name: ref, tag, isOfficial: false };
}

// GET /api/images/updates — check for Docker image updates
app.get('/api/images/updates', asyncRoute(async (req, res) => {
  const force = req.query.force === 'true';
  const now = Date.now();

  if (!force && cachedImageUpdates && (now - lastImageUpdatesCheck) < IMAGE_UPDATES_TTL) {
    return res.json(cachedImageUpdates);
  }

  const result = await checkImageUpdates();
  cachedImageUpdates = result;
  lastImageUpdatesCheck = now;
  res.json(result);
}));

// POST /api/containers/:name/diagnose — run diagnostic checks on a container
app.post('/api/containers/:name/diagnose', asyncRoute(async (req, res) => {
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === req.params.name);
  if (!target) return res.status(404).json({ error: 'Container not found' });

  const container = docker.getContainer(target.Id);
  const report = { container: req.params.name, status: target.State };

  // Run all diagnostic checks in parallel
  const [inspectResult, statsResult, topResult, logsResult] = await Promise.allSettled([
    container.inspect(),
    target.State === 'running' ? container.stats({ stream: false }) : Promise.reject(new Error('not running')),
    target.State === 'running' ? container.top() : Promise.reject(new Error('not running')),
    container.logs({ stdout: true, stderr: true, tail: 50, timestamps: true }),
  ]);

  // Uptime from container start time
  if (inspectResult.status === 'fulfilled') {
    const info = inspectResult.value;
    const startedAt = info.State?.StartedAt;
    if (startedAt) {
      const ms = Date.now() - new Date(startedAt).getTime();
      const days = Math.floor(ms / 86400000);
      const hours = Math.floor((ms % 86400000) / 3600000);
      const mins = Math.floor((ms % 3600000) / 60000);
      report.uptime = days > 0 ? `${days}d ${hours}h ${mins}m` : hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
    }
    // Config summary
    report.config = {
      image: info.Config?.Image || info.Image || '',
      created: info.Created,
      restartPolicy: info.HostConfig?.RestartPolicy?.Name || 'none',
      mounts: (info.Mounts || []).map(m => ({ type: m.Type, source: m.Source, destination: m.Destination, mode: m.Mode })),
      ports: Object.entries(info.HostConfig?.PortBindings || {}).map(([container, bindings]) => ({
        container,
        host: (bindings || []).map(b => b.HostPort).join(', '),
      })),
      env: (info.Config?.Env || []).map(e => {
        const [key] = e.split('=', 1);
        return SENSITIVE_PATTERN.test(key) ? `${key}=***` : e;
      }),
    };
    // Health check info
    const health = info.State?.Health;
    if (health) {
      const lastLog = health.Log?.length ? health.Log[health.Log.length - 1] : null;
      report.healthCheck = {
        status: health.Status,
        failingStreak: health.FailingStreak || 0,
        lastCheck: lastLog?.End || null,
        exitCode: lastLog?.ExitCode ?? null,
        output: lastLog?.Output ? lastLog.Output.trim().slice(0, 500) : null,
      };
    }
  }

  // Stats snapshot
  if (statsResult.status === 'fulfilled') {
    const s = statsResult.value;
    const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
    const systemDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
    const cpuCount = s.cpu_stats.online_cpus || 1;
    const cpuPercent = systemDelta > 0 ? (cpuDelta / systemDelta) * cpuCount * 100 : 0;
    const memUsage = s.memory_stats.usage || 0;
    const memLimit = s.memory_stats.limit || 0;
    const netRx = s.networks ? Object.values(s.networks).reduce((sum, n) => sum + n.rx_bytes, 0) : 0;
    const netTx = s.networks ? Object.values(s.networks).reduce((sum, n) => sum + n.tx_bytes, 0) : 0;
    const blkRead = s.blkio_stats?.io_service_bytes_recursive?.find(e => e.op === 'read')?.value || 0;
    const blkWrite = s.blkio_stats?.io_service_bytes_recursive?.find(e => e.op === 'write')?.value || 0;

    report.resources = {
      cpuPercent: Math.round(cpuPercent * 100) / 100,
      memoryBytes: memUsage,
      memoryLimitBytes: memLimit,
      memoryPercent: memLimit > 0 ? Math.round((memUsage / memLimit) * 10000) / 100 : 0,
      netRxBytes: netRx,
      netTxBytes: netTx,
      blockReadBytes: blkRead,
      blockWriteBytes: blkWrite,
      cpuCount,
    };
  }

  // Process list
  if (topResult.status === 'fulfilled') {
    const top = topResult.value;
    const titles = top.Titles || [];
    report.processes = (top.Processes || []).map(row => {
      const proc = {};
      titles.forEach((t, i) => { proc[t] = row[i]; });
      return proc;
    });
  }

  // Recent logs
  if (logsResult.status === 'fulfilled') {
    const raw = logsResult.value.toString('utf8');
    report.recentLogs = raw.split('\n')
      .map(line => line.length > 8 ? line.slice(8) : line)
      .filter(line => line.trim());
  }

  auditLog(req, 'container.diagnose', req.params.name);
  res.json(report);
}));

// POST /api/containers/:name/restart — restart a container
app.post('/api/containers/:name/restart', asyncRoute(async (req, res) => {
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === req.params.name);
  if (!target) return res.status(404).json({ error: 'Container not found' });

  const container = docker.getContainer(target.Id);
  await container.restart({ t: 10 });
  auditLog(req, 'container.restart', req.params.name);
  res.json({ ok: true, message: `Container ${req.params.name} restarted` });
}));

// POST /api/apps/:slug/restart — restart all containers for an app
app.post('/api/apps/:slug/restart', asyncRoute(async (req, res) => {
  const appDef = config.apps.find(a => (a.slug || slugify(a.name)) === req.params.slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });
  if (!appDef.containers?.length) return res.status(400).json({ error: 'No containers configured for this app' });

  const containers = await docker.listContainers({ all: true });
  const results = [];
  for (const cn of appDef.containers) {
    const target = containers.find(c => containerName(c) === cn);
    if (!target) { results.push({ container: cn, status: 'not_found' }); continue; }
    try {
      await docker.getContainer(target.Id).restart({ t: 10 });
      results.push({ container: cn, status: 'restarted' });
    } catch (err) { results.push({ container: cn, status: 'failed', error: err.message }); }
  }
  auditLog(req, 'app.restart', req.params.slug);
  res.json({ ok: true, app: req.params.slug, results });
}));

// POST /api/apps/:slug/maintenance — toggle maintenance mode
app.post('/api/apps/:slug/maintenance', asyncRoute((req, res) => {
  const appDef = config.apps.find(a => (a.slug || slugify(a.name)) === req.params.slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });
  const { enabled, reason, duration } = req.body;
  setMaintenance(req.params.slug, !!enabled, reason || '', duration || null);
  auditLog(req, 'app.maintenance', req.params.slug, { enabled: !!enabled, reason, duration });
  console.log(`[MAINTENANCE] ${enabled ? 'Enabled' : 'Disabled'} maintenance mode for ${req.params.slug}${reason ? ` — ${reason}` : ''}${duration ? ` (${duration}m)` : ''}`);
  res.json({ ok: true, slug: req.params.slug, maintenance: maintenanceMode.get(req.params.slug) || { enabled: false } });
}));

// GET /api/apps/:slug/maintenance — check maintenance status for an app
app.get('/api/apps/:slug/maintenance', asyncRoute((req, res) => {
  const appDef = config.apps.find(a => (a.slug || slugify(a.name)) === req.params.slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });
  const state = maintenanceMode.get(req.params.slug);
  res.json(state && isInMaintenance(req.params.slug) ? state : { enabled: false });
}));

// GET /api/maintenance — list all apps in maintenance mode
app.get('/api/maintenance', asyncRoute((_req, res) => {
  const result = {};
  for (const [slug, state] of maintenanceMode) {
    if (isInMaintenance(slug)) {
      result[slug] = state;
    }
  }
  res.json(result);
}));

// GET /api/health — detailed health check
app.get('/api/health', async (_req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    const running = containers.filter(c => c.State === 'running').length;
    const elMetrics = getEventLoopMetrics();
    const elDegraded = elMetrics.p99 > 500 || elMetrics.mean > 100;

    // WAL file size monitoring
    const WAL_THRESHOLD_BYTES = 50 * 1024 * 1024; // 50MB
    const dataWalBytes = existsSync(MARKETING_DB_PATH + '-wal') ? statSync(MARKETING_DB_PATH + '-wal').size : 0;
    const authWalBytes = existsSync(AUTH_DB_PATH + '-wal') ? statSync(AUTH_DB_PATH + '-wal').size : 0;
    const dataWalMB = Math.round(dataWalBytes / 1024 / 1024 * 100) / 100;
    const authWalMB = Math.round(authWalBytes / 1024 / 1024 * 100) / 100;
    const walHealthy = dataWalBytes < WAL_THRESHOLD_BYTES && authWalBytes < WAL_THRESHOLD_BYTES;

    // Trigger passive checkpoint if WAL is too large
    if (!walHealthy) {
      try {
        if (dataWalBytes >= WAL_THRESHOLD_BYTES) db.pragma('wal_checkpoint(PASSIVE)');
        if (authWalBytes >= WAL_THRESHOLD_BYTES) authDb.pragma('wal_checkpoint(PASSIVE)');
        console.log(`[WAL] Passive checkpoint triggered — data: ${dataWalMB}MB, auth: ${authWalMB}MB`);
      } catch (cpErr) {
        console.error('[WAL] Checkpoint failed:', cpErr.message);
      }
    }

    const degraded = elDegraded || !walHealthy;
    res.json({
      status: degraded ? 'degraded' : 'ok',
      uptime: process.uptime(),
      containers: { total: containers.length, running },
      eventLoop: { ...elMetrics, degraded: elDegraded },
      wal: { dataWalMB, authWalMB, healthy: walHealthy },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/uptime — proxy Uptime Kuma status page data
let cachedUptime = null;
let lastUptimeUpdate = 0;
const UPTIME_TTL = 60_000;

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

// GET /api/ssl — check SSL certificate expiry for all domains
let cachedSSL = null;
let lastSSLUpdate = 0;
const SSL_TTL = MS_PER_HOUR;

app.get('/api/ssl', asyncRoute(async (_req, res) => {
  const now = Date.now();
  if (cachedSSL && (now - lastSSLUpdate) < SSL_TTL) {
    return res.json(cachedSSL);
  }

  const https = await import('https');
  const domains = config.apps
    .filter(a => a.domain && a.type !== 'redirect')
    .map(a => a.domain);

  const results = {};
  await Promise.all(domains.map(domain => new Promise((resolve) => {
    const req = https.default.request({ hostname: domain, port: 443, method: 'HEAD', timeout: TIMEOUT_QUICK }, (response) => {
      const cert = response.socket?.getPeerCertificate?.();
      if (cert?.valid_to) {
        const expiry = new Date(cert.valid_to);
        const daysLeft = Math.floor((expiry - now) / MS_PER_DAY);
        results[domain] = { expiry: cert.valid_to, daysLeft, issuer: cert.issuer?.O || '' };
      }
      response.destroy();
      resolve();
    });
    req.on('error', () => { results[domain] = { error: 'unreachable' }; resolve(); });
    req.on('timeout', () => { req.destroy(); resolve(); });
    req.end();
  })));

  cachedSSL = { domains: results, timestamp: new Date().toISOString() };
  lastSSLUpdate = now;
  res.json(cachedSSL);
}));

// POST /api/ssl/renew — renew SSL certificate for a domain via certbot
app.post('/api/ssl/renew', asyncRoute(async (req, res) => {
  const { domain } = req.body;
  if (!domain || !/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain' });
  }
  // Verify domain is in our config
  const app = config.apps.find(a => a.domain === domain);
  if (!app) return res.status(404).json({ error: 'Domain not found in config' });

  try {
    const result = execSync(
      `sudo certbot renew --cert-name ${domain} --non-interactive 2>&1`,
      { timeout: 60_000 }
    ).toString();
    // Reload nginx after renewal
    try { execSync('sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload', { timeout: TIMEOUT_STANDARD }); } catch (err) { console.error('[SSL] Nginx reload failed:', err.message); }
    // Bust SSL cache
    cachedSSL = null;
    lastSSLUpdate = 0;
    res.json({ ok: true, output: result.slice(-500) });
  } catch (err) {
    res.status(500).json({ error: 'Renewal failed', output: (err.stderr || err.stdout || err.message || '').toString().slice(-500) });
  }
}));

// GET /api/logs/search — search across all container logs
app.get('/api/logs/search', asyncRoute(async (req, res) => {
  const query = (req.query.q || '').trim();
  if (!query || query.length < 2) return res.status(400).json({ error: 'Query must be at least 2 characters' });

  const targetSlugs = req.query.app ? [req.query.app] : null;
  const tail = Math.min(parseInt(req.query.tail) || 200, 500);
  const containers = await docker.listContainers();

  // Map containers to apps
  const appMap = {};
  for (const appDef of config.apps) {
    if (appDef.containers) {
      for (const cn of appDef.containers) { appMap[cn] = appDef.slug || appDef.name; }
    }
  }

  const results = [];
  const queryLower = query.toLowerCase();

  for (const c of containers) {
    const name = c.Names?.[0]?.replace(/^\//, '') || c.Id.slice(0, 12);
    const appSlug = appMap[name];
    if (targetSlugs && appSlug && !targetSlugs.includes(appSlug)) continue;
    if (targetSlugs && !appSlug) continue;

    try {
      const container = docker.getContainer(c.Id);
      const logs = await container.logs({ stdout: true, stderr: true, tail, timestamps: true });
      const logText = typeof logs === 'string' ? logs : logs.toString('utf8');
      const lines = logText.split('\n').filter(Boolean);

      for (const line of lines) {
        const clean = line.replace(/^.{8}/, ''); // strip Docker header
        if (clean.toLowerCase().includes(queryLower)) {
          results.push({ container: name, app: appSlug || null, line: clean.trim() });
          if (results.length >= 100) break;
        }
      }
    } catch { /* skip inaccessible containers */ }
    if (results.length >= 100) break;
  }

  res.json({ query, count: results.length, results });
}));

// GET /api/events — recent Docker events (starts, stops, health changes)
let cachedEvents = null;
let lastEventsUpdate = 0;
const EVENTS_TTL = 15_000;

app.get('/api/events', async (_req, res) => {
  try {
    const now = Date.now();
    if (cachedEvents && (now - lastEventsUpdate) < EVENTS_TTL) {
      return res.json(cachedEvents);
    }

    const since = Math.floor((now - 6 * MS_PER_HOUR) / 1000);
    const until = Math.floor(now / 1000);

    const stream = await docker.getEvents({
      since,
      until,
      filters: JSON.stringify({
        type: ['container'],
        event: ['start', 'stop', 'die', 'kill', 'restart', 'health_status', 'create', 'destroy'],
      }),
    });

    const chunks = [];
    await new Promise((resolve, reject) => {
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('end', resolve);
      stream.on('error', reject);
      setTimeout(() => { stream.destroy(); resolve(); }, 4000);
    });

    const raw = Buffer.concat(chunks).toString();
    const events = raw.split('\n').filter(Boolean).map(line => {
      try {
        const e = JSON.parse(line);
        return {
          time: e.time,
          action: e.Action || e.status,
          actor: e.Actor?.Attributes?.name || e.Actor?.Attributes?.image || '',
        };
      } catch { return null; }
    }).filter(Boolean).slice(-50).reverse();

    cachedEvents = { events, timestamp: new Date().toISOString() };
    lastEventsUpdate = now;
    res.json(cachedEvents);
  } catch (err) {
    res.json({ events: [], error: err.message, timestamp: new Date().toISOString() });
  }
});

// GET /api/uptime/timeline — 24h container uptime timeline
let cachedUptimeTimeline = null;
let lastUptimeTimelineUpdate = 0;
const UPTIME_TIMELINE_TTL = 300_000; // 5 min cache

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

// GET /api/disk — per-container and image disk breakdown
let cachedDisk = null;
let lastDiskUpdate = 0;
const DISK_TTL = 120_000;

app.get('/api/disk', asyncRoute(async (_req, res) => {
  const now = Date.now();
  if (cachedDisk && (now - lastDiskUpdate) < DISK_TTL) {
    return res.json(cachedDisk);
  }

  const [containers, images] = await Promise.all([
    docker.listContainers({ all: true, size: true }),
    docker.listImages(),
  ]);

  const containerSizes = containers.map(c => ({
    name: containerName(c),
    size: c.SizeRw || 0,
    rootSize: c.SizeRootFs || 0,
    image: c.Image,
  })).sort((a, b) => b.rootSize - a.rootSize);

  const imageSizes = images.map(i => ({
    name: (i.RepoTags?.[0] || i.Id?.slice(7, 19)),
    size: i.Size,
    shared: i.SharedSize || 0,
  })).sort((a, b) => b.size - a.size);

  cachedDisk = { containers: containerSizes, images: imageSizes, timestamp: new Date().toISOString() };
  lastDiskUpdate = now;
  res.json(cachedDisk);
}));

// POST /api/actions/prune — clean up Docker resources
app.post('/api/actions/prune', asyncRoute(async (req, res) => {
  const result = {};
  const pruneContainers = await docker.pruneContainers();
  result.containers = pruneContainers.ContainersDeleted?.length || 0;

  const pruneImages = await docker.pruneImages();
  result.images = pruneImages.ImagesDeleted?.length || 0;
  result.spaceReclaimed = pruneImages.SpaceReclaimed || 0;

  result.buildCache = execSync('docker builder prune -f 2>&1 | tail -1', { timeout: TIMEOUT_HEAVY }).toString().trim();

  auditLog(req, 'docker.prune', null, result);
  res.json({ ok: true, ...result });
}));

// GET /api/discover — auto-discover Docker containers not in config
app.get('/api/discover', asyncRoute(async (_req, res) => {
  const containers = await docker.listContainers({ all: true });
  const trackedContainers = new Set();
  for (const appDef of config.apps) {
    for (const name of (appDef.containers || [])) {
      trackedContainers.add(name);
    }
  }

  // Group containers by compose project
  const projects = new Map();
  const untracked = [];

  for (const c of containers) {
    const name = containerName(c);
    if (!name || trackedContainers.has(name)) continue;

    const project = c.Labels?.['com.docker.compose.project'] || null;
    const service = c.Labels?.['com.docker.compose.service'] || name;
    const state = c.State;
    const status = c.Status;
    const image = c.Image;
    const ports = (c.Ports || []).filter(p => p.PublicPort).map(p => p.PublicPort);

    const entry = { name, service, state, status, image, ports };

    if (project) {
      if (!projects.has(project)) projects.set(project, []);
      projects.get(project).push(entry);
    } else {
      untracked.push(entry);
    }
  }

  // Convert projects to suggested apps
  const suggestions = [];
  for (const [project, containers] of projects) {
    const webPort = containers.find(c => c.ports.length > 0)?.ports[0];
    suggestions.push({
      suggestedName: project.charAt(0).toUpperCase() + project.slice(1),
      project,
      containers: containers.map(c => c.name),
      services: containers.map(c => c.service),
      state: containers.every(c => c.state === 'running') ? 'running' : 'partial',
      webPort,
    });
  }

  // Standalone containers as individual suggestions
  for (const c of untracked) {
    suggestions.push({
      suggestedName: c.name.charAt(0).toUpperCase() + c.name.slice(1).replace(/-/g, ' '),
      project: null,
      containers: [c.name],
      services: [c.service],
      state: c.state,
      webPort: c.ports[0] || null,
    });
  }

  res.json({ suggestions, trackedCount: trackedContainers.size, totalContainers: containers.length });
}));

// GET /api/dependencies — dependency health map
let cachedDeps = null, lastDepsUpdate = 0;
const DEPS_TTL = 5 * 60 * 1000; // 5 minutes

app.get('/api/dependencies', asyncRoute(async (_req, res) => {
  const now = Date.now();
  if (cachedDeps && (now - lastDepsUpdate) < DEPS_TTL) {
    return res.json(cachedDeps);
  }

  const containers = await docker.listContainers({ all: true });
  const runningContainers = new Set();
  for (const c of containers) {
    if (c.State === 'running') {
      const name = containerName(c);
      if (name) runningContainers.add(name);
    }
  }

  // Service detection rules: env var prefix -> service id
  const envRules = [
    { prefix: 'STRIPE_', id: 'stripe', name: 'Stripe' },
    { prefix: 'ANTHROPIC_', id: 'anthropic', name: 'Anthropic' },
    { prefix: 'CLAUDE_', id: 'anthropic', name: 'Anthropic' },
    { prefix: 'RESEND_', id: 'resend', name: 'Resend' },
    { prefix: 'PLAUSIBLE_', id: 'plausible', name: 'Plausible' },
    { prefix: 'SENTRY_', id: 'sentry', name: 'Sentry' },
  ];
  const urlRules = [
    { key: 'DATABASE_URL', match: 'postgres', id: 'postgres', name: 'PostgreSQL' },
    { key: 'REDIS_URL', match: null, id: 'redis', name: 'Redis' },
  ];

  // Container name patterns -> infrastructure service
  const infraPatterns = [
    { pattern: 'postgres', id: 'postgres', name: 'PostgreSQL' },
    { pattern: 'redis', id: 'redis', name: 'Redis' },
  ];

  const serviceMap = new Map(); // id -> { name, status, dependents Set }
  const appsList = [];

  for (const appDef of config.apps) {
    const appSlug = appDef.slug || slugify(appDef.name);
    const deps = new Set();

    // 1. Check containers for infra deps (postgres, redis)
    for (const cn of (appDef.containers || [])) {
      for (const ip of infraPatterns) {
        if (cn.toLowerCase().includes(ip.pattern)) {
          deps.add(ip.id);
          if (!serviceMap.has(ip.id)) serviceMap.set(ip.id, { name: ip.name, dependents: new Set() });
          serviceMap.get(ip.id).dependents.add(appSlug);
        }
      }
    }

    // 2. Scan env vars for service deps
    if (appDef.envFile) {
      try {
        const vars = parseEnvFile(appDef.envFile);
        for (const v of vars) {
          // Prefix rules
          for (const rule of envRules) {
            if (v.key.startsWith(rule.prefix) && v.value) {
              deps.add(rule.id);
              if (!serviceMap.has(rule.id)) serviceMap.set(rule.id, { name: rule.name, dependents: new Set() });
              serviceMap.get(rule.id).dependents.add(appSlug);
            }
          }
          // URL rules
          for (const rule of urlRules) {
            if (v.key === rule.key && v.value && (!rule.match || v.value.includes(rule.match))) {
              deps.add(rule.id);
              if (!serviceMap.has(rule.id)) serviceMap.set(rule.id, { name: rule.name, dependents: new Set() });
              serviceMap.get(rule.id).dependents.add(appSlug);
            }
          }
        }
      } catch { /* env file missing or unreadable — skip */ }
    }

    if (deps.size > 0) {
      appsList.push({ slug: appSlug, name: appDef.name, dependencies: [...deps] });
    }
  }

  // Determine service status
  const cbMap = { stripe: cbStripe, plausible: cbPlausible, anthropic: cbAnthropic, github: cbGitHub };
  const services = [];
  for (const [id, info] of serviceMap) {
    let status = 'unknown';
    if (cbMap[id]) {
      const state = cbMap[id].state;
      status = state === 'closed' ? 'healthy' : state === 'open' ? 'down' : 'degraded';
    } else if (id === 'postgres' || id === 'redis') {
      // Check if any container matching this pattern is running
      const hasRunning = [...runningContainers].some(cn => cn.toLowerCase().includes(id));
      status = hasRunning ? 'healthy' : 'down';
    } else {
      status = 'healthy'; // default for services without health checks (sentry, resend)
    }
    services.push({ id, name: info.name, status, dependents: [...info.dependents] });
  }

  services.sort((a, b) => a.name.localeCompare(b.name));
  cachedDeps = { apps: appsList, services, timestamp: new Date().toISOString() };
  lastDepsUpdate = now;
  res.json(cachedDeps);
}));

// GET /api/backups — backup status for all apps
app.get('/api/backups', asyncRoute((_req, res) => {
  const backupRoot = BACKUP_DIR;
  // Dynamically scan backup directory for subdirectories
  let apps = [];
  try {
    if (existsSync(backupRoot)) {
      apps = readdirSync(backupRoot, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => d.name);
    }
  } catch { apps = []; }
  const results = {};

  for (const app of apps) {
    const dir = join(backupRoot, app);
    if (!existsSync(dir)) {
      results[app] = { status: 'no_backups', files: [] };
      continue;
    }

    try {
      const files = execSync(`ls -lt "${dir}" 2>/dev/null | grep -E '\\.(sql\\.gz|gz)$'`, { timeout: TIMEOUT_STANDARD }).toString().trim().split('\n').filter(Boolean);
      if (files.length === 0) {
        results[app] = { status: 'no_backups', files: [] };
        continue;
      }

      const parsed = files.map(line => {
        const parts = line.split(/\s+/);
        const name = parts[parts.length - 1];
        const size = parseInt(parts[4], 10) || 0;
        // Get mtime via stat
        let mtime;
        try {
          mtime = statSync(join(dir, name)).mtime.toISOString();
        } catch {
          mtime = null;
        }
        return { name, size, mtime };
      });

      const latest = parsed[0];
      const ageMs = latest.mtime ? Date.now() - new Date(latest.mtime).getTime() : null;
      const ageHours = ageMs ? Math.round(ageMs / MS_PER_HOUR) : null;

      results[app] = {
        status: ageHours !== null && ageHours <= 25 ? 'ok' : 'stale',
        count: parsed.length,
        latest: latest,
        ageHours,
        totalSize: parsed.reduce((s, f) => s + f.size, 0),
      };
    } catch {
      results[app] = { status: 'no_backups', files: [] };
    }
  }

  res.json({ backups: results, timestamp: new Date().toISOString() });
}));

// --- Marketing Manager ---

// SEO audit: crawl a domain and check meta tags, OG, sitemap, robots, etc.
const SEO_CHECKS = [
  { id: 'title', label: 'Page Title', weight: 15 },
  { id: 'title_length', label: 'Title Length (50-60 chars)', weight: 5 },
  { id: 'meta_desc', label: 'Meta Description', weight: 15 },
  { id: 'meta_desc_length', label: 'Description Length (120-160 chars)', weight: 5 },
  { id: 'og_title', label: 'OG Title', weight: 8 },
  { id: 'og_desc', label: 'OG Description', weight: 8 },
  { id: 'og_image', label: 'OG Image', weight: 10 },
  { id: 'canonical', label: 'Canonical URL', weight: 5 },
  { id: 'viewport', label: 'Viewport Meta', weight: 5 },
  { id: 'lang', label: 'HTML lang Attribute', weight: 4 },
  { id: 'sitemap', label: 'Sitemap.xml', weight: 8 },
  { id: 'robots', label: 'Robots.txt', weight: 7 },
  { id: 'favicon', label: 'Favicon', weight: 5 },
];

async function auditSEO(domain) {
  const results = {};
  const issues = [];

  try {
    // Fetch homepage
    const res = await fetch(`https://${domain}`, {
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
      headers: { 'User-Agent': 'AppManager-SEO-Audit/1.0' },
    });
    const html = await res.text();

    // Title
    const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/is);
    const title = titleMatch ? titleMatch[1].trim() : '';
    results.title = !!title;
    if (!title) issues.push({ severity: 'high', msg: 'Missing page title' });

    // Title length
    const titleLen = title.length;
    results.title_length = titleLen >= 30 && titleLen <= 65;
    if (title && !results.title_length) {
      issues.push({ severity: 'medium', msg: `Title length ${titleLen} chars (aim for 50-60)` });
    }

    // Meta description
    const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i)
      || html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i);
    const desc = descMatch ? descMatch[1].trim() : '';
    results.meta_desc = !!desc;
    if (!desc) issues.push({ severity: 'high', msg: 'Missing meta description' });

    // Description length
    const descLen = desc.length;
    results.meta_desc_length = descLen >= 100 && descLen <= 170;
    if (desc && !results.meta_desc_length) {
      issues.push({ severity: 'medium', msg: `Description length ${descLen} chars (aim for 120-160)` });
    }

    // OG tags
    const ogTitle = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']*)["']/i);
    results.og_title = !!(ogTitle && ogTitle[1]);
    if (!results.og_title) issues.push({ severity: 'medium', msg: 'Missing og:title' });

    const ogDesc = html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']*)["']/i);
    results.og_desc = !!(ogDesc && ogDesc[1]);
    if (!results.og_desc) issues.push({ severity: 'medium', msg: 'Missing og:description' });

    const ogImage = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']*)["']/i);
    results.og_image = !!(ogImage && ogImage[1]);
    if (!results.og_image) issues.push({ severity: 'high', msg: 'Missing og:image (critical for social sharing)' });

    // Canonical
    const canonical = html.match(/<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']*)["']/i);
    results.canonical = !!(canonical && canonical[1]);
    if (!results.canonical) issues.push({ severity: 'low', msg: 'Missing canonical URL' });

    // Viewport
    const viewport = html.match(/<meta[^>]*name=["']viewport["']/i);
    results.viewport = !!viewport;
    if (!viewport) issues.push({ severity: 'high', msg: 'Missing viewport meta (mobile unfriendly)' });

    // Lang
    const lang = html.match(/<html[^>]*lang=["']([^"']*)["']/i);
    results.lang = !!(lang && lang[1]);
    if (!results.lang) issues.push({ severity: 'low', msg: 'Missing lang attribute on <html>' });

    // Favicon
    const favicon = html.match(/<link[^>]*rel=["'](icon|shortcut icon)["'][^>]*/i);
    results.favicon = !!favicon;
    if (!favicon) issues.push({ severity: 'low', msg: 'Missing favicon link tag' });

  } catch (err) {
    issues.push({ severity: 'high', msg: `Failed to fetch homepage: ${err.message}` });
  }

  // Sitemap
  try {
    const sRes = await fetch(`https://${domain}/sitemap.xml`, {
      signal: AbortSignal.timeout(TIMEOUT_QUICK),
      method: 'HEAD',
    });
    results.sitemap = sRes.ok;
    if (!sRes.ok) issues.push({ severity: 'medium', msg: 'No sitemap.xml found' });
  } catch {
    results.sitemap = false;
    issues.push({ severity: 'medium', msg: 'No sitemap.xml found' });
  }

  // Robots.txt
  try {
    const rRes = await fetch(`https://${domain}/robots.txt`, {
      signal: AbortSignal.timeout(TIMEOUT_QUICK),
      method: 'HEAD',
    });
    results.robots = rRes.ok;
    if (!rRes.ok) issues.push({ severity: 'medium', msg: 'No robots.txt found' });
  } catch {
    results.robots = false;
    issues.push({ severity: 'medium', msg: 'No robots.txt found' });
  }

  // Calculate score
  let earned = 0;
  let total = 0;
  for (const check of SEO_CHECKS) {
    total += check.weight;
    if (results[check.id]) earned += check.weight;
  }
  const score = Math.round((earned / total) * 100);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return { score, grade, checks: results, issues };
}

let cachedSEO = null;
let lastSEOUpdate = 0;
const SEO_TTL = MS_PER_HOUR;

// GET /api/marketing/seo — SEO audit for all marketable apps
app.get('/api/marketing/seo', asyncRoute(async (req, res) => {
  const now = Date.now();
  const force = req.query.force === 'true';
  if (!force && cachedSEO && (now - lastSEOUpdate) < SEO_TTL) {
    return res.json(cachedSEO);
  }

  const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
  const results = {};

  // Run audits in parallel (all at once since they're different domains)
  await Promise.all(marketableApps.map(async (appDef) => {
    const audit = await auditSEO(appDef.domain);
    results[appDef.name] = {
      domain: appDef.domain,
      ...audit,
      marketing: appDef.marketing || null,
    };
  }));

  // Overall stats
  const scores = Object.values(results).map(r => r.score);
  const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const totalIssues = Object.values(results).reduce((sum, r) => sum + r.issues.length, 0);

  cachedSEO = {
    apps: results,
    summary: { avgScore, totalIssues, appCount: scores.length },
    timestamp: new Date().toISOString(),
  };
  lastSEOUpdate = now;
  res.json(cachedSEO);
}));

// GET /api/marketing/overview — comprehensive portfolio overview
app.get('/api/marketing/overview', asyncRoute(async (_req, res) => {
  const overview = config.apps.map(appDef => {
    const slug = slugify(appDef.name);

    // Revenue (from cached metrics)
    const mrrRow = qLatestMetric.get(slug, 'mrr');
    const revRow = qLatestMetric.get(slug, 'revenue');

    // Traffic (from cached analytics)
    const trafficData = cachedAnalytics?.apps?.[appDef.name] || null;

    // Security score (scans are global, not per-app)
    const secRow = db.prepare('SELECT overall_score as score, grade FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();

    // SEO score
    const seoRow = qLatestSEO.get(slug);

    // Project tasks
    const openTasks = db.prepare("SELECT COUNT(*) as n FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.n || 0;
    const doneTasks = db.prepare("SELECT COUNT(*) as n FROM project_tasks WHERE app_slug = ? AND status = 'done'").get(slug)?.n || 0;

    // Roadmap
    const roadmapItems = db.prepare("SELECT COUNT(*) as n FROM project_roadmap WHERE app_slug = ?").get(slug)?.n || 0;
    const roadmapShipped = db.prepare("SELECT COUNT(*) as n FROM project_roadmap WHERE app_slug = ? AND status = 'shipped'").get(slug)?.n || 0;

    // Banner placements
    const bannerCount = db.prepare("SELECT COUNT(*) as n FROM banner_placements WHERE app_slug = ? AND status = 'active'").get(slug)?.n || 0;

    // Project meta
    const meta = db.prepare('SELECT lifecycle, priority, revenue_goal_mrr as revenue_goal, traffic_goal_mpv as traffic_goal, user_goal FROM project_meta WHERE app_slug = ?').get(slug);

    return {
      name: appDef.name,
      slug,
      type: appDef.type,
      domain: appDef.domain,
      description: appDef.description,
      marketing: appDef.marketing || null,
      revenue: {
        mrrCents: mrrRow?.value || 0,
        revenue30dCents: revRow?.value || 0,
      },
      traffic: {
        visitors30d: trafficData?.visitors || 0,
        pageviews30d: trafficData?.pageviews || 0,
        realtime: trafficData?.realtime || 0,
      },
      security: secRow ? { score: secRow.score, grade: secRow.grade } : null,
      seo: seoRow ? { score: seoRow.score } : null,
      tasks: { open: openTasks, done: doneTasks },
      roadmap: { total: roadmapItems, shipped: roadmapShipped },
      bannerPlacements: bannerCount,
      project: meta || null,
    };
  });

  // Portfolio totals
  const totalMRR = overview.reduce((s, a) => s + (a.revenue.mrrCents || 0), 0);
  const totalRevenue30d = overview.reduce((s, a) => s + (a.revenue.revenue30dCents || 0), 0);
  const totalVisitors30d = overview.reduce((s, a) => s + (a.traffic.visitors30d || 0), 0);
  const totalOpenTasks = overview.reduce((s, a) => s + a.tasks.open, 0);

  res.json({
    apps: overview,
    totals: {
      appCount: overview.length,
      mrrCents: totalMRR,
      revenue30dCents: totalRevenue30d,
      visitors30d: totalVisitors30d,
      openTasks: totalOpenTasks,
    },
    timestamp: new Date().toISOString(),
  });
}));

// --- Environment Variable Management ---

// GET /api/apps/:slug/env — read env vars for an app
app.get('/api/apps/:slug/env', asyncRoute((req, res) => {
  const appDef = findAppBySlug(req.params.slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });
  if (!appDef.envFile) return res.status(400).json({ error: 'No env file configured for this app' });
  if (!existsSync(appDef.envFile)) return res.status(404).json({ error: 'Env file not found on disk' });

  const vars = parseEnvFile(appDef.envFile);
  const reveal = req.query.reveal === 'true';

  const result = vars.map(v => {
    const sensitive = SENSITIVE_PATTERN.test(v.key);
    return {
      key: v.key,
      value: (!reveal && sensitive) ? maskValue(v.value) : v.value,
      sensitive,
      empty: !v.value,
    };
  });

  const hasSentry = vars.some(v => (v.key === 'SENTRY_DSN' || v.key === 'NEXT_PUBLIC_SENTRY_DSN') && v.value);
  res.json({ vars: result, hasSentry, appName: appDef.name });
}));

// PUT /api/apps/:slug/env — update env vars
app.put('/api/apps/:slug/env', asyncRoute((req, res) => {
  const appDef = findAppBySlug(req.params.slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });
  if (!appDef.envFile) return res.status(400).json({ error: 'No env file configured' });

  const { changes, deletes } = req.body;
  if (!changes && !deletes) return res.status(400).json({ error: 'No changes provided' });

  // Backup current file
  const bakPath = appDef.envFile + '.bak';
  if (existsSync(appDef.envFile)) {
    copyFileSync(appDef.envFile, bakPath);
  }

  // Read current vars
  const vars = parseEnvFile(appDef.envFile);
  const varMap = new Map(vars.map(v => [v.key, v.value]));

  // Apply changes
  if (changes) {
    for (const [key, value] of Object.entries(changes)) {
      const oldValue = varMap.get(key);
      varMap.set(key, value);
      console.log(`[ENV] ${appDef.name}: ${key} ${oldValue !== undefined ? 'updated' : 'added'}`);
    }
  }

  // Apply deletes
  if (deletes) {
    for (const key of deletes) {
      if (varMap.has(key)) {
        varMap.delete(key);
        console.log(`[ENV] ${appDef.name}: ${key} deleted`);
      }
    }
  }

  // Write updated file
  const newVars = Array.from(varMap.entries()).map(([key, value]) => ({ key, value }));
  writeFileSync(appDef.envFile, serializeEnvVars(newVars), 'utf8');

  res.json({ ok: true, message: `Updated ${appDef.name} env file` });
}));

// GET /api/env/diff — compare env vars across all apps
app.get('/api/env/diff', asyncRoute((req, res) => {
  const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));
  if (appsWithEnv.length === 0) return res.json({ apps: [], keys: {}, warnings: [] });

  const appSlugs = appsWithEnv.map(a => a.slug);
  const appEnvs = {};  // slug -> { key: value }

  for (const appDef of appsWithEnv) {
    try {
      const vars = parseEnvFile(appDef.envFile);
      const map = {};
      for (const v of vars) {
        map[v.key] = v.value;
      }
      appEnvs[appDef.slug] = map;
    } catch (err) {
      console.error(`[ENV-DIFF] Failed to parse ${appDef.envFile}:`, err.message);
    }
  }

  // Build comparison matrix
  const allKeys = new Set();
  for (const slug of appSlugs) {
    if (appEnvs[slug]) {
      for (const key of Object.keys(appEnvs[slug])) {
        allKeys.add(key);
      }
    }
  }

  const keys = {};
  const warnings = [];
  const sortedKeys = [...allKeys].sort();

  for (const key of sortedKeys) {
    const sensitive = SENSITIVE_PATTERN.test(key);
    const entry = {};
    const presentApps = [];
    const values = {};  // slug -> actual value (for inconsistency check)

    for (const slug of appSlugs) {
      if (!appEnvs[slug]) continue;
      if (key in appEnvs[slug]) {
        const val = appEnvs[slug][key];
        if (sensitive) {
          entry[slug] = val ? '[set]' : '[empty]';
        } else {
          entry[slug] = val || '[empty]';
        }
        presentApps.push(slug);
        values[slug] = val;
      } else {
        entry[slug] = '[missing]';
      }
    }

    keys[key] = entry;

    // Flag missing: key present in 2+ apps but missing in at least one that has env
    if (presentApps.length >= 2) {
      for (const slug of appSlugs) {
        if (appEnvs[slug] && !(key in appEnvs[slug])) {
          warnings.push({ type: 'missing', key, app: slug });
        }
      }
    }

    // Flag inconsistent values for non-sensitive keys
    if (!sensitive && presentApps.length >= 2) {
      const uniqueValues = [...new Set(presentApps.map(s => values[s]).filter(v => v))];
      if (uniqueValues.length > 1) {
        warnings.push({
          type: 'inconsistent',
          key,
          apps: presentApps,
          values: presentApps.map(s => values[s]),
        });
      }
    }
  }

  res.json({ apps: appSlugs, keys, warnings });
}));

// POST /api/apps/:slug/recreate — recreate container with new env
app.post('/api/apps/:slug/recreate', asyncRoute(async (req, res) => {
  try {
    const appDef = findAppBySlug(req.params.slug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });
    if (!appDef.composeFile) return res.status(400).json({ error: 'No compose file configured' });

    const projectDir = dirname(appDef.composeFile);
    const output = execSync(
      `docker compose -f "${appDef.composeFile}" --project-directory "${projectDir}" up -d --no-build 2>&1`,
      { timeout: TIMEOUT_HEAVY }
    ).toString();

    console.log(`[RECREATE] ${appDef.name}: container recreated`);
    res.json({ ok: true, output });
  } catch (err) {
    res.status(500).json({ error: err.stderr?.toString() || err.message });
  }
}));

// GET /api/env/health — validate API keys across all apps
let cachedKeyHealth = null;
let lastKeyHealthUpdate = 0;
const KEY_HEALTH_TTL = 300_000; // 5 minutes

async function validateKey(type, value) {
  try {
    const opts = { method: 'GET', headers: {}, signal: AbortSignal.timeout(TIMEOUT_STANDARD) };
    let url;
    if (type === 'STRIPE_SECRET_KEY') {
      url = `${STRIPE_API}/balance`;
      opts.headers['Authorization'] = 'Basic ' + Buffer.from(value + ':').toString('base64');
    } else if (type === 'ANTHROPIC_API_KEY') {
      url = 'https://api.anthropic.com/v1/models';
      opts.headers['x-api-key'] = value;
      opts.headers['anthropic-version'] = '2023-06-01';
    } else if (type === 'RESEND_API_KEY') {
      // Resend "Sending access" keys can only send, not list resources
      // Send an intentionally invalid request — 422 = key valid, 401/403 = key invalid
      url = 'https://api.resend.com/emails';
      opts.method = 'POST';
      opts.headers['Authorization'] = `Bearer ${value}`;
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify({ from: 'test@test.com', to: 'invalid', subject: 'x', text: 'x' });
    } else {
      return null; // Unknown key type
    }
    const response = await fetch(url, opts);
    // 200/201 = valid, 422 = valid (validation error means auth passed), 429 = valid (rate-limited but key works), 401/403 = expired
    const s = response.status;
    return (s === 200 || s === 201 || s === 422 || s === 429) ? 'valid' : 'expired';
  } catch {
    return 'error';
  }
}

const VALIDATABLE_KEYS = ['STRIPE_SECRET_KEY', 'ANTHROPIC_API_KEY', 'RESEND_API_KEY'];

app.get('/api/env/health', asyncRoute(async (req, res) => {
  const now = Date.now();
  const force = req.query.force === 'true';
  if (!force && cachedKeyHealth && (now - lastKeyHealthUpdate) < KEY_HEALTH_TTL) {
    return res.json(cachedKeyHealth);
  }

  const results = {};
  const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));

  // Deduplicate keys: validate each unique key+value only once to avoid rate limiting
  const uniqueKeys = new Map(); // "type::value" -> { type, value, apps: [{name, key}] }
  for (const appDef of appsWithEnv) {
    const vars = parseEnvFile(appDef.envFile);
    for (const v of vars) {
      if (VALIDATABLE_KEYS.includes(v.key) && v.value) {
        const dedupeKey = `${v.key}::${v.value}`;
        if (!uniqueKeys.has(dedupeKey)) {
          uniqueKeys.set(dedupeKey, { type: v.key, value: v.value, apps: [] });
        }
        uniqueKeys.get(dedupeKey).apps.push({ name: appDef.name, key: v.key });
      }
    }
  }

  // Validate each unique key once
  for (const [, entry] of uniqueKeys) {
    const status = await validateKey(entry.type, entry.value);
    if (status) {
      for (const app of entry.apps) {
        if (!results[app.name]) results[app.name] = {};
        results[app.name][app.key] = { status, maskedValue: maskValue(entry.value) };
      }
    }
  }

  cachedKeyHealth = { results, timestamp: new Date().toISOString() };
  lastKeyHealthUpdate = now;
  res.json(cachedKeyHealth);
}));

// --- Integration Keys (Settings DB) ---

// GET /api/settings/keys — list all integration keys with status
app.get('/api/settings/keys', asyncRoute(async (req, res) => {
  const skipValidation = req.query.skip_validation === 'true';
  const results = [];

  for (const entry of INTEGRATION_KEYS) {
    const dbVal = getSetting(entry.key);
    const envVal = process.env[entry.key] || null;
    const appVal = (() => {
      for (const appDef of config.apps) {
        if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
        const vars = parseEnvFile(appDef.envFile);
        const found = vars.find(v => v.key === entry.key && v.value);
        if (found) return found.value;
      }
      return null;
    })();

    const value = dbVal || envVal || appVal;
    const source = dbVal ? 'database' : envVal ? 'environment' : appVal ? 'app-env' : null;
    let status = value ? 'configured' : 'missing';

    // Validate keys that support it (unless skipped)
    if (value && entry.validatable && !skipValidation) {
      const result = await validateKey(entry.key, value);
      status = result === 'valid' ? 'valid' : result === 'expired' ? 'expired' : result === 'error' ? 'error' : 'configured';
    }

    results.push({
      key: entry.key,
      label: entry.label,
      category: entry.category,
      validatable: entry.validatable,
      hasValue: !!value,
      source,
      maskedValue: value ? maskValue(value) : null,
      status,
    });
  }

  res.json({ keys: results });
}));

// PUT /api/settings/keys — save integration keys
app.put('/api/settings/keys', asyncRoute(async (req, res) => {
  const { keys } = req.body;
  if (!Array.isArray(keys)) return res.status(400).json({ error: 'keys must be an array' });

  let saved = 0;
  let deleted = 0;
  for (const { key, value } of keys) {
    if (!INTEGRATION_KEY_SET.has(key)) continue;
    if (!value || !value.trim()) {
      deleteSettingStmt.run(key);
      deleted++;
    } else {
      upsertSettingStmt.run(key, value.trim());
      saved++;
    }
  }

  res.json({ ok: true, saved, deleted });
}));

// GET /api/settings/favorites — get favorite app slugs
app.get('/api/settings/favorites', (req, res) => {
  const raw = getSetting('favorite_apps');
  const favorites = raw ? JSON.parse(raw) : [];
  res.json({ favorites });
});

// PUT /api/settings/favorites — save favorite app slugs
app.put('/api/settings/favorites', asyncRoute(async (req, res) => {
  const { favorites } = req.body;
  if (!Array.isArray(favorites)) return res.status(400).json({ error: 'favorites must be an array' });
  upsertSettingStmt.run('favorite_apps', JSON.stringify(favorites));
  res.json({ ok: true, favorites });
}));

// --- App Configuration Management ---

function reloadConfig() {
  const raw = readFileSync(configPath, 'utf8');
  const parsed = yaml.load(raw);
  config.apps = parsed.apps || [];
}

function saveConfig() {
  const yamlStr = yaml.dump({ apps: config.apps }, { lineWidth: -1, noRefs: true, quotingType: '"' });
  writeFileSync(configPath, yamlStr, 'utf8');
}

// GET /api/config/apps — list all configured apps (for settings)
app.get('/api/config/apps', (_req, res) => {
  res.json(config.apps.map(a => ({
    name: a.name,
    slug: slugify(a.name),
    type: a.type || 'app',
    domain: a.domain || '',
    port: a.port || null,
    health: a.health || '/',
    containers: a.containers || [],
    description: a.description || '',
    tech: a.tech || '',
    envFile: a.envFile || '',
    composeFile: a.composeFile || '',
  })));
});

// POST /api/config/apps — add a new app
app.post('/api/config/apps', asyncRoute(async (req, res) => {
  const { name, type, domain, port, health, containers, description, tech, envFile, composeFile } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'App name is required' });
  }
  const existing = config.apps.find(a => slugify(a.name) === slugify(name.trim()));
  if (existing) {
    return res.status(409).json({ error: 'An app with this name already exists' });
  }

  const newApp = {
    name: name.trim(),
    type: type || 'app',
    domain: domain || '',
    health: health || '/',
    containers: Array.isArray(containers) ? containers : [],
    description: description || '',
  };
  if (port) newApp.port = Number(port);
  if (tech) newApp.tech = tech;
  if (envFile) newApp.envFile = envFile;
  if (composeFile) newApp.composeFile = composeFile;

  config.apps.push(newApp);
  saveConfig();
  res.json({ ok: true, slug: slugify(newApp.name) });
}));

// POST /api/config/apps/validate — validate a partial app config
app.post('/api/config/apps/validate', asyncRoute(async (req, res) => {
  const { name, domain, port, step } = req.body;
  const errors = [];

  // Step 1 validations: basics
  if (step === undefined || step === 1) {
    if (!name || !name.trim()) {
      errors.push('App name is required');
    } else {
      const slug = slugify(name.trim());
      const existing = config.apps.find(a => slugify(a.name) === slug);
      if (existing) errors.push(`An app with slug "${slug}" already exists`);
    }
  }

  // Step 2 validations: infrastructure
  if (step === undefined || step === 2) {
    if (domain && domain.trim()) {
      try {
        const { promises: dnsPromises } = await import('dns');
        await dnsPromises.resolve4(domain.trim());
      } catch {
        errors.push(`Domain "${domain}" does not resolve (DNS lookup failed)`);
      }
    }
    if (port) {
      const portNum = Number(port);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        errors.push('Port must be a number between 1 and 65535');
      } else {
        const portConflict = config.apps.find(a => a.port && Number(a.port) === portNum);
        if (portConflict) errors.push(`Port ${portNum} is already used by "${portConflict.name}"`);
      }
    }
  }

  res.json({ valid: errors.length === 0, errors });
}));

// PUT /api/config/apps/:slug — update an app
app.put('/api/config/apps/:slug', asyncRoute(async (req, res) => {
  const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
  if (idx === -1) return res.status(404).json({ error: 'App not found' });

  const { name, type, domain, port, health, containers, description, tech, envFile, composeFile } = req.body;
  const app = config.apps[idx];
  if (name) app.name = name.trim();
  if (type) app.type = type;
  if (domain !== undefined) app.domain = domain;
  if (port !== undefined) app.port = port ? Number(port) : undefined;
  if (health !== undefined) app.health = health;
  if (containers) app.containers = Array.isArray(containers) ? containers : [];
  if (description !== undefined) app.description = description;
  if (tech !== undefined) app.tech = tech;
  if (envFile !== undefined) app.envFile = envFile;
  if (composeFile !== undefined) app.composeFile = composeFile;

  saveConfig();
  res.json({ ok: true });
}));

// DELETE /api/config/apps/:slug — remove an app
app.delete('/api/config/apps/:slug', asyncRoute(async (req, res) => {
  const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
  if (idx === -1) return res.status(404).json({ error: 'App not found' });
  config.apps.splice(idx, 1);
  saveConfig();
  res.json({ ok: true });
}));

// --- Marketing Manager: SQLite + Revenue + Analytics ---

const MARKETING_DB_PATH = process.env.MARKETING_DB_PATH || join(process.env.HOME || '/data', 'marketing', 'data.db');
const MARKETING_DIR = dirname(MARKETING_DB_PATH);
if (!existsSync(MARKETING_DIR)) mkdirSync(MARKETING_DIR, { recursive: true });
const db = new Database(MARKETING_DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = -64000');       // 64MB (main data DB)
db.pragma('temp_store = MEMORY');
db.pragma('mmap_io = 268435456');       // 256MB

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS metrics_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    date TEXT NOT NULL,
    metric_type TEXT NOT NULL,
    value REAL NOT NULL,
    metadata TEXT,
    UNIQUE(app_slug, date, metric_type)
  );
  CREATE INDEX IF NOT EXISTS idx_metrics_daily_lookup ON metrics_daily(app_slug, date, metric_type);
  CREATE TABLE IF NOT EXISTS seo_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    date TEXT NOT NULL,
    score INTEGER,
    grade TEXT,
    checks TEXT,
    UNIQUE(app_slug, date)
  );
  CREATE INDEX IF NOT EXISTS idx_seo_audits_app ON seo_audits(app_slug);

  CREATE TABLE IF NOT EXISTS container_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_name TEXT NOT NULL,
    app_slug TEXT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    cpu REAL NOT NULL DEFAULT 0,
    memory REAL NOT NULL DEFAULT 0,
    UNIQUE(container_name, ts)
  );
  CREATE INDEX IF NOT EXISTS idx_container_metrics_lookup ON container_metrics(container_name, ts);

  CREATE TABLE IF NOT EXISTS system_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    disk_used_bytes INTEGER NOT NULL,
    disk_total_bytes INTEGER NOT NULL,
    mem_used_bytes INTEGER NOT NULL,
    mem_total_bytes INTEGER NOT NULL,
    cpu_percent REAL NOT NULL DEFAULT 0,
    load_1m REAL NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_system_snapshots_ts ON system_snapshots(ts);

  CREATE TABLE IF NOT EXISTS customer_graph (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_hash TEXT NOT NULL,
    app_slug TEXT NOT NULL,
    stripe_customer_id TEXT NOT NULL,
    stripe_key_hash TEXT NOT NULL,
    mrr INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_active TEXT NOT NULL,
    plan_name TEXT,
    UNIQUE(email_hash, app_slug)
  );
  CREATE INDEX IF NOT EXISTS idx_customer_graph_email ON customer_graph(email_hash);
  CREATE INDEX IF NOT EXISTS idx_customer_graph_app ON customer_graph(app_slug);

  CREATE TABLE IF NOT EXISTS email_sequences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    segment TEXT NOT NULL,
    app_slug TEXT,
    active INTEGER NOT NULL DEFAULT 0,
    steps TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (date('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_email_sequences_active ON email_sequences(active);

  CREATE TABLE IF NOT EXISTS subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_hash TEXT NOT NULL,
    email_encrypted TEXT NOT NULL,
    app_slug TEXT NOT NULL,
    stripe_customer_id TEXT,
    segment TEXT NOT NULL,
    subscribed_at TEXT NOT NULL DEFAULT (datetime('now')),
    unsubscribed_at TEXT,
    UNIQUE(email_hash, app_slug)
  );
  CREATE INDEX IF NOT EXISTS idx_subscribers_segment ON subscribers(app_slug, segment);

  CREATE TABLE IF NOT EXISTS email_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_hash TEXT NOT NULL,
    app_slug TEXT NOT NULL,
    segment TEXT NOT NULL,
    template_key TEXT NOT NULL,
    scheduled_at TEXT NOT NULL,
    sent_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    sequence_id INTEGER REFERENCES email_sequences(id)
  );
  CREATE INDEX IF NOT EXISTS idx_email_queue_pending ON email_queue(status, scheduled_at)
    WHERE status = 'pending';

  CREATE TABLE IF NOT EXISTS healing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    app_slug TEXT,
    condition TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    confidence TEXT NOT NULL,
    result TEXT NOT NULL DEFAULT 'pending',
    auto INTEGER NOT NULL DEFAULT 0,
    details TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_healing_log_ts ON healing_log(timestamp);

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    action TEXT NOT NULL DEFAULT '',
    target TEXT,
    details TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    method TEXT,
    path TEXT,
    status INTEGER,
    detail TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(created_at);

  CREATE TABLE IF NOT EXISTS content_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    content_type TEXT NOT NULL,
    keyword TEXT,
    title TEXT,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    published_at TEXT,
    ai_model TEXT DEFAULT 'claude-sonnet-4-20250514',
    token_count INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_content_queue_status ON content_queue(app_slug, status);

  CREATE TABLE IF NOT EXISTS crosspromo_campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    source_app TEXT NOT NULL,
    target_app TEXT NOT NULL,
    headline TEXT,
    cta_text TEXT NOT NULL DEFAULT 'Learn More',
    cta_url TEXT NOT NULL,
    banner_data TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    views INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_crosspromo_status ON crosspromo_campaigns(status);
  CREATE INDEX IF NOT EXISTS idx_crosspromo_source ON crosspromo_campaigns(source_app, status);

  CREATE TABLE IF NOT EXISTS banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'bannerforge',
    width INTEGER NOT NULL DEFAULT 728,
    height INTEGER NOT NULL DEFAULT 90,
    content TEXT NOT NULL,
    thumbnail TEXT,
    bannerforge_config TEXT,
    click_url TEXT,
    tags TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_banners_type ON banners(type);

  CREATE TABLE IF NOT EXISTS banner_placements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    banner_id INTEGER NOT NULL REFERENCES banners(id) ON DELETE CASCADE,
    app_slug TEXT NOT NULL,
    position TEXT DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'draft',
    priority INTEGER NOT NULL DEFAULT 0,
    weight INTEGER NOT NULL DEFAULT 100,
    click_url TEXT,
    start_date TEXT,
    end_date TEXT,
    views INTEGER NOT NULL DEFAULT 0,
    clicks INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_placements_app ON banner_placements(app_slug, status);
  CREATE INDEX IF NOT EXISTS idx_placements_banner ON banner_placements(banner_id);

  CREATE TABLE IF NOT EXISTS marketing_playbooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    section TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_playbooks_app ON marketing_playbooks(app_slug);

  CREATE TABLE IF NOT EXISTS security_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    scan_type TEXT NOT NULL,
    overall_score INTEGER,
    grade TEXT,
    category_scores TEXT,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_security_scans_ts ON security_scans(timestamp);

  CREATE TABLE IF NOT EXISTS security_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES security_scans(id),
    app_slug TEXT,
    container_name TEXT,
    category TEXT NOT NULL,
    check_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    title TEXT NOT NULL,
    details TEXT,
    remediation TEXT,
    dismissed_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_security_findings_scan ON security_findings(scan_id);
  CREATE INDEX IF NOT EXISTS idx_security_findings_app ON security_findings(app_slug);

  CREATE TABLE IF NOT EXISTS project_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL UNIQUE,
    lifecycle TEXT NOT NULL DEFAULT 'launched',
    priority INTEGER NOT NULL DEFAULT 2,
    revenue_goal_mrr INTEGER,
    traffic_goal_mpv INTEGER,
    user_goal INTEGER,
    notes TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_project_meta_lifecycle ON project_meta(lifecycle);

  CREATE TABLE IF NOT EXISTS project_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'todo',
    priority TEXT NOT NULL DEFAULT 'medium',
    due_date TEXT,
    completed_at TEXT,
    reminder_at TEXT,
    reminder_sent INTEGER NOT NULL DEFAULT 0,
    tags TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_project_tasks_app ON project_tasks(app_slug, status);
  CREATE INDEX IF NOT EXISTS idx_project_tasks_status ON project_tasks(status);
  CREATE INDEX IF NOT EXISTS idx_project_tasks_due ON project_tasks(due_date);

  CREATE TABLE IF NOT EXISTS project_roadmap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT,
    title TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL DEFAULT 'feature',
    status TEXT NOT NULL DEFAULT 'planned',
    target_date TEXT,
    shipped_date TEXT,
    impact TEXT NOT NULL DEFAULT 'medium',
    effort TEXT NOT NULL DEFAULT 'medium',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_project_roadmap_app ON project_roadmap(app_slug, status);
  CREATE INDEX IF NOT EXISTS idx_project_roadmap_status ON project_roadmap(status);

  CREATE TABLE IF NOT EXISTS project_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    snapshot_date TEXT NOT NULL,
    mrr_cents INTEGER,
    traffic_30d INTEGER,
    task_count_open INTEGER,
    task_count_done INTEGER,
    roadmap_shipped INTEGER,
    security_score INTEGER,
    seo_score INTEGER,
    health_status TEXT,
    UNIQUE(app_slug, snapshot_date)
  );
  CREATE INDEX IF NOT EXISTS idx_project_snapshots_app ON project_snapshots(app_slug);

  CREATE TABLE IF NOT EXISTS project_ai_insights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    insight_type TEXT NOT NULL,
    content TEXT NOT NULL,
    token_count INTEGER,
    generated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(app_slug, insight_type)
  );
  CREATE INDEX IF NOT EXISTS idx_ai_insights_lookup ON project_ai_insights(app_slug, insight_type);

  CREATE TABLE IF NOT EXISTS ops_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    snapshot_type TEXT NOT NULL DEFAULT 'auto',
    env_hashes TEXT NOT NULL,
    container_states TEXT NOT NULL,
    disk_usage_pct INTEGER,
    total_containers INTEGER,
    config_hash TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ops_baselines_ts ON ops_baselines(timestamp);

  CREATE TABLE IF NOT EXISTS ops_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    app_slug TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    details TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acknowledged_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ops_events_ts ON ops_events(timestamp);
  CREATE INDEX IF NOT EXISTS idx_ops_events_type ON ops_events(event_type, acknowledged);

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    message TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    app_slug TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_notifications_ts ON notifications(timestamp);
  CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);

  CREATE TABLE IF NOT EXISTS ops_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    worry_score INTEGER NOT NULL,
    breakdown TEXT NOT NULL,
    streak_days INTEGER NOT NULL DEFAULT 0,
    streak_broken_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_ops_scores_ts ON ops_scores(timestamp);

  CREATE TABLE IF NOT EXISTS error_issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    app_slug TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'error',
    status TEXT NOT NULL DEFAULT 'open',
    title TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    resolved_at TEXT,
    metadata TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_error_issues_app ON error_issues(app_slug);
  CREATE INDEX IF NOT EXISTS idx_error_issues_status ON error_issues(status);

  CREATE TABLE IF NOT EXISTS error_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL REFERENCES error_issues(id),
    app_slug TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    message TEXT NOT NULL,
    stack_trace TEXT,
    source TEXT NOT NULL DEFAULT 'api',
    container_name TEXT,
    request_url TEXT,
    request_method TEXT,
    breadcrumbs TEXT,
    extra TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_error_events_issue ON error_events(issue_id);
  CREATE INDEX IF NOT EXISTS idx_error_events_ts ON error_events(timestamp);

  CREATE TABLE IF NOT EXISTS perf_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL DEFAULT 'dockfolio',
    endpoint TEXT NOT NULL,
    hour TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    p50_ms INTEGER,
    p95_ms INTEGER,
    p99_ms INTEGER,
    error_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(app_slug, endpoint, hour)
  );
  CREATE INDEX IF NOT EXISTS idx_perf_metrics_hour ON perf_metrics(hour);

  CREATE TABLE IF NOT EXISTS uptime_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL,
    response_ms INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_uptime_app_ts ON uptime_history(app_slug, checked_at);

  CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT,
    metric TEXT NOT NULL,
    operator TEXT NOT NULL,
    threshold TEXT NOT NULL,
    window_minutes INTEGER DEFAULT 5,
    action TEXT DEFAULT 'telegram',
    enabled INTEGER DEFAULT 1,
    last_fired_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS maintenance_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    day_of_week INTEGER NOT NULL,
    start_hour INTEGER NOT NULL,
    start_minute INTEGER NOT NULL DEFAULT 0,
    duration_minutes INTEGER NOT NULL DEFAULT 120,
    suppress_alerts INTEGER NOT NULL DEFAULT 1,
    auto_restart INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Log aggregation tables (FTS5 for full-text search across all containers)
db.exec(`
  CREATE TABLE IF NOT EXISTS container_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_name TEXT NOT NULL,
    app_slug TEXT,
    stream TEXT NOT NULL DEFAULT 'stdout',
    line TEXT NOT NULL,
    logged_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_container_logs_ts ON container_logs(logged_at);
  CREATE INDEX IF NOT EXISTS idx_container_logs_app ON container_logs(app_slug, logged_at);
  CREATE INDEX IF NOT EXISTS idx_container_logs_container ON container_logs(container_name, logged_at);
`);

// FTS5 virtual table for full-text search (separate exec — CREATE VIRTUAL TABLE can't be IF NOT EXISTS in all SQLite versions)
try {
  db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS container_logs_fts USING fts5(line, container_name, app_slug, content='container_logs', content_rowid='id')`);
} catch { /* already exists */ }

// Triggers to keep FTS index in sync
try {
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS container_logs_ai AFTER INSERT ON container_logs BEGIN
      INSERT INTO container_logs_fts(rowid, line, container_name, app_slug) VALUES (new.id, new.line, new.container_name, new.app_slug);
    END;
    CREATE TRIGGER IF NOT EXISTS container_logs_ad AFTER DELETE ON container_logs BEGIN
      INSERT INTO container_logs_fts(container_logs_fts, rowid, line, container_name, app_slug) VALUES('delete', old.id, old.line, old.container_name, old.app_slug);
    END;
  `);
} catch { /* already exists */ }

// In-house analytics tables (replace Plausible dependency)
db.exec(`
  CREATE TABLE IF NOT EXISTS page_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    url TEXT NOT NULL,
    referrer TEXT,
    user_agent TEXT,
    country TEXT,
    session_id TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_pv_app_ts ON page_views(app_slug, created_at);
  CREATE INDEX IF NOT EXISTS idx_pv_url ON page_views(url);

  CREATE TABLE IF NOT EXISTS analytics_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    date TEXT NOT NULL,
    visitors INTEGER DEFAULT 0,
    pageviews INTEGER DEFAULT 0,
    top_pages TEXT,
    top_referrers TEXT,
    countries TEXT,
    UNIQUE(app_slug, date)
  );
  CREATE INDEX IF NOT EXISTS idx_ad_app_date ON analytics_daily(app_slug, date);

  CREATE TABLE IF NOT EXISTS analytics_hourly (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    hour TEXT NOT NULL,
    visitors INTEGER DEFAULT 0,
    pageviews INTEGER DEFAULT 0,
    UNIQUE(app_slug, hour)
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS github_cache (
    app_slug TEXT NOT NULL,
    data_json TEXT NOT NULL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app_slug)
  );
`);

// --- FTS5 Command Palette Index ---
db.exec(`DROP TABLE IF EXISTS command_search_fts`);
db.exec(`
  CREATE VIRTUAL TABLE command_search_fts USING fts5(
    type, key, name, description, extra,
    tokenize='unicode61'
  )
`);

// Populate FTS5 index with apps and built-in commands
const ftsInsert = db.prepare('INSERT INTO command_search_fts (type, key, name, description, extra) VALUES (?, ?, ?, ?, ?)');
const populateFts = db.transaction(() => {
  for (const appDef of (config.apps || [])) {
    const slug = slugify(appDef.name);
    const containers = (appDef.containers || []).join(' ');
    ftsInsert.run('app', slug, appDef.name, appDef.description || '', `${slug} ${appDef.domain || ''} ${containers}`);
  }

  const commands = [
    { cmd: 'briefing', label: 'Morning Briefing', description: 'AI-generated operations summary' },
    { cmd: 'revenue', label: 'Revenue Dashboard', description: 'Open marketing revenue tab' },
    { cmd: 'seo', label: 'SEO Audit', description: 'Open marketing SEO tab' },
    { cmd: 'backups', label: 'Backup Status', description: 'Show database backup panel' },
    { cmd: 'prune', label: 'Docker Prune', description: 'Clean up unused containers/images' },
    { cmd: 'status', label: 'System Status', description: 'Show system metrics' },
    { cmd: 'healing', label: 'Auto-Healing Log', description: 'Show recent auto-healing actions' },
    { cmd: 'emails', label: 'Email Sequences', description: 'Open marketing emails tab' },
    { cmd: 'content', label: 'Content Pipeline', description: 'Open marketing content tab' },
    { cmd: 'cohorts', label: 'Customer Cohorts', description: 'Open revenue cohorts subtab' },
    { cmd: 'keys', label: 'API Key Health', description: 'Show API key validation status' },
    { cmd: 'ssl', label: 'SSL Certificates', description: 'Show SSL certificate expiry' },
    { cmd: 'crosspromo', label: 'Cross-Promotion', description: 'Manage cross-app promotion campaigns' },
    { cmd: 'banners', label: 'Banner Manager', description: 'Create and manage ad banners across sites' },
    { cmd: 'playbook', label: 'Marketing Playbook', description: 'AI-generated marketing strategies per app' },
    { cmd: 'security', label: 'Security Manager', description: 'Docker security audit and scoring' },
    { cmd: 'projects', label: 'Projects Manager', description: 'App lifecycle, tasks, roadmap, insights' },
    { cmd: 'tasks', label: 'Project Tasks', description: 'View and manage project tasks' },
    { cmd: 'roadmap', label: 'Product Roadmap', description: 'Feature planning and milestones' },
    { cmd: 'overdue', label: 'Overdue Tasks', description: 'Show tasks past their due date' },
    { cmd: 'ops', label: 'Ops Intelligence', description: 'Worry score, drift detection, report cards' },
    { cmd: 'worry', label: 'Worry Score', description: 'Current ops worry score breakdown' },
    { cmd: 'drift', label: 'Config Drift', description: 'Detect changes since last baseline' },
    { cmd: 'reportcards', label: 'Report Cards', description: 'Per-app health scorecards' },
    { cmd: 'playground', label: 'API Playground', description: 'Interactive API explorer' },
    { cmd: 'notifications', label: 'Notification Center', description: 'View all alerts and events' },
    { cmd: 'containermap', label: 'Container Map', description: 'Visual network graph of container dependencies' },
    { cmd: 'uptime', label: 'Uptime Timeline', description: '24h container uptime history with state transitions' },
    { cmd: 'updates', label: 'Image Updates', description: 'Check for Docker image updates across containers' },
  ];
  for (const c of commands) {
    ftsInsert.run('command', c.cmd, c.label, c.description, c.cmd);
  }
});
populateFts();

const TRANSPARENT_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

const upsertMetric = db.prepare(`
  INSERT INTO metrics_daily (app_slug, date, metric_type, value, metadata)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(app_slug, date, metric_type) DO UPDATE SET value = excluded.value, metadata = excluded.metadata
`);

// --- Prepared Query Helpers ---
const qLatestMetric = db.prepare('SELECT value, metadata FROM metrics_daily WHERE app_slug = ? AND metric_type = ? ORDER BY date DESC LIMIT 1');
const qLatestSEO = db.prepare('SELECT score, grade, checks FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1');

const upsertSEOAudit = db.prepare(`
  INSERT INTO seo_audits (app_slug, date, score, grade, checks)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(app_slug, date) DO UPDATE SET score = excluded.score, grade = excluded.grade, checks = excluded.checks
`);

// --- Error Tracking ---

const insertErrorEvent = db.prepare(`
  INSERT INTO error_events (issue_id, app_slug, message, stack_trace, source, container_name, request_url, request_method, breadcrumbs, extra)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

// Rate tracking for Telegram spike alerts
const errorRateTracker = new Map(); // appSlug -> { count, windowStart }
const errorSpikeAlerted = new Map(); // appSlug -> lastAlertTimestamp

function ingestError({ app: appSlug, message, stack, severity = 'error', source = 'api', container, url, method, breadcrumbs, extra }) {
  if (!message || !appSlug) return { ok: false, error: 'message and app required' };

  const fp = errorFingerprint(message, stack, appSlug);
  const title = message.length > 200 ? message.slice(0, 200) + '...' : message;
  const validSeverity = ['critical', 'error', 'warning', 'info'].includes(severity) ? severity : 'error';

  // Upsert the issue
  const existing = db.prepare('SELECT id, status, occurrence_count FROM error_issues WHERE fingerprint = ?').get(fp);
  let issueId, isNew = false;

  if (existing) {
    issueId = existing.id;
    const newCount = existing.occurrence_count + 1;
    // Auto-reopen resolved issues
    if (existing.status === 'resolved') {
      db.prepare("UPDATE error_issues SET status = 'open', last_seen = datetime('now'), occurrence_count = occurrence_count + 1, resolved_at = NULL WHERE id = ?").run(issueId);
      if (validSeverity === 'critical' || validSeverity === 'error') {
        sendTelegram(`🔁 Reopened: ${appSlug}\n${title}\nWas resolved, occurred again (#${newCount})`);
      }
    } else {
      db.prepare("UPDATE error_issues SET last_seen = datetime('now'), occurrence_count = occurrence_count + 1 WHERE id = ?").run(issueId);
      // Alert at milestones for critical errors
      if (validSeverity === 'critical' && [10, 50, 100, 500].includes(newCount)) {
        sendTelegram(`🔥 Recurring critical: ${appSlug}\n${title}\nOccurrences: ${newCount}`);
      }
    }
  } else {
    isNew = true;
    const result = db.prepare('INSERT INTO error_issues (fingerprint, app_slug, severity, title, metadata) VALUES (?, ?, ?, ?, ?)').run(
      fp, appSlug, validSeverity, title, JSON.stringify({ source, container })
    );
    issueId = result.lastInsertRowid;
  }

  // Cap events: max 100 per issue per day
  const today = todayString();
  const todayCount = db.prepare("SELECT COUNT(*) as n FROM error_events WHERE issue_id = ? AND timestamp >= ?").get(issueId, today + 'T00:00:00');
  if ((todayCount?.n || 0) < 100) {
    insertErrorEvent.run(issueId, appSlug, message, stack || null, source, container || null, url || null, method || null,
      breadcrumbs ? JSON.stringify(breadcrumbs) : null, extra ? JSON.stringify(extra) : null);
  }

  // Telegram alert for new error fingerprints (critical/error only)
  if (isNew && (validSeverity === 'critical' || validSeverity === 'error')) {
    sendTelegram(`🐛 New ${validSeverity}: ${appSlug}\n${title}${source !== 'api' ? `\nSource: ${source}` : ''}`);
  }

  // Rate spike detection (>20 errors in 5 min for one app)
  const now = Date.now();
  const tracker = errorRateTracker.get(appSlug) || { count: 0, windowStart: now };
  if (now - tracker.windowStart > 300_000) {
    tracker.count = 1;
    tracker.windowStart = now;
  } else {
    tracker.count++;
  }
  errorRateTracker.set(appSlug, tracker);

  if (tracker.count > 20) {
    const lastAlert = errorSpikeAlerted.get(appSlug) || 0;
    if (now - lastAlert > MS_PER_HOUR) { // max once per hour per app
      errorSpikeAlerted.set(appSlug, now);
      sendTelegram(`⚡ Error spike: ${appSlug} — ${tracker.count} errors in 5 min`);
    }
  }

  return { ok: true, issue_id: issueId, is_new: isNew, fingerprint: fp };
}

// --- Stripe Revenue ---

function getStripeKeys() {
  const keys = new Map(); // stripeKey -> [appNames]
  const appKeys = new Map(); // appName -> stripeKey
  for (const appDef of config.apps) {
    if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
    const vars = parseEnvFile(appDef.envFile);
    const sk = vars.find(v => v.key === 'STRIPE_SECRET_KEY' && v.value);
    if (sk) {
      appKeys.set(appDef.name, sk.value);
      if (!keys.has(sk.value)) keys.set(sk.value, []);
      keys.get(sk.value).push(appDef.name);
    }
  }
  // Fallback: check settings DB for a global Stripe key
  if (keys.size === 0) {
    const dbKey = getSetting('STRIPE_SECRET_KEY');
    if (dbKey) {
      keys.set(dbKey, ['(global)']);
      appKeys.set('(global)', dbKey);
    }
  }
  return { keys, appKeys };
}

async function fetchStripeData(secretKey) {
  const headers = {
    'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64'),
  };
  const opts = { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) };

  try {
    const [balanceRes, chargesRes] = await Promise.all([
      fetch(`${STRIPE_API}/balance`, opts),
      fetch(`${STRIPE_API}/charges?limit=10`, opts),
    ]);

    const balance = balanceRes.ok ? await balanceRes.json() : null;
    const charges = chargesRes.ok ? await chargesRes.json() : null;

    // Get MRR from active subscriptions
    const subsRes = await fetch(`${STRIPE_API}/subscriptions?status=active&limit=100`, opts);
    const subs = subsRes.ok ? await subsRes.json() : null;

    let mrr = 0;
    if (subs?.data) {
      for (const sub of subs.data) {
        for (const item of sub.items?.data || []) {
          const amount = item.price?.unit_amount || 0;
          const interval = item.price?.recurring?.interval;
          if (interval === 'month') mrr += amount;
          else if (interval === 'year') mrr += Math.round(amount / 12);
        }
      }
    }

    // Revenue last 30 days
    const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 86400;
    const revenueRes = await fetch(`${STRIPE_API}/charges?limit=100&created[gte]=${thirtyDaysAgo}`, opts);
    const revenueData = revenueRes.ok ? await revenueRes.json() : null;

    let revenue30d = 0;
    let chargeCount30d = 0;
    if (revenueData?.data) {
      for (const c of revenueData.data) {
        if (c.paid && !c.refunded) {
          revenue30d += c.amount;
          chargeCount30d++;
        }
      }
    }

    return {
      balance: balance?.available?.[0]?.amount || 0,
      pending: balance?.pending?.[0]?.amount || 0,
      currency: balance?.available?.[0]?.currency || 'eur',
      mrr,
      revenue30d,
      chargeCount30d,
      recentCharges: (charges?.data || []).slice(0, 5).map(c => ({
        amount: c.amount,
        currency: c.currency,
        status: c.paid ? (c.refunded ? 'refunded' : 'paid') : 'failed',
        created: c.created,
        description: c.description || c.metadata?.product || '',
      })),
      activeSubscriptions: subs?.data?.length || 0,
    };
  } catch (err) {
    return { error: err.message };
  }
}

let cachedRevenue = null;
let lastRevenueUpdate = 0;
const REVENUE_TTL = 300_000; // 5 min

app.get('/api/marketing/revenue', asyncRoute(async (req, res) => {
  const now = Date.now();
  const force = req.query.force === 'true';
  if (!force && cachedRevenue && (now - lastRevenueUpdate) < REVENUE_TTL) {
    return res.json(cachedRevenue);
  }

  const { keys, appKeys } = getStripeKeys();
  const results = {};
  let totalMRR = 0, totalRevenue30d = 0, totalBalance = 0;

  // Deduplicate: fetch each unique key once
  const keyResults = new Map();
  for (const [key, appNames] of keys) {
    const data = await cbStripe.call(() => fetchStripeData(key));
    keyResults.set(key, data);
  }

  // Map results to apps
  for (const [appName, key] of appKeys) {
    const data = keyResults.get(key);
    if (!data) continue;
    const appsWithKey = keys.get(key);
    // For shared keys, show full data but mark as shared
    results[appName] = {
      ...data,
      shared: appsWithKey.length > 1,
      sharedWith: appsWithKey.filter(n => n !== appName),
    };
    // Only count revenue once per unique key (attribute to first app)
    if (appsWithKey[0] === appName) {
      totalMRR += data.mrr || 0;
      totalRevenue30d += data.revenue30d || 0;
      totalBalance += data.balance || 0;
    }
  }

  cachedRevenue = {
    apps: results,
    totals: {
      mrr: totalMRR,
      revenue30d: totalRevenue30d,
      balance: totalBalance,
      currency: 'eur',
    },
    timestamp: new Date().toISOString(),
  };
  lastRevenueUpdate = now;

  // Store daily snapshot
  const today = todayString();
  try {
    upsertMetric.run('_total', today, 'mrr', totalMRR / 100, null);
    upsertMetric.run('_total', today, 'revenue_30d', totalRevenue30d / 100, null);
    for (const [appName, data] of Object.entries(results)) {
      if (data.mrr != null) upsertMetric.run(slugify(appName), today, 'mrr', data.mrr / 100, null);
    }
  } catch (err) { console.error('[METRICS] Revenue snapshot failed:', err.message); }

  res.json(cachedRevenue);
}));

// --- Plausible Analytics ---

function getPlausibleUrl() { return getSetting('PLAUSIBLE_URL') || process.env.PLAUSIBLE_URL || 'http://plausible-plausible-1:8000'; }
function getPlausibleApiKey() { return getSetting('PLAUSIBLE_API_KEY') || process.env.PLAUSIBLE_API_KEY || ''; }

async function fetchPlausibleStats(domain, period = '30d') {
  try {
    const baseUrl = `${getPlausibleUrl()}/api/v1/stats`;
    const apiKey = getPlausibleApiKey();
    const headers = apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {};
    const opts = { signal: AbortSignal.timeout(TIMEOUT_STANDARD), headers };

    const [realtimeRes, aggregateRes, topPagesRes, topSourcesRes] = await Promise.all([
      fetch(`${baseUrl}/realtime/visitors?site_id=${domain}`, opts),
      fetch(`${baseUrl}/aggregate?site_id=${domain}&period=${period}&metrics=visitors,pageviews,bounce_rate,visit_duration`, opts),
      fetch(`${baseUrl}/breakdown?site_id=${domain}&period=${period}&property=event:page&limit=5&metrics=visitors`, opts),
      fetch(`${baseUrl}/breakdown?site_id=${domain}&period=${period}&property=visit:source&limit=5&metrics=visitors`, opts),
    ]);

    const realtime = realtimeRes.ok ? await realtimeRes.text() : '0';
    const aggregate = aggregateRes.ok ? await aggregateRes.json() : null;
    const topPages = topPagesRes.ok ? await topPagesRes.json() : null;
    const topSources = topSourcesRes.ok ? await topSourcesRes.json() : null;

    return {
      realtime: parseInt(realtime) || 0,
      visitors: aggregate?.results?.visitors?.value || 0,
      pageviews: aggregate?.results?.pageviews?.value || 0,
      bounceRate: aggregate?.results?.bounce_rate?.value || 0,
      visitDuration: aggregate?.results?.visit_duration?.value || 0,
      topPages: (topPages?.results || []).map(p => ({ page: p.page, visitors: p.visitors })),
      topSources: (topSources?.results || []).map(s => ({ source: s.source, visitors: s.visitors })),
    };
  } catch (err) {
    return { error: err.message, visitors: 0, pageviews: 0 };
  }
}

let cachedAnalytics = null;
let lastAnalyticsUpdate = 0;
const ANALYTICS_TTL = 300_000; // 5 min

app.get('/api/marketing/analytics', asyncRoute(async (req, res) => {
  const now = Date.now();
  const force = req.query.force === 'true';
  if (!force && cachedAnalytics && (now - lastAnalyticsUpdate) < ANALYTICS_TTL) {
    return res.json(cachedAnalytics);
  }

  const trackableApps = config.apps.filter(a =>
    (a.type === 'saas' || a.type === 'tool' || a.type === 'static') && a.domain
  );

  const results = {};
  let totalVisitors = 0, totalPageviews = 0, totalRealtime = 0;

  await Promise.all(trackableApps.map(async (appDef) => {
    const stats = await cbPlausible.call(() => fetchPlausibleStats(appDef.domain));
    results[appDef.name] = { domain: appDef.domain, ...stats };
    totalVisitors += stats.visitors || 0;
    totalPageviews += stats.pageviews || 0;
    totalRealtime += stats.realtime || 0;
  }));

  cachedAnalytics = {
    apps: results,
    totals: { visitors: totalVisitors, pageviews: totalPageviews, realtime: totalRealtime },
    timestamp: new Date().toISOString(),
  };
  lastAnalyticsUpdate = now;

  // Store daily snapshot
  const today = todayString();
  try {
    upsertMetric.run('_total', today, 'visitors', totalVisitors, null);
    upsertMetric.run('_total', today, 'pageviews', totalPageviews, null);
    for (const [appName, data] of Object.entries(results)) {
      if (data.visitors != null) upsertMetric.run(slugify(appName), today, 'visitors', data.visitors, null);
    }
  } catch (err) { console.error('[METRICS] Analytics snapshot failed:', err.message); }

  res.json(cachedAnalytics);
}));

// GET /api/marketing/trends — historical metric data from SQLite
app.get('/api/marketing/trends', asyncRoute((req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 365);
  const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);

  const rows = db.prepare(`
    SELECT app_slug, date, metric_type, value
    FROM metrics_daily
    WHERE date >= ?
    ORDER BY date ASC
  `).all(cutoff);

  // Group by metric type
  const grouped = {};
  for (const row of rows) {
    const key = `${row.app_slug}::${row.metric_type}`;
    if (!grouped[key]) grouped[key] = { app: row.app_slug, metric: row.metric_type, data: [] };
    grouped[key].data.push({ date: row.date, value: row.value });
  }

  res.json({ trends: Object.values(grouped), days });
}));

// === Chart-optimized API endpoints ===

// GET /api/charts/revenue — MRR series per app, pre-formatted for Chart.js
app.get('/api/charts/revenue', asyncRoute((req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 365);
  const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);
  const rows = db.prepare(`
    SELECT app_slug, date, value FROM metrics_daily
    WHERE metric_type = 'mrr' AND date >= ?
    ORDER BY date ASC
  `).all(cutoff);
  const apps = {};
  const labels = new Set();
  for (const row of rows) {
    labels.add(row.date);
    if (!apps[row.app_slug]) apps[row.app_slug] = {};
    apps[row.app_slug][row.date] = row.value / 100; // cents to euros
  }
  const sortedLabels = [...labels].sort();
  const datasets = Object.entries(apps).map(([slug, data]) => ({
    label: slug,
    data: sortedLabels.map(d => data[d] || 0)
  }));
  // Add total line
  const totalData = sortedLabels.map(d => datasets.reduce((sum, ds) => sum + (ds.data[sortedLabels.indexOf(d)] || 0), 0));
  res.json({ labels: sortedLabels, datasets, total: totalData });
}));

// GET /api/charts/traffic — visitors/pageviews per app per day
app.get('/api/charts/traffic', asyncRoute((req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 365);
  const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);
  const rows = db.prepare(`
    SELECT app_slug, date, visitors, pageviews FROM analytics_daily
    WHERE date >= ?
    ORDER BY date ASC
  `).all(cutoff);
  const labels = new Set();
  const visitors = {};
  const pageviews = {};
  for (const row of rows) {
    labels.add(row.date);
    if (!visitors[row.app_slug]) { visitors[row.app_slug] = {}; pageviews[row.app_slug] = {}; }
    visitors[row.app_slug][row.date] = row.visitors || 0;
    pageviews[row.app_slug][row.date] = row.pageviews || 0;
  }
  const sortedLabels = [...labels].sort();
  const visitorDatasets = Object.entries(visitors).map(([slug, data]) => ({
    label: slug, data: sortedLabels.map(d => data[d] || 0)
  }));
  const totalVisitors = sortedLabels.map(d => visitorDatasets.reduce((sum, ds) => sum + (ds.data[sortedLabels.indexOf(d)] || 0), 0));
  res.json({ labels: sortedLabels, visitors: visitorDatasets, totalVisitors });
}));

// GET /api/charts/errors — error counts by severity per day
app.get('/api/charts/errors', asyncRoute((req, res) => {
  const days = Math.min(parseInt(req.query.days) || 7, 365);
  const cutoff = formatDateISO(Date.now() - days * MS_PER_DAY);
  const rows = db.prepare(`
    SELECT date(timestamp) as day, severity, COUNT(*) as count
    FROM error_events
    WHERE timestamp >= ?
    GROUP BY day, severity
    ORDER BY day ASC
  `).all(cutoff);
  const labels = new Set();
  const bySeverity = {};
  for (const row of rows) {
    labels.add(row.day);
    if (!bySeverity[row.severity]) bySeverity[row.severity] = {};
    bySeverity[row.severity][row.day] = row.count;
  }
  const sortedLabels = [...labels].sort();
  const datasets = Object.entries(bySeverity).map(([sev, data]) => ({
    label: sev, data: sortedLabels.map(d => data[d] || 0)
  }));
  res.json({ labels: sortedLabels, datasets });
}));

// GET /api/charts/latency — hourly p50/p95/p99 aggregates
app.get('/api/charts/latency', asyncRoute((req, res) => {
  const hours = Math.min(parseInt(req.query.hours) || 168, 8760);
  const cutoff = new Date(Date.now() - hours * MS_PER_HOUR).toISOString().slice(0, 13);
  const rows = db.prepare(`
    SELECT hour, SUM(request_count) as requests,
           AVG(p50_ms) as p50, AVG(p95_ms) as p95, AVG(p99_ms) as p99
    FROM perf_metrics
    WHERE hour >= ?
    GROUP BY hour
    ORDER BY hour ASC
  `).all(cutoff);
  res.json({
    labels: rows.map(r => r.hour),
    p50: rows.map(r => Math.round(r.p50 || 0)),
    p95: rows.map(r => Math.round(r.p95 || 0)),
    p99: rows.map(r => Math.round(r.p99 || 0)),
    requests: rows.map(r => r.requests)
  });
}));

// GET /api/charts/uptime — per-app status per hour (heatmap data)
app.get('/api/charts/uptime', asyncRoute((req, res) => {
  const days = Math.min(parseInt(req.query.days) || 7, 365);
  const cutoff = new Date(Date.now() - days * MS_PER_DAY).toISOString();
  const rows = db.prepare(`
    SELECT app_slug, strftime('%Y-%m-%d %H:00', checked_at) as hour,
           SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count,
           SUM(CASE WHEN status = 'down' THEN 1 ELSE 0 END) as down_count,
           AVG(response_ms) as avg_response
    FROM uptime_history
    WHERE checked_at >= ?
    GROUP BY app_slug, hour
    ORDER BY hour ASC
  `).all(cutoff);
  const apps = {};
  for (const row of rows) {
    if (!apps[row.app_slug]) apps[row.app_slug] = [];
    apps[row.app_slug].push({
      hour: row.hour,
      status: row.down_count > 0 ? 'down' : 'up',
      avgMs: Math.round(row.avg_response || 0)
    });
  }
  res.json({ apps, days });
}));

// GET /api/charts/sparklines — 24h CPU/memory sparklines per container (for app cards)
app.get('/api/charts/sparklines', asyncRoute((req, res) => {
  const cutoff = new Date(Date.now() - 24 * MS_PER_HOUR).toISOString();
  const rows = db.prepare(`
    SELECT container_name, app_slug, ts, cpu, memory
    FROM container_metrics
    WHERE ts >= ?
    ORDER BY ts ASC
  `).all(cutoff);
  const containers = {};
  for (const row of rows) {
    if (!containers[row.container_name]) containers[row.container_name] = { app_slug: row.app_slug, cpu: [], memory: [] };
    containers[row.container_name].cpu.push(row.cpu);
    containers[row.container_name].memory.push(row.memory);
  }
  res.json(containers);
}));

// GET /api/containers/:name/sparkline — 24h CPU/memory sparkline for a single container
app.get('/api/containers/:name/sparkline', asyncRoute((req, res) => {
  const cutoff = new Date(Date.now() - 24 * MS_PER_HOUR).toISOString();
  const rows = db.prepare(`
    SELECT ts, cpu, memory FROM container_metrics
    WHERE container_name = ? AND ts >= ?
    ORDER BY ts ASC
  `).all(req.params.name, cutoff);
  res.json({
    container: req.params.name,
    points: rows.map(r => ({ ts: r.ts, cpu: Math.round(r.cpu * 100) / 100, memoryMB: Math.round(r.memory / (1024 * 1024) * 10) / 10 }))
  });
}));

// GET /api/apps/:slug/sparkline — aggregated 24h sparkline for all containers of an app
app.get('/api/apps/:slug/sparkline', asyncRoute((req, res) => {
  const cutoff = new Date(Date.now() - 24 * MS_PER_HOUR).toISOString();
  const rows = db.prepare(`
    SELECT ts, SUM(cpu) as cpu, SUM(memory) as memory FROM container_metrics
    WHERE app_slug = ? AND ts >= ?
    GROUP BY ts
    ORDER BY ts ASC
  `).all(req.params.slug, cutoff);
  res.json({
    app: req.params.slug,
    points: rows.map(r => ({ ts: r.ts, cpu: Math.round(r.cpu * 100) / 100, memoryMB: Math.round(r.memory / (1024 * 1024) * 10) / 10 }))
  });
}));

// GET /api/marketing/health — portfolio health scores
app.get('/api/marketing/health', asyncRoute(async (req, res) => {
  const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
  const scores = {};

  for (const appDef of marketableApps) {
    let score = 50; // base
    const factors = {};

    // SEO score (from cache)
    if (cachedSEO?.apps?.[appDef.name]) {
      const seoScore = cachedSEO.apps[appDef.name].score;
      factors.seo = seoScore;
      score += (seoScore - 50) * 0.3; // weight 30%
    }

    // Revenue (from cache)
    if (cachedRevenue?.apps?.[appDef.name]) {
      const rev = cachedRevenue.apps[appDef.name];
      if (rev.mrr > 0) {
        factors.mrr = rev.mrr / 100;
        score += 15; // has revenue = +15
      }
      if (rev.activeSubscriptions > 0) {
        factors.subscriptions = rev.activeSubscriptions;
        score += 5;
      }
    }

    // Analytics (from cache)
    if (cachedAnalytics?.apps?.[appDef.name]) {
      const analytics = cachedAnalytics.apps[appDef.name];
      if (analytics.visitors > 100) score += 10;
      else if (analytics.visitors > 10) score += 5;
      factors.visitors = analytics.visitors;
    }

    scores[appDef.name] = {
      score: Math.max(0, Math.min(100, Math.round(score))),
      factors,
    };
  }

  const avgScore = Object.values(scores).length > 0
    ? Math.round(Object.values(scores).reduce((s, v) => s + v.score, 0) / Object.values(scores).length)
    : 0;

  res.json({ apps: scores, avgScore, timestamp: new Date().toISOString() });
}));

// --- Cron: collect data periodically ---
// Every 6 hours: collect revenue + analytics
cron.schedule('0 */6 * * *', async () => {
  console.log('[CRON] Collecting revenue data...');
  try {
    const { keys, appKeys } = getStripeKeys();
    const today = todayString();
    let totalMRR = 0;
    const keyResults = new Map();
    for (const [key, appNames] of keys) {
      const data = await cbStripe.call(() => fetchStripeData(key));
      keyResults.set(key, data);
      if (data.mrr) totalMRR += data.mrr;
    }
    upsertMetric.run('_total', today, 'mrr', totalMRR / 100, null);
    for (const [appName, key] of appKeys) {
      const data = keyResults.get(key);
      if (data?.mrr != null) upsertMetric.run(slugify(appName), today, 'mrr', data.mrr / 100, null);
    }
    console.log('[CRON] Revenue data collected');
  } catch (err) {
    cronFail('Revenue refresh', err);
  }
});

// Daily at 1:30 AM: run SEO audits and store
cron.schedule('30 1 * * *', async () => {
  console.log('[CRON] Running daily SEO audits...');
  try {
    const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const today = todayString();
    for (const appDef of marketableApps) {
      const audit = await auditSEO(appDef.domain);
      upsertSEOAudit.run(slugify(appDef.name), today, audit.score, audit.grade, JSON.stringify(audit.checks));
      upsertMetric.run(slugify(appDef.name), today, 'seo_score', audit.score, null);
    }
    console.log('[CRON] SEO audits stored');
  } catch (err) {
    cronFail('SEO audit', err);
  }
});

// === Feature: AI SEO Content Pipeline ===

// --- Settings DB helpers ---
const getSettingStmt = db.prepare('SELECT value FROM settings WHERE key = ?');
const upsertSettingStmt = db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, datetime(\'now\')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime(\'now\')');
const deleteSettingStmt = db.prepare('DELETE FROM settings WHERE key = ?');
const allSettingsStmt = db.prepare('SELECT key, value FROM settings');

function getSetting(key) {
  const row = getSettingStmt.get(key);
  return row ? row.value : null;
}

// Load persisted maintenance state now that getSetting is available
loadMaintenanceState();

const INTEGRATION_KEYS = [
  { key: 'STRIPE_SECRET_KEY', label: 'Stripe Secret Key', category: 'Payments', validatable: true },
  { key: 'ANTHROPIC_API_KEY', label: 'Anthropic API Key', category: 'AI', validatable: true },
  { key: 'REPLICATE_API_TOKEN', label: 'Replicate API Token', category: 'AI', validatable: false },
  { key: 'RESEND_API_KEY', label: 'Resend API Key', category: 'Email', validatable: true },
  { key: 'PLAUSIBLE_API_KEY', label: 'Plausible API Key', category: 'Analytics', validatable: false },
  { key: 'PLAUSIBLE_URL', label: 'Plausible URL', category: 'Analytics', validatable: false },
  { key: 'TELEGRAM_BOT_TOKEN', label: 'Telegram Bot Token', category: 'Notifications', validatable: false },
  { key: 'TELEGRAM_CHAT_ID', label: 'Telegram Chat ID', category: 'Notifications', validatable: false },
  { key: 'BANNERFORGE_URL', label: 'BannerForge URL', category: 'Integrations', validatable: false },
  { key: 'GITHUB_WEBHOOK_SECRET', label: 'GitHub Webhook Secret', category: 'Integrations', validatable: false },
];
const INTEGRATION_KEY_SET = new Set(INTEGRATION_KEYS.map(k => k.key));

function getEnvKeyFromApps(envKeyName) {
  // Check settings DB first
  const dbVal = getSetting(envKeyName);
  if (dbVal) return dbVal;
  for (const appDef of config.apps) {
    if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
    const vars = parseEnvFile(appDef.envFile);
    const found = vars.find(v => v.key === envKeyName && v.value);
    if (found) return found.value;
  }
  return null;
}

function getAnthropicKey() { return getEnvKeyFromApps('ANTHROPIC_API_KEY'); }
function getResendKey() { return getEnvKeyFromApps('RESEND_API_KEY'); }

const CONTENT_PROMPTS = {
  meta_description: (keyword, appDef) =>
    `Write a compelling meta description (150-160 chars) for "${appDef.domain}" targeting the keyword "${keyword}". Include a clear value proposition and call to action.`,
  title: (keyword, appDef) =>
    `Write an SEO-optimized page title (50-60 chars) for "${appDef.domain}" targeting "${keyword}". Make it compelling and include the brand name.`,
  blog_outline: (keyword, appDef) =>
    `Create a detailed blog post outline for an article targeting "${keyword}" for ${appDef.name} (${appDef.description || ''}). Include 5-7 H2 sections with 2-3 H3 sub-points each. Output as markdown headings only, no full content.`,
  faq_schema: (keyword, appDef) =>
    `Generate 5 FAQ questions and concise answers about "${keyword}" for ${appDef.name}. Format as a numbered list with Q: and A: prefixes. Questions should target common user queries.`,
  comparison_page: (keyword, appDef) =>
    `Outline a comparison page for "${appDef.name} vs alternatives" targeting "${keyword}". List 6-8 comparison criteria with brief notes on differentiators. Format as a markdown table outline.`,
};

function buildContentSystemPrompt(appDef, seoData) {
  const issues = seoData?.issues?.map(i => `- ${i.msg}`).join('\n') || 'No known issues';
  const m = appDef.marketing || {};
  return `You are an SEO content specialist for ${appDef.name}, a ${appDef.description || 'web application'}.
Target audience: ${m.targetAudience || 'general users'}
Tagline: ${m.tagline || ''}
Languages: ${(m.languages || ['en']).join(', ')}
Domain: ${appDef.domain}

Current SEO issues:
${issues}

Write in the primary language listed above. Be concise and conversion-focused. Output only the requested content with no meta-commentary or preamble.`;
}

function formatContentTitle(contentType, keyword) {
  return `${contentType.replace(/_/g, ' ')}: ${keyword}`;
}

function deriveKeywords(appDef) {
  const m = appDef.marketing || {};
  const keywords = [];
  if (m.tagline) keywords.push(m.tagline);
  if (m.targetAudience) {
    for (const seg of m.targetAudience.split(',')) {
      const trimmed = seg.trim();
      if (trimmed) keywords.push(`${appDef.name} for ${trimmed}`);
    }
  }
  if (appDef.description) keywords.push(appDef.description);
  return keywords.slice(0, 3);
}

async function generateContent(appSlug, contentType, keyword) {
  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) throw new Error('No Anthropic API key found in any app .env file');

  const appDef = findAppBySlug(appSlug);
  if (!appDef) throw new Error(`App not found: ${appSlug}`);

  const promptFn = CONTENT_PROMPTS[contentType];
  if (!promptFn) throw new Error(`Unknown content type: ${contentType}`);

  const seoData = cachedSEO?.apps?.[appDef.name];
  const systemPrompt = buildContentSystemPrompt(appDef, seoData);
  const userPrompt = promptFn(keyword, appDef);

  const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
    model: 'claude-sonnet-4-20250514', maxTokens: 1024, timeout: TIMEOUT_AI,
    system: systemPrompt, messages: [{ role: 'user', content: userPrompt }],
  }));

  return { body: ai.text, tokenCount: ai.tokens };
}

// Content Pipeline endpoints
app.get('/api/marketing/content', asyncRoute((_req, res) => {
  const { app_slug, status } = _req.query;
  let where = '1=1';
  const params = [];
  if (app_slug) { where += ' AND app_slug = ?'; params.push(app_slug); }
  if (status) { where += ' AND status = ?'; params.push(status); }

  const items = db.prepare(`SELECT * FROM content_queue WHERE ${where} ORDER BY created_at DESC LIMIT 100`).all(...params);
  const counts = db.prepare(`SELECT status, COUNT(*) as count FROM content_queue GROUP BY status`).all();
  const countMap = {};
  for (const c of counts) countMap[c.status] = c.count;

  res.json({ items, counts: countMap });
}));

app.post('/api/marketing/content/generate', asyncRoute(async (req, res) => {
  const { app_slug, content_type, keyword } = req.body;
  if (!app_slug || !content_type || !keyword) {
    return res.status(400).json({ error: 'app_slug, content_type, and keyword are required' });
  }

  console.log(`[CONTENT] Generating ${content_type} for ${app_slug} (keyword: ${keyword})`);
  const { body, tokenCount } = await generateContent(app_slug, content_type, keyword);
  const title = formatContentTitle(content_type, keyword);

  const result = db.prepare(`
    INSERT INTO content_queue (app_slug, content_type, keyword, title, body, token_count)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(app_slug, content_type, keyword, title, body, tokenCount);

  console.log(`[CONTENT] Generated id=${result.lastInsertRowid}, tokens=${tokenCount}`);
  res.json({ ok: true, id: result.lastInsertRowid, body, tokenCount });
}));

app.patch('/api/marketing/content/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid content ID' });

  const { status, published_at } = req.body;
  const validStatuses = ['draft', 'approved', 'published', 'rejected'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` });
  }

  if (status === 'published' && published_at) {
    db.prepare('UPDATE content_queue SET status = ?, published_at = ? WHERE id = ?').run(status, published_at, id);
  } else {
    db.prepare('UPDATE content_queue SET status = ? WHERE id = ?').run(status, id);
  }

  res.json({ ok: true });
}));

// DELETE /api/marketing/content/:id — Delete content item
app.delete('/api/marketing/content/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid content ID' });
  const result = db.prepare('DELETE FROM content_queue WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Content not found' });
  res.json({ ok: true });
}));

// Weekly content generation cron — Sunday 3AM
cron.schedule('0 3 * * 0', async () => {
  console.log('[CRON] Starting weekly content generation...');
  try {
    const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const insertContent = db.prepare(`
      INSERT INTO content_queue (app_slug, content_type, keyword, title, body, token_count)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const contentTypes = ['meta_description', 'blog_outline', 'title'];
    let generated = 0;

    for (const appDef of marketableApps) {
      const slug = slugify(appDef.name);
      const keywords = deriveKeywords(appDef);

      for (let i = 0; i < Math.min(contentTypes.length, keywords.length); i++) {
        try {
          const { body, tokenCount } = await generateContent(slug, contentTypes[i], keywords[i]);
          const title = formatContentTitle(contentTypes[i], keywords[i]);
          insertContent.run(slug, contentTypes[i], keywords[i], title, body, tokenCount);
          generated++;
          // Rate limit: 2s between Anthropic calls
          await new Promise(r => setTimeout(r, 2000));
        } catch (err) {
          console.error(`[CRON] Content gen failed for ${slug}/${contentTypes[i]}:`, err.message);
        }
      }
    }
    console.log(`[CRON] Weekly content generation done: ${generated} items created`);
  } catch (err) {
    cronFail('Content generation', err);
  }
});

// === Feature: Cross-App Revenue Cohort Engine ===

function stripeHeaders(secretKey) {
  return { 'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64') };
}

async function paginateStripe(secretKey, endpoint, extraParams = '', maxPages = 50) {
  const headers = stripeHeaders(secretKey);
  const results = [];
  let startingAfter = null;
  let pages = 0;

  do {
    let url = `${STRIPE_API}/${endpoint}?limit=100`;
    if (extraParams) url += '&' + extraParams;
    if (startingAfter) url += '&starting_after=' + startingAfter;
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_MEDIUM) });
    if (!res.ok) {
      console.error(`[Stripe] ${endpoint} page ${pages} failed: ${res.status}`);
      break;
    }
    const data = await res.json();
    results.push(...(data.data || []));
    startingAfter = data.has_more ? data.data[data.data.length - 1]?.id : null;
    pages++;
    if (pages >= maxPages) break;
  } while (startingAfter);

  return results;
}

async function fetchStripeCustomers(secretKey) {
  return paginateStripe(secretKey, 'customers');
}

async function fetchStripeSubscriptionsMRR(secretKey) {
  const subs = await paginateStripe(secretKey, 'subscriptions', 'status=active');
  const mrrMap = new Map();
  for (const sub of subs) {
    const custId = typeof sub.customer === 'string' ? sub.customer : sub.customer?.id;
    if (!custId) continue;
    let mrr = 0;
    for (const item of (sub.items?.data || [])) {
      const amount = item.price?.unit_amount || 0;
      const interval = item.price?.recurring?.interval;
      if (interval === 'month') mrr += amount;
      else if (interval === 'year') mrr += Math.round(amount / 12);
    }
    mrrMap.set(custId, (mrrMap.get(custId) || 0) + mrr);
  }
  return mrrMap;
}

const upsertCustomer = db.prepare(`
  INSERT INTO customer_graph (email_hash, app_slug, stripe_customer_id, stripe_key_hash, mrr, first_seen, last_active, plan_name)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(email_hash, app_slug) DO UPDATE SET
    mrr = excluded.mrr, last_active = excluded.last_active, plan_name = excluded.plan_name
`);

async function collectCustomerGraph() {
  console.log('[CRON] Collecting customer graph...');
  const { keys } = getStripeKeys();
  const today = todayString();
  let totalCustomers = 0;

  for (const [stripeKey, appNames] of keys) {
    try {
      const keyHash = hashValue(stripeKey);
      const [customers, mrrMap] = await Promise.all([
        fetchStripeCustomers(stripeKey),
        fetchStripeSubscriptionsMRR(stripeKey)
      ]);

      for (const customer of customers) {
        if (!customer.email) continue;
        const emailHash = hashValue(customer.email.toLowerCase(), 64);
        const mrr = mrrMap.get(customer.id) || 0;
        const firstSeen = new Date(customer.created * 1000).toISOString().slice(0, 10);

        for (const appName of appNames) {
          upsertCustomer.run(emailHash, slugify(appName), customer.id, keyHash, mrr, firstSeen, today, null);
        }
        totalCustomers++;
      }
    } catch (err) {
      console.error(`[CRON] Customer graph error for ${appNames.join(',')}:`, err.message);
    }
  }

  console.log(`[CRON] Customer graph updated: ${totalCustomers} customers processed`);
}

// Cohort endpoints
app.get('/api/marketing/cohorts', asyncRoute((_req, res) => {
  const totalUnique = db.prepare('SELECT COUNT(DISTINCT email_hash) as n FROM customer_graph').get().n;
  const multiApp = db.prepare(`
    SELECT email_hash, COUNT(DISTINCT app_slug) as app_count, GROUP_CONCAT(DISTINCT app_slug) as apps
    FROM customer_graph GROUP BY email_hash HAVING app_count >= 2
  `).all();

  const singleAppCustomers = totalUnique - multiApp.length;
  const powerUsers = multiApp.filter(r => r.app_count >= 3).length;

  // Build overlap matrix
  const overlapMatrix = {};
  for (const row of multiApp) {
    const apps = row.apps.split(',');
    for (let i = 0; i < apps.length; i++) {
      for (let j = i + 1; j < apps.length; j++) {
        if (!overlapMatrix[apps[i]]) overlapMatrix[apps[i]] = {};
        if (!overlapMatrix[apps[j]]) overlapMatrix[apps[j]] = {};
        overlapMatrix[apps[i]][apps[j]] = (overlapMatrix[apps[i]][apps[j]] || 0) + 1;
        overlapMatrix[apps[j]][apps[i]] = (overlapMatrix[apps[j]][apps[i]] || 0) + 1;
      }
    }
  }

  const lastUpdated = db.prepare('SELECT MAX(last_active) as d FROM customer_graph').get()?.d;

  res.json({
    summary: {
      totalUniqueCustomers: totalUnique,
      singleAppCustomers,
      multiAppCustomers: multiApp.length,
      powerUsers,
      lastUpdated,
    },
    overlapMatrix,
  });
}));

// GET /api/marketing/cohorts/crosssell — cross-sell opportunities
app.get('/api/marketing/cohorts/crosssell', asyncRoute((_req, res) => {
  // Find customers who use one app but not another — these are cross-sell targets
  const appCustomerCounts = db.prepare(
    'SELECT app_slug, COUNT(DISTINCT email_hash) as customers FROM customer_graph GROUP BY app_slug'
  ).all();
  const countMap = Object.fromEntries(appCustomerCounts.map(r => [r.app_slug, r.customers]));

  // Find multi-app customers for overlap
  const multiApp = db.prepare(`
    SELECT email_hash, GROUP_CONCAT(DISTINCT app_slug) as apps
    FROM customer_graph GROUP BY email_hash HAVING COUNT(DISTINCT app_slug) >= 2
  `).all();

  // Build pairwise overlap counts
  const pairOverlap = {};
  for (const row of multiApp) {
    const apps = row.apps.split(',');
    for (let i = 0; i < apps.length; i++) {
      for (let j = i + 1; j < apps.length; j++) {
        const key = [apps[i], apps[j]].sort().join('|');
        pairOverlap[key] = (pairOverlap[key] || 0) + 1;
      }
    }
  }

  // Generate cross-sell opportunities for marketable app pairs
  const marketableSlugs = getMarketableApps(config.apps).map(a => slugify(a.name));
  const opportunities = [];

  for (let i = 0; i < marketableSlugs.length; i++) {
    for (let j = i + 1; j < marketableSlugs.length; j++) {
      const a = marketableSlugs[i], b = marketableSlugs[j];
      const key = [a, b].sort().join('|');
      const overlap = pairOverlap[key] || 0;
      const aCount = countMap[a] || 0;
      const bCount = countMap[b] || 0;
      if (aCount === 0 && bCount === 0) continue;

      // Potential: customers in A who aren't in B, plus vice versa
      const potentialReach = Math.max(0, (aCount - overlap)) + Math.max(0, (bCount - overlap));
      if (potentialReach === 0) continue;

      const appA = config.apps.find(x => slugify(x.name) === a);
      const appB = config.apps.find(x => slugify(x.name) === b);

      opportunities.push({
        label: `${appA?.name || a} ↔ ${appB?.name || b}`,
        apps: [appA?.name || a, appB?.name || b],
        reason: overlap > 0
          ? `${overlap} shared customers already — high cross-sell affinity`
          : `No overlap yet — untapped cross-sell potential`,
        existingOverlap: overlap,
        potentialReach,
      });
    }
  }

  // Sort by overlap (proven affinity first), then by potential
  opportunities.sort((a, b) => b.existingOverlap - a.existingOverlap || b.potentialReach - a.potentialReach);

  res.json({ opportunities });
}));

// Customer graph cron — daily 3:30AM
cron.schedule('30 3 * * *', async () => {
  try {
    await collectCustomerGraph();
  } catch (err) {
    cronFail('Customer graph', err);
  }
});

// === Feature: Automated Email Sequences ===

// Simple obfuscation to avoid plaintext emails in SQLite — not cryptographic security
const EMAIL_OBFUSCATION_KEY = process.env.EMAIL_OBFUSCATION_KEY || 'dockfolio-email-obfuscate-2026';

function deobfuscateEmail(encoded) {
  const decoded = Buffer.from(encoded, 'base64').toString();
  const chars = [];
  for (let i = 0; i < decoded.length; i++) {
    chars.push(String.fromCharCode(decoded.charCodeAt(i) ^ EMAIL_OBFUSCATION_KEY.charCodeAt(i % EMAIL_OBFUSCATION_KEY.length)));
  }
  return chars.join('');
}

const DEFAULT_SEQUENCES = [
  {
    name: 'New Paid Welcome',
    segment: 'new_paid',
    app_slug: null,
    steps: [
      { delay_days: 0, subject: 'Welcome to {{appName}}!', template_key: 'new_paid_day0' },
      { delay_days: 3, subject: 'Quick tip: Get more from {{appName}}', template_key: 'new_paid_day3' },
      { delay_days: 14, subject: 'How is {{appName}} working for you?', template_key: 'new_paid_day14' },
    ]
  },
  {
    name: 'At Risk Re-engagement',
    segment: 'at_risk',
    app_slug: null,
    steps: [
      { delay_days: 0, subject: 'We miss you at {{appName}}', template_key: 'at_risk_day0' },
      { delay_days: 7, subject: 'Anything we can improve?', template_key: 'at_risk_day7' },
    ]
  },
  {
    name: 'Churned Win-Back',
    segment: 'churned',
    app_slug: null,
    steps: [
      { delay_days: 3, subject: 'We are sorry to see you go', template_key: 'churned_day3' },
      { delay_days: 14, subject: 'A special offer to come back to {{appName}}', template_key: 'churned_day14' },
    ]
  },
  {
    name: 'Cross-Sell Introduction',
    segment: 'established',
    app_slug: null,
    steps: [
      { delay_days: 30, subject: 'Discover more tools from our portfolio', template_key: 'crosssell_day30' },
    ]
  },
];

const EMAIL_TEMPLATES = new Map([
  ['new_paid_day0', {
    subject: 'Welcome to {{appName}}!',
    html: `<h2>Welcome aboard!</h2><p>Thank you for choosing {{appName}}. We are excited to have you.</p><p>Here are some tips to get started:</p><ul><li>Explore the main features</li><li>Check out our documentation</li><li>Reach out if you need help</li></ul><p>Best regards,<br>The {{appName}} Team</p>`,
  }],
  ['new_paid_day3', {
    subject: 'Quick tip: Get more from {{appName}}',
    html: `<h2>Did you know?</h2><p>Many of our users get the most value from {{appName}} by exploring all available features.</p><p>Take a moment to discover what else {{appName}} can do for you.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['new_paid_day14', {
    subject: 'How is {{appName}} working for you?',
    html: `<h2>Quick check-in</h2><p>You have been using {{appName}} for 2 weeks now. How is it going?</p><p>We would love to hear your feedback. Simply reply to this email.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['at_risk_day0', {
    subject: 'We miss you at {{appName}}',
    html: `<h2>It has been a while!</h2><p>We noticed you have not used {{appName}} recently. Is everything okay?</p><p>We have made some improvements that you might like. Come check them out!</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['at_risk_day7', {
    subject: 'Anything we can improve?',
    html: `<h2>Your feedback matters</h2><p>We want to make {{appName}} better for you. If there is something we can improve, please let us know by replying to this email.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['churned_day3', {
    subject: 'We are sorry to see you go',
    html: `<h2>We are sorry to see you leave</h2><p>We noticed you cancelled your {{appName}} subscription. We understand, and we hope you got value from the product.</p><p>If you ever want to come back, we will be here.</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['churned_day14', {
    subject: 'A special offer to come back to {{appName}}',
    html: `<h2>Come back to {{appName}}</h2><p>We have been working hard to improve {{appName}} since you left. Would you like to give it another try?</p><p>Best,<br>The {{appName}} Team</p>`,
  }],
  ['crosssell_day30', {
    subject: 'Discover more tools from our portfolio',
    html: `<h2>More tools for you</h2><p>Since you enjoy {{appName}}, you might also like our other products.${process.env.BRAND_URL ? ` Check them out at ${process.env.BRAND_URL}!` : ''}</p><p>Best,<br>The ${process.env.BRAND_NAME || 'Dockfolio'} Team</p>`,
  }],
]);

function getEmailTemplate(templateKey, appSlug) {
  const template = EMAIL_TEMPLATES.get(templateKey);
  if (!template) return { subject: 'Update from your app', html: '<p>Hello!</p>' };
  const appDef = findAppBySlug(appSlug);
  const appName = appDef?.name || appSlug;
  return {
    subject: template.subject.replace(/\{\{appName\}\}/g, appName),
    html: template.html.replace(/\{\{appName\}\}/g, appName),
  };
}

function seedDefaultSequences() {
  const count = db.prepare('SELECT COUNT(*) as n FROM email_sequences').get().n;
  if (count > 0) return;
  const insert = db.prepare('INSERT INTO email_sequences (name, segment, app_slug, active, steps) VALUES (?, ?, ?, ?, ?)');
  for (const seq of DEFAULT_SEQUENCES) {
    insert.run(seq.name, seq.segment, seq.app_slug, 0, JSON.stringify(seq.steps));
  }
  console.log(`[STARTUP] Seeded ${DEFAULT_SEQUENCES.length} default email sequences (all inactive)`);
}
seedDefaultSequences();

async function sendEmail(toEmail, subject, htmlBody, appSlug) {
  const resendKey = getResendKey();
  if (!resendKey) throw new Error('No Resend API key found');

  // Enforce daily cap
  const today = todayString();
  const sentToday = db.prepare(
    "SELECT COUNT(*) as n FROM email_queue WHERE status='sent' AND sent_at >= ?"
  ).get(today + 'T00:00:00Z').n;
  if (sentToday >= 95) throw new Error('Daily email cap reached (95/100)');

  const appDef = findAppBySlug(appSlug);
  const fromName = appDef?.name || 'Dockfolio';
  const fromDomain = process.env.EMAIL_FROM_DOMAIN || appDef?.domain;
  if (!fromDomain) {
    throw new Error('No email domain configured (set EMAIL_FROM_DOMAIN or add domain to app config)');
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${resendKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: `${fromName} <noreply@${fromDomain}>`,
      to: [toEmail],
      subject,
      html: htmlBody,
    }),
    signal: AbortSignal.timeout(TIMEOUT_STANDARD),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Resend error ${res.status}`);
  }
  return await res.json();
}

// Email sequence endpoints
app.get('/api/marketing/emails/sequences', asyncRoute((_req, res) => {
  const sequences = db.prepare('SELECT * FROM email_sequences ORDER BY id').all();

  // Batch query: get all queue counts grouped by sequence_id + status (avoids N+1)
  const queueCounts = db.prepare(
    'SELECT sequence_id, status, COUNT(*) as n FROM email_queue GROUP BY sequence_id, status'
  ).all();
  const countsBySeq = {};
  for (const row of queueCounts) {
    if (!countsBySeq[row.sequence_id]) countsBySeq[row.sequence_id] = {};
    countsBySeq[row.sequence_id][row.status] = row.n;
  }

  const result = sequences.map(seq => ({
    ...seq,
    steps: safeJSON(seq.steps, []),
    active: !!seq.active,
    queuedCount: countsBySeq[seq.id]?.pending || 0,
    sentCount: countsBySeq[seq.id]?.sent || 0,
  }));
  res.json({ sequences: result });
}));

app.get('/api/marketing/emails/queue', asyncRoute((req, res) => {
  const status = req.query.status || 'pending';
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;

  const queue = db.prepare(
    'SELECT * FROM email_queue WHERE status = ? ORDER BY scheduled_at ASC LIMIT ? OFFSET ?'
  ).all(status, limit, offset);

  const counts = {};
  for (const row of db.prepare('SELECT status, COUNT(*) as n FROM email_queue GROUP BY status').all()) {
    counts[row.status] = row.n;
  }

  const today = todayString();
  const dailySentToday = db.prepare(
    "SELECT COUNT(*) as n FROM email_queue WHERE status='sent' AND sent_at >= ?"
  ).get(today + 'T00:00:00Z').n;

  res.json({ queue, counts, dailySentToday, dailyLimit: 100 });
}));

app.post('/api/marketing/emails/send-test', asyncRoute(async (req, res) => {
  const { template_key, app_slug, to_email } = req.body;
  if (!template_key || !app_slug || !to_email) {
    return res.status(400).json({ error: 'template_key, app_slug, and to_email are required' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to_email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }

  console.log(`[EMAIL] Sending test email to ${to_email} (template: ${template_key}, app: ${app_slug})`);
  const template = getEmailTemplate(template_key, app_slug);
  const result = await sendEmail(to_email, template.subject, template.html, app_slug);
  console.log(`[EMAIL] Test email sent, messageId=${result.id}`);
  res.json({ ok: true, messageId: result.id });
}));

// POST /api/marketing/emails/sequences — Create sequence
app.post('/api/marketing/emails/sequences', asyncRoute((req, res) => {
  const { name, app_slug, segment, steps, active } = req.body;
  if (!name || !segment || !steps) return res.status(400).json({ error: 'name, segment, and steps are required' });
  const result = db.prepare('INSERT INTO email_sequences (name, segment, app_slug, active, steps) VALUES (?, ?, ?, ?, ?)').run(name, segment || 'all', app_slug || null, active ? 1 : 0, typeof steps === 'string' ? steps : JSON.stringify(steps));
  res.json({ ok: true, id: result.lastInsertRowid });
}));

// PUT /api/marketing/emails/sequences/:id — Update sequence
app.put('/api/marketing/emails/sequences/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });
  const { name, app_slug, segment, steps, active } = req.body;
  const existing = db.prepare('SELECT * FROM email_sequences WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Sequence not found' });
  db.prepare('UPDATE email_sequences SET name = ?, segment = ?, app_slug = ?, active = ?, steps = ? WHERE id = ?')
    .run(name || existing.name, segment || existing.segment, app_slug ?? existing.app_slug, active !== undefined ? (active ? 1 : 0) : existing.active, steps ? (typeof steps === 'string' ? steps : JSON.stringify(steps)) : existing.steps, id);
  res.json({ ok: true });
}));

// DELETE /api/marketing/emails/sequences/:id — Delete sequence + cascade
app.delete('/api/marketing/emails/sequences/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });
  db.prepare('DELETE FROM email_queue WHERE sequence_id = ?').run(id);
  const result = db.prepare('DELETE FROM email_sequences WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Sequence not found' });
  res.json({ ok: true });
}));

// Process email queue — hourly cron
cron.schedule('0 * * * *', async () => {
  console.log('[CRON] Processing email queue...');
  try {
    const now = new Date().toISOString();
    const due = db.prepare(`
      SELECT eq.*, s.email_encrypted FROM email_queue eq
      JOIN subscribers s ON eq.recipient_hash = s.email_hash AND eq.app_slug = s.app_slug
      WHERE eq.status = 'pending' AND eq.scheduled_at <= ?
      ORDER BY eq.scheduled_at ASC LIMIT 20
    `).all(now);

    if (due.length === 0) {
      console.log('[CRON] No emails due');
      return;
    }

    const updateSent = db.prepare("UPDATE email_queue SET status='sent', sent_at=? WHERE id=?");
    const updateFailed = db.prepare("UPDATE email_queue SET status='failed', error=? WHERE id=?");
    let sent = 0, failed = 0;

    for (const item of due) {
      try {
        const toEmail = deobfuscateEmail(item.email_encrypted);
        const template = getEmailTemplate(item.template_key, item.app_slug);
        await sendEmail(toEmail, template.subject, template.html, item.app_slug);
        updateSent.run(new Date().toISOString(), item.id);
        sent++;
      } catch (err) {
        updateFailed.run(err.message, item.id);
        failed++;
      }
    }

    console.log(`[CRON] Email queue processed: ${sent} sent, ${failed} failed`);
  } catch (err) {
    cronFail('Email queue', err);
  }
});

// Snapshot container CPU/memory metrics every hour (for sparklines)
cron.schedule('5 * * * *', async () => {
  try {
    const containers = await docker.listContainers();
    const insertMetric = db.prepare('INSERT OR REPLACE INTO container_metrics (container_name, app_slug, ts, cpu, memory) VALUES (?, ?, datetime(\'now\'), ?, ?)');
    const appMap = {};
    for (const appDef of config.apps) {
      if (appDef.containers) {
        for (const cn of appDef.containers) { appMap[cn] = appDef.slug; }
      }
    }
    let count = 0;
    for (const c of containers) {
      const name = c.Names?.[0]?.replace(/^\//, '') || c.Id.slice(0, 12);
      try {
        const s = await docker.getContainer(c.Id).stats({ stream: false });
        const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
        const systemDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
        const cpuCount = s.cpu_stats.online_cpus || 1;
        const cpu = systemDelta > 0 ? Math.round((cpuDelta / systemDelta) * cpuCount * 10000) / 100 : 0;
        const memory = s.memory_stats.usage || 0;
        insertMetric.run(name, appMap[name] || null, cpu, memory);
        count++;
      } catch { /* skip unavailable containers */ }
    }
    // Prune entries older than 48h
    db.prepare("DELETE FROM container_metrics WHERE ts < datetime('now', '-48 hours')").run();

    // System-level snapshot (for predictive alerts)
    try {
      const dfParts = getDiskParts();
      const diskTotal = parseInt(dfParts[1], 10);
      const diskUsed = parseInt(dfParts[2], 10);
      const memInfo = readFileSync('/proc/meminfo', 'utf8');
      const memTotal = parseInt(memInfo.match(/MemTotal:\s+(\d+)/)?.[1] || '0') * 1024;
      const memAvail = parseInt(memInfo.match(/MemAvailable:\s+(\d+)/)?.[1] || '0') * 1024;
      const loadavg = parseFloat(readFileSync('/proc/loadavg', 'utf8').split(' ')[0]);
      const cpuCount = parseInt(execSync('nproc', { timeout: TIMEOUT_QUICK }).toString().trim(), 10);
      const cpuPct = Math.round((loadavg / cpuCount) * 100);
      db.prepare('INSERT INTO system_snapshots (ts, disk_used_bytes, disk_total_bytes, mem_used_bytes, mem_total_bytes, cpu_percent, load_1m) VALUES (datetime(\'now\'), ?, ?, ?, ?, ?, ?)')
        .run(diskUsed, diskTotal, memTotal - memAvail, memTotal, cpuPct, loadavg);
      // Prune system snapshots older than 30 days
      db.prepare("DELETE FROM system_snapshots WHERE ts < datetime('now', '-30 days')").run();
    } catch (sysErr) { console.error('[CRON] System snapshot error:', sysErr.message); }

    console.log(`[CRON] Container metrics snapshot: ${count} containers`);
  } catch (err) { cronFail('Container metrics snapshot', err); }
});

// === Feature: Morning Briefing ===

let cachedBriefing = null;
let lastBriefingUpdate = 0;
const BRIEFING_TTL = 30 * 60_000; // 30 minutes

async function collectBriefingContext() {
  const context = {};

  // System health
  try {
    const memInfo = readFileSync('/proc/meminfo', 'utf8');
    const memTotal = parseInt(memInfo.match(/MemTotal:\s+(\d+)/)?.[1] || '0') * 1024;
    const memAvail = parseInt(memInfo.match(/MemAvailable:\s+(\d+)/)?.[1] || '0') * 1024;
    const memUsedPct = Math.round(((memTotal - memAvail) / memTotal) * 100);
    const diskLine = getDiskParts();
    const diskUsedPct = parseInt(diskLine[4]);
    context.system = { memUsedPct, diskUsedPct, diskUsedGB: Math.round(parseInt(diskLine[2]) / 1e9), diskTotalGB: Math.round(parseInt(diskLine[1]) / 1e9) };
  } catch { context.system = { error: 'unavailable' }; }

  // Container statuses
  try {
    const containers = await docker.listContainers({ all: true });
    const unhealthy = containers.filter(c => c.Status?.includes('unhealthy'));
    const restarting = containers.filter(c => c.State === 'restarting');
    context.containers = {
      total: containers.length,
      running: containers.filter(c => c.State === 'running').length,
      unhealthy: unhealthy.map(c => containerName(c)),
      restarting: restarting.map(c => containerName(c)),
    };
  } catch { context.containers = { error: 'unavailable' }; }

  // Backup statuses
  try {
    const backupDir = BACKUP_DIR;
    let backupApps = [];
    try {
      if (existsSync(backupDir)) {
        backupApps = readdirSync(backupDir, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name);
      }
    } catch { backupApps = []; }
    context.backups = {};
    for (const app of backupApps) {
      const dir = join(BACKUP_DIR, app);
      if (!existsSync(dir)) { context.backups[app] = 'no_backups'; continue; }
      try {
        const files = getLatestFile(dir);
        if (!files) { context.backups[app] = 'no_backups'; continue; }
        const mtime = statSync(join(dir, files)).mtime;
        const ageH = Math.round((Date.now() - mtime.getTime()) / MS_PER_HOUR);
        context.backups[app] = ageH <= 25 ? `ok (${ageH}h ago)` : `stale (${ageH}h ago)`;
      } catch { context.backups[app] = 'error'; }
    }
  } catch { context.backups = { error: 'unavailable' }; }

  // Revenue (from cache or fresh)
  if (cachedRevenue) {
    context.revenue = {
      totalMRR: (cachedRevenue.totals.mrr / 100).toFixed(0),
      revenue30d: (cachedRevenue.totals.revenue30d / 100).toFixed(0),
      currency: 'EUR',
      apps: Object.fromEntries(Object.entries(cachedRevenue.apps).map(([name, d]) => [name, { mrr: (d.mrr / 100).toFixed(0), chargeCount30d: d.chargeCount30d }])),
    };
  }

  // SEO scores (from cache)
  if (cachedSEO?.apps) {
    context.seo = Object.fromEntries(Object.entries(cachedSEO.apps).map(([name, d]) => [name, { score: d.score, grade: d.grade }]));
  }

  // Security score (from latest scan)
  try {
    const latestScan = db.prepare('SELECT overall_score, grade, critical_count, high_count, medium_count, low_count FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
    if (latestScan) context.security = latestScan;
  } catch (err) { console.error('[BRIEFING] Security score lookup failed:', err.message); }

  // Recent Docker events (last 24h)
  try {
    const since = Math.floor((Date.now() - MS_PER_DAY) / 1000);
    const events = await docker.getEvents({ since, until: Math.floor(Date.now() / 1000), filters: { type: ['container'], event: ['die', 'oom', 'restart', 'health_status'] } });
    const chunks = [];
    await new Promise((resolve) => {
      events.on('data', (chunk) => chunks.push(chunk));
      setTimeout(() => { events.destroy(); resolve(); }, 3000);
    });
    const parsed = chunks.join('').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    context.events24h = {
      total: parsed.length,
      restarts: parsed.filter(e => e.Action === 'restart').length,
      oom: parsed.filter(e => e.Action === 'oom').length,
      dies: parsed.filter(e => e.Action === 'die').length,
      unhealthyEvents: parsed.filter(e => e.Action === 'health_status: unhealthy').length,
    };
  } catch (err) { console.error('[BRIEFING] Docker events query failed:', err.message); context.events24h = { total: 0 }; }

  // Healing log (last 24h)
  try {
    const since24h = new Date(Date.now() - MS_PER_DAY).toISOString();
    const healingActions = db.prepare('SELECT * FROM healing_log WHERE timestamp >= ? ORDER BY timestamp DESC').all(since24h);
    context.healing = healingActions.map(h => ({ condition: h.condition, action: h.action_taken, result: h.result, app: h.app_slug }));
  } catch (err) { console.error('[BRIEFING] Healing log query failed:', err.message); context.healing = []; }

  // Project tasks (overdue + due today)
  try {
    const today = todayString();
    const overdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today);
    const dueToday = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date = ? AND status NOT IN ('done','cancelled')").get(today);
    const lastShipped = db.prepare("SELECT title, app_slug, shipped_date FROM project_roadmap WHERE status = 'shipped' ORDER BY shipped_date DESC LIMIT 1").get();
    context.projects = { overdueCount: overdue?.count || 0, dueTodayCount: dueToday?.count || 0, lastShipped: lastShipped || null };
  } catch (err) { console.error('[BRIEFING] Project tasks query failed:', err.message); context.projects = {}; }

  // Ops Intelligence
  try {
    const worryResult = await calculateWorryScore();
    const latestScore = db.prepare('SELECT streak_days FROM ops_scores ORDER BY timestamp DESC LIMIT 1').get();
    const recentDrifts = db.prepare("SELECT COUNT(*) as n FROM ops_events WHERE event_type LIKE 'drift_%' AND acknowledged = 0 AND timestamp >= datetime('now', '-24 hours')").get();
    context.ops = { worryScore: worryResult.score, breakdown: worryResult.breakdown, streakDays: latestScore?.streak_days || 0, unacknowledgedDrifts: recentDrifts?.n || 0 };
  } catch (err) { console.error('[BRIEFING] Ops intelligence failed:', err.message); context.ops = {}; }

  // Error tracking
  try {
    const newIssues24h = db.prepare("SELECT COUNT(*) as n FROM error_issues WHERE first_seen >= datetime('now', '-24 hours')").get();
    const totalOpen = db.prepare("SELECT COUNT(*) as n FROM error_issues WHERE status = 'open'").get();
    const noisiest = db.prepare("SELECT app_slug, title, occurrence_count FROM error_issues WHERE status = 'open' ORDER BY occurrence_count DESC LIMIT 5").all();
    const byApp = db.prepare("SELECT app_slug, COUNT(*) as count FROM error_issues WHERE status = 'open' GROUP BY app_slug").all();
    context.errors = { newIssues24h: newIssues24h?.n || 0, totalOpen: totalOpen?.n || 0, noisiest, byApp };
  } catch { context.errors = { newIssues24h: 0, totalOpen: 0 }; }

  return context;
}

app.get('/api/briefing', asyncRoute(async (req, res) => {
  const force = req.query.force === 'true';
  const now = Date.now();
  if (!force && cachedBriefing && (now - lastBriefingUpdate) < BRIEFING_TTL) {
    return res.json(cachedBriefing);
  }

  const context = await collectBriefingContext();
  const anthropicKey = getAnthropicKey();

  if (!anthropicKey) {
    // No AI key — return raw context as structured briefing
    cachedBriefing = { type: 'raw', context, generated: new Date().toISOString() };
    lastBriefingUpdate = now;
    return res.json(cachedBriefing);
  }

  const prompt = `You are an operations briefing officer for a portfolio of 13 web apps running on a single Hetzner VM.
Generate a concise morning briefing based on this operational data:

${JSON.stringify(context, null, 2)}

Format your response as a brief, scannable report:
1. **Status Line** One sentence: overall health (green/yellow/red)
2. **Overnight Events** What happened in the last 24h (2-3 bullet points max, skip if nothing notable)
3. **Key Metrics** MRR, revenue, notable SEO changes (2-3 bullets)
4. **Action Items** Prioritized list of things that need attention (be specific: which app, what to do)
5. **All Clear** If nothing needs attention, just say "All systems nominal."

Be direct, no fluff. Use markdown formatting. If backups are stale or containers unhealthy, that's priority 1.`;

  const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { messages: [{ role: 'user', content: prompt }] }));

  cachedBriefing = { type: 'ai', briefing: ai.text || 'Unable to generate briefing.', context, tokens: ai.tokens, generated: new Date().toISOString() };
  lastBriefingUpdate = now;
  console.log(`[BRIEFING] Generated (${ai.tokens} tokens)`);
  res.json(cachedBriefing);
}));

// === Feature: Command Palette ===

function fuzzyMatch(query, target) {
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  if (t.includes(q)) return true;
  if (t.replace(/[-_\s]/g, '').includes(q.replace(/[-_\s]/g, ''))) return true;
  return false;
}

// Shortcut lookup for command palette results
const commandShortcuts = {
  briefing: 'd', revenue: 'm', seo: 'm', backups: 'b', prune: '', status: '',
  healing: 'h', emails: '', content: '', cohorts: '', keys: 'k', ssl: 's',
  crosspromo: 'x', banners: 'b', playbook: 'p', security: 'S', projects: 'j',
  tasks: '', roadmap: '', overdue: '', ops: 'o', worry: '', drift: '',
  reportcards: '', playground: '', notifications: 'n', containermap: '',
  uptime: '', updates: '',
};

// Prepared FTS5 search query ranked by BM25
const ftsSearchStmt = db.prepare(`
  SELECT type, key, name, description, extra, bm25(command_search_fts) AS rank
  FROM command_search_fts
  WHERE command_search_fts MATCH ?
  ORDER BY rank
  LIMIT 10
`);

app.get('/api/command/search', (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ results: [] });

  let results = [];

  // Match action patterns first: "logs X", "restart X", "seo X"
  const actionMatch = q.match(/^(logs?|restart|seo|revenue|env)\s+(.+)/i);
  if (actionMatch) {
    const [, action, target] = actionMatch;
    const matchedApp = config.apps.find(a => fuzzyMatch(target, a.name) || fuzzyMatch(target, slugify(a.name)));
    if (matchedApp) {
      results.push({
        type: 'action',
        action: action.toLowerCase().replace(/s$/, ''),
        app: matchedApp.name,
        slug: slugify(matchedApp.name),
        label: `${action} ${matchedApp.name}`,
      });
    }
  }

  // FTS5 search with fallback to LIKE-based fuzzy match
  let ftsMatched = false;
  try {
    // Escape user input: double-quote each token and append * for prefix matching
    const ftsQuery = q
      .replace(/[""]/g, '') // strip existing quotes
      .split(/\s+/)
      .filter(t => t.length > 0)
      .map(t => '"' + t.replace(/"/g, '""') + '"*')
      .join(' ');

    if (ftsQuery) {
      const rows = ftsSearchStmt.all(ftsQuery);
      for (const row of rows) {
        if (row.type === 'app') {
          const appDef = config.apps.find(a => slugify(a.name) === row.key);
          if (appDef) {
            results.push({ type: 'app', name: appDef.name, slug: row.key, domain: appDef.domain, description: appDef.description });
          }
        } else if (row.type === 'command') {
          results.push({
            type: 'command',
            cmd: row.key,
            label: row.name,
            description: row.description,
            shortcut: commandShortcuts[row.key] || '',
          });
        }
      }
      ftsMatched = true;
    }
  } catch (_ftsErr) {
    // FTS5 query failed (e.g. invalid syntax) — fall back to fuzzy match
  }

  // Fallback: original fuzzy match if FTS5 failed or returned nothing
  if (!ftsMatched || results.length <= (actionMatch ? 1 : 0)) {
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      if (fuzzyMatch(q, appDef.name) || fuzzyMatch(q, slug) || (appDef.domain && fuzzyMatch(q, appDef.domain))) {
        results.push({ type: 'app', name: appDef.name, slug, domain: appDef.domain, description: appDef.description });
      }
    }

    const fallbackCommands = [
      { cmd: 'briefing', label: 'Morning Briefing', description: 'AI-generated operations summary', shortcut: 'd' },
      { cmd: 'revenue', label: 'Revenue Dashboard', description: 'Open marketing revenue tab', shortcut: 'm' },
      { cmd: 'seo', label: 'SEO Audit', description: 'Open marketing SEO tab', shortcut: 'm' },
      { cmd: 'backups', label: 'Backup Status', description: 'Show database backup panel', shortcut: 'b' },
      { cmd: 'prune', label: 'Docker Prune', description: 'Clean up unused containers/images', shortcut: '' },
      { cmd: 'status', label: 'System Status', description: 'Show system metrics', shortcut: '' },
      { cmd: 'healing', label: 'Auto-Healing Log', description: 'Show recent auto-healing actions', shortcut: 'h' },
      { cmd: 'emails', label: 'Email Sequences', description: 'Open marketing emails tab', shortcut: '' },
      { cmd: 'content', label: 'Content Pipeline', description: 'Open marketing content tab', shortcut: '' },
      { cmd: 'cohorts', label: 'Customer Cohorts', description: 'Open revenue cohorts subtab', shortcut: '' },
      { cmd: 'keys', label: 'API Key Health', description: 'Show API key validation status', shortcut: 'k' },
      { cmd: 'ssl', label: 'SSL Certificates', description: 'Show SSL certificate expiry', shortcut: 's' },
      { cmd: 'crosspromo', label: 'Cross-Promotion', description: 'Manage cross-app promotion campaigns', shortcut: 'x' },
      { cmd: 'banners', label: 'Banner Manager', description: 'Create and manage ad banners across sites', shortcut: 'b' },
      { cmd: 'playbook', label: 'Marketing Playbook', description: 'AI-generated marketing strategies per app', shortcut: 'p' },
      { cmd: 'security', label: 'Security Manager', description: 'Docker security audit and scoring', shortcut: 'S' },
      { cmd: 'projects', label: 'Projects Manager', description: 'App lifecycle, tasks, roadmap, insights', shortcut: 'j' },
      { cmd: 'tasks', label: 'Project Tasks', description: 'View and manage project tasks', shortcut: '' },
      { cmd: 'roadmap', label: 'Product Roadmap', description: 'Feature planning and milestones', shortcut: '' },
      { cmd: 'overdue', label: 'Overdue Tasks', description: 'Show tasks past their due date', shortcut: '' },
      { cmd: 'ops', label: 'Ops Intelligence', description: 'Worry score, drift detection, report cards', shortcut: 'o' },
      { cmd: 'worry', label: 'Worry Score', description: 'Current ops worry score breakdown', shortcut: '' },
      { cmd: 'drift', label: 'Config Drift', description: 'Detect changes since last baseline', shortcut: '' },
      { cmd: 'reportcards', label: 'Report Cards', description: 'Per-app health scorecards', shortcut: '' },
      { cmd: 'playground', label: 'API Playground', description: 'Interactive API explorer', shortcut: '' },
      { cmd: 'notifications', label: 'Notification Center', description: 'View all alerts and events', shortcut: 'n' },
      { cmd: 'containermap', label: 'Container Map', description: 'Visual network graph of container dependencies', shortcut: '' },
      { cmd: 'updates', label: 'Image Updates', description: 'Check for Docker image updates across containers', shortcut: '' },
    ];

    for (const c of fallbackCommands) {
      if (fuzzyMatch(q, c.cmd) || fuzzyMatch(q, c.label)) {
        results.push({ type: 'command', ...c });
      }
    }
  }

  res.json({ results: results.slice(0, 10) });
});

// GET /api/playground/routes — List all registered Express routes grouped by category
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
              // Extract URL params from path
              const params = (path.match(/:(\w+)/g) || []).map(p => p.slice(1));
              routes.push({ method, path, category, params });
            }
          }
        }
      }
    }
  }

  // Group by category
  const grouped = {};
  for (const route of routes) {
    if (!grouped[route.category]) grouped[route.category] = [];
    grouped[route.category].push(route);
  }

  // Sort categories
  const order = ['Auth', 'Docker & Infrastructure', 'System', 'Configuration', 'Marketing', 'Banners', 'Cross-Promotion', 'Security', 'Auto-Healing', 'AI', 'Analytics', 'Playground', 'Other'];
  const sorted = {};
  for (const cat of order) {
    if (grouped[cat]) sorted[cat] = grouped[cat];
  }
  // Add any remaining categories
  for (const cat of Object.keys(grouped)) {
    if (!sorted[cat]) sorted[cat] = grouped[cat];
  }

  res.json({ routes: sorted, total: routes.length });
});

// POST /api/ai/command — Natural language container management

async function aiCmdRestart(req, targetContainer, targetApp, query) {
  if (!targetContainer) {
    return { action: 'restart', target: targetApp, result: null, summary: 'Could not identify which container to restart. Please be more specific.' };
  }
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === targetContainer);
  if (!target) {
    return { action: 'restart', target: targetContainer, result: null, summary: `Container "${targetContainer}" not found. Check the name and try again.` };
  }
  const container = docker.getContainer(target.Id);
  await container.restart({ t: 10 });
  auditLog(req, 'ai.container.restart', targetContainer, { query });
  return { action: 'restart', target: targetContainer, result: { restarted: targetContainer }, summary: `Restarted container "${targetContainer}" successfully.` };
}

async function aiCmdLogs(targetContainer, targetApp) {
  if (!targetContainer) {
    return { action: 'logs', target: targetApp, result: null, summary: 'Could not identify which container to show logs for. Please specify a container name.' };
  }
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === targetContainer);
  if (!target) {
    return { action: 'logs', target: targetContainer, result: null, summary: `Container "${targetContainer}" not found.` };
  }
  const container = docker.getContainer(target.Id);
  const logs = await container.logs({ stdout: true, stderr: true, tail: 30, timestamps: true });
  const clean = logs.toString('utf8').split('\n').map(line => line.length > 8 ? line.slice(8) : line).join('\n');
  return { action: 'logs', target: targetContainer, result: { logs: clean, container: targetContainer }, summary: `Last 30 log lines from "${targetContainer}":\n${clean.split('\n').slice(-10).join('\n')}` };
}

async function aiCmdStatus(targetApp) {
  if (targetApp) {
    const appDef = findAppBySlug(targetApp);
    if (!appDef) {
      return { action: 'status', target: targetApp, result: null, summary: `App "${targetApp}" not found.` };
    }
    const containers = await docker.listContainers({ all: true });
    const appContainers = (appDef.containers || []).map(name => {
      const c = containers.find(ct => containerName(ct) === name);
      return { name, state: c ? c.State : 'not found', status: c ? c.Status : 'N/A' };
    });
    const statusLines = appContainers.map(c => `  ${c.name}: ${c.state} (${c.status})`).join('\n');
    return { action: 'status', target: targetApp, result: { app: appDef.name, containers: appContainers }, summary: `Status of ${appDef.name}:\n${statusLines}` };
  }
  const containers = await docker.listContainers({ all: true });
  const running = containers.filter(c => c.State === 'running').length;
  const total = containers.length;
  return { action: 'status', target: null, result: { containers: { total, running, stopped: total - running } }, summary: `System status: ${running}/${total} containers running.` };
}

async function aiCmdExplain(anthropicKey, targetContainer, targetApp, query) {
  const contextParts = [];

  if (targetContainer) {
    const containers = await docker.listContainers({ all: true });
    const target = containers.find(c => containerName(c) === targetContainer);
    if (target) {
      const container = docker.getContainer(target.Id);
      const [statsResult, logsResult] = await Promise.allSettled([
        container.stats({ stream: false }),
        container.logs({ stdout: true, stderr: true, tail: 20, timestamps: true }),
      ]);
      if (statsResult.status === 'fulfilled') {
        const s = statsResult.value;
        const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
        const systemDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
        const cpuPercent = systemDelta > 0 ? (cpuDelta / systemDelta) * (s.cpu_stats.online_cpus || 1) * 100 : 0;
        const memMB = Math.round((s.memory_stats.usage || 0) / 1024 / 1024);
        const memLimitMB = Math.round((s.memory_stats.limit || 0) / 1024 / 1024);
        contextParts.push(`Container stats for ${targetContainer}: CPU ${cpuPercent.toFixed(1)}%, Memory ${memMB}MB / ${memLimitMB}MB`);
      }
      if (logsResult.status === 'fulfilled') {
        const clean = logsResult.value.toString('utf8').split('\n').map(l => l.length > 8 ? l.slice(8) : l).join('\n');
        contextParts.push(`Recent logs:\n${clean}`);
      }
      contextParts.push(`Container state: ${target.State}, Status: ${target.Status}`);
    }
  }

  if (targetApp) {
    const appDef = findAppBySlug(targetApp);
    if (appDef) {
      contextParts.push(`App: ${appDef.name}, Domain: ${appDef.domain || 'none'}, Containers: ${(appDef.containers || []).join(', ')}`);
    }
  }

  if (!contextParts.length) {
    contextParts.push('No specific container or app context available.');
  }

  const explainResponse = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
    model: 'claude-haiku-4-20250414', maxTokens: 512, timeout: TIMEOUT_AI,
    system: 'You are a DevOps assistant. Analyze the provided container data and logs to explain what is happening. Be concise and actionable. 2-4 sentences max.',
    messages: [{ role: 'user', content: `User question: ${query}\n\nContext:\n${contextParts.join('\n\n')}` }],
  }));

  return { action: 'explain', target: targetContainer || targetApp, result: { explanation: explainResponse.text }, summary: explainResponse.text };
}

app.post('/api/ai/command', asyncRoute(async (req, res) => {
  const { query } = req.body;
  if (!query || typeof query !== 'string' || query.trim().length < 3) {
    return res.status(400).json({ error: 'Query must be at least 3 characters' });
  }

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) {
    return res.status(503).json({ error: 'AI not configured — no Anthropic API key found' });
  }

  const SAFE_ACTIONS = ['restart', 'logs', 'status', 'explain'];
  const appList = config.apps.map(a => ({
    name: a.name,
    slug: slugify(a.name),
    containers: a.containers || [],
    domain: a.domain || null,
  }));

  const systemPrompt = `You are a container management assistant for Dockfolio. Parse the user's natural language command into a structured action.

Available apps and containers:
${JSON.stringify(appList, null, 2)}

Valid actions: ${SAFE_ACTIONS.join(', ')}
- restart: Restart a specific container
- logs: Show recent logs for a container
- status: Check app or system status
- explain: Analyze why something is happening (high memory, errors, etc.)

Respond with ONLY valid JSON (no markdown, no backticks):
{"action": "restart|logs|status|explain", "target_container": "container-name-or-null", "target_app": "app-slug-or-null", "confidence": 0.0-1.0}

Rules:
- NEVER output anything except the JSON object
- If the user asks to delete, prune, remove, or any destructive operation, respond: {"action": "blocked", "reason": "Destructive operations are not allowed via AI commands"}
- If you cannot determine the intent, respond: {"action": "unknown", "reason": "Could not understand the request"}
- For restart/logs, you MUST identify a specific container name from the available list
- For status, target_app is optional (null means system-wide)
- For explain, identify the app/container the user is asking about`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MEDIUM);

  try {
    const parsed = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      model: 'claude-haiku-4-20250414', maxTokens: 256, timeout: TIMEOUT_MEDIUM,
      system: systemPrompt,
      messages: [{ role: 'user', content: query.trim() }],
    }));

    let intent;
    try {
      intent = JSON.parse(parsed.text.trim());
    } catch {
      return res.json({ action: 'error', target: null, result: null, summary: 'Could not parse AI response. Try rephrasing your command.' });
    }

    if (intent.action === 'blocked') {
      return res.json({ action: 'blocked', target: null, result: null, summary: intent.reason || 'This operation is not allowed via AI commands.' });
    }
    if (intent.action === 'unknown' || !SAFE_ACTIONS.includes(intent.action)) {
      return res.json({ action: 'unknown', target: null, result: null, summary: intent.reason || 'Could not understand the request. Try something like "restart promoforge worker" or "show lohncheck logs".' });
    }

    const { target_container: targetContainer, target_app: targetApp } = intent;
    const ACTION_HANDLERS = {
      restart: () => aiCmdRestart(req, targetContainer, targetApp, query),
      logs: () => aiCmdLogs(targetContainer, targetApp),
      status: () => aiCmdStatus(targetApp),
      explain: () => aiCmdExplain(anthropicKey, targetContainer, targetApp, query),
    };

    res.json(await ACTION_HANDLERS[intent.action]());
  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(504).json({ error: 'AI command timed out. Try a simpler request.' });
    }
    console.error('[AI-CMD] Error:', err.message);
    res.status(500).json({ error: 'AI command failed: ' + (err.message || 'Unknown error') });
  } finally {
    clearTimeout(timeout);
  }
}));

// === Feature: Auto-Healing Engine ===

const HEALING_PLAYBOOKS = [
  {
    id: 'unhealthy_restart',
    condition: 'Container unhealthy',
    check: async () => {
      const containers = await docker.listContainers({ all: true, filters: { health: ['unhealthy'] } });
      return containers.map(c => ({
        name: containerName(c),
        id: c.Id,
        status: c.Status,
      })).filter(c => !c.name.includes('dockfolio'));  // Don't self-heal the dashboard
    },
    action: 'restart',
    confidence: 'high',
    execute: async (target) => {
      const container = docker.getContainer(target.id);
      const info = await container.inspect();
      if (info.State?.RemovalInProgress) return `Skipped ${target.name} — container is being removed/rebuilt`;
      await container.restart({ t: 10 });
      return `Restarted ${target.name}`;
    },
  },
  {
    id: 'restarting_loop',
    condition: 'Container in restart loop',
    check: async () => {
      const containers = await docker.listContainers({ all: true, filters: { status: ['restarting'] } });
      return containers.map(c => ({
        name: containerName(c),
        id: c.Id,
        status: c.Status,
      })).filter(c => !c.name.includes('dockfolio'));
    },
    action: 'log_only',
    confidence: 'low',
    execute: async (target) => {
      return `Container ${target.name} is in restart loop, needs manual investigation`;
    },
  },
  {
    id: 'disk_critical',
    condition: 'Disk usage > 90%',
    check: async () => {
      try {
        const diskLine = getDiskParts();
        const pct = parseInt(diskLine[4]);
        return pct > 90 ? [{ name: 'root_disk', pct }] : [];
      } catch { return []; }
    },
    action: 'prune_docker',
    confidence: 'medium',
    execute: async () => {
      const pruneResult = await docker.pruneContainers();
      const imgResult = await docker.pruneImages();
      const buildResult = await docker.pruneBuilderCache();
      const freed = (pruneResult.SpaceReclaimed || 0) + (imgResult.SpaceReclaimed || 0) + (buildResult.SpaceReclaimed || 0);
      return `Docker pruned, freed ${Math.round(freed / 1e6)}MB`;
    },
  },
  {
    id: 'exited_restart',
    condition: 'Container exited unexpectedly',
    check: async () => {
      const containers = await docker.listContainers({ all: true, filters: { status: ['exited'] } });
      const tracked = new Set();
      for (const appDef of config.apps) {
        for (const cn of (appDef.containers || [])) tracked.add(cn);
      }
      return containers
        .filter(c => {
          const name = containerName(c);
          if (!tracked.has(name) || name.includes('dockfolio')) return false;
          const exitCode = c.Status?.match(/Exited \((\d+)\)/)?.[1];
          return exitCode && exitCode !== '0';
        })
        .map(c => ({ name: containerName(c), id: c.Id, status: c.Status }));
    },
    action: 'restart',
    confidence: 'medium',
    execute: async (target) => {
      const container = docker.getContainer(target.id);
      const info = await container.inspect();
      if (info.State?.RemovalInProgress) return `Skipped ${target.name} — container is being removed/rebuilt`;
      await container.restart({ t: 10 });
      return `Restarted exited container ${target.name} (was: ${target.status})`;
    },
  },
];

const insertHealing = db.prepare(
  'INSERT INTO healing_log (app_slug, condition, action_taken, confidence, result, auto, details) VALUES (?, ?, ?, ?, ?, ?, ?)'
);

async function generateAlertExplanation(condition, containerName, appSlug) {
  try {
    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return '';

    // Try to fetch last 50 log lines from the container
    let logSnippet = '';
    try {
      const container = docker.getContainer(containerName);
      const logs = await container.logs({ stdout: true, stderr: true, tail: 50 });
      logSnippet = (typeof logs === 'string' ? logs : logs.toString('utf8')).replace(/^.{8}/gm, '').trim();
    } catch { /* container may not be accessible */ }

    const prompt = `A Docker container triggered an auto-healing alert. Analyze and explain the likely root cause in 2-3 sentences.

Condition: ${condition}
Container: ${containerName}
App: ${appSlug}
${logSnippet ? `\nRecent logs:\n${logSnippet.slice(-2000)}` : '(No logs available)'}

Be concise and actionable. Focus on the most likely root cause.`;

    const ai = await Promise.race([
      cbAnthropic.call(() => callAnthropic(anthropicKey, {
        maxTokens: 200, timeout: TIMEOUT_STANDARD,
        messages: [{ role: 'user', content: prompt }],
      })),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Alert explanation timeout')), 10_000)),
    ]);

    return ai.text ? `\n\n🤖 Analysis: ${ai.text}` : '';
  } catch {
    return ''; // Best-effort — never block the alert
  }
}

async function runHealingCheck() {
  for (const playbook of HEALING_PLAYBOOKS) {
    try {
      const targets = await playbook.check();
      if (!targets || targets.length === 0) continue;

      for (const target of targets) {
        const appSlug = target.name || 'system';

        // Skip apps in maintenance mode
        if (isInMaintenance(appSlug)) {
          console.log(`[HEALING] Skipped ${appSlug} — maintenance mode`);
          continue;
        }

        // Skip apps in a scheduled maintenance window
        const mwCheck = isInMaintenanceWindow(appSlug);
        if (mwCheck.inMaintenance && mwCheck.window.suppress_alerts) {
          console.log(`[HEALING] Skipped ${appSlug} — scheduled maintenance window`);
          continue;
        }

        // Check if we already acted on this in the last hour (avoid spam)
        const recentAction = db.prepare(
          "SELECT id FROM healing_log WHERE app_slug = ? AND condition = ? AND timestamp >= datetime('now', '-1 hour')"
        ).get(appSlug, playbook.condition);
        if (recentAction) continue;

        // Best-effort AI explanation for the alert (non-blocking)
        const explanation = await generateAlertExplanation(playbook.condition, target.name, appSlug);

        if (playbook.confidence === 'high') {
          // Auto-execute
          try {
            const result = await playbook.execute(target);
            insertHealing.run(appSlug, playbook.condition, playbook.action, playbook.confidence, 'executed', 1, result);
            console.log(`[HEALING] Auto-executed: ${playbook.condition} on ${appSlug} — ${result}`);

            await sendTelegram(`🔧 Auto-Healing: ${playbook.condition}\nApp: ${appSlug}\nAction: ${result}${explanation}`);
          } catch (err) {
            insertHealing.run(appSlug, playbook.condition, playbook.action, playbook.confidence, 'failed', 1, err.message);
            console.error(`[HEALING] Failed: ${playbook.condition} on ${appSlug} — ${err.message}`);
            await sendTelegram(`❌ Healing FAILED: ${playbook.condition}\nApp: ${appSlug}\nError: ${err.message}${explanation}`);
          }
        } else {
          // Log as pending for manual approval
          const detail = await playbook.execute(target).catch(e => e.message);
          insertHealing.run(appSlug, playbook.condition, playbook.action, playbook.confidence, 'pending', 0, detail);
          console.log(`[HEALING] Pending approval: ${playbook.condition} on ${appSlug}`);
          await sendTelegram(`🔔 Healing needs approval: ${playbook.condition}\nApp: ${appSlug}\nAction: ${playbook.action}\nDetails: ${detail}${explanation}`);
        }
      }
    } catch (err) {
      console.error(`[HEALING] Playbook ${playbook.id} error:`, err.message);
    }
  }
}

// Run healing checks every 2 minutes
cron.schedule('*/2 * * * *', guardedCron('healing', async () => {
  // Auto-expire maintenance mode entries
  for (const [slug] of maintenanceMode) {
    isInMaintenance(slug); // triggers auto-expiry check
  }

  await runHealingCheck().catch(err => cronFail('Healing check', err));

  // Event loop lag alert (max once per hour)
  const elMetrics = getEventLoopMetrics();
  if (elMetrics.p99 > 1000) {
    const now = Date.now();
    if (now - eventLoopLagAlertedAt > MS_PER_HOUR) {
      eventLoopLagAlertedAt = now;
      sendTelegram(`⚠️ Event loop lag high\np99: ${elMetrics.p99}ms, mean: ${elMetrics.mean}ms, max: ${elMetrics.max}ms`);
    }
  }
}));

// Healing API endpoints
app.get('/api/healing/log', asyncRoute((_req, res) => {
  const limit = parseInt(_req.query.limit) || 50;
  const logs = db.prepare('SELECT * FROM healing_log ORDER BY timestamp DESC LIMIT ?').all(limit);
  const pending = db.prepare("SELECT COUNT(*) as n FROM healing_log WHERE result = 'pending'").get().n;
  res.json({ logs, pending });
}));

app.post('/api/healing/approve/:id', asyncRoute(async (req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });

  const entry = db.prepare('SELECT * FROM healing_log WHERE id = ?').get(id);
  if (!entry) return res.status(404).json({ error: 'Not found' });
  if (entry.result !== 'pending') return res.status(400).json({ error: 'Not pending' });

  // Find matching playbook and execute
  const playbook = HEALING_PLAYBOOKS.find(p => p.action === entry.action_taken);
  if (playbook && playbook.confidence !== 'high') {
    try {
      const targets = await playbook.check();
      const target = targets.find(t => (t.name || 'system') === entry.app_slug);
      if (target) {
        const result = await playbook.execute(target);
        db.prepare('UPDATE healing_log SET result = ?, details = ? WHERE id = ?').run('executed', result, id);
        return res.json({ ok: true, result });
      }
    } catch (err) {
      db.prepare('UPDATE healing_log SET result = ?, details = ? WHERE id = ?').run('failed', err.message, id);
      return res.json({ ok: false, error: err.message });
    }
  }

  db.prepare("UPDATE healing_log SET result = 'dismissed' WHERE id = ?").run(id);
  res.json({ ok: true, result: 'dismissed' });
}));

app.post('/api/healing/dismiss/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  db.prepare("UPDATE healing_log SET result = 'dismissed' WHERE id = ? AND result = 'pending'").run(id);
  res.json({ ok: true });
}));

// === Feature: Predictive Resource Alerts ===

// Simple linear regression: returns { slope, intercept, r2 }
// x = hours since first data point, y = metric value
function linearRegression(points) {
  const n = points.length;
  if (n < 3) return null;
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;
  for (const { x, y } of points) {
    sumX += x; sumY += y; sumXY += x * y; sumX2 += x * x; sumY2 += y * y;
  }
  const denom = n * sumX2 - sumX * sumX;
  if (denom === 0) return null;
  const slope = (n * sumXY - sumX * sumY) / denom;
  const intercept = (sumY - slope * sumX) / n;
  const ssTot = sumY2 - (sumY * sumY) / n;
  const ssRes = sumY2 - intercept * sumY - slope * sumXY;
  const r2 = ssTot > 0 ? 1 - ssRes / ssTot : 0;
  return { slope, intercept, r2 };
}

function computePredictions() {
  const snapshots = db.prepare("SELECT * FROM system_snapshots WHERE ts > datetime('now', '-7 days') ORDER BY ts ASC").all();
  if (snapshots.length < 6) return { status: 'insufficient_data', dataPoints: snapshots.length, predictions: [] };

  const t0 = new Date(snapshots[0].ts + 'Z').getTime();
  const predictions = [];

  // Disk prediction
  const diskPoints = snapshots.map(s => ({ x: (new Date(s.ts + 'Z').getTime() - t0) / 3600000, y: s.disk_used_bytes }));
  const diskReg = linearRegression(diskPoints);
  if (diskReg && diskReg.slope > 0) {
    const lastSnap = snapshots[snapshots.length - 1];
    const diskTotal = lastSnap.disk_total_bytes;
    const threshold90 = diskTotal * 0.9;
    const currentUsed = lastSnap.disk_used_bytes;
    const currentPct = Math.round((currentUsed / diskTotal) * 100);
    const lastX = diskPoints[diskPoints.length - 1].x;
    const hoursTo90 = diskReg.slope > 0 ? (threshold90 - diskReg.intercept - diskReg.slope * lastX) / diskReg.slope : Infinity;
    if (hoursTo90 > 0 && hoursTo90 < 168) { // within 7 days
      predictions.push({
        metric: 'disk',
        severity: hoursTo90 < 48 ? 'critical' : 'warning',
        currentPct,
        currentUsedGB: Math.round(currentUsed / 1e9 * 10) / 10,
        totalGB: Math.round(diskTotal / 1e9 * 10) / 10,
        growthPerDayGB: Math.round(diskReg.slope * 24 / 1e9 * 100) / 100,
        hoursToThreshold: Math.round(hoursTo90),
        thresholdPct: 90,
        r2: Math.round(diskReg.r2 * 100) / 100,
        message: `Disk usage at ${currentPct}%, growing ${Math.round(diskReg.slope * 24 / 1e9 * 100) / 100} GB/day — projected to hit 90% in ${Math.round(hoursTo90)} hours (${Math.round(hoursTo90 / 24 * 10) / 10} days)`,
      });
    }
  }

  // Memory prediction
  const memPoints = snapshots.map(s => ({ x: (new Date(s.ts + 'Z').getTime() - t0) / 3600000, y: s.mem_used_bytes }));
  const memReg = linearRegression(memPoints);
  if (memReg && memReg.slope > 0) {
    const lastSnap = snapshots[snapshots.length - 1];
    const memTotal = lastSnap.mem_total_bytes;
    const threshold90 = memTotal * 0.9;
    const currentUsed = lastSnap.mem_used_bytes;
    const currentPct = Math.round((currentUsed / memTotal) * 100);
    const lastX = memPoints[memPoints.length - 1].x;
    const hoursTo90 = memReg.slope > 0 ? (threshold90 - memReg.intercept - memReg.slope * lastX) / memReg.slope : Infinity;
    if (hoursTo90 > 0 && hoursTo90 < 168) {
      predictions.push({
        metric: 'memory',
        severity: hoursTo90 < 48 ? 'critical' : 'warning',
        currentPct,
        currentUsedGB: Math.round(currentUsed / 1e9 * 10) / 10,
        totalGB: Math.round(memTotal / 1e9 * 10) / 10,
        growthPerDayMB: Math.round(memReg.slope * 24 / 1e6),
        hoursToThreshold: Math.round(hoursTo90),
        thresholdPct: 90,
        r2: Math.round(memReg.r2 * 100) / 100,
        message: `Memory usage at ${currentPct}%, growing ${Math.round(memReg.slope * 24 / 1e6)} MB/day — projected to hit 90% in ${Math.round(hoursTo90)} hours (${Math.round(hoursTo90 / 24 * 10) / 10} days)`,
      });
    }
  }

  return { status: 'ok', dataPoints: snapshots.length, predictions };
}

// Check predictions daily at 6 AM and alert via Telegram
const predictionAlerted = new Map(); // metric -> timestamp
cron.schedule('0 6 * * *', guardedCron('predictions', async () => {
  try {
    const result = computePredictions();
    for (const pred of result.predictions) {
      if (pred.severity !== 'critical') continue;
      const lastAlert = predictionAlerted.get(pred.metric) || 0;
      if (Date.now() - lastAlert < 24 * 60 * 60 * 1000) continue; // max 1 alert per metric per day
      predictionAlerted.set(pred.metric, Date.now());
      sendTelegram(`🔮 <b>Predictive Alert — ${pred.metric.toUpperCase()}</b>\n${pred.message}\n\nBased on ${result.dataPoints} data points over 7 days (R²=${pred.r2})`);
    }
    console.log(`[CRON] Predictive alerts: ${result.predictions.length} predictions, ${result.predictions.filter(p => p.severity === 'critical').length} critical`);
  } catch (err) { cronFail('Predictive alerts', err); }
}));

app.get('/api/predictions', asyncRoute((_req, res) => {
  const result = computePredictions();
  res.json(result);
}));

// === Feature: AI Cost Optimizer ===

let cachedCostAnalysis = null;
let lastCostAnalysisTime = 0;
const COST_ANALYSIS_TTL = 60 * 60 * 1000; // 1 hour

app.get('/api/cost-analysis', asyncRoute(async (_req, res) => {
  const now = Date.now();
  const force = _req.query.force === 'true';
  if (!force && cachedCostAnalysis && (now - lastCostAnalysisTime) < COST_ANALYSIS_TTL) {
    return res.json(cachedCostAnalysis);
  }

  // Collect per-container stats
  const containers = await docker.listContainers();
  const appMap = {};
  for (const appDef of config.apps) {
    if (appDef.containers) {
      for (const cn of appDef.containers) { appMap[cn] = appDef.slug; }
    }
  }

  const containerStats = [];
  for (const c of containers) {
    const name = c.Names?.[0]?.replace(/^\//, '') || c.Id.slice(0, 12);
    try {
      const s = await docker.getContainer(c.Id).stats({ stream: false });
      const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
      const systemDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
      const cpuCount = s.cpu_stats.online_cpus || 1;
      const cpu = systemDelta > 0 ? Math.round((cpuDelta / systemDelta) * cpuCount * 10000) / 100 : 0;
      const memUsed = s.memory_stats.usage || 0;
      const memLimit = s.memory_stats.limit || 0;
      containerStats.push({ name, app: appMap[name] || null, cpu, memUsedMB: Math.round(memUsed / 1e6), memLimitMB: memLimit > 0 ? Math.round(memLimit / 1e6) : null });
    } catch { /* skip */ }
  }

  // Aggregate per app
  const appStats = {};
  for (const cs of containerStats) {
    const app = cs.app || '_untracked';
    if (!appStats[app]) appStats[app] = { containers: [], totalCPU: 0, totalMemMB: 0 };
    appStats[app].containers.push(cs);
    appStats[app].totalCPU += cs.cpu;
    appStats[app].totalMemMB += cs.memUsedMB;
  }

  // System totals
  const memInfo = readFileSync('/proc/meminfo', 'utf8');
  const memTotalKB = parseInt(memInfo.match(/MemTotal:\s+(\d+)/)?.[1] || '0');
  const memAvailKB = parseInt(memInfo.match(/MemAvailable:\s+(\d+)/)?.[1] || '0');
  const dfParts = getDiskParts();
  const totalMemGB = Math.round(memTotalKB / 1024 / 1024 * 10) / 10;
  const usedMemGB = Math.round((memTotalKB - memAvailKB) / 1024 / 1024 * 10) / 10;
  const diskUsedGB = Math.round(parseInt(dfParts[2]) / 1e9 * 10) / 10;
  const diskTotalGB = Math.round(parseInt(dfParts[1]) / 1e9 * 10) / 10;

  // Revenue per app (from cached metrics)
  const revenueData = {};
  try {
    const rows = db.prepare("SELECT app_slug, value FROM metrics_daily WHERE metric_type = 'mrr' AND date = (SELECT MAX(date) FROM metrics_daily WHERE metric_type = 'mrr')").all();
    for (const r of rows) revenueData[r.app_slug] = r.value;
  } catch { /* no revenue data */ }

  // Build summary for AI
  const summary = {
    system: { totalMemGB, usedMemGB, memPct: Math.round((1 - memAvailKB / memTotalKB) * 100), diskUsedGB, diskTotalGB, diskPct: Math.round(diskUsedGB / diskTotalGB * 100), containerCount: containers.length },
    apps: Object.entries(appStats).map(([slug, s]) => ({
      slug, cpu: Math.round(s.totalCPU * 100) / 100, memMB: s.totalMemMB, containers: s.containers.length,
      mrrEUR: revenueData[slug] ? Math.round(revenueData[slug] / 100) : 0,
    })).sort((a, b) => b.memMB - a.memMB),
  };

  // AI analysis (best-effort)
  let aiRecommendations = '';
  try {
    const anthropicKey = getAnthropicKey();
    if (anthropicKey) {
      const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
        maxTokens: 600, timeout: TIMEOUT_AI,
        system: 'You are a DevOps cost optimizer. Analyze resource usage and give 3-5 concrete, actionable recommendations. Be specific with numbers. Format as a numbered list.',
        messages: [{ role: 'user', content: `Analyze this server resource usage and suggest optimizations:\n\n${JSON.stringify(summary, null, 2)}\n\nThe server costs ~€12/month (Hetzner CX32). Suggest right-sizing, cleanup, or savings.` }],
      }));
      aiRecommendations = ai.text;
    }
  } catch { /* AI unavailable */ }

  cachedCostAnalysis = { ...summary, aiRecommendations, timestamp: new Date().toISOString() };
  lastCostAnalysisTime = now;
  res.json(cachedCostAnalysis);
}));

// === Feature: Automated Changelog Generator ===

// Schema for deploy history
db.exec(`
  CREATE TABLE IF NOT EXISTS deploy_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    commits TEXT,
    summary TEXT,
    container_name TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_deploy_log_app ON deploy_log(app_slug, timestamp);
`);

// Detect deploys by watching for container recreate events (create after destroy)
// This is called from the existing Docker event watcher when a container starts
async function onContainerDeploy(containerName) {
  // Map container to app
  let appSlug = null, repoPath = null;
  for (const appDef of config.apps) {
    if (appDef.containers && appDef.containers.some(cn => containerName.includes(cn) || cn.includes(containerName))) {
      appSlug = appDef.slug;
      repoPath = appDef.repo;
      break;
    }
  }
  if (!appSlug || !repoPath) return;

  // Check if we already logged a deploy for this app in the last 5 minutes (avoid duplicates from multi-container deploys)
  const recent = db.prepare("SELECT id FROM deploy_log WHERE app_slug = ? AND timestamp > datetime('now', '-5 minutes')").get(appSlug);
  if (recent) return;

  // Read recent git commits from the repo
  let commits = [];
  try {
    const gitLog = execSync(
      `cd "${repoPath}" && git log --oneline --no-decorate -10 2>/dev/null`,
      { timeout: TIMEOUT_STANDARD }
    ).toString().trim();
    commits = gitLog.split('\n').filter(Boolean).map(line => {
      const [hash, ...rest] = line.split(' ');
      return { hash, message: rest.join(' ') };
    });
  } catch { /* repo may not have git, or command fails */ }

  // AI summary (best-effort)
  let summary = '';
  if (commits.length > 0) {
    try {
      const anthropicKey = getAnthropicKey();
      if (anthropicKey) {
        const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
          maxTokens: 150, timeout: TIMEOUT_STANDARD,
          system: 'Generate a brief, user-facing changelog entry (2-3 bullet points) from these git commits. Focus on what changed for users, not implementation details. No markdown headers.',
          messages: [{ role: 'user', content: commits.map(c => c.message).join('\n') }],
        }));
        summary = ai.text;
      }
    } catch { /* AI unavailable */ }
  }

  db.prepare('INSERT INTO deploy_log (app_slug, container_name, commits, summary) VALUES (?, ?, ?, ?)')
    .run(appSlug, containerName, JSON.stringify(commits), summary);

  console.log(`[CHANGELOG] Deploy detected: ${appSlug} (${commits.length} commits)`);
}

// API: Get deploy history
app.get('/api/deploys', asyncRoute((_req, res) => {
  const slug = _req.query.app;
  const limit = parseInt(_req.query.limit) || 20;
  const deploys = slug
    ? db.prepare('SELECT * FROM deploy_log WHERE app_slug = ? ORDER BY timestamp DESC LIMIT ?').all(slug, limit)
    : db.prepare('SELECT * FROM deploy_log ORDER BY timestamp DESC LIMIT ?').all(limit);
  for (const d of deploys) {
    try { d.commits = JSON.parse(d.commits); } catch { d.commits = []; }
  }
  res.json({ deploys });
}));

// =============================================
// Security Manager
// =============================================

const CONTAINER_SECURITY_CHECKS = [
  { id: 'privileged_mode', severity: 'critical', weight: 15,
    check: (i) => i.HostConfig?.Privileged === true,
    title: 'Running in privileged mode',
    remediation: 'Remove --privileged flag. Use specific capabilities instead.' },
  { id: 'docker_socket', severity: 'critical', weight: 15,
    check: (i) => (i.Mounts || []).some(m => m.Source === '/var/run/docker.sock'),
    title: 'Docker socket mounted',
    remediation: 'Only mount Docker socket for management containers. Consider a Docker API proxy.' },
  { id: 'host_pid', severity: 'critical', weight: 10,
    check: (i) => i.HostConfig?.PidMode === 'host',
    title: 'Shares host PID namespace',
    remediation: 'Remove --pid=host unless required for monitoring.' },
  { id: 'host_ipc', severity: 'critical', weight: 5,
    check: (i) => i.HostConfig?.IpcMode === 'host',
    title: 'Shares host IPC namespace',
    remediation: 'Remove --ipc=host. Use named IPC namespaces if needed.' },
  { id: 'host_network', severity: 'high', weight: 10,
    check: (i) => i.HostConfig?.NetworkMode === 'host',
    title: 'Uses host network',
    remediation: 'Use bridge networking with explicit port mapping instead of --network=host.' },
  { id: 'root_user', severity: 'high', weight: 10,
    check: (i) => { const u = i.Config?.User; return !u || u === '' || u === '0' || u === 'root'; },
    title: 'Running as root user',
    remediation: 'Add USER directive in Dockerfile or use --user flag.' },
  { id: 'excessive_caps', severity: 'high', weight: 8,
    check: (i) => {
      const dangerous = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'DAC_OVERRIDE', 'NET_RAW', 'SYS_MODULE', 'MKNOD', 'AUDIT_WRITE'];
      return (i.HostConfig?.CapAdd || []).some(c => dangerous.includes(c));
    },
    title: 'Has dangerous Linux capabilities',
    remediation: 'Use --cap-drop=ALL and add back only needed capabilities.' },
  { id: 'sensitive_mounts', severity: 'high', weight: 8,
    check: (i) => {
      const sensitive = ['/etc/', '/root/', '/proc/', '/sys/', '/boot/'];
      return (i.Mounts || []).some(m => m.Source && sensitive.some(s => m.Source.startsWith(s)));
    },
    title: 'Mounts sensitive host paths',
    remediation: 'Avoid mounting /etc, /root, /proc, /sys. Use specific paths instead.' },
  { id: 'no_memory_limit', severity: 'medium', weight: 5,
    check: (i) => !i.HostConfig?.Memory || i.HostConfig.Memory === 0,
    title: 'No memory limit set',
    remediation: 'Set --memory flag to prevent OOM kills affecting other containers.' },
  { id: 'no_cpu_limit', severity: 'medium', weight: 5,
    check: (i) => !i.HostConfig?.NanoCpus && !i.HostConfig?.CpuQuota,
    title: 'No CPU limit set',
    remediation: 'Set --cpus or --cpu-quota to prevent resource starvation.' },
  { id: 'no_new_privileges', severity: 'medium', weight: 5,
    check: (i) => !(i.HostConfig?.SecurityOpt || []).some(o => o.includes('no-new-privileges')),
    title: 'no-new-privileges not set',
    remediation: 'Add --security-opt=no-new-privileges:true to prevent privilege escalation.' },
  { id: 'no_pids_limit', severity: 'low', weight: 3,
    check: (i) => !i.HostConfig?.PidsLimit || i.HostConfig.PidsLimit <= 0,
    title: 'No PID limit (fork bomb risk)',
    remediation: 'Set --pids-limit to prevent fork bombs.' },
  { id: 'writable_rootfs', severity: 'low', weight: 3,
    check: (i) => !i.HostConfig?.ReadonlyRootfs,
    title: 'Root filesystem is writable',
    remediation: 'Use --read-only and mount writable paths with tmpfs or volumes.' },
  { id: 'no_restart_policy', severity: 'low', weight: 3,
    check: (i) => !i.HostConfig?.RestartPolicy?.Name || i.HostConfig.RestartPolicy.Name === 'no',
    title: 'No restart policy',
    remediation: 'Set --restart=unless-stopped for production containers.' },
];

const SECURITY_HEADERS = [
  { id: 'hsts', header: 'strict-transport-security', weight: 20, severity: 'high',
    remediation: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' },
  { id: 'csp', header: 'content-security-policy', weight: 20, severity: 'medium',
    remediation: 'Add Content-Security-Policy header. Start with report-only mode.' },
  { id: 'xcto', header: 'x-content-type-options', weight: 15, severity: 'medium',
    remediation: 'add_header X-Content-Type-Options "nosniff" always;' },
  { id: 'xfo', header: 'x-frame-options', weight: 15, severity: 'medium',
    remediation: 'add_header X-Frame-Options "SAMEORIGIN" always;' },
  { id: 'referrer', header: 'referrer-policy', weight: 10, severity: 'low',
    remediation: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' },
  { id: 'permissions', header: 'permissions-policy', weight: 10, severity: 'low',
    remediation: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;' },
  { id: 'xss', header: 'x-xss-protection', weight: 10, severity: 'low',
    remediation: 'add_header X-XSS-Protection "1; mode=block" always;' },
];

function securityGrade(score) {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

async function scanContainerSecurity() {
  const containers = await docker.listContainers({ all: true });
  const findings = [];
  let totalWeight = 0, earnedWeight = 0;

  for (const c of containers) {
    const name = containerName(c);
    let inspect;
    try { inspect = await docker.getContainer(c.Id).inspect(); } catch { continue; }

    const resolved = resolveContainerApp(name);
    const appSlug = resolved?.slug || null;

    for (const check of CONTAINER_SECURITY_CHECKS) {
      totalWeight += check.weight;
      try {
        if (check.check(inspect)) {
          findings.push({ app_slug: appSlug, container_name: name, category: 'containers', check_id: check.id,
            severity: check.severity, title: `${name}: ${check.title}`, details: JSON.stringify({ container: name, image: inspect.Config?.Image }),
            remediation: check.remediation });
        } else {
          earnedWeight += check.weight;
        }
      } catch { earnedWeight += check.weight; }
    }
  }
  return { score: totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 100, findings, containerCount: containers.length };
}

async function scanCertificateSecurity() {
  const tls = await import('tls');
  const domains = getAuditDomains();
  const findings = [];
  let totalWeight = 0, earnedWeight = 0;

  await Promise.all(domains.map(({ domain, slug }) => new Promise((resolve) => {
    const checkWeights = { ssl_valid: 20, ssl_expiry: 15, ssl_chain: 10, tls_version: 10, self_signed: 10 };
    Object.values(checkWeights).forEach(w => totalWeight += w);

    const socket = tls.default.connect({ host: domain, port: 443, servername: domain, timeout: TIMEOUT_TLS, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      const proto = socket.getProtocol();

      if (socket.authorized) { earnedWeight += checkWeights.ssl_valid; }
      else { findings.push({ app_slug: slug, category: 'certificates', check_id: 'ssl_valid', severity: 'critical',
        title: `${domain}: Certificate not trusted`, details: socket.authorizationError, remediation: 'Renew certificate via certbot or check chain.' }); }

      if (cert?.valid_to) {
        const daysLeft = Math.floor((new Date(cert.valid_to) - Date.now()) / MS_PER_DAY);
        if (daysLeft > 30) { earnedWeight += checkWeights.ssl_expiry; }
        else if (daysLeft > 7) {
          earnedWeight += 7;
          findings.push({ app_slug: slug, category: 'certificates', check_id: 'ssl_expiry', severity: 'high',
            title: `${domain}: Certificate expires in ${daysLeft} days`, remediation: 'Run certbot renew.' });
        } else {
          findings.push({ app_slug: slug, category: 'certificates', check_id: 'ssl_expiry', severity: 'critical',
            title: `${domain}: Certificate expires in ${daysLeft} days!`, remediation: 'Immediately run certbot renew.' });
        }
      }

      if (cert?.issuerCertificate && cert.issuerCertificate !== cert) { earnedWeight += checkWeights.ssl_chain; }
      else { findings.push({ app_slug: slug, category: 'certificates', check_id: 'ssl_chain', severity: 'medium',
        title: `${domain}: Incomplete certificate chain`, remediation: 'Ensure full chain in nginx ssl_certificate.' }); }

      if (proto === 'TLSv1.3') { earnedWeight += checkWeights.tls_version; }
      else if (proto === 'TLSv1.2') {
        earnedWeight += 7;
        findings.push({ app_slug: slug, category: 'certificates', check_id: 'tls_version', severity: 'low',
          title: `${domain}: Using TLS 1.2 (1.3 preferred)`, remediation: 'Enable TLS 1.3: ssl_protocols TLSv1.2 TLSv1.3;' });
      } else {
        findings.push({ app_slug: slug, category: 'certificates', check_id: 'tls_version', severity: 'high',
          title: `${domain}: Outdated ${proto}`, remediation: 'Disable TLS 1.0/1.1 in nginx.' });
      }

      const issuerCN = cert?.issuer?.CN || '';
      const subjectCN = cert?.subject?.CN || '';
      const isSelfSigned = issuerCN && subjectCN && issuerCN === subjectCN && (!cert.issuerCertificate || cert.issuerCertificate === cert);
      if (!isSelfSigned) { earnedWeight += checkWeights.self_signed; }
      else { findings.push({ app_slug: slug, category: 'certificates', check_id: 'self_signed', severity: 'high',
        title: `${domain}: Self-signed certificate`, remediation: "Use Let's Encrypt for free trusted certificates." }); }

      socket.destroy();
      resolve();
    });
    socket.on('error', (err) => {
      findings.push({ app_slug: slug, category: 'certificates', check_id: 'ssl_valid', severity: 'critical',
        title: `${domain}: TLS connection failed`, details: err.message, remediation: 'Check nginx is running and SSL configured.' });
      resolve();
    });
    socket.setTimeout(8000, () => { socket.destroy(); resolve(); });
  })));

  return { score: totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 100, findings };
}

async function scanHeaderSecurity() {
  const domains = getAuditDomains();
  const findings = [];
  let totalWeight = 0, earnedWeight = 0;

  for (const { domain, slug } of domains) {
    try {
      const res = await fetch(`https://${domain}`, { method: 'HEAD', signal: AbortSignal.timeout(TIMEOUT_TLS),
        headers: { 'User-Agent': 'Dockfolio-Security-Audit/1.0' } });
      for (const check of SECURITY_HEADERS) {
        totalWeight += check.weight;
        if (res.headers.get(check.header)) { earnedWeight += check.weight; }
        else { findings.push({ app_slug: slug, category: 'headers', check_id: check.id, severity: check.severity,
          title: `${domain}: Missing ${check.header}`, details: JSON.stringify({ domain }), remediation: check.remediation }); }
      }
    } catch (err) {
      SECURITY_HEADERS.forEach(c => totalWeight += c.weight);
      findings.push({ app_slug: slug, category: 'headers', check_id: 'unreachable', severity: 'high',
        title: `${domain}: Could not check headers`, details: err.message, remediation: 'Verify the domain is reachable.' });
    }
  }
  return { score: totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 100, findings };
}

async function scanNetworkSecurity() {
  const containers = await docker.listContainers({ all: true });
  const findings = [];
  let totalWeight = 0, earnedWeight = 0;

  for (const c of containers) {
    const name = containerName(c);
    const resolved = resolveContainerApp(name);
    const slug = resolved?.slug || null;

    const published = (c.Ports || []).filter(p => p.IP === '0.0.0.0' && p.PublicPort);
    totalWeight += 10;
    if (published.length === 0) { earnedWeight += 10; }
    else {
      const isDb = /postgres|redis|clickhouse|mysql|mariadb|mongo/i.test(name);
      const sev = isDb ? 'critical' : 'medium';
      findings.push({ app_slug: slug, container_name: name, category: 'network', check_id: 'published_ports', severity: sev,
        title: `${name}: Ports exposed to all interfaces (${published.map(p => p.PublicPort).join(', ')})`,
        remediation: isDb ? 'Database ports should NEVER be exposed. Use Docker networks.' : 'Bind to 127.0.0.1 if only local access needed.' });
      if (!isDb) earnedWeight += 5;
    }

    const networks = Object.keys(c.NetworkSettings?.Networks || {});
    totalWeight += 5;
    if (networks.length === 1 && networks[0] === 'bridge') {
      earnedWeight += 2;
      findings.push({ app_slug: slug, container_name: name, category: 'network', check_id: 'default_bridge', severity: 'low',
        title: `${name}: Using default bridge network`, remediation: 'Create custom Docker networks for better isolation.' });
    } else { earnedWeight += 5; }
  }
  return { score: totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 100, findings };
}

async function runSecurityScan(category = 'full') {
  const results = {};
  if (category === 'full' || category === 'containers') results.containers = await scanContainerSecurity();
  if (category === 'full' || category === 'certificates') results.certificates = await scanCertificateSecurity();
  if (category === 'full' || category === 'headers') results.headers = await scanHeaderSecurity();
  if (category === 'full' || category === 'network') results.network = await scanNetworkSecurity();

  const categories = Object.entries(results);
  const overall = categories.length > 0 ? Math.round(categories.reduce((s, [, r]) => s + r.score, 0) / categories.length) : 0;
  const grade = securityGrade(overall);
  const allFindings = categories.flatMap(([, r]) => r.findings);

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  allFindings.forEach(f => counts[f.severity]++);

  const scanResult = db.prepare(`INSERT INTO security_scans (scan_type, overall_score, grade, category_scores, total_findings, critical_count, high_count, medium_count, low_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(category, overall, grade, JSON.stringify(Object.fromEntries(categories.map(([k, v]) => [k, v.score]))), allFindings.length, counts.critical, counts.high, counts.medium, counts.low);

  const scanId = scanResult.lastInsertRowid;
  const ins = db.prepare(`INSERT INTO security_findings (scan_id, app_slug, container_name, category, check_id, severity, title, details, remediation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const insertAll = db.transaction(() => { for (const f of allFindings) ins.run(scanId, f.app_slug, f.container_name, f.category, f.check_id, f.severity, f.title, f.details, f.remediation); });
  insertAll();

  return { scan_id: scanId, overall_score: overall, grade, category_scores: Object.fromEntries(categories.map(([k, v]) => [k, v.score])),
    total_findings: allFindings.length, ...counts, findings: allFindings };
}

// --- Security Manager API ---

app.get('/api/security/scan', asyncRoute(async (req, res) => {
  const result = await runSecurityScan(req.query.category || 'full');
  res.json(result);
}));

app.get('/api/security/status', asyncRoute((_req, res) => {
  const scan = db.prepare('SELECT * FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
  if (!scan) return res.json({ status: 'no_scan', message: 'No security scan has been run yet' });
  const findings = db.prepare(`SELECT * FROM security_findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`).all(scan.id);
  res.json({ ...scan, category_scores: safeJSON(scan.category_scores, {}), findings });
}));

app.get('/api/security/history', asyncRoute((req, res) => {
  const limit = parseInt(req.query.limit) || 30;
  const scans = db.prepare('SELECT * FROM security_scans ORDER BY timestamp DESC LIMIT ?').all(limit);
  res.json(scans.map(s => ({ ...s, category_scores: safeJSON(s.category_scores, {}) })));
}));

app.get('/api/security/app/:slug', asyncRoute((req, res) => {
  const scan = db.prepare('SELECT * FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
  if (!scan) return res.json({ findings: [] });
  const findings = db.prepare('SELECT * FROM security_findings WHERE scan_id = ? AND app_slug = ?').all(scan.id, req.params.slug);
  res.json({ scan_id: scan.id, app_slug: req.params.slug, findings });
}));

app.post('/api/security/dismiss/:id', asyncRoute((req, res) => {
  db.prepare("UPDATE security_findings SET status = 'dismissed', dismissed_at = datetime('now') WHERE id = ?").run(parseId(req.params.id));
  res.json({ ok: true });
}));

// Security crons
cron.schedule('0 1 * * *', async () => {
  console.log('[CRON] Running daily security scan...');
  try { const r = await runSecurityScan('full'); console.log(`[CRON] Security scan complete: ${r.grade} (${r.overall_score}/100, ${r.total_findings} findings)`); }
  catch (err) { cronFail('Security scan', err); }
});

cron.schedule('0 */6 * * *', async () => {
  try {
    const result = await scanCertificateSecurity();
    const critical = result.findings.filter(f => f.severity === 'critical');
    if (critical.length > 0) {
      await sendTelegram(`Security: SSL Alert - ${critical.map(f => f.title).join(', ')}`);
    }
  } catch (err) { cronFail('SSL security check', err); }
});

// Cleanup old security scans (90-day retention)
cron.schedule('0 5 * * 0', () => {
  try {
    const cutoff = new Date(Date.now() - 90 * MS_PER_DAY).toISOString();
    const old = db.prepare('SELECT id FROM security_scans WHERE timestamp < ?').all(cutoff);
    if (old.length > 0) {
      // Safe: placeholders are generated from .map(() => '?') and values are parameterized via .run()
      const placeholders = old.map(() => '?').join(',');
      db.prepare(`DELETE FROM security_findings WHERE scan_id IN (${placeholders})`).run(...old.map(o => o.id));
      db.prepare('DELETE FROM security_scans WHERE timestamp < ?').run(cutoff);
      console.log(`[CRON] Cleaned up ${old.length} old security scans`);
    }
  } catch (err) { cronFail('Security cleanup', err); }
});

// =============================================
// Cross-Promotion System
// =============================================

// CORS preflight for public crosspromo endpoints (called from external sites)
app.options('/api/crosspromo/:path', (_req, res) => {
  setCORS(res);
  res.sendStatus(204);
});
app.options('/api/crosspromo/:id/:action', (_req, res) => {
  setCORS(res);
  res.sendStatus(204);
});

// --- Authenticated endpoints (admin manages campaigns) ---

app.get('/api/marketing/crosspromo', asyncRoute((_req, res) => {
  const campaigns = db.prepare('SELECT * FROM crosspromo_campaigns ORDER BY created_at DESC').all();
  campaigns.forEach(c => { c.banner_data = safeJSON(c.banner_data); });
  res.json(campaigns);
}));

app.post('/api/marketing/crosspromo', asyncRoute(async (req, res) => {
  const { name, source_app, target_app, headline, cta_text } = req.body;
  if (!name || !source_app || !target_app) {
    return res.status(400).json({ error: 'name, source_app, target_app required' });
  }
  if (source_app === target_app) {
    return res.status(400).json({ error: 'source_app and target_app must be different' });
  }

  const sourceApp = findAppBySlug(source_app);
  const targetApp = findAppBySlug(target_app);
  if (!sourceApp || !targetApp) {
    return res.status(400).json({ error: 'Unknown app slug' });
  }

  const campaignHeadline = headline || targetApp.marketing?.tagline || targetApp.description || targetApp.name;
  const campaignCta = cta_text || 'Learn More';

  // Insert campaign, then update with UTM-enriched URL (needs campaign ID)
  const insertCampaign = db.transaction(() => {
    const result = db.prepare(`
      INSERT INTO crosspromo_campaigns (name, source_app, target_app, headline, cta_text, cta_url, status)
      VALUES (?, ?, ?, ?, ?, ?, 'draft')
    `).run(name, source_app, target_app, campaignHeadline, campaignCta, 'https://' + targetApp.domain);
    const campaignId = result.lastInsertRowid;
    const ctaUrl = `https://${targetApp.domain}?utm_source=${encodeURIComponent(source_app)}&utm_medium=crosspromo&utm_campaign=${campaignId}`;
    db.prepare('UPDATE crosspromo_campaigns SET cta_url = ? WHERE id = ?').run(ctaUrl, campaignId);
    return campaignId;
  });
  const campaignId = insertCampaign();

  // Try to generate banners via BannerForge
  let bannerData = null;
  try {
    const bannerforgeUrl = getBannerForgeUrl();
    if (!bannerforgeUrl) throw new Error('BannerForge not configured');
    const brandColors = ['#1a1a2e', '#e94560', '#0f3460'];
    const sizes = [
      { name: 'leaderboard', width: 728, height: 90 },
      { name: 'medium-rectangle', width: 300, height: 250 },
      { name: 'square', width: 1080, height: 1080 },
    ];

    const banners = [];
    for (const size of sizes) {
      try {
        const renderResp = await fetch(bannerforgeUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            layout: 'centered-bold',
            brand: {
              companyName: targetApp.name,
              colors: brandColors,
              tagline: campaignHeadline,
            },
            copy: {
              headline: campaignHeadline,
              cta: campaignCta,
            },
            size: { width: size.width, height: size.height },
            format: 'png',
          }),
          signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
        });

        if (renderResp.ok) {
          const renderResult = await renderResp.json();
          banners.push({ ...size, dataUrl: renderResult.dataUrl || renderResult.url || null });
        }
      } catch (renderErr) {
        console.log(`BannerForge render failed for ${size.name}: ${renderErr.message}`);
      }
    }

    if (banners.length > 0) {
      bannerData = JSON.stringify({ sizes: banners });
    }
  } catch (bfErr) {
    console.log(`BannerForge integration unavailable: ${bfErr.message}`);
  }

  // Fallback: generate simple HTML banners if BannerForge didn't work
  if (!bannerData) {
    const fallbackBanners = [
      { name: 'leaderboard', width: 728, height: 90, html: true },
      { name: 'medium-rectangle', width: 300, height: 250, html: true },
    ];
    bannerData = JSON.stringify({ sizes: fallbackBanners, fallback: true });
  }

  db.prepare('UPDATE crosspromo_campaigns SET banner_data = ? WHERE id = ?').run(bannerData, campaignId);

  const campaign = db.prepare('SELECT * FROM crosspromo_campaigns WHERE id = ?').get(campaignId);
  campaign.banner_data = safeJSON(campaign.banner_data);
  res.json(campaign);
}));

app.patch('/api/marketing/crosspromo/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const { status } = req.body;
  if (!['draft', 'active', 'paused', 'ended'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  db.prepare('UPDATE crosspromo_campaigns SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run(status, id);
  const campaign = db.prepare('SELECT * FROM crosspromo_campaigns WHERE id = ?').get(id);
  if (!campaign) return res.status(404).json({ error: 'Not found' });
  campaign.banner_data = safeJSON(campaign.banner_data);
  res.json(campaign);
}));

app.delete('/api/marketing/crosspromo/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const result = db.prepare('DELETE FROM crosspromo_campaigns WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// --- Public endpoints (no auth — served to external sites) ---

app.get('/api/crosspromo/embed.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'public, max-age=300');
  setCORS(res);
  res.send(`(function(){
  var s=document.currentScript;
  var app=s&&s.getAttribute('data-app');
  if(!app)return;
  var base=s.src.replace(/\\/api\\/crosspromo\\/embed\\.js(\\?.*)?$/,'');
  fetch(base+'/api/crosspromo/banner?app='+encodeURIComponent(app))
    .then(function(r){if(!r.ok)throw new Error();return r.json()})
    .then(function(d){
      if(!d||!d.id)return;
      try{
        var key='crosspromo_'+d.id;
        if(!sessionStorage.getItem(key)){
          fetch(base+'/api/crosspromo/'+d.id+'/view',{method:'POST'});
          sessionStorage.setItem(key,'1');
        }
      }catch(e){}
      function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
      var el=document.getElementById('crosspromo')||document.createElement('div');
      if(!el.id){el.id='crosspromo';document.body.appendChild(el);}
      el.innerHTML='<a href="'+base+'/api/crosspromo/'+d.id+'/click" target="_blank" rel="noopener" '
        +'style="display:inline-block;text-decoration:none;background:linear-gradient(135deg,#1a1a2e,#0f3460);'
        +'color:#fff;padding:12px 24px;border-radius:8px;font-family:system-ui;font-size:14px;">'
        +'<strong>'+esc(d.headline)+'</strong> &mdash; '+esc(d.cta_text)+' &rarr;</a>';
    }).catch(function(){});
})();`);
});

app.get('/api/crosspromo/banner', asyncRoute((req, res) => {
  setCORS(res);
  const app = req.query.app;
  if (!app) return res.status(400).json({ error: 'app query param required' });
  // Find an active campaign where this app is the source (showing the banner)
  const campaign = db.prepare(
    'SELECT id, headline, cta_text, cta_url, banner_data FROM crosspromo_campaigns WHERE source_app = ? AND status = \'active\' ORDER BY created_at DESC LIMIT 1'
  ).get(app);
  if (!campaign) return res.json(null);
  campaign.banner_data = safeJSON(campaign.banner_data);
  res.json(campaign);
}));

app.post('/api/crosspromo/:id/view', asyncRoute((req, res) => {
  setCORS(res);
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  db.prepare('UPDATE crosspromo_campaigns SET views = views + 1 WHERE id = ?').run(id);
  res.json({ ok: true });
}));

app.get('/api/crosspromo/:id/click', (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) return res.redirect('/');
    const campaign = db.prepare('SELECT cta_url FROM crosspromo_campaigns WHERE id = ?').get(id);
    if (!campaign) return res.redirect('/');
    db.prepare('UPDATE crosspromo_campaigns SET clicks = clicks + 1 WHERE id = ?').run(id);
    res.redirect(campaign.cta_url);
  } catch (err) {
    res.redirect('/');
  }
});

// =============================================
// Banner Management System
// =============================================

// CORS preflight for public banner endpoints
app.options('/api/banners/:path', (_req, res) => {
  setCORS(res);
  res.sendStatus(204);
});
app.options('/api/banners/:id/:action', (_req, res) => {
  setCORS(res);
  res.sendStatus(204);
});

// --- Authenticated banner endpoints ---

app.get('/api/marketing/banners', asyncRoute((_req, res) => {
  const banners = db.prepare('SELECT * FROM banners ORDER BY created_at DESC').all();
  const placements = db.prepare('SELECT * FROM banner_placements ORDER BY created_at DESC').all();
  banners.forEach(b => {
    b.bannerforge_config = safeJSON(b.bannerforge_config);
    b.placements = placements.filter(p => p.banner_id === b.id);
    b.total_views = b.placements.reduce((s, p) => s + p.views, 0);
    b.total_clicks = b.placements.reduce((s, p) => s + p.clicks, 0);
  });
  res.json(banners);
}));

app.post('/api/marketing/banners', asyncRoute(async (req, res) => {
  const { name, type, width, height, click_url, tags, content: rawContent, bannerforge_config } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });

  const bannerType = type || 'bannerforge';
  const w = Math.max(1, Math.min(10000, parseInt(width) || 728));
  const h = Math.max(1, Math.min(10000, parseInt(height) || 90));
  let content = rawContent || '';
  let bfConfig = null;

  if (bannerType === 'bannerforge') {
    // Generate via BannerForge API
    const bfc = bannerforge_config || {};
    bfConfig = JSON.stringify(bfc);
    const bfUrl = getBannerForgeUrl();
    if (!bfUrl) return res.status(400).json({ error: 'BannerForge not configured. Set BANNERFORGE_URL or add BannerForge to your apps.' });
    try {
      const renderResp = await fetch(bfUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          layout: bfc.layout || 'centered-bold',
          brand: bfc.brand || { companyName: name, colors: ['#1a1a2e', '#e94560', '#0f3460'] },
          copy: bfc.copy || { headline: name, cta: 'Learn More' },
          size: { width: w, height: h },
          format: 'png',
        }),
        signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
      });
      if (renderResp.ok) {
        const result = await renderResp.json();
        content = result.dataUrl || result.url || '';
      }
    } catch (bfErr) {
      console.log(`BannerForge render failed: ${bfErr.message}`);
    }
    // Fallback to placeholder HTML
    if (!content) {
      const colors = bfc.brand?.colors || ['#1a1a2e', '#e94560'];
      const headline = bfc.copy?.headline || name;
      const cta = bfc.copy?.cta || 'Learn More';
      content = `<div style="width:${w}px;height:${h}px;background:linear-gradient(135deg,${colors[0]},${colors[1] || colors[0]});display:flex;align-items:center;justify-content:center;color:#fff;font-family:system-ui;border-radius:8px;padding:12px"><strong>${headline}</strong>&nbsp;&mdash;&nbsp;${cta}</div>`;
    }
  } else if (bannerType === 'image_url') {
    if (!content) return res.status(400).json({ error: 'content (image URL) required for image_url type' });
  } else if (bannerType === 'custom_html') {
    if (!content) return res.status(400).json({ error: 'content (HTML) required for custom_html type' });
  } else {
    return res.status(400).json({ error: 'type must be bannerforge, image_url, or custom_html' });
  }

  const result = db.prepare(`
    INSERT INTO banners (name, type, width, height, content, bannerforge_config, click_url, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(name, bannerType, w, h, content, bfConfig, click_url || null, tags || null);

  const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(result.lastInsertRowid);
  banner.bannerforge_config = safeJSON(banner.bannerforge_config);
  banner.placements = [];
  banner.total_views = 0;
  banner.total_clicks = 0;
  res.json(banner);
}));

app.put('/api/marketing/banners/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  if (!banner) return res.status(404).json({ error: 'Not found' });

  const { name, click_url, tags } = req.body;
  db.prepare(`UPDATE banners SET name = ?, click_url = ?, tags = ?, updated_at = datetime('now') WHERE id = ?`)
    .run(name || banner.name, click_url !== undefined ? click_url : banner.click_url, tags !== undefined ? tags : banner.tags, id);
  const updated = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  updated.bannerforge_config = safeJSON(updated.bannerforge_config);
  res.json(updated);
}));

app.delete('/api/marketing/banners/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  db.prepare('DELETE FROM banner_placements WHERE banner_id = ?').run(id);
  const result = db.prepare('DELETE FROM banners WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

app.post('/api/marketing/banners/:id/regenerate', asyncRoute(async (req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  if (!banner) return res.status(404).json({ error: 'Not found' });
  if (banner.type !== 'bannerforge') return res.status(400).json({ error: 'Only BannerForge banners can be regenerated' });

  const bfc = safeJSON(banner.bannerforge_config, {});
  const bfUrl = getBannerForgeUrl();
  if (!bfUrl) return res.status(400).json({ error: 'BannerForge not configured. Set BANNERFORGE_URL or add BannerForge to your apps.' });
  const renderResp = await fetch(bfUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      layout: bfc.layout || 'centered-bold',
      brand: bfc.brand || { companyName: banner.name, colors: ['#1a1a2e', '#e94560', '#0f3460'] },
      copy: bfc.copy || { headline: banner.name, cta: 'Learn More' },
      size: { width: banner.width, height: banner.height },
      format: 'png',
    }),
    signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
  });

  if (!renderResp.ok) throw new Error('BannerForge render failed');
  const result = await renderResp.json();
  const content = result.dataUrl || result.url || '';
  if (!content) throw new Error('BannerForge returned empty result');

  db.prepare(`UPDATE banners SET content = ?, updated_at = datetime('now') WHERE id = ?`).run(content, id);
  const updated = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
  updated.bannerforge_config = safeJSON(updated.bannerforge_config);
  res.json(updated);
}));

// --- Placement endpoints ---

app.get('/api/marketing/placements', asyncRoute((req, res) => {
  const appFilter = req.query.app;
  let placements;
  if (appFilter) {
    placements = db.prepare('SELECT bp.*, b.name as banner_name, b.type as banner_type, b.width, b.height FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id WHERE bp.app_slug = ? ORDER BY bp.priority DESC, bp.created_at DESC').all(appFilter);
  } else {
    placements = db.prepare('SELECT bp.*, b.name as banner_name, b.type as banner_type, b.width, b.height FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id ORDER BY bp.priority DESC, bp.created_at DESC').all();
  }
  res.json(placements);
}));

app.post('/api/marketing/placements', asyncRoute((req, res) => {
  const { banner_id, app_slug, position, weight, click_url, start_date, end_date } = req.body;
  if (!banner_id || !app_slug) return res.status(400).json({ error: 'banner_id and app_slug required' });

  const banner = db.prepare('SELECT id FROM banners WHERE id = ?').get(banner_id);
  if (!banner) return res.status(400).json({ error: 'Banner not found' });

  const app = findAppBySlug(app_slug);
  if (!app) return res.status(400).json({ error: 'Unknown app slug' });

  const result = db.prepare(`
    INSERT INTO banner_placements (banner_id, app_slug, position, weight, click_url, start_date, end_date)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(banner_id, app_slug, position || 'default', parseInt(weight) || 100, click_url || null, start_date || null, end_date || null);

  const placement = db.prepare('SELECT * FROM banner_placements WHERE id = ?').get(result.lastInsertRowid);
  res.json(placement);
}));

app.patch('/api/marketing/placements/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const placement = db.prepare('SELECT * FROM banner_placements WHERE id = ?').get(id);
  if (!placement) return res.status(404).json({ error: 'Not found' });

  const { status, weight, priority, click_url, start_date, end_date } = req.body;
  if (status && !['draft', 'active', 'paused', 'ended'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  db.prepare(`UPDATE banner_placements SET
    status = ?, weight = ?, priority = ?, click_url = ?, start_date = ?, end_date = ?, updated_at = datetime('now')
    WHERE id = ?`).run(
    status || placement.status,
    weight !== undefined ? parseInt(weight) : placement.weight,
    priority !== undefined ? parseInt(priority) : placement.priority,
    click_url !== undefined ? click_url : placement.click_url,
    start_date !== undefined ? start_date : placement.start_date,
    end_date !== undefined ? end_date : placement.end_date,
    id
  );

  const updated = db.prepare('SELECT * FROM banner_placements WHERE id = ?').get(id);
  res.json(updated);
}));

app.delete('/api/marketing/placements/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const result = db.prepare('DELETE FROM banner_placements WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// --- Public banner serve endpoints ---

app.get('/api/banners/embed.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'public, max-age=300');
  setCORS(res);
  res.send(`(function(){
  var s=document.currentScript;
  var app=s&&s.getAttribute('data-app');
  if(!app)return;
  var pos=s.getAttribute('data-position')||'default';
  var base=s.src.replace(/\\/api\\/banners\\/embed\\.js(\\?.*)?$/,'');
  fetch(base+'/api/banners/serve?app='+encodeURIComponent(app)+'&pos='+encodeURIComponent(pos))
    .then(function(r){if(!r.ok)throw new Error();return r.json()})
    .then(function(d){
      if(!d||!d.placement_id)return;
      try{
        var key='banner_'+d.placement_id;
        if(!sessionStorage.getItem(key)){
          fetch(base+'/api/banners/'+d.placement_id+'/view',{method:'POST'});
          sessionStorage.setItem(key,'1');
        }
      }catch(e){}
      function esc(t){return String(t||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
      var w=parseInt(d.width)||728,h=parseInt(d.height)||90;
      var el=document.getElementById('dockfolio-banner')||document.createElement('div');
      if(!el.id){el.id='dockfolio-banner';document.body.appendChild(el);}
      var link=base+'/api/banners/'+parseInt(d.placement_id)+'/click';
      if(d.type==='image_url'){
        el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener"><img src="'+esc(d.content)+'" width="'+w+'" height="'+h+'" style="border:0;max-width:100%;height:auto" alt="'+esc(d.name)+'"></a>';
      }else if(d.type==='custom_html'){
        el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener" style="display:inline-block;text-decoration:none">'+esc(d.content)+'</a>';
      }else{
        if(d.content&&d.content.indexOf('data:image')===0){
          el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener"><img src="'+esc(d.content)+'" width="'+w+'" height="'+h+'" style="border:0;max-width:100%;height:auto" alt="'+esc(d.name)+'"></a>';
        }else{
          el.innerHTML='<a href="'+link+'" target="_blank" rel="noopener" style="display:inline-block;text-decoration:none;color:#fff;background:linear-gradient(135deg,#1a1a2e,#0f3460);padding:12px 24px;border-radius:8px;font-family:system-ui;font-size:14px"><strong>'+esc(d.name)+'</strong> &rarr;</a>';
        }
      }
    }).catch(function(){});
})();`);
});

app.get('/api/banners/serve', rlBannerServe, asyncRoute((req, res) => {
  setCORS(res);
  const app = req.query.app;
  const pos = req.query.pos || 'default';
  if (!app) return res.status(400).json({ error: 'app query param required' });

  const now = new Date().toISOString();
  const placements = db.prepare(`
    SELECT bp.id as placement_id, bp.weight, bp.click_url as placement_click_url,
           b.id as banner_id, b.name, b.type, b.width, b.height, b.content, b.click_url as banner_click_url
    FROM banner_placements bp
    JOIN banners b ON bp.banner_id = b.id
    WHERE bp.app_slug = ? AND bp.status = 'active'
      AND (bp.position = ? OR bp.position = 'default')
      AND (bp.start_date IS NULL OR bp.start_date <= ?)
      AND (bp.end_date IS NULL OR bp.end_date >= ?)
    ORDER BY bp.priority DESC
  `).all(app, pos, now, now);

  if (placements.length === 0) return res.json(null);

  // Weighted random selection
  let selected = placements[0];
  if (placements.length > 1) {
    const totalWeight = placements.reduce((s, p) => s + p.weight, 0);
    if (totalWeight > 0) {
      let rand = Math.random() * totalWeight;
      for (const p of placements) {
        rand -= p.weight;
        if (rand <= 0) { selected = p; break; }
      }
    } else {
      selected = placements[Math.floor(Math.random() * placements.length)];
    }
  }

  res.json({
    placement_id: selected.placement_id,
    banner_id: selected.banner_id,
    name: selected.name,
    type: selected.type,
    width: selected.width,
    height: selected.height,
    content: selected.content,
    click_url: selected.placement_click_url || selected.banner_click_url || '#',
  });
}));

app.post('/api/banners/:placementId/view', rlBannerTrack, asyncRoute((req, res) => {
  setCORS(res);
  const id = parseId(req.params.placementId);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  db.prepare('UPDATE banner_placements SET views = views + 1 WHERE id = ?').run(id);
  res.json({ ok: true });
}));

app.get('/api/banners/:placementId/click', rlBannerTrack, (req, res) => {
  try {
    const id = parseId(req.params.placementId);
    if (isNaN(id)) return res.redirect('/');
    const placement = db.prepare(`
      SELECT bp.click_url as p_url, b.click_url as b_url
      FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id
      WHERE bp.id = ?
    `).get(id);
    if (!placement) return res.redirect('/');
    db.prepare('UPDATE banner_placements SET clicks = clicks + 1 WHERE id = ?').run(id);
    res.redirect(placement.p_url || placement.b_url || '/');
  } catch (err) {
    res.redirect('/');
  }
});

// Banner injection status — checks which sites have embed.js deployed
app.get('/api/banners/injection-status', asyncRoute(async (_req, res) => {
  const results = [];
  for (const app of config.apps || []) {
    if (!app.domain || app.type === 'infra' || app.type === 'redirect') continue;
    const slug = slugify(app.name);
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_QUICK);
      const resp = await fetch(`https://${app.domain}/`, {
        headers: { 'Accept-Encoding': '' },
        signal: controller.signal,
      });
      clearTimeout(timeout);
      const html = await resp.text();
      const injected = html.includes('banners/embed.js') && html.includes(`data-app="${slug}"`);
      const proxyWorks = html.includes('/api/banners/embed.js');
      results.push({ slug, domain: app.domain, injected, proxyWorks });
    } catch {
      results.push({ slug, domain: app.domain, injected: null, error: 'unreachable' });
    }
  }
  res.json(results);
}));

// =============================================
// Marketing Playbook
// =============================================

app.get('/api/marketing/playbooks', asyncRoute((req, res) => {
  const appSlug = req.query.app;
  let entries;
  if (appSlug) {
    entries = db.prepare('SELECT * FROM marketing_playbooks WHERE app_slug = ? ORDER BY section, priority DESC, created_at').all(appSlug);
  } else {
    entries = db.prepare('SELECT * FROM marketing_playbooks ORDER BY app_slug, section, priority DESC, created_at').all();
  }
  res.json(entries);
}));

app.post('/api/marketing/playbooks', asyncRoute((req, res) => {
  const { app_slug, section, title, content, status, priority } = req.body;
  if (!app_slug || !section || !title || !content) {
    return res.status(400).json({ error: 'app_slug, section, title, content required' });
  }
  const validSections = ['strategy', 'channels', 'content', 'seo', 'email', 'crosssell', 'notes'];
  if (!validSections.includes(section)) {
    return res.status(400).json({ error: `Invalid section. Must be one of: ${validSections.join(', ')}` });
  }

  const result = db.prepare(`
    INSERT INTO marketing_playbooks (app_slug, section, title, content, status, priority)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(app_slug, section, title, content, status || 'draft', parseInt(priority) || 0);

  const entry = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(result.lastInsertRowid);
  res.json(entry);
}));

app.put('/api/marketing/playbooks/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const entry = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(id);
  if (!entry) return res.status(404).json({ error: 'Not found' });

  const { title, content, status, priority } = req.body;
  db.prepare(`UPDATE marketing_playbooks SET title = ?, content = ?, status = ?, priority = ?, updated_at = datetime('now') WHERE id = ?`)
    .run(title || entry.title, content || entry.content, status || entry.status, priority !== undefined ? parseInt(priority) : entry.priority, id);

  const updated = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(id);
  res.json(updated);
}));

app.delete('/api/marketing/playbooks/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const result = db.prepare('DELETE FROM marketing_playbooks WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// --- Playbook Generation Helpers ---
function buildPlaybookPrompt(appDef, seoAudit, revenueData) {
  return `You are a marketing strategist for a portfolio of SaaS/tool apps.
Generate a marketing playbook for ${appDef.name} (${appDef.domain}).

App details:
- Description: ${appDef.description}
- Tech: ${appDef.tech || 'Unknown'}
- Target audience: ${appDef.marketing?.targetAudience || 'General'}
- Languages: ${(appDef.marketing?.languages || ['en']).join(', ')}
- Tagline: ${appDef.marketing?.tagline || 'N/A'}
${seoAudit ? `- Current SEO score: ${seoAudit.score}/100 (Grade: ${seoAudit.grade})` : '- SEO: not yet audited'}
${revenueData ? `- Recent revenue data: ${revenueData.value}` : '- Revenue: no data yet'}

Generate 6 sections. For each section, output a JSON object on its own line with fields: section, title, content (markdown).

Sections needed:
1. section:"strategy" Positioning, key differentiator, 3-month goals (3-5 bullets each)
2. section:"channels" Ranked marketing channels with effort/impact ratings
3. section:"content" 5 blog post topics, 3 social media angles, video ideas
4. section:"seo" Specific SEO action items based on current score
5. section:"email" Onboarding (3 emails), activation (2 emails), retention (2 emails), just subject lines + timing
6. section:"crosssell" How to cross-promote with related apps in the portfolio

Output ONLY a JSON array of 6 objects, no other text. Each object: {"section":"...", "title":"...", "content":"..."}`;
}

function parseAIJsonArray(text) {
  // Strip markdown code fences that LLMs often wrap around JSON
  text = text.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();
  const jsonMatch = text.match(/\[[\s\S]*\]/);
  let jsonStr = jsonMatch ? jsonMatch[0] : text;
  try {
    return JSON.parse(jsonStr);
  } catch (_) {
    // Fix truncated JSON: remove last incomplete object and close the array
    jsonStr = jsonStr.replace(/,\s*\{[^}]*$/, '').replace(/,\s*$/, '');
    if (!jsonStr.endsWith(']')) jsonStr += ']';
    return JSON.parse(jsonStr);
  }
}

app.post('/api/marketing/playbooks/:appSlug/generate', asyncRoute(async (req, res) => {
  const appSlug = req.params.appSlug;
  const appDef = findAppBySlug(appSlug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(500).json({ error: 'No Anthropic API key available' });

  const slug = slugify(appDef.name);
  const seoAudit = qLatestSEO.get(slug);
  const revenueData = qLatestMetric.get(slug, 'revenue');

  const prompt = buildPlaybookPrompt(appDef, seoAudit, revenueData);
  const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
    maxTokens: 4096, timeout: TIMEOUT_AI, messages: [{ role: 'user', content: prompt }],
  }));

  const sections = parseAIJsonArray(ai.text || '[]');

  const insertPlaybook = db.transaction(() => {
    db.prepare('DELETE FROM marketing_playbooks WHERE app_slug = ?').run(slug);
    for (const s of sections) {
      if (s.section && s.title && s.content) {
        db.prepare('INSERT INTO marketing_playbooks (app_slug, section, title, content, status) VALUES (?, ?, ?, ?, ?)')
          .run(slug, s.section, s.title, s.content, 'draft');
      }
    }
  });
  insertPlaybook();

  const entries = db.prepare('SELECT * FROM marketing_playbooks WHERE app_slug = ? ORDER BY section, priority DESC').all(slug);
  res.json({ entries, tokens: ai.tokens, generated: new Date().toISOString() });
}));

// =============================================
// Projects Manager
// =============================================

// Initialize project_meta defaults for all apps in config.yml
function initProjectDefaults() {
  const lifecycleByType = { saas: 'launched', tool: 'launched', infra: 'mature', static: 'mature', redirect: 'deprecated' };
  const priorityByType = { saas: 1, tool: 1, infra: 2, static: 3, redirect: 4 };
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const existing = db.prepare('SELECT id FROM project_meta WHERE app_slug = ?').get(slug);
    if (!existing) {
      db.prepare('INSERT INTO project_meta (app_slug, lifecycle, priority) VALUES (?, ?, ?)').run(slug, lifecycleByType[appDef.type] || 'launched', priorityByType[appDef.type] || 2);
    }
  }
}
try { initProjectDefaults(); } catch (err) { console.error('[PROJECTS] Init error:', err.message); }

// --- Overview: All apps enriched with meta + live KPIs ---
app.get('/api/projects/overview', asyncRoute(async (req, res) => {
  const allMeta = db.prepare('SELECT * FROM project_meta').all();
  const metaMap = Object.fromEntries(allMeta.map(m => [m.app_slug, m]));
  const today = todayString();

  const apps = config.apps.map(appDef => {
    const slug = slugify(appDef.name);
    const meta = metaMap[slug] || {};

    // Open task count
    const taskCounts = db.prepare("SELECT status, COUNT(*) as count FROM project_tasks WHERE app_slug = ? GROUP BY status").all(slug);
    const taskMap = Object.fromEntries(taskCounts.map(t => [t.status, t.count]));
    const openTasks = (taskMap.todo || 0) + (taskMap.in_progress || 0) + (taskMap.blocked || 0);
    const doneTasks = taskMap.done || 0;
    const overdueTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND due_date < ? AND status NOT IN ('done','cancelled')").get(slug, today)?.count || 0;

    // Roadmap counts
    const roadmapCounts = db.prepare("SELECT status, COUNT(*) as count FROM project_roadmap WHERE app_slug = ? GROUP BY status").all(slug);
    const rmMap = Object.fromEntries(roadmapCounts.map(r => [r.status, r.count]));

    // Latest SEO score
    const seo = qLatestSEO.get(slug);

    // Latest security findings count for this app
    const secFindings = db.prepare("SELECT COUNT(*) as count FROM security_findings WHERE app_slug = ? AND status = 'open'").get(slug);

    // Latest MRR from metrics_daily
    const mrrRow = qLatestMetric.get(slug, 'mrr');

    return {
      slug, name: appDef.name, type: appDef.type, domain: appDef.domain,
      description: appDef.description, tech: appDef.tech,
      lifecycle: meta.lifecycle || 'launched',
      priority: meta.priority || 2,
      revenue_goal_mrr: meta.revenue_goal_mrr,
      traffic_goal_mpv: meta.traffic_goal_mpv,
      user_goal: meta.user_goal,
      notes: meta.notes,
      mrr: mrrRow?.value || 0,
      seo_score: seo?.score || null, seo_grade: seo?.grade || null,
      security_findings: secFindings?.count || 0,
      tasks: { open: openTasks, done: doneTasks, overdue: overdueTasks },
      roadmap: { idea: rmMap.idea || 0, planned: rmMap.planned || 0, in_progress: rmMap.in_progress || 0, shipped: rmMap.shipped || 0 },
    };
  });

  // Portfolio totals
  const totalOpenTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE status NOT IN ('done','cancelled')").get()?.count || 0;
  const totalOverdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today)?.count || 0;
  const thisWeekDone = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE completed_at >= datetime('now', '-7 days')").get()?.count || 0;

  res.json({ apps, totals: { openTasks: totalOpenTasks, overdueTasks: totalOverdue, completedThisWeek: thisWeekDone } });
}));

// --- Update project meta ---
app.put('/api/projects/meta/:slug', asyncRoute((req, res) => {
  const slug = req.params.slug;
  const { lifecycle, priority, revenue_goal_mrr, traffic_goal_mpv, user_goal, notes } = req.body;
  const ALLOWED_PROJECT_META_FIELDS = ['lifecycle', 'priority', 'revenue_goal_mrr', 'traffic_goal_mpv', 'user_goal', 'notes'];
  const existing = db.prepare('SELECT id FROM project_meta WHERE app_slug = ?').get(slug);
  if (!existing) {
    db.prepare('INSERT INTO project_meta (app_slug, lifecycle, priority, revenue_goal_mrr, traffic_goal_mpv, user_goal, notes) VALUES (?, ?, ?, ?, ?, ?, ?)').run(slug, lifecycle || 'launched', priority || 2, revenue_goal_mrr || null, traffic_goal_mpv || null, user_goal || null, notes || null);
  } else {
    const fields = [];
    const values = [];
    if (lifecycle !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('lifecycle')) { fields.push('lifecycle = ?'); values.push(lifecycle); }
    if (priority !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('priority')) { fields.push('priority = ?'); values.push(priority); }
    if (revenue_goal_mrr !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('revenue_goal_mrr')) { fields.push('revenue_goal_mrr = ?'); values.push(revenue_goal_mrr); }
    if (traffic_goal_mpv !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('traffic_goal_mpv')) { fields.push('traffic_goal_mpv = ?'); values.push(traffic_goal_mpv); }
    if (user_goal !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('user_goal')) { fields.push('user_goal = ?'); values.push(user_goal); }
    if (notes !== undefined && ALLOWED_PROJECT_META_FIELDS.includes('notes')) { fields.push('notes = ?'); values.push(notes); }
    if (fields.length > 0) {
      fields.push("updated_at = datetime('now')");
      values.push(slug);
      db.prepare(`UPDATE project_meta SET ${fields.join(', ')} WHERE app_slug = ?`).run(...values);
    }
  }
  res.json({ ok: true });
}));

// --- Tasks CRUD ---
app.get('/api/projects/tasks', asyncRoute((req, res) => {
  const { app, status, priority } = req.query;
  let sql = 'SELECT * FROM project_tasks WHERE 1=1';
  const params = [];
  if (app) { sql += ' AND app_slug = ?'; params.push(app); }
  if (status) { sql += ' AND status = ?'; params.push(status); }
  if (priority) { sql += ' AND priority = ?'; params.push(priority); }
  sql += ' ORDER BY CASE priority WHEN \'critical\' THEN 0 WHEN \'high\' THEN 1 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 3 END, due_date ASC NULLS LAST, created_at DESC';
  res.json(db.prepare(sql).all(...params));
}));

app.post('/api/projects/tasks', asyncRoute((req, res) => {
  const { app_slug, title, description, priority, due_date, reminder_at, tags } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  const result = db.prepare('INSERT INTO project_tasks (app_slug, title, description, priority, due_date, reminder_at, tags) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    app_slug || null, title, description || null, priority || 'medium', due_date || null, reminder_at || null, tags ? JSON.stringify(tags) : null
  );
  res.json({ ok: true, id: result.lastInsertRowid });
}));

app.put('/api/projects/tasks/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid task ID' });
  const { title, description, status, priority, due_date, reminder_at, tags, app_slug } = req.body;
  const ALLOWED_TASK_FIELDS = ['title', 'description', 'status', 'priority', 'due_date', 'reminder_at', 'tags', 'app_slug'];
  const fields = [];
  const values = [];
  if (title !== undefined && ALLOWED_TASK_FIELDS.includes('title')) { fields.push('title = ?'); values.push(title); }
  if (description !== undefined && ALLOWED_TASK_FIELDS.includes('description')) { fields.push('description = ?'); values.push(description); }
  if (status !== undefined && ALLOWED_TASK_FIELDS.includes('status')) { fields.push('status = ?'); values.push(status); }
  if (priority !== undefined && ALLOWED_TASK_FIELDS.includes('priority')) { fields.push('priority = ?'); values.push(priority); }
  if (due_date !== undefined && ALLOWED_TASK_FIELDS.includes('due_date')) { fields.push('due_date = ?'); values.push(due_date); }
  if (reminder_at !== undefined && ALLOWED_TASK_FIELDS.includes('reminder_at')) { fields.push('reminder_at = ?'); values.push(reminder_at); fields.push('reminder_sent = 0'); }
  if (tags !== undefined && ALLOWED_TASK_FIELDS.includes('tags')) { fields.push('tags = ?'); values.push(JSON.stringify(tags)); }
  if (app_slug !== undefined && ALLOWED_TASK_FIELDS.includes('app_slug')) { fields.push('app_slug = ?'); values.push(app_slug); }
  if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  const result = db.prepare(`UPDATE project_tasks SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  if (result.changes === 0) return res.status(404).json({ error: 'Task not found' });
  res.json({ ok: true });
}));

app.delete('/api/projects/tasks/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid task ID' });
  const result = db.prepare('DELETE FROM project_tasks WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Task not found' });
  res.json({ ok: true });
}));

app.post('/api/projects/tasks/:id/complete', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid task ID' });
  const result = db.prepare("UPDATE project_tasks SET status = 'done', completed_at = datetime('now'), updated_at = datetime('now') WHERE id = ?").run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Task not found' });
  res.json({ ok: true });
}));

app.get('/api/projects/tasks/overdue', asyncRoute((_req, res) => {
  const today = todayString();
  const tasks = db.prepare("SELECT * FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled') ORDER BY due_date ASC").all(today);
  res.json(tasks);
}));

app.get('/api/projects/tasks/today', asyncRoute((_req, res) => {
  const today = todayString();
  const tasks = db.prepare("SELECT * FROM project_tasks WHERE (due_date <= ? OR due_date IS NULL) AND status NOT IN ('done','cancelled') ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END, due_date ASC").all(today);
  res.json(tasks);
}));

app.post('/api/projects/tasks/import', asyncRoute((req, res) => {
  const { text, app_slug } = req.body;
  if (!text) return res.status(400).json({ error: 'text is required' });
  const lines = text.split('\n');
  let created = 0;
  for (const line of lines) {
    const doneMatch = line.match(/^[-*]\s+\[x\]\s+(.+)/i);
    const todoMatch = line.match(/^[-*]\s+\[\s?\]\s+(.+)/i);
    if (doneMatch) {
      db.prepare("INSERT INTO project_tasks (app_slug, title, status, completed_at) VALUES (?, ?, 'done', datetime('now'))").run(app_slug || null, doneMatch[1].trim());
      created++;
    } else if (todoMatch) {
      db.prepare("INSERT INTO project_tasks (app_slug, title, status) VALUES (?, ?, 'todo')").run(app_slug || null, todoMatch[1].trim());
      created++;
    }
  }
  res.json({ ok: true, created });
}));

// --- Roadmap CRUD ---
app.get('/api/projects/roadmap', asyncRoute((req, res) => {
  const { app, status } = req.query;
  let sql = 'SELECT * FROM project_roadmap WHERE 1=1';
  const params = [];
  if (app) { sql += ' AND app_slug = ?'; params.push(app); }
  if (status) { sql += ' AND status = ?'; params.push(status); }
  sql += " ORDER BY CASE status WHEN 'in_progress' THEN 0 WHEN 'planned' THEN 1 WHEN 'idea' THEN 2 WHEN 'shipped' THEN 3 WHEN 'cancelled' THEN 4 END, target_date ASC NULLS LAST";
  res.json(db.prepare(sql).all(...params));
}));

app.post('/api/projects/roadmap', asyncRoute((req, res) => {
  const { app_slug, title, description, type, status, target_date, impact, effort } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });
  const result = db.prepare('INSERT INTO project_roadmap (app_slug, title, description, type, status, target_date, impact, effort) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
    app_slug || null, title, description || null, type || 'feature', status || 'planned', target_date || null, impact || 'medium', effort || 'medium'
  );
  res.json({ ok: true, id: result.lastInsertRowid });
}));

app.put('/api/projects/roadmap/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid roadmap ID' });
  const { title, description, type, status, target_date, impact, effort, app_slug } = req.body;
  const fields = [];
  const values = [];
  if (title !== undefined) { fields.push('title = ?'); values.push(title); }
  if (description !== undefined) { fields.push('description = ?'); values.push(description); }
  if (type !== undefined) { fields.push('type = ?'); values.push(type); }
  if (status !== undefined) { fields.push('status = ?'); values.push(status); }
  if (target_date !== undefined) { fields.push('target_date = ?'); values.push(target_date); }
  if (impact !== undefined) { fields.push('impact = ?'); values.push(impact); }
  if (effort !== undefined) { fields.push('effort = ?'); values.push(effort); }
  if (app_slug !== undefined) { fields.push('app_slug = ?'); values.push(app_slug); }
  if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
  fields.push("updated_at = datetime('now')");
  values.push(id);
  const result = db.prepare(`UPDATE project_roadmap SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  if (result.changes === 0) return res.status(404).json({ error: 'Roadmap item not found' });
  res.json({ ok: true });
}));

app.post('/api/projects/roadmap/:id/ship', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid roadmap ID' });
  const result = db.prepare("UPDATE project_roadmap SET status = 'shipped', shipped_date = datetime('now'), updated_at = datetime('now') WHERE id = ?").run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Roadmap item not found' });
  res.json({ ok: true });
}));

// DELETE /api/projects/roadmap/:id — Delete roadmap item
app.delete('/api/projects/roadmap/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid roadmap ID' });
  const result = db.prepare('DELETE FROM project_roadmap WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Roadmap item not found' });
  res.json({ ok: true });
}));

// --- AI Insights ---
app.get('/api/projects/insights/:slug', asyncRoute(async (req, res) => {
  const slug = req.params.slug;
  const type = req.query.type || 'next_actions';
  const force = req.query.force === 'true';

  if (!force) {
    const cached = db.prepare('SELECT * FROM project_ai_insights WHERE app_slug = ? AND insight_type = ?').get(slug, type);
    if (cached) {
      const age = Date.now() - new Date(cached.generated_at).getTime();
      const maxAge = type === 'weekly_summary' ? 7 * MS_PER_DAY : 72 * MS_PER_HOUR;
      if (age < maxAge) return res.json({ content: cached.content, generated_at: cached.generated_at, cached: true });
    }
  }

  const appDef = config.apps.find(a => slugify(a.name) === slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });

  const meta = db.prepare('SELECT * FROM project_meta WHERE app_slug = ?').get(slug) || {};
  const openTasks = db.prepare("SELECT title FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled') LIMIT 5").all(slug);
  const roadmapItems = db.prepare("SELECT title, status FROM project_roadmap WHERE app_slug = ? AND status IN ('planned','in_progress') LIMIT 5").all(slug);
  const seo = qLatestSEO.get(slug);
  const mrrRow = qLatestMetric.get(slug, 'mrr');

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(503).json({ error: 'No Anthropic API key available' });

  const prompt = `You are an indie SaaS advisor for a solo founder. Given:
- App: ${appDef.name} (${appDef.type}) — ${appDef.description}
- Lifecycle: ${meta.lifecycle || 'launched'}
- MRR: €${((mrrRow?.value || 0) / 100).toFixed(0)} ${meta.revenue_goal_mrr ? `(goal: €${(meta.revenue_goal_mrr / 100).toFixed(0)})` : '(no goal set)'}
- SEO score: ${seo?.score ?? 'unknown'}/100 (${seo?.grade || 'N/A'})
- Open tasks: ${openTasks.length > 0 ? openTasks.map(t => t.title).join(', ') : 'none'}
- Roadmap: ${roadmapItems.length > 0 ? roadmapItems.map(r => `${r.title} (${r.status})`).join(', ') : 'none'}
- Tech: ${appDef.tech || 'unknown'}
- Domain: ${appDef.domain || 'none'}

${type === 'next_actions' ? 'Output 3-5 specific, immediately actionable next steps. Be direct. No fluff. Each step should be doable in under a day. Format as a markdown bullet list.' : 'Write a concise weekly status summary in 3 short paragraphs: 1) current state, 2) progress this week, 3) recommended focus for next week.'}`;

  const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { messages: [{ role: 'user', content: prompt }] }));

  db.prepare('INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES (?, ?, ?, ?, datetime(\'now\')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at').run(slug, type, ai.text || 'No insight generated', ai.outputTokens);

  res.json({ content: ai.text || 'No insight generated', generated_at: new Date().toISOString(), cached: false });
}));

app.get('/api/projects/insights/portfolio/summary', asyncRoute(async (req, res) => {
  const force = req.query.force === 'true';
  if (!force) {
    const cached = db.prepare("SELECT * FROM project_ai_insights WHERE app_slug = '_portfolio' AND insight_type = 'summary'").get();
    if (cached) {
      const age = Date.now() - new Date(cached.generated_at).getTime();
      if (age < 24 * MS_PER_HOUR) return res.json({ content: cached.content, generated_at: cached.generated_at, cached: true });
    }
  }

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(503).json({ error: 'No Anthropic API key available' });

  const saasApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
  const appSummaries = saasApps.map(a => {
    const slug = slugify(a.name);
    const meta = db.prepare('SELECT lifecycle, priority FROM project_meta WHERE app_slug = ?').get(slug) || {};
    const openTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.count || 0;
    const mrr = qLatestMetric.get(slug, 'mrr')?.value || 0;
    return `- ${a.name}: lifecycle=${meta.lifecycle || 'launched'}, MRR=€${(mrr / 100).toFixed(0)}, ${openTasks} open tasks`;
  }).join('\n');

  const today = todayString();
  const totalOverdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today)?.count || 0;
  const weekDone = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE completed_at >= datetime('now', '-7 days')").get()?.count || 0;

  const prompt = `You are an indie SaaS portfolio advisor. Here is the current state of a solo founder's app portfolio:

${appSummaries}

Portfolio stats: ${totalOverdue} overdue tasks, ${weekDone} tasks completed this week.

Write a concise 3-paragraph portfolio briefing: 1) overall health assessment, 2) what to focus on this week, 3) one strategic recommendation. Be direct, specific, actionable.`;

  const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { messages: [{ role: 'user', content: prompt }] }));

  db.prepare("INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES ('_portfolio', 'summary', ?, ?, datetime('now')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at").run(ai.text || 'No summary generated', ai.outputTokens);

  res.json({ content: ai.text || 'No summary generated', generated_at: new Date().toISOString(), cached: false });
}));

// --- Projects Cron Jobs ---

// Every 15 min: check for due reminders, send Telegram
cron.schedule('*/15 * * * *', async () => {
  try {
    const now = new Date().toISOString();
    const dueTasks = db.prepare("SELECT * FROM project_tasks WHERE reminder_at <= ? AND reminder_sent = 0 AND status NOT IN ('done','cancelled')").all(now);
    if (dueTasks.length === 0) return;

    for (const task of dueTasks) {
      const appName = config.apps.find(a => slugify(a.name) === task.app_slug)?.name || 'Portfolio';
      await sendTelegram(`📋 Reminder — ${appName}\nTask: ${task.title}${task.due_date ? `\nDue: ${task.due_date}` : ''}`);
      db.prepare('UPDATE project_tasks SET reminder_sent = 1 WHERE id = ?').run(task.id);
    }
    console.log(`[PROJECTS] Sent ${dueTasks.length} reminder(s)`);
  } catch (err) { cronFail('Task reminders', err); }
});

// Daily 8 AM: overdue task alert
cron.schedule('0 8 * * *', async () => {
  try {
    const today = todayString();
    const overdue = db.prepare("SELECT * FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled') ORDER BY due_date ASC LIMIT 10").all(today);
    if (overdue.length === 0) return;

    const lines = overdue.map(t => {
      const appName = config.apps.find(a => slugify(a.name) === t.app_slug)?.name || 'Portfolio';
      const daysLate = Math.ceil((new Date(today) - new Date(t.due_date)) / MS_PER_DAY);
      return `• ${appName}: ${t.title} (${daysLate}d late)`;
    });
    await sendTelegram(`⚠ Overdue Tasks — ${overdue.length} task${overdue.length > 1 ? 's' : ''} past due:\n${lines.join('\n')}`);
    console.log(`[PROJECTS] Overdue alert sent (${overdue.length} tasks)`);
  } catch (err) { cronFail('Overdue tasks', err); }
});

// Weekly Monday 6 AM: snapshot per-app KPIs
cron.schedule('0 6 * * 1', async () => {
  try {
    const snapDate = todayString();
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const mrr = qLatestMetric.get(slug, 'mrr')?.value || null;
      const openTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.count || 0;
      const doneTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status = 'done'").get(slug)?.count || 0;
      const shipped = db.prepare("SELECT COUNT(*) as count FROM project_roadmap WHERE app_slug = ? AND status = 'shipped'").get(slug)?.count || 0;
      const seo = qLatestSEO.get(slug)?.score || null;
      const secScore = db.prepare('SELECT score FROM security_scans WHERE app_slug = ? ORDER BY timestamp DESC LIMIT 1').get(slug)?.score || null;

      // Plausible traffic (30d visitors)
      let traffic30d = null;
      const plausibleKey = getPlausibleApiKey();
      if (appDef.domain && plausibleKey) {
        try {
          const tRes = await fetch(
            `${getPlausibleUrl()}/api/v1/stats/aggregate?site_id=${appDef.domain}&period=30d&metrics=visitors`,
            { headers: { Authorization: `Bearer ${plausibleKey}` }, signal: AbortSignal.timeout(TIMEOUT_QUICK) }
          );
          if (tRes.ok) {
            const tData = await tRes.json();
            traffic30d = tData?.results?.visitors?.value || 0;
          }
        } catch { /* Plausible may not track all sites */ }
      }

      // Container health
      let healthStatus = 'unknown';
      if (appDef.containers?.length > 0) {
        try {
          const containers = await docker.listContainers({ all: true });
          const appContainers = containers.filter(c => appDef.containers.includes(containerName(c)));
          if (appContainers.length === 0) healthStatus = 'unknown';
          else if (appContainers.every(c => c.State === 'running')) healthStatus = 'healthy';
          else healthStatus = 'degraded';
        } catch { healthStatus = 'unknown'; }
      }

      db.prepare(`INSERT INTO project_snapshots (app_slug, snapshot_date, mrr_cents, traffic_30d, task_count_open, task_count_done, roadmap_shipped, security_score, seo_score, health_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(app_slug, snapshot_date) DO UPDATE SET
        mrr_cents = excluded.mrr_cents, traffic_30d = excluded.traffic_30d, task_count_open = excluded.task_count_open, task_count_done = excluded.task_count_done,
        roadmap_shipped = excluded.roadmap_shipped, security_score = excluded.security_score, seo_score = excluded.seo_score, health_status = excluded.health_status`).run(
        slug, snapDate, mrr, traffic30d, openTasks, doneTasks, shipped, secScore, seo, healthStatus
      );
    }
    console.log(`[PROJECTS] Weekly snapshot completed for ${config.apps.length} apps`);
  } catch (err) { cronFail('Project snapshots', err); }
});

// Weekly Sunday 4 AM: generate AI weekly summaries
cron.schedule('0 4 * * 0', async () => {
  try {
    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return;
    const saasApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    for (const appDef of saasApps) {
      const slug = slugify(appDef.name);
      try {
        const meta = db.prepare('SELECT * FROM project_meta WHERE app_slug = ?').get(slug) || {};
        const openTasks = db.prepare("SELECT title FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled') LIMIT 5").all(slug);
        const mrrRow = qLatestMetric.get(slug, 'mrr');
        const prompt = `Write a concise weekly status for ${appDef.name} (${appDef.type}): lifecycle=${meta.lifecycle}, MRR=€${((mrrRow?.value || 0) / 100).toFixed(0)}, ${openTasks.length} open tasks${openTasks.length > 0 ? ': ' + openTasks.map(t => t.title).join(', ') : ''}. 3 short paragraphs: state, progress, next focus.`;
        const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, { maxTokens: 400, messages: [{ role: 'user', content: prompt }] }));
        if (ai.text) {
          db.prepare("INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES (?, 'weekly_summary', ?, ?, datetime('now')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at").run(slug, ai.text, ai.outputTokens);
        }
      } catch (appErr) { console.error(`[PROJECTS] AI summary error for ${slug}:`, appErr.message); }
    }
    console.log(`[PROJECTS] Weekly AI summaries generated for ${saasApps.length} apps`);
  } catch (err) { cronFail('AI project summary', err); }
});

// ========== OPS INTELLIGENCE ==========


async function calculateWorryScore() {
  const breakdown = { containers: 0, keys: 0, disk: 0, backups: 0, security: 0, healing: 0, seo: 0, errors: 0 };
  const MAX = { containers: 25, keys: 20, disk: 15, backups: 15, security: 10, healing: 10, seo: 5, errors: 10 };

  // 1. Container health
  try {
    const containers = await docker.listContainers({ all: true });
    const appNames = new Set();
    config.apps.forEach(a => (a.containers || []).forEach(c => appNames.add(c)));
    const appContainers = containers.filter(c => appNames.has(containerName(c)));
    const unhealthy = appContainers.filter(c => c.Status?.includes('unhealthy')).length;
    const restarting = appContainers.filter(c => c.State === 'restarting').length;
    const stopped = appContainers.filter(c => c.State !== 'running').length;
    breakdown.containers = Math.min(MAX.containers, unhealthy * 8 + restarting * 6 + stopped * 5);
  } catch { breakdown.containers = MAX.containers; }

  // 2. API key health
  if (cachedKeyHealth?.results) {
    let expired = 0, errors = 0;
    for (const appKeys of Object.values(cachedKeyHealth.results)) {
      for (const keyInfo of Object.values(appKeys)) {
        if (keyInfo.status === 'expired') expired++;
        else if (keyInfo.status === 'error') errors++;
      }
    }
    breakdown.keys = Math.min(MAX.keys, expired * 10 + errors * 5);
  }

  // 3. Disk usage
  try {
    const diskLine = getDiskParts();
    const diskPct = parseInt(diskLine[4]);
    if (diskPct >= 90) breakdown.disk = 15;
    else if (diskPct >= 80) breakdown.disk = 10;
    else if (diskPct >= 70) breakdown.disk = 5;
  } catch { breakdown.disk = 5; }

  // 4. Backup freshness
  try {
    const backupDir = BACKUP_DIR;
    if (existsSync(backupDir)) {
      const dirs = readdirSync(backupDir, { withFileTypes: true }).filter(d => d.isDirectory());
      let staleCount = 0;
      for (const d of dirs) {
        try {
          const latest = getLatestFile(join(backupDir, d.name));
          if (!latest) { staleCount++; continue; }
          const ageH = (Date.now() - statSync(join(backupDir, d.name, latest)).mtime.getTime()) / MS_PER_HOUR;
          if (ageH > 25) staleCount++;
        } catch { staleCount++; }
      }
      breakdown.backups = Math.min(MAX.backups, staleCount * 5);
    }
  } catch (err) { console.error('[WORRY] Backup freshness check failed:', err.message); }

  // 5. Security score
  try {
    const scan = db.prepare('SELECT overall_score FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
    if (scan) {
      if (scan.overall_score < 40) breakdown.security = 10;
      else if (scan.overall_score < 60) breakdown.security = 7;
      else if (scan.overall_score < 75) breakdown.security = 4;
    } else { breakdown.security = 5; }
  } catch (err) { console.error('[WORRY] Security score lookup failed:', err.message); }

  // 6. Healing activity (last hour)
  try {
    const since1h = new Date(Date.now() - MS_PER_HOUR).toISOString();
    const r = db.prepare("SELECT COUNT(*) as n FROM healing_log WHERE timestamp >= ? AND result IN ('executed','pending')").get(since1h);
    breakdown.healing = Math.min(MAX.healing, (r?.n || 0) * 5);
  } catch (err) { console.error('[WORRY] Healing activity query failed:', err.message); }

  // 7. SEO
  try {
    const seoRows = db.prepare('SELECT score FROM seo_audits WHERE date = (SELECT MAX(date) FROM seo_audits)').all();
    if (seoRows.length > 0) {
      const avg = seoRows.reduce((a, b) => a + b.score, 0) / seoRows.length;
      if (avg < 40) breakdown.seo = 5;
      else if (avg < 60) breakdown.seo = 3;
    }
  } catch (err) { console.error('[WORRY] SEO score query failed:', err.message); }

  // 8. Error tracking
  try {
    const since1h = new Date(Date.now() - MS_PER_HOUR).toISOString();
    const criticals = db.prepare("SELECT COUNT(*) as n FROM error_issues WHERE severity = 'critical' AND status = 'open' AND last_seen >= ?").get(since1h);
    const openErrors = db.prepare("SELECT COUNT(*) as n FROM error_events WHERE timestamp >= datetime('now', '-1 hour')").get();
    breakdown.errors = errorScore(criticals?.n || 0, openErrors?.n || 0);
  } catch (err) { console.error('[WORRY] Error tracking query failed:', err.message); }

  const total = Math.min(100, Object.values(breakdown).reduce((a, b) => a + b, 0));
  return { score: total, breakdown, maxScores: MAX, timestamp: new Date().toISOString() };
}

async function snapshotBaseline(type = 'auto') {
  const envHashes = {};
  for (const appDef of config.apps) {
    if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
    const slug = slugify(appDef.name);
    const vars = parseEnvFile(appDef.envFile);
    envHashes[slug] = {};
    for (const v of vars) {
      if (SENSITIVE_PATTERN.test(v.key) && v.value) {
        envHashes[slug][v.key] = hashValue(v.value);
      }
    }
  }

  const containerStates = {};
  try {
    const containers = await docker.listContainers({ all: true });
    for (const c of containers) {
      const name = containerName(c);
      containerStates[name] = { state: c.State, image: c.Image, imageId: (c.ImageID || '').slice(0, 24) };
    }
  } catch (err) { console.error('[BASELINE] Container list failed:', err.message); }

  const configHash = hashValue(readFileSync(configPath, 'utf8'));
  let diskPct = 0;
  try {
    diskPct = getDiskPercent();
  } catch (err) { console.error('[BASELINE] Disk usage check failed:', err.message); }

  db.prepare(`INSERT INTO ops_baselines (snapshot_type, env_hashes, container_states, disk_usage_pct, total_containers, config_hash)
    VALUES (?, ?, ?, ?, ?, ?)`).run(type, JSON.stringify(envHashes), JSON.stringify(containerStates), diskPct, Object.keys(containerStates).length, configHash);

  return { envHashes, containerStates, diskPct, totalContainers: Object.keys(containerStates).length, configHash };
}

async function detectDrift() {
  const baseline = db.prepare('SELECT * FROM ops_baselines ORDER BY timestamp DESC LIMIT 1').get();
  if (!baseline) return { drifts: [], message: 'No baseline yet. Create one first.' };

  const baseEnv = safeJSON(baseline.env_hashes, {});
  const baseContainers = safeJSON(baseline.container_states, {});
  const drifts = [];

  // Env key changes
  for (const appDef of config.apps) {
    if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
    const slug = slugify(appDef.name);
    const vars = parseEnvFile(appDef.envFile);
    const currentHashes = {};
    for (const v of vars) {
      if (SENSITIVE_PATTERN.test(v.key) && v.value) {
        currentHashes[v.key] = hashValue(v.value);
      }
    }
    const baseAppEnv = baseEnv[slug] || {};
    for (const [key, hash] of Object.entries(currentHashes)) {
      if (baseAppEnv[key] && baseAppEnv[key] !== hash) {
        drifts.push({ type: 'drift_env', app_slug: slug, severity: 'warning', title: `${appDef.name}: ${key} changed`, details: JSON.stringify({ key }) });
      } else if (!baseAppEnv[key]) {
        drifts.push({ type: 'drift_env', app_slug: slug, severity: 'info', title: `${appDef.name}: New key ${key}`, details: JSON.stringify({ key }) });
      }
    }
    for (const key of Object.keys(baseAppEnv)) {
      if (!currentHashes[key]) {
        drifts.push({ type: 'drift_env', app_slug: slug, severity: 'warning', title: `${appDef.name}: Key ${key} removed`, details: JSON.stringify({ key }) });
      }
    }
  }

  // Container state changes
  try {
    const containers = await docker.listContainers({ all: true });
    for (const c of containers) {
      const name = containerName(c);
      const base = baseContainers[name];
      if (base && base.state !== c.State) {
        drifts.push({ type: 'drift_container', severity: c.State === 'running' ? 'info' : 'warning', title: `${name}: ${base.state} → ${c.State}`, details: JSON.stringify({ container: name, was: base.state, now: c.State }) });
      }
      if (base && base.image !== c.Image) {
        drifts.push({ type: 'drift_container', severity: 'info', title: `${name}: image changed`, details: JSON.stringify({ container: name, wasImage: base.image, nowImage: c.Image }) });
      }
    }
  } catch (err) { console.error('[DRIFT] Container state check failed:', err.message); }

  // Config.yml change
  const currentConfigHash = hashValue(readFileSync(configPath, 'utf8'));
  if (baseline.config_hash && baseline.config_hash !== currentConfigHash) {
    drifts.push({ type: 'drift_config', severity: 'info', title: 'config.yml changed since baseline', details: JSON.stringify({ oldHash: baseline.config_hash, newHash: currentConfigHash }) });
  }

  // Disk usage jump
  try {
    const diskPct = getDiskPercent();
    if (baseline.disk_usage_pct && diskPct > baseline.disk_usage_pct + 10) {
      drifts.push({ type: 'drift_disk', severity: diskPct >= 80 ? 'critical' : 'warning', title: `Disk: ${baseline.disk_usage_pct}% → ${diskPct}%`, details: JSON.stringify({ was: baseline.disk_usage_pct, now: diskPct }) });
    }
  } catch (err) { console.error('[DRIFT] Disk usage check failed:', err.message); }

  return { drifts, baseline_timestamp: baseline.timestamp, baseline_id: baseline.id };
}

function calculateAppReportCard(slug) {
  const appDef = config.apps.find(a => slugify(a.name) === slug);
  if (!appDef) return null;
  const dims = {};

  // Security
  try {
    const findings = db.prepare(`SELECT severity FROM security_findings WHERE app_slug = ? AND scan_id = (SELECT id FROM security_scans ORDER BY timestamp DESC LIMIT 1) AND status != 'dismissed'`).all(slug);
    const crit = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const s = Math.max(0, 100 - crit * 25 - high * 15 - findings.length * 3);
    dims.security = { score: s, grade: letterGrade(s) };
  } catch { dims.security = { score: 50, grade: 'C' }; }

  // Backup
  try {
    const backupDir = join(BACKUP_DIR, slug);
    if (existsSync(backupDir)) {
      const latest = getLatestFile(backupDir);
      if (latest) {
        const ageH = (Date.now() - statSync(join(backupDir, latest)).mtime.getTime()) / MS_PER_HOUR;
        const s = ageH <= 25 ? 100 : ageH <= 48 ? 70 : ageH <= 168 ? 40 : 10;
        dims.backup = { score: s, grade: letterGrade(s) };
      } else dims.backup = { score: 0, grade: 'F' };
    } else dims.backup = { score: 0, grade: 'N/A' };
  } catch { dims.backup = { score: 0, grade: 'N/A' }; }

  // Revenue
  try {
    const row = qLatestMetric.get(slug, 'mrr');
    const mrr = row?.value || 0;
    const s = mrr > 0 ? Math.min(100, Math.round(50 + Math.log10(mrr / 100 + 1) * 30)) : 0;
    dims.revenue = { score: s, grade: letterGrade(s), mrr: mrr / 100 };
  } catch { dims.revenue = { score: 0, grade: 'N/A' }; }

  // Traffic
  try {
    const row = qLatestMetric.get(slug, 'pageviews_30d');
    const pv = row?.value || 0;
    const s = pv > 0 ? Math.min(100, Math.round(30 + Math.log10(pv + 1) * 20)) : 0;
    dims.traffic = { score: s, grade: letterGrade(s), pageviews: pv };
  } catch { dims.traffic = { score: 0, grade: 'N/A' }; }

  // SEO
  try {
    const row = qLatestSEO.get(slug);
    dims.seo = row ? { score: row.score, grade: row.grade } : { score: 0, grade: 'N/A' };
  } catch { dims.seo = { score: 0, grade: 'N/A' }; }

  // Uptime (container running = 100, else degraded)
  dims.uptime = { score: 100, grade: 'A' };

  // Freshness (placeholder — enhanced with container inspect)
  dims.freshness = { score: 70, grade: 'C' };

  const scores = Object.values(dims).map(d => d.score).filter(s => typeof s === 'number' && s > 0);
  const overall = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  return { slug, name: appDef.name, type: appDef.type, overall, grade: letterGrade(overall), dimensions: dims };
}

function getAppDependencyMap() {
  const nodes = config.apps.map(a => ({ id: slugify(a.name), name: a.name, type: a.type }));
  const edges = [];
  const hashMap = new Map();
  const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));
  for (const appDef of appsWithEnv) {
    const slug = slugify(appDef.name);
    const vars = parseEnvFile(appDef.envFile);
    for (const v of vars) {
      if (!SENSITIVE_PATTERN.test(v.key) || !v.value) continue;
      const hash = hashValue(v.value, 64);
      const mapKey = `${v.key}::${hash}`;
      if (!hashMap.has(mapKey)) hashMap.set(mapKey, { key: v.key, maskedValue: maskValue(v.value), apps: [] });
      hashMap.get(mapKey).apps.push(slug);
    }
  }
  const sharedKeys = [];
  for (const [, entry] of hashMap) {
    if (entry.apps.length < 2) continue;
    sharedKeys.push(entry);
    for (let i = 0; i < entry.apps.length; i++) {
      for (let j = i + 1; j < entry.apps.length; j++) {
        edges.push({ source: entry.apps[i], target: entry.apps[j], label: entry.key, type: 'shared_key' });
      }
    }
  }
  return { nodes, edges, shared_keys: sharedKeys };
}

// --- Ops Intelligence API Endpoints ---

app.get('/api/ops/worry-score', asyncRoute(async (_req, res) => {
  const result = await calculateWorryScore();
  const latest = db.prepare('SELECT streak_days, streak_broken_at FROM ops_scores ORDER BY timestamp DESC LIMIT 1').get();
  result.streak = { days: latest?.streak_days || 0, lastBroken: latest?.streak_broken_at || null };
  res.json(result);
}));

app.get('/api/ops/heartbeat', asyncRoute(async (_req, res) => {
  const containers = await docker.listContainers({ all: true });
  const apps = config.apps.map(appDef => {
    const slug = slugify(appDef.name);
    const appContainers = (appDef.containers || []).map(name => {
      const c = containers.find(cn => containerName(cn) === name);
      return { name, state: c?.State || 'not_found', health: c?.Status?.includes('healthy') ? 'healthy' : c?.Status?.includes('unhealthy') ? 'unhealthy' : c?.State || 'unknown' };
    });
    const health = appContainers.length === 0 ? 'static'
      : appContainers.every(c => c.health === 'healthy' || c.state === 'running') ? 'healthy'
      : appContainers.some(c => c.health === 'unhealthy') ? 'unhealthy'
      : appContainers.some(c => c.state === 'restarting') ? 'restarting' : 'degraded';
    return { slug, name: appDef.name, type: appDef.type, health, containers: appContainers };
  });
  res.json({ apps, timestamp: new Date().toISOString() });
}));

app.get('/api/ops/report-card/:slug', asyncRoute((req, res) => {
  const card = calculateAppReportCard(req.params.slug);
  if (!card) return res.status(404).json({ error: 'App not found' });
  res.json(card);
}));

app.get('/api/ops/report-cards', asyncRoute((_req, res) => {
  const cards = config.apps.map(a => calculateAppReportCard(slugify(a.name))).filter(Boolean);
  res.json({ cards, timestamp: new Date().toISOString() });
}));

app.get('/api/ops/dependencies', asyncRoute((_req, res) => {
  res.json(getAppDependencyMap());
}));

app.get('/api/ops/drift', asyncRoute(async (_req, res) => {
  res.json(await detectDrift());
}));

app.post('/api/ops/drift/:id/acknowledge', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  db.prepare("UPDATE ops_events SET acknowledged = 1, acknowledged_at = datetime('now') WHERE id = ?").run(id);
  res.json({ ok: true });
}));

app.post('/api/ops/baseline', asyncRoute(async (_req, res) => {
  const result = await snapshotBaseline('manual');
  db.prepare("INSERT INTO ops_events (event_type, severity, title, details) VALUES ('baseline_created', 'info', 'Manual baseline created', ?)").run(JSON.stringify({ containers: result.totalContainers, disk: result.diskPct }));
  res.json({ ok: true, ...result });
}));

app.get('/api/ops/streak', asyncRoute((_req, res) => {
  const latest = db.prepare('SELECT streak_days, streak_broken_at FROM ops_scores ORDER BY timestamp DESC LIMIT 1').get();
  const best = db.prepare('SELECT MAX(streak_days) as best FROM ops_scores').get();
  const history = db.prepare('SELECT worry_score, timestamp FROM ops_scores ORDER BY timestamp DESC LIMIT 672').all(); // 7 days * 96 (15min intervals)
  res.json({ streak_days: latest?.streak_days || 0, best_streak: best?.best || 0, last_broken: latest?.streak_broken_at || null, history });
}));

app.get('/api/ops/timeline', asyncRoute((req, res) => {
  const limit = Math.min(parseInt(req.query?.limit) || 50, 200);
  const events = db.prepare('SELECT * FROM ops_events ORDER BY timestamp DESC LIMIT ?').all(limit);
  const unack = db.prepare("SELECT COUNT(*) as n FROM ops_events WHERE acknowledged = 0").get();
  res.json({ events, unacknowledged: unack?.n || 0 });
}));

// --- Ops Cron Jobs ---

// Worry score + streak update (every 15 min)
cron.schedule('*/15 * * * *', async () => {
  try {
    const result = await calculateWorryScore();
    const prev = db.prepare('SELECT streak_days, streak_broken_at FROM ops_scores ORDER BY timestamp DESC LIMIT 1').get();
    let streakDays = prev?.streak_days || 0;
    let streakBroken = prev?.streak_broken_at || null;
    if (result.score <= 30) {
      // Check if last score was also <=30 and on the same day — increment streak at midnight boundary
      const lastTs = db.prepare('SELECT timestamp FROM ops_scores ORDER BY timestamp DESC LIMIT 1').get();
      const lastDate = lastTs ? new Date(lastTs.timestamp).toDateString() : '';
      const nowDate = new Date().toDateString();
      if (lastDate !== nowDate && result.score <= 30) streakDays++;
    } else {
      if (streakDays > 0) {
        streakBroken = new Date().toISOString();
        db.prepare("INSERT INTO ops_events (event_type, severity, title, details) VALUES ('score_change', 'warning', ?, ?)").run(
          `Streak broken after ${streakDays} days (score: ${result.score})`, JSON.stringify({ score: result.score, streak: streakDays }));
      }
      streakDays = 0;
    }
    db.prepare('INSERT INTO ops_scores (worry_score, breakdown, streak_days, streak_broken_at) VALUES (?, ?, ?, ?)').run(
      result.score, JSON.stringify(result.breakdown), streakDays, streakBroken);
    console.log(`[OPS] Worry score: ${result.score}/100, streak: ${streakDays}d`);
  } catch (err) { cronFail('Worry score', err); }
});

// Auto baseline + drift detection (daily 2:30 AM)
cron.schedule('30 2 * * *', async () => {
  try {
    await snapshotBaseline('auto');
    const { drifts } = await detectDrift();
    const criticalDrifts = drifts.filter(d => d.severity === 'critical');
    for (const d of drifts) {
      db.prepare("INSERT INTO ops_events (event_type, app_slug, severity, title, details) VALUES (?, ?, ?, ?, ?)").run(d.type, d.app_slug || null, d.severity, d.title, d.details || null);
    }
    if (criticalDrifts.length > 0) {
      await sendTelegram(`⚠️ Dockfolio Drift Alert — ${criticalDrifts.length} critical drift(s):\n${criticalDrifts.map(d => '• ' + d.title).join('\n')}`);
    }
    console.log(`[OPS] Daily baseline: ${drifts.length} drifts (${criticalDrifts.length} critical)`);
    // Cleanup old scores (>30 days)
    db.prepare("DELETE FROM ops_scores WHERE timestamp < datetime('now', '-30 days')").run();
    db.prepare("DELETE FROM ops_baselines WHERE timestamp < datetime('now', '-90 days')").run();
    db.prepare("DELETE FROM ops_events WHERE timestamp < datetime('now', '-90 days')").run();
    db.prepare("DELETE FROM notifications WHERE timestamp < datetime('now', '-30 days')").run();
  } catch (err) { cronFail('Baseline drift', err); }
});

// Key rotation reminder (weekly Monday 9 AM)
cron.schedule('0 9 * * 1', async () => {
  try {
    const staleKeys = [];
    const baselines = db.prepare('SELECT env_hashes, timestamp FROM ops_baselines ORDER BY timestamp ASC LIMIT 1').get();
    if (!baselines) return;
    const firstSeen = safeJSON(baselines.env_hashes, {});
    const baselineAge = Math.round((Date.now() - new Date(baselines.timestamp).getTime()) / MS_PER_DAY);
    if (baselineAge > 90) {
      for (const [slug, keys] of Object.entries(firstSeen)) {
        for (const keyName of Object.keys(keys)) {
          const appDef = config.apps.find(a => slugify(a.name) === slug);
          staleKeys.push(`${appDef?.name || slug}: ${keyName} (baseline ${baselineAge}d old)`);
        }
      }
    }
    if (staleKeys.length > 0) {
      await sendTelegram(`🔑 Key Rotation Reminder — ${staleKeys.length} key(s) may need rotation:\n${staleKeys.map(k => '• ' + k).join('\n')}`);
      db.prepare("INSERT INTO ops_events (event_type, severity, title, details) VALUES ('key_rotation', 'warning', ?, ?)").run(
        `${staleKeys.length} key(s) may need rotation`, JSON.stringify(staleKeys));
    }
    console.log(`[OPS] Key rotation check: ${staleKeys.length} stale keys`);
  } catch (err) { cronFail('Key rotation', err); }
});

// --- Docker Log Scanner (every 5 min) ---
const logScanLastTimestamps = new Map(); // containerName -> ISO timestamp
const ERROR_PATTERNS = [
  /\bError:\s/i, /\bFATAL\b/i, /\bTypeError\b/, /\bReferenceError\b/,
  /\bSyntaxError\b/, /\bECONNREFUSED\b/, /\bENOENT\b/, /\bOOM\b/i,
  /\bexit code [1-9]/i, /\bUnhandledPromiseRejection\b/, /\bSegmentation fault\b/i,
  /\bKilled\b/, /\bpanic\b/i, /\bcritical\b/i
];
const NOISE_PATTERNS = [
  /DeprecationWarning/i, /ExperimentalWarning/i, /npm warn/i,
  /punycode/i, /DEP0040/i, /node --trace-warnings/i,
  /^\[(?:OPS|CRON|HEALING|ERROR_SCAN|ERROR_WATCH|PERF|CLEANUP|MAINT|BACKUP|SSL|UPTIME|ANALYTICS|PROJECTS|ALERTS|ENV|AUDIT)\]\s/,
  /Failed to find Server Action/i
];

// Refresh Docker image update checks every 6 hours
cron.schedule('30 */6 * * *', guardedCron('image-updates', async () => {
  try {
    const result = await checkImageUpdates();
    cachedImageUpdates = result;
    lastImageUpdatesCheck = Date.now();
    console.log(`[IMAGE-UPDATES] Refreshed: ${result.summary.updatesAvailable} updates available out of ${result.summary.total} images`);
  } catch (err) {
    console.error('[IMAGE-UPDATES] Cron failed:', err.message);
  }
}));

cron.schedule('*/5 * * * *', guardedCron('error-ingest', async () => {
  try {
    const containers = await docker.listContainers();
    // Map containers to app slugs
    const containerToApp = new Map();
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      for (const cn of (appDef.containers || [])) {
        containerToApp.set(cn, slug);
      }
    }

    for (const c of containers) {
      const name = containerName(c);
      const appSlug = containerToApp.get(name);
      if (!appSlug) continue;

      const since = logScanLastTimestamps.get(name) || new Date(Date.now() - 300_000).toISOString();
      logScanLastTimestamps.set(name, new Date().toISOString());

      try {
        const container = docker.getContainer(c.Id);
        const logStream = await container.logs({ stdout: true, stderr: true, since: Math.floor(new Date(since).getTime() / 1000), tail: 200 });
        const logText = typeof logStream === 'string' ? logStream : logStream.toString('utf8');
        const lines = logText.split('\n').filter(Boolean);

        let errorsIngested = 0;
        for (let i = 0; i < lines.length && errorsIngested < 50; i++) {
          const line = lines[i].replace(/^.{8}/, ''); // strip Docker log header bytes
          if (NOISE_PATTERNS.some(p => p.test(line))) continue;
          if (!ERROR_PATTERNS.some(p => p.test(line))) continue;

          // Collect stack trace lines following the error
          let stack = '';
          for (let j = i + 1; j < lines.length && j < i + 20; j++) {
            const nextLine = lines[j].replace(/^.{8}/, '');
            if (/^\s+at\s/.test(nextLine) || /^\s+/.test(nextLine) && !ERROR_PATTERNS.some(p => p.test(nextLine))) {
              stack += nextLine + '\n';
            } else break;
          }

          ingestError({ app: appSlug, message: line.trim(), stack: stack || null, severity: /FATAL|OOM|panic|critical/i.test(line) ? 'critical' : 'error', source: 'docker_log', container: name });
          errorsIngested++;
        }
      } catch { /* container may have stopped between list and logs */ }
    }
  } catch (err) { cronFail('Docker log scan', err); }
}));

// --- Docker Event Watcher (persistent stream with exponential backoff) ---
let eventStream = null;
let eventWatcherBackoff = TIMEOUT_QUICK; // start at 5s, max 5min

async function startEventWatcher() {
  try {
    if (eventStream) try { eventStream.destroy(); } catch (e) { console.error('[ERROR_WATCH] Stream destroy error:', e.message); }
    eventStream = await docker.getEvents({ filters: { type: ['container'], event: ['die', 'oom', 'health_status', 'start'] } });
    eventWatcherBackoff = TIMEOUT_QUICK; // reset on successful connect

    eventStream.on('data', async (chunk) => {
      try {
        const event = JSON.parse(chunk.toString());
        const name = event.Actor?.Attributes?.name;
        if (!name) return;

        // Find app slug
        let appSlug = null;
        for (const appDef of config.apps) {
          if ((appDef.containers || []).includes(name)) { appSlug = slugify(appDef.name); break; }
        }
        if (!appSlug) return;

        if (event.Action === 'oom') {
          ingestError({ app: appSlug, message: `Container ${name} killed by OOM (out of memory)`, severity: 'critical', source: 'docker_event', container: name });
        } else if (event.Action === 'die') {
          const exitCode = event.Actor?.Attributes?.exitCode;
          if (exitCode && exitCode !== '0') {
            // Grab last 20 log lines for context
            let lastLogs = '';
            try {
              const container = docker.getContainer(event.Actor.ID);
              const logs = await container.logs({ stdout: true, stderr: true, tail: 20 });
              lastLogs = (typeof logs === 'string' ? logs : logs.toString('utf8')).replace(/^.{8}/gm, '');
            } catch (e) { console.error('[ERROR_WATCH] Failed to fetch dying container logs:', e.message); }
            ingestError({ app: appSlug, message: `Container ${name} died with exit code ${exitCode}`, stack: lastLogs || null, severity: 'critical', source: 'docker_event', container: name });
          }
        } else if (event.Action === 'health_status: unhealthy') {
          ingestError({ app: appSlug, message: `Container ${name} health check failed`, severity: 'warning', source: 'docker_event', container: name });
        } else if (event.Action === 'start') {
          // Detect deploy — container started (could be restart or fresh deploy)
          onContainerDeploy(name).catch(err => console.error('[CHANGELOG] Deploy detection error:', err.message));
        }
      } catch (err) { console.error('[ERROR_WATCH] Event processing error:', err.message); }
    });

    const scheduleReconnect = (reason) => {
      const jitter = Math.random() * eventWatcherBackoff * 0.3;
      const delay = eventWatcherBackoff + jitter;
      console.error(`[ERROR_WATCH] ${reason}, reconnecting in ${Math.round(delay / 1000)}s`);
      eventWatcherBackoff = Math.min(eventWatcherBackoff * 2, TIMEOUT_BUILD); // cap at 5 min
      setTimeout(startEventWatcher, delay);
    };
    eventStream.on('error', (err) => scheduleReconnect(`Stream error: ${err?.message || 'unknown'}`));
    eventStream.on('close', () => scheduleReconnect('Stream closed'));
    console.log('[ERROR_WATCH] Docker event watcher started');
  } catch (err) {
    const jitter = Math.random() * eventWatcherBackoff * 0.3;
    const delay = eventWatcherBackoff + jitter;
    console.error(`[ERROR_WATCH] Failed to start: ${err.message}, retrying in ${Math.round(delay / 1000)}s`);
    eventWatcherBackoff = Math.min(eventWatcherBackoff * 2, 300000);
    setTimeout(startEventWatcher, delay);
  }
}
startEventWatcher();

// --- Performance Accumulator ---
const perfAccumulator = new Map(); // endpoint -> [responseTimes]

// Extend request logging to capture response times
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    if (!req.path.startsWith('/api/')) return;
    const duration = Date.now() - start;
    // Normalize endpoint: strip IDs from paths
    const endpoint = req.method + ' ' + req.path.replace(/\/\d+/g, '/:id');
    const times = perfAccumulator.get(endpoint) || [];
    times.push({ ms: duration, error: res.statusCode >= 500 });
    if (times.length > 10000) times.splice(0, times.length - 5000); // prevent unbounded growth
    perfAccumulator.set(endpoint, times);
  });
  next();
});

// Every 15 min: aggregate perf metrics
cron.schedule('*/15 * * * *', () => {
  try {
    const hour = new Date().toISOString().slice(0, 13) + ':00:00';
    const upsertPerf = db.prepare(`INSERT INTO perf_metrics (app_slug, endpoint, hour, request_count, p50_ms, p95_ms, p99_ms, error_count)
      VALUES ('dockfolio', ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(app_slug, endpoint, hour) DO UPDATE SET
        request_count = request_count + excluded.request_count,
        p50_ms = excluded.p50_ms, p95_ms = excluded.p95_ms, p99_ms = excluded.p99_ms,
        error_count = error_count + excluded.error_count`);

    for (const [endpoint, times] of perfAccumulator.entries()) {
      if (times.length === 0) continue;
      const sorted = times.map(t => t.ms).sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
      const p95 = sorted[Math.floor(sorted.length * 0.95)] || 0;
      const p99 = sorted[Math.floor(sorted.length * 0.99)] || 0;
      const errors = times.filter(t => t.error).length;
      upsertPerf.run(endpoint, hour, times.length, p50, p95, p99, errors);
    }
    perfAccumulator.clear();
  } catch (err) { cronFail('Perf aggregation', err); }
});

// Daily 3:15 AM: Retention cleanup for error events (30d) and perf metrics (14d)
cron.schedule('15 3 * * *', () => {
  try {
    const deletedEvents = db.prepare("DELETE FROM error_events WHERE timestamp < datetime('now', '-30 days')").run();
    const deletedPerf = db.prepare("DELETE FROM perf_metrics WHERE hour < datetime('now', '-14 days')").run();
    console.log(`[CLEANUP] Pruned ${deletedEvents.changes} error events, ${deletedPerf.changes} perf metrics`);
  } catch (err) { cronFail('Data retention cleanup', err); }
});

// Daily 4:00 AM: Database maintenance (WAL checkpoint + cleanup)
cron.schedule('0 4 * * *', () => {
  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
    authDb.pragma('wal_checkpoint(TRUNCATE)');
    // Clean up old uptime history (>90 days) and audit log (>180 days)
    const deletedUptime = db.prepare("DELETE FROM uptime_history WHERE checked_at < datetime('now', '-90 days')").run();
    const deletedAudit = db.prepare("DELETE FROM audit_log WHERE created_at < datetime('now', '-180 days')").run();
    console.log(`[MAINT] WAL checkpoint done. Pruned ${deletedUptime.changes} uptime rows, ${deletedAudit.changes} audit rows`);
  } catch (err) { cronFail('DB maintenance', err); }
});

// Daily 5:00 AM: Backup freshness alerts
cron.schedule('0 5 * * *', () => {
  try {
    if (!existsSync(BACKUP_DIR)) return;
    const stale = [];
    const dirs = readdirSync(BACKUP_DIR, { withFileTypes: true }).filter(d => d.isDirectory());
    for (const d of dirs) {
      try {
        const latest = getLatestFile(join(BACKUP_DIR, d.name));
        if (!latest) { stale.push(d.name); continue; }
        const ageH = (Date.now() - statSync(join(BACKUP_DIR, d.name, latest)).mtime.getTime()) / MS_PER_HOUR;
        if (ageH > 25) stale.push(`${d.name} (${Math.round(ageH)}h ago)`);
      } catch { stale.push(d.name); }
    }
    if (stale.length > 0) {
      sendTelegram(`\u26a0\ufe0f Stale backups detected:\n${stale.join('\n')}`);
      console.log(`[BACKUP] ${stale.length} stale backups: ${stale.join(', ')}`);
    }
  } catch (err) { cronFail('Backup freshness', err); }
});

// Daily 7:00 AM: SSL certificate expiry alerts
cron.schedule('0 7 * * *', async () => {
  try {
    const expiring = [];
    for (const a of config.apps) {
      if (!a.domain) continue;
      try {
        const result = execSync(`echo | openssl s_client -servername ${a.domain} -connect ${a.domain}:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null`, { timeout: TIMEOUT_MEDIUM }).toString().trim();
        const match = result.match(/notAfter=(.*)/);
        if (match) {
          const expiresAt = new Date(match[1]);
          const daysLeft = Math.round((expiresAt - Date.now()) / MS_PER_DAY);
          if (daysLeft < 14) expiring.push(`${a.domain}: ${daysLeft}d left`);
        }
      } catch { /* skip domains without SSL */ }
    }
    if (expiring.length > 0) {
      sendTelegram(`\ud83d\udd12 SSL certificates expiring soon:\n${expiring.join('\n')}`);
      console.log(`[SSL] ${expiring.length} certs expiring: ${expiring.join(', ')}`);
    }
  } catch (err) { cronFail('SSL expiry check', err); }
});

// Every 5 min: Uptime health checks
const uptimePrevStatus = new Map(); // slug -> 'up'|'degraded'|'down'
cron.schedule('*/5 * * * *', guardedCron('uptime', async () => {
  try {
    const insert = db.prepare('INSERT INTO uptime_history (app_slug, status, response_ms) VALUES (?, ?, ?)');
    for (const a of config.apps) {
      const slug = slugify(a.name);
      let status = 'unknown';
      let response_ms = null;
      try {
        if (a.domain) {
          const url = a.health ? `https://${a.domain}${a.health}` : `https://${a.domain}`;
          const start = Date.now();
          const r = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_STANDARD) });
          response_ms = Date.now() - start;
          status = r.ok ? 'up' : 'degraded';
        } else if (a.health) {
          const start = Date.now();
          const r = await fetch(`https://${a.domain}`, { signal: AbortSignal.timeout(TIMEOUT_STANDARD) });
          response_ms = Date.now() - start;
          status = r.ok ? 'up' : 'degraded';
        } else continue;
      } catch { status = 'down'; }
      insert.run(slug, status, response_ms);

      // Alert on status transitions
      const prev = uptimePrevStatus.get(slug);
      if (prev && prev !== status) {
        if (status === 'down') {
          sendTelegram(`🔴 ${a.name} is DOWN\nDomain: ${a.domain}`);
        } else if (status === 'degraded') {
          sendTelegram(`🟡 ${a.name} is DEGRADED\nDomain: ${a.domain}${response_ms ? `\nResponse: ${response_ms}ms` : ''}`);
        } else if (status === 'up' && (prev === 'down' || prev === 'degraded')) {
          sendTelegram(`🟢 ${a.name} is back UP\nDomain: ${a.domain}${response_ms ? `\nResponse: ${response_ms}ms` : ''}`);
        }
      }
      uptimePrevStatus.set(slug, status);
    }
  } catch (err) { cronFail('Uptime check', err); }
}));

// --- Error Tracking API ---

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
    // Extract app slug from DSN path: http://key@host/APP_SLUG
    let appSlug = 'unknown';
    if (header.dsn) {
      const dsnPath = new URL(header.dsn).pathname.replace(/^\//, '');
      if (dsnPath) appSlug = dsnPath;
    }

    // Parse event items
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

// --- Public Status Page ---
app.get('/api/status', rlPublicRead, asyncRoute(async (_req, res) => {
  const results = [];
  const dayAgo = new Date(Date.now() - MS_PER_DAY).toISOString();
  for (const a of config.apps) {
    let status = 'unknown';
    let response_ms = null;
    try {
      if (a.health) {
        const start = Date.now();
        const r = await fetch(a.health, { signal: AbortSignal.timeout(TIMEOUT_QUICK) });
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

// --- Data Export ---
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

// --- Comprehensive Data Export ---
function sendExport(res, rows, name, format) {
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${name}-${new Date().toISOString().slice(0,10)}.csv"`);
    return res.send(toCsv(rows));
  }
  res.json({ entity: name, exported_at: new Date().toISOString(), count: rows.length, data: rows });
}

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

// --- Anti-SaaS Savings Tracker ---
const SAAS_EQUIVALENTS = {
  plausible: { name: 'Plausible Cloud', cost: 9 },
  promoforge: { name: 'Mailchimp + Hotjar', cost: 49 },
  bannerforge: { name: 'AdRoll', cost: 36 },
  'headshot-ai': { name: 'HeadshotPro', cost: 29 },
  abschlusscheck: { name: 'Custom SaaS', cost: 19 },
  lohncheck: { name: 'Custom SaaS', cost: 19 },
  sacredlens: { name: 'Custom SaaS', cost: 19 },
  'uptime-kuma': { name: 'Better Uptime', cost: 24 },
};
app.get('/api/savings', asyncRoute((_req, res) => {
  const vmCost = parseFloat(process.env.VM_COST_MONTHLY || '12.48');
  let totalSaasCost = 0;
  const breakdown = [];
  for (const a of config.apps) {
    const slug = slugify(a.name);
    const equiv = SAAS_EQUIVALENTS[slug];
    if (equiv) {
      totalSaasCost += equiv.cost;
      breakdown.push({ app: a.name, slug, saas_equivalent: equiv.name, monthly_cost: equiv.cost });
    }
  }
  res.json({
    monthly_if_saas: totalSaasCost,
    actual_cost: vmCost,
    monthly_savings: Math.round((totalSaasCost - vmCost) * 100) / 100,
    percent_saved: totalSaasCost > 0 ? Math.round(((totalSaasCost - vmCost) / totalSaasCost) * 100) : 0,
    breakdown
  });
}));

// --- Cost Per App Breakdown ---
app.get('/api/costs', asyncRoute(async (_req, res) => {
  const vmCost = parseFloat(process.env.VM_COST_MONTHLY || '12.48');
  const containers = await docker.listContainers();
  let totalCpu = 0;
  let totalMem = 0;
  const appCosts = [];
  for (const a of config.apps) {
    const appContainers = containers.filter(c => (a.containers || []).some(n => containerName(c).includes(n)));
    let cpuPct = 0, memPct = 0;
    for (const c of appContainers) {
      try {
        const stats = await docker.getContainer(c.Id).stats({ stream: false });
        const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - (stats.precpu_stats?.cpu_usage?.total_usage || 0);
        const sysDelta = stats.cpu_stats.system_cpu_usage - (stats.precpu_stats?.system_cpu_usage || 0);
        const cores = stats.cpu_stats.online_cpus || 1;
        if (sysDelta > 0) cpuPct += (cpuDelta / sysDelta) * cores * 100;
        if (stats.memory_stats.limit > 0) memPct += (stats.memory_stats.usage / stats.memory_stats.limit) * 100;
      } catch { /* container might be stopped */ }
    }
    totalCpu += cpuPct;
    totalMem += memPct;
    appCosts.push({ app: a.name, slug: slugify(a.name), cpu_pct: Math.round(cpuPct * 10) / 10, mem_pct: Math.round(memPct * 10) / 10 });
  }
  // Allocate cost proportionally by average of CPU + memory share
  for (const ac of appCosts) {
    const share = totalCpu + totalMem > 0 ? ((ac.cpu_pct / Math.max(totalCpu, 1)) + (ac.mem_pct / Math.max(totalMem, 1))) / 2 : 1 / appCosts.length;
    ac.cost_share = Math.round(vmCost * share * 100) / 100;
  }
  appCosts.sort((a, b) => b.cost_share - a.cost_share);
  res.json({ vm_cost: vmCost, apps: appCosts });
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

// --- Audit Log ---
app.get('/api/audit', asyncRoute((req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM audit_log').get().c;
  res.json({ total, limit, offset, data: rows });
}));

// Audit log helper
function auditLog(req, action, target, details = {}) {
  try {
    db.prepare('INSERT INTO audit_log (user, action, target, details, ip) VALUES (?, ?, ?, ?, ?)').run(
      req?.session?.username || 'system', action, target || null, JSON.stringify(details), req?.ip || 'unknown'
    );
  } catch (err) { console.error('[AUDIT]', err.message); }
}

// ========== IN-HOUSE ANALYTICS ==========

// Public: 1x1 tracking pixel (no-JS fallback)
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
  // Calculate uptime streak: consecutive days where all apps had status='up'
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
  // Get latest security grade
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
    // Top pages + referrers per app
    for (const r of rows) {
      const pages = db.prepare("SELECT url, COUNT(*) as c FROM page_views WHERE app_slug = ? AND date(created_at) = ? GROUP BY url ORDER BY c DESC LIMIT 10").all(r.app_slug, yesterday);
      const refs = db.prepare("SELECT referrer, COUNT(*) as c FROM page_views WHERE app_slug = ? AND date(created_at) = ? AND referrer IS NOT NULL AND referrer != '' GROUP BY referrer ORDER BY c DESC LIMIT 10").all(r.app_slug, yesterday);
      const countries = db.prepare("SELECT country, COUNT(*) as c FROM page_views WHERE app_slug = ? AND date(created_at) = ? AND country IS NOT NULL GROUP BY country ORDER BY c DESC").all(r.app_slug, yesterday);
      const countryObj = {};
      for (const c of countries) countryObj[c.country] = c.c;
      db.prepare("UPDATE analytics_daily SET top_pages = ?, top_referrers = ?, countries = ? WHERE app_slug = ? AND date = ?")
        .run(JSON.stringify(pages.map(p => p.url)), JSON.stringify(refs.map(r => r.referrer)), JSON.stringify(countryObj), r.app_slug, yesterday);
    }
    // Prune raw events older than 7 days
    const pruned = db.prepare("DELETE FROM page_views WHERE created_at < datetime('now', '-7 days')").run();
    console.log(`[ANALYTICS] Daily rollup for ${yesterday}: ${rows.length} apps, pruned ${pruned.changes} old events`);
  } catch (err) { cronFail('Analytics daily rollup', err); }
});

// ========== GITHUB WEBHOOK (auto-deploy) ==========

app.post('/api/webhooks/github', asyncRoute(async (req, res) => {
  const WEBHOOK_SECRET = getSetting('GITHUB_WEBHOOK_SECRET') || process.env.GITHUB_WEBHOOK_SECRET;
  if (!WEBHOOK_SECRET) return res.status(500).json({ error: 'Webhook secret not configured' });
  const sig = req.headers['x-hub-signature-256'];
  if (!sig || !req.rawBody) return res.status(401).json({ error: 'Invalid signature' });
  const expected = 'sha256=' + createHmac('sha256', WEBHOOK_SECRET).update(req.rawBody).digest('hex');
  if (sig !== expected) return res.status(401).json({ error: 'Invalid signature' });
  const event = req.headers['x-github-event'];
  const payload = req.body;
  if (event === 'push' && (payload.ref === 'refs/heads/main' || payload.ref === 'refs/heads/master')) {
    const appSlug = matchRepoToApp(payload.repository?.full_name);
    if (!appSlug) return res.json({ ok: true, skipped: 'no matching app' });
    auditLog(req, 'github_deploy', appSlug, { commit: payload.head_commit?.id?.slice(0, 7), message: payload.head_commit?.message });
    console.log(`[DEPLOY] GitHub push to ${appSlug}: ${payload.head_commit?.message}`);
    const appDef = config.apps.find(a => slugify(a.name) === appSlug);
    if (appDef?.composePath) {
      try {
        const dir = dirname(appDef.composePath);
        execSync(`cd ${dir} && git pull && docker compose up -d --build`, { timeout: TIMEOUT_BUILD });
        sendTelegram(`Deploy complete: ${appSlug} (${payload.head_commit?.id?.slice(0, 7)})`);
      } catch (err) {
        console.error(`[DEPLOY] ${appSlug} failed:`, err.message);
        sendTelegram(`Deploy FAILED: ${appSlug} — ${err.message.slice(0, 200)}`);
      }
    }
    res.json({ ok: true, deploying: appSlug });
  } else {
    res.json({ ok: true, event, skipped: true });
  }
}));

function matchRepoToApp(repoFullName) {
  if (!repoFullName) return null;
  for (const appDef of config.apps) {
    if (appDef.repo === repoFullName || appDef.repo === `https://github.com/${repoFullName}` || appDef.repo?.endsWith('/' + repoFullName)) {
      return slugify(appDef.name);
    }
  }
  return null;
}

// ========== SQLITE BACKUP CRON ==========

// Daily 3 AM: backup data.db + auth.db
cron.schedule('0 3 * * *', async () => {
  try {
    const timestamp = new Date().toISOString().slice(0, 10);
    const backupDir = join(BACKUP_DIR, 'sqlite');
    if (!existsSync(backupDir)) mkdirSync(backupDir, { recursive: true });
    await db.backup(join(backupDir, `data-${timestamp}.db`));
    console.log(`[BACKUP] data.db backed up`);
    await authDb.backup(join(backupDir, `auth-${timestamp}.db`));
    console.log(`[BACKUP] auth.db backed up`);
    // Prune backups older than 7 days
    const cutoff = new Date(Date.now() - 7 * MS_PER_DAY).toISOString().slice(0, 10);
    for (const f of readdirSync(backupDir)) {
      const match = f.match(/\d{4}-\d{2}-\d{2}/);
      if (match && match[0] < cutoff) {
        unlinkSync(join(backupDir, f));
        console.log(`[BACKUP] Pruned old backup: ${f}`);
      }
    }
  } catch (err) { cronFail('SQLite backup', err); }
});

// ========== ENV FILE CHANGE MONITOR ==========

const envFileHashes = new Map();

// Every 15 min: detect .env file changes
cron.schedule('*/15 * * * *', () => {
  try {
    for (const appDef of config.apps) {
      if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
      const slug = slugify(appDef.name);
      const content = readFileSync(appDef.envFile, 'utf8');
      const hash = hashValue(content);
      const prevHash = envFileHashes.get(slug);
      if (prevHash && prevHash !== hash) {
        sendTelegram(`Env file changed: ${slug}\nRe-verify env health or restart container.`);
        auditLog(null, 'env_change_detected', slug, { previous: prevHash, current: hash });
        console.log(`[ENV] Change detected: ${slug}`);
      }
      envFileHashes.set(slug, hash);
    }
  } catch (err) { cronFail('Env monitor', err); }
});

// ========== SMART CROSS-PROMO AUTO-PLACEMENT ==========

app.post('/api/marketing/crosspromo/auto-place', asyncRoute(async (req, res) => {
  const traffic = db.prepare("SELECT app_slug, SUM(visitors) as visitors FROM analytics_daily WHERE date >= date('now', '-30 days') GROUP BY app_slug ORDER BY visitors DESC").all();
  const banners = db.prepare("SELECT * FROM banners WHERE status = 'active'").all();
  const placements = [];
  for (const app of traffic) {
    const otherBanners = banners.filter(b => b.app_slug !== app.app_slug);
    if (otherBanners.length === 0) continue;
    const sorted = otherBanners.sort((a, b) => {
      const aT = traffic.find(t => t.app_slug === a.app_slug)?.visitors || 0;
      const bT = traffic.find(t => t.app_slug === b.app_slug)?.visitors || 0;
      return aT - bT;
    }).slice(0, 2);
    for (const banner of sorted) placements.push({ app_slug: app.app_slug, banner_id: banner.id });
  }
  res.json({ placements, count: placements.length });
}));

// GET /api/perf — request duration metrics (last 5 minutes)
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

// --- Notification Center API ---
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

// --- App Health Scores (lightweight batch endpoint for home view) ---
app.get('/api/apps/health-scores', asyncRoute((_req, res) => {
  const scores = {};
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const card = calculateAppReportCard(slug);
    if (card) {
      scores[slug] = { overall: card.overall, grade: card.grade, dimensions: card.dimensions };
    }
  }
  res.json({ scores, timestamp: new Date().toISOString() });
}));

// --- Portfolio P&L Dashboard ---
app.get('/api/portfolio/pnl', asyncRoute((_req, res) => {
  const apps = [];
  const totalVMCost = 12.00; // EUR/month Hetzner VM

  // Get total resource usage across all containers for proportional cost allocation
  let totalMemAlloc = 0;
  const appMemUsage = {};
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    let memMB = 0;
    if (appDef.containers?.length) {
      // Estimate base memory per container type
      memMB = appDef.containers.length * 80; // ~80MB avg per container
    } else {
      memMB = 10; // static sites ~10MB nginx
    }
    appMemUsage[slug] = memMB;
    totalMemAlloc += memMB;
  }

  let totalRevenue = 0, totalCosts = 0;

  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);

    // Revenue from Stripe
    const mrrRow = qLatestMetric.get(slug, 'mrr');
    const mrr = (mrrRow?.value || 0) / 100; // cents to EUR

    // Proportional infra cost based on estimated memory
    const memShare = totalMemAlloc > 0 ? (appMemUsage[slug] / totalMemAlloc) : 0;
    const infraCost = +(totalVMCost * memShare).toFixed(2);

    // Domain cost estimate (~1 EUR/month amortized for paid domains)
    const domainCost = appDef.domain ? 1.00 : 0;

    // API costs (rough estimate from env vars)
    let apiCost = 0;
    if (appDef.envFile && existsSync(appDef.envFile)) {
      const vars = parseEnvFile(appDef.envFile);
      const hasStripe = vars.some(v => v.key.includes('STRIPE') && v.value);
      const hasAI = vars.some(v => (v.key.includes('ANTHROPIC') || v.key.includes('OPENAI')) && v.value);
      const hasResend = vars.some(v => v.key.includes('RESEND') && v.value);
      if (hasStripe) apiCost += 0.50; // Stripe base fees
      if (hasAI) apiCost += 1.00; // AI API costs
      if (hasResend) apiCost += 0.50; // Email costs
    }

    const totalAppCost = +(infraCost + domainCost + apiCost).toFixed(2);
    const profit = +(mrr - totalAppCost).toFixed(2);

    totalRevenue += mrr;
    totalCosts += totalAppCost;

    apps.push({
      slug,
      name: appDef.name,
      type: appDef.type,
      revenue: mrr,
      costs: {
        infra: infraCost,
        domain: domainCost,
        api: apiCost,
        total: totalAppCost,
      },
      profit,
      profitable: profit > 0,
    });
  }

  // Sort by profit descending
  apps.sort((a, b) => b.profit - a.profit);

  res.json({
    portfolio: {
      totalRevenue: +totalRevenue.toFixed(2),
      totalCosts: +totalCosts.toFixed(2),
      totalProfit: +(totalRevenue - totalCosts).toFixed(2),
      vmCost: totalVMCost,
      appCount: apps.length,
    },
    apps,
    timestamp: new Date().toISOString(),
  });
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

// --- Cron Job Monitoring (Dead Man's Switch) ---
const cronHeartbeats = new Map(); // cronName -> { lastRun, duration, status, error }

function recordCronHeartbeat(name, status, durationMs, error) {
  cronHeartbeats.set(name, {
    lastRun: new Date().toISOString(),
    duration: durationMs,
    status, // 'ok' | 'error'
    error: error || null,
  });
}

// Wrap existing guardedCron to track heartbeats
const _origGuardedCron = guardedCron;
// We can't replace guardedCron retroactively, but we can track via a monitoring endpoint
// that checks last execution times from ops_scores, security_scans, etc.

app.get('/api/cron/status', asyncRoute((_req, res) => {
  const jobs = [];

  // Check each cron by its last output in the database
  const cronChecks = [
    { name: 'Revenue & Analytics', schedule: 'Every 6h', table: 'metrics_daily', query: "SELECT MAX(date) as last FROM metrics_daily" },
    { name: 'SEO Audits', schedule: 'Daily 1:30 AM', table: 'seo_audits', query: "SELECT MAX(date) as last FROM seo_audits" },
    { name: 'Security Scan', schedule: 'Daily 1 AM', table: 'security_scans', query: "SELECT MAX(timestamp) as last FROM security_scans" },
    { name: 'Worry Score', schedule: 'Every 15 min', table: 'ops_scores', query: "SELECT MAX(timestamp) as last FROM ops_scores" },
    { name: 'Uptime Checks', schedule: 'Every 5 min', table: 'uptime_history', query: "SELECT MAX(checked_at) as last FROM uptime_history" },
    { name: 'Error Ingestion', schedule: 'Every 5 min', table: 'error_events', query: "SELECT MAX(created_at) as last FROM error_events" },
    { name: 'Sparkline Snapshots', schedule: 'Hourly', table: 'sparkline_snapshots', query: "SELECT MAX(timestamp) as last FROM sparkline_snapshots" },
    { name: 'Database Backup', schedule: 'Daily 3 AM', table: null, query: null },
    { name: 'Perf Metrics', schedule: 'Every 15 min', table: 'perf_metrics', query: "SELECT MAX(hour) as last FROM perf_metrics" },
    { name: 'Log Ingestion', schedule: 'Every 5 min', table: 'container_logs', query: "SELECT MAX(ingested_at) as last FROM container_logs" },
    { name: 'Alert Rules', schedule: 'Every 5 min', table: 'alert_rules', query: "SELECT MAX(last_fired_at) as last FROM alert_rules WHERE last_fired_at IS NOT NULL" },
    { name: 'Anomaly Check', schedule: 'Every 30 min', table: 'system_snapshots', query: "SELECT MAX(ts) as last FROM system_snapshots" },
    { name: 'Auto-Healing', schedule: 'Every 2 min', table: 'healing_log', query: "SELECT MAX(timestamp) as last FROM healing_log" },
  ];

  const expectedIntervals = {
    'Every 5 min': 10 * 60 * 1000,      // alert if >10 min
    'Every 15 min': 30 * 60 * 1000,     // alert if >30 min
    'Hourly': 2 * 60 * 60 * 1000,       // alert if >2h
    'Every 6h': 12 * 60 * 60 * 1000,    // alert if >12h
    'Daily 1 AM': 36 * 60 * 60 * 1000,  // alert if >36h
    'Daily 1:30 AM': 36 * 60 * 60 * 1000,
    'Daily 3 AM': 36 * 60 * 60 * 1000,
    'Every 2 min': 10 * 60 * 1000,
    'Every 30 min': 60 * 60 * 1000,
  };

  for (const check of cronChecks) {
    let lastRun = null, status = 'unknown';
    if (check.query) {
      try {
        const row = db.prepare(check.query).get();
        lastRun = row?.last || null;
      } catch { /* table may not exist yet */ }
    }

    if (lastRun) {
      const ageMs = Date.now() - new Date(lastRun).getTime();
      const maxAge = expectedIntervals[check.schedule] || 36 * 60 * 60 * 1000;
      status = ageMs <= maxAge ? 'ok' : 'overdue';
    } else {
      status = 'never_run';
    }

    jobs.push({
      name: check.name,
      schedule: check.schedule,
      lastRun,
      status,
    });
  }

  const overdue = jobs.filter(j => j.status === 'overdue');
  res.json({
    jobs,
    healthy: overdue.length === 0,
    overdueCount: overdue.length,
    timestamp: new Date().toISOString(),
  });
}));

// --- Weekly Portfolio Report Card ---
app.get('/api/portfolio/report', asyncRoute((_req, res) => {
  const cards = config.apps.map(a => calculateAppReportCard(slugify(a.name))).filter(Boolean);

  // Portfolio-level aggregations
  const avgScore = cards.length > 0 ? Math.round(cards.reduce((s, c) => s + c.overall, 0) / cards.length) : 0;
  const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const c of cards) {
    const g = c.grade.charAt(0);
    if (gradeDistribution[g] !== undefined) gradeDistribution[g]++;
  }

  // Week-over-week comparison from project_snapshots
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const prevSnapshots = db.prepare('SELECT app_slug, security_score, seo_score, mrr_cents, traffic_30d FROM project_snapshots WHERE snapshot_date <= ? ORDER BY snapshot_date DESC').all(weekAgo);
  const prevMap = new Map();
  for (const s of prevSnapshots) {
    if (!prevMap.has(s.app_slug)) prevMap.set(s.app_slug, s);
  }

  const appReports = cards.map(card => {
    const prev = prevMap.get(card.slug);
    const trends = {};
    if (prev) {
      if (prev.security_score != null) trends.security = card.dimensions.security?.score - prev.security_score;
      if (prev.seo_score != null) trends.seo = (card.dimensions.seo?.score || 0) - prev.seo_score;
      if (prev.mrr_cents != null) trends.revenue = (card.dimensions.revenue?.score || 0) - (prev.mrr_cents > 0 ? Math.min(100, Math.round(50 + Math.log10(prev.mrr_cents / 100 + 1) * 30)) : 0);
    }
    return { ...card, trends };
  });

  // Top accomplishment & biggest concern
  const sorted = [...appReports].sort((a, b) => b.overall - a.overall);
  const topApp = sorted[0];
  const weakestApp = sorted[sorted.length - 1];

  res.json({
    portfolioGrade: letterGrade(avgScore),
    portfolioScore: avgScore,
    gradeDistribution,
    appCount: cards.length,
    topPerformer: topApp ? { name: topApp.name, grade: topApp.grade, score: topApp.overall } : null,
    needsAttention: weakestApp && weakestApp.overall < 60 ? { name: weakestApp.name, grade: weakestApp.grade, score: weakestApp.overall } : null,
    apps: appReports,
    timestamp: new Date().toISOString(),
  });
}));

// Weekly report card cron — send via Telegram every Monday at 8 AM
cron.schedule('0 8 * * 1', guardedCron('weekly-report', async () => {
  try {
    const cards = config.apps.map(a => calculateAppReportCard(slugify(a.name))).filter(Boolean);
    const avgScore = cards.length > 0 ? Math.round(cards.reduce((s, c) => s + c.overall, 0) / cards.length) : 0;
    const grade = letterGrade(avgScore);
    const sorted = [...cards].sort((a, b) => b.overall - a.overall);
    const top = sorted[0];
    const weak = sorted[sorted.length - 1];

    let msg = `📊 <b>Weekly Portfolio Report</b>\n`;
    msg += `\nOverall: <b>${grade}</b> (${avgScore}/100)`;
    msg += `\nApps: ${cards.length}`;
    if (top) msg += `\n⭐ Top: ${top.name} (${top.grade}, ${top.overall}/100)`;
    if (weak && weak.overall < 60) msg += `\n⚠️ Needs attention: ${weak.name} (${weak.grade}, ${weak.overall}/100)`;

    // Grade breakdown
    const grades = cards.map(c => `${c.name}: ${c.grade}`).join(', ');
    msg += `\n\n${grades}`;

    sendTelegram(msg);
    addNotification('ops', 'info', `Weekly Report: ${grade} (${avgScore}/100)`, msg);
  } catch (err) { cronFail('Weekly report', err); }
}));

// Uptime streak celebration — daily check at 10 AM
cron.schedule('0 10 * * *', guardedCron('streak-celebrate', async () => {
  try {
    for (const appDef of config.apps) {
      if (!appDef.domain) continue;
      const slug = slugify(appDef.name);
      const days = db.prepare(`
        SELECT date(checked_at) as day, COUNT(*) as checks,
               SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_checks
        FROM uptime_history WHERE app_slug = ? AND checked_at > datetime('now', '-90 days')
        GROUP BY date(checked_at) ORDER BY day DESC
      `).all(slug);

      let streak = 0;
      for (const d of days) {
        if (d.checks > 0 && d.up_checks === d.checks) streak++;
        else break;
      }

      // Celebrate milestones: 7, 30, 60, 90 days
      if ([7, 30, 60, 90].includes(streak)) {
        sendTelegram(`🏆 ${appDef.name}: ${streak}-day uptime streak!`);
        addNotification('ops', 'info', `${appDef.name}: ${streak}-day uptime streak!`, null, slug);
      }
    }
  } catch (err) { cronFail('Streak celebrate', err); }
}));

// Cron health check — alert if any job is overdue (hourly)
cron.schedule('30 * * * *', guardedCron('cron-monitor', async () => {
  const cronChecks = [
    { name: 'Worry Score', query: "SELECT MAX(timestamp) as last FROM ops_scores", maxAgeMs: 30 * 60 * 1000 },
    { name: 'Uptime Checks', query: "SELECT MAX(checked_at) as last FROM uptime_history", maxAgeMs: 15 * 60 * 1000 },
    { name: 'Security Scan', query: "SELECT MAX(timestamp) as last FROM security_scans", maxAgeMs: 36 * 60 * 60 * 1000 },
  ];

  const overdue = [];
  for (const check of cronChecks) {
    try {
      const row = db.prepare(check.query).get();
      if (row?.last) {
        const ageMs = Date.now() - new Date(row.last).getTime();
        if (ageMs > check.maxAgeMs) overdue.push(check.name);
      }
    } catch { /* table may not exist yet */ }
  }

  if (overdue.length > 0) {
    sendTelegram(`⚠️ Overdue cron jobs: ${overdue.join(', ')}\nCheck /api/cron/status for details`);
  }
}));

// --- Anomaly Detection (statistical z-scores on system metrics) ---
app.get('/api/anomalies', asyncRoute((_req, res) => {
  const anomalies = [];
  const ALLOWED_METRICS = ['cpu_percent', 'mem_used_bytes', 'load_1m', 'disk_used_bytes'];
  const metrics = ['cpu_percent', 'mem_used_bytes', 'load_1m', 'disk_used_bytes'];

  for (const metric of metrics) {
    // Whitelist check to prevent SQL injection via dynamic column name
    if (!ALLOWED_METRICS.includes(metric)) continue;
    // Get 7-day baseline
    const rows = db.prepare(`SELECT ${metric} as val FROM system_snapshots WHERE ts > datetime('now', '-7 days') ORDER BY ts ASC`).all();
    if (rows.length < 20) continue; // need enough data

    const values = rows.map(r => r.val);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
    const stddev = Math.sqrt(variance);
    if (stddev === 0) continue;

    // Check latest value
    const latest = values[values.length - 1];
    const zscore = (latest - mean) / stddev;

    if (Math.abs(zscore) >= 2) {
      const direction = zscore > 0 ? 'above' : 'below';
      const severity = Math.abs(zscore) >= 3 ? 'critical' : 'warning';
      let displayVal, displayMean;

      if (metric.includes('bytes')) {
        displayVal = (latest / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
        displayMean = (mean / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
      } else if (metric === 'cpu_percent') {
        displayVal = latest.toFixed(1) + '%';
        displayMean = mean.toFixed(1) + '%';
      } else {
        displayVal = latest.toFixed(2);
        displayMean = mean.toFixed(2);
      }

      const label = metric.replace(/_/g, ' ').replace('bytes', '').replace('percent', '%').trim();
      anomalies.push({
        metric,
        label,
        severity,
        zscore: +zscore.toFixed(2),
        direction,
        current: displayVal,
        mean7d: displayMean,
        message: `${label} is ${Math.abs(zscore).toFixed(1)}x std dev ${direction} 7-day average (${displayVal} vs avg ${displayMean})`,
      });
    }
  }

  // Per-app uptime anomalies
  for (const appDef of config.apps) {
    if (!appDef.domain) continue;
    const slug = slugify(appDef.name);
    const rows = db.prepare(`
      SELECT date(checked_at) as day, COUNT(*) as checks,
             SUM(CASE WHEN status != 'up' THEN 1 ELSE 0 END) as failures
      FROM uptime_history WHERE app_slug = ? AND checked_at > datetime('now', '-7 days')
      GROUP BY date(checked_at)
    `).all(slug);

    const todayRow = rows[rows.length - 1];
    if (todayRow && todayRow.failures > 0 && rows.length >= 3) {
      const avgFailures = rows.slice(0, -1).reduce((s, r) => s + r.failures, 0) / Math.max(1, rows.length - 1);
      if (todayRow.failures > avgFailures * 2 + 1) {
        anomalies.push({
          metric: 'uptime',
          label: `${appDef.name} failures`,
          severity: 'warning',
          zscore: 0,
          direction: 'above',
          current: `${todayRow.failures} failures`,
          mean7d: `${avgFailures.toFixed(1)} avg`,
          message: `${appDef.name}: ${todayRow.failures} uptime failures today vs ${avgFailures.toFixed(1)} daily avg`,
          appSlug: slug,
        });
      }
    }
  }

  res.json({ anomalies, timestamp: new Date().toISOString() });
}));

// GET /api/anomalies/narrative — AI-generated explanation of current anomalies
app.get('/api/anomalies/narrative', asyncRoute(async (req, res) => {
  const apiKey = getAnthropicKey();
  if (!apiKey) return res.json({ narrative: null, error: 'No API key configured' });

  // Collect current anomalies (reuse logic)
  const anomalies = [];
  const ALLOWED_METRICS = ['cpu_percent', 'mem_used_bytes', 'load_1m', 'disk_used_bytes'];
  for (const metric of ALLOWED_METRICS) {
    const rows = db.prepare(`SELECT ${metric} as val, ts FROM system_snapshots WHERE ts > datetime('now', '-7 days') ORDER BY ts ASC`).all();
    if (rows.length < 20) continue;
    const values = rows.map(r => r.val);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const stddev = Math.sqrt(values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length);
    if (stddev === 0) continue;
    const latest = values[values.length - 1];
    const zscore = (latest - mean) / stddev;
    if (Math.abs(zscore) >= 2) {
      anomalies.push({ metric, zscore: +zscore.toFixed(2), current: latest, mean: mean, latestTs: rows[rows.length - 1].ts });
    }
  }

  if (anomalies.length === 0) return res.json({ narrative: 'No anomalies detected. All metrics are within normal ranges.', anomalies: [] });

  // Gather context for AI
  const contextParts = [];
  contextParts.push(`Current anomalies: ${anomalies.map(a => `${a.metric}: z-score ${a.zscore} (current: ${a.current}, 7d mean: ${a.mean.toFixed(2)})`).join('; ')}`);

  // Recent Docker events
  try {
    const recentHealing = db.prepare("SELECT condition, action_taken, app_slug FROM healing_log WHERE timestamp > datetime('now', '-6 hours') ORDER BY timestamp DESC LIMIT 5").all();
    if (recentHealing.length > 0) contextParts.push(`Recent healing: ${recentHealing.map(h => `${h.app_slug}: ${h.condition} -> ${h.action_taken}`).join('; ')}`);
  } catch { /* skip */ }

  // Container stats
  try {
    const containers = await docker.listContainers({ all: true });
    const unhealthy = containers.filter(c => c.Status?.includes('unhealthy') || c.State === 'restarting');
    if (unhealthy.length > 0) contextParts.push(`Unhealthy containers: ${unhealthy.map(c => containerName(c)).join(', ')}`);
    contextParts.push(`Total containers: ${containers.length}, running: ${containers.filter(c => c.State === 'running').length}`);
  } catch { /* skip */ }

  // Recent error patterns from log aggregation
  try {
    const errors = db.prepare("SELECT container_name, COUNT(*) as count FROM container_logs WHERE logged_at > datetime('now', '-1 hour') AND (line LIKE '%error%' OR line LIKE '%ERROR%') GROUP BY container_name ORDER BY count DESC LIMIT 5").all();
    if (errors.length > 0) contextParts.push(`Error volume (last hour): ${errors.map(e => `${e.container_name}: ${e.count} errors`).join(', ')}`);
  } catch { /* skip */ }

  try {
    const result = await callAnthropic(apiKey, {
      model: 'claude-haiku-4-5-20251001', maxTokens: 400, timeout: TIMEOUT_AI,
      system: 'You are a DevOps analyst. Explain the anomalies in plain language. What is likely causing them? What should the operator do? Be concise — 3-5 sentences max. No bullet points, write as a narrative paragraph.',
      messages: [{ role: 'user', content: contextParts.join('\n\n') }],
    });
    res.json({ narrative: result.text, anomalies, tokens: result.tokens, timestamp: new Date().toISOString() });
  } catch (err) {
    res.json({ narrative: null, error: err.message, anomalies });
  }
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

// --- Revenue Milestones ---
const revenueMilestonesChecked = new Set();

app.get('/api/revenue/milestones', asyncRoute((_req, res) => {
  const milestones = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
  const result = [];

  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const row = qLatestMetric.get(slug, 'mrr');
    const mrr = (row?.value || 0) / 100; // cents to EUR

    const achieved = milestones.filter(m => mrr >= m);
    const nextMilestone = milestones.find(m => mrr < m) || null;
    const progress = nextMilestone ? +(mrr / nextMilestone * 100).toFixed(1) : 100;

    if (mrr > 0) {
      result.push({
        slug,
        name: appDef.name,
        mrr: +mrr.toFixed(2),
        achieved,
        nextMilestone,
        progress,
      });
    }
  }

  // Portfolio total
  const totalMRR = result.reduce((s, a) => s + a.mrr, 0);
  const portfolioAchieved = milestones.filter(m => totalMRR >= m);
  const portfolioNext = milestones.find(m => totalMRR < m) || null;

  res.json({
    apps: result,
    portfolio: {
      totalMRR: +totalMRR.toFixed(2),
      achieved: portfolioAchieved,
      nextMilestone: portfolioNext,
      progress: portfolioNext ? +(totalMRR / portfolioNext * 100).toFixed(1) : 100,
    },
    timestamp: new Date().toISOString(),
  });
}));

// Revenue milestone celebration cron — daily at 9 AM
cron.schedule('0 9 * * *', guardedCron('revenue-milestones', async () => {
  try {
    const milestones = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const row = qLatestMetric.get(slug, 'mrr');
      const mrr = (row?.value || 0) / 100;

      for (const m of milestones) {
        const key = `${slug}:${m}`;
        if (mrr >= m && !revenueMilestonesChecked.has(key)) {
          // Check if we already celebrated (stored in settings)
          const celebrated = getSetting(`milestone:${key}`);
          if (!celebrated) {
            upsertSettingStmt.run(`milestone:${key}`, new Date().toISOString());
            sendTelegram(`🎉 <b>Revenue Milestone!</b>\n${appDef.name} crossed €${m} MRR!\nCurrent: €${mrr.toFixed(0)}`);
            addNotification('revenue', 'info', `${appDef.name} crossed €${m} MRR!`, `Current MRR: €${mrr.toFixed(0)}`, slug);
          }
          revenueMilestonesChecked.add(key);
        }
      }
    }
  } catch (err) { cronFail('Revenue milestones', err); }
}));

// Anomaly alert cron — every 30 minutes
cron.schedule('*/30 * * * *', guardedCron('anomaly-check', async () => {
  try {
    const ALLOWED_ANOMALY_METRICS = ['cpu_percent', 'mem_used_bytes', 'load_1m'];
    const metrics = ['cpu_percent', 'mem_used_bytes', 'load_1m'];
    for (const metric of metrics) {
      // Whitelist check to prevent SQL injection via dynamic column name
      if (!ALLOWED_ANOMALY_METRICS.includes(metric)) continue;
      const rows = db.prepare(`SELECT ${metric} as val FROM system_snapshots WHERE ts > datetime('now', '-7 days') ORDER BY ts ASC`).all();
      if (rows.length < 20) continue;

      const values = rows.map(r => r.val);
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
      const stddev = Math.sqrt(variance);
      if (stddev === 0) continue;

      const latest = values[values.length - 1];
      const zscore = (latest - mean) / stddev;

      if (zscore >= 3) {
        const label = metric.replace(/_/g, ' ').replace('percent', '%');
        sendTelegram(`📊 <b>Anomaly Detected</b>\n${label}: ${zscore.toFixed(1)}σ above 7-day average\nCurrent vs avg: check /api/anomalies`);
      }
    }
  } catch (err) { cronFail('Anomaly check', err); }
}));

// --- AI Incident Responder ---

app.post('/api/incidents/analyze', asyncRoute(async (req, res) => {
  const { containerName, appSlug } = req.body;
  if (!containerName) return res.status(400).json({ error: 'containerName is required' });

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(400).json({ error: 'No Anthropic API key configured' });

  // Gather context: logs, system metrics, healing history, uptime
  let logSnippet = '';
  try {
    const container = docker.getContainer(containerName);
    const logs = await container.logs({ stdout: true, stderr: true, tail: 200 });
    logSnippet = (typeof logs === 'string' ? logs : logs.toString('utf8')).replace(/^.{8}/gm, '').trim().slice(-4000);
  } catch { logSnippet = '(Container logs unavailable)'; }

  const slug = appSlug || containerName;

  // Recent system metrics
  const recentMetrics = db.prepare(
    "SELECT ts, cpu_percent, mem_used_bytes, mem_total_bytes, disk_used_bytes, disk_total_bytes, load_1m FROM system_snapshots WHERE ts > datetime('now', '-6 hours') ORDER BY ts DESC LIMIT 20"
  ).all();

  // Recent healing events for this app
  const recentHealing = db.prepare(
    "SELECT condition, action_taken, result, timestamp FROM healing_log WHERE app_slug = ? ORDER BY timestamp DESC LIMIT 5"
  ).all(slug);

  // Uptime history
  const uptimeHistory = db.prepare(
    "SELECT status, checked_at FROM uptime_history WHERE app_slug = ? ORDER BY checked_at DESC LIMIT 20"
  ).all(slug);

  const metricsStr = recentMetrics.slice(0, 5).map(m =>
    `${m.ts}: CPU ${m.cpu_percent.toFixed(1)}%, Mem ${(m.mem_used_bytes / m.mem_total_bytes * 100).toFixed(1)}%, Disk ${(m.disk_used_bytes / m.disk_total_bytes * 100).toFixed(1)}%, Load ${m.load_1m}`
  ).join('\n');

  const healingStr = recentHealing.map(h =>
    `${h.timestamp}: ${h.condition} → ${h.action_taken} (${h.result})`
  ).join('\n');

  const uptimeStr = uptimeHistory.slice(0, 10).map(u =>
    `${u.checked_at}: ${u.status}`
  ).join('\n');

  const prompt = `You are a DevOps incident responder analyzing a container issue. Provide a root cause analysis.

Container: ${containerName}
App: ${slug}

## Recent Logs (last 200 lines)
${logSnippet}

## System Metrics (last 6 hours)
${metricsStr || '(No metrics available)'}

## Recent Healing Events
${healingStr || '(None)'}

## Uptime History
${uptimeStr || '(No data)'}

Provide your analysis in this format:
1. **Root Cause**: Most likely reason for the issue (1-2 sentences)
2. **Evidence**: What in the logs/metrics supports this conclusion
3. **Impact**: What users/services are affected
4. **Fix**: Specific actionable steps to resolve
5. **Prevention**: How to prevent recurrence

Be concise and actionable. Focus on the most likely root cause.`;

  try {
    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      maxTokens: 500,
      timeout: 15000,
      messages: [{ role: 'user', content: prompt }],
    }));

    res.json({
      analysis: ai.text,
      context: {
        logLines: logSnippet.split('\n').length,
        metricsPoints: recentMetrics.length,
        healingEvents: recentHealing.length,
        uptimeChecks: uptimeHistory.length,
      },
      tokens: ai.tokens,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}));

// --- Public Status Page ---

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

    // Check container health from pre-fetched inspect results
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

    // If no containers, check domain health
    if (containers.length === 0 && appDef.domain) {
      status = 'operational';
      statusText = 'Static Site';
    }

    // Uptime percentage from batched history
    const uptimeRows = uptimeByApp[slug] || [];
    const totalChecks = uptimeRows.length;
    const upChecks = uptimeRows.filter(r => r.status === 'up' || r.status === 'healthy').length;
    const uptimePct = totalChecks > 0 ? +(upChecks / totalChecks * 100).toFixed(2) : null;

    // Recent incidents from batched healing log
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

// Public status page — serves standalone HTML, no auth required
app.get('/status', (_req, res) => {
  res.send(generateStatusPageHTML());
});

function generateStatusPageHTML() {
  // Batch queries to avoid N+1 per app
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

// --- Real-Time Visitors Widget ---
app.get('/api/realtime/visitors', asyncRoute(async (_req, res) => {
  const apiKey = getPlausibleApiKey();
  if (!apiKey) return res.json({ apps: [], total: 0 });

  const baseUrl = `${getPlausibleUrl()}/api/v1/stats/realtime/visitors`;
  const apps = [];
  let total = 0;

  await Promise.all(config.apps.filter(a => a.domain).map(async (appDef) => {
    try {
      const r = await fetch(`${baseUrl}?site_id=${appDef.domain}`, {
        headers: { Authorization: `Bearer ${apiKey}` },
        signal: AbortSignal.timeout(5000),
      });
      const count = r.ok ? parseInt(await r.text()) || 0 : 0;
      if (count > 0) {
        apps.push({ slug: slugify(appDef.name), name: appDef.name, domain: appDef.domain, visitors: count });
        total += count;
      }
    } catch { /* silent */ }
  }));

  apps.sort((a, b) => b.visitors - a.visitors);
  res.json({ apps, total, timestamp: new Date().toISOString() });
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

// --- Solopreneur Focus Recommendations (AI-powered) ---
app.get('/api/focus', asyncRoute(async (_req, res) => {
  const apiKey = getAnthropicKey();
  if (!apiKey) return res.json({ recommendations: [], error: 'No API key' });

  // Gather all app metrics for AI analysis
  const appSummaries = [];
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const card = calculateAppReportCard(slug);
    const mrrRow = qLatestMetric.get(slug, 'mrr');
    const trafficRow = qLatestMetric.get(slug, 'pageviews_30d');
    const seoRow = qLatestSEO.get(slug);

    appSummaries.push({
      name: appDef.name,
      type: appDef.type,
      score: card?.overall || 0,
      grade: card?.grade || 'N/A',
      mrr: mrrRow ? (mrrRow.value / 100).toFixed(0) : '0',
      traffic: trafficRow?.value || 0,
      seoScore: seoRow?.score || 0,
      seoGrade: seoRow?.grade || 'N/A',
    });
  }

  const systemPrompt = `You are a startup advisor for a solo developer running ${appSummaries.length} apps. Be concise and actionable. Return exactly 3 recommendations in this JSON format:
[{"app":"AppName","action":"One sentence what to do","why":"One sentence why","effort":"low|medium|high","impact":"low|medium|high"}]
Only return the JSON array, no markdown, no explanation.`;

  const userMsg = `Here are my apps and their current metrics:
${appSummaries.map(a => `- ${a.name} (${a.type}): Score ${a.score}/100 (${a.grade}), MRR €${a.mrr}, Traffic ${a.traffic} visits/30d, SEO ${a.seoGrade}`).join('\n')}

Based on effort-to-impact ratio, what 3 things should I focus on this week?`;

  try {
    const result = await callAnthropic(apiKey, {
      model: 'claude-haiku-4-5-20251001',
      messages: [{ role: 'user', content: userMsg }],
      system: systemPrompt,
      maxTokens: 512,
      timeout: 10000,
    });

    let recommendations = [];
    try {
      recommendations = JSON.parse(result.text);
    } catch {
      recommendations = [{ app: 'Portfolio', action: result.text, why: 'AI analysis', effort: 'medium', impact: 'high' }];
    }

    res.json({
      recommendations,
      tokens: result.tokens,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.json({ recommendations: [], error: err.message });
  }
}));

// --- Stripe Checkout Management ---

function getStripeKeyForApp(appSlug, appKeys) {
  if (!appSlug) return null;
  for (const appDef of config.apps) {
    if (slugify(appDef.name) === appSlug) {
      return appKeys.get(appDef.name);
    }
  }
  return null;
}

// List Stripe products and prices for an app
app.get('/api/stripe/products', asyncRoute(async (req, res) => {
  const { keys, appKeys } = getStripeKeys();
  const appSlug = req.query.app;
  let secretKey = getStripeKeyForApp(appSlug, appKeys);
  if (!secretKey) secretKey = keys.keys().next().value;
  if (!secretKey) return res.json({ products: [], error: 'No Stripe key configured' });

  const headers = stripeHeaders(secretKey);
  const opts = { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) };

  const [productsRes, pricesRes] = await Promise.all([
    fetch(`${STRIPE_API}/products?active=true&limit=100`, opts),
    fetch(`${STRIPE_API}/prices?active=true&limit=100&expand[]=data.product`, opts),
  ]);

  const products = productsRes.ok ? (await productsRes.json()).data : [];
  const prices = pricesRes.ok ? (await pricesRes.json()).data : [];

  res.json({
    products: products.map(p => ({
      id: p.id,
      name: p.name,
      description: p.description,
      images: p.images,
      metadata: p.metadata,
    })),
    prices: prices.map(p => ({
      id: p.id,
      productId: p.product?.id || p.product,
      productName: p.product?.name || null,
      currency: p.currency,
      unitAmount: p.unit_amount,
      type: p.type,
      recurring: p.recurring ? { interval: p.recurring.interval, intervalCount: p.recurring.interval_count } : null,
    })),
    timestamp: new Date().toISOString(),
  });
}));

// Create a Stripe Checkout session (one-time or subscription)
app.post('/api/stripe/checkout', asyncRoute(async (req, res) => {
  const { priceId, mode, successUrl, cancelUrl, appSlug } = req.body;
  if (!priceId) return res.status(400).json({ error: 'priceId is required' });
  if (!successUrl || !cancelUrl) {
    return res.status(400).json({ error: 'success_url and cancel_url are required' });
  }

  const { keys, appKeys } = getStripeKeys();
  let secretKey = getStripeKeyForApp(appSlug, appKeys);
  if (!secretKey) secretKey = keys.keys().next().value;
  if (!secretKey) return res.status(400).json({ error: 'No Stripe key configured' });

  const headers = stripeHeaders(secretKey);
  const body = new URLSearchParams({
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'mode': mode || 'payment',
    'success_url': successUrl,
    'cancel_url': cancelUrl,
    'allow_promotion_codes': 'true',
    'tax_id_collection[enabled]': 'true',
  });

  // Add German payment methods for payment mode
  if ((mode || 'payment') === 'payment') {
    body.append('payment_method_types[]', 'card');
    body.append('payment_method_types[]', 'sepa_debit');
  }

  const sessionRes = await fetch(`${STRIPE_API}/checkout/sessions`, {
    method: 'POST',
    headers,
    body,
    signal: AbortSignal.timeout(TIMEOUT_STANDARD),
  });

  if (!sessionRes.ok) {
    const err = await sessionRes.json();
    return res.status(400).json({ error: err.error?.message || 'Stripe API error' });
  }

  const session = await sessionRes.json();
  res.json({
    sessionId: session.id,
    url: session.url,
    mode: session.mode,
    expiresAt: new Date(session.expires_at * 1000).toISOString(),
  });
}));

// List Stripe Payment Links
app.get('/api/stripe/payment-links', asyncRoute(async (req, res) => {
  const { keys, appKeys } = getStripeKeys();
  const appSlug = req.query.app;
  let secretKey = getStripeKeyForApp(appSlug, appKeys);
  if (!secretKey) secretKey = keys.keys().next().value;
  if (!secretKey) return res.json({ links: [], error: 'No Stripe key configured' });

  const headers = stripeHeaders(secretKey);
  const linksRes = await fetch(`${STRIPE_API}/payment_links?active=true&limit=100`, {
    headers,
    signal: AbortSignal.timeout(TIMEOUT_STANDARD),
  });

  if (!linksRes.ok) {
    const err = await linksRes.json();
    return res.status(400).json({ error: err.error?.message || 'Stripe API error' });
  }

  const data = await linksRes.json();
  res.json({
    links: data.data.map(l => ({
      id: l.id,
      url: l.url,
      active: l.active,
      metadata: l.metadata,
    })),
    timestamp: new Date().toISOString(),
  });
}));

// Create a Stripe Payment Link (permanent, reusable)
app.post('/api/stripe/payment-links', asyncRoute(async (req, res) => {
  const { priceId, appSlug } = req.body;
  if (!priceId) return res.status(400).json({ error: 'priceId is required' });

  const { keys, appKeys } = getStripeKeys();
  let secretKey = getStripeKeyForApp(appSlug, appKeys);
  if (!secretKey) secretKey = keys.keys().next().value;
  if (!secretKey) return res.status(400).json({ error: 'No Stripe key configured' });

  const headers = stripeHeaders(secretKey);
  const body = new URLSearchParams({
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'allow_promotion_codes': 'true',
    'tax_id_collection[enabled]': 'true',
  });

  if (req.body.afterCompletionUrl) {
    body.append('after_completion[type]', 'redirect');
    body.append('after_completion[redirect][url]', req.body.afterCompletionUrl);
  }

  const linkRes = await fetch(`${STRIPE_API}/payment_links`, {
    method: 'POST',
    headers,
    body,
    signal: AbortSignal.timeout(TIMEOUT_STANDARD),
  });

  if (!linkRes.ok) {
    const err = await linkRes.json();
    return res.status(400).json({ error: err.error?.message || 'Stripe API error' });
  }

  const link = await linkRes.json();
  res.json({
    id: link.id,
    url: link.url,
    active: link.active,
  });
}));

// Stripe recent payments/charges summary
app.get('/api/stripe/recent', asyncRoute(async (_req, res) => {
  const { keys } = getStripeKeys();
  const secretKey = keys.keys().next().value;
  if (!secretKey) return res.json({ charges: [], error: 'No Stripe key configured' });

  const headers = stripeHeaders(secretKey);
  const chargesRes = await fetch(`${STRIPE_API}/charges?limit=25`, {
    headers,
    signal: AbortSignal.timeout(TIMEOUT_STANDARD),
  });

  if (!chargesRes.ok) return res.json({ charges: [], error: 'Stripe API error' });

  const data = await chargesRes.json();
  res.json({
    charges: data.data.map(c => ({
      id: c.id,
      amount: c.amount,
      currency: c.currency,
      status: c.status,
      description: c.description,
      customerEmail: c.billing_details?.email,
      created: new Date(c.created * 1000).toISOString(),
      paid: c.paid,
      refunded: c.refunded,
    })),
    timestamp: new Date().toISOString(),
  });
}));

// --- Webhook / Alert Rules ---

app.get('/api/alerts/rules', asyncRoute((_req, res) => {
  const rules = db.prepare('SELECT * FROM alert_rules ORDER BY created_at DESC').all();
  res.json({ rules });
}));

app.post('/api/alerts/rules', asyncRoute((req, res) => {
  const { appSlug, metric, operator, threshold, windowMinutes, action } = req.body;
  if (!metric || !operator || !threshold) return res.status(400).json({ error: 'metric, operator, and threshold are required' });

  const validOperators = ['>', '<', '>=', '<=', '==', '!=', 'contains'];
  if (!validOperators.includes(operator)) return res.status(400).json({ error: 'Invalid operator' });

  const validActions = ['telegram', 'webhook', 'email'];
  const act = action || 'telegram';
  if (!validActions.includes(act.split(':')[0])) return res.status(400).json({ error: 'Invalid action. Use: telegram, webhook:URL, or email:ADDRESS' });

  const result = db.prepare(
    'INSERT INTO alert_rules (app_slug, metric, operator, threshold, window_minutes, action) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(appSlug || null, metric, operator, String(threshold), windowMinutes || 5, act);

  res.json({ id: result.lastInsertRowid, message: 'Rule created' });
}));

app.put('/api/alerts/rules/:id', asyncRoute((req, res) => {
  const { id } = req.params;
  const { enabled, metric, operator, threshold, windowMinutes, action } = req.body;

  const rule = db.prepare('SELECT * FROM alert_rules WHERE id = ?').get(id);
  if (!rule) return res.status(404).json({ error: 'Rule not found' });

  db.prepare(
    'UPDATE alert_rules SET metric = ?, operator = ?, threshold = ?, window_minutes = ?, action = ?, enabled = ? WHERE id = ?'
  ).run(
    metric || rule.metric,
    operator || rule.operator,
    threshold != null ? String(threshold) : rule.threshold,
    windowMinutes || rule.window_minutes,
    action || rule.action,
    enabled != null ? (enabled ? 1 : 0) : rule.enabled,
    id
  );

  res.json({ message: 'Rule updated' });
}));

app.delete('/api/alerts/rules/:id', asyncRoute((req, res) => {
  const result = db.prepare('DELETE FROM alert_rules WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Rule not found' });
  res.json({ message: 'Rule deleted' });
}));

// --- Scheduled Maintenance Windows ---

app.get('/api/maintenance', asyncRoute((_req, res) => {
  const rows = db.prepare('SELECT * FROM maintenance_windows ORDER BY day_of_week, start_hour, start_minute').all();
  const result = rows.map(w => {
    const appDef = config.apps.find(a => slugify(a.name) === w.app_slug);
    return { ...w, app_name: appDef ? appDef.name : w.app_slug };
  });
  res.json({ windows: result });
}));

app.post('/api/maintenance', asyncRoute((req, res) => {
  const { app_slug, day_of_week, start_hour, start_minute, duration_minutes, suppress_alerts, auto_restart } = req.body;

  if (!app_slug) return res.status(400).json({ error: 'app_slug is required' });
  const day = parseInt(day_of_week, 10);
  const hour = parseInt(start_hour, 10);
  const minute = parseInt(start_minute || 0, 10);
  const duration = parseInt(duration_minutes || 120, 10);

  if (isNaN(day) || day < 0 || day > 6) return res.status(400).json({ error: 'day_of_week must be 0-6 (0=Sunday)' });
  if (isNaN(hour) || hour < 0 || hour > 23) return res.status(400).json({ error: 'start_hour must be 0-23' });
  if (isNaN(minute) || minute < 0 || minute > 59) return res.status(400).json({ error: 'start_minute must be 0-59' });
  if (isNaN(duration) || duration <= 0) return res.status(400).json({ error: 'duration_minutes must be > 0' });

  const result = db.prepare(
    'INSERT INTO maintenance_windows (app_slug, day_of_week, start_hour, start_minute, duration_minutes, suppress_alerts, auto_restart) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(app_slug, day, hour, minute, duration, suppress_alerts ? 1 : 0, auto_restart ? 1 : 0);

  res.json({ id: result.lastInsertRowid, message: 'Maintenance window created' });
}));

app.delete('/api/maintenance/:id', asyncRoute((req, res) => {
  const result = db.prepare('DELETE FROM maintenance_windows WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Maintenance window not found' });
  res.json({ message: 'Maintenance window deleted' });
}));

// Evaluate alert rules against current metrics
async function evaluateAlertRules() {
  const rules = db.prepare('SELECT * FROM alert_rules WHERE enabled = 1').all();
  if (rules.length === 0) return;

  // Gather current values
  const currentValues = {};

  // System metrics
  const sysRow = db.prepare("SELECT * FROM system_snapshots ORDER BY ts DESC LIMIT 1").get();
  if (sysRow) {
    currentValues['cpu'] = sysRow.cpu_percent;
    currentValues['memory_percent'] = sysRow.mem_total_bytes > 0 ? (sysRow.mem_used_bytes / sysRow.mem_total_bytes * 100) : 0;
    currentValues['disk_percent'] = sysRow.disk_total_bytes > 0 ? (sysRow.disk_used_bytes / sysRow.disk_total_bytes * 100) : 0;
    currentValues['load'] = sysRow.load_1m;
  }

  // Per-app MRR
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const row = qLatestMetric.get(slug, 'mrr');
    if (row) currentValues[`${slug}.mrr`] = row.value / 100;
    const pv = qLatestMetric.get(slug, 'pageviews_30d');
    if (pv) currentValues[`${slug}.traffic`] = pv.value;
  }

  for (const rule of rules) {
    // Skip if app is in a scheduled maintenance window
    if (rule.app_slug) {
      const mw = isInMaintenanceWindow(rule.app_slug);
      if (mw.inMaintenance && mw.window.suppress_alerts) {
        console.log(`[ALERTS] Suppressed rule ${rule.id} for ${rule.app_slug} — scheduled maintenance window`);
        continue;
      }
    }

    // Cooldown check
    if (rule.last_fired_at) {
      const lastFired = new Date(rule.last_fired_at + 'Z').getTime();
      if (Date.now() - lastFired < rule.window_minutes * 60 * 1000) continue;
    }

    const metricKey = rule.app_slug ? `${rule.app_slug}.${rule.metric}` : rule.metric;
    const value = currentValues[metricKey];
    if (value == null) continue;

    const threshold = parseFloat(rule.threshold);
    let triggered = false;

    switch (rule.operator) {
      case '>': triggered = value > threshold; break;
      case '<': triggered = value < threshold; break;
      case '>=': triggered = value >= threshold; break;
      case '<=': triggered = value <= threshold; break;
      case '==': triggered = value === threshold; break;
      case '!=': triggered = value !== threshold; break;
      case 'contains': triggered = String(value).includes(rule.threshold); break;
    }

    if (triggered) {
      db.prepare('UPDATE alert_rules SET last_fired_at = datetime(\'now\') WHERE id = ?').run(rule.id);

      const msg = `Alert: ${rule.metric}${rule.app_slug ? ` (${rule.app_slug})` : ''} is ${value} (${rule.operator} ${rule.threshold})`;

      const actionType = rule.action.split(':')[0];
      const actionTarget = rule.action.slice(actionType.length + 1);

      if (actionType === 'telegram') {
        sendTelegram(`🔔 <b>Alert Rule Triggered</b>\n${msg}`);
      } else if (actionType === 'webhook' && actionTarget) {
        fetch(actionTarget, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ alert: msg, metric: rule.metric, value, threshold, app: rule.app_slug, timestamp: new Date().toISOString() }),
          signal: AbortSignal.timeout(TIMEOUT_QUICK),
        }).catch(() => {});
      }
    }
  }
}

// Evaluate alert rules every 5 minutes
cron.schedule('*/5 * * * *', guardedCron('alert-rules', async () => {
  await evaluateAlertRules().catch(err => cronFail('Alert rules evaluation', err));
}));

// --- "What If" Simulator ---

app.post('/api/whatif', asyncRoute(async (req, res) => {
  const { scenario } = req.body;
  if (!scenario) return res.status(400).json({ error: 'scenario is required' });

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(400).json({ error: 'No Anthropic API key configured' });

  // Gather portfolio context
  const appSummaries = [];
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const mrr = qLatestMetric.get(slug, 'mrr')?.value || 0;
    const pv = qLatestMetric.get(slug, 'pageviews_30d')?.value || 0;
    const containers = appDef.containers || [];

    let memMB = 0;
    let cpuPct = 0;
    for (const cName of containers) {
      try {
        const stats = await docker.getContainer(cName).stats({ stream: false });
        memMB += (stats.memory_stats?.usage || 0) / 1e6;
        const cpuDelta = stats.cpu_stats?.cpu_usage?.total_usage - stats.precpu_stats?.cpu_usage?.total_usage;
        const sysDelta = stats.cpu_stats?.system_cpu_usage - stats.precpu_stats?.system_cpu_usage;
        if (sysDelta > 0) cpuPct += (cpuDelta / sysDelta) * 100;
      } catch { /* container may not be running */ }
    }

    appSummaries.push({
      name: appDef.name,
      slug,
      domain: appDef.domain,
      type: appDef.type || 'unknown',
      containers: containers.length,
      mrrEUR: (mrr / 100).toFixed(2),
      monthlyVisitors: pv,
      memoryMB: Math.round(memMB),
      cpuPercent: cpuPct.toFixed(1),
    });
  }

  const sysRow = db.prepare("SELECT * FROM system_snapshots ORDER BY ts DESC LIMIT 1").get();

  const prompt = `You are a portfolio strategist for a solo developer running ${appSummaries.length} apps on one server.

## Current Portfolio
${appSummaries.map(a => `- ${a.name} (${a.domain}): ${a.type}, ${a.mrrEUR} EUR/mo MRR, ${a.monthlyVisitors} visitors/mo, ${a.containers} containers, ${a.memoryMB}MB RAM, ${a.cpuPercent}% CPU`).join('\n')}

## Server Resources
${sysRow ? `CPU: ${sysRow.cpu_percent}%, Memory: ${(sysRow.mem_used_bytes / sysRow.mem_total_bytes * 100).toFixed(1)}% (${(sysRow.mem_used_bytes / 1e9).toFixed(1)}/${(sysRow.mem_total_bytes / 1e9).toFixed(1)} GB), Disk: ${(sysRow.disk_used_bytes / sysRow.disk_total_bytes * 100).toFixed(1)}%` : 'No system data available'}

## Scenario to Analyze
"${scenario}"

Provide a structured analysis:
1. **Impact Summary**: One-sentence verdict
2. **Resource Impact**: CPU, memory, disk changes (with numbers)
3. **Revenue Impact**: What happens to MRR and traffic
4. **Risk Assessment**: What could go wrong
5. **Recommendation**: Do it / Don't do it / Do it with modifications

Be specific with numbers. Reference actual apps and their metrics.`;

  try {
    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      maxTokens: 600,
      timeout: 15000,
      messages: [{ role: 'user', content: prompt }],
    }));

    res.json({
      scenario,
      analysis: ai.text,
      portfolioContext: {
        totalApps: appSummaries.length,
        totalMRR: appSummaries.reduce((s, a) => s + parseFloat(a.mrrEUR), 0).toFixed(2),
        totalContainers: appSummaries.reduce((s, a) => s + a.containers, 0),
      },
      tokens: ai.tokens,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}));

// --- Security Leaderboard ---

app.get('/api/security/leaderboard', asyncRoute((_req, res) => {
  const leaderboard = [];
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const reportCard = calculateAppReportCard(slug);
    if (!reportCard) continue;

    const secDim = reportCard.dimensions?.security || { score: 0, grade: 'N/A' };
    const findings = db.prepare(
      "SELECT severity, COUNT(*) as count FROM security_findings WHERE app_slug = ? AND status != 'dismissed' GROUP BY severity"
    ).all(slug);

    const findingCounts = {};
    for (const f of findings) findingCounts[f.severity] = f.count;

    // Trend: compare with 7 days ago
    const prevScan = db.prepare(
      "SELECT overall_score FROM security_scans WHERE timestamp < datetime('now', '-7 days') ORDER BY timestamp DESC LIMIT 1"
    ).get();

    leaderboard.push({
      name: appDef.name,
      slug,
      domain: appDef.domain,
      score: secDim.score,
      grade: secDim.grade,
      findings: findingCounts,
      totalFindings: findings.reduce((s, f) => s + f.count, 0),
      trend: prevScan ? (secDim.score > prevScan.overall_score ? 'up' : secDim.score < prevScan.overall_score ? 'down' : 'stable') : 'new',
    });
  }

  leaderboard.sort((a, b) => b.score - a.score);

  const avgScore = leaderboard.length > 0 ? Math.round(leaderboard.reduce((s, a) => s + a.score, 0) / leaderboard.length) : 0;

  res.json({
    leaderboard,
    portfolioAvg: avgScore,
    portfolioGrade: avgScore >= 90 ? 'A' : avgScore >= 80 ? 'B' : avgScore >= 70 ? 'C' : avgScore >= 60 ? 'D' : 'F',
    timestamp: new Date().toISOString(),
  });
}));

// --- Time-to-Revenue Tracker ---

app.get('/api/time-to-revenue', asyncRoute((_req, res) => {
  const results = [];

  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);

    // First deploy: earliest Docker event or container creation
    let firstDeploy = null;
    try {
      const row = db.prepare(
        "SELECT MIN(date) as first_date FROM metrics WHERE app_slug = ? AND metric = 'mrr' AND value > 0"
      ).get(slug);
      // Use first metric date as proxy for first activity
      const firstActivity = db.prepare(
        "SELECT MIN(date) as first_date FROM metrics WHERE app_slug = ?"
      ).get(slug);
      firstDeploy = firstActivity?.first_date || null;
    } catch { /* no data */ }

    // First revenue: earliest non-zero MRR
    let firstRevenue = null;
    try {
      const row = db.prepare(
        "SELECT MIN(date) as first_date FROM metrics WHERE app_slug = ? AND metric = 'mrr' AND value > 0"
      ).get(slug);
      firstRevenue = row?.first_date || null;
    } catch { /* no data */ }

    // Current MRR
    const currentMRR = qLatestMetric.get(slug, 'mrr')?.value || 0;

    if (firstDeploy || firstRevenue || currentMRR > 0) {
      let daysToRevenue = null;
      if (firstDeploy && firstRevenue) {
        const d1 = new Date(firstDeploy);
        const d2 = new Date(firstRevenue);
        daysToRevenue = Math.max(0, Math.round((d2 - d1) / (1000 * 60 * 60 * 24)));
      }

      results.push({
        name: appDef.name,
        slug,
        firstDeploy,
        firstRevenue,
        daysToRevenue,
        currentMRR: +(currentMRR / 100).toFixed(2),
        status: currentMRR > 0 ? 'monetized' : firstDeploy ? 'pre-revenue' : 'no-data',
      });
    }
  }

  // Sort: monetized first (by fastest time-to-revenue), then pre-revenue
  results.sort((a, b) => {
    if (a.status === 'monetized' && b.status !== 'monetized') return -1;
    if (b.status === 'monetized' && a.status !== 'monetized') return 1;
    if (a.daysToRevenue != null && b.daysToRevenue != null) return a.daysToRevenue - b.daysToRevenue;
    return 0;
  });

  const avgDays = results.filter(r => r.daysToRevenue != null);
  const avgTimeToRevenue = avgDays.length > 0 ? Math.round(avgDays.reduce((s, r) => s + r.daysToRevenue, 0) / avgDays.length) : null;

  res.json({
    apps: results,
    avgTimeToRevenue,
    monetizedCount: results.filter(r => r.status === 'monetized').length,
    totalApps: results.length,
    timestamp: new Date().toISOString(),
  });
}));

// --- Audit Log API ---

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

// Audit log cleanup — daily, keep 90 days
cron.schedule('0 4 * * *', guardedCron('audit-cleanup', () => {
  try {
    const result = db.prepare("DELETE FROM audit_log WHERE created_at < datetime('now', '-90 days')").run();
    if (result.changes > 0) console.log(`[CRON] Audit log cleanup: removed ${result.changes} entries`);
  } catch (err) { cronFail('Audit cleanup', err); }
}));

// === Feature: Log Aggregation with Smart Search ===

// Track last ingested timestamp per container to avoid duplicate lines
const logIngestionState = new Map(); // container_name -> last_ingested_ts (unix seconds)

const insertLogStmt = db.prepare('INSERT INTO container_logs (container_name, app_slug, stream, line, logged_at) VALUES (?, ?, ?, ?, ?)');
const insertLogBatch = db.transaction((rows) => {
  for (const row of rows) insertLogStmt.run(row.container_name, row.app_slug, row.stream, row.line, row.logged_at);
});

// Ingest logs from all running containers (every 5 minutes)
cron.schedule('*/5 * * * *', guardedCron('log-ingest', async () => {
  try {
    const containers = await docker.listContainers({ filters: { status: ['running'] } });
    let totalIngested = 0;

    for (const c of containers) {
      const name = containerName(c);
      const resolved = resolveContainerApp(name);
      const appSlug = resolved?.slug || null;
      const since = logIngestionState.get(name) || Math.floor((Date.now() - 5 * 60 * 1000) / 1000);

      try {
        const container = docker.getContainer(c.Id);
        const logs = await container.logs({ stdout: true, stderr: true, since, timestamps: true, tail: 500 });
        const raw = logs.toString('utf8');
        if (!raw.trim()) continue;

        const rows = [];
        for (const rawLine of raw.split('\n')) {
          if (!rawLine || rawLine.length < 8) continue;
          // Docker log lines have 8-byte header + optional timestamp
          const line = rawLine.length > 8 ? rawLine.slice(8) : rawLine;
          // Extract timestamp if present (ISO format at start of line)
          const tsMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s/);
          const logged_at = tsMatch ? tsMatch[1] : new Date().toISOString();
          const content = tsMatch ? line.slice(tsMatch[0].length) : line;
          if (!content.trim()) continue;
          rows.push({ container_name: name, app_slug: appSlug, stream: 'mixed', line: content.slice(0, 2000), logged_at });
        }

        if (rows.length > 0) {
          insertLogBatch(rows);
          totalIngested += rows.length;
        }
        logIngestionState.set(name, Math.floor(Date.now() / 1000));
      } catch (err) {
        console.error(`[LOG-INGEST] Failed for ${name}:`, err.message);
      }
    }

    if (totalIngested > 0) console.log(`[LOG-INGEST] Ingested ${totalIngested} lines from ${containers.length} containers`);
  } catch (err) { cronFail('Log ingestion', err); }
}));

// Log cleanup — daily, keep 24 hours
cron.schedule('15 4 * * *', guardedCron('log-cleanup', () => {
  try {
    const result = db.prepare("DELETE FROM container_logs WHERE logged_at < datetime('now', '-24 hours')").run();
    if (result.changes > 0) console.log(`[CRON] Log cleanup: removed ${result.changes} entries`);
  } catch (err) { cronFail('Log cleanup', err); }
}));

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

// === Feature: Guided Troubleshooting ===

const TROUBLESHOOT_FLOWS = {
  'app-not-responding': {
    name: 'App Not Responding',
    steps: [
      { id: 'check-container', label: 'Check container status', auto: true },
      { id: 'check-health', label: 'Check health endpoint', auto: true },
      { id: 'check-logs', label: 'Check recent error logs', auto: true },
      { id: 'check-dns', label: 'Check DNS resolution', auto: true },
      { id: 'check-ssl', label: 'Check SSL certificate', auto: true },
      { id: 'check-nginx', label: 'Check nginx config', auto: false, hint: 'SSH to server and run: sudo nginx -c /home/deploy/nginx-configs/nginx.conf -t' },
    ],
  },
  'high-memory': {
    name: 'High Memory Usage',
    steps: [
      { id: 'check-system', label: 'Check system memory', auto: true },
      { id: 'check-containers', label: 'Find top memory consumers', auto: true },
      { id: 'check-swap', label: 'Check swap usage', auto: true },
      { id: 'check-oom', label: 'Check for OOM kills (last 24h)', auto: true },
      { id: 'suggest-action', label: 'Suggest remediation', auto: true },
    ],
  },
  'high-disk': {
    name: 'Disk Space Issue',
    steps: [
      { id: 'check-disk', label: 'Check disk usage', auto: true },
      { id: 'check-docker', label: 'Check Docker disk usage', auto: true },
      { id: 'check-logs-size', label: 'Check log file sizes', auto: true },
      { id: 'suggest-cleanup', label: 'Suggest cleanup actions', auto: true },
    ],
  },
  'deploy-failed': {
    name: 'Deploy Failed',
    steps: [
      { id: 'check-container', label: 'Check container status', auto: true },
      { id: 'check-logs', label: 'Check container logs for startup errors', auto: true },
      { id: 'check-image', label: 'Check if image exists', auto: true },
      { id: 'check-ports', label: 'Check for port conflicts', auto: true },
    ],
  },
};

// POST /api/troubleshoot — Run guided troubleshooting flow
app.post('/api/troubleshoot', asyncRoute(async (req, res) => {
  const { flow: flowId, appSlug } = req.body;
  if (!flowId || !TROUBLESHOOT_FLOWS[flowId]) {
    return res.status(400).json({ error: 'Invalid flow. Available: ' + Object.keys(TROUBLESHOOT_FLOWS).join(', ') });
  }

  const flow = TROUBLESHOOT_FLOWS[flowId];
  const appDef = appSlug ? findAppBySlug(appSlug) : null;
  const results = [];

  for (const step of flow.steps) {
    if (!step.auto) {
      results.push({ step: step.id, label: step.label, status: 'manual', hint: step.hint || 'Requires manual action' });
      continue;
    }

    const result = { step: step.id, label: step.label, status: 'ok', details: null };

    try {
      switch (step.id) {
        case 'check-container': {
          const containers = await docker.listContainers({ all: true });
          if (appDef) {
            const appContainers = (appDef.containers || []).map(name => {
              const c = containers.find(ct => containerName(ct) === name);
              return { name, state: c?.State || 'not found', status: c?.Status || 'N/A' };
            });
            const down = appContainers.filter(c => c.state !== 'running');
            result.details = appContainers;
            if (down.length > 0) { result.status = 'fail'; result.message = `${down.length} container(s) not running: ${down.map(c => c.name).join(', ')}`; }
            else result.message = `All ${appContainers.length} containers running`;
          } else {
            const running = containers.filter(c => c.State === 'running').length;
            result.details = { total: containers.length, running };
            result.message = `${running}/${containers.length} containers running`;
          }
          break;
        }
        case 'check-health': {
          if (appDef?.domain) {
            const healthPath = appDef.health || '/';
            try {
              const r = await fetch(`https://${appDef.domain}${healthPath}`, { signal: AbortSignal.timeout(10000) });
              result.details = { statusCode: r.status, ok: r.ok };
              if (!r.ok) { result.status = 'fail'; result.message = `Health check returned ${r.status}`; }
              else result.message = `Health check OK (${r.status})`;
            } catch (err) { result.status = 'fail'; result.message = `Cannot reach ${appDef.domain}: ${err.message}`; }
          } else { result.status = 'skip'; result.message = 'No domain configured'; }
          break;
        }
        case 'check-logs': {
          if (appDef?.containers?.length) {
            const containerNameStr = appDef.containers[0];
            const containers = await docker.listContainers({ all: true });
            const target = containers.find(c => containerName(c) === containerNameStr);
            if (target) {
              const container = docker.getContainer(target.Id);
              const logs = await container.logs({ stdout: true, stderr: true, tail: 30, timestamps: true });
              const lines = logs.toString('utf8').split('\n').map(l => l.length > 8 ? l.slice(8) : l).filter(Boolean);
              const errors = lines.filter(l => /error|exception|fatal|panic|failed/i.test(l));
              result.details = { totalLines: lines.length, errorLines: errors.length, lastErrors: errors.slice(-5) };
              if (errors.length > 5) { result.status = 'warn'; result.message = `${errors.length} error lines in last 30 log lines`; }
              else if (errors.length > 0) { result.status = 'warn'; result.message = `${errors.length} error line(s) found`; }
              else result.message = 'No errors in recent logs';
            } else { result.status = 'fail'; result.message = `Container ${containerNameStr} not found`; }
          } else { result.status = 'skip'; result.message = 'No containers configured'; }
          break;
        }
        case 'check-dns': {
          if (appDef?.domain) {
            const { promises: dnsPromises } = await import('dns');
            try {
              const addrs = await dnsPromises.resolve4(appDef.domain);
              const pointsToServer = addrs.includes('91.99.104.132');
              result.details = { addresses: addrs, pointsToServer };
              if (!pointsToServer) { result.status = 'warn'; result.message = `DNS resolves to ${addrs.join(', ')} (expected 91.99.104.132)`; }
              else result.message = `DNS OK: ${addrs.join(', ')}`;
            } catch { result.status = 'fail'; result.message = `DNS lookup failed for ${appDef.domain}`; }
          } else { result.status = 'skip'; result.message = 'No domain configured'; }
          break;
        }
        case 'check-ssl': {
          if (appDef?.domain) {
            try {
              const r = await fetch(`https://${appDef.domain}/`, { method: 'HEAD', signal: AbortSignal.timeout(10000) });
              result.message = 'SSL connection successful';
            } catch (err) {
              if (err.message.includes('certificate') || err.message.includes('SSL')) {
                result.status = 'fail'; result.message = `SSL error: ${err.message}`;
              } else { result.message = 'SSL OK (connection issue may be non-SSL related)'; }
            }
          } else { result.status = 'skip'; result.message = 'No domain configured'; }
          break;
        }
        case 'check-system': {
          try {
            const memInfo = readFileSync('/proc/meminfo', 'utf8');
            const memTotal = parseInt(memInfo.match(/MemTotal:\s+(\d+)/)?.[1] || '0') * 1024;
            const memAvail = parseInt(memInfo.match(/MemAvailable:\s+(\d+)/)?.[1] || '0') * 1024;
            const memPct = Math.round(((memTotal - memAvail) / memTotal) * 100);
            result.details = { memPct, memTotalGB: (memTotal / 1e9).toFixed(1), memAvailGB: (memAvail / 1e9).toFixed(1) };
            if (memPct > 90) { result.status = 'fail'; result.message = `Memory at ${memPct}% — critical`; }
            else if (memPct > 80) { result.status = 'warn'; result.message = `Memory at ${memPct}% — high`; }
            else result.message = `Memory at ${memPct}%`;
          } catch { result.status = 'skip'; result.message = 'Cannot read memory info'; }
          break;
        }
        case 'check-containers': {
          try {
            const containers = await docker.listContainers();
            const statsPromises = containers.slice(0, 15).map(async c => {
              try {
                const stats = await docker.getContainer(c.Id).stats({ stream: false });
                return { name: containerName(c), memMB: Math.round((stats.memory_stats.usage || 0) / 1024 / 1024) };
              } catch { return { name: containerName(c), memMB: 0 }; }
            });
            const stats = await Promise.all(statsPromises);
            stats.sort((a, b) => b.memMB - a.memMB);
            result.details = stats.slice(0, 10);
            result.message = `Top consumer: ${stats[0]?.name} (${stats[0]?.memMB} MB)`;
          } catch { result.status = 'skip'; result.message = 'Cannot collect container stats'; }
          break;
        }
        case 'check-swap': {
          try {
            const memInfo = readFileSync('/proc/meminfo', 'utf8');
            const swapTotal = parseInt(memInfo.match(/SwapTotal:\s+(\d+)/)?.[1] || '0') * 1024;
            const swapFree = parseInt(memInfo.match(/SwapFree:\s+(\d+)/)?.[1] || '0') * 1024;
            const swapPct = swapTotal > 0 ? Math.round(((swapTotal - swapFree) / swapTotal) * 100) : 0;
            result.details = { swapPct, swapTotalMB: Math.round(swapTotal / 1e6), swapUsedMB: Math.round((swapTotal - swapFree) / 1e6) };
            if (swapPct > 90) { result.status = 'warn'; result.message = `Swap at ${swapPct}% — system under memory pressure`; }
            else result.message = `Swap at ${swapPct}%`;
          } catch { result.status = 'skip'; result.message = 'Cannot read swap info'; }
          break;
        }
        case 'check-oom': {
          try {
            const since = Math.floor((Date.now() - 86400000) / 1000);
            const events = await docker.getEvents({ since, until: Math.floor(Date.now() / 1000), filters: { event: ['oom'] } });
            const chunks = [];
            await new Promise((resolve) => {
              events.on('data', (chunk) => chunks.push(chunk));
              setTimeout(() => { events.destroy(); resolve(); }, 2000);
            });
            const oomCount = chunks.join('').split('\n').filter(Boolean).length;
            result.details = { oomKills: oomCount };
            if (oomCount > 0) { result.status = 'fail'; result.message = `${oomCount} OOM kill(s) in last 24 hours`; }
            else result.message = 'No OOM kills in last 24 hours';
          } catch { result.status = 'skip'; result.message = 'Cannot query Docker events'; }
          break;
        }
        case 'suggest-action':
        case 'suggest-cleanup': {
          const prevResults = results.filter(r => r.status === 'fail' || r.status === 'warn');
          if (prevResults.length === 0) { result.message = 'No issues found — system looks healthy'; }
          else {
            const suggestions = prevResults.map(r => {
              if (r.step === 'check-oom') return 'Consider increasing container memory limits or adding swap';
              if (r.step === 'check-swap') return 'Free memory by stopping unused containers or upgrading VM';
              if (r.step === 'check-system') return 'Identify and restart memory-heavy containers, or add swap';
              if (r.step === 'check-disk' || r.step === 'check-docker') return 'Run docker system prune or clean old images/logs';
              return `Fix: ${r.message}`;
            });
            result.message = suggestions.join('; ');
            result.details = suggestions;
          }
          break;
        }
        case 'check-disk': {
          try {
            const parts = getDiskParts();
            const usedPct = parseInt(parts[4]);
            const usedGB = Math.round(parseInt(parts[2]) / 1e9);
            const totalGB = Math.round(parseInt(parts[1]) / 1e9);
            result.details = { usedPct, usedGB, totalGB };
            if (usedPct > 90) { result.status = 'fail'; result.message = `Disk at ${usedPct}% (${usedGB}/${totalGB} GB)`; }
            else if (usedPct > 80) { result.status = 'warn'; result.message = `Disk at ${usedPct}%`; }
            else result.message = `Disk at ${usedPct}% (${usedGB}/${totalGB} GB)`;
          } catch { result.status = 'skip'; result.message = 'Cannot read disk info'; }
          break;
        }
        case 'check-docker': {
          try {
            const info = await docker.info();
            result.details = { images: info.Images, containers: info.Containers };
            result.message = `${info.Images} images, ${info.Containers} containers`;
          } catch { result.status = 'skip'; result.message = 'Cannot query Docker'; }
          break;
        }
        case 'check-logs-size': {
          try {
            const output = execSync("du -sh /var/log/nginx/ 2>/dev/null || echo 'N/A'", { timeout: TIMEOUT_STANDARD }).toString().trim();
            result.details = { nginxLogs: output.split('\t')[0] };
            result.message = `Nginx logs: ${output.split('\t')[0]}`;
          } catch { result.status = 'skip'; result.message = 'Cannot check log sizes'; }
          break;
        }
        case 'check-image': {
          if (appDef?.containers?.length) {
            const containers = await docker.listContainers({ all: true });
            const target = containers.find(c => containerName(c) === appDef.containers[0]);
            if (target) {
              result.details = { image: target.Image, state: target.State };
              result.message = `Image: ${target.Image} (${target.State})`;
            } else { result.status = 'fail'; result.message = 'Container not found — image may not be built'; }
          } else { result.status = 'skip'; result.message = 'No containers configured'; }
          break;
        }
        case 'check-ports': {
          if (appDef?.port) {
            const containers = await docker.listContainers();
            const portUsers = containers.filter(c => c.Ports?.some(p => p.PublicPort === Number(appDef.port)));
            result.details = { port: appDef.port, usedBy: portUsers.map(c => containerName(c)) };
            if (portUsers.length > 1) { result.status = 'warn'; result.message = `Port ${appDef.port} used by ${portUsers.length} containers`; }
            else result.message = `Port ${appDef.port} OK`;
          } else { result.status = 'skip'; result.message = 'No port configured'; }
          break;
        }
        default:
          result.status = 'skip';
          result.message = 'Unknown check';
      }
    } catch (err) {
      result.status = 'error';
      result.message = err.message;
    }

    results.push(result);
  }

  // Overall verdict
  const failures = results.filter(r => r.status === 'fail');
  const warnings = results.filter(r => r.status === 'warn');
  const verdict = failures.length > 0 ? 'issues-found' : warnings.length > 0 ? 'warnings' : 'healthy';

  auditLog(req, 'troubleshoot', flowId, { appSlug, verdict });
  res.json({ flow: flowId, flowName: flow.name, app: appDef?.name || null, results, verdict, timestamp: new Date().toISOString() });
}));

// GET /api/troubleshoot/flows — List available troubleshooting flows
app.get('/api/troubleshoot/flows', (_req, res) => {
  const flows = Object.entries(TROUBLESHOOT_FLOWS).map(([id, flow]) => ({
    id, name: flow.name, stepCount: flow.steps.length,
  }));
  res.json({ flows });
});

// === Feature: Launch Day Dashboard ===

let launchMode = null; // { slug, appName, startedAt, intervalId }

// POST /api/launch/start — Activate launch mode for an app
app.post('/api/launch/start', asyncRoute(async (req, res) => {
  const { slug } = req.body;
  if (!slug) return res.status(400).json({ error: 'slug is required' });
  const appDef = findAppBySlug(slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });

  // Stop existing launch mode if active
  if (launchMode?.intervalId) clearInterval(launchMode.intervalId);

  launchMode = { slug, appName: appDef.name, startedAt: new Date().toISOString(), stats: [] };
  auditLog(req, 'launch.start', slug);

  // Send Telegram notification
  sendTelegram(`🚀 <b>Launch Mode Activated!</b>\n${appDef.name} (${appDef.domain || slug})\nMonitoring every 30 seconds.`);

  // Collect stats every 30 seconds during launch mode
  launchMode.intervalId = setInterval(async () => {
    if (!launchMode || launchMode.slug !== slug) return;
    try {
      const snapshot = { ts: new Date().toISOString() };

      // Container health
      const containers = await docker.listContainers({ all: true });
      const appContainers = (appDef.containers || []).map(name => {
        const c = containers.find(ct => containerName(ct) === name);
        return { name, state: c?.State || 'not found' };
      });
      snapshot.containers = appContainers;
      snapshot.allHealthy = appContainers.every(c => c.state === 'running');

      // Traffic (from analytics if available)
      const recentVisits = db.prepare("SELECT COUNT(*) as count FROM page_views WHERE app_slug = ? AND created_at >= datetime('now', '-5 minutes')").get(slug);
      snapshot.visitors5m = recentVisits?.count || 0;

      // Revenue (from cached data)
      if (cachedRevenue?.apps) {
        const appRev = Object.entries(cachedRevenue.apps).find(([name]) => slugify(name) === slug);
        if (appRev) snapshot.revenue = { mrr: (appRev[1].mrr / 100).toFixed(2), charges30d: appRev[1].chargeCount30d };
      }

      // System load
      try {
        const loadLine = readFileSync('/proc/loadavg', 'utf8').trim().split(' ');
        snapshot.load = parseFloat(loadLine[0]);
      } catch { snapshot.load = null; }

      launchMode.stats.push(snapshot);
      if (launchMode.stats.length > 600) launchMode.stats.shift(); // Keep last 5 hours (600 * 30s)

      // Alert if container goes down
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

// POST /api/launch/stop — Deactivate launch mode
app.post('/api/launch/stop', asyncRoute(async (req, res) => {
  if (!launchMode) return res.json({ ok: true, message: 'Launch mode was not active' });
  const duration = Math.round((Date.now() - new Date(launchMode.startedAt).getTime()) / 60000);
  sendTelegram(`🏁 <b>Launch Mode Ended</b>\n${launchMode.appName}\nDuration: ${duration} minutes\nSnapshots collected: ${launchMode.stats.length}`);
  if (launchMode.intervalId) clearInterval(launchMode.intervalId);
  auditLog(req, 'launch.stop', launchMode.slug);
  launchMode = null;
  res.json({ ok: true });
}));

// GET /api/launch/status — Get current launch mode status and stats
app.get('/api/launch/status', asyncRoute(async (req, res) => {
  if (!launchMode) return res.json({ active: false });

  const appDef = findAppBySlug(launchMode.slug);
  const duration = Math.round((Date.now() - new Date(launchMode.startedAt).getTime()) / 60000);
  const recentStats = launchMode.stats.slice(-20); // Last 10 minutes

  // Aggregate stats
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

// === Feature: INWX DNS Management ===

// INWX JSON-RPC API helper (session-based auth via cookies)
async function inwxCall(method, params = {}, sessionCookie = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (sessionCookie) headers['Cookie'] = sessionCookie;
  const res = await fetch('https://api.domrobot.com/jsonrpc/', {
    method: 'POST',
    headers,
    body: JSON.stringify({ method, params }),
    signal: AbortSignal.timeout(TIMEOUT_MEDIUM),
  });
  const setCookie = res.headers.get('set-cookie');
  const data = await res.json();
  if (data.code !== 1000) {
    throw new Error(`INWX API error (${data.code}): ${data.msg || 'Unknown error'}`);
  }
  return { data: data.resData, cookie: setCookie || sessionCookie };
}

async function inwxSession() {
  const user = getSetting('inwx_user');
  const pass = getSetting('inwx_pass');
  if (!user || !pass) throw new Error('INWX credentials not configured. Set inwx_user and inwx_pass in Settings.');
  const result = await inwxCall('account.login', { user, pass });
  return result.cookie;
}

// GET /api/dns/records — List DNS records for a domain
app.get('/api/dns/records', asyncRoute(async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });

  let cookie;
  try {
    cookie = await inwxSession();
    const result = await inwxCall('nameserver.info', { domain }, cookie);
    const records = (result.data?.record || []).map(r => ({
      id: r.id, name: r.name, type: r.type, content: r.content,
      ttl: r.ttl, prio: r.prio || null,
    }));
    res.json({ domain, records, count: records.length });
  } catch (err) {
    res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
  } finally {
    if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
  }
}));

// POST /api/dns/records — Create a DNS record
app.post('/api/dns/records', asyncRoute(async (req, res) => {
  const { domain, type, name, content, ttl, prio } = req.body;
  if (!domain || !type || !name || !content) {
    return res.status(400).json({ error: 'domain, type, name, and content are required' });
  }
  const ALLOWED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'];
  if (!ALLOWED_TYPES.includes(type.toUpperCase())) {
    return res.status(400).json({ error: `Invalid record type. Allowed: ${ALLOWED_TYPES.join(', ')}` });
  }

  let cookie;
  try {
    cookie = await inwxSession();
    const params = { domain, type: type.toUpperCase(), name, content, ttl: ttl || 3600 };
    if (prio !== undefined && prio !== null) params.prio = Number(prio);
    const result = await inwxCall('nameserver.createRecord', params, cookie);
    auditLog(req, 'dns.create', domain, { type, name, content });
    res.json({ ok: true, id: result.data?.id });
  } catch (err) {
    res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
  } finally {
    if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
  }
}));

// PUT /api/dns/records/:id — Update a DNS record
app.put('/api/dns/records/:id', asyncRoute(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid record ID' });
  const { content, ttl, prio } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });

  let cookie;
  try {
    cookie = await inwxSession();
    const params = { id, content };
    if (ttl) params.ttl = ttl;
    if (prio !== undefined && prio !== null) params.prio = Number(prio);
    await inwxCall('nameserver.updateRecord', params, cookie);
    auditLog(req, 'dns.update', String(id), { content });
    res.json({ ok: true });
  } catch (err) {
    res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
  } finally {
    if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
  }
}));

// DELETE /api/dns/records/:id — Delete a DNS record
app.delete('/api/dns/records/:id', asyncRoute(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid record ID' });

  let cookie;
  try {
    cookie = await inwxSession();
    await inwxCall('nameserver.deleteRecord', { id }, cookie);
    auditLog(req, 'dns.delete', String(id));
    res.json({ ok: true });
  } catch (err) {
    res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
  } finally {
    if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
  }
}));

// GET /api/dns/validate — Validate DNS for all configured domains
app.get('/api/dns/validate', asyncRoute(async (req, res) => {
  const { promises: dnsPromises } = await import('dns');
  const domains = (config.apps || []).filter(a => a.domain).map(a => ({ domain: a.domain, slug: slugify(a.name) }));
  const results = [];

  for (const { domain, slug } of domains) {
    const checks = { domain, slug, a: null, www: null, reachable: null };
    try {
      const addrs = await dnsPromises.resolve4(domain);
      checks.a = { ok: addrs.includes('91.99.104.132'), addresses: addrs };
    } catch { checks.a = { ok: false, addresses: [] }; }
    try {
      const cname = await dnsPromises.resolveCname(`www.${domain}`);
      checks.www = { ok: true, target: cname[0] };
    } catch {
      try {
        const addrs = await dnsPromises.resolve4(`www.${domain}`);
        checks.www = { ok: addrs.includes('91.99.104.132'), addresses: addrs };
      } catch { checks.www = { ok: false }; }
    }
    checks.reachable = checks.a?.ok || false;
    results.push(checks);
  }

  res.json({ results, server_ip: '91.99.104.132' });
}));

// --- Achievement System ---

const ACHIEVEMENTS = [
  { id: 'first-deploy', name: 'First Deploy', desc: 'Deploy an app for the first time', icon: '🚀', check: () => db.prepare("SELECT COUNT(*) as c FROM healing_log WHERE action_taken LIKE '%restart%'").get().c > 0 },
  { id: 'security-hawk', name: 'Security Hawk', desc: 'Security score > 90 for any app', icon: '🛡️', check: () => {
    for (const appDef of config.apps) { const rc = calculateAppReportCard(slugify(appDef.name)); if (rc?.dimensions?.security?.score > 90) return true; } return false;
  }},
  { id: 'revenue-10', name: 'First Tenner', desc: 'Reach 10 EUR MRR on any app', icon: '💰', check: () => {
    for (const appDef of config.apps) { const r = qLatestMetric.get(slugify(appDef.name), 'mrr'); if (r?.value >= 1000) return true; } return false;
  }},
  { id: 'revenue-100', name: 'Triple Digits', desc: 'Reach 100 EUR MRR on any app', icon: '💎', check: () => {
    for (const appDef of config.apps) { const r = qLatestMetric.get(slugify(appDef.name), 'mrr'); if (r?.value >= 10000) return true; } return false;
  }},
  { id: 'revenue-1000', name: 'Four Figures', desc: 'Reach 1,000 EUR MRR portfolio-wide', icon: '👑', check: () => {
    let total = 0; for (const appDef of config.apps) { const r = qLatestMetric.get(slugify(appDef.name), 'mrr'); total += r?.value || 0; } return total >= 100000;
  }},
  { id: 'uptime-7', name: 'Steady Ship', desc: '7-day uptime streak on any app', icon: '🔥', check: () => {
    const row = db.prepare("SELECT MAX(streak_days) as m FROM (SELECT app_slug, COUNT(*) as streak_days FROM uptime_history WHERE status = 'up' GROUP BY app_slug)").get();
    return (row?.m || 0) >= 7;
  }},
  { id: 'uptime-30', name: 'Iron Uptime', desc: '30-day uptime streak', icon: '⚡', check: () => {
    const row = db.prepare("SELECT MAX(streak_days) as m FROM (SELECT app_slug, COUNT(*) as streak_days FROM uptime_history WHERE status = 'up' GROUP BY app_slug)").get();
    return (row?.m || 0) >= 30;
  }},
  { id: 'portfolio-5', name: 'Portfolio Builder', desc: 'Run 5+ apps', icon: '📦', check: () => config.apps.length >= 5 },
  { id: 'portfolio-10', name: 'App Empire', desc: 'Run 10+ apps', icon: '🏰', check: () => config.apps.length >= 10 },
  { id: 'healer', name: 'Self-Healer', desc: 'Auto-healing has fixed 10+ issues', icon: '🔧', check: () => db.prepare("SELECT COUNT(*) as c FROM healing_log WHERE result = 'executed'").get().c >= 10 },
  { id: 'night-owl', name: 'Night Owl', desc: 'Activity logged between midnight and 5 AM', icon: '🦉', check: () => db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE CAST(strftime('%H', created_at) AS INTEGER) < 5").get().c > 0 },
  { id: 'clean-sweep', name: 'Clean Sweep', desc: 'All apps have security grade A or B', icon: '✨', check: () => {
    for (const appDef of config.apps) { const rc = calculateAppReportCard(slugify(appDef.name)); if (!rc?.dimensions?.security || rc.dimensions.security.score < 80) return false; } return config.apps.length > 0;
  }},
];

app.get('/api/achievements', asyncRoute((_req, res) => {
  const unlocked = [];
  const locked = [];

  for (const ach of ACHIEVEMENTS) {
    try {
      const earned = ach.check();
      const stored = getSetting(`achievement_${ach.id}`);
      if (earned && !stored) {
        setSetting(`achievement_${ach.id}`, new Date().toISOString());
      }
      const unlockedAt = stored || (earned ? new Date().toISOString() : null);
      if (unlockedAt) {
        unlocked.push({ ...ach, check: undefined, unlockedAt });
      } else {
        locked.push({ id: ach.id, name: ach.name, desc: ach.desc, icon: ach.icon });
      }
    } catch {
      locked.push({ id: ach.id, name: ach.name, desc: ach.desc, icon: ach.icon });
    }
  }

  res.json({
    unlocked,
    locked,
    total: ACHIEVEMENTS.length,
    earned: unlocked.length,
    timestamp: new Date().toISOString(),
  });
}));

// --- Build in Public Generator ---

app.get('/api/build-in-public', asyncRoute(async (_req, res) => {
  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(400).json({ error: 'No Anthropic API key configured' });

  // Gather this week's activity
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const healingEvents = db.prepare("SELECT COUNT(*) as c FROM healing_log WHERE timestamp > ?").get(weekAgo).c;
  const auditEvents = db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE created_at > ?").get(weekAgo).c;
  const securityFindings = db.prepare("SELECT COUNT(*) as c FROM security_findings WHERE created_at > ?").get(weekAgo).c;

  // Revenue data
  const appMetrics = [];
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const mrr = qLatestMetric.get(slug, 'mrr')?.value || 0;
    const pv = qLatestMetric.get(slug, 'pageviews_30d')?.value || 0;
    if (mrr > 0 || pv > 100) {
      appMetrics.push({ name: appDef.name, mrrEUR: (mrr / 100).toFixed(2), visitors: pv });
    }
  }

  const totalMRR = appMetrics.reduce((s, a) => s + parseFloat(a.mrrEUR), 0).toFixed(2);

  const prompt = `Generate a short "build in public" update for a solo developer running ${config.apps.length} apps. Make it authentic, casual, and engaging for Twitter/X (max 280 chars for the main tweet, then 2-3 reply tweets for details).

This week's stats:
- Total MRR: ${totalMRR} EUR
- Apps with traction: ${appMetrics.map(a => `${a.name}: ${a.mrrEUR} EUR MRR, ${a.visitors} visitors`).join('; ') || 'None yet'}
- Infrastructure events: ${healingEvents} auto-healing, ${auditEvents} config changes, ${securityFindings} security findings fixed
- Portfolio: ${config.apps.length} apps on one server

Format as JSON array of tweet strings. Be genuine, share real numbers, mention specific apps. No hashtag spam (1-2 max).`;

  try {
    const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      maxTokens: 400,
      timeout: 15000,
      messages: [{ role: 'user', content: prompt }],
    }));

    let tweets = [];
    try { tweets = JSON.parse(ai.text); } catch { tweets = [ai.text]; }

    res.json({
      tweets,
      stats: { totalMRR, appsWithRevenue: appMetrics.length, totalApps: config.apps.length, healingEvents, auditEvents },
      tokens: ai.tokens,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}));

// ========== GITHUB DEEP INTEGRATION ==========

function parseGitHubRepo(repoField) {
  if (!repoField) return null;
  // Handle full URLs: https://github.com/owner/repo or git@github.com:owner/repo
  const urlMatch = repoField.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  if (urlMatch) return `${urlMatch[1]}/${urlMatch[2]}`;
  // Handle owner/repo format
  if (/^[\w.-]+\/[\w.-]+$/.test(repoField)) return repoField;
  return null;
}

async function fetchGitHubData(ownerRepo, token) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'Dockfolio' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const ghFetch = (url) => fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) }).then(r => {
    if (!r.ok) throw new Error(`GitHub API ${r.status}: ${r.statusText}`);
    return r.json();
  });

  const [repoInfo, commits, pulls, actionsRuns] = await Promise.allSettled([
    ghFetch(`https://api.github.com/repos/${ownerRepo}`),
    ghFetch(`https://api.github.com/repos/${ownerRepo}/commits?per_page=5`),
    ghFetch(`https://api.github.com/repos/${ownerRepo}/pulls?state=open&per_page=100`),
    ghFetch(`https://api.github.com/repos/${ownerRepo}/actions/runs?per_page=1`),
  ]);

  return {
    repo: ownerRepo,
    openIssues: repoInfo.status === 'fulfilled' ? (repoInfo.value.open_issues_count || 0) : null,
    defaultBranch: repoInfo.status === 'fulfilled' ? repoInfo.value.default_branch : 'main',
    stars: repoInfo.status === 'fulfilled' ? repoInfo.value.stargazers_count : null,
    commits: commits.status === 'fulfilled' ? commits.value.map(c => ({
      sha: c.sha?.slice(0, 7),
      message: c.commit?.message?.split('\n')[0]?.slice(0, 80),
      author: c.commit?.author?.name,
      date: c.commit?.author?.date,
    })) : [],
    openPRs: pulls.status === 'fulfilled' ? pulls.value.length : null,
    ci: actionsRuns.status === 'fulfilled' && actionsRuns.value.workflow_runs?.length > 0 ? {
      status: actionsRuns.value.workflow_runs[0].status,
      conclusion: actionsRuns.value.workflow_runs[0].conclusion,
      name: actionsRuns.value.workflow_runs[0].name,
      updated: actionsRuns.value.workflow_runs[0].updated_at,
    } : null,
  };
}

const ghCacheGet = db.prepare('SELECT data_json, fetched_at FROM github_cache WHERE app_slug = ?');
const ghCacheUpsert = db.prepare('INSERT OR REPLACE INTO github_cache (app_slug, data_json, fetched_at) VALUES (?, ?, datetime(\'now\'))');

async function getGitHubForApp(slug, repoField, token) {
  // Check cache (5 min TTL)
  const cached = ghCacheGet.get(slug);
  if (cached) {
    const age = Date.now() - new Date(cached.fetched_at + 'Z').getTime();
    if (age < 5 * 60 * 1000) return JSON.parse(cached.data_json);
  }

  const ownerRepo = parseGitHubRepo(repoField);
  if (!ownerRepo) return null;

  const data = await cbGitHub.call(() => fetchGitHubData(ownerRepo, token));
  ghCacheUpsert.run(slug, JSON.stringify(data));
  return data;
}

app.get('/api/github/summary', asyncRoute(async (_req, res) => {
  const token = getSetting('GITHUB_TOKEN') || process.env.GITHUB_TOKEN;
  const results = [];

  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    const ghRepo = parseGitHubRepo(appDef.repo);
    if (!ghRepo) continue;

    try {
      const data = await getGitHubForApp(slug, appDef.repo, token);
      if (data) results.push({ slug, name: appDef.name, ...data });
    } catch (err) {
      // Return cached data on error, or partial result
      const cached = ghCacheGet.get(slug);
      if (cached) {
        results.push({ slug, name: appDef.name, ...JSON.parse(cached.data_json), stale: true });
      } else {
        results.push({ slug, name: appDef.name, repo: ghRepo, error: err.message });
      }
    }
  }

  res.json({ apps: results, hasToken: !!token, timestamp: new Date().toISOString() });
}));

app.get('/api/github/app/:slug', asyncRoute(async (req, res) => {
  const token = getSetting('GITHUB_TOKEN') || process.env.GITHUB_TOKEN;
  const appDef = config.apps.find(a => slugify(a.name) === req.params.slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });

  const ghRepo = parseGitHubRepo(appDef.repo);
  if (!ghRepo) return res.status(404).json({ error: 'No GitHub repo configured for this app' });

  try {
    const data = await getGitHubForApp(req.params.slug, appDef.repo, token);
    res.json({ slug: req.params.slug, name: appDef.name, ...data, hasToken: !!token });
  } catch (err) {
    const cached = ghCacheGet.get(req.params.slug);
    if (cached) {
      res.json({ slug: req.params.slug, name: appDef.name, ...JSON.parse(cached.data_json), stale: true, hasToken: !!token });
    } else {
      res.status(502).json({ error: err.message });
    }
  }
}));

// Health check endpoint
app.get('/health', (_req, res) => res.send('ok'));

const port = process.env.PORT || 3000;
const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Dashboard API running on port ${port}`);
});

// --- Graceful Shutdown ---
function gracefulShutdown(signal) {
  console.log(`[SHUTDOWN] ${signal} received, shutting down gracefully...`);
  if (eventStream) try { eventStream.destroy(); } catch (e) { console.error('[SHUTDOWN] Event stream destroy error:', e.message); }
  server.close(() => {
    console.log('[SHUTDOWN] HTTP server closed');
    try { db.close(); } catch (e) { console.error('[SHUTDOWN] data.db close error:', e.message); }
    try { authDb.close(); } catch (e) { console.error('[SHUTDOWN] auth.db close error:', e.message); }
    console.log('[SHUTDOWN] Databases closed. Exiting.');
    process.exit(0);
  });
  setTimeout(() => { console.error('[SHUTDOWN] Forceful shutdown after 10s timeout'); process.exit(1); }, TIMEOUT_SHUTDOWN);
}
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
