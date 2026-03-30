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
  parseId, asyncRoute, errorFingerprint, errorScore, rateLimit,
  isBot, callAnthropic, htmlEscape, assertSafeDomain, assertSafeUrl
} from './utils.js';
import registerDnsRoutes from './routes/dns.js';
import registerHetznerRoutes from './routes/hetzner.js';
import registerLaunchRoutes from './routes/launch.js';
import registerTroubleshootRoutes from './routes/troubleshoot.js';
import registerUptimeRoutes from './routes/uptime.js';
import registerGitHubRoutes from './routes/github.js';
import registerDockerRoutes from './routes/docker.js';
import registerMarketingRoutes from './routes/marketing.js';
import registerErrorRoutes from './routes/errors.js';
import registerOpsRoutes from './routes/ops.js';
import registerProjectsRoutes from './routes/projects.js';
import registerSecurityRoutes from './routes/security.js';
import registerConfigRoutes from './routes/config.js';
import registerAIRoutes from './routes/ai.js';
import registerLogRoutes from './routes/logs.js';
import registerExportRoutes from './routes/export.js';
import registerAnalyticsRoutes from './routes/analytics.js';
import registerStripeRoutes from './routes/stripe.js';
import registerAlertRoutes from './routes/alerts.js';
import registerStatusRoutes from './routes/status.js';
import registerSnapshotRoutes from './routes/snapshots.js';
import registerPortfolioRoutes from './routes/portfolio.js';
import registerMiscRoutes from './routes/misc.js';

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
const _intervals = [];
_intervals.push(setInterval(() => { eventLoopHistogram.reset(); }, 5 * 60_000));

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
  return (config.apps || []).filter(a => a.domain && a.type !== 'redirect' && !/^\d+\.\d+\.\d+\.\d+$/.test(a.domain)).map(a => ({ domain: a.domain, slug: slugify(a.name) }));
}

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
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  next(err);
});
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
_intervals.push(setInterval(cleanExpiredSessions, MS_PER_HOUR));

const SESSION_TTL_DAYS = 7;

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
const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/setup', '/api/auth/status', '/health', '/api/health', '/api/crosspromo', '/api/banners/embed.js', '/api/banners/serve', '/api/errors/ingest', '/api/errors/envelope', '/api/errors/sdk.js', '/api/status', '/status', '/api/status-page', '/api/analytics/pixel.gif', '/api/analytics/track.js', '/api/analytics/event', '/api/webhooks'];

function authMiddleware(req, res, next) {
  // Normalize path to prevent traversal bypass (e.g. /api/crosspromo/../marketing/crosspromo)
  const normalizedPath = req.path.replace(/\/\.\.+/g, '').replace(/\/+/g, '/');
  // Allow public paths
  if (PUBLIC_PATHS.some(p => normalizedPath === p || normalizedPath.startsWith(p + '/'))) return next();
  // Allow public banner tracking endpoints: /api/banners/:id/view, /api/banners/:id/click
  if (/^\/api\/banners\/\d+\/(view|click)$/.test(normalizedPath)) return next();
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
_intervals.push(setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now > entry.resetAt) loginAttempts.delete(ip);
  }
}, 30 * 60_000));

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
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
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

// Docker/container routes extracted to routes/docker.js
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

// GET /api/uptime — moved to routes/uptime.js

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
    .filter(a => a.domain && a.type !== 'redirect' && !/^\d+\.\d+\.\d+\.\d+$/.test(a.domain))
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

// GET /api/uptime/timeline — moved to routes/uptime.js

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
function getPlausibleUrl() { return getSetting('PLAUSIBLE_URL') || process.env.PLAUSIBLE_URL || 'http://plausible-plausible-1:8000'; }
function getPlausibleApiKey() { return getSetting('PLAUSIBLE_API_KEY') || process.env.PLAUSIBLE_API_KEY || ''; }

// Snapshot container CPU/memory metrics every hour (for sparklines)
cron.schedule('5 * * * *', guardedCron('container-metrics', async () => {
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
    const results = await Promise.allSettled(containers.map(async c => {
      const name = c.Names?.[0]?.replace(/^\//, '') || c.Id.slice(0, 12);
      const s = await docker.getContainer(c.Id).stats({ stream: false });
      return { name, s };
    }));
    for (const r of results) {
      if (r.status !== 'fulfilled') continue;
      const { name, s } = r.value;
      const cpuDelta = s.cpu_stats.cpu_usage.total_usage - s.precpu_stats.cpu_usage.total_usage;
      const systemDelta = s.cpu_stats.system_cpu_usage - s.precpu_stats.system_cpu_usage;
      const cpuCount = s.cpu_stats.online_cpus || 1;
      const cpu = systemDelta > 0 ? Math.round((cpuDelta / systemDelta) * cpuCount * 10000) / 100 : 0;
      const memory = s.memory_stats.usage || 0;
      insertMetric.run(name, appMap[name] || null, cpu, memory);
      count++;
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
}));

// Playground routes — extracted to routes/misc.js

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
      })).filter(c => !c.name.includes('dockfolio') && !c.name.includes('whisper') && !c.name.includes('demucs'));
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
      })).filter(c => !c.name.includes('dockfolio') && !c.name.includes('whisper') && !c.name.includes('demucs'));
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
      let buildFreed = 0;
      try {
        const buildOutput = execSync('docker builder prune -f 2>&1', { timeout: TIMEOUT_HEAVY }).toString();
        const match = buildOutput.match(/Total reclaimed space:\s*([\d.]+\s*[kMGT]?B)/i);
        if (match) buildFreed = match[1];
      } catch { /* builder prune may not be available */ }
      const freed = (pruneResult.SpaceReclaimed || 0) + (imgResult.SpaceReclaimed || 0);
      return `Docker pruned, freed ${Math.round(freed / 1e6)}MB${buildFreed ? ` + ${buildFreed} build cache` : ''}`;
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
          if (!tracked.has(name) || name.includes('dockfolio') || name.includes('whisper') || name.includes('demucs')) return false;
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


// Snapshots, deploys — extracted to routes/snapshots.js




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
let onContainerDeploy = null; // assigned after snapshot module registration

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
            } catch (e) { if (!e.message?.includes('409')) console.error('[ERROR_WATCH] Failed to fetch dying container logs:', e.message); }
            ingestError({ app: appSlug, message: `Container ${name} died with exit code ${exitCode}`, stack: lastLogs || null, severity: 'critical', source: 'docker_event', container: name });
          }
        } else if (event.Action === 'health_status: unhealthy') {
          ingestError({ app: appSlug, message: `Container ${name} health check failed`, severity: 'warning', source: 'docker_event', container: name });
        } else if (event.Action === 'start') {
          // Detect deploy — container started (could be restart or fresh deploy)
          if (onContainerDeploy) onContainerDeploy(name).catch(err => console.error('[CHANGELOG] Deploy detection error:', err.message));
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

// Daily 3:30 AM: Retention cleanup for error events (30d) and perf metrics (14d)
cron.schedule('30 3 * * *', guardedCron('data-retention', () => {
  try {
    const deletedEvents = db.prepare("DELETE FROM error_events WHERE timestamp < datetime('now', '-30 days')").run();
    const deletedPerf = db.prepare("DELETE FROM perf_metrics WHERE hour < datetime('now', '-14 days')").run();
    console.log(`[CLEANUP] Pruned ${deletedEvents.changes} error events, ${deletedPerf.changes} perf metrics`);
  } catch (err) { cronFail('Data retention cleanup', err); }
}));

// Weekly Sunday 3:45 AM: Docker build cache prune
cron.schedule('45 3 * * 0', () => {
  try {
    const result = execSync('docker builder prune --filter until=168h -f 2>&1 | tail -1', { timeout: TIMEOUT_HEAVY }).toString().trim();
    console.log(`[CLEANUP] Docker build cache prune: ${result}`);
  } catch (err) { cronFail('Docker build cache prune', err); }
});

// Daily 4:00 AM: Database maintenance (WAL checkpoint + cleanup)
cron.schedule('0 4 * * *', guardedCron('db-maintenance', () => {
  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
    authDb.pragma('wal_checkpoint(TRUNCATE)');
    // Clean up old uptime history (>90 days) and audit log (>180 days)
    const deletedUptime = db.prepare("DELETE FROM uptime_history WHERE checked_at < datetime('now', '-90 days')").run();
    const deletedAudit = db.prepare("DELETE FROM audit_log WHERE created_at < datetime('now', '-180 days')").run();
    console.log(`[MAINT] WAL checkpoint done. Pruned ${deletedUptime.changes} uptime rows, ${deletedAudit.changes} audit rows`);
  } catch (err) { cronFail('DB maintenance', err); }
}));

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
cron.schedule('0 7 * * *', guardedCron('ssl-expiry', async () => {
  try {
    const expiring = [];
    for (const a of config.apps) {
      if (!a.domain || /^\d+\.\d+\.\d+\.\d+$/.test(a.domain)) continue;
      try {
        assertSafeDomain(a.domain);
        const result = execSync(`echo | openssl s_client -servername "${a.domain}" -connect "${a.domain}:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null`, { timeout: TIMEOUT_MEDIUM }).toString().trim();
        const match = result.match(/notAfter=(.*)/);
        if (match) {
          const expiresAt = new Date(match[1]);
          const daysLeft = Math.round((expiresAt - Date.now()) / MS_PER_DAY);
          if (daysLeft < 14) expiring.push(`${a.domain}: ${daysLeft}d left`);
        }
      } catch (err) { if (process.env.DEBUG) console.log(`[SSL] Skipping ${a.domain}:`, err.message); }
    }
    if (expiring.length > 0) {
      sendTelegram(`\ud83d\udd12 SSL certificates expiring soon:\n${expiring.join('\n')}`);
      console.log(`[SSL] ${expiring.length} certs expiring: ${expiring.join(', ')}`);
    }
  } catch (err) { cronFail('SSL expiry check', err); }
}));

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


// Status page, savings, audit — extracted to routes/status.js, routes/portfolio.js, routes/misc.js

// Audit log helper
function auditLog(req, action, target, details = {}) {
  try {
    db.prepare('INSERT INTO audit_log (user, action, target, details, ip) VALUES (?, ?, ?, ?, ?)').run(
      req?.session?.username || 'system', action, target || null, JSON.stringify(details), req?.ip || 'unknown'
    );
  } catch (err) { console.error('[AUDIT]', err.message); }
}

// ========== SQLITE BACKUP CRON ==========

// Daily 2:45 AM: backup data.db + auth.db (before 3:30 cleanup)
cron.schedule('45 2 * * *', guardedCron('sqlite-backup', async () => {
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
}));

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

// Perf, notifications, health scores — extracted to routes/misc.js, routes/portfolio.js


// === Route Modules (extracted for modularity) ===
const { cache: marketingCache, getStripeKeys } = registerMarketingRoutes({
  app, db, config, cron,
  findAppBySlug, getSetting, getEnvKeyFromApps, getBannerForgeUrl, setCORS,
  cbStripe, cbPlausible, cbAnthropic,
  rlBannerServe, rlBannerTrack,
  upsertMetric, upsertSEOAudit, qLatestMetric, qLatestSEO,
  cronFail, sendTelegram,
  TIMEOUT_QUICK, TIMEOUT_STANDARD, TIMEOUT_MEDIUM, TIMEOUT_AI,
  MS_PER_HOUR, MS_PER_DAY,
});
registerDnsRoutes({ app, config, getSetting, auditLog, slugify });
registerHetznerRoutes({ app, getSetting, TIMEOUT_STANDARD });
registerLaunchRoutes({ app, docker, db, config, findAppBySlug, auditLog, sendTelegram, cachedRevenue: () => marketingCache.revenue });
registerTroubleshootRoutes({ app, docker, findAppBySlug, auditLog, getDiskParts, TIMEOUT_STANDARD });
registerGitHubRoutes({ app, config, db, getSetting, auditLog, sendTelegram, cbGitHub, TIMEOUT_STANDARD, TIMEOUT_BUILD });
registerUptimeRoutes({ app, docker, db, config, TIMEOUT_QUICK, TIMEOUT_STANDARD, MS_PER_DAY });
registerDockerRoutes({ app, db, docker, config, auditLog, resolveContainerApp, SENSITIVE_PATTERN, TIMEOUT_STANDARD, MS_PER_HOUR });
registerErrorRoutes({ app, db, ingestError, rlErrorIngest });
const { getCachedKeyHealth } = registerConfigRoutes({
  app, config, configPath,
  findAppBySlug, getSetting,
  SENSITIVE_PATTERN, INTEGRATION_KEYS, INTEGRATION_KEY_SET,
  upsertSettingStmt, deleteSettingStmt,
  TIMEOUT_STANDARD, TIMEOUT_HEAVY,
});
const { calculateWorryScore, calculateAppReportCard } = registerOpsRoutes({
  app, db, docker, config, cron,
  findAppBySlug, getSetting, getDiskParts, getDiskPercent, getLatestFile,
  sendTelegram, cronFail, guardedCron, auditLog,
  qLatestMetric, qLatestSEO,
  TIMEOUT_STANDARD, MS_PER_HOUR, MS_PER_DAY, BACKUP_DIR, SENSITIVE_PATTERN,
  HEALING_PLAYBOOKS, configPath,
  getCachedKeyHealth,
});
registerProjectsRoutes({
  app, db, docker, config, cron,
  findAppBySlug, qLatestMetric, qLatestSEO,
  getAnthropicKey, getPlausibleUrl, getPlausibleApiKey, cbAnthropic,
  sendTelegram, cronFail,
  TIMEOUT_QUICK, MS_PER_DAY,
});
registerSecurityRoutes({
  app, db, docker, config, cron,
  resolveContainerApp, getAuditDomains,
  sendTelegram, cronFail, calculateAppReportCard,
  TIMEOUT_TLS, MS_PER_DAY,
});
registerAIRoutes({
  app, db, docker, config,
  findAppBySlug, auditLog, sendTelegram,
  getSetting, getEnvKeyFromApps, getAnthropicKey,
  cbAnthropic,
  marketingCache,
  calculateWorryScore, calculateAppReportCard,
  qLatestMetric, qLatestSEO,
  getDiskParts, getLatestFile,
  TIMEOUT_STANDARD, TIMEOUT_MEDIUM, TIMEOUT_AI,
  MS_PER_HOUR, MS_PER_DAY,
  BACKUP_DIR,
});
registerLogRoutes({ app, db });
registerExportRoutes({ app, db, config });
registerAnalyticsRoutes({
  app, db, cron,
  rlPublicRead, TRANSPARENT_GIF, setCORS,
  cronFail,
  MS_PER_HOUR, MS_PER_DAY,
});
registerStripeRoutes({ app, config, getStripeKeys });
registerAlertRoutes({
  app, db, config, cron,
  qLatestMetric,
  sendTelegram, guardedCron, cronFail,
  isInMaintenanceWindow,
  TIMEOUT_QUICK,
});
const _snapshotExports = registerSnapshotRoutes({
  app, db, docker, config,
  resolveContainerApp, auditLog,
  getAnthropicKey, cbAnthropic,
  TIMEOUT_STANDARD,
});
onContainerDeploy = _snapshotExports.onContainerDeploy;
registerStatusRoutes({
  app, db, docker, config,
  rlPublicRead, calculateAppReportCard,
  TIMEOUT_QUICK, MS_PER_DAY,
});
registerPortfolioRoutes({
  app, db, docker, config, cron,
  qLatestMetric, qLatestSEO,
  calculateAppReportCard,
  getSetting, setSetting: (k, v) => upsertSettingStmt.run(k, v),
  getAnthropicKey, getPlausibleUrl, getPlausibleApiKey,
  cbAnthropic,
  sendTelegram, cronFail, guardedCron, addNotification,
  marketingCache,
  TIMEOUT_STANDARD, MS_PER_HOUR, MS_PER_DAY,
});
registerMiscRoutes({
  app, db, docker, config,
  auditLog, resolveContainerApp, getSetting,
  qLatestMetric, calculateAppReportCard,
  marketingCache,
  perfRing, slowRequests,
  setCORS,
  MS_PER_HOUR, MS_PER_DAY,
});

// Health check endpoint
app.get('/health', (_req, res) => res.send('ok'));

const port = process.env.PORT || 3000;
const server = app.listen(port, '0.0.0.0', () => {
  console.log(`Dashboard API running on port ${port}`);
});

// --- Graceful Shutdown ---
function gracefulShutdown(signal) {
  console.log(`[SHUTDOWN] ${signal} received, shutting down gracefully...`);
  // Stop all cron jobs
  for (const [, task] of cron.getTasks()) { try { task.stop(); } catch { /* already stopped */ } }
  // Clear all intervals
  for (const id of _intervals) clearInterval(id);
  // Destroy Docker event stream
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
