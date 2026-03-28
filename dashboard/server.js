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
import registerDnsRoutes from './routes/dns.js';
import registerHetznerRoutes from './routes/hetzner.js';
import registerLaunchRoutes from './routes/launch.js';
import registerTroubleshootRoutes from './routes/troubleshoot.js';
import registerMarketingRoutes from './routes/marketing.js';
import registerErrorRoutes from './routes/errors.js';
import registerOpsRoutes from './routes/ops.js';
import registerProjectsRoutes from './routes/projects.js';
import registerSecurityRoutes from './routes/security.js';

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

// POST /api/containers/:name/exec — Execute a command inside a container
app.post('/api/containers/:name/exec', asyncRoute(async (req, res) => {
  const { cmd } = req.body;
  if (!cmd || typeof cmd !== 'string' || cmd.trim().length < 1) {
    return res.status(400).json({ error: 'cmd is required' });
  }

  // Safety: block destructive commands
  const BLOCKED = ['rm -rf /', 'mkfs', 'dd if=', ':(){', 'shutdown', 'reboot', 'halt', 'init 0', 'init 6'];
  const lowerCmd = cmd.toLowerCase().trim();
  if (BLOCKED.some(b => lowerCmd.includes(b))) {
    return res.status(403).json({ error: 'This command is blocked for safety' });
  }

  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === req.params.name);
  if (!target) return res.status(404).json({ error: 'Container not found' });
  if (target.State !== 'running') return res.status(400).json({ error: 'Container is not running' });

  const container = docker.getContainer(target.Id);
  const exec = await container.exec({
    Cmd: ['sh', '-c', cmd.trim()],
    AttachStdout: true,
    AttachStderr: true,
  });

  const stream = await exec.start({ Detach: false });
  const chunks = [];
  await new Promise((resolve) => {
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', resolve);
    setTimeout(() => { stream.destroy(); resolve(); }, 10000); // 10s timeout
  });

  const output = Buffer.concat(chunks).toString('utf8')
    .split('\n').map(l => l.length > 8 ? l.slice(8) : l).join('\n')
    .slice(0, 10000); // Cap output at 10KB

  const inspect = await exec.inspect();
  auditLog(req, 'container.exec', req.params.name, { cmd: cmd.slice(0, 200) });

  res.json({ output, exitCode: inspect.ExitCode, container: req.params.name });
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

// POST /api/config/apps/:slug/preview — Preview config changes before applying
app.post('/api/config/apps/:slug/preview', asyncRoute(async (req, res) => {
  const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
  if (idx === -1) return res.status(404).json({ error: 'App not found' });

  const current = { ...config.apps[idx] };
  const changes = req.body;
  const diff = [];
  const impacts = [];

  const FIELDS = ['name', 'type', 'domain', 'port', 'health', 'containers', 'description', 'tech', 'envFile', 'composeFile'];
  for (const field of FIELDS) {
    if (changes[field] === undefined) continue;
    const oldVal = current[field];
    const newVal = field === 'port' && changes[field] ? Number(changes[field]) : changes[field];
    const oldStr = JSON.stringify(oldVal ?? null);
    const newStr = JSON.stringify(newVal ?? null);
    if (oldStr !== newStr) {
      diff.push({ field, old: oldVal ?? null, new: newVal ?? null });

      // Impact analysis
      if (field === 'port') {
        const conflict = config.apps.find(a => a !== current && a.port && Number(a.port) === Number(newVal));
        if (conflict) impacts.push({ severity: 'error', message: `Port ${newVal} conflicts with ${conflict.name}` });
        else impacts.push({ severity: 'info', message: `Port change requires nginx config update` });
      }
      if (field === 'domain') {
        if (oldVal && newVal !== oldVal) impacts.push({ severity: 'warning', message: `Domain change: SSL cert + nginx config + DNS update needed` });
        if (newVal && !oldVal) impacts.push({ severity: 'info', message: `New domain: needs DNS A record + SSL cert + nginx config` });
      }
      if (field === 'containers') {
        const oldC = Array.isArray(oldVal) ? oldVal : [];
        const newC = Array.isArray(newVal) ? newVal : [];
        const removed = oldC.filter(c => !newC.includes(c));
        if (removed.length > 0) impacts.push({ severity: 'warning', message: `Removing containers: ${removed.join(', ')} — these will no longer be monitored` });
      }
      if (field === 'name') {
        impacts.push({ severity: 'info', message: `Slug will change from "${slugify(oldVal)}" to "${slugify(newVal)}"` });
      }
    }
  }

  res.json({ slug: req.params.slug, diff, impacts, hasChanges: diff.length > 0 });
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
  const cachedRevenue = marketingCache?.revenue;
  if (cachedRevenue) {
    context.revenue = {
      totalMRR: (cachedRevenue.totals.mrr / 100).toFixed(0),
      revenue30d: (cachedRevenue.totals.revenue30d / 100).toFixed(0),
      currency: 'EUR',
      apps: Object.fromEntries(Object.entries(cachedRevenue.apps).map(([name, d]) => [name, { mrr: (d.mrr / 100).toFixed(0), chargeCount30d: d.chargeCount30d }])),
    };
  }

  // SEO scores (from cache)
  const cachedSEO = marketingCache?.seo;
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

  // Auto-snapshot before logging deploy (capture pre-deploy state)
  await snapshotContainer(containerName, appSlug, 'pre-deploy').catch(() => {});

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

// === Feature: Snapshot & Rollback ===

db.exec(`
  CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    container_name TEXT NOT NULL,
    image_id TEXT NOT NULL,
    image_tag TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    label TEXT,
    auto INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_snapshots_app ON snapshots(app_slug, created_at);
`);

// Auto-snapshot: capture current image before deploy
async function snapshotContainer(containerName, appSlug, label) {
  try {
    const containers = await docker.listContainers({ all: true });
    const target = containers.find(c => containerName(c) === containerName);
    if (!target) return null;
    const inspect = await docker.getContainer(target.Id).inspect();
    const imageId = inspect.Image;
    const imageTag = inspect.Config?.Image || target.Image;
    db.prepare('INSERT INTO snapshots (app_slug, container_name, image_id, image_tag, label, auto) VALUES (?, ?, ?, ?, ?, ?)')
      .run(appSlug, containerName, imageId, imageTag, label || 'auto', label ? 0 : 1);
    console.log(`[SNAPSHOT] Captured ${containerName} -> ${imageTag} (${imageId.slice(0, 12)})`);
    return { imageId, imageTag };
  } catch (err) {
    console.error(`[SNAPSHOT] Failed for ${containerName}:`, err.message);
    return null;
  }
}

// GET /api/snapshots — List snapshots per app
app.get('/api/snapshots', asyncRoute((_req, res) => {
  const slug = _req.query.app;
  const limit = Math.min(parseInt(_req.query.limit) || 50, 200);
  const snapshots = slug
    ? db.prepare('SELECT * FROM snapshots WHERE app_slug = ? ORDER BY created_at DESC LIMIT ?').all(slug, limit)
    : db.prepare('SELECT * FROM snapshots ORDER BY created_at DESC LIMIT ?').all(limit);
  res.json({ snapshots });
}));

// POST /api/snapshots — Create a manual snapshot
app.post('/api/snapshots', asyncRoute(async (req, res) => {
  const { container, label } = req.body;
  if (!container) return res.status(400).json({ error: 'container is required' });

  const resolved = resolveContainerApp(container);
  const appSlug = resolved?.slug || 'unknown';
  const result = await snapshotContainer(container, appSlug, label || 'manual');
  if (!result) return res.status(404).json({ error: 'Container not found or not inspectable' });

  auditLog(req, 'snapshot.create', container, { label, imageTag: result.imageTag });
  res.json({ ok: true, imageId: result.imageId, imageTag: result.imageTag });
}));

// POST /api/snapshots/:id/rollback — Rollback to a snapshot
app.post('/api/snapshots/:id/rollback', asyncRoute(async (req, res) => {
  const snapshot = db.prepare('SELECT * FROM snapshots WHERE id = ?').get(req.params.id);
  if (!snapshot) return res.status(404).json({ error: 'Snapshot not found' });

  // First, snapshot current state (so we can rollback the rollback)
  await snapshotContainer(snapshot.container_name, snapshot.app_slug, 'pre-rollback');

  // Find the running container
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === snapshot.container_name);
  if (!target) return res.status(404).json({ error: `Container ${snapshot.container_name} not found` });

  // Stop current container, start with old image
  const container = docker.getContainer(target.Id);

  // Tag the snapshot image so we can reference it
  const rollbackTag = `${snapshot.container_name}:rollback-${snapshot.id}`;
  try {
    const image = docker.getImage(snapshot.image_id);
    await image.tag({ repo: snapshot.container_name, tag: `rollback-${snapshot.id}` });
  } catch (err) {
    return res.status(400).json({ error: `Cannot find image ${snapshot.image_id.slice(0, 12)}. It may have been pruned.` });
  }

  auditLog(req, 'snapshot.rollback', snapshot.container_name, { snapshotId: snapshot.id, imageTag: snapshot.image_tag });

  // Note: actual rollback via docker compose is safer than raw container manipulation
  // Return the info needed for the operator to execute
  res.json({
    ok: true,
    message: `Image tagged as ${rollbackTag}. To complete rollback, run: docker compose up -d ${snapshot.container_name}`,
    snapshot: { id: snapshot.id, container: snapshot.container_name, imageTag: snapshot.image_tag, imageId: snapshot.image_id },
    rollbackTag,
  });
}));

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

function stripeHeaders(secretKey) {
  return { 'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64') };
}

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

// === Feature: Container Comparison (ranked resource usage) ===

app.get('/api/containers/compare', asyncRoute(async (_req, res) => {
  const containers = await docker.listContainers();
  const results = [];

  await Promise.all(containers.map(async (c) => {
    const name = containerName(c);
    try {
      const stats = await docker.getContainer(c.Id).stats({ stream: false });
      const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
      const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
      const cpuCount = stats.cpu_stats.online_cpus || 1;
      const cpuPercent = systemDelta > 0 ? (cpuDelta / systemDelta) * cpuCount * 100 : 0;
      const memUsage = stats.memory_stats.usage || 0;
      const memLimit = stats.memory_stats.limit || 0;
      const memPercent = memLimit > 0 ? (memUsage / memLimit) * 100 : 0;
      const netRx = stats.networks ? Object.values(stats.networks).reduce((s, n) => s + n.rx_bytes, 0) : 0;
      const netTx = stats.networks ? Object.values(stats.networks).reduce((s, n) => s + n.tx_bytes, 0) : 0;

      const resolved = resolveContainerApp(name);
      results.push({
        name, appSlug: resolved?.slug || null,
        cpu: +cpuPercent.toFixed(2),
        memMB: Math.round(memUsage / 1024 / 1024),
        memLimitMB: Math.round(memLimit / 1024 / 1024),
        memPercent: +memPercent.toFixed(1),
        netRxMB: +(netRx / 1024 / 1024).toFixed(1),
        netTxMB: +(netTx / 1024 / 1024).toFixed(1),
        status: c.State, uptime: c.Status,
      });
    } catch { /* container may have stopped */ }
  }));

  // Sort by memory usage descending (biggest consumers first)
  results.sort((a, b) => b.memMB - a.memMB);

  const totalMemMB = results.reduce((s, r) => s + r.memMB, 0);
  const totalCpu = results.reduce((s, r) => s + r.cpu, 0);

  res.json({ containers: results, totals: { memMB: totalMemMB, cpu: +totalCpu.toFixed(2), count: results.length }, timestamp: new Date().toISOString() });
}));

// === Feature: Domain Overview (unified per-domain dashboard) ===

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

    // SSL (from cache if available)
    if (cachedSSL?.results) {
      const sslEntry = cachedSSL.results.find(r => r.domain === domain);
      if (sslEntry) {
        entry.ssl = { valid: sslEntry.valid, daysRemaining: sslEntry.daysRemaining, issuer: sslEntry.issuer };
      }
    }

    // SEO (from cache)
    const cachedSEO = marketingCache?.seo;
    if (cachedSEO?.apps) {
      const seoEntry = Object.entries(cachedSEO.apps).find(([name]) => slugify(name) === slug);
      if (seoEntry) entry.seo = { score: seoEntry[1].score, grade: seoEntry[1].grade };
    }

    // Traffic (from metrics)
    try {
      const pv = qLatestMetric.get(slug, 'pageviews_30d');
      entry.traffic = pv ? { pageviews30d: pv.value } : { pageviews30d: 0 };
    } catch { entry.traffic = { pageviews30d: 0 }; }

    // Revenue
    try {
      const mrr = qLatestMetric.get(slug, 'mrr');
      entry.revenue = mrr ? { mrr: mrr.value / 100 } : { mrr: 0 };
    } catch { entry.revenue = { mrr: 0 }; }

    // Uptime (last 24h)
    try {
      const stats = db.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) as up_count FROM uptime_history WHERE app_slug = ? AND checked_at > datetime('now', '-24 hours')").get(slug);
      entry.uptime = stats.total > 0 ? { pct: +(stats.up_count / stats.total * 100).toFixed(1), checks: stats.total } : { pct: null, checks: 0 };
    } catch { entry.uptime = { pct: null, checks: 0 }; }

    // Container status
    try {
      const containers = await docker.listContainers({ all: true });
      const appContainers = (appDef.containers || []).map(name => {
        const c = containers.find(ct => containerName(ct) === name);
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

  // Sort by health score (worst first to highlight issues)
  domains.sort((a, b) => (a.healthScore?.score || 0) - (b.healthScore?.score || 0));

  res.json({ domains, timestamp: new Date().toISOString() });
}));

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
registerErrorRoutes({ app, db, ingestError, rlErrorIngest });
const { calculateWorryScore, calculateAppReportCard } = registerOpsRoutes({
  app, db, docker, config, cron,
  findAppBySlug, getSetting, getDiskParts, getDiskPercent, getLatestFile,
  sendTelegram, cronFail, guardedCron, auditLog,
  qLatestMetric, qLatestSEO,
  TIMEOUT_STANDARD, MS_PER_HOUR, MS_PER_DAY, BACKUP_DIR, SENSITIVE_PATTERN,
  HEALING_PLAYBOOKS, configPath,
  getCachedKeyHealth: () => cachedKeyHealth,
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
