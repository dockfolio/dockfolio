import express from 'express';
import Docker from 'dockerode';
import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdirSync, statSync, readdirSync } from 'fs';
import yaml from 'js-yaml';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';
import Database from 'better-sqlite3';
import cron from 'node-cron';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import {
  slugify, containerName, hashValue, todayString, percent, safeJSON,
  letterGrade, maskValue, parseEnvFile, serializeEnvVars,
  getMarketableApps, getAppsWithEnv, diskScore, securityScore, seoScore,
  parseId, asyncRoute, errorFingerprint, errorScore
} from './utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const docker = new Docker({ socketPath: '/var/run/docker.sock' });
const BACKUP_DIR = process.env.BACKUP_DIR || join(process.env.HOME || '/home/deploy', 'backups');

// Load app config
const configPath = join(__dirname, 'config.yml');
const config = yaml.load(readFileSync(configPath, 'utf8'));

// Cache for container stats (refreshed every 30s)
let cachedStats = null;
let lastStatsUpdate = 0;
const STATS_TTL = 30_000;

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
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
app.use(express.json());
app.use(cookieParser());

// --- Request logging & tracing ---
app.use((req, res, next) => {
  const requestId = randomUUID();
  req.id = requestId;
  res.setHeader('X-Request-ID', requestId);
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (req.path.startsWith('/api/')) {
      console.log(`[REQ] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
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
    const CSRF_EXEMPT = ['/api/auth/login', '/api/auth/setup', '/api/banners/', '/api/crosspromo/', '/api/errors/ingest', '/api/errors/envelope'];
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
setInterval(cleanExpiredSessions, 3600_000);

const SESSION_TTL_DAYS = 30;

function createSession(userId) {
  const token = randomUUID();
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 86400_000).toISOString();
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
const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/setup', '/api/auth/status', '/health', '/api/health', '/api/crosspromo', '/api/banners', '/api/errors/ingest', '/api/errors/envelope', '/api/errors/sdk.js'];

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

// --- Auth API ---
app.get('/api/auth/status', (_req, res) => {
  res.json({ setupComplete: isSetupComplete() });
});

app.post('/api/auth/setup', (req, res) => {
  if (isSetupComplete()) {
    return res.status(400).json({ error: 'Setup already completed' });
  }
  const { username, password } = req.body;
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'Username required, password must be 8+ characters' });
  }
  const hash = bcrypt.hashSync(password, 12);
  const result = authDb.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(username.trim(), hash, 'admin');
  const session = createSession(result.lastInsertRowid);
  res.cookie('session', session.token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: SESSION_TTL_DAYS * 86400_000 });
  res.json({ success: true });
});

app.post('/api/auth/login', (req, res) => {
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
  res.cookie('session', session.token, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: SESSION_TTL_DAYS * 86400_000 });
  res.json({ success: true, username: user.username });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.cookies?.session;
  if (token) {
    authDb.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  }
  res.clearCookie('session');
  res.json({ success: true });
});

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

function getBannerForgeUrl() {
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

async function sendTelegram(message) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' }),
      signal: AbortSignal.timeout(5000)
    });
  } catch { /* silent — Telegram is best-effort */ }
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

    return {
      ...appDef,
      containerStatuses,
      overallHealth,
      hasSentry,
      hasEnvFile,
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
  const dfOutput = execSync('df -B1 / | tail -1', { timeout: 10000 }).toString().trim();
  const dfParts = dfOutput.split(/\s+/);
  const diskTotal = parseInt(dfParts[1], 10);
  const diskUsed = parseInt(dfParts[2], 10);

  // Load average
  const loadavg = readFileSync('/proc/loadavg', 'utf8').split(' ');
  const cpuCount = parseInt(execSync('nproc', { timeout: 5000 }).toString().trim(), 10);

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

// GET /api/containers/:name/logs — last N lines of container logs
app.get('/api/containers/:name/logs', asyncRoute(async (req, res) => {
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === req.params.name);
  if (!target) return res.status(404).json({ error: 'Container not found' });

  const container = docker.getContainer(target.Id);
  const logs = await container.logs({
    stdout: true,
    stderr: true,
    tail: parseInt(req.query.lines) || 100,
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
  const [images, containers, volumes] = await Promise.all([
    docker.listImages(),
    docker.listContainers({ all: true }),
    docker.listVolumes(),
  ]);

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

// POST /api/containers/:name/restart — restart a container
app.post('/api/containers/:name/restart', asyncRoute(async (req, res) => {
  const containers = await docker.listContainers({ all: true });
  const target = containers.find(c => containerName(c) === req.params.name);
  if (!target) return res.status(404).json({ error: 'Container not found' });

  const container = docker.getContainer(target.Id);
  await container.restart({ t: 10 });
  res.json({ ok: true, message: `Container ${req.params.name} restarted` });
}));

// GET /api/health — detailed health check
app.get('/api/health', async (_req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    const running = containers.filter(c => c.State === 'running').length;
    res.json({
      status: 'ok',
      uptime: process.uptime(),
      containers: { total: containers.length, running },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
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
  const [statusRes, heartbeatRes] = await Promise.all([
    fetch(`${kumaBase}/api/status-page/status`),
    fetch(`${kumaBase}/api/status-page/heartbeat/status`),
  ]);

  const statusData = await statusRes.json();
  const heartbeatData = await heartbeatRes.json();

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
const SSL_TTL = 3600_000; // 1 hour

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
    const req = https.default.request({ hostname: domain, port: 443, method: 'HEAD', timeout: 5000 }, (response) => {
      const cert = response.socket?.getPeerCertificate?.();
      if (cert?.valid_to) {
        const expiry = new Date(cert.valid_to);
        const daysLeft = Math.floor((expiry - now) / 86400000);
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

    const since = Math.floor((now - 6 * 3600_000) / 1000);
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
app.post('/api/actions/prune', asyncRoute(async (_req, res) => {
  const result = {};
  const pruneContainers = await docker.pruneContainers();
  result.containers = pruneContainers.ContainersDeleted?.length || 0;

  const pruneImages = await docker.pruneImages();
  result.images = pruneImages.ImagesDeleted?.length || 0;
  result.spaceReclaimed = pruneImages.SpaceReclaimed || 0;

  result.buildCache = execSync('docker builder prune -f 2>&1 | tail -1', { timeout: 60000 }).toString().trim();

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
      const files = execSync(`ls -lt "${dir}" 2>/dev/null | grep -E '\\.(sql\\.gz|gz)$'`, { timeout: 10000 }).toString().trim().split('\n').filter(Boolean);
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
      const ageHours = ageMs ? Math.round(ageMs / 3600000) : null;

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
      signal: AbortSignal.timeout(10000),
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
      signal: AbortSignal.timeout(5000),
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
      signal: AbortSignal.timeout(5000),
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
const SEO_TTL = 3600_000; // 1 hour

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
    const mrrRow = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug);
    const revRow = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'revenue' ORDER BY date DESC LIMIT 1").get(slug);

    // Traffic (from cached analytics)
    const trafficData = cachedAnalytics?.apps?.[appDef.name] || null;

    // Security score
    const secRow = db.prepare('SELECT score, grade FROM security_scans WHERE app_slug = ? ORDER BY timestamp DESC LIMIT 1').get(slug);

    // SEO score
    const seoRow = db.prepare('SELECT score FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1').get(slug);

    // Project tasks
    const openTasks = db.prepare("SELECT COUNT(*) as n FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.n || 0;
    const doneTasks = db.prepare("SELECT COUNT(*) as n FROM project_tasks WHERE app_slug = ? AND status = 'done'").get(slug)?.n || 0;

    // Roadmap
    const roadmapItems = db.prepare("SELECT COUNT(*) as n FROM project_roadmap WHERE app_slug = ?").get(slug)?.n || 0;
    const roadmapShipped = db.prepare("SELECT COUNT(*) as n FROM project_roadmap WHERE app_slug = ? AND status = 'shipped'").get(slug)?.n || 0;

    // Banner placements
    const bannerCount = db.prepare("SELECT COUNT(*) as n FROM banner_placements WHERE app_slug = ? AND status = 'active'").get(slug)?.n || 0;

    // Project meta
    const meta = db.prepare('SELECT lifecycle, priority, revenue_goal, traffic_goal, user_goal FROM project_meta WHERE app_slug = ?').get(slug);

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

// POST /api/apps/:slug/recreate — recreate container with new env
app.post('/api/apps/:slug/recreate', (req, res) => {
  try {
    const appDef = findAppBySlug(req.params.slug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });
    if (!appDef.composeFile) return res.status(400).json({ error: 'No compose file configured' });

    const projectDir = dirname(appDef.composeFile);
    const output = execSync(
      `docker compose -f "${appDef.composeFile}" --project-directory "${projectDir}" up -d --no-build 2>&1`,
      { timeout: 60000 }
    ).toString();

    console.log(`[RECREATE] ${appDef.name}: container recreated`);
    res.json({ ok: true, output });
  } catch (err) {
    res.status(500).json({ error: err.stderr?.toString() || err.message });
  }
});

// GET /api/env/health — validate API keys across all apps
let cachedKeyHealth = null;
let lastKeyHealthUpdate = 0;
const KEY_HEALTH_TTL = 300_000; // 5 minutes

async function validateKey(type, value) {
  try {
    const opts = { method: 'GET', headers: {}, signal: AbortSignal.timeout(10000) };
    let url;
    if (type === 'STRIPE_SECRET_KEY') {
      url = 'https://api.stripe.com/v1/balance';
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
    } else if (type === 'REPLICATE_API_TOKEN') {
      url = 'https://api.replicate.com/v1/account';
      opts.headers['Authorization'] = `Bearer ${value}`;
    } else {
      return null; // Unknown key type
    }
    const response = await fetch(url, opts);
    // 200/201 = valid, 422 = valid (validation error means auth passed), 401/403 = expired
    const s = response.status;
    return (s === 200 || s === 201 || s === 422) ? 'valid' : 'expired';
  } catch {
    return 'error';
  }
}

const VALIDATABLE_KEYS = ['STRIPE_SECRET_KEY', 'ANTHROPIC_API_KEY', 'RESEND_API_KEY', 'REPLICATE_API_TOKEN'];

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

// GET /api/env/shared — detect shared keys across apps
app.get('/api/env/shared', asyncRoute((_req, res) => {
  const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));
  // Map: hash -> { key, maskedValue, apps[] }
  const hashMap = new Map();

  for (const appDef of appsWithEnv) {
    const vars = parseEnvFile(appDef.envFile);
    for (const v of vars) {
      if (!SENSITIVE_PATTERN.test(v.key) || !v.value) continue;
      const hash = hashValue(v.value, 64);
      const mapKey = `${v.key}::${hash}`;
      if (!hashMap.has(mapKey)) {
        hashMap.set(mapKey, { key: v.key, maskedValue: maskValue(v.value), apps: [] });
      }
      hashMap.get(mapKey).apps.push(appDef.name);
    }
  }

  // Only return entries shared by 2+ apps
  const shared = Array.from(hashMap.values()).filter(e => e.apps.length > 1);
  res.json({ shared });
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
app.post('/api/config/apps', (req, res) => {
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
  res.json({ success: true, slug: slugify(newApp.name) });
});

// PUT /api/config/apps/:slug — update an app
app.put('/api/config/apps/:slug', (req, res) => {
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
  res.json({ success: true });
});

// DELETE /api/config/apps/:slug — remove an app
app.delete('/api/config/apps/:slug', (req, res) => {
  const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
  if (idx === -1) return res.status(404).json({ error: 'App not found' });
  config.apps.splice(idx, 1);
  saveConfig();
  res.json({ success: true });
});

// --- Marketing Manager: SQLite + Revenue + Analytics ---

const MARKETING_DB_PATH = process.env.MARKETING_DB_PATH || join(process.env.HOME || '/data', 'marketing', 'data.db');
const MARKETING_DIR = dirname(MARKETING_DB_PATH);
if (!existsSync(MARKETING_DIR)) mkdirSync(MARKETING_DIR, { recursive: true });
const db = new Database(MARKETING_DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('foreign_keys = ON');

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
  CREATE TABLE IF NOT EXISTS seo_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_slug TEXT NOT NULL,
    date TEXT NOT NULL,
    score INTEGER,
    grade TEXT,
    checks TEXT,
    UNIQUE(app_slug, date)
  );

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
`);

const upsertMetric = db.prepare(`
  INSERT INTO metrics_daily (app_slug, date, metric_type, value, metadata)
  VALUES (?, ?, ?, ?, ?)
  ON CONFLICT(app_slug, date, metric_type) DO UPDATE SET value = excluded.value, metadata = excluded.metadata
`);

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
    // Auto-reopen resolved issues
    if (existing.status === 'resolved') {
      db.prepare("UPDATE error_issues SET status = 'open', last_seen = datetime('now'), occurrence_count = occurrence_count + 1, resolved_at = NULL WHERE id = ?").run(issueId);
    } else {
      db.prepare("UPDATE error_issues SET last_seen = datetime('now'), occurrence_count = occurrence_count + 1 WHERE id = ?").run(issueId);
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
    if (now - lastAlert > 3600_000) { // max once per hour per app
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
  return { keys, appKeys };
}

async function fetchStripeData(secretKey) {
  const headers = {
    'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64'),
  };
  const opts = { headers, signal: AbortSignal.timeout(10000) };

  try {
    const [balanceRes, chargesRes] = await Promise.all([
      fetch('https://api.stripe.com/v1/balance', opts),
      fetch('https://api.stripe.com/v1/charges?limit=10', opts),
    ]);

    const balance = balanceRes.ok ? await balanceRes.json() : null;
    const charges = chargesRes.ok ? await chargesRes.json() : null;

    // Get MRR from active subscriptions
    const subsRes = await fetch('https://api.stripe.com/v1/subscriptions?status=active&limit=100', opts);
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
    const revenueRes = await fetch(`https://api.stripe.com/v1/charges?limit=100&created[gte]=${thirtyDaysAgo}`, opts);
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
    const data = await fetchStripeData(key);
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
  } catch {}

  res.json(cachedRevenue);
}));

// --- Plausible Analytics ---

const PLAUSIBLE_URL = process.env.PLAUSIBLE_URL || 'http://plausible-plausible-1:8000';
const PLAUSIBLE_API_KEY = process.env.PLAUSIBLE_API_KEY || '';

async function fetchPlausibleStats(domain, period = '30d') {
  try {
    const baseUrl = `${PLAUSIBLE_URL}/api/v1/stats`;
    const headers = PLAUSIBLE_API_KEY ? { 'Authorization': `Bearer ${PLAUSIBLE_API_KEY}` } : {};
    const opts = { signal: AbortSignal.timeout(10000), headers };

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
    const stats = await fetchPlausibleStats(appDef.domain);
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
  } catch {}

  res.json(cachedAnalytics);
}));

// GET /api/marketing/trends — historical metric data from SQLite
app.get('/api/marketing/trends', asyncRoute((req, res) => {
  const days = parseInt(req.query.days) || 30;
  const cutoff = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

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
      const data = await fetchStripeData(key);
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
    console.error('[CRON] Revenue error:', err.message);
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
    console.error('[CRON] SEO audit error:', err.message);
  }
});

// === Feature: AI SEO Content Pipeline ===

function getEnvKeyFromApps(envKeyName) {
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

  const appDef = findAppBySlug(appSlug) || config.apps.find(a => slugify(a.name) === appSlug);
  if (!appDef) throw new Error(`App not found: ${appSlug}`);

  const promptFn = CONTENT_PROMPTS[contentType];
  if (!promptFn) throw new Error(`Unknown content type: ${contentType}`);

  const seoData = cachedSEO?.apps?.[appDef.name];
  const systemPrompt = buildContentSystemPrompt(appDef, seoData);
  const userPrompt = promptFn(keyword, appDef);

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': anthropicKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
    }),
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `Anthropic API error ${res.status}`);
  }

  const data = await res.json();
  const body = data.content?.[0]?.text || '';
  const tokenCount = (data.usage?.input_tokens || 0) + (data.usage?.output_tokens || 0);

  return { body, tokenCount };
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
    console.error('[CRON] Content generation error:', err.message);
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
    let url = `https://api.stripe.com/v1/${endpoint}?limit=100`;
    if (extraParams) url += '&' + extraParams;
    if (startingAfter) url += '&starting_after=' + startingAfter;
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
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
    console.error('[CRON] Customer graph error:', err.message);
  }
});

// === Feature: Automated Email Sequences ===

// Simple obfuscation to avoid plaintext emails in SQLite — not cryptographic security
const EMAIL_OBFUSCATION_KEY = process.env.EMAIL_OBFUSCATION_KEY || 'dockfolio-email-obfuscate-2026';

function obfuscateEmail(text) {
  const chars = [];
  for (let i = 0; i < text.length; i++) {
    chars.push(String.fromCharCode(text.charCodeAt(i) ^ EMAIL_OBFUSCATION_KEY.charCodeAt(i % EMAIL_OBFUSCATION_KEY.length)));
  }
  return Buffer.from(chars.join('')).toString('base64');
}

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
  const fromDomain = process.env.EMAIL_FROM_DOMAIN || appDef?.domain || 'example.com';

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
    signal: AbortSignal.timeout(10000),
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

app.post('/api/marketing/emails/pause/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });

  db.prepare('UPDATE email_sequences SET active = 0 WHERE id = ?').run(id);
  db.prepare("UPDATE email_queue SET status = 'paused' WHERE sequence_id = ? AND status = 'pending'").run(id);
  console.log(`[EMAIL] Sequence ${id} paused`);
  res.json({ ok: true, paused: true });
}));

app.post('/api/marketing/emails/resume/:id', asyncRoute((req, res) => {
  const id = parseId(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });

  db.prepare('UPDATE email_sequences SET active = 1 WHERE id = ?').run(id);
  db.prepare("UPDATE email_queue SET status = 'pending' WHERE sequence_id = ? AND status = 'paused'").run(id);
  console.log(`[EMAIL] Sequence ${id} resumed`);
  res.json({ ok: true, active: true });
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
    console.error('[CRON] Email queue error:', err.message);
  }
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
    const diskLine = execSync('df -B1 / | tail -1', { timeout: 10000 }).toString().trim().split(/\s+/);
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
        const files = execSync(`ls -t "${dir}" 2>/dev/null | head -1`, { timeout: 10000 }).toString().trim();
        if (!files) { context.backups[app] = 'no_backups'; continue; }
        const mtime = statSync(join(dir, files)).mtime;
        const ageH = Math.round((Date.now() - mtime.getTime()) / 3600000);
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
  } catch {}

  // Recent Docker events (last 24h)
  try {
    const since = Math.floor((Date.now() - 86400000) / 1000);
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
  } catch { context.events24h = { total: 0 }; }

  // Healing log (last 24h)
  try {
    const since24h = new Date(Date.now() - 86400000).toISOString();
    const healingActions = db.prepare('SELECT * FROM healing_log WHERE timestamp >= ? ORDER BY timestamp DESC').all(since24h);
    context.healing = healingActions.map(h => ({ condition: h.condition, action: h.action_taken, result: h.result, app: h.app_slug }));
  } catch { context.healing = []; }

  // Project tasks (overdue + due today)
  try {
    const today = new Date().toISOString().split('T')[0];
    const overdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today);
    const dueToday = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date = ? AND status NOT IN ('done','cancelled')").get(today);
    const lastShipped = db.prepare("SELECT title, app_slug, shipped_date FROM project_roadmap WHERE status = 'shipped' ORDER BY shipped_date DESC LIMIT 1").get();
    context.projects = { overdueCount: overdue?.count || 0, dueTodayCount: dueToday?.count || 0, lastShipped: lastShipped || null };
  } catch { context.projects = {}; }

  // Ops Intelligence
  try {
    const worryResult = await calculateWorryScore();
    const latestScore = db.prepare('SELECT streak_days FROM ops_scores ORDER BY timestamp DESC LIMIT 1').get();
    const recentDrifts = db.prepare("SELECT COUNT(*) as n FROM ops_events WHERE event_type LIKE 'drift_%' AND acknowledged = 0 AND timestamp >= datetime('now', '-24 hours')").get();
    context.ops = { worryScore: worryResult.score, breakdown: worryResult.breakdown, streakDays: latestScore?.streak_days || 0, unacknowledgedDrifts: recentDrifts?.n || 0 };
  } catch { context.ops = {}; }

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

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': anthropicKey,
      'anthropic-version': '2023-06-01',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 512,
      messages: [{ role: 'user', content: prompt }],
    }),
    signal: AbortSignal.timeout(15000),
  });

  if (!aiRes.ok) {
    const err = await aiRes.json().catch(() => ({}));
    throw new Error(err.error?.message || `Anthropic API error ${aiRes.status}`);
  }

  const aiData = await aiRes.json();
  const briefingText = aiData.content?.[0]?.text || 'Unable to generate briefing.';
  const tokens = (aiData.usage?.input_tokens || 0) + (aiData.usage?.output_tokens || 0);

  cachedBriefing = { type: 'ai', briefing: briefingText, context, tokens, generated: new Date().toISOString() };
  lastBriefingUpdate = now;
  console.log(`[BRIEFING] Generated (${tokens} tokens)`);
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

app.get('/api/command/search', (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ results: [] });

  const results = [];

  // Match apps
  for (const appDef of config.apps) {
    const slug = slugify(appDef.name);
    if (fuzzyMatch(q, appDef.name) || fuzzyMatch(q, slug) || (appDef.domain && fuzzyMatch(q, appDef.domain))) {
      results.push({ type: 'app', name: appDef.name, slug, domain: appDef.domain, description: appDef.description });
    }
  }

  // Match built-in commands
  const commands = [
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
  ];

  for (const c of commands) {
    if (fuzzyMatch(q, c.cmd) || fuzzyMatch(q, c.label)) {
      results.push({ type: 'command', ...c });
    }
  }

  // Match action patterns: "logs X", "restart X", "seo X"
  const actionMatch = q.match(/^(logs?|restart|seo|revenue|env)\s+(.+)/i);
  if (actionMatch) {
    const [, action, target] = actionMatch;
    const matchedApp = config.apps.find(a => fuzzyMatch(target, a.name) || fuzzyMatch(target, slugify(a.name)));
    if (matchedApp) {
      results.unshift({
        type: 'action',
        action: action.toLowerCase().replace(/s$/, ''),
        app: matchedApp.name,
        slug: slugify(matchedApp.name),
        label: `${action} ${matchedApp.name}`,
      });
    }
  }

  res.json({ results: results.slice(0, 10) });
});

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
        const diskLine = execSync('df / | tail -1', { timeout: 10000 }).toString().trim().split(/\s+/);
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
];

const insertHealing = db.prepare(
  'INSERT INTO healing_log (app_slug, condition, action_taken, confidence, result, auto, details) VALUES (?, ?, ?, ?, ?, ?, ?)'
);

async function runHealingCheck() {
  for (const playbook of HEALING_PLAYBOOKS) {
    try {
      const targets = await playbook.check();
      if (!targets || targets.length === 0) continue;

      for (const target of targets) {
        const appSlug = target.name || 'system';

        // Check if we already acted on this in the last hour (avoid spam)
        const recentAction = db.prepare(
          "SELECT id FROM healing_log WHERE app_slug = ? AND condition = ? AND timestamp >= datetime('now', '-1 hour')"
        ).get(appSlug, playbook.condition);
        if (recentAction) continue;

        if (playbook.confidence === 'high') {
          // Auto-execute
          try {
            const result = await playbook.execute(target);
            insertHealing.run(appSlug, playbook.condition, playbook.action, playbook.confidence, 'executed', 1, result);
            console.log(`[HEALING] Auto-executed: ${playbook.condition} on ${appSlug} — ${result}`);

            await sendTelegram(`🔧 Auto-Healing: ${playbook.condition}\nApp: ${appSlug}\nAction: ${result}`);
          } catch (err) {
            insertHealing.run(appSlug, playbook.condition, playbook.action, playbook.confidence, 'failed', 1, err.message);
            console.error(`[HEALING] Failed: ${playbook.condition} on ${appSlug} — ${err.message}`);
          }
        } else {
          // Log as pending for manual approval
          const detail = await playbook.execute(target).catch(e => e.message);
          insertHealing.run(appSlug, playbook.condition, playbook.action, playbook.confidence, 'pending', 0, detail);
          console.log(`[HEALING] Pending approval: ${playbook.condition} on ${appSlug}`);
        }
      }
    } catch (err) {
      console.error(`[HEALING] Playbook ${playbook.id} error:`, err.message);
    }
  }
}

// Run healing checks every 2 minutes
cron.schedule('*/2 * * * *', () => {
  runHealingCheck().catch(err => console.error('[HEALING] Cron error:', err.message));
});

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

    const appDef = config.apps?.find(a => (a.containers || [name]).some(cn => name.includes(cn || slugify(a.name))));
    const appSlug = appDef ? slugify(appDef.name) : null;

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
  const domains = (config.apps || []).filter(a => a.domain && a.type !== 'redirect').map(a => ({ domain: a.domain, slug: slugify(a.name) }));
  const findings = [];
  let totalWeight = 0, earnedWeight = 0;

  await Promise.all(domains.map(({ domain, slug }) => new Promise((resolve) => {
    const checkWeights = { ssl_valid: 20, ssl_expiry: 15, ssl_chain: 10, tls_version: 10, self_signed: 10 };
    Object.values(checkWeights).forEach(w => totalWeight += w);

    const socket = tls.default.connect({ host: domain, port: 443, servername: domain, timeout: 8000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      const proto = socket.getProtocol();

      if (socket.authorized) { earnedWeight += checkWeights.ssl_valid; }
      else { findings.push({ app_slug: slug, category: 'certificates', check_id: 'ssl_valid', severity: 'critical',
        title: `${domain}: Certificate not trusted`, details: socket.authorizationError, remediation: 'Renew certificate via certbot or check chain.' }); }

      if (cert?.valid_to) {
        const daysLeft = Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000);
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
  const domains = (config.apps || []).filter(a => a.domain && a.type !== 'redirect').map(a => ({ domain: a.domain, slug: slugify(a.name) }));
  const findings = [];
  let totalWeight = 0, earnedWeight = 0;

  for (const { domain, slug } of domains) {
    try {
      const res = await fetch(`https://${domain}`, { method: 'HEAD', signal: AbortSignal.timeout(8000),
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
    const appDef = config.apps?.find(a => (a.containers || [name]).some(cn => name.includes(cn || slugify(a.name))));
    const slug = appDef ? slugify(appDef.name) : null;

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
  catch (err) { console.error('[CRON] Security scan error:', err.message); }
});

cron.schedule('0 */6 * * *', async () => {
  try {
    const result = await scanCertificateSecurity();
    const critical = result.findings.filter(f => f.severity === 'critical');
    if (critical.length > 0) {
      await sendTelegram(`Security: SSL Alert - ${critical.map(f => f.title).join(', ')}`);
    }
  } catch (err) { console.error('[CRON] SSL security check error:', err.message); }
});

// Cleanup old security scans (90-day retention)
cron.schedule('0 5 * * 0', () => {
  try {
    const cutoff = new Date(Date.now() - 90 * 86400000).toISOString();
    const old = db.prepare('SELECT id FROM security_scans WHERE timestamp < ?').all(cutoff);
    if (old.length > 0) {
      db.prepare(`DELETE FROM security_findings WHERE scan_id IN (${old.map(o => o.id).join(',')})`).run();
      db.prepare('DELETE FROM security_scans WHERE timestamp < ?').run(cutoff);
      console.log(`[CRON] Cleaned up ${old.length} old security scans`);
    }
  } catch (err) { console.error('[CRON] Security cleanup error:', err.message); }
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
          signal: AbortSignal.timeout(15000),
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
        signal: AbortSignal.timeout(15000),
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
    signal: AbortSignal.timeout(15000),
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

app.get('/api/banners/serve', asyncRoute((req, res) => {
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

app.post('/api/banners/:placementId/view', asyncRoute((req, res) => {
  setCORS(res);
  const id = parseId(req.params.placementId);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  db.prepare('UPDATE banner_placements SET views = views + 1 WHERE id = ?').run(id);
  res.json({ ok: true });
}));

app.get('/api/banners/:placementId/click', (req, res) => {
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
      const timeout = setTimeout(() => controller.abort(), 5000);
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

app.post('/api/marketing/playbooks/:appSlug/generate', async (req, res) => {
  try {
    const appSlug = req.params.appSlug;
    const appDef = findAppBySlug(appSlug) || config.apps.find(a => slugify(a.name) === appSlug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });

    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return res.status(500).json({ error: 'No Anthropic API key available' });

    // Gather context
    const today = new Date().toISOString().split('T')[0];
    const seoAudit = db.prepare('SELECT score, grade, checks FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1').get(slugify(appDef.name));
    const revenueData = db.prepare('SELECT value, metadata FROM metrics_daily WHERE app_slug = ? AND metric_type = ? ORDER BY date DESC LIMIT 1').get(slugify(appDef.name), 'revenue');

    const prompt = `You are a marketing strategist for a portfolio of SaaS/tool apps.
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

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': anthropicKey,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 4096,
        messages: [{ role: 'user', content: prompt }],
      }),
      signal: AbortSignal.timeout(30000),
    });

    if (!aiRes.ok) {
      const err = await aiRes.json().catch(() => ({}));
      throw new Error(err.error?.message || `Anthropic API error ${aiRes.status}`);
    }

    const aiData = await aiRes.json();
    let text = aiData.content?.[0]?.text || '[]';
    const tokens = (aiData.usage?.input_tokens || 0) + (aiData.usage?.output_tokens || 0);

    // Strip markdown code fences that LLMs often wrap around JSON
    text = text.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();

    // Parse JSON array from AI response (handle truncation by closing brackets)
    let sections;
    try {
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      let jsonStr = jsonMatch ? jsonMatch[0] : text;
      // Fix truncated JSON: try to close it if it was cut off
      try {
        sections = JSON.parse(jsonStr);
      } catch (_) {
        // Remove last incomplete object and close the array
        jsonStr = jsonStr.replace(/,\s*\{[^}]*$/, '').replace(/,\s*$/, '');
        if (!jsonStr.endsWith(']')) jsonStr += ']';
        sections = JSON.parse(jsonStr);
      }
    } catch (parseErr) {
      return res.status(500).json({ error: 'Failed to parse AI response', raw: text });
    }

    // Delete existing playbook for this app and insert new sections
    const insertPlaybook = db.transaction(() => {
      db.prepare('DELETE FROM marketing_playbooks WHERE app_slug = ?').run(slugify(appDef.name));
      for (const s of sections) {
        if (s.section && s.title && s.content) {
          db.prepare('INSERT INTO marketing_playbooks (app_slug, section, title, content, status) VALUES (?, ?, ?, ?, ?)')
            .run(slugify(appDef.name), s.section, s.title, s.content, 'draft');
        }
      }
    });
    insertPlaybook();

    const entries = db.prepare('SELECT * FROM marketing_playbooks WHERE app_slug = ? ORDER BY section, priority DESC').all(slugify(appDef.name));
    res.json({ entries, tokens, generated: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
  const today = new Date().toISOString().split('T')[0];

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
    const seo = db.prepare('SELECT score, grade FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1').get(slug);

    // Latest security findings count for this app
    const secFindings = db.prepare("SELECT COUNT(*) as count FROM security_findings WHERE app_slug = ? AND status = 'open'").get(slug);

    // Latest MRR from metrics_daily
    const mrrRow = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug);

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
  const existing = db.prepare('SELECT id FROM project_meta WHERE app_slug = ?').get(slug);
  if (!existing) {
    db.prepare('INSERT INTO project_meta (app_slug, lifecycle, priority, revenue_goal_mrr, traffic_goal_mpv, user_goal, notes) VALUES (?, ?, ?, ?, ?, ?, ?)').run(slug, lifecycle || 'launched', priority || 2, revenue_goal_mrr || null, traffic_goal_mpv || null, user_goal || null, notes || null);
  } else {
    const fields = [];
    const values = [];
    if (lifecycle !== undefined) { fields.push('lifecycle = ?'); values.push(lifecycle); }
    if (priority !== undefined) { fields.push('priority = ?'); values.push(priority); }
    if (revenue_goal_mrr !== undefined) { fields.push('revenue_goal_mrr = ?'); values.push(revenue_goal_mrr); }
    if (traffic_goal_mpv !== undefined) { fields.push('traffic_goal_mpv = ?'); values.push(traffic_goal_mpv); }
    if (user_goal !== undefined) { fields.push('user_goal = ?'); values.push(user_goal); }
    if (notes !== undefined) { fields.push('notes = ?'); values.push(notes); }
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
  const fields = [];
  const values = [];
  if (title !== undefined) { fields.push('title = ?'); values.push(title); }
  if (description !== undefined) { fields.push('description = ?'); values.push(description); }
  if (status !== undefined) { fields.push('status = ?'); values.push(status); }
  if (priority !== undefined) { fields.push('priority = ?'); values.push(priority); }
  if (due_date !== undefined) { fields.push('due_date = ?'); values.push(due_date); }
  if (reminder_at !== undefined) { fields.push('reminder_at = ?'); values.push(reminder_at); fields.push('reminder_sent = 0'); }
  if (tags !== undefined) { fields.push('tags = ?'); values.push(JSON.stringify(tags)); }
  if (app_slug !== undefined) { fields.push('app_slug = ?'); values.push(app_slug); }
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
  const today = new Date().toISOString().split('T')[0];
  const tasks = db.prepare("SELECT * FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled') ORDER BY due_date ASC").all(today);
  res.json(tasks);
}));

app.get('/api/projects/tasks/today', asyncRoute((_req, res) => {
  const today = new Date().toISOString().split('T')[0];
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

// --- AI Insights ---
app.get('/api/projects/insights/:slug', asyncRoute(async (req, res) => {
  const slug = req.params.slug;
  const type = req.query.type || 'next_actions';
  const force = req.query.force === 'true';

  if (!force) {
    const cached = db.prepare('SELECT * FROM project_ai_insights WHERE app_slug = ? AND insight_type = ?').get(slug, type);
    if (cached) {
      const age = Date.now() - new Date(cached.generated_at).getTime();
      const maxAge = type === 'weekly_summary' ? 7 * 86400000 : 72 * 3600000;
      if (age < maxAge) return res.json({ content: cached.content, generated_at: cached.generated_at, cached: true });
    }
  }

  const appDef = config.apps.find(a => slugify(a.name) === slug);
  if (!appDef) return res.status(404).json({ error: 'App not found' });

  const meta = db.prepare('SELECT * FROM project_meta WHERE app_slug = ?').get(slug) || {};
  const openTasks = db.prepare("SELECT title FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled') LIMIT 5").all(slug);
  const roadmapItems = db.prepare("SELECT title, status FROM project_roadmap WHERE app_slug = ? AND status IN ('planned','in_progress') LIMIT 5").all(slug);
  const seo = db.prepare('SELECT score, grade FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1').get(slug);
  const mrrRow = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug);

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

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 512, messages: [{ role: 'user', content: prompt }] }),
    signal: AbortSignal.timeout(15000),
  });
  const aiData = await aiRes.json();
  const content = aiData.content?.[0]?.text || 'No insight generated';
  const tokens = aiData.usage?.output_tokens || 0;

  db.prepare('INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES (?, ?, ?, ?, datetime(\'now\')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at').run(slug, type, content, tokens);

  res.json({ content, generated_at: new Date().toISOString(), cached: false });
}));

app.get('/api/projects/insights/portfolio/summary', asyncRoute(async (req, res) => {
  const force = req.query.force === 'true';
  if (!force) {
    const cached = db.prepare("SELECT * FROM project_ai_insights WHERE app_slug = '_portfolio' AND insight_type = 'summary'").get();
    if (cached) {
      const age = Date.now() - new Date(cached.generated_at).getTime();
      if (age < 24 * 3600000) return res.json({ content: cached.content, generated_at: cached.generated_at, cached: true });
    }
  }

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(503).json({ error: 'No Anthropic API key available' });

  const saasApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
  const appSummaries = saasApps.map(a => {
    const slug = slugify(a.name);
    const meta = db.prepare('SELECT lifecycle, priority FROM project_meta WHERE app_slug = ?').get(slug) || {};
    const openTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.count || 0;
    const mrr = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug)?.value || 0;
    return `- ${a.name}: lifecycle=${meta.lifecycle || 'launched'}, MRR=€${(mrr / 100).toFixed(0)}, ${openTasks} open tasks`;
  }).join('\n');

  const today = new Date().toISOString().split('T')[0];
  const totalOverdue = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')").get(today)?.count || 0;
  const weekDone = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE completed_at >= datetime('now', '-7 days')").get()?.count || 0;

  const prompt = `You are an indie SaaS portfolio advisor. Here is the current state of a solo founder's app portfolio:

${appSummaries}

Portfolio stats: ${totalOverdue} overdue tasks, ${weekDone} tasks completed this week.

Write a concise 3-paragraph portfolio briefing: 1) overall health assessment, 2) what to focus on this week, 3) one strategic recommendation. Be direct, specific, actionable.`;

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 512, messages: [{ role: 'user', content: prompt }] }),
    signal: AbortSignal.timeout(15000),
  });
  const aiData = await aiRes.json();
  const content = aiData.content?.[0]?.text || 'No summary generated';
  const tokens = aiData.usage?.output_tokens || 0;

  db.prepare("INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES ('_portfolio', 'summary', ?, ?, datetime('now')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at").run(content, tokens);

  res.json({ content, generated_at: new Date().toISOString(), cached: false });
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
  } catch (err) { console.error('[PROJECTS] Reminder cron error:', err.message); }
});

// Daily 8 AM: overdue task alert
cron.schedule('0 8 * * *', async () => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const overdue = db.prepare("SELECT * FROM project_tasks WHERE due_date < ? AND status NOT IN ('done','cancelled') ORDER BY due_date ASC LIMIT 10").all(today);
    if (overdue.length === 0) return;

    const lines = overdue.map(t => {
      const appName = config.apps.find(a => slugify(a.name) === t.app_slug)?.name || 'Portfolio';
      const daysLate = Math.ceil((new Date(today) - new Date(t.due_date)) / 86400000);
      return `• ${appName}: ${t.title} (${daysLate}d late)`;
    });
    await sendTelegram(`⚠ Overdue Tasks — ${overdue.length} task${overdue.length > 1 ? 's' : ''} past due:\n${lines.join('\n')}`);
    console.log(`[PROJECTS] Overdue alert sent (${overdue.length} tasks)`);
  } catch (err) { console.error('[PROJECTS] Overdue cron error:', err.message); }
});

// Weekly Monday 6 AM: snapshot per-app KPIs
cron.schedule('0 6 * * 1', async () => {
  try {
    const snapDate = new Date().toISOString().split('T')[0];
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const mrr = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug)?.value || null;
      const openTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status NOT IN ('done','cancelled')").get(slug)?.count || 0;
      const doneTasks = db.prepare("SELECT COUNT(*) as count FROM project_tasks WHERE app_slug = ? AND status = 'done'").get(slug)?.count || 0;
      const shipped = db.prepare("SELECT COUNT(*) as count FROM project_roadmap WHERE app_slug = ? AND status = 'shipped'").get(slug)?.count || 0;
      const seo = db.prepare('SELECT score FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1').get(slug)?.score || null;
      const secScore = db.prepare('SELECT score FROM security_scans WHERE app_slug = ? ORDER BY timestamp DESC LIMIT 1').get(slug)?.score || null;

      // Plausible traffic (30d visitors)
      let traffic30d = null;
      if (appDef.domain && PLAUSIBLE_API_KEY) {
        try {
          const tRes = await fetch(
            `${PLAUSIBLE_URL}/api/v1/stats/aggregate?site_id=${appDef.domain}&period=30d&metrics=visitors`,
            { headers: { Authorization: `Bearer ${PLAUSIBLE_API_KEY}` }, signal: AbortSignal.timeout(5000) }
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
  } catch (err) { console.error('[PROJECTS] Snapshot cron error:', err.message); }
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
        const mrrRow = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug);
        const prompt = `Write a concise weekly status for ${appDef.name} (${appDef.type}): lifecycle=${meta.lifecycle}, MRR=€${((mrrRow?.value || 0) / 100).toFixed(0)}, ${openTasks.length} open tasks${openTasks.length > 0 ? ': ' + openTasks.map(t => t.title).join(', ') : ''}. 3 short paragraphs: state, progress, next focus.`;
        const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: { 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01', 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: 400, messages: [{ role: 'user', content: prompt }] }),
          signal: AbortSignal.timeout(15000),
        });
        const aiData = await aiRes.json();
        const content = aiData.content?.[0]?.text || '';
        if (content) {
          db.prepare("INSERT INTO project_ai_insights (app_slug, insight_type, content, token_count, generated_at) VALUES (?, 'weekly_summary', ?, ?, datetime('now')) ON CONFLICT(app_slug, insight_type) DO UPDATE SET content = excluded.content, token_count = excluded.token_count, generated_at = excluded.generated_at").run(slug, content, aiData.usage?.output_tokens || 0);
        }
      } catch (appErr) { console.error(`[PROJECTS] AI summary error for ${slug}:`, appErr.message); }
    }
    console.log(`[PROJECTS] Weekly AI summaries generated for ${saasApps.length} apps`);
  } catch (err) { console.error('[PROJECTS] AI summary cron error:', err.message); }
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
    const diskLine = execSync('df -B1 / | tail -1', { timeout: 10000 }).toString().trim().split(/\s+/);
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
          const latest = execSync(`ls -t "${join(backupDir, d.name)}" 2>/dev/null | head -1`, { timeout: 10000 }).toString().trim();
          if (!latest) { staleCount++; continue; }
          const ageH = (Date.now() - statSync(join(backupDir, d.name, latest)).mtime.getTime()) / 3600000;
          if (ageH > 25) staleCount++;
        } catch { staleCount++; }
      }
      breakdown.backups = Math.min(MAX.backups, staleCount * 5);
    }
  } catch {}

  // 5. Security score
  try {
    const scan = db.prepare('SELECT overall_score FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
    if (scan) {
      if (scan.overall_score < 40) breakdown.security = 10;
      else if (scan.overall_score < 60) breakdown.security = 7;
      else if (scan.overall_score < 75) breakdown.security = 4;
    } else { breakdown.security = 5; }
  } catch {}

  // 6. Healing activity (last hour)
  try {
    const since1h = new Date(Date.now() - 3600000).toISOString();
    const r = db.prepare("SELECT COUNT(*) as n FROM healing_log WHERE timestamp >= ? AND result IN ('executed','pending')").get(since1h);
    breakdown.healing = Math.min(MAX.healing, (r?.n || 0) * 5);
  } catch {}

  // 7. SEO
  try {
    const seoRows = db.prepare('SELECT score FROM seo_audits WHERE date = (SELECT MAX(date) FROM seo_audits)').all();
    if (seoRows.length > 0) {
      const avg = seoRows.reduce((a, b) => a + b.score, 0) / seoRows.length;
      if (avg < 40) breakdown.seo = 5;
      else if (avg < 60) breakdown.seo = 3;
    }
  } catch {}

  // 8. Error tracking
  try {
    const since1h = new Date(Date.now() - 3600000).toISOString();
    const criticals = db.prepare("SELECT COUNT(*) as n FROM error_issues WHERE severity = 'critical' AND status = 'open' AND last_seen >= ?").get(since1h);
    const openErrors = db.prepare("SELECT COUNT(*) as n FROM error_events WHERE timestamp >= datetime('now', '-1 hour')").get();
    breakdown.errors = errorScore(criticals?.n || 0, openErrors?.n || 0);
  } catch {}

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
  } catch {}

  const configHash = hashValue(readFileSync(configPath, 'utf8'));
  let diskPct = 0;
  try {
    diskPct = parseInt(execSync('df -B1 / | tail -1', { timeout: 10000 }).toString().trim().split(/\s+/)[4]);
  } catch {}

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
  } catch {}

  // Config.yml change
  const currentConfigHash = hashValue(readFileSync(configPath, 'utf8'));
  if (baseline.config_hash && baseline.config_hash !== currentConfigHash) {
    drifts.push({ type: 'drift_config', severity: 'info', title: 'config.yml changed since baseline', details: JSON.stringify({ oldHash: baseline.config_hash, newHash: currentConfigHash }) });
  }

  // Disk usage jump
  try {
    const diskPct = parseInt(execSync('df -B1 / | tail -1', { timeout: 10000 }).toString().trim().split(/\s+/)[4]);
    if (baseline.disk_usage_pct && diskPct > baseline.disk_usage_pct + 10) {
      drifts.push({ type: 'drift_disk', severity: diskPct >= 80 ? 'critical' : 'warning', title: `Disk: ${baseline.disk_usage_pct}% → ${diskPct}%`, details: JSON.stringify({ was: baseline.disk_usage_pct, now: diskPct }) });
    }
  } catch {}

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
      const latest = execSync(`ls -t "${backupDir}" 2>/dev/null | head -1`, { timeout: 10000 }).toString().trim();
      if (latest) {
        const ageH = (Date.now() - statSync(join(backupDir, latest)).mtime.getTime()) / 3600000;
        const s = ageH <= 25 ? 100 : ageH <= 48 ? 70 : ageH <= 168 ? 40 : 10;
        dims.backup = { score: s, grade: letterGrade(s) };
      } else dims.backup = { score: 0, grade: 'F' };
    } else dims.backup = { score: 0, grade: 'N/A' };
  } catch { dims.backup = { score: 0, grade: 'N/A' }; }

  // Revenue
  try {
    const row = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'mrr' ORDER BY date DESC LIMIT 1").get(slug);
    const mrr = row?.value || 0;
    const s = mrr > 0 ? Math.min(100, Math.round(50 + Math.log10(mrr / 100 + 1) * 30)) : 0;
    dims.revenue = { score: s, grade: letterGrade(s), mrr: mrr / 100 };
  } catch { dims.revenue = { score: 0, grade: 'N/A' }; }

  // Traffic
  try {
    const row = db.prepare("SELECT value FROM metrics_daily WHERE app_slug = ? AND metric_type = 'pageviews_30d' ORDER BY date DESC LIMIT 1").get(slug);
    const pv = row?.value || 0;
    const s = pv > 0 ? Math.min(100, Math.round(30 + Math.log10(pv + 1) * 20)) : 0;
    dims.traffic = { score: s, grade: letterGrade(s), pageviews: pv };
  } catch { dims.traffic = { score: 0, grade: 'N/A' }; }

  // SEO
  try {
    const row = db.prepare('SELECT score, grade FROM seo_audits WHERE app_slug = ? ORDER BY date DESC LIMIT 1').get(slug);
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
  } catch (err) { console.error('[OPS] Worry score cron error:', err.message); }
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
  } catch (err) { console.error('[OPS] Baseline cron error:', err.message); }
});

// Key rotation reminder (weekly Monday 9 AM)
cron.schedule('0 9 * * 1', async () => {
  try {
    const staleKeys = [];
    const baselines = db.prepare('SELECT env_hashes, timestamp FROM ops_baselines ORDER BY timestamp ASC LIMIT 1').get();
    if (!baselines) return;
    const firstSeen = safeJSON(baselines.env_hashes, {});
    const baselineAge = Math.round((Date.now() - new Date(baselines.timestamp).getTime()) / 86400000);
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
  } catch (err) { console.error('[OPS] Key rotation cron error:', err.message); }
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
  /punycode/i, /DEP0040/i, /node --trace-warnings/i
];

cron.schedule('*/5 * * * *', async () => {
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
  } catch (err) { console.error('[ERROR_SCAN] Docker log scan error:', err.message); }
});

// --- Docker Event Watcher (persistent stream) ---
let eventStream = null;

async function startEventWatcher() {
  try {
    if (eventStream) try { eventStream.destroy(); } catch {}
    eventStream = await docker.getEvents({ filters: { type: ['container'], event: ['die', 'oom', 'health_status'] } });

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
            } catch {}
            ingestError({ app: appSlug, message: `Container ${name} died with exit code ${exitCode}`, stack: lastLogs || null, severity: 'critical', source: 'docker_event', container: name });
          }
        } else if (event.Action === 'health_status: unhealthy') {
          ingestError({ app: appSlug, message: `Container ${name} health check failed`, severity: 'warning', source: 'docker_event', container: name });
        }
      } catch {}
    });

    eventStream.on('error', () => { setTimeout(startEventWatcher, 30_000); });
    eventStream.on('close', () => { setTimeout(startEventWatcher, 30_000); });
    console.log('[ERROR_WATCH] Docker event watcher started');
  } catch (err) {
    console.error('[ERROR_WATCH] Failed to start:', err.message);
    setTimeout(startEventWatcher, 30_000);
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
  } catch (err) { console.error('[PERF] Aggregation error:', err.message); }
});

// Daily 3:15 AM: Retention cleanup for error events (30d) and perf metrics (14d)
cron.schedule('15 3 * * *', () => {
  try {
    const deletedEvents = db.prepare("DELETE FROM error_events WHERE timestamp < datetime('now', '-30 days')").run();
    const deletedPerf = db.prepare("DELETE FROM perf_metrics WHERE hour < datetime('now', '-14 days')").run();
    console.log(`[CLEANUP] Pruned ${deletedEvents.changes} error events, ${deletedPerf.changes} perf metrics`);
  } catch (err) { console.error('[CLEANUP] Retention error:', err.message); }
});

// --- Error Tracking API ---

// Public: Accept error reports from apps
app.post('/api/errors/ingest', (req, res) => {
  const { app: appSlug, message, stack, severity, url, method, breadcrumbs, extra } = req.body;
  const result = ingestError({ app: appSlug, message, stack, severity, source: 'sdk', url, method, breadcrumbs, extra });
  res.status(result.ok ? 200 : 400).json(result);
});

// Public: Sentry SDK envelope compatibility
app.post('/api/errors/envelope', express.text({ type: '*/*', limit: '64kb' }), (req, res) => {
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
});

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

// Health check endpoint
app.get('/health', (_req, res) => res.send('ok'));

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`Dashboard API running on port ${port}`);
});
