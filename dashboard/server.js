import express from 'express';
import Docker from 'dockerode';
import { readFileSync, writeFileSync, copyFileSync, existsSync, mkdirSync, statSync, readdirSync } from 'fs';
import yaml from 'js-yaml';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { createHash, randomUUID } from 'crypto';
import Database from 'better-sqlite3';
import cron from 'node-cron';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const docker = new Docker({ socketPath: '/var/run/docker.sock' });

// Load app config
const configPath = join(__dirname, 'config.yml');
const config = yaml.load(readFileSync(configPath, 'utf8'));

// Cache for container stats (refreshed every 30s)
let cachedStats = null;
let lastStatsUpdate = 0;
const STATS_TTL = 30_000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());

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
const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/setup', '/api/auth/status', '/health', '/api/health', '/api/crosspromo', '/api/banners'];

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

function slugify(name) {
  return name.toLowerCase().replace(/\s+/g, '-');
}

function findAppBySlug(slug) {
  return config.apps.find(a => slugify(a.name) === slug);
}

function getBannerForgeUrl() {
  if (process.env.BANNERFORGE_URL) return process.env.BANNERFORGE_URL;
  const bf = config.apps.find(a => slugify(a.name) === 'bannerforge');
  if (bf?.port) return `http://localhost:${bf.port}/api/render`;
  return null;
}

function parseEnvFile(filePath) {
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
    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    vars.push({ key, value });
  }
  return vars;
}

function maskValue(value) {
  if (!value || value.length <= 12) return '***';
  return value.slice(0, 8) + '...' + value.slice(-4);
}

function serializeEnvVars(vars) {
  return vars.map(v => `${v.key}=${v.value}`).join('\n') + '\n';
}

// GET /api/apps — all apps with their container status
app.get('/api/apps', async (_req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    const containerMap = new Map();
    for (const c of containers) {
      const name = c.Names[0]?.replace(/^\//, '');
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/system — system metrics
app.get('/api/system', async (_req, res) => {
  try {
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
    const dfOutput = execSync('df -B1 / | tail -1').toString().trim();
    const dfParts = dfOutput.split(/\s+/);
    const diskTotal = parseInt(dfParts[1], 10);
    const diskUsed = parseInt(dfParts[2], 10);

    // Load average
    const loadavg = readFileSync('/proc/loadavg', 'utf8').split(' ');
    const cpuCount = parseInt(execSync('nproc').toString().trim(), 10);

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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/containers/stats — container resource usage
app.get('/api/containers/stats', async (_req, res) => {
  try {
    const now = Date.now();
    if (cachedStats && (now - lastStatsUpdate) < STATS_TTL) {
      return res.json(cachedStats);
    }

    const containers = await docker.listContainers();
    const stats = {};

    await Promise.all(containers.map(async (c) => {
      const name = c.Names[0]?.replace(/^\//, '');
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/containers/:name/logs — last N lines of container logs
app.get('/api/containers/:name/logs', async (req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    const target = containers.find(c => c.Names[0]?.replace(/^\//, '') === req.params.name);
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/docker/overview — Docker disk usage summary
app.get('/api/docker/overview', async (_req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/containers/:name/restart — restart a container
app.post('/api/containers/:name/restart', async (req, res) => {
  try {
    const containers = await docker.listContainers({ all: true });
    const target = containers.find(c => c.Names[0]?.replace(/^\//, '') === req.params.name);
    if (!target) return res.status(404).json({ error: 'Container not found' });

    const container = docker.getContainer(target.Id);
    await container.restart({ t: 10 });
    res.json({ ok: true, message: `Container ${req.params.name} restarted` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

app.get('/api/uptime', async (_req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ssl — check SSL certificate expiry for all domains
let cachedSSL = null;
let lastSSLUpdate = 0;
const SSL_TTL = 3600_000; // 1 hour

app.get('/api/ssl', async (_req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

app.get('/api/disk', async (_req, res) => {
  try {
    const now = Date.now();
    if (cachedDisk && (now - lastDiskUpdate) < DISK_TTL) {
      return res.json(cachedDisk);
    }

    const [containers, images] = await Promise.all([
      docker.listContainers({ all: true, size: true }),
      docker.listImages(),
    ]);

    const containerSizes = containers.map(c => ({
      name: c.Names[0]?.replace(/^\//, ''),
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/actions/prune — clean up Docker resources
app.post('/api/actions/prune', async (_req, res) => {
  try {
    const result = {};
    const pruneContainers = await docker.pruneContainers();
    result.containers = pruneContainers.ContainersDeleted?.length || 0;

    const pruneImages = await docker.pruneImages();
    result.images = pruneImages.ImagesDeleted?.length || 0;
    result.spaceReclaimed = pruneImages.SpaceReclaimed || 0;

    result.buildCache = execSync('docker builder prune -f 2>&1 | tail -1').toString().trim();

    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/discover — auto-discover Docker containers not in config
app.get('/api/discover', async (_req, res) => {
  try {
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
      const name = c.Names[0]?.replace(/^\//, '');
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/backups — backup status for all apps
app.get('/api/backups', (_req, res) => {
  try {
    const backupRoot = process.env.BACKUP_DIR || '/home/deploy/backups';
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
        const files = execSync(`ls -lt "${dir}" 2>/dev/null | grep -E '\\.(sql\\.gz|gz)$'`).toString().trim().split('\n').filter(Boolean);
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
app.get('/api/marketing/seo', async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/marketing/overview — combined marketing overview
app.get('/api/marketing/overview', (_req, res) => {
  try {
    const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const overview = marketableApps.map(appDef => ({
      name: appDef.name,
      type: appDef.type,
      domain: appDef.domain,
      description: appDef.description,
      marketing: appDef.marketing || null,
      hasEnvFile: !!appDef.envFile,
    }));
    res.json({ apps: overview });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Environment Variable Management ---

// GET /api/apps/:slug/env — read env vars for an app
app.get('/api/apps/:slug/env', (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/apps/:slug/env — update env vars
app.put('/api/apps/:slug/env', (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

app.get('/api/env/health', async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/env/shared — detect shared keys across apps
app.get('/api/env/shared', (_req, res) => {
  try {
    const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));
    // Map: hash -> { key, maskedValue, apps[] }
    const hashMap = new Map();

    for (const appDef of appsWithEnv) {
      const vars = parseEnvFile(appDef.envFile);
      for (const v of vars) {
        if (!SENSITIVE_PATTERN.test(v.key) || !v.value) continue;
        const hash = createHash('sha256').update(v.value).digest('hex');
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

const MARKETING_DB_PATH = process.env.MARKETING_DB_PATH || '/home/deploy/marketing/data.db';
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

app.get('/api/marketing/revenue', async (req, res) => {
  try {
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
    const today = new Date().toISOString().slice(0, 10);
    try {
      upsertMetric.run('_total', today, 'mrr', totalMRR / 100, null);
      upsertMetric.run('_total', today, 'revenue_30d', totalRevenue30d / 100, null);
      for (const [appName, data] of Object.entries(results)) {
        if (data.mrr != null) upsertMetric.run(slugify(appName), today, 'mrr', data.mrr / 100, null);
      }
    } catch {}

    res.json(cachedRevenue);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

app.get('/api/marketing/analytics', async (req, res) => {
  try {
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
    const today = new Date().toISOString().slice(0, 10);
    try {
      upsertMetric.run('_total', today, 'visitors', totalVisitors, null);
      upsertMetric.run('_total', today, 'pageviews', totalPageviews, null);
      for (const [appName, data] of Object.entries(results)) {
        if (data.visitors != null) upsertMetric.run(slugify(appName), today, 'visitors', data.visitors, null);
      }
    } catch {}

    res.json(cachedAnalytics);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/marketing/trends — historical metric data from SQLite
app.get('/api/marketing/trends', (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/marketing/health — portfolio health scores
app.get('/api/marketing/health', async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Cron: collect data periodically ---
// Every 6 hours: collect revenue + analytics
cron.schedule('0 */6 * * *', async () => {
  console.log('[CRON] Collecting revenue data...');
  try {
    const { keys, appKeys } = getStripeKeys();
    const today = new Date().toISOString().slice(0, 10);
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

// Daily at 2 AM: run SEO audits and store
cron.schedule('0 2 * * *', async () => {
  console.log('[CRON] Running daily SEO audits...');
  try {
    const marketableApps = config.apps.filter(a => a.type === 'saas' || a.type === 'tool');
    const today = new Date().toISOString().slice(0, 10);
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
app.get('/api/marketing/content', (_req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/content/generate', async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/marketing/content/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

const CROSSSELL_PAIRS = [];

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
  const today = new Date().toISOString().slice(0, 10);
  let totalCustomers = 0;

  for (const [stripeKey, appNames] of keys) {
    try {
      const keyHash = createHash('sha256').update(stripeKey).digest('hex').slice(0, 16);
      const [customers, mrrMap] = await Promise.all([
        fetchStripeCustomers(stripeKey),
        fetchStripeSubscriptionsMRR(stripeKey)
      ]);

      for (const customer of customers) {
        if (!customer.email) continue;
        const emailHash = createHash('sha256').update(customer.email.toLowerCase()).digest('hex');
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
app.get('/api/marketing/cohorts', (_req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/marketing/cohorts/crosssell', (_req, res) => {
  try {
    const opportunities = CROSSSELL_PAIRS.map(pair => {
      const [appA, appB] = pair.apps;
      // Customers who use both
      const overlap = db.prepare(`
        SELECT COUNT(*) as n FROM (
          SELECT email_hash FROM customer_graph WHERE app_slug = ?
          INTERSECT
          SELECT email_hash FROM customer_graph WHERE app_slug = ?
        )
      `).get(appA, appB).n;

      // Customers who use only one (potential cross-sell targets)
      const onlyA = db.prepare(`
        SELECT COUNT(*) as n FROM customer_graph WHERE app_slug = ?
        AND email_hash NOT IN (SELECT email_hash FROM customer_graph WHERE app_slug = ?)
      `).get(appA, appB).n;
      const onlyB = db.prepare(`
        SELECT COUNT(*) as n FROM customer_graph WHERE app_slug = ?
        AND email_hash NOT IN (SELECT email_hash FROM customer_graph WHERE app_slug = ?)
      `).get(appB, appA).n;

      return {
        ...pair,
        existingOverlap: overlap,
        potentialReach: onlyA + onlyB,
      };
    });

    res.json({ opportunities });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
  const today = new Date().toISOString().slice(0, 10);
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
app.get('/api/marketing/emails/sequences', (_req, res) => {
  try {
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
      steps: JSON.parse(seq.steps || '[]'),
      active: !!seq.active,
      queuedCount: countsBySeq[seq.id]?.pending || 0,
      sentCount: countsBySeq[seq.id]?.sent || 0,
    }));
    res.json({ sequences: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/marketing/emails/queue', (req, res) => {
  try {
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

    const today = new Date().toISOString().slice(0, 10);
    const dailySentToday = db.prepare(
      "SELECT COUNT(*) as n FROM email_queue WHERE status='sent' AND sent_at >= ?"
    ).get(today + 'T00:00:00Z').n;

    res.json({ queue, counts, dailySentToday, dailyLimit: 100 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/emails/send-test', async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/emails/pause/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });

    db.prepare('UPDATE email_sequences SET active = 0 WHERE id = ?').run(id);
    db.prepare("UPDATE email_queue SET status = 'paused' WHERE sequence_id = ? AND status = 'pending'").run(id);
    console.log(`[EMAIL] Sequence ${id} paused`);
    res.json({ ok: true, paused: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/emails/resume/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid sequence ID' });

    db.prepare('UPDATE email_sequences SET active = 1 WHERE id = ?').run(id);
    db.prepare("UPDATE email_queue SET status = 'pending' WHERE sequence_id = ? AND status = 'paused'").run(id);
    console.log(`[EMAIL] Sequence ${id} resumed`);
    res.json({ ok: true, active: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    const diskLine = execSync('df -B1 / | tail -1').toString().trim().split(/\s+/);
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
      unhealthy: unhealthy.map(c => c.Names[0]?.replace(/^\//, '')),
      restarting: restarting.map(c => c.Names[0]?.replace(/^\//, '')),
    };
  } catch { context.containers = { error: 'unavailable' }; }

  // Backup statuses
  try {
    const backupDir = process.env.BACKUP_DIR || '/home/deploy/backups';
    let backupApps = [];
    try {
      if (existsSync(backupDir)) {
        backupApps = readdirSync(backupDir, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name);
      }
    } catch { backupApps = []; }
    context.backups = {};
    for (const app of backupApps) {
      const dir = join(process.env.BACKUP_DIR || '/home/deploy/backups', app);
      if (!existsSync(dir)) { context.backups[app] = 'no_backups'; continue; }
      try {
        const files = execSync(`ls -t "${dir}" 2>/dev/null | head -1`).toString().trim();
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

  return context;
}

app.get('/api/briefing', async (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
        name: c.Names[0]?.replace(/^\//, ''),
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
        name: c.Names[0]?.replace(/^\//, ''),
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
        const diskLine = execSync('df / | tail -1').toString().trim().split(/\s+/);
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

            // Notify via Telegram (if configured)
            try {
              const tgToken = process.env.TELEGRAM_BOT_TOKEN;
              const tgChat = process.env.TELEGRAM_CHAT_ID;
              if (tgToken && tgChat) {
                await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ chat_id: tgChat, text: `🔧 Auto-Healing: ${playbook.condition}\nApp: ${appSlug}\nAction: ${result}`, parse_mode: 'HTML' }),
                  signal: AbortSignal.timeout(5000),
                });
              }
            } catch { /* Telegram notification best-effort */ }
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
app.get('/api/healing/log', (_req, res) => {
  try {
    const limit = parseInt(_req.query.limit) || 50;
    const logs = db.prepare('SELECT * FROM healing_log ORDER BY timestamp DESC LIMIT ?').all(limit);
    const pending = db.prepare("SELECT COUNT(*) as n FROM healing_log WHERE result = 'pending'").get().n;
    res.json({ logs, pending });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/healing/approve/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/healing/dismiss/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare("UPDATE healing_log SET result = 'dismissed' WHERE id = ? AND result = 'pending'").run(id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    const name = c.Names[0]?.replace(/^\//, '');
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
    const name = c.Names[0]?.replace(/^\//, '');
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

app.get('/api/security/scan', async (req, res) => {
  try {
    const result = await runSecurityScan(req.query.category || 'full');
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/security/status', (_req, res) => {
  try {
    const scan = db.prepare('SELECT * FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
    if (!scan) return res.json({ status: 'no_scan', message: 'No security scan has been run yet' });
    const findings = db.prepare(`SELECT * FROM security_findings WHERE scan_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`).all(scan.id);
    res.json({ ...scan, category_scores: JSON.parse(scan.category_scores || '{}'), findings });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/security/history', (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 30;
    const scans = db.prepare('SELECT * FROM security_scans ORDER BY timestamp DESC LIMIT ?').all(limit);
    res.json(scans.map(s => ({ ...s, category_scores: JSON.parse(s.category_scores || '{}') })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/security/app/:slug', (req, res) => {
  try {
    const scan = db.prepare('SELECT * FROM security_scans ORDER BY timestamp DESC LIMIT 1').get();
    if (!scan) return res.json({ findings: [] });
    const findings = db.prepare('SELECT * FROM security_findings WHERE scan_id = ? AND app_slug = ?').all(scan.id, req.params.slug);
    res.json({ scan_id: scan.id, app_slug: req.params.slug, findings });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/security/dismiss/:id', (req, res) => {
  try {
    db.prepare("UPDATE security_findings SET status = 'dismissed', dismissed_at = datetime('now') WHERE id = ?").run(parseInt(req.params.id));
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

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
      const tgToken = process.env.TELEGRAM_BOT_TOKEN;
      const tgChat = process.env.TELEGRAM_CHAT_ID;
      if (tgToken && tgChat) {
        const msg = `Security: SSL Alert - ${critical.map(f => f.title).join(', ')}`;
        await fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, { method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: tgChat, text: msg }), signal: AbortSignal.timeout(5000) }).catch(() => {});
      }
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
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.sendStatus(204);
});
app.options('/api/crosspromo/:id/:action', (_req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.sendStatus(204);
});

// --- Authenticated endpoints (admin manages campaigns) ---

app.get('/api/marketing/crosspromo', (_req, res) => {
  try {
    const campaigns = db.prepare('SELECT * FROM crosspromo_campaigns ORDER BY created_at DESC').all();
    campaigns.forEach(c => { if (c.banner_data) c.banner_data = JSON.parse(c.banner_data); });
    res.json(campaigns);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/crosspromo', async (req, res) => {
  try {
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
    if (campaign.banner_data) campaign.banner_data = JSON.parse(campaign.banner_data);
    res.json(campaign);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/marketing/crosspromo/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const { status } = req.body;
    if (!['draft', 'active', 'paused', 'ended'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    db.prepare('UPDATE crosspromo_campaigns SET status = ?, updated_at = datetime(\'now\') WHERE id = ?').run(status, id);
    const campaign = db.prepare('SELECT * FROM crosspromo_campaigns WHERE id = ?').get(id);
    if (!campaign) return res.status(404).json({ error: 'Not found' });
    if (campaign.banner_data) campaign.banner_data = JSON.parse(campaign.banner_data);
    res.json(campaign);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/marketing/crosspromo/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const result = db.prepare('DELETE FROM crosspromo_campaigns WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Public endpoints (no auth — served to external sites) ---

app.get('/api/crosspromo/embed.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.setHeader('Access-Control-Allow-Origin', '*');
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

app.get('/api/crosspromo/banner', (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const app = req.query.app;
    if (!app) return res.status(400).json({ error: 'app query param required' });
    // Find an active campaign where this app is the source (showing the banner)
    const campaign = db.prepare(
      'SELECT id, headline, cta_text, cta_url, banner_data FROM crosspromo_campaigns WHERE source_app = ? AND status = \'active\' ORDER BY created_at DESC LIMIT 1'
    ).get(app);
    if (!campaign) return res.json(null);
    if (campaign.banner_data) campaign.banner_data = JSON.parse(campaign.banner_data);
    res.json(campaign);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/crosspromo/:id/view', (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare('UPDATE crosspromo_campaigns SET views = views + 1 WHERE id = ?').run(id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/crosspromo/:id/click', (req, res) => {
  try {
    const id = parseInt(req.params.id);
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
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.sendStatus(204);
});
app.options('/api/banners/:id/:action', (_req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.sendStatus(204);
});

// --- Authenticated banner endpoints ---

app.get('/api/marketing/banners', (_req, res) => {
  try {
    const banners = db.prepare('SELECT * FROM banners ORDER BY created_at DESC').all();
    const placements = db.prepare('SELECT * FROM banner_placements ORDER BY created_at DESC').all();
    banners.forEach(b => {
      if (b.bannerforge_config) try { b.bannerforge_config = JSON.parse(b.bannerforge_config); } catch (_) { b.bannerforge_config = null; }
      b.placements = placements.filter(p => p.banner_id === b.id);
      b.total_views = b.placements.reduce((s, p) => s + p.views, 0);
      b.total_clicks = b.placements.reduce((s, p) => s + p.clicks, 0);
    });
    res.json(banners);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/banners', async (req, res) => {
  try {
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
    if (banner.bannerforge_config) try { banner.bannerforge_config = JSON.parse(banner.bannerforge_config); } catch (_) { banner.bannerforge_config = null; }
    banner.placements = [];
    banner.total_views = 0;
    banner.total_clicks = 0;
    res.json(banner);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/marketing/banners/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    if (!banner) return res.status(404).json({ error: 'Not found' });

    const { name, click_url, tags } = req.body;
    db.prepare(`UPDATE banners SET name = ?, click_url = ?, tags = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(name || banner.name, click_url !== undefined ? click_url : banner.click_url, tags !== undefined ? tags : banner.tags, id);
    const updated = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    if (updated.bannerforge_config) try { updated.bannerforge_config = JSON.parse(updated.bannerforge_config); } catch (_) { updated.bannerforge_config = null; }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/marketing/banners/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare('DELETE FROM banner_placements WHERE banner_id = ?').run(id);
    const result = db.prepare('DELETE FROM banners WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/banners/:id/regenerate', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const banner = db.prepare('SELECT * FROM banners WHERE id = ?').get(id);
    if (!banner) return res.status(404).json({ error: 'Not found' });
    if (banner.type !== 'bannerforge') return res.status(400).json({ error: 'Only BannerForge banners can be regenerated' });

    let bfc = {};
    if (banner.bannerforge_config) try { bfc = JSON.parse(banner.bannerforge_config); } catch (_) {}
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
    if (updated.bannerforge_config) try { updated.bannerforge_config = JSON.parse(updated.bannerforge_config); } catch (_) { updated.bannerforge_config = null; }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Placement endpoints ---

app.get('/api/marketing/placements', (req, res) => {
  try {
    const appFilter = req.query.app;
    let placements;
    if (appFilter) {
      placements = db.prepare('SELECT bp.*, b.name as banner_name, b.type as banner_type, b.width, b.height FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id WHERE bp.app_slug = ? ORDER BY bp.priority DESC, bp.created_at DESC').all(appFilter);
    } else {
      placements = db.prepare('SELECT bp.*, b.name as banner_name, b.type as banner_type, b.width, b.height FROM banner_placements bp JOIN banners b ON bp.banner_id = b.id ORDER BY bp.priority DESC, bp.created_at DESC').all();
    }
    res.json(placements);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/placements', (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/marketing/placements/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/marketing/placements/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const result = db.prepare('DELETE FROM banner_placements WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Public banner serve endpoints ---

app.get('/api/banners/embed.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.setHeader('Access-Control-Allow-Origin', '*');
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

app.get('/api/banners/serve', (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/banners/:placementId/view', (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    const id = parseInt(req.params.placementId);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    db.prepare('UPDATE banner_placements SET views = views + 1 WHERE id = ?').run(id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/banners/:placementId/click', (req, res) => {
  try {
    const id = parseInt(req.params.placementId);
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
app.get('/api/banners/injection-status', async (_req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================
// Marketing Playbook
// =============================================

app.get('/api/marketing/playbooks', (req, res) => {
  try {
    const appSlug = req.query.app;
    let entries;
    if (appSlug) {
      entries = db.prepare('SELECT * FROM marketing_playbooks WHERE app_slug = ? ORDER BY section, priority DESC, created_at').all(appSlug);
    } else {
      entries = db.prepare('SELECT * FROM marketing_playbooks ORDER BY app_slug, section, priority DESC, created_at').all();
    }
    res.json(entries);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/marketing/playbooks', (req, res) => {
  try {
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/marketing/playbooks/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const entry = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(id);
    if (!entry) return res.status(404).json({ error: 'Not found' });

    const { title, content, status, priority } = req.body;
    db.prepare(`UPDATE marketing_playbooks SET title = ?, content = ?, status = ?, priority = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(title || entry.title, content || entry.content, status || entry.status, priority !== undefined ? parseInt(priority) : entry.priority, id);

    const updated = db.prepare('SELECT * FROM marketing_playbooks WHERE id = ?').get(id);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/marketing/playbooks/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
    const result = db.prepare('DELETE FROM marketing_playbooks WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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

    const bundles = CROSSSELL_PAIRS.filter(p => p.apps.includes(slugify(appDef.name)))
      .map(p => `${p.label}: ${p.apps.join(' + ')} (${p.reason})`).join('\n');

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
${bundles ? `\nCross-sell bundles:\n${bundles}` : ''}

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

// Health check endpoint
app.get('/health', (_req, res) => res.send('ok'));

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`Dashboard API running on port ${port}`);
});
