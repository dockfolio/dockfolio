import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import {
  slugify, containerName, todayString, asyncRoute, callAnthropic,
} from '../utils.js';

export default function registerAIRoutes({
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
}) {

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
  let memTotalKB = 0, memAvailKB = 0;
  try {
    const memInfo = readFileSync('/proc/meminfo', 'utf8');
    memTotalKB = parseInt(memInfo.match(/MemTotal:\s+(\d+)/)?.[1] || '0');
    memAvailKB = parseInt(memInfo.match(/MemAvailable:\s+(\d+)/)?.[1] || '0');
  } catch {}
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

// --- Cost Per App Breakdown ---
app.get('/api/costs', asyncRoute(async (_req, res) => {
  const vmCost = parseFloat(process.env.VM_COST_MONTHLY || '12.48');
  const containers = await docker.listContainers();
  // Batch all Docker stats calls in parallel
  const statsMap = new Map();
  const statsResults = await Promise.allSettled(containers.map(async c => {
    const stats = await docker.getContainer(c.Id).stats({ stream: false });
    statsMap.set(c.Id, stats);
  }));
  let totalCpu = 0;
  let totalMem = 0;
  const appCosts = [];
  for (const a of config.apps) {
    const appContainers = containers.filter(c => (a.containers || []).some(n => containerName(c).includes(n)));
    let cpuPct = 0, memPct = 0;
    for (const c of appContainers) {
      const stats = statsMap.get(c.Id);
      if (!stats) continue;
      const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - (stats.precpu_stats?.cpu_usage?.total_usage || 0);
      const sysDelta = stats.cpu_stats.system_cpu_usage - (stats.precpu_stats?.system_cpu_usage || 0);
      const cores = stats.cpu_stats.online_cpus || 1;
      if (sysDelta > 0) cpuPct += (cpuDelta / sysDelta) * cores * 100;
      if (stats.memory_stats.limit > 0) memPct += (stats.memory_stats.usage / stats.memory_stats.limit) * 100;
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

// --- AI Incident Responder ---

app.post('/api/incidents/analyze', asyncRoute(async (req, res) => {
  const { containerName: cName, appSlug } = req.body;
  if (!cName) return res.status(400).json({ error: 'containerName is required' });

  const anthropicKey = getAnthropicKey();
  if (!anthropicKey) return res.status(400).json({ error: 'No Anthropic API key configured' });

  // Gather context: logs, system metrics, healing history, uptime
  let logSnippet = '';
  try {
    const container = docker.getContainer(cName);
    const logs = await container.logs({ stdout: true, stderr: true, tail: 200 });
    logSnippet = (typeof logs === 'string' ? logs : logs.toString('utf8')).replace(/^.{8}/gm, '').trim().slice(-4000);
  } catch { logSnippet = '(Container logs unavailable)'; }

  const slug = appSlug || cName;

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

Container: ${cName}
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

} // end registerAIRoutes
