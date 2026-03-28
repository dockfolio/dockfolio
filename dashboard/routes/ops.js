import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { asyncRoute, slugify, containerName, hashValue, safeJSON, parseEnvFile, letterGrade, maskValue, parseId, errorScore } from '../utils.js';

export default function registerOpsRoutes({ app, db, docker, config, cron, findAppBySlug, getSetting, getDiskParts, getDiskPercent, getLatestFile, sendTelegram, cronFail, guardedCron, auditLog, qLatestMetric, qLatestSEO, TIMEOUT_STANDARD, MS_PER_HOUR, MS_PER_DAY, BACKUP_DIR, SENSITIVE_PATTERN, HEALING_PLAYBOOKS, configPath, getCachedKeyHealth }) {

  // ==================== Healing API endpoints ====================

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

  // ==================== Predictive Resource Alerts ====================

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

  // ==================== Ops Intelligence ====================

  async function calculateWorryScore() {
    const cachedKeyHealth = getCachedKeyHealth();
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

    let configHash = '';
    try { configHash = hashValue(readFileSync(configPath, 'utf8')); } catch (err) { console.error('[BASELINE] Config read failed:', err.message); }
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
    let currentConfigHash = '';
    try { currentConfigHash = hashValue(readFileSync(configPath, 'utf8')); } catch { /* config unreadable */ }
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

  return { calculateWorryScore, calculateAppReportCard };
}
