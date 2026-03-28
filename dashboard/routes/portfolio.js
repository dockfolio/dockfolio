import { asyncRoute, slugify, letterGrade, parseEnvFile, callAnthropic } from '../utils.js';
import { existsSync } from 'fs';

export default function registerPortfolioRoutes({
  app, db, docker, config, cron,
  qLatestMetric, qLatestSEO,
  calculateAppReportCard,
  getSetting, setSetting,
  getAnthropicKey, getPlausibleUrl, getPlausibleApiKey,
  cbAnthropic,
  sendTelegram, cronFail, guardedCron, addNotification,
  marketingCache,
  TIMEOUT_STANDARD, MS_PER_HOUR, MS_PER_DAY,
}) {

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

  // --- App Health Scores ---
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
    const totalVMCost = 12.00;

    let totalMemAlloc = 0;
    const appMemUsage = {};
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      let memMB = appDef.containers?.length ? appDef.containers.length * 80 : 10;
      appMemUsage[slug] = memMB;
      totalMemAlloc += memMB;
    }

    let totalRevenue = 0, totalCosts = 0;

    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const mrrRow = qLatestMetric.get(slug, 'mrr');
      const mrr = (mrrRow?.value || 0) / 100;

      const memShare = totalMemAlloc > 0 ? (appMemUsage[slug] / totalMemAlloc) : 0;
      const infraCost = +(totalVMCost * memShare).toFixed(2);
      const domainCost = appDef.domain ? 1.00 : 0;

      let apiCost = 0;
      if (appDef.envFile && existsSync(appDef.envFile)) {
        const vars = parseEnvFile(appDef.envFile);
        const hasStripe = vars.some(v => v.key.includes('STRIPE') && v.value);
        const hasAI = vars.some(v => (v.key.includes('ANTHROPIC') || v.key.includes('OPENAI')) && v.value);
        const hasResend = vars.some(v => v.key.includes('RESEND') && v.value);
        if (hasStripe) apiCost += 0.50;
        if (hasAI) apiCost += 1.00;
        if (hasResend) apiCost += 0.50;
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
        costs: { infra: infraCost, domain: domainCost, api: apiCost, total: totalAppCost },
        profit,
        profitable: profit > 0,
      });
    }

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

  // --- Weekly Portfolio Report Card ---
  app.get('/api/portfolio/report', asyncRoute((_req, res) => {
    const cards = config.apps.map(a => calculateAppReportCard(slugify(a.name))).filter(Boolean);

    const avgScore = cards.length > 0 ? Math.round(cards.reduce((s, c) => s + c.overall, 0) / cards.length) : 0;
    const gradeDistribution = { A: 0, B: 0, C: 0, D: 0, F: 0 };
    for (const c of cards) {
      const g = c.grade.charAt(0);
      if (gradeDistribution[g] !== undefined) gradeDistribution[g]++;
    }

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

  // Weekly report card cron — every Monday at 8 AM
  cron.schedule('0 8 * * 1', guardedCron('weekly-report', async () => {
    try {
      const cards = config.apps.map(a => calculateAppReportCard(slugify(a.name))).filter(Boolean);
      const avgScore = cards.length > 0 ? Math.round(cards.reduce((s, c) => s + c.overall, 0) / cards.length) : 0;
      const grade = letterGrade(avgScore);
      const sorted = [...cards].sort((a, b) => b.overall - a.overall);
      const top = sorted[0];
      const weak = sorted[sorted.length - 1];

      let msg = `\ud83d\udcca <b>Weekly Portfolio Report</b>\n`;
      msg += `\nOverall: <b>${grade}</b> (${avgScore}/100)`;
      msg += `\nApps: ${cards.length}`;
      if (top) msg += `\n\u2b50 Top: ${top.name} (${top.grade}, ${top.overall}/100)`;
      if (weak && weak.overall < 60) msg += `\n\u26a0\ufe0f Needs attention: ${weak.name} (${weak.grade}, ${weak.overall}/100)`;

      const grades = cards.map(c => `${c.name}: ${c.grade}`).join(', ');
      msg += `\n\n${grades}`;

      sendTelegram(msg);
      addNotification('ops', 'info', `Weekly Report: ${grade} (${avgScore}/100)`, msg);
    } catch (err) { cronFail('Weekly report', err); }
  }));

  // Uptime streak celebration — daily at 10 AM
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

        if ([7, 30, 60, 90].includes(streak)) {
          sendTelegram(`\ud83c\udfc6 ${appDef.name}: ${streak}-day uptime streak!`);
          addNotification('ops', 'info', `${appDef.name}: ${streak}-day uptime streak!`, null, slug);
        }
      }
    } catch (err) { cronFail('Streak celebrate', err); }
  }));

  // Cron health check — hourly
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
      sendTelegram(`\u26a0\ufe0f Overdue cron jobs: ${overdue.join(', ')}\nCheck /api/cron/status for details`);
    }
  }));

  // --- Revenue Milestones ---
  const revenueMilestonesChecked = new Set();

  app.get('/api/revenue/milestones', asyncRoute((_req, res) => {
    const milestones = [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
    const result = [];

    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const row = qLatestMetric.get(slug, 'mrr');
      const mrr = (row?.value || 0) / 100;

      const achieved = milestones.filter(m => mrr >= m);
      const nextMilestone = milestones.find(m => mrr < m) || null;
      const progress = nextMilestone ? +(mrr / nextMilestone * 100).toFixed(1) : 100;

      if (mrr > 0) {
        result.push({ slug, name: appDef.name, mrr: +mrr.toFixed(2), achieved, nextMilestone, progress });
      }
    }

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
            const celebrated = getSetting(`milestone:${key}`);
            if (!celebrated) {
              setSetting(`milestone:${key}`, new Date().toISOString());
              sendTelegram(`\ud83c\udf89 <b>Revenue Milestone!</b>\n${appDef.name} crossed \u20ac${m} MRR!\nCurrent: \u20ac${mrr.toFixed(0)}`);
              addNotification('revenue', 'info', `${appDef.name} crossed \u20ac${m} MRR!`, `Current MRR: \u20ac${mrr.toFixed(0)}`, slug);
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
      for (const metric of ALLOWED_ANOMALY_METRICS) {
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
          sendTelegram(`\ud83d\udcca <b>Anomaly Detected</b>\n${label}: ${zscore.toFixed(1)}\u03c3 above 7-day average\nCurrent vs avg: check /api/anomalies`);
        }
      }
    } catch (err) { cronFail('Anomaly check', err); }
  }));

  // --- Cron Job Monitoring ---
  app.get('/api/cron/status', asyncRoute((_req, res) => {
    const jobs = [];

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
      'Every 5 min': 10 * 60 * 1000,
      'Every 15 min': 30 * 60 * 1000,
      'Hourly': 2 * 60 * 60 * 1000,
      'Every 6h': 12 * 60 * 60 * 1000,
      'Daily 1 AM': 36 * 60 * 60 * 1000,
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

      jobs.push({ name: check.name, schedule: check.schedule, lastRun, status });
    }

    const overdueJobs = jobs.filter(j => j.status === 'overdue');
    res.json({
      jobs,
      healthy: overdueJobs.length === 0,
      overdueCount: overdueJobs.length,
      timestamp: new Date().toISOString(),
    });
  }));

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

  // --- "What If" Simulator ---
  app.post('/api/whatif', asyncRoute(async (req, res) => {
    const { scenario } = req.body;
    if (!scenario) return res.status(400).json({ error: 'scenario is required' });

    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return res.status(400).json({ error: 'No Anthropic API key configured' });

    const appSummaries = [];
    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const mrr = qLatestMetric.get(slug, 'mrr')?.value || 0;
      const pv = qLatestMetric.get(slug, 'pageviews_30d')?.value || 0;
      const containers = appDef.containers || [];

      let memMB = 0, cpuPct = 0;
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
        name: appDef.name, slug, domain: appDef.domain, type: appDef.type || 'unknown',
        containers: containers.length, mrrEUR: (mrr / 100).toFixed(2), monthlyVisitors: pv,
        memoryMB: Math.round(memMB), cpuPercent: cpuPct.toFixed(1),
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
        maxTokens: 600, timeout: 15000,
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
      let firstDeploy = null;
      try {
        const firstActivity = db.prepare("SELECT MIN(date) as first_date FROM metrics WHERE app_slug = ?").get(slug);
        firstDeploy = firstActivity?.first_date || null;
      } catch { /* no data */ }

      let firstRevenue = null;
      try {
        const row = db.prepare("SELECT MIN(date) as first_date FROM metrics WHERE app_slug = ? AND metric = 'mrr' AND value > 0").get(slug);
        firstRevenue = row?.first_date || null;
      } catch { /* no data */ }

      const currentMRR = qLatestMetric.get(slug, 'mrr')?.value || 0;

      if (firstDeploy || firstRevenue || currentMRR > 0) {
        let daysToRevenue = null;
        if (firstDeploy && firstRevenue) {
          const d1 = new Date(firstDeploy);
          const d2 = new Date(firstRevenue);
          daysToRevenue = Math.max(0, Math.round((d2 - d1) / (1000 * 60 * 60 * 24)));
        }

        results.push({
          name: appDef.name, slug, firstDeploy, firstRevenue, daysToRevenue,
          currentMRR: +(currentMRR / 100).toFixed(2),
          status: currentMRR > 0 ? 'monetized' : firstDeploy ? 'pre-revenue' : 'no-data',
        });
      }
    }

    results.sort((a, b) => {
      if (a.status === 'monetized' && b.status !== 'monetized') return -1;
      if (b.status === 'monetized' && a.status !== 'monetized') return 1;
      if (a.daysToRevenue != null && b.daysToRevenue != null) return a.daysToRevenue - b.daysToRevenue;
      return 0;
    });

    const avgDays = results.filter(r => r.daysToRevenue != null);
    const avgTimeToRevenue = avgDays.length > 0 ? Math.round(avgDays.reduce((s, r) => s + r.daysToRevenue, 0) / avgDays.length) : null;

    res.json({
      apps: results, avgTimeToRevenue,
      monetizedCount: results.filter(r => r.status === 'monetized').length,
      totalApps: results.length,
      timestamp: new Date().toISOString(),
    });
  }));

  // --- Achievement System ---
  const ACHIEVEMENTS = [
    { id: 'first-deploy', name: 'First Deploy', desc: 'Deploy an app for the first time', icon: '\ud83d\ude80', check: () => db.prepare("SELECT COUNT(*) as c FROM healing_log WHERE action_taken LIKE '%restart%'").get().c > 0 },
    { id: 'security-hawk', name: 'Security Hawk', desc: 'Security score > 90 for any app', icon: '\ud83d\udee1\ufe0f', check: () => {
      for (const appDef of config.apps) { const rc = calculateAppReportCard(slugify(appDef.name)); if (rc?.dimensions?.security?.score > 90) return true; } return false;
    }},
    { id: 'revenue-10', name: 'First Tenner', desc: 'Reach 10 EUR MRR on any app', icon: '\ud83d\udcb0', check: () => {
      for (const appDef of config.apps) { const r = qLatestMetric.get(slugify(appDef.name), 'mrr'); if (r?.value >= 1000) return true; } return false;
    }},
    { id: 'revenue-100', name: 'Triple Digits', desc: 'Reach 100 EUR MRR on any app', icon: '\ud83d\udc8e', check: () => {
      for (const appDef of config.apps) { const r = qLatestMetric.get(slugify(appDef.name), 'mrr'); if (r?.value >= 10000) return true; } return false;
    }},
    { id: 'revenue-1000', name: 'Four Figures', desc: 'Reach 1,000 EUR MRR portfolio-wide', icon: '\ud83d\udc51', check: () => {
      let total = 0; for (const appDef of config.apps) { const r = qLatestMetric.get(slugify(appDef.name), 'mrr'); total += r?.value || 0; } return total >= 100000;
    }},
    { id: 'uptime-7', name: 'Steady Ship', desc: '7-day uptime streak on any app', icon: '\ud83d\udd25', check: () => {
      const row = db.prepare("SELECT MAX(streak_days) as m FROM (SELECT app_slug, COUNT(*) as streak_days FROM uptime_history WHERE status = 'up' GROUP BY app_slug)").get();
      return (row?.m || 0) >= 7;
    }},
    { id: 'uptime-30', name: 'Iron Uptime', desc: '30-day uptime streak', icon: '\u26a1', check: () => {
      const row = db.prepare("SELECT MAX(streak_days) as m FROM (SELECT app_slug, COUNT(*) as streak_days FROM uptime_history WHERE status = 'up' GROUP BY app_slug)").get();
      return (row?.m || 0) >= 30;
    }},
    { id: 'portfolio-5', name: 'Portfolio Builder', desc: 'Run 5+ apps', icon: '\ud83d\udce6', check: () => config.apps.length >= 5 },
    { id: 'portfolio-10', name: 'App Empire', desc: 'Run 10+ apps', icon: '\ud83c\udff0', check: () => config.apps.length >= 10 },
    { id: 'healer', name: 'Self-Healer', desc: 'Auto-healing has fixed 10+ issues', icon: '\ud83d\udd27', check: () => db.prepare("SELECT COUNT(*) as c FROM healing_log WHERE result = 'executed'").get().c >= 10 },
    { id: 'night-owl', name: 'Night Owl', desc: 'Activity logged between midnight and 5 AM', icon: '\ud83e\udd89', check: () => db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE CAST(strftime('%H', created_at) AS INTEGER) < 5").get().c > 0 },
    { id: 'clean-sweep', name: 'Clean Sweep', desc: 'All apps have security grade A or B', icon: '\u2728', check: () => {
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
      unlocked, locked,
      total: ACHIEVEMENTS.length,
      earned: unlocked.length,
      timestamp: new Date().toISOString(),
    });
  }));

  // --- Build in Public Generator ---
  app.get('/api/build-in-public', asyncRoute(async (_req, res) => {
    const anthropicKey = getAnthropicKey();
    if (!anthropicKey) return res.status(400).json({ error: 'No Anthropic API key configured' });

    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const healingEvents = db.prepare("SELECT COUNT(*) as c FROM healing_log WHERE timestamp > ?").get(weekAgo).c;
    const auditEvents = db.prepare("SELECT COUNT(*) as c FROM audit_log WHERE created_at > ?").get(weekAgo).c;
    const securityFindings = db.prepare("SELECT COUNT(*) as c FROM security_findings WHERE created_at > ?").get(weekAgo).c;

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
        maxTokens: 400, timeout: 15000,
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
}
