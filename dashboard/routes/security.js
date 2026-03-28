import { asyncRoute, slugify, containerName, parseId, safeJSON } from '../utils.js';

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

export default function registerSecurityRoutes({ app, db, docker, config, cron, resolveContainerApp, getAuditDomains, sendTelegram, cronFail, calculateAppReportCard, TIMEOUT_TLS, MS_PER_DAY }) {

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
}
