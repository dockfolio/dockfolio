import { asyncRoute, containerName, slugify, callAnthropic } from '../utils.js';

// Parse Docker image reference into registry, owner, name, tag
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

export default function registerDockerRoutes({ app, db, docker, config, auditLog, resolveContainerApp, SENSITIVE_PATTERN, TIMEOUT_STANDARD, MS_PER_HOUR }) {

  // Cache for container stats (refreshed every 30s)
  let cachedStats = null;
  let lastStatsUpdate = 0;
  const STATS_TTL = 30_000;

  // Cache for container graph
  let cachedGraph = null;
  let lastGraphUpdate = 0;
  const GRAPH_TTL = 300_000; // 5 minutes

  // Cache for image updates
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

  // GET /api/containers/stats — per-container CPU/memory usage
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

    // Safety: whitelist allowed commands (diagnostic only)
    const ALLOWED_PREFIXES = ['ls', 'cat', 'head', 'tail', 'ps', 'df', 'du', 'env', 'printenv', 'whoami', 'hostname', 'uname', 'uptime', 'free', 'top -bn1', 'netstat', 'ss', 'ip', 'ifconfig', 'ping', 'dig', 'nslookup', 'curl', 'wget', 'wc', 'find', 'grep', 'echo', 'date', 'id', 'mount', 'which', 'npm list', 'pip list', 'node -v', 'python --version'];
    const trimmedCmd = cmd.trim();
    const cmdBase = trimmedCmd.split(/\s+/)[0].toLowerCase();
    if (!ALLOWED_PREFIXES.some(p => cmdBase === p.split(/\s+/)[0])) {
      return res.status(403).json({ error: `Command '${cmdBase}' is not in the allowed list. Only diagnostic commands are permitted.` });
    }
    // Block shell operators that could chain arbitrary commands
    if (/[;&|`$()]/.test(trimmedCmd)) {
      return res.status(403).json({ error: 'Shell operators (;, &, |, `, $, parentheses) are not allowed' });
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

  // GET /api/containers/compare — ranked view of all containers by resource usage
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
}
