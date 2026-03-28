import { readFileSync } from 'fs';
import { execSync } from 'child_process';
import { asyncRoute, containerName } from '../utils.js';

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

export default function registerTroubleshootRoutes({ app, docker, findAppBySlug, auditLog, getDiskParts, TIMEOUT_STANDARD }) {
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
                await fetch(`https://${appDef.domain}/`, { method: 'HEAD', signal: AbortSignal.timeout(10000) });
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

    const failures = results.filter(r => r.status === 'fail');
    const warnings = results.filter(r => r.status === 'warn');
    const verdict = failures.length > 0 ? 'issues-found' : warnings.length > 0 ? 'warnings' : 'healthy';

    auditLog(req, 'troubleshoot', flowId, { appSlug, verdict });
    res.json({ flow: flowId, flowName: flow.name, app: appDef?.name || null, results, verdict, timestamp: new Date().toISOString() });
  }));

  app.get('/api/troubleshoot/flows', (_req, res) => {
    const flows = Object.entries(TROUBLESHOOT_FLOWS).map(([id, flow]) => ({
      id, name: flow.name, stepCount: flow.steps.length,
    }));
    res.json({ flows });
  });
}
