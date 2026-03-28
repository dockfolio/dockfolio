import { asyncRoute } from '../utils.js';

export default function registerHetznerRoutes({ app, getSetting, TIMEOUT_STANDARD }) {
  app.get('/api/hetzner/server', asyncRoute(async (_req, res) => {
    const apiToken = getSetting('HETZNER_API_TOKEN') || process.env.HETZNER_API_TOKEN;
    if (!apiToken) return res.status(503).json({ error: 'Hetzner API token not configured. Set HETZNER_API_TOKEN in Settings.' });

    try {
      const r = await fetch('https://api.hetzner.cloud/v1/servers', {
        headers: { Authorization: `Bearer ${apiToken}` },
        signal: AbortSignal.timeout(TIMEOUT_STANDARD),
      });
      if (!r.ok) return res.status(r.status).json({ error: `Hetzner API error: ${r.status}` });
      const data = await r.json();
      const servers = (data.servers || []).map(s => ({
        id: s.id, name: s.name, status: s.status,
        serverType: s.server_type?.description || s.server_type?.name,
        cores: s.server_type?.cores, memory: s.server_type?.memory, disk: s.server_type?.disk,
        datacenter: s.datacenter?.description || s.datacenter?.name,
        ip: s.public_net?.ipv4?.ip,
        created: s.created,
        monthlyCost: s.server_type?.prices?.find(p => p.location === s.datacenter?.location?.name)?.price_monthly?.gross,
      }));
      res.json({ servers });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }));

  app.get('/api/hetzner/metrics', asyncRoute(async (req, res) => {
    const apiToken = getSetting('HETZNER_API_TOKEN') || process.env.HETZNER_API_TOKEN;
    if (!apiToken) return res.status(503).json({ error: 'Hetzner API token not configured' });

    const serverId = req.query.server_id || getSetting('HETZNER_SERVER_ID');
    if (!serverId) return res.status(400).json({ error: 'server_id required (set HETZNER_SERVER_ID in Settings)' });

    const type = req.query.type || 'cpu';
    const ALLOWED_TYPES = ['cpu', 'disk', 'network'];
    if (!ALLOWED_TYPES.includes(type)) return res.status(400).json({ error: `type must be one of: ${ALLOWED_TYPES.join(', ')}` });

    const end = new Date().toISOString();
    const start = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    try {
      const r = await fetch(`https://api.hetzner.cloud/v1/servers/${serverId}/metrics?type=${type}&start=${start}&end=${end}`, {
        headers: { Authorization: `Bearer ${apiToken}` },
        signal: AbortSignal.timeout(TIMEOUT_STANDARD),
      });
      if (!r.ok) return res.status(r.status).json({ error: `Hetzner metrics error: ${r.status}` });
      const data = await r.json();
      res.json({ type, metrics: data.metrics, start, end });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }));
}
