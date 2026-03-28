import { asyncRoute } from '../utils.js';

// INWX JSON-RPC API helper (session-based auth via cookies)
async function inwxCall(method, params = {}, sessionCookie = null, timeoutMs = 15000) {
  const headers = { 'Content-Type': 'application/json' };
  if (sessionCookie) headers['Cookie'] = sessionCookie;
  const res = await fetch('https://api.domrobot.com/jsonrpc/', {
    method: 'POST',
    headers,
    body: JSON.stringify({ method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const setCookie = res.headers.get('set-cookie');
  const data = await res.json();
  if (data.code !== 1000) {
    throw new Error(`INWX API error (${data.code}): ${data.msg || 'Unknown error'}`);
  }
  return { data: data.resData, cookie: setCookie || sessionCookie };
}

export default function registerDnsRoutes({ app, config, getSetting, auditLog, slugify }) {
  async function inwxSession() {
    const user = getSetting('inwx_user');
    const pass = getSetting('inwx_pass');
    if (!user || !pass) throw new Error('INWX credentials not configured. Set inwx_user and inwx_pass in Settings.');
    const result = await inwxCall('account.login', { user, pass });
    return result.cookie;
  }

  app.get('/api/dns/records', asyncRoute(async (req, res) => {
    const { domain } = req.query;
    if (!domain) return res.status(400).json({ error: 'domain parameter required' });

    let cookie;
    try {
      cookie = await inwxSession();
      const result = await inwxCall('nameserver.info', { domain }, cookie);
      const records = (result.data?.record || []).map(r => ({
        id: r.id, name: r.name, type: r.type, content: r.content,
        ttl: r.ttl, prio: r.prio || null,
      }));
      res.json({ domain, records, count: records.length });
    } catch (err) {
      res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
    } finally {
      if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
    }
  }));

  app.post('/api/dns/records', asyncRoute(async (req, res) => {
    const { domain, type, name, content, ttl, prio } = req.body;
    if (!domain || !type || !name || !content) {
      return res.status(400).json({ error: 'domain, type, name, and content are required' });
    }
    const ALLOWED_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA'];
    if (!ALLOWED_TYPES.includes(type.toUpperCase())) {
      return res.status(400).json({ error: `Invalid record type. Allowed: ${ALLOWED_TYPES.join(', ')}` });
    }

    let cookie;
    try {
      cookie = await inwxSession();
      const params = { domain, type: type.toUpperCase(), name, content, ttl: ttl || 3600 };
      if (prio !== undefined && prio !== null) params.prio = Number(prio);
      const result = await inwxCall('nameserver.createRecord', params, cookie);
      auditLog(req, 'dns.create', domain, { type, name, content });
      res.json({ ok: true, id: result.data?.id });
    } catch (err) {
      res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
    } finally {
      if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
    }
  }));

  app.put('/api/dns/records/:id', asyncRoute(async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid record ID' });
    const { content, ttl, prio } = req.body;
    if (!content) return res.status(400).json({ error: 'content is required' });

    let cookie;
    try {
      cookie = await inwxSession();
      const params = { id, content };
      if (ttl) params.ttl = ttl;
      if (prio !== undefined && prio !== null) params.prio = Number(prio);
      await inwxCall('nameserver.updateRecord', params, cookie);
      auditLog(req, 'dns.update', String(id), { content });
      res.json({ ok: true });
    } catch (err) {
      res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
    } finally {
      if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
    }
  }));

  app.delete('/api/dns/records/:id', asyncRoute(async (req, res) => {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ error: 'Invalid record ID' });

    let cookie;
    try {
      cookie = await inwxSession();
      await inwxCall('nameserver.deleteRecord', { id }, cookie);
      auditLog(req, 'dns.delete', String(id));
      res.json({ ok: true });
    } catch (err) {
      res.status(err.message.includes('not configured') ? 503 : 500).json({ error: err.message });
    } finally {
      if (cookie) inwxCall('account.logout', {}, cookie).catch(() => {});
    }
  }));

  app.get('/api/dns/validate', asyncRoute(async (req, res) => {
    const { promises: dnsPromises } = await import('dns');
    const domains = (config.apps || []).filter(a => a.domain).map(a => ({ domain: a.domain, slug: slugify(a.name) }));
    const results = [];

    for (const { domain, slug } of domains) {
      const checks = { domain, slug, a: null, www: null, reachable: null };
      try {
        const addrs = await dnsPromises.resolve4(domain);
        checks.a = { ok: addrs.includes('91.99.104.132'), addresses: addrs };
      } catch { checks.a = { ok: false, addresses: [] }; }
      try {
        const cname = await dnsPromises.resolveCname(`www.${domain}`);
        checks.www = { ok: true, target: cname[0] };
      } catch {
        try {
          const addrs = await dnsPromises.resolve4(`www.${domain}`);
          checks.www = { ok: addrs.includes('91.99.104.132'), addresses: addrs };
        } catch { checks.www = { ok: false }; }
      }
      checks.reachable = checks.a?.ok || false;
      results.push(checks);
    }

    res.json({ results, server_ip: '91.99.104.132' });
  }));
}
