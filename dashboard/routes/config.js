import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'fs';
import { dirname } from 'path';
import { execSync } from 'child_process';
import yaml from 'js-yaml';
import { asyncRoute, slugify, parseEnvFile, serializeEnvVars, maskValue, assertSafePath } from '../utils.js';

const STRIPE_API = 'https://api.stripe.com/v1';

export default function registerConfigRoutes({
  app, config, configPath,
  findAppBySlug, getSetting,
  SENSITIVE_PATTERN, INTEGRATION_KEYS, INTEGRATION_KEY_SET,
  upsertSettingStmt, deleteSettingStmt,
  TIMEOUT_STANDARD, TIMEOUT_HEAVY,
}) {

  // --- Env cache state ---
  let cachedKeyHealth = null;
  let lastKeyHealthUpdate = 0;
  const KEY_HEALTH_TTL = 300_000;

  // =============================================
  // Environment Variable Management
  // =============================================

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

  app.put('/api/apps/:slug/env', asyncRoute((req, res) => {
    const appDef = findAppBySlug(req.params.slug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });
    if (!appDef.envFile) return res.status(400).json({ error: 'No env file configured' });

    const { changes, deletes } = req.body;
    if (!changes && !deletes) return res.status(400).json({ error: 'No changes provided' });

    const bakPath = appDef.envFile + '.bak';
    if (existsSync(appDef.envFile)) {
      copyFileSync(appDef.envFile, bakPath);
    }

    const vars = parseEnvFile(appDef.envFile);
    const varMap = new Map(vars.map(v => [v.key, v.value]));

    if (changes) {
      for (const [key, value] of Object.entries(changes)) {
        const oldValue = varMap.get(key);
        varMap.set(key, value);
        console.log(`[ENV] ${appDef.name}: ${key} ${oldValue !== undefined ? 'updated' : 'added'}`);
      }
    }

    if (deletes) {
      for (const key of deletes) {
        if (varMap.has(key)) {
          varMap.delete(key);
          console.log(`[ENV] ${appDef.name}: ${key} deleted`);
        }
      }
    }

    const newVars = Array.from(varMap.entries()).map(([key, value]) => ({ key, value }));
    writeFileSync(appDef.envFile, serializeEnvVars(newVars), 'utf8');

    res.json({ ok: true, message: `Updated ${appDef.name} env file` });
  }));

  app.get('/api/env/diff', asyncRoute((req, res) => {
    const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));
    if (appsWithEnv.length === 0) return res.json({ apps: [], keys: {}, warnings: [] });

    const appSlugs = appsWithEnv.map(a => a.slug);
    const appEnvs = {};

    for (const appDef of appsWithEnv) {
      try {
        const vars = parseEnvFile(appDef.envFile);
        const map = {};
        for (const v of vars) {
          map[v.key] = v.value;
        }
        appEnvs[appDef.slug] = map;
      } catch (err) {
        console.error(`[ENV-DIFF] Failed to parse ${appDef.envFile}:`, err.message);
      }
    }

    const allKeys = new Set();
    for (const slug of appSlugs) {
      if (appEnvs[slug]) {
        for (const key of Object.keys(appEnvs[slug])) {
          allKeys.add(key);
        }
      }
    }

    const keys = {};
    const warnings = [];
    const sortedKeys = [...allKeys].sort();

    for (const key of sortedKeys) {
      const sensitive = SENSITIVE_PATTERN.test(key);
      const entry = {};
      const presentApps = [];
      const values = {};

      for (const slug of appSlugs) {
        if (!appEnvs[slug]) continue;
        if (key in appEnvs[slug]) {
          const val = appEnvs[slug][key];
          if (sensitive) {
            entry[slug] = val ? '[set]' : '[empty]';
          } else {
            entry[slug] = val || '[empty]';
          }
          presentApps.push(slug);
          values[slug] = val;
        } else {
          entry[slug] = '[missing]';
        }
      }

      keys[key] = entry;

      if (presentApps.length >= 2) {
        for (const slug of appSlugs) {
          if (appEnvs[slug] && !(key in appEnvs[slug])) {
            warnings.push({ type: 'missing', key, app: slug });
          }
        }
      }

      if (!sensitive && presentApps.length >= 2) {
        const uniqueValues = [...new Set(presentApps.map(s => values[s]).filter(v => v))];
        if (uniqueValues.length > 1) {
          warnings.push({
            type: 'inconsistent',
            key,
            apps: presentApps,
            values: presentApps.map(s => values[s]),
          });
        }
      }
    }

    res.json({ apps: appSlugs, keys, warnings });
  }));

  // POST /api/apps/:slug/recreate — recreate container with new env
  app.post('/api/apps/:slug/recreate', asyncRoute(async (req, res) => {
    try {
      const appDef = findAppBySlug(req.params.slug);
      if (!appDef) return res.status(404).json({ error: 'App not found' });
      if (!appDef.composeFile) return res.status(400).json({ error: 'No compose file configured' });

      const projectDir = assertSafePath(dirname(appDef.composeFile));
      assertSafePath(appDef.composeFile);
      const output = execSync(
        `docker compose -f "${appDef.composeFile}" --project-directory "${projectDir}" up -d --no-build 2>&1`,
        { timeout: TIMEOUT_HEAVY }
      ).toString();

      console.log(`[RECREATE] ${appDef.name}: container recreated`);
      res.json({ ok: true, output });
    } catch (err) {
      res.status(500).json({ error: err.stderr?.toString() || err.message });
    }
  }));

  // =============================================
  // Env Health / Key Validation
  // =============================================

  async function validateKey(type, value) {
    try {
      const opts = { method: 'GET', headers: {}, signal: AbortSignal.timeout(TIMEOUT_STANDARD) };
      let url;
      if (type === 'STRIPE_SECRET_KEY') {
        url = `${STRIPE_API}/balance`;
        opts.headers['Authorization'] = 'Basic ' + Buffer.from(value + ':').toString('base64');
      } else if (type === 'ANTHROPIC_API_KEY') {
        url = 'https://api.anthropic.com/v1/models';
        opts.headers['x-api-key'] = value;
        opts.headers['anthropic-version'] = '2023-06-01';
      } else if (type === 'RESEND_API_KEY') {
        url = 'https://api.resend.com/emails';
        opts.method = 'POST';
        opts.headers['Authorization'] = `Bearer ${value}`;
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify({ from: 'test@test.com', to: 'invalid', subject: 'x', text: 'x' });
      } else {
        return null;
      }
      const response = await fetch(url, opts);
      const s = response.status;
      return (s === 200 || s === 201 || s === 422 || s === 429) ? 'valid' : 'expired';
    } catch {
      return 'error';
    }
  }

  const VALIDATABLE_KEYS = ['STRIPE_SECRET_KEY', 'ANTHROPIC_API_KEY', 'RESEND_API_KEY'];

  app.get('/api/env/health', asyncRoute(async (req, res) => {
    const now = Date.now();
    const force = req.query.force === 'true';
    if (!force && cachedKeyHealth && (now - lastKeyHealthUpdate) < KEY_HEALTH_TTL) {
      return res.json(cachedKeyHealth);
    }

    const results = {};
    const appsWithEnv = config.apps.filter(a => a.envFile && existsSync(a.envFile));

    const uniqueKeys = new Map();
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

    for (const [, entry] of uniqueKeys) {
      const status = await validateKey(entry.type, entry.value);
      if (status) {
        for (const appEntry of entry.apps) {
          if (!results[appEntry.name]) results[appEntry.name] = {};
          results[appEntry.name][appEntry.key] = { status, maskedValue: maskValue(entry.value) };
        }
      }
    }

    cachedKeyHealth = { results, timestamp: new Date().toISOString() };
    lastKeyHealthUpdate = now;
    res.json(cachedKeyHealth);
  }));

  // =============================================
  // Integration Keys (Settings DB)
  // =============================================

  app.get('/api/settings/keys', asyncRoute(async (req, res) => {
    const skipValidation = req.query.skip_validation === 'true';
    const results = [];

    for (const entry of INTEGRATION_KEYS) {
      const dbVal = getSetting(entry.key);
      const envVal = process.env[entry.key] || null;
      const appVal = (() => {
        for (const appDef of config.apps) {
          if (!appDef.envFile || !existsSync(appDef.envFile)) continue;
          const vars = parseEnvFile(appDef.envFile);
          const found = vars.find(v => v.key === entry.key && v.value);
          if (found) return found.value;
        }
        return null;
      })();

      const value = dbVal || envVal || appVal;
      const source = dbVal ? 'database' : envVal ? 'environment' : appVal ? 'app-env' : null;
      let status = value ? 'configured' : 'missing';

      if (value && entry.validatable && !skipValidation) {
        const result = await validateKey(entry.key, value);
        status = result === 'valid' ? 'valid' : result === 'expired' ? 'expired' : result === 'error' ? 'error' : 'configured';
      }

      results.push({
        key: entry.key,
        label: entry.label,
        category: entry.category,
        validatable: entry.validatable,
        hasValue: !!value,
        source,
        maskedValue: value ? maskValue(value) : null,
        status,
      });
    }

    res.json({ keys: results });
  }));

  app.put('/api/settings/keys', asyncRoute(async (req, res) => {
    const { keys } = req.body;
    if (!Array.isArray(keys)) return res.status(400).json({ error: 'keys must be an array' });

    let saved = 0;
    let deleted = 0;
    for (const { key, value } of keys) {
      if (!INTEGRATION_KEY_SET.has(key)) continue;
      if (!value || !value.trim()) {
        deleteSettingStmt.run(key);
        deleted++;
      } else {
        upsertSettingStmt.run(key, value.trim());
        saved++;
      }
    }

    res.json({ ok: true, saved, deleted });
  }));

  app.get('/api/settings/favorites', (req, res) => {
    const raw = getSetting('favorite_apps');
    const favorites = raw ? JSON.parse(raw) : [];
    res.json({ favorites });
  });

  app.put('/api/settings/favorites', asyncRoute(async (req, res) => {
    const { favorites } = req.body;
    if (!Array.isArray(favorites)) return res.status(400).json({ error: 'favorites must be an array' });
    upsertSettingStmt.run('favorite_apps', JSON.stringify(favorites));
    res.json({ ok: true, favorites });
  }));

  // =============================================
  // App Configuration CRUD
  // =============================================

  function reloadConfig() {
    const raw = readFileSync(configPath, 'utf8');
    const parsed = yaml.load(raw);
    config.apps = parsed.apps || [];
  }

  function saveConfig() {
    const yamlStr = yaml.dump({ apps: config.apps }, { lineWidth: -1, noRefs: true, quotingType: '"' });
    writeFileSync(configPath, yamlStr, 'utf8');
  }

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

  app.post('/api/config/apps', asyncRoute(async (req, res) => {
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
    res.json({ ok: true, slug: slugify(newApp.name) });
  }));

  app.post('/api/config/apps/validate', asyncRoute(async (req, res) => {
    const { name, domain, port, step } = req.body;
    const errors = [];

    if (step === undefined || step === 1) {
      if (!name || !name.trim()) {
        errors.push('App name is required');
      } else {
        const slug = slugify(name.trim());
        const existing = config.apps.find(a => slugify(a.name) === slug);
        if (existing) errors.push(`An app with slug "${slug}" already exists`);
      }
    }

    if (step === undefined || step === 2) {
      if (domain && domain.trim()) {
        try {
          const { promises: dnsPromises } = await import('dns');
          await dnsPromises.resolve4(domain.trim());
        } catch {
          errors.push(`Domain "${domain}" does not resolve (DNS lookup failed)`);
        }
      }
      if (port) {
        const portNum = Number(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
          errors.push('Port must be a number between 1 and 65535');
        } else {
          const portConflict = config.apps.find(a => a.port && Number(a.port) === portNum);
          if (portConflict) errors.push(`Port ${portNum} is already used by "${portConflict.name}"`);
        }
      }
    }

    res.json({ valid: errors.length === 0, errors });
  }));

  app.put('/api/config/apps/:slug', asyncRoute(async (req, res) => {
    const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
    if (idx === -1) return res.status(404).json({ error: 'App not found' });

    const { name, type, domain, port, health, containers, description, tech, envFile, composeFile } = req.body;
    // Validate path fields to prevent command injection via config manipulation
    const SAFE_PATH_RE = /^[a-zA-Z0-9\/_. -]+$/;
    for (const [field, val] of [['envFile', envFile], ['composeFile', composeFile]]) {
      if (val !== undefined && val && (!SAFE_PATH_RE.test(val) || val.includes('..'))) {
        return res.status(400).json({ error: `Invalid ${field}: must be a safe file path` });
      }
    }
    const appDef = config.apps[idx];
    if (name) appDef.name = name.trim();
    if (type) appDef.type = type;
    if (domain !== undefined) appDef.domain = domain;
    if (port !== undefined) appDef.port = port ? Number(port) : undefined;
    if (health !== undefined) appDef.health = health;
    if (containers) appDef.containers = Array.isArray(containers) ? containers : [];
    if (description !== undefined) appDef.description = description;
    if (tech !== undefined) appDef.tech = tech;
    if (envFile !== undefined) appDef.envFile = envFile;
    if (composeFile !== undefined) appDef.composeFile = composeFile;

    saveConfig();
    res.json({ ok: true });
  }));

  app.post('/api/config/apps/:slug/preview', asyncRoute(async (req, res) => {
    const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
    if (idx === -1) return res.status(404).json({ error: 'App not found' });

    const current = { ...config.apps[idx] };
    const changes = req.body;
    const diff = [];
    const impacts = [];

    const FIELDS = ['name', 'type', 'domain', 'port', 'health', 'containers', 'description', 'tech', 'envFile', 'composeFile'];
    for (const field of FIELDS) {
      if (changes[field] === undefined) continue;
      const oldVal = current[field];
      const newVal = field === 'port' && changes[field] ? Number(changes[field]) : changes[field];
      const oldStr = JSON.stringify(oldVal ?? null);
      const newStr = JSON.stringify(newVal ?? null);
      if (oldStr !== newStr) {
        diff.push({ field, old: oldVal ?? null, new: newVal ?? null });

        if (field === 'port') {
          const conflict = config.apps.find(a => a !== current && a.port && Number(a.port) === Number(newVal));
          if (conflict) impacts.push({ severity: 'error', message: `Port ${newVal} conflicts with ${conflict.name}` });
          else impacts.push({ severity: 'info', message: `Port change requires nginx config update` });
        }
        if (field === 'domain') {
          if (oldVal && newVal !== oldVal) impacts.push({ severity: 'warning', message: `Domain change: SSL cert + nginx config + DNS update needed` });
          if (newVal && !oldVal) impacts.push({ severity: 'info', message: `New domain: needs DNS A record + SSL cert + nginx config` });
        }
        if (field === 'containers') {
          const oldC = Array.isArray(oldVal) ? oldVal : [];
          const newC = Array.isArray(newVal) ? newVal : [];
          const removed = oldC.filter(c => !newC.includes(c));
          if (removed.length > 0) impacts.push({ severity: 'warning', message: `Removing containers: ${removed.join(', ')} — these will no longer be monitored` });
        }
        if (field === 'name') {
          impacts.push({ severity: 'info', message: `Slug will change from "${slugify(oldVal)}" to "${slugify(newVal)}"` });
        }
      }
    }

    res.json({ slug: req.params.slug, diff, impacts, hasChanges: diff.length > 0 });
  }));

  app.delete('/api/config/apps/:slug', asyncRoute(async (req, res) => {
    const idx = config.apps.findIndex(a => slugify(a.name) === req.params.slug);
    if (idx === -1) return res.status(404).json({ error: 'App not found' });
    config.apps.splice(idx, 1);
    saveConfig();
    res.json({ ok: true });
  }));

  return { getCachedKeyHealth: () => cachedKeyHealth };
}
