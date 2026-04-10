// Standalone smoke test for Marketing Brain.
// Loads minimal deps, initializes a db handle, loads config, and invokes
// runBrainCycle for a specific app. Run inside the container.
// Usage: node brain-smoketest.mjs <appSlug>

import Database from 'better-sqlite3';
import { readFileSync, existsSync } from 'fs';
import yaml from 'js-yaml';
import registerMarketingBrainRoutes from './routes/marketing-brain.js';
import { parseEnvFile } from './utils.js';

const DB_PATH = process.env.MARKETING_DB_PATH || '/home/deploy/marketing/data.db';
const CONFIG_PATH = process.env.CONFIG_PATH || '/app/config.yml';

const appSlug = process.argv[2];
if (!appSlug) {
  console.error('Usage: node brain-smoketest.mjs <appSlug>');
  process.exit(1);
}

const db = new Database(DB_PATH);
const config = yaml.load(readFileSync(CONFIG_PATH, 'utf8'));

// Backfill slug field
for (const a of config.apps) {
  if (!a.slug) a.slug = (a.name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  if (a.envFile && !existsSync(a.envFile)) a.envFile = null;
}

// Minimal env-key lookup across app .env files
function getEnvKeyFromApps(key) {
  for (const a of config.apps) {
    if (!a.envFile || !existsSync(a.envFile)) continue;
    try {
      const vars = parseEnvFile(a.envFile);
      const found = vars.find(v => v.key === key && v.value);
      if (found) return found.value;
    } catch {}
  }
  return null;
}

// Fake express app that collects route registrations
const fakeApp = {};
for (const m of ['get', 'post', 'patch', 'put', 'delete']) fakeApp[m] = () => {};

// Fake cron that captures schedules but doesn't run them
const fakeCron = { schedule: () => {} };

// Fake circuit breaker that just calls through
const cbAnthropic = { call: async (fn) => fn() };

const brain = registerMarketingBrainRoutes({
  app: fakeApp, db, config, cron: fakeCron,
  marketingCache: {},
  getEnvKeyFromApps,
  cbAnthropic,
  cronFail: () => {},
  sendTelegram: () => {},
});

console.log(`[smoketest] Running brain cycle for ${appSlug}...`);
try {
  const result = await brain.runBrainCycle(appSlug);
  console.log('[smoketest] SUCCESS');
  console.log(JSON.stringify(result, null, 2));

  // Pull actions for this brief
  const actions = db.prepare('SELECT kind, title, priority, impact, effort FROM marketing_actions WHERE brief_id = ? ORDER BY priority DESC').all(result.briefId);
  console.log(`\n[smoketest] ${actions.length} actions created:`);
  for (const a of actions) console.log(`  [p${a.priority} ${a.impact}/${a.effort}] ${a.kind}: ${a.title}`);
} catch (e) {
  console.error('[smoketest] FAILED:', e.message);
  console.error(e.stack);
  process.exit(1);
}
