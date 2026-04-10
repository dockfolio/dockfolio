// Standalone smoke test for Marketing Brain.
// Loads minimal deps, initializes a db handle, loads config, and invokes
// runBrainCycle for a specific app. Run inside the container.
// Usage: node brain-smoketest.mjs <appSlug> [--deep]
//   --deep  Run a Sonnet strategic deep-dive (~$0.07, 90-150s) instead of
//           the default Haiku tactical cycle (~$0.015, 30s)

import Database from 'better-sqlite3';
import { readFileSync, existsSync } from 'fs';
import yaml from 'js-yaml';
import registerMarketingBrainRoutes from './routes/marketing-brain.js';
import { parseEnvFile, slugify } from './utils.js';

const DB_PATH = process.env.MARKETING_DB_PATH || '/home/deploy/marketing/data.db';
const CONFIG_PATH = process.env.CONFIG_PATH || '/app/config.yml';

const args = process.argv.slice(2);
const deep = args.includes('--deep');
const appSlug = args.find(a => !a.startsWith('--'));
if (!appSlug) {
  console.error('Usage: node brain-smoketest.mjs <appSlug> [--deep]');
  process.exit(1);
}

const db = new Database(DB_PATH);
const config = yaml.load(readFileSync(CONFIG_PATH, 'utf8'));

// Use slugify() to match what the brain module expects
for (const a of config.apps) {
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

// Resolve human-friendly arg to canonical slug
const canonicalSlug = (() => {
  if (config.apps.find(a => slugify(a.name) === appSlug)) return appSlug;
  const match = config.apps.find(a => slugify(a.name) === slugify(appSlug) ||
    a.name?.toLowerCase() === appSlug.toLowerCase());
  return match ? slugify(match.name) : appSlug;
})();

console.log(`[smoketest] Running ${deep ? 'DEEP ' : ''}brain cycle for ${canonicalSlug}...`);
if (deep) {
  try {
    const ctx = brain.collectAppContextDeep(canonicalSlug);
    console.log(`[smoketest] Deep context: ${ctx.prior_briefs?.length || 0} prior briefs, ${ctx.executed_actions?.length || 0} executed w/ outcomes, ${ctx.learnings?.length || 0} learnings`);
  } catch (e) {
    console.error('[smoketest] Context collection failed:', e.message);
    process.exit(1);
  }
}
try {
  const result = await brain.runBrainCycle(canonicalSlug, deep
    ? { model: 'claude-sonnet-4-5-20250929', deep: true }
    : {});
  console.log('[smoketest] SUCCESS');
  console.log(JSON.stringify(result, null, 2));

  // Pull actions for this brief
  const actions = db.prepare('SELECT kind, title, priority, impact, effort, status, outcome FROM marketing_actions WHERE brief_id = ? ORDER BY priority DESC').all(result.briefId);
  console.log(`\n[smoketest] ${actions.length} actions created (${result.autoExecuted || 0} auto-executed):`);
  for (const a of actions) {
    const tag = a.status === 'executed' ? ' EXECUTED' : '';
    console.log(`  [p${a.priority} ${a.impact}/${a.effort}]${tag} ${a.kind}: ${a.title}`);
    if (a.outcome) console.log(`       outcome: ${a.outcome}`);
  }
} catch (e) {
  console.error('[smoketest] FAILED:', e.message);
  console.error(e.stack);
  process.exit(1);
}
