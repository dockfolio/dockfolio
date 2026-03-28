import { createHmac, timingSafeEqual } from 'crypto';
import { execSync } from 'child_process';
import { dirname } from 'path';
import { asyncRoute, slugify, assertSafePath, safeJSON } from '../utils.js';

const GITHUB_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function parseGitHubRepo(repoField) {
  if (!repoField) return null;
  // Handle full URLs: https://github.com/owner/repo or git@github.com:owner/repo
  const urlMatch = repoField.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?$/);
  if (urlMatch) return `${urlMatch[1]}/${urlMatch[2]}`;
  // Handle owner/repo format
  if (/^[\w.-]+\/[\w.-]+$/.test(repoField)) return repoField;
  return null;
}

async function fetchGitHubData(ownerRepo, token, TIMEOUT_STANDARD) {
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'Dockfolio' };
  if (token) headers.Authorization = `Bearer ${token}`;

  const ghFetch = (url) => fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) }).then(r => {
    if (!r.ok) throw new Error(`GitHub API ${r.status}: ${r.statusText}`);
    return r.json();
  });

  const [repoInfo, commits, pulls, actionsRuns] = await Promise.allSettled([
    ghFetch(`https://api.github.com/repos/${ownerRepo}`),
    ghFetch(`https://api.github.com/repos/${ownerRepo}/commits?per_page=5`),
    ghFetch(`https://api.github.com/repos/${ownerRepo}/pulls?state=open&per_page=100`),
    ghFetch(`https://api.github.com/repos/${ownerRepo}/actions/runs?per_page=1`),
  ]);

  return {
    repo: ownerRepo,
    openIssues: repoInfo.status === 'fulfilled' ? (repoInfo.value.open_issues_count || 0) : null,
    defaultBranch: repoInfo.status === 'fulfilled' ? repoInfo.value.default_branch : 'main',
    stars: repoInfo.status === 'fulfilled' ? repoInfo.value.stargazers_count : null,
    commits: commits.status === 'fulfilled' ? commits.value.map(c => ({
      sha: c.sha?.slice(0, 7),
      message: c.commit?.message?.split('\n')[0]?.slice(0, 80),
      author: c.commit?.author?.name,
      date: c.commit?.author?.date,
    })) : [],
    openPRs: pulls.status === 'fulfilled' ? pulls.value.length : null,
    ci: actionsRuns.status === 'fulfilled' && actionsRuns.value.workflow_runs?.length > 0 ? {
      status: actionsRuns.value.workflow_runs[0].status,
      conclusion: actionsRuns.value.workflow_runs[0].conclusion,
      name: actionsRuns.value.workflow_runs[0].name,
      updated: actionsRuns.value.workflow_runs[0].updated_at,
    } : null,
  };
}

export default function registerGitHubRoutes({ app, config, db, getSetting, auditLog, sendTelegram, cbGitHub, TIMEOUT_STANDARD, TIMEOUT_BUILD }) {
  const ghCacheGet = db.prepare('SELECT data_json, fetched_at FROM github_cache WHERE app_slug = ?');
  const ghCacheUpsert = db.prepare('INSERT OR REPLACE INTO github_cache (app_slug, data_json, fetched_at) VALUES (?, ?, datetime(\'now\'))');

  async function getGitHubForApp(slug, repoField, token) {
    // Check cache (5 min TTL)
    const cached = ghCacheGet.get(slug);
    if (cached) {
      const age = Date.now() - new Date(cached.fetched_at + 'Z').getTime();
      if (age < GITHUB_CACHE_TTL) return safeJSON(cached.data_json, {});
    }

    const ownerRepo = parseGitHubRepo(repoField);
    if (!ownerRepo) return null;

    const data = await cbGitHub.call(() => fetchGitHubData(ownerRepo, token, TIMEOUT_STANDARD));
    ghCacheUpsert.run(slug, JSON.stringify(data));
    return data;
  }

  function matchRepoToApp(repoFullName) {
    if (!repoFullName) return null;
    for (const appDef of config.apps) {
      if (appDef.repo === repoFullName || appDef.repo === `https://github.com/${repoFullName}` || appDef.repo?.endsWith('/' + repoFullName)) {
        return slugify(appDef.name);
      }
    }
    return null;
  }

  // ========== GITHUB WEBHOOK (auto-deploy) ==========

  app.post('/api/webhooks/github', asyncRoute(async (req, res) => {
    const WEBHOOK_SECRET = getSetting('GITHUB_WEBHOOK_SECRET') || process.env.GITHUB_WEBHOOK_SECRET;
    if (!WEBHOOK_SECRET) return res.status(500).json({ error: 'Webhook secret not configured' });
    const sig = req.headers['x-hub-signature-256'];
    if (!sig || !req.rawBody) return res.status(401).json({ error: 'Invalid signature' });
    const expected = 'sha256=' + createHmac('sha256', WEBHOOK_SECRET).update(req.rawBody).digest('hex');
    const sigBuf = Buffer.from(sig);
    const expectedBuf = Buffer.from(expected);
    if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) return res.status(401).json({ error: 'Invalid signature' });
    const event = req.headers['x-github-event'];
    const payload = req.body;
    if (event === 'push' && (payload.ref === 'refs/heads/main' || payload.ref === 'refs/heads/master')) {
      const appSlug = matchRepoToApp(payload.repository?.full_name);
      if (!appSlug) return res.json({ ok: true, skipped: 'no matching app' });
      auditLog(req, 'github_deploy', appSlug, { commit: payload.head_commit?.id?.slice(0, 7), message: payload.head_commit?.message });
      console.log(`[DEPLOY] GitHub push to ${appSlug}: ${payload.head_commit?.message}`);
      const appDef = config.apps.find(a => slugify(a.name) === appSlug);
      if (appDef?.composePath) {
        try {
          const dir = assertSafePath(dirname(appDef.composePath));
          execSync(`cd "${dir}" && git pull && docker compose up -d --build`, { timeout: TIMEOUT_BUILD });
          sendTelegram(`Deploy complete: ${appSlug} (${payload.head_commit?.id?.slice(0, 7)})`);
        } catch (err) {
          console.error(`[DEPLOY] ${appSlug} failed:`, err.message);
          sendTelegram(`Deploy FAILED: ${appSlug} — ${err.message.slice(0, 200)}`);
        }
      }
      res.json({ ok: true, deploying: appSlug });
    } else {
      res.json({ ok: true, event, skipped: true });
    }
  }));

  // ========== GITHUB DEEP INTEGRATION ==========

  app.get('/api/github/summary', asyncRoute(async (_req, res) => {
    const token = getSetting('GITHUB_TOKEN') || process.env.GITHUB_TOKEN;
    const results = [];

    for (const appDef of config.apps) {
      const slug = slugify(appDef.name);
      const ghRepo = parseGitHubRepo(appDef.repo);
      if (!ghRepo) continue;

      try {
        const data = await getGitHubForApp(slug, appDef.repo, token);
        if (data) results.push({ slug, name: appDef.name, ...data });
      } catch (err) {
        // Return cached data on error, or partial result
        const cached = ghCacheGet.get(slug);
        if (cached) {
          results.push({ slug, name: appDef.name, ...safeJSON(cached.data_json, {}), stale: true });
        } else {
          results.push({ slug, name: appDef.name, repo: ghRepo, error: err.message });
        }
      }
    }

    res.json({ apps: results, hasToken: !!token, timestamp: new Date().toISOString() });
  }));

  app.get('/api/github/app/:slug', asyncRoute(async (req, res) => {
    const token = getSetting('GITHUB_TOKEN') || process.env.GITHUB_TOKEN;
    const appDef = config.apps.find(a => slugify(a.name) === req.params.slug);
    if (!appDef) return res.status(404).json({ error: 'App not found' });

    const ghRepo = parseGitHubRepo(appDef.repo);
    if (!ghRepo) return res.status(404).json({ error: 'No GitHub repo configured for this app' });

    try {
      const data = await getGitHubForApp(req.params.slug, appDef.repo, token);
      res.json({ slug: req.params.slug, name: appDef.name, ...data, hasToken: !!token });
    } catch (err) {
      const cached = ghCacheGet.get(req.params.slug);
      if (cached) {
        res.json({ slug: req.params.slug, name: appDef.name, ...safeJSON(cached.data_json, {}), stale: true, hasToken: !!token });
      } else {
        res.status(502).json({ error: err.message });
      }
    }
  }));
}
