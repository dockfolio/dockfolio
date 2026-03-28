import { asyncRoute, slugify, containerName, callAnthropic, assertSafePath } from '../utils.js';
import { execSync } from 'child_process';

export default function registerSnapshotRoutes({ app, db, docker, config, resolveContainerApp, auditLog, getAnthropicKey, cbAnthropic, TIMEOUT_STANDARD }) {

  // --- Schema ---
  db.exec(`
    CREATE TABLE IF NOT EXISTS deploy_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_slug TEXT NOT NULL,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      commits TEXT,
      summary TEXT,
      container_name TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_deploy_log_app ON deploy_log(app_slug, timestamp);
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_slug TEXT NOT NULL,
      container_name TEXT NOT NULL,
      image_id TEXT NOT NULL,
      image_tag TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      label TEXT,
      auto INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_snapshots_app ON snapshots(app_slug, created_at);
  `);

  // Auto-snapshot: capture current image before deploy
  async function snapshotContainer(cName, appSlug, label) {
    try {
      const containers = await docker.listContainers({ all: true });
      const target = containers.find(c => containerName(c) === cName);
      if (!target) return null;
      const inspect = await docker.getContainer(target.Id).inspect();
      const imageId = inspect.Image;
      const imageTag = inspect.Config?.Image || target.Image;
      db.prepare('INSERT INTO snapshots (app_slug, container_name, image_id, image_tag, label, auto) VALUES (?, ?, ?, ?, ?, ?)')
        .run(appSlug, cName, imageId, imageTag, label || 'auto', label ? 0 : 1);
      console.log(`[SNAPSHOT] Captured ${cName} -> ${imageTag} (${imageId.slice(0, 12)})`);
      return { imageId, imageTag };
    } catch (err) {
      console.error(`[SNAPSHOT] Failed for ${cName}:`, err.message);
      return null;
    }
  }

  // Detect deploys by watching for container recreate events
  async function onContainerDeploy(cName) {
    let appSlug = null, repoPath = null;
    for (const appDef of config.apps) {
      if (appDef.containers && appDef.containers.some(cn => cName.includes(cn) || cn.includes(cName))) {
        appSlug = appDef.slug;
        repoPath = appDef.repo;
        break;
      }
    }
    if (!appSlug || !repoPath) return;

    const recent = db.prepare("SELECT id FROM deploy_log WHERE app_slug = ? AND timestamp > datetime('now', '-5 minutes')").get(appSlug);
    if (recent) return;

    // Auto-snapshot before logging deploy
    await snapshotContainer(cName, appSlug, 'pre-deploy').catch(() => {});

    // Read recent git commits from the repo
    let commits = [];
    try {
      assertSafePath(repoPath);
      const gitLog = execSync(
        `cd "${repoPath}" && git log --oneline --no-decorate -10 2>/dev/null`,
        { timeout: TIMEOUT_STANDARD }
      ).toString().trim();
      commits = gitLog.split('\n').filter(Boolean).map(line => {
        const [hash, ...rest] = line.split(' ');
        return { hash, message: rest.join(' ') };
      });
    } catch { /* repo may not have git */ }

    // AI summary (best-effort)
    let summary = '';
    if (commits.length > 0) {
      try {
        const anthropicKey = getAnthropicKey();
        if (anthropicKey) {
          const ai = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
            maxTokens: 150, timeout: TIMEOUT_STANDARD,
            system: 'Generate a brief, user-facing changelog entry (2-3 bullet points) from these git commits. Focus on what changed for users, not implementation details. No markdown headers.',
            messages: [{ role: 'user', content: commits.map(c => c.message).join('\n') }],
          }));
          summary = ai.text;
        }
      } catch { /* AI unavailable */ }
    }

    db.prepare('INSERT INTO deploy_log (app_slug, container_name, commits, summary) VALUES (?, ?, ?, ?)')
      .run(appSlug, cName, JSON.stringify(commits), summary);

    console.log(`[CHANGELOG] Deploy detected: ${appSlug} (${commits.length} commits)`);
  }

  // GET /api/snapshots — List snapshots per app
  app.get('/api/snapshots', asyncRoute((_req, res) => {
    const slug = _req.query.app;
    const limit = Math.min(parseInt(_req.query.limit) || 50, 200);
    const snapshots = slug
      ? db.prepare('SELECT * FROM snapshots WHERE app_slug = ? ORDER BY created_at DESC LIMIT ?').all(slug, limit)
      : db.prepare('SELECT * FROM snapshots ORDER BY created_at DESC LIMIT ?').all(limit);
    res.json({ snapshots });
  }));

  // POST /api/snapshots — Create a manual snapshot
  app.post('/api/snapshots', asyncRoute(async (req, res) => {
    const { container, label } = req.body;
    if (!container) return res.status(400).json({ error: 'container is required' });

    const resolved = resolveContainerApp(container);
    const appSlug = resolved?.slug || 'unknown';
    const result = await snapshotContainer(container, appSlug, label || 'manual');
    if (!result) return res.status(404).json({ error: 'Container not found or not inspectable' });

    auditLog(req, 'snapshot.create', container, { label, imageTag: result.imageTag });
    res.json({ ok: true, imageId: result.imageId, imageTag: result.imageTag });
  }));

  // POST /api/snapshots/:id/rollback — Rollback to a snapshot
  app.post('/api/snapshots/:id/rollback', asyncRoute(async (req, res) => {
    const snapshot = db.prepare('SELECT * FROM snapshots WHERE id = ?').get(req.params.id);
    if (!snapshot) return res.status(404).json({ error: 'Snapshot not found' });

    // Snapshot current state first
    await snapshotContainer(snapshot.container_name, snapshot.app_slug, 'pre-rollback');

    const containers = await docker.listContainers({ all: true });
    const target = containers.find(c => containerName(c) === snapshot.container_name);
    if (!target) return res.status(404).json({ error: `Container ${snapshot.container_name} not found` });

    const rollbackTag = `${snapshot.container_name}:rollback-${snapshot.id}`;
    try {
      const image = docker.getImage(snapshot.image_id);
      await image.tag({ repo: snapshot.container_name, tag: `rollback-${snapshot.id}` });
    } catch (err) {
      return res.status(400).json({ error: `Cannot find image ${snapshot.image_id.slice(0, 12)}. It may have been pruned.` });
    }

    auditLog(req, 'snapshot.rollback', snapshot.container_name, { snapshotId: snapshot.id, imageTag: snapshot.image_tag });

    res.json({
      ok: true,
      message: `Image tagged as ${rollbackTag}. To complete rollback, run: docker compose up -d ${snapshot.container_name}`,
      snapshot: { id: snapshot.id, container: snapshot.container_name, imageTag: snapshot.image_tag, imageId: snapshot.image_id },
      rollbackTag,
    });
  }));

  // GET /api/deploys — deploy history
  app.get('/api/deploys', asyncRoute((_req, res) => {
    const slug = _req.query.app;
    const limit = parseInt(_req.query.limit) || 20;
    const deploys = slug
      ? db.prepare('SELECT * FROM deploy_log WHERE app_slug = ? ORDER BY timestamp DESC LIMIT ?').all(slug, limit)
      : db.prepare('SELECT * FROM deploy_log ORDER BY timestamp DESC LIMIT ?').all(limit);
    for (const d of deploys) {
      try { d.commits = JSON.parse(d.commits); } catch { d.commits = []; }
    }
    res.json({ deploys });
  }));

  return { snapshotContainer, onContainerDeploy };
}
