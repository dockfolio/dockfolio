import { asyncRoute, callAnthropic, todayString } from '../utils.js';

/**
 * Social Autopilot — automated content posting + mention monitoring
 *
 * Platforms (posting):  X/Twitter, Bluesky, Mastodon, Dev.to
 * Platforms (monitoring): Reddit (read-only), Hacker News (read-only)
 * Content: AI-generated via Claude Haiku, stored in SQLite queue
 *
 * Config keys (settings table):
 *   TWITTER_APP_KEY, TWITTER_APP_SECRET, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET
 *   BLUESKY_HANDLE, BLUESKY_APP_PASSWORD
 *   MASTODON_INSTANCE, MASTODON_ACCESS_TOKEN
 *   DEVTO_API_KEY
 */

// --- Platform adapters ---

async function postToTwitter(getSetting, text, timeout) {
  const appKey = getSetting('TWITTER_APP_KEY');
  const appSecret = getSetting('TWITTER_APP_SECRET');
  const accessToken = getSetting('TWITTER_ACCESS_TOKEN');
  const accessSecret = getSetting('TWITTER_ACCESS_SECRET');
  if (!appKey || !appSecret || !accessToken || !accessSecret) return { ok: false, error: 'Twitter not configured' };

  // OAuth 1.0a signature — use twitter-api-v2 if installed, else skip
  try {
    const { TwitterApi } = await import('twitter-api-v2');
    const client = new TwitterApi({ appKey, appSecret, accessToken, accessSecret });
    const { data } = await client.v2.tweet(text);
    return { ok: true, id: data.id, url: `https://x.com/i/status/${data.id}` };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function postToBluesky(getSetting, text, timeout) {
  const handle = getSetting('BLUESKY_HANDLE');
  const password = getSetting('BLUESKY_APP_PASSWORD');
  if (!handle || !password) return { ok: false, error: 'Bluesky not configured' };

  try {
    const { BskyAgent, RichText } = await import('@atproto/api');
    const agent = new BskyAgent({ service: 'https://bsky.social' });
    await agent.login({ identifier: handle, password });
    const rt = new RichText({ text });
    await rt.detectFacets(agent);
    const res = await agent.post({ text: rt.text, facets: rt.facets });
    return { ok: true, uri: res.uri };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function postToMastodon(getSetting, text, timeout) {
  const instance = getSetting('MASTODON_INSTANCE');
  const token = getSetting('MASTODON_ACCESS_TOKEN');
  if (!instance || !token) return { ok: false, error: 'Mastodon not configured' };

  try {
    const res = await fetch(`${instance}/api/v1/statuses`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: text, visibility: 'public' }),
      signal: AbortSignal.timeout(timeout),
    });
    if (!res.ok) throw new Error(`Mastodon ${res.status}`);
    const data = await res.json();
    return { ok: true, id: data.id, url: data.url };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function postToDevTo(getSetting, title, markdown, tags, canonicalUrl, timeout) {
  const apiKey = getSetting('DEVTO_API_KEY');
  if (!apiKey) return { ok: false, error: 'Dev.to not configured' };

  try {
    const res = await fetch('https://dev.to/api/articles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'api-key': apiKey },
      body: JSON.stringify({
        article: {
          title,
          body_markdown: markdown,
          published: true,
          tags: (tags || []).slice(0, 4),
          canonical_url: canonicalUrl || undefined,
        },
      }),
      signal: AbortSignal.timeout(timeout),
    });
    if (!res.ok) throw new Error(`Dev.to ${res.status}`);
    const data = await res.json();
    return { ok: true, id: data.id, url: data.url };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// --- Monitoring adapters ---

async function searchReddit(subreddit, query, timeout) {
  try {
    const url = `https://www.reddit.com/r/${subreddit}/search.json?q=${encodeURIComponent(query)}&sort=new&t=week&restrict_sr=on&limit=10`;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Dockfolio-Monitor/1.0' },
      signal: AbortSignal.timeout(timeout),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return (data?.data?.children || []).map(c => ({
      id: c.data.id,
      title: c.data.title,
      selftext: (c.data.selftext || '').slice(0, 500),
      url: `https://reddit.com${c.data.permalink}`,
      subreddit: c.data.subreddit,
      created: c.data.created_utc,
      score: c.data.score,
      num_comments: c.data.num_comments,
    }));
  } catch {
    return [];
  }
}

async function searchHackerNews(query, timeout) {
  try {
    const since = Math.floor(Date.now() / 1000) - 86400; // last 24h
    const url = `https://hn.algolia.com/api/v1/search_by_date?query=${encodeURIComponent(query)}&tags=story&numericFilters=created_at_i>${since}&hitsPerPage=10`;
    const res = await fetch(url, { signal: AbortSignal.timeout(timeout) });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.hits || []).map(h => ({
      id: h.objectID,
      title: h.title,
      url: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
      hn_url: `https://news.ycombinator.com/item?id=${h.objectID}`,
      points: h.points,
      num_comments: h.num_comments,
      created: h.created_at,
    }));
  } catch {
    return [];
  }
}

// --- Content generation ---

async function generateSocialContent(anthropicKey, appContext, cbAnthropic, timeout) {
  const prompt = `Generate 4 social media posts for a solo developer's product portfolio. Context:
${appContext}

Generate exactly 4 posts as JSON array. Each post has: platform (twitter/bluesky/mastodon/linkedin), text, hashtags.
Rules:
- Twitter: max 270 chars (leave room for link), punchy, 1-2 hashtags
- Bluesky: max 290 chars, similar to twitter
- Mastodon: max 490 chars, slightly more technical, include hashtags
- LinkedIn: 2-3 short paragraphs, professional tone, end with a question

Mix content types: tip, behind-the-scenes, product highlight, industry insight.
Output ONLY the JSON array, no other text.`;

  const result = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
    messages: [{ role: 'user', content: prompt }],
    maxTokens: 1024,
    timeout,
  }));

  try {
    const cleaned = result.text.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    return JSON.parse(cleaned);
  } catch {
    return [];
  }
}

// --- Main module ---

export default function registerSocialAutopilotRoutes({
  app, db, config, cron,
  getSetting, getEnvKeyFromApps,
  cbAnthropic,
  cronFail, sendTelegram,
  TIMEOUT_STANDARD, TIMEOUT_AI,
}) {

  // --- Tables ---
  db.exec(`
    CREATE TABLE IF NOT EXISTS social_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      platform TEXT NOT NULL,
      content TEXT NOT NULL,
      post_type TEXT DEFAULT 'short',
      status TEXT DEFAULT 'queued',
      scheduled_at TEXT,
      posted_at TEXT,
      external_id TEXT,
      external_url TEXT,
      error TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS social_mentions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      external_id TEXT NOT NULL UNIQUE,
      title TEXT,
      url TEXT,
      snippet TEXT,
      score INTEGER DEFAULT 0,
      num_comments INTEGER DEFAULT 0,
      keywords_matched TEXT,
      response_draft TEXT,
      status TEXT DEFAULT 'new',
      found_at TEXT DEFAULT (datetime('now'))
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS social_accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      platform TEXT NOT NULL UNIQUE,
      enabled INTEGER DEFAULT 0,
      last_posted_at TEXT,
      posts_today INTEGER DEFAULT 0,
      daily_limit INTEGER DEFAULT 3
    )
  `);

  // Ensure platform rows exist
  const upsertAccount = db.prepare(`INSERT OR IGNORE INTO social_accounts (platform) VALUES (?)`);
  for (const p of ['twitter', 'bluesky', 'mastodon', 'devto', 'linkedin']) {
    upsertAccount.run(p);
  }

  // --- Prepared statements ---
  const queuePost = db.prepare(`INSERT INTO social_posts (platform, content, post_type, status, scheduled_at) VALUES (?, ?, ?, 'queued', ?)`);
  const getQueued = db.prepare(`SELECT * FROM social_posts WHERE status = 'queued' AND (scheduled_at IS NULL OR scheduled_at <= datetime('now')) ORDER BY created_at ASC LIMIT 10`);
  const markPosted = db.prepare(`UPDATE social_posts SET status = 'posted', posted_at = datetime('now'), external_id = ?, external_url = ? WHERE id = ?`);
  const markFailed = db.prepare(`UPDATE social_posts SET status = 'failed', error = ? WHERE id = ?`);
  const getMentions = db.prepare(`SELECT * FROM social_mentions WHERE status = ? ORDER BY found_at DESC LIMIT ?`);
  const insertMention = db.prepare(`INSERT OR IGNORE INTO social_mentions (source, external_id, title, url, snippet, score, num_comments, keywords_matched) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  const updateMentionStatus = db.prepare(`UPDATE social_mentions SET status = ? WHERE id = ?`);
  const updateMentionDraft = db.prepare(`UPDATE social_mentions SET response_draft = ? WHERE id = ?`);
  const getAccount = db.prepare(`SELECT * FROM social_accounts WHERE platform = ?`);
  const updateAccount = db.prepare(`UPDATE social_accounts SET enabled = ?, daily_limit = ? WHERE platform = ?`);
  const bumpPostCount = db.prepare(`UPDATE social_accounts SET posts_today = posts_today + 1, last_posted_at = datetime('now') WHERE platform = ?`);
  const resetDailyCounts = db.prepare(`UPDATE social_accounts SET posts_today = 0`);

  // --- Monitoring config ---
  const MONITOR_SUBREDDITS = [
    { sub: 'selfhosted', keywords: ['docker dashboard', 'self-hosted dashboard', 'dockfolio', 'portainer alternative'] },
    { sub: 'Finanzen', keywords: ['gehaltsrechner', 'gehalt prüfen', 'lohnabrechnung', 'abfindung berechnen'] },
    { sub: 'StudiumDE', keywords: ['abschlussarbeit', 'bachelorarbeit check', 'thesis feedback'] },
    { sub: 'arbeitsleben', keywords: ['gehalt verhandeln', 'bewerbungsfoto', 'salary negotiation germany'] },
    { sub: 'docker', keywords: ['docker dashboard', 'docker gui', 'container management'] },
    { sub: 'webdev', keywords: ['self-hosted', 'docker dashboard', 'saas dashboard'] },
  ];

  const MONITOR_HN_QUERIES = [
    'docker dashboard', 'self-hosted dashboard', 'solopreneur tools',
    'indie hacker infrastructure', 'salary calculator germany',
  ];

  // --- API Routes ---

  // GET /api/social/posts — list posts (queued, posted, failed)
  app.get('/api/social/posts', asyncRoute(async (req, res) => {
    const status = req.query.status || 'all';
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    let rows;
    if (status === 'all') {
      rows = db.prepare('SELECT * FROM social_posts ORDER BY created_at DESC LIMIT ?').all(limit);
    } else {
      rows = db.prepare('SELECT * FROM social_posts WHERE status = ? ORDER BY created_at DESC LIMIT ?').all(status, limit);
    }
    res.json(rows);
  }));

  // POST /api/social/posts — manually queue a post
  app.post('/api/social/posts', asyncRoute(async (req, res) => {
    const { platform, content, post_type, scheduled_at } = req.body;
    if (!platform || !content) return res.status(400).json({ error: 'platform and content required' });
    const validPlatforms = ['twitter', 'bluesky', 'mastodon', 'devto', 'linkedin'];
    if (!validPlatforms.includes(platform)) return res.status(400).json({ error: `platform must be one of: ${validPlatforms.join(', ')}` });
    const info = queuePost.run(platform, content.trim(), post_type || 'short', scheduled_at || null);
    res.json({ id: info.lastInsertRowid, status: 'queued' });
  }));

  // POST /api/social/posts/:id/publish — manually publish a queued post
  app.post('/api/social/posts/:id/publish', asyncRoute(async (req, res) => {
    const post = db.prepare('SELECT * FROM social_posts WHERE id = ?').get(req.params.id);
    if (!post) return res.status(404).json({ error: 'Post not found' });
    const result = await publishPost(post);
    res.json(result);
  }));

  // DELETE /api/social/posts/:id — delete a post from the queue
  app.delete('/api/social/posts/:id', asyncRoute(async (_req, res) => {
    db.prepare('DELETE FROM social_posts WHERE id = ?').run(_req.params.id);
    res.json({ ok: true });
  }));

  // POST /api/social/generate — generate content for today
  app.post('/api/social/generate', asyncRoute(async (_req, res) => {
    const posts = await generateAndQueue();
    res.json({ generated: posts.length, posts });
  }));

  // GET /api/social/mentions — list keyword mentions from Reddit/HN
  app.get('/api/social/mentions', asyncRoute(async (req, res) => {
    const status = req.query.status || 'new';
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const rows = getMentions.all(status, limit);
    res.json(rows);
  }));

  // POST /api/social/mentions/:id/dismiss — dismiss a mention
  app.post('/api/social/mentions/:id/dismiss', asyncRoute(async (req, res) => {
    updateMentionStatus.run('dismissed', req.params.id);
    res.json({ ok: true });
  }));

  // POST /api/social/mentions/:id/draft — generate a response draft
  app.post('/api/social/mentions/:id/draft', asyncRoute(async (req, res) => {
    const mention = db.prepare('SELECT * FROM social_mentions WHERE id = ?').get(req.params.id);
    if (!mention) return res.status(404).json({ error: 'Mention not found' });

    const anthropicKey = getEnvKeyFromApps('ANTHROPIC_API_KEY');
    if (!anthropicKey) return res.status(500).json({ error: 'Anthropic API key not configured' });

    const result = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      messages: [{ role: 'user', content: `A user posted on ${mention.source}: "${mention.title}"\n\nSnippet: ${mention.snippet || 'N/A'}\n\nKeywords matched: ${mention.keywords_matched}\n\nWrite a helpful, genuine reply (2-3 sentences). Be helpful first, mention a relevant tool only if natural. Never be salesy. The tools available: Dockfolio (Docker dashboard), LohnCheck (German salary checker), AbschlussCheck (thesis review), Bewerbungsfotos AI (AI headshots for German job applications). Only mention tools that are genuinely relevant to the post.` }],
      system: 'You write genuine, helpful Reddit/HN replies. No marketing speak. Be a real person helping another person.',
      maxTokens: 256,
      timeout: TIMEOUT_AI,
    }));

    updateMentionDraft.run(result.text, mention.id);
    updateMentionStatus.run('drafted', mention.id);
    res.json({ draft: result.text });
  }));

  // GET /api/social/accounts — list platform accounts and their status
  app.get('/api/social/accounts', asyncRoute(async (_req, res) => {
    const accounts = db.prepare('SELECT * FROM social_accounts ORDER BY platform').all();
    // Check which are configured
    const configured = accounts.map(a => ({
      ...a,
      configured: isPlatformConfigured(a.platform),
    }));
    res.json(configured);
  }));

  // PUT /api/social/accounts/:platform — update account settings
  app.put('/api/social/accounts/:platform', asyncRoute(async (req, res) => {
    const { enabled, daily_limit } = req.body;
    const account = getAccount.get(req.params.platform);
    if (!account) return res.status(404).json({ error: 'Platform not found' });
    updateAccount.run(
      enabled !== undefined ? (enabled ? 1 : 0) : account.enabled,
      daily_limit !== undefined ? daily_limit : account.daily_limit,
      req.params.platform,
    );
    res.json({ ok: true });
  }));

  // POST /api/social/monitor — manually trigger mention monitoring
  app.post('/api/social/monitor', asyncRoute(async (_req, res) => {
    const found = await runMonitoring();
    res.json({ mentions_found: found });
  }));

  // GET /api/social/feed.xml — RSS feed of posted content
  app.get('/api/social/feed.xml', (_req, res) => {
    const posts = db.prepare(`SELECT * FROM social_posts WHERE status = 'posted' ORDER BY posted_at DESC LIMIT 50`).all();
    const items = posts.map(p => {
      const date = new Date(p.posted_at || p.created_at).toUTCString();
      const title = p.content.slice(0, 80).replace(/[<>&]/g, '') + (p.content.length > 80 ? '...' : '');
      const link = p.external_url || `https://admin.crelvo.dev/api/social/posts?status=posted`;
      return `    <item>
      <title>${title}</title>
      <description><![CDATA[${p.content}]]></description>
      <link>${link}</link>
      <pubDate>${date}</pubDate>
      <guid>${p.platform}-${p.id}</guid>
      <category>${p.platform}</category>
    </item>`;
    }).join('\n');

    res.setHeader('Content-Type', 'application/rss+xml');
    res.setHeader('Cache-Control', 'public, max-age=600');
    res.send(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Crelvo - Build in Public</title>
    <link>https://crelvo.dev</link>
    <description>Updates from a solo developer running 18+ apps on one server</description>
    <language>en</language>
    <atom:link href="https://admin.crelvo.dev/api/social/feed.xml" rel="self" type="application/rss+xml"/>
${items}
  </channel>
</rss>`);
  });

  // GET /api/social/stats — overview stats
  app.get('/api/social/stats', asyncRoute(async (_req, res) => {
    const today = todayString();
    const posted_today = db.prepare(`SELECT COUNT(*) as c FROM social_posts WHERE status = 'posted' AND date(posted_at) = ?`).get(today)?.c || 0;
    const queued = db.prepare(`SELECT COUNT(*) as c FROM social_posts WHERE status = 'queued'`).get()?.c || 0;
    const new_mentions = db.prepare(`SELECT COUNT(*) as c FROM social_mentions WHERE status = 'new'`).get()?.c || 0;
    const total_posted = db.prepare(`SELECT COUNT(*) as c FROM social_posts WHERE status = 'posted'`).get()?.c || 0;
    const platforms = db.prepare('SELECT * FROM social_accounts ORDER BY platform').all();
    res.json({ posted_today, queued, new_mentions, total_posted, platforms });
  }));

  // --- Helper functions ---

  function isPlatformConfigured(platform) {
    switch (platform) {
      case 'twitter': return !!(getSetting('TWITTER_APP_KEY') && getSetting('TWITTER_ACCESS_TOKEN'));
      case 'bluesky': return !!(getSetting('BLUESKY_HANDLE') && getSetting('BLUESKY_APP_PASSWORD'));
      case 'mastodon': return !!(getSetting('MASTODON_INSTANCE') && getSetting('MASTODON_ACCESS_TOKEN'));
      case 'devto': return !!getSetting('DEVTO_API_KEY');
      case 'linkedin': return false; // TODO: implement when API access is granted
      default: return false;
    }
  }

  async function publishPost(post) {
    const account = getAccount.get(post.platform);
    if (!account || !account.enabled) {
      markFailed.run('Platform not enabled', post.id);
      return { ok: false, error: 'Platform not enabled' };
    }
    if (account.posts_today >= account.daily_limit) {
      return { ok: false, error: `Daily limit reached (${account.daily_limit})` };
    }

    let result;
    switch (post.platform) {
      case 'twitter':
        result = await postToTwitter(getSetting, post.content, TIMEOUT_STANDARD);
        break;
      case 'bluesky':
        result = await postToBluesky(getSetting, post.content, TIMEOUT_STANDARD);
        break;
      case 'mastodon':
        result = await postToMastodon(getSetting, post.content, TIMEOUT_STANDARD);
        break;
      case 'devto': {
        // Dev.to posts need title + markdown — stored as JSON in content for devto posts
        try {
          const parsed = JSON.parse(post.content);
          result = await postToDevTo(getSetting, parsed.title, parsed.markdown, parsed.tags, parsed.canonical_url, TIMEOUT_STANDARD);
        } catch {
          result = { ok: false, error: 'Dev.to posts must have JSON content with title + markdown' };
        }
        break;
      }
      default:
        result = { ok: false, error: `Unsupported platform: ${post.platform}` };
    }

    if (result.ok) {
      markPosted.run(result.id || result.uri || '', result.url || '', post.id);
      bumpPostCount.run(post.platform);
    } else {
      markFailed.run(result.error, post.id);
    }

    return { ...result, post_id: post.id };
  }

  async function generateAndQueue() {
    const anthropicKey = getEnvKeyFromApps('ANTHROPIC_API_KEY');
    if (!anthropicKey) return [];

    const apps = config.apps || [];
    const marketable = apps.filter(a => a.marketing).slice(0, 5);
    const appContext = marketable.map(a =>
      `- ${a.name} (${a.domain}): ${a.marketing?.tagline || a.description || 'No description'}`
    ).join('\n');

    const posts = await generateSocialContent(anthropicKey, appContext, cbAnthropic, TIMEOUT_AI);
    const queued = [];

    for (const post of posts) {
      if (!post.platform || !post.text) continue;
      const text = post.hashtags ? `${post.text} ${post.hashtags}` : post.text;
      queuePost.run(post.platform, text, 'short', null);
      queued.push({ platform: post.platform, text });
    }

    return queued;
  }

  async function runMonitoring() {
    let found = 0;

    // Reddit monitoring
    for (const { sub, keywords } of MONITOR_SUBREDDITS) {
      for (const kw of keywords) {
        const posts = await searchReddit(sub, kw, TIMEOUT_STANDARD);
        for (const post of posts) {
          const changes = insertMention.run(
            'reddit', `reddit-${post.id}`, post.title, post.url,
            post.selftext, post.score, post.num_comments, kw,
          );
          if (changes.changes > 0) found++;
        }
        // Rate limit: don't hammer Reddit
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    // Hacker News monitoring
    for (const query of MONITOR_HN_QUERIES) {
      const stories = await searchHackerNews(query, TIMEOUT_STANDARD);
      for (const story of stories) {
        const changes = insertMention.run(
          'hackernews', `hn-${story.id}`, story.title, story.hn_url,
          '', story.points, story.num_comments, query,
        );
        if (changes.changes > 0) found++;
      }
    }

    // Notify via Telegram if new mentions found
    if (found > 0) {
      sendTelegram(`📡 Social Monitor: ${found} new mention${found > 1 ? 's' : ''} found across Reddit/HN. Check /api/social/mentions`);
    }

    return found;
  }

  async function processQueue() {
    const posts = getQueued.all();
    let posted = 0;
    let failed = 0;

    for (const post of posts) {
      const result = await publishPost(post);
      if (result.ok) posted++;
      else failed++;
      // Small delay between posts
      await new Promise(r => setTimeout(r, 1000));
    }

    if (posted > 0 || failed > 0) {
      console.log(`[CRON] Social autopilot: ${posted} posted, ${failed} failed`);
    }
  }

  // --- Cron jobs ---

  // Monitor Reddit/HN every 15 minutes
  cron.schedule('*/15 * * * *', async () => {
    try {
      await runMonitoring();
    } catch (err) {
      cronFail('Social monitoring', err);
    }
  });

  // Process post queue every hour at :15
  cron.schedule('15 * * * *', async () => {
    try {
      await processQueue();
    } catch (err) {
      cronFail('Social post queue', err);
    }
  });

  // Generate daily content at 8 AM
  cron.schedule('0 8 * * *', async () => {
    try {
      const posts = await generateAndQueue();
      if (posts.length > 0) {
        console.log(`[CRON] Generated ${posts.length} social posts for today`);
      }
    } catch (err) {
      cronFail('Social content generation', err);
    }
  });

  // Reset daily post counts at midnight
  cron.schedule('0 0 * * *', () => {
    resetDailyCounts.run();
  });

  console.log('[Social Autopilot] Routes registered, crons scheduled');
}
