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

// Reddit OAuth token cache (server-to-server, no user login needed)
let redditToken = null;
let redditTokenExpires = 0;

async function getRedditToken(getSetting, timeout) {
  if (redditToken && Date.now() < redditTokenExpires) return redditToken;

  const clientId = getSetting('REDDIT_CLIENT_ID');
  const clientSecret = getSetting('REDDIT_CLIENT_SECRET');
  if (!clientId || !clientSecret) return null;

  try {
    const res = await fetch('https://www.reddit.com/api/v1/access_token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dockfolio-Monitor/2.0 (by /u/crelvo)',
      },
      body: 'grant_type=client_credentials',
      signal: AbortSignal.timeout(timeout),
    });
    if (!res.ok) return null;
    const data = await res.json();
    redditToken = data.access_token;
    redditTokenExpires = Date.now() + (data.expires_in - 60) * 1000; // refresh 60s early
    return redditToken;
  } catch {
    return null;
  }
}

async function searchReddit(subreddit, query, timeout, getSetting) {
  // Try OAuth API first (works from server IPs), fallback to public API
  const token = getSetting ? await getRedditToken(getSetting, timeout) : null;

  try {
    let url, headers;
    if (token) {
      url = `https://oauth.reddit.com/r/${subreddit}/search?q=${encodeURIComponent(query)}&sort=new&t=week&restrict_sr=on&limit=10`;
      headers = { 'Authorization': `Bearer ${token}`, 'User-Agent': 'Dockfolio-Monitor/2.0 (by /u/crelvo)' };
    } else {
      url = `https://www.reddit.com/r/${subreddit}/search.json?q=${encodeURIComponent(query)}&sort=new&t=week&restrict_sr=on&limit=10`;
      headers = { 'User-Agent': 'Dockfolio-Monitor/2.0 (by /u/crelvo)' };
    }

    const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeout) });
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

async function searchHNComments(query, timeout) {
  try {
    const since = Math.floor(Date.now() / 1000) - 86400; // last 24h
    const url = `https://hn.algolia.com/api/v1/search_by_date?query=${encodeURIComponent(query)}&tags=comment&numericFilters=created_at_i>${since}&hitsPerPage=10`;
    const res = await fetch(url, { signal: AbortSignal.timeout(timeout) });
    if (!res.ok) return [];
    const data = await res.json();
    return (data.hits || []).map(h => ({
      id: h.objectID,
      text: (h.comment_text || '').replace(/<[^>]+>/g, ' ').slice(0, 500),
      url: `https://news.ycombinator.com/item?id=${h.objectID}`,
      storyId: h.story_id,
      points: h.points,
      created: h.created_at,
    }));
  } catch {
    return [];
  }
}

// --- Content generation ---

async function generateSocialContent(anthropicKey, appContext, cbAnthropic, timeout) {
  const prompt = `Generate 6 social media posts for a solo developer who runs 18 apps on a single server. Context:
${appContext}

Also promote: Crelvo Dev Studio (crelvo.dev) — a solo dev studio available for hire. 18 live products. Build web apps, SaaS, and tools for clients.

Generate exactly 6 posts as JSON array. Each post has: platform (twitter/bluesky/mastodon/linkedin), text, hashtags.
Rules:
- Twitter: max 270 chars, punchy, 1-2 hashtags
- Bluesky: max 290 chars, similar to twitter
- Mastodon: max 490 chars, slightly more technical, include hashtags
- LinkedIn: 2-3 short paragraphs, professional tone, end with a question

Content mix (pick 6 from these types, vary daily):
- Product highlight (feature one specific app with its URL)
- Behind-the-scenes / build-in-public (real numbers, real challenges)
- Industry tip (genuinely useful, positions you as expert)
- "Hire us" angle (showcase portfolio as proof of capability)
- German-language post (for German apps: AbschlussCheck, LohnCheck, Bewerbungsfotos AI, etc.)
- Engagement bait (ask a question, start a discussion)
- Thread starter (numbered insights, "3 things I learned...")

Include the relevant URL in every product-focused post. For German apps, write in German.
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

  // --- App context for AI drafts ---
  const APP_CONTEXT = {
    dockfolio: { name: 'Dockfolio', domain: 'dockfolio.dev', pitch: 'Self-hosted Docker dashboard with business intelligence — manage 30+ apps from one panel', tags: ['selfhosted', 'docker', 'devops', 'infrastructure'] },
    abschlusscheck: { name: 'AbschlussCheck', domain: 'abschlusscheck.de', pitch: 'AI-powered thesis review for German students — structure, citation, formatting check in 5 minutes for €14-29', tags: ['education', 'thesis', 'german', 'ai'] },
    lohncheck: { name: 'LohnCheck', domain: 'lohnpruefung.de', pitch: 'German payslip verification tool — checks if your salary, taxes, and deductions are correct', tags: ['finance', 'salary', 'german', 'employment'] },
    headshot: { name: 'Bewerbungsfotos AI', domain: 'bewerbungsfotos-ai.de', pitch: 'AI-generated professional headshots for German job applications — no photographer needed', tags: ['ai', 'photos', 'career', 'german'] },
    abfindung: { name: 'AbfindungsOptimizer', domain: 'abfindungsoptimizer.de', pitch: 'German severance pay calculator — optimize your Abfindung for taxes', tags: ['finance', 'legal', 'german', 'employment'] },
    schenkung: { name: 'SchenkungsPlaner', domain: 'schenkungsplaner.eu', pitch: 'German gift tax planner — calculate Schenkungssteuer and optimize gift timing', tags: ['finance', 'tax', 'german', 'family'] },
    sacredlens: { name: 'SacredLens', domain: 'sacredlens.de', pitch: 'AI tool for analyzing religious art and symbolism', tags: ['ai', 'art', 'religion', 'education'] },
    theadhdmind: { name: 'TheADHDMind', domain: 'theadhdmind.org', pitch: 'Resources and tools for developers with ADHD — productivity tips, community', tags: ['adhd', 'productivity', 'mental-health', 'developer'] },
    promoforge: { name: 'PromoForge', domain: 'promoforge.app', pitch: 'AI-powered promotional material generator for indie makers', tags: ['marketing', 'ai', 'saas', 'indie'] },
    bannerforge: { name: 'BannerForge', domain: 'bannerforge.app', pitch: 'AI banner ad generator — create display ads in seconds', tags: ['marketing', 'ai', 'design', 'ads'] },
    crelvo: { name: 'Crelvo Dev Studio', domain: 'crelvo.dev', pitch: 'Solo dev studio — we build web apps, SaaS products, and tools. 18 live products. Hire us for your next project.', tags: ['freelance', 'developer', 'agency', 'web'] },
    oldworldlogos: { name: 'Old World Logos', domain: 'oldworldlogos.com', pitch: 'Curated collection of vintage and classic logo designs for inspiration', tags: ['design', 'logos', 'vintage', 'branding'] },
  };

  // --- Monitoring config ---
  // Structure: per-app keyword groups so AI drafts know which product to recommend
  const MONITOR_SUBREDDITS = [
    // Dockfolio — selfhosted & Docker
    { sub: 'selfhosted', keywords: ['docker dashboard', 'self-hosted dashboard', 'dockfolio', 'portainer alternative', 'container management ui', 'docker gui', 'manage containers', 'docker compose ui'] },
    { sub: 'docker', keywords: ['docker dashboard', 'docker gui', 'container management', 'portainer alternative', 'docker monitoring', 'manage docker containers'] },
    { sub: 'homelab', keywords: ['docker dashboard', 'self-hosted dashboard', 'container management', 'homelab dashboard'] },
    { sub: 'webdev', keywords: ['self-hosted', 'docker dashboard', 'saas dashboard', 'deploy side project', 'vps setup'] },
    { sub: 'devops', keywords: ['docker dashboard', 'container monitoring', 'self-hosted monitoring', 'single server deployment'] },

    // AbschlussCheck — thesis / academic
    { sub: 'StudiumDE', keywords: ['abschlussarbeit', 'bachelorarbeit', 'masterarbeit', 'thesis check', 'korrekturlesen', 'abgabe bachelorarbeit', 'thesis feedback'] },
    { sub: 'de', keywords: ['bachelorarbeit hilfe', 'masterarbeit korrektur', 'abschlussarbeit tipps'] },
    { sub: 'germany', keywords: ['thesis help germany', 'bachelor thesis german university'] },
    { sub: 'GradSchool', keywords: ['thesis review', 'thesis feedback', 'dissertation check', 'thesis proofreading'] },
    { sub: 'college', keywords: ['thesis review tool', 'check my thesis', 'thesis feedback ai'] },

    // LohnCheck — salary / payslip
    { sub: 'Finanzen', keywords: ['gehaltsrechner', 'gehalt prüfen', 'lohnabrechnung', 'lohnabrechnung prüfen', 'gehaltsabrechnung fehler', 'brutto netto', 'nettolohn berechnen'] },
    { sub: 'arbeitsleben', keywords: ['gehalt verhandeln', 'lohnabrechnung falsch', 'gehaltsabrechnung verstehen', 'gehaltscheck', 'lohn prüfen'] },
    { sub: 'antiwork', keywords: ['payslip wrong', 'salary deduction wrong', 'paycheck incorrect', 'employer underpaying'] },
    { sub: 'personalfinance', keywords: ['payslip check', 'salary verification', 'paycheck calculator'] },

    // Bewerbungsfotos AI — job application photos
    { sub: 'arbeitsleben', keywords: ['bewerbungsfoto', 'bewerbungsfotos kosten', 'bewerbungsfoto selber machen', 'professionelles foto bewerbung'] },
    { sub: 'Bewerbung', keywords: ['bewerbungsfoto', 'foto bewerbung', 'bewerbungsfotos', 'lebenslauf foto'] },
    { sub: 'remotework', keywords: ['ai headshot', 'professional headshot ai', 'linkedin photo ai'] },
    { sub: 'jobs', keywords: ['ai headshot', 'professional photo resume', 'headshot generator'] },
    { sub: 'linkedin', keywords: ['ai headshot', 'professional headshot', 'linkedin photo generator'] },

    // AbfindungsOptimizer — severance pay
    { sub: 'Finanzen', keywords: ['abfindung berechnen', 'abfindung steuer', 'abfindung versteuern', 'abfindungsrechner'] },
    { sub: 'arbeitsleben', keywords: ['abfindung', 'abfindung verhandeln', 'kündigung abfindung', 'aufhebungsvertrag abfindung'] },
    { sub: 'recht', keywords: ['abfindung steuer', 'abfindung berechnen', 'fünftelregelung'] },

    // SchenkungsPlaner — gift tax
    { sub: 'Finanzen', keywords: ['schenkung steuer', 'schenkungssteuer', 'schenkung freibetrag', 'geld verschenken steuer'] },
    { sub: 'recht', keywords: ['schenkung steuer', 'schenkungssteuer freibetrag', 'immobilie verschenken'] },

    // TheADHDMind — ADHD + productivity
    { sub: 'ADHD', keywords: ['adhd developer', 'adhd programmer', 'adhd productivity tools', 'adhd coding', 'adhd software developer'] },
    { sub: 'adhdwomen', keywords: ['adhd work tips', 'adhd productivity', 'adhd career'] },
    { sub: 'ADHDers', keywords: ['adhd developer', 'adhd productivity', 'adhd work strategies'] },

    // Crelvo Dev Studio — freelance / hire a developer
    { sub: 'startups', keywords: ['looking for developer', 'need a developer', 'hire developer', 'find technical cofounder', 'solo developer', 'mvp developer'] },
    { sub: 'SideProject', keywords: ['need developer', 'looking for developer', 'hire developer for side project', 'build my app'] },
    { sub: 'Entrepreneur', keywords: ['need a developer', 'looking for developer', 'hire developer', 'build mvp', 'technical cofounder'] },
    { sub: 'indiehackers', keywords: ['hire developer', 'need developer', 'looking for dev', 'solo developer portfolio'] },
    { sub: 'forhire', keywords: ['developer', 'web developer', 'fullstack developer', 'react developer', 'node developer'] },
    { sub: 'freelance', keywords: ['web developer', 'fullstack developer', 'hire developer'] },

    // PromoForge / BannerForge — marketing tools
    { sub: 'marketing', keywords: ['banner generator', 'ad creative tool', 'promotional material generator', 'create ads free'] },
    { sub: 'EntrepreneurRideAlong', keywords: ['marketing tools', 'banner ads', 'promotional material', 'indie marketing'] },

    // SacredLens — religious art
    { sub: 'ArtHistory', keywords: ['religious art analysis', 'symbolism art', 'analyze painting', 'christian art symbols'] },
    { sub: 'Christianity', keywords: ['religious art', 'christian symbolism', 'sacred art analysis'] },

    // Old World Logos — design
    { sub: 'graphic_design', keywords: ['vintage logo', 'classic logo design', 'retro logo inspiration', 'old logos'] },
    { sub: 'logodesign', keywords: ['vintage logo', 'logo inspiration', 'classic logo', 'retro branding'] },
  ];

  const MONITOR_HN_QUERIES = [
    // Dockfolio
    'docker dashboard', 'self-hosted dashboard', 'solopreneur tools',
    'indie hacker infrastructure', 'portainer alternative',
    // Career tools (German market)
    'salary calculator germany', 'ai headshot generator',
    // Dev studio / freelance
    'solo developer portfolio', 'indie developer', 'one person saas',
    'side project to saas', 'build in public',
    // Thesis / education
    'ai thesis review', 'thesis proofreading tool',
    // ADHD
    'adhd developer', 'adhd programmer productivity',
    // Marketing
    'banner ad generator', 'promotional material ai',
  ];

  // --- YouTube monitoring ---
  async function searchYouTube(query, timeout) {
    const apiKey = getSetting('YOUTUBE_API_KEY');
    if (!apiKey) return [];
    try {
      const url = `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(query)}&type=video&order=date&maxResults=5&publishedAfter=${new Date(Date.now() - 7 * 86400000).toISOString()}&key=${apiKey}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(timeout) });
      if (!res.ok) return [];
      const data = await res.json();
      return (data.items || []).map(item => ({
        id: item.id.videoId,
        title: item.snippet.title,
        description: (item.snippet.description || '').slice(0, 500),
        url: `https://www.youtube.com/watch?v=${item.id.videoId}`,
        channel: item.snippet.channelTitle,
        created: item.snippet.publishedAt,
      }));
    } catch {
      return [];
    }
  }

  const MONITOR_YOUTUBE_QUERIES = [
    // Dockfolio / selfhosted
    'docker dashboard 2026', 'self hosted dashboard', 'portainer alternative',
    'homelab dashboard setup',
    // German career / finance
    'Bewerbungsfoto KI', 'Gehaltsabrechnung prüfen', 'Abschlussarbeit Tipps',
    'Brutto Netto Rechner', 'Abfindung berechnen',
    // ADHD dev
    'ADHD programmer', 'ADHD developer productivity',
    // Dev freelance
    'hire a developer 2026', 'solo developer saas',
  ];

  // --- Quora monitoring ---
  async function searchQuora(query, timeout) {
    try {
      // Quora has no API — use Google site search as proxy
      const url = `https://www.google.com/search?q=site:quora.com+${encodeURIComponent(query)}&tbs=qdr:w&num=5`;
      const res = await fetch(url, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) return [];
      const html = await res.text();
      // Extract Quora URLs from Google results
      const matches = [...html.matchAll(/href="(https:\/\/(?:www\.)?quora\.com\/[^"&]+)"/g)];
      return matches.slice(0, 5).map((m, i) => {
        const qUrl = m[1];
        // Extract question from URL
        const question = decodeURIComponent(qUrl.split('/').pop() || '').replace(/-/g, ' ');
        return {
          id: `quora-${Buffer.from(qUrl).toString('base64').slice(0, 20)}`,
          title: question,
          url: qUrl,
          created: new Date().toISOString(),
        };
      });
    } catch {
      return [];
    }
  }

  const MONITOR_QUORA_QUERIES = [
    // German career / finance (Quora has German content)
    'Gehaltsabrechnung prüfen lassen', 'Bewerbungsfoto selber machen',
    'Bachelorarbeit prüfen lassen', 'Abfindung berechnen Steuer',
    // English
    'best docker dashboard', 'self hosted server dashboard',
    'AI headshot generator', 'ADHD developer tips',
    'hire solo developer', 'freelance web developer portfolio',
  ];

  // --- X/Twitter search monitoring ---
  async function searchTwitter(query, timeout) {
    // Requires Twitter API Basic tier ($100/mo) for search endpoint
    const appKey = getSetting('TWITTER_APP_KEY');
    const appSecret = getSetting('TWITTER_APP_SECRET');
    const accessToken = getSetting('TWITTER_ACCESS_TOKEN');
    const accessSecret = getSetting('TWITTER_ACCESS_SECRET');
    if (!appKey || !appSecret || !accessToken || !accessSecret) return [];

    try {
      const { TwitterApi } = await import('twitter-api-v2');
      const client = new TwitterApi({ appKey, appSecret, accessToken, accessSecret });
      const result = await client.v2.search(query, {
        'tweet.fields': 'created_at,public_metrics,author_id',
        max_results: 10,
        sort_order: 'recency',
      });
      return (result.data?.data || []).map(tweet => ({
        id: tweet.id,
        title: tweet.text.slice(0, 140),
        text: tweet.text,
        url: `https://x.com/i/status/${tweet.id}`,
        created: tweet.created_at,
        likes: tweet.public_metrics?.like_count || 0,
        retweets: tweet.public_metrics?.retweet_count || 0,
      }));
    } catch {
      return [];
    }
  }

  const MONITOR_TWITTER_QUERIES = [
    // Dockfolio / selfhosted
    '"docker dashboard" -portainer', '"self-hosted dashboard"',
    '"portainer alternative"',
    // German career (German Twitter is active)
    'Bewerbungsfoto KI', 'Gehaltsabrechnung prüfen',
    'Bachelorarbeit Hilfe', 'Abfindung berechnen',
    // Dev / freelance
    '"looking for a developer"', '"need a developer"',
    '"hire a developer"', 'solo developer saas',
    // ADHD
    'ADHD developer', 'ADHD programmer',
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

    // Parse keywords_matched to find which app this mention is about
    let matchedApp = null;
    let matchedKeyword = mention.keywords_matched;
    try {
      const parsed = JSON.parse(mention.keywords_matched);
      matchedApp = parsed.app ? APP_CONTEXT[parsed.app] : null;
      matchedKeyword = parsed.keyword || mention.keywords_matched;
    } catch { /* old format — plain keyword string */ }

    const appList = Object.values(APP_CONTEXT).map(a =>
      `- ${a.name} (${a.domain}): ${a.pitch}`
    ).join('\n');

    const focusApp = matchedApp
      ? `\n\nThe MOST relevant product for this post is: ${matchedApp.name} (${matchedApp.domain}) — ${matchedApp.pitch}. Prioritize mentioning this one if it fits naturally.`
      : '';

    const platformGuide = {
      reddit: 'Write a Reddit comment. Be genuinely helpful first — answer their question or share relevant experience. Only mention a product if it directly solves their problem. Use casual tone. Never say "check out" or "you should try" — instead say "I\'ve been using X for this" or "there\'s a tool called X that does exactly this". 2-4 sentences.',
      hackernews: 'Write a Hacker News comment. Be technical, substantive, and add real value to the discussion. HN users hate marketing — only mention a tool if it\'s genuinely relevant and you can explain WHY it\'s good. Share technical insight first. 2-4 sentences.',
      youtube: 'Write a YouTube comment. Be friendly, add value to the video topic. If relevant, mention a tool that could help. Keep it natural — 1-3 sentences.',
      twitter: 'Write a Twitter/X reply. Be concise, engaging, add value. If a product is relevant, mention it casually. Max 280 chars.',
      quora: 'Write a Quora answer. Be thorough and genuinely helpful — Quora rewards detailed answers. Structure your response clearly. Mention relevant tools as part of a complete answer, not as the main point. 3-5 sentences.',
    }[mention.source] || 'Write a helpful reply. 2-3 sentences.';

    const result = await cbAnthropic.call(() => callAnthropic(anthropicKey, {
      messages: [{ role: 'user', content: `A user posted on ${mention.source}: "${mention.title}"\n\nSnippet: ${mention.snippet || 'N/A'}\n\nKeyword that matched: ${matchedKeyword}\n\nOur product portfolio:\n${appList}\n${focusApp}\n\n${platformGuide}` }],
      system: 'You are a solo developer who genuinely helps people online. You built 18 apps and run them on a single server. You share real experience, not marketing pitches. When mentioning your own tools, frame it as personal experience: "I built X for this exact reason" or "I use X myself". Your tone matches the platform culture. For German posts, reply in German. For English posts, reply in English.',
      maxTokens: 400,
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
    const marketable = apps.filter(a => a.marketing && a.domain && a.type !== 'redirect');
    // Rotate focus: pick 6 random apps each day so content varies
    const shuffled = marketable.sort(() => Math.random() - 0.5).slice(0, 8);
    const appContext = shuffled.map(a =>
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

  // Figure out which app a keyword match is about (for smarter AI drafts)
  function matchKeywordToApp(keyword, title) {
    const combined = `${keyword} ${title}`.toLowerCase();
    if (/docker|portainer|self.hosted|homelab|container|devops/.test(combined)) return 'dockfolio';
    if (/abschluss|bachelor|master|thesis|korrektur|diplomarbeit/.test(combined)) return 'abschlusscheck';
    if (/gehalt|lohn|brutto|netto|payslip|salary|gehaltsabrechnung|lohnpr/.test(combined)) return 'lohncheck';
    if (/bewerbungsfoto|headshot|bewerbung foto|linkedin photo|resume photo/.test(combined)) return 'headshot';
    if (/abfindung|severance|aufhebungsvertrag|fünftelregel/.test(combined)) return 'abfindung';
    if (/schenkung|gift tax|verschenken steuer|freibetrag/.test(combined)) return 'schenkung';
    if (/adhd|adhs|aufmerksamkeit/.test(combined)) return 'theadhdmind';
    if (/hire.*dev|need.*dev|looking.*dev|freelance|mvp|cofounder|build.*app|forhire/.test(combined)) return 'crelvo';
    if (/banner.*gen|ad.*creative|promo.*material/.test(combined)) return 'promoforge';
    if (/vintage.*logo|classic.*logo|retro.*logo|old.*logo/.test(combined)) return 'oldworldlogos';
    if (/religious.*art|sacred|christian.*symbol/.test(combined)) return 'sacredlens';
    return null;
  }

  async function runMonitoring() {
    let found = 0;

    // Reddit monitoring
    for (const { sub, keywords } of MONITOR_SUBREDDITS) {
      for (const kw of keywords) {
        const posts = await searchReddit(sub, kw, TIMEOUT_STANDARD, getSetting);
        for (const post of posts) {
          const appMatch = matchKeywordToApp(kw, post.title);
          const changes = insertMention.run(
            'reddit', `reddit-${post.id}`, post.title, post.url,
            post.selftext, post.score, post.num_comments,
            JSON.stringify({ keyword: kw, app: appMatch }),
          );
          if (changes.changes > 0) found++;
        }
        // Rate limit: don't hammer Reddit
        await new Promise(r => setTimeout(r, 2000));
      }
    }

    // Hacker News monitoring — stories
    for (const query of MONITOR_HN_QUERIES) {
      const stories = await searchHackerNews(query, TIMEOUT_STANDARD);
      for (const story of stories) {
        const appMatch = matchKeywordToApp(query, story.title);
        const changes = insertMention.run(
          'hackernews', `hn-${story.id}`, story.title, story.hn_url,
          '', story.points, story.num_comments,
          JSON.stringify({ keyword: query, app: appMatch }),
        );
        if (changes.changes > 0) found++;
      }
    }

    // Hacker News comments — people asking questions (higher engagement value)
    for (const query of MONITOR_HN_QUERIES.slice(0, 8)) {
      const comments = await searchHNComments(query, TIMEOUT_STANDARD);
      for (const comment of comments) {
        const appMatch = matchKeywordToApp(query, comment.text);
        const changes = insertMention.run(
          'hackernews', `hn-comment-${comment.id}`, comment.text.slice(0, 200), comment.url,
          comment.text.slice(0, 500), comment.points || 0, 0,
          JSON.stringify({ keyword: query, app: appMatch, type: 'comment' }),
        );
        if (changes.changes > 0) found++;
      }
    }

    // YouTube monitoring (if API key configured)
    if (getSetting('YOUTUBE_API_KEY')) {
      for (const query of MONITOR_YOUTUBE_QUERIES) {
        const videos = await searchYouTube(query, TIMEOUT_STANDARD);
        for (const video of videos) {
          const appMatch = matchKeywordToApp(query, video.title);
          const changes = insertMention.run(
            'youtube', `yt-${video.id}`, video.title, video.url,
            video.description, 0, 0,
            JSON.stringify({ keyword: query, app: appMatch, channel: video.channel }),
          );
          if (changes.changes > 0) found++;
        }
        await new Promise(r => setTimeout(r, 500));
      }
    }

    // X/Twitter search monitoring (if configured — requires Basic tier)
    const hasTwitter = getSetting('TWITTER_APP_KEY') && getSetting('TWITTER_ACCESS_TOKEN');
    if (hasTwitter) {
      for (const query of MONITOR_TWITTER_QUERIES) {
        const tweets = await searchTwitter(query, TIMEOUT_STANDARD);
        for (const tweet of tweets) {
          const appMatch = matchKeywordToApp(query, tweet.text || tweet.title);
          const changes = insertMention.run(
            'twitter', `tw-${tweet.id}`, tweet.title, tweet.url,
            tweet.text || '', tweet.likes || 0, tweet.retweets || 0,
            JSON.stringify({ keyword: query, app: appMatch }),
          );
          if (changes.changes > 0) found++;
        }
        await new Promise(r => setTimeout(r, 1000));
      }
    }

    // Quora monitoring (via Google site search — less reliable, run less often)
    // Only run Quora on every 4th cycle (~hourly instead of every 15 min)
    const minute = new Date().getMinutes();
    if (minute < 15) {
      for (const query of MONITOR_QUORA_QUERIES) {
        const questions = await searchQuora(query, TIMEOUT_STANDARD);
        for (const q of questions) {
          const appMatch = matchKeywordToApp(query, q.title);
          const changes = insertMention.run(
            'quora', q.id, q.title, q.url,
            '', 0, 0,
            JSON.stringify({ keyword: query, app: appMatch }),
          );
          if (changes.changes > 0) found++;
        }
        await new Promise(r => setTimeout(r, 3000)); // slower for Google scraping
      }
    }

    // Notify via Telegram if new mentions found — include platform breakdown
    if (found > 0) {
      const breakdown = db.prepare(`
        SELECT source, COUNT(*) as c FROM social_mentions
        WHERE status = 'new' AND found_at > datetime('now', '-1 hour')
        GROUP BY source
      `).all();
      const parts = breakdown.map(r => `${r.source}: ${r.c}`).join(', ');
      sendTelegram(`📡 Social Monitor: ${found} new mention${found > 1 ? 's' : ''} found (${parts}). Check /api/social/mentions`);
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
      const found = await runMonitoring();
      console.log(`[CRON] Social monitoring: ${found} new mentions`);
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
