/**
 * Integration tests for Dockfolio server API
 *
 * Run against a live server instance:
 *   SERVER_URL=http://localhost:3000 node server.test.js
 *
 * These tests verify API contract, auth enforcement, and public endpoint behavior.
 * They do NOT modify state (no POSTs to destructive endpoints).
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

const BASE = process.env.SERVER_URL || 'http://127.0.0.1:3000';

// Auth credentials (set via env or use defaults for testing)
const AUTH_USER = process.env.TEST_USER || 'admin';
const AUTH_PASS = process.env.TEST_PASS || '';

let sessionCookie = null;
let csrfToken = null;

async function req(path, opts = {}) {
  const url = `${BASE}${path}`;
  const headers = { ...opts.headers };
  if (sessionCookie) headers.Cookie = sessionCookie;
  if (csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(opts.method)) {
    headers['X-CSRF-Token'] = csrfToken;
    headers.Cookie = (headers.Cookie || '') + `; _csrf=${csrfToken}`;
  }
  const res = await fetch(url, { ...opts, headers, redirect: 'manual' });
  return res;
}

async function json(path, opts = {}) {
  const res = await req(path, opts);
  const body = await res.json();
  return { status: res.status, body, headers: res.headers };
}

// ── Public endpoints (no auth required) ──────────────────────────────

describe('Public endpoints', () => {
  it('GET /health returns ok', async () => {
    const res = await req('/health');
    const text = await res.text();
    assert.equal(res.status, 200);
    assert.equal(text, 'ok');
  });

  it('GET /api/health returns JSON with status', async () => {
    const { status, body } = await json('/api/health');
    assert.equal(status, 200);
    assert.ok(body.status, 'should have status field');
    assert.ok(typeof body.containers === 'object', 'should have containers');
  });

  it('GET /api/auth/status returns setup state', async () => {
    const { status, body } = await json('/api/auth/status');
    assert.equal(status, 200);
    assert.ok(typeof body.setupComplete === 'boolean');
  });

  it('GET /api/banners/embed.js returns script', async () => {
    const res = await req('/api/banners/embed.js');
    assert.equal(res.status, 200);
    const ct = res.headers.get('content-type');
    assert.ok(ct.includes('javascript'), `Expected javascript content-type, got ${ct}`);
  });

  it('GET /status returns public status page HTML', async () => {
    const res = await req('/status');
    assert.equal(res.status, 200);
    const ct = res.headers.get('content-type');
    assert.ok(ct.includes('text/html'), `Expected HTML content-type, got ${ct}`);
    const text = await res.text();
    assert.ok(text.includes('Status'), 'Status page should contain Status heading');
  });

  it('GET /api/status-page returns JSON status data', async () => {
    const { status, body } = await json('/api/status-page');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.apps) || typeof body === 'object', 'should return status data');
  });
});

// ── Auth enforcement ─────────────────────────────────────────────────

describe('Auth enforcement (no session)', () => {
  it('GET /api/apps returns 401 without auth', async () => {
    const saved = sessionCookie;
    sessionCookie = null;
    const { status } = await json('/api/apps');
    assert.equal(status, 401);
    sessionCookie = saved;
  });

  it('GET /api/system returns 401 without auth', async () => {
    const saved = sessionCookie;
    sessionCookie = null;
    const { status } = await json('/api/system');
    assert.equal(status, 401);
    sessionCookie = saved;
  });

  it('GET /api/marketing/revenue returns 401 without auth', async () => {
    const saved = sessionCookie;
    sessionCookie = null;
    const { status } = await json('/api/marketing/revenue');
    assert.equal(status, 401);
    sessionCookie = saved;
  });

  it('GET /api/security/status returns 401 without auth', async () => {
    const saved = sessionCookie;
    sessionCookie = null;
    const { status } = await json('/api/security/status');
    assert.equal(status, 401);
    sessionCookie = saved;
  });

  it('POST /api/auth/login rejects wrong credentials', async () => {
    const saved = sessionCookie;
    sessionCookie = null;
    const res = await req('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'nonexistent', password: 'wrongpassword' })
    });
    assert.ok([400, 401, 429].includes(res.status), `Expected 400/401/429, got ${res.status}`);
    sessionCookie = saved;
  });
});

// ── CSRF protection ──────────────────────────────────────────────────

describe('CSRF protection', () => {
  it('POST without CSRF token returns 403', async () => {
    // Try a POST without CSRF token (but with auth)
    if (!sessionCookie) return; // skip if no auth
    const res = await fetch(`${BASE}/api/actions/prune`, {
      method: 'POST',
      headers: { Cookie: sessionCookie }
    });
    assert.equal(res.status, 403);
  });
});

// ── Authenticated endpoints ──────────────────────────────────────────

describe('Authenticated endpoints', { skip: !AUTH_PASS ? 'No TEST_PASS set — skipping authenticated tests' : false }, () => {
  before(async () => {
    // Login to get session cookie
    const res = await fetch(`${BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: AUTH_USER, password: AUTH_PASS }),
      redirect: 'manual',
    });
    assert.equal(res.status, 200, 'Login should succeed');
    const setCookie = res.headers.getSetCookie?.() || [res.headers.get('set-cookie')].filter(Boolean);
    const sessionEntry = setCookie.find(c => c.startsWith('session='));
    assert.ok(sessionEntry, 'Should receive session cookie');
    sessionCookie = sessionEntry.split(';')[0];

    // Get CSRF token
    const csrfCookie = setCookie.find(c => c.startsWith('_csrf='));
    if (csrfCookie) {
      csrfToken = csrfCookie.split(';')[0].split('=')[1];
    }
  });

  it('GET /api/auth/me returns user info', async () => {
    const { status, body } = await json('/api/auth/me');
    assert.equal(status, 200);
    assert.equal(body.username, AUTH_USER);
    assert.ok(body.role);
  });

  it('GET /api/apps returns app list', async () => {
    const { status, body } = await json('/api/apps');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array');
    assert.ok(body.length > 0, 'should have at least one app');
    // Verify app shape
    const app = body[0];
    assert.ok(app.name, 'app should have name');
    assert.ok(app.type, 'app should have type');
  });

  it('GET /api/system returns system metrics', async () => {
    const { status, body } = await json('/api/system');
    assert.equal(status, 200);
    assert.ok(body.memory, 'should have memory');
    assert.ok(body.disk, 'should have disk');
    assert.ok(typeof body.memory.total === 'number');
    assert.ok(typeof body.disk.total === 'number');
  });

  it('GET /api/containers/stats returns container stats', async () => {
    const { status, body } = await json('/api/containers/stats');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array');
  });

  it('GET /api/docker/overview returns Docker info', async () => {
    const { status, body } = await json('/api/docker/overview');
    assert.equal(status, 200);
    assert.ok(body.info || body.version, 'should have Docker info');
  });

  it('GET /api/config/apps returns config', async () => {
    const { status, body } = await json('/api/config/apps');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array of app configs');
  });

  it('GET /api/events returns Docker events', async () => {
    const { status, body } = await json('/api/events');
    assert.equal(status, 200);
    assert.ok(body.events !== undefined || Array.isArray(body), 'should return events');
  });

  it('GET /api/ssl returns SSL status', async () => {
    const { status, body } = await json('/api/ssl');
    assert.equal(status, 200);
    assert.ok(typeof body === 'object');
  });

  it('GET /api/backups returns backup status', async () => {
    const { status, body } = await json('/api/backups');
    assert.equal(status, 200);
    assert.ok(typeof body === 'object');
  });

  it('GET /api/marketing/revenue returns revenue data', async () => {
    const { status, body } = await json('/api/marketing/revenue');
    assert.equal(status, 200);
    assert.ok(body.totals || body.error === 'No Stripe keys configured');
  });

  it('GET /api/marketing/banners returns banners', async () => {
    const { status, body } = await json('/api/marketing/banners');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array');
  });

  it('GET /api/security/status returns security scan', async () => {
    const { status, body } = await json('/api/security/status');
    assert.equal(status, 200);
    assert.ok(body.score !== undefined || body.findings !== undefined || body.latest !== undefined);
  });

  it('GET /api/healing/log returns healing events', async () => {
    const { status, body } = await json('/api/healing/log');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array');
  });

  it('GET /api/marketing/playbooks returns playbooks', async () => {
    const { status, body } = await json('/api/marketing/playbooks');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body));
  });

  it('GET /api/command/search?q=apps returns results', async () => {
    const { status, body } = await json('/api/command/search?q=apps');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array');
  });

  it('GET /api/disk returns disk breakdown', async () => {
    const { status, body } = await json('/api/disk');
    assert.equal(status, 200);
    assert.ok(typeof body === 'object');
  });

  it('GET /api/audit returns audit log entries', async () => {
    const { status, body } = await json('/api/audit');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.rows) || Array.isArray(body), 'should return audit entries');
  });

  it('GET /api/achievements returns achievements list', async () => {
    const { status, body } = await json('/api/achievements');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array of achievements');
    if (body.length > 0) {
      assert.ok(body[0].id, 'achievement should have id');
      assert.ok(body[0].name, 'achievement should have name');
      assert.ok(typeof body[0].unlocked === 'boolean', 'achievement should have unlocked flag');
    }
  });

  it('GET /api/security/leaderboard returns ranked apps', async () => {
    const { status, body } = await json('/api/security/leaderboard');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array');
  });

  it('GET /api/alert-rules returns alert rules', async () => {
    const { status, body } = await json('/api/alert-rules');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body), 'should return array of rules');
  });

  it('GET /api/build-in-public returns content or API key error', async () => {
    const { status, body } = await json('/api/build-in-public');
    assert.ok([200, 500].includes(status), `Expected 200 or 500, got ${status}`);
    if (status === 200) {
      assert.ok(body.thread || body.content, 'should return generated content');
    }
  });

  it('GET /api/time-to-revenue returns tracker data', async () => {
    const { status, body } = await json('/api/time-to-revenue');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body) || typeof body === 'object', 'should return revenue tracking data');
  });

  it('GET /api/logs/stats returns log volume stats', async () => {
    const { status, body } = await json('/api/logs/stats');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.stats), 'should return stats array');
    assert.ok(typeof body.total === 'number', 'should have total count');
  });

  it('GET /api/logs/search validates query parameter', async () => {
    const { status, body } = await json('/api/logs/search?q=a');
    assert.equal(status, 400);
    assert.ok(body.error.includes('2 characters'), 'should require at least 2 chars');
  });

  it('GET /api/logs/patterns returns error patterns', async () => {
    const { status, body } = await json('/api/logs/patterns?hours=1');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.patterns), 'should return patterns array');
    assert.ok(typeof body.total_error_lines === 'number', 'should have total count');
  });

  it('GET /api/dns/validate returns DNS validation results', async () => {
    const { status, body } = await json('/api/dns/validate');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.results), 'should return results array');
    assert.ok(body.server_ip, 'should include server IP');
  });

  it('GET /api/dns/records requires domain parameter', async () => {
    const { status, body } = await json('/api/dns/records');
    assert.equal(status, 400);
    assert.ok(body.error.includes('domain'), 'should require domain parameter');
  });

  it('GET /api/launch/status returns launch mode status', async () => {
    const { status, body } = await json('/api/launch/status');
    assert.equal(status, 200);
    assert.ok(typeof body.active === 'boolean', 'should have active flag');
  });

  it('GET /api/troubleshoot/flows returns available flows', async () => {
    const { status, body } = await json('/api/troubleshoot/flows');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.flows), 'should return flows array');
    assert.ok(body.flows.length >= 4, 'should have at least 4 flows');
    assert.ok(body.flows[0].id, 'flow should have id');
    assert.ok(body.flows[0].name, 'flow should have name');
  });

  it('POST /api/troubleshoot validates flow parameter', async () => {
    const res = await req('/api/troubleshoot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flow: 'invalid-flow' }),
    });
    assert.equal(res.status, 400);
  });

  it('GET /api/anomalies returns anomaly data', async () => {
    const { status, body } = await json('/api/anomalies');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.anomalies), 'should return anomalies array');
    assert.ok(body.timestamp, 'should include timestamp');
  });

  it('GET /api/cron/status returns cron job statuses', async () => {
    const { status, body } = await json('/api/cron/status');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.jobs), 'should return jobs array');
    assert.ok(typeof body.healthy === 'boolean', 'should have healthy flag');
    assert.ok(body.jobs.length >= 9, 'should track at least 9 cron jobs');
  });

  it('GET /api/focus returns AI recommendations or error', async () => {
    const { status, body } = await json('/api/focus');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.recommendations) || body.error, 'should return recommendations or error');
  });

  it('GET /api/domains/overview returns unified domain data', async () => {
    const { status, body } = await json('/api/domains/overview');
    assert.equal(status, 200);
    assert.ok(Array.isArray(body.domains), 'should return domains array');
    assert.ok(body.timestamp, 'should include timestamp');
    if (body.domains.length > 0) {
      const d = body.domains[0];
      assert.ok(d.domain, 'domain entry should have domain field');
      assert.ok(d.slug, 'domain entry should have slug');
      assert.ok(d.dns !== undefined, 'should include DNS check');
    }
  });

  it('GET /api/marketing/emails/analytics returns email stats', async () => {
    const { status, body } = await json('/api/marketing/emails/analytics');
    assert.equal(status, 200);
    assert.ok(body.totals, 'should have totals');
    assert.ok(typeof body.totals.sent === 'number', 'should have sent count');
    assert.ok(typeof body.totals.pending === 'number', 'should have pending count');
  });

  it('POST /api/containers/nonexistent/exec returns 404', async () => {
    const res = await req('/api/containers/nonexistent-container-xyz/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cmd: 'ls' }),
    });
    assert.equal(res.status, 404);
  });

  it('POST /api/config/apps/nonexistent/preview returns 404', async () => {
    const res = await req('/api/config/apps/nonexistent-app-xyz/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test' }),
    });
    assert.equal(res.status, 404);
  });
});

// ── Response headers ─────────────────────────────────────────────────

describe('Security headers', () => {
  it('Responses include X-Request-ID', async () => {
    const res = await req('/api/health');
    const requestId = res.headers.get('x-request-id');
    assert.ok(requestId, 'Should have X-Request-ID header');
    assert.ok(requestId.length > 10, 'X-Request-ID should be a UUID');
  });

  it('Responses include CSP header', async () => {
    const res = await req('/api/health');
    const csp = res.headers.get('content-security-policy');
    assert.ok(csp, 'Should have Content-Security-Policy header');
    assert.ok(csp.includes("default-src"), 'CSP should include default-src');
  });

  it('Responses include X-Content-Type-Options', async () => {
    const res = await req('/api/health');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });

  it('Sets CSRF cookie on first request', async () => {
    const res = await fetch(`${BASE}/api/health`);
    const setCookie = res.headers.getSetCookie?.() || [res.headers.get('set-cookie')].filter(Boolean);
    const csrfCookie = setCookie.find(c => c?.startsWith('_csrf='));
    assert.ok(csrfCookie, 'Should set _csrf cookie');
  });
});

// ── Edge cases ───────────────────────────────────────────────────────

describe('Edge cases', () => {
  it('Non-existent API endpoint returns 404', async () => {
    const res = await req('/api/nonexistent-endpoint-xyz');
    assert.ok([401, 404].includes(res.status), `Expected 401 or 404, got ${res.status}`);
  });

  it('Invalid JSON body returns 400', async () => {
    const res = await req('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{invalid json'
    });
    assert.ok([400, 415].includes(res.status), `Expected 400/415, got ${res.status}`);
  });
});
