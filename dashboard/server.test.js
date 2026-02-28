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

  it('GET /api/env/shared returns shared keys', async () => {
    const { status, body } = await json('/api/env/shared');
    assert.equal(status, 200);
    assert.ok(typeof body === 'object');
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
