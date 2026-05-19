#!/usr/bin/env node
/**
 * inwx-dns.mjs — INWX DNS CLI for the fiscanto.de Proton Mail setup.
 *
 * Idempotent and create-only: it reads the current zone, then creates
 * only the records that are missing. It never edits or deletes an
 * existing record, so the protonmail-verification TXT and the wildcard
 * A record stay untouched. Running it twice is harmless.
 *
 * Reuses the INWX JSON-RPC flow already proven in
 * dashboard/routes/dns.js (account.login, nameserver.info,
 * nameserver.createRecord, cookie based session).
 *
 * Credentials — never commit these, pass them via env vars:
 *   INWX_USER   INWX account login
 *   INWX_PASS   INWX account password
 *
 * Optional DKIM targets — unique per domain, from Christoph's Proton
 * dashboard (Einstellungen, Domain-Namen, fiscanto.de, DKIM):
 *   INWX_DKIM1  target for protonmail._domainkey
 *   INWX_DKIM2  target for protonmail2._domainkey
 *   INWX_DKIM3  target for protonmail3._domainkey
 * When a target is absent, that DKIM record is skipped.
 *
 * Usage:
 *   node scripts/inwx-dns.mjs --dry-run   show desired records, no login
 *   node scripts/inwx-dns.mjs --plan      login, diff against live zone
 *   node scripts/inwx-dns.mjs --apply     create the missing records
 *
 * Domain override: INWX_DOMAIN env var (default fiscanto.de).
 */

const API_URL = 'https://api.domrobot.com/jsonrpc/';
const DOMAIN = (process.env.INWX_DOMAIN || 'fiscanto.de').trim();
const TTL = 3600;

async function inwxCall(method, params = {}, cookie = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(API_URL, {
    method: 'POST',
    headers,
    body: JSON.stringify({ method, params }),
    signal: AbortSignal.timeout(20000),
  });
  const setCookie = res.headers.get('set-cookie');
  const data = await res.json();
  if (data.code !== 1000) {
    throw new Error(`INWX ${method} failed (code ${data.code}): ${data.msg || 'unknown error'}`);
  }
  return { data: data.resData, cookie: setCookie || cookie };
}

// host '' means the zone apex (fiscanto.de itself).
function desiredRecords() {
  const recs = [
    { type: 'MX', host: '', content: 'mail.protonmail.ch', prio: 10, note: 'Proton primary mail server' },
    { type: 'MX', host: '', content: 'mailsec.protonmail.ch', prio: 20, note: 'Proton fallback mail server' },
    { type: 'TXT', host: '', content: 'v=spf1 include:_spf.protonmail.ch ~all', note: 'SPF sender policy' },
    { type: 'TXT', host: '_dmarc', content: 'v=DMARC1; p=none', note: 'DMARC monitor mode' },
  ];
  const dkim = [
    ['protonmail._domainkey', process.env.INWX_DKIM1],
    ['protonmail2._domainkey', process.env.INWX_DKIM2],
    ['protonmail3._domainkey', process.env.INWX_DKIM3],
  ];
  for (const [host, target] of dkim) {
    if (target && target.trim()) {
      recs.push({ type: 'CNAME', host, content: target.trim().replace(/\.$/, ''), note: `DKIM ${host}` });
    }
  }
  return recs;
}

function fqdn(host) {
  return host ? `${host}.${DOMAIN}` : DOMAIN;
}

// INWX returns TXT content sometimes wrapped in quotes; normalise for compare.
function norm(value) {
  return String(value ?? '').trim().replace(/^"|"$/g, '').trim();
}

function findExisting(desired, existing) {
  const wantName = fqdn(desired.host).toLowerCase();
  const wantContent = norm(desired.content);
  return existing.find((r) => {
    if (String(r.type).toUpperCase() !== desired.type) return false;
    if (String(r.name).toLowerCase() !== wantName) return false;
    if (norm(r.content) !== wantContent) return false;
    if (desired.type === 'MX' && Number(r.prio) !== desired.prio) return false;
    return true;
  });
}

function printDesired(recs) {
  console.log(`\nDesired DNS records for ${DOMAIN}:`);
  for (const r of recs) {
    const prio = r.prio != null ? `  prio ${r.prio}` : '';
    console.log(`  ${r.type.padEnd(5)} ${fqdn(r.host).padEnd(34)} -> ${r.content}${prio}`);
    console.log(`        # ${r.note}`);
  }
  const missingDkim = [1, 2, 3].filter((n) => !process.env[`INWX_DKIM${n}`]);
  if (missingDkim.length) {
    console.log(`\n  NOTE: ${missingDkim.length} DKIM target(s) not set.`);
    console.log('  DKIM CNAMEs stay skipped until Christoph supplies them from Proton.');
  }
}

async function login() {
  const user = (process.env.INWX_USER || '').trim();
  const pass = process.env.INWX_PASS || '';
  if (!user || !pass) {
    throw new Error('INWX_USER and INWX_PASS env vars are required for --plan and --apply.');
  }
  const { cookie } = await inwxCall('account.login', { user, pass });
  return cookie;
}

async function main() {
  const mode = process.argv[2] || '--dry-run';
  const recs = desiredRecords();

  if (mode === '--dry-run') {
    printDesired(recs);
    console.log('\nDry run only. Set INWX_USER / INWX_PASS and use --plan or --apply.');
    return 0;
  }
  if (mode !== '--plan' && mode !== '--apply') {
    console.error(`Unknown mode "${mode}". Use --dry-run, --plan or --apply.`);
    return 1;
  }

  let cookie;
  try {
    cookie = await login();
    const info = await inwxCall('nameserver.info', { domain: DOMAIN }, cookie);
    const existing = info.data?.record || [];
    const label = mode === '--apply' ? 'APPLY' : 'PLAN';
    console.log(`\n${label} for ${DOMAIN} (${existing.length} records currently in the zone)\n`);

    const missing = [];
    for (const r of recs) {
      const hit = findExisting(r, existing);
      if (hit) {
        console.log(`  ok    ${r.type.padEnd(5)} ${fqdn(r.host).padEnd(34)} already present (id ${hit.id})`);
      } else {
        missing.push(r);
        console.log(`  new   ${r.type.padEnd(5)} ${fqdn(r.host).padEnd(34)} -> ${r.content}`);
      }
    }

    if (!missing.length) {
      console.log('\nNothing to do. The zone already matches the desired state.');
      return 0;
    }
    if (mode === '--plan') {
      console.log(`\nPlan only: ${missing.length} record(s) would be created. Re-run with --apply.`);
      return 0;
    }

    let ok = 0;
    let failed = 0;
    for (const r of missing) {
      const params = { domain: DOMAIN, type: r.type, name: r.host, content: r.content, ttl: TTL };
      if (r.prio != null) params.prio = r.prio;
      try {
        const created = await inwxCall('nameserver.createRecord', params, cookie);
        ok += 1;
        console.log(`  created ${r.type.padEnd(5)} ${fqdn(r.host).padEnd(34)} id ${created.data?.id ?? '?'}`);
      } catch (err) {
        failed += 1;
        console.error(`  FAILED  ${r.type.padEnd(5)} ${fqdn(r.host).padEnd(34)} ${err.message}`);
      }
    }
    console.log(`\nApply done: ${ok} created, ${failed} failed.`);
    return failed ? 2 : 0;
  } finally {
    if (cookie) {
      try {
        await inwxCall('account.logout', {}, cookie);
      } catch {
        /* logout failure is harmless */
      }
    }
  }
}

main()
  .then((code) => process.exit(code ?? 0))
  .catch((err) => {
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  });
