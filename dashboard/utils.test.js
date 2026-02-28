import { strict as assert } from 'assert';
import { writeFileSync, unlinkSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  slugify, containerName, hashValue, todayString, percent, safeJSON,
  letterGrade, maskValue, parseEnvFile, serializeEnvVars,
  getMarketableApps, diskScore, securityScore, seoScore,
  parseId, asyncRoute, errorFingerprint, errorScore, rateLimit, toCsv
} from './utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.message}`);
  }
}

// --- slugify ---
console.log('\nsluglify()');

test('lowercases and replaces spaces', () => {
  assert.equal(slugify('Headshot AI'), 'headshot-ai');
});

test('handles single word', () => {
  assert.equal(slugify('PromoForge'), 'promoforge');
});

test('handles multiple spaces', () => {
  assert.equal(slugify('Old World Logos'), 'old-world-logos');
});

// --- containerName ---
console.log('\ncontainerName()');

test('strips leading slash', () => {
  assert.equal(containerName({ Names: ['/my-container'] }), 'my-container');
});

test('returns empty string for missing Names', () => {
  assert.equal(containerName({}), '');
});

test('returns empty string for empty Names array', () => {
  assert.equal(containerName({ Names: [] }), '');
});

// --- hashValue ---
console.log('\nhashValue()');

test('returns 16 chars by default', () => {
  assert.equal(hashValue('test').length, 16);
});

test('returns specified length', () => {
  assert.equal(hashValue('test', 8).length, 8);
});

test('is deterministic', () => {
  assert.equal(hashValue('secret'), hashValue('secret'));
});

test('different inputs produce different hashes', () => {
  assert.notEqual(hashValue('a'), hashValue('b'));
});

test('full hash length', () => {
  assert.equal(hashValue('test', 64).length, 64);
});

// --- todayString ---
console.log('\ntodayString()');

test('returns YYYY-MM-DD format', () => {
  const today = todayString();
  assert.match(today, /^\d{4}-\d{2}-\d{2}$/);
});

test('returns 10 characters', () => {
  assert.equal(todayString().length, 10);
});

// --- percent ---
console.log('\npercent()');

test('calculates percentage', () => {
  assert.equal(percent(50, 100), 50);
});

test('rounds to integer', () => {
  assert.equal(percent(1, 3), 33);
});

test('handles zero total', () => {
  assert.equal(percent(5, 0), 0);
});

test('handles 100%', () => {
  assert.equal(percent(100, 100), 100);
});

// --- safeJSON ---
console.log('\nsafeJSON()');

test('parses valid JSON', () => {
  assert.deepEqual(safeJSON('{"a":1}'), { a: 1 });
});

test('returns fallback for invalid JSON', () => {
  assert.equal(safeJSON('not json'), null);
});

test('returns fallback for null input', () => {
  assert.equal(safeJSON(null), null);
});

test('returns custom fallback', () => {
  assert.deepEqual(safeJSON('bad', []), []);
});

test('returns fallback for empty string', () => {
  assert.equal(safeJSON(''), null);
});

// --- letterGrade ---
console.log('\nletterGrade()');

test('A for 90+', () => { assert.equal(letterGrade(95), 'A'); });
test('A for exactly 90', () => { assert.equal(letterGrade(90), 'A'); });
test('B for 80-89', () => { assert.equal(letterGrade(85), 'B'); });
test('C for 70-79', () => { assert.equal(letterGrade(75), 'C'); });
test('D for 60-69', () => { assert.equal(letterGrade(65), 'D'); });
test('F for below 60', () => { assert.equal(letterGrade(45), 'F'); });
test('F for zero', () => { assert.equal(letterGrade(0), 'F'); });

// --- maskValue ---
console.log('\nmaskValue()');

test('masks long values', () => {
  assert.equal(maskValue('sk_live_1234567890abcdef'), 'sk_live_...cdef');
});

test('returns *** for short values', () => {
  assert.equal(maskValue('short'), '***');
});

test('returns *** for null', () => {
  assert.equal(maskValue(null), '***');
});

test('returns *** for empty string', () => {
  assert.equal(maskValue(''), '***');
});

// --- parseEnvFile ---
console.log('\nparseEnvFile()');

const tmpEnv = join(__dirname, '.test-env-tmp');

test('parses basic env file', () => {
  writeFileSync(tmpEnv, 'KEY=value\nSECRET=mysecret\n');
  const vars = parseEnvFile(tmpEnv);
  assert.equal(vars.length, 2);
  assert.equal(vars[0].key, 'KEY');
  assert.equal(vars[0].value, 'value');
  unlinkSync(tmpEnv);
});

test('strips quotes', () => {
  writeFileSync(tmpEnv, 'KEY="quoted value"\nKEY2=\'single\'\n');
  const vars = parseEnvFile(tmpEnv);
  assert.equal(vars[0].value, 'quoted value');
  assert.equal(vars[1].value, 'single');
  unlinkSync(tmpEnv);
});

test('skips comments and empty lines', () => {
  writeFileSync(tmpEnv, '# comment\n\nKEY=value\n  \n# another\n');
  const vars = parseEnvFile(tmpEnv);
  assert.equal(vars.length, 1);
  unlinkSync(tmpEnv);
});

test('handles values with equals signs', () => {
  writeFileSync(tmpEnv, 'URL=https://example.com?a=1&b=2\n');
  const vars = parseEnvFile(tmpEnv);
  assert.equal(vars[0].value, 'https://example.com?a=1&b=2');
  unlinkSync(tmpEnv);
});

test('returns empty array for missing file', () => {
  assert.deepEqual(parseEnvFile('/nonexistent'), []);
});

// --- serializeEnvVars ---
console.log('\nserializeEnvVars()');

test('serializes vars back to env format', () => {
  const result = serializeEnvVars([{ key: 'A', value: '1' }, { key: 'B', value: '2' }]);
  assert.equal(result, 'A=1\nB=2\n');
});

test('roundtrips with parseEnvFile', () => {
  const original = [{ key: 'KEY', value: 'val' }, { key: 'SECRET', value: 'abc123' }];
  writeFileSync(tmpEnv, serializeEnvVars(original));
  const parsed = parseEnvFile(tmpEnv);
  assert.deepEqual(parsed, original);
  unlinkSync(tmpEnv);
});

// --- getMarketableApps ---
console.log('\ngetMarketableApps()');

test('filters saas and tool apps', () => {
  const apps = [
    { name: 'App1', type: 'saas' },
    { name: 'App2', type: 'tool' },
    { name: 'App3', type: 'static' },
    { name: 'App4', type: 'infra' },
  ];
  const result = getMarketableApps(apps);
  assert.equal(result.length, 2);
  assert.equal(result[0].name, 'App1');
  assert.equal(result[1].name, 'App2');
});

// --- diskScore ---
console.log('\ndiskScore()');

test('15 for 90%+', () => { assert.equal(diskScore(95), 15); });
test('10 for 80-89%', () => { assert.equal(diskScore(85), 10); });
test('5 for 70-79%', () => { assert.equal(diskScore(75), 5); });
test('0 for under 70%', () => { assert.equal(diskScore(50), 0); });

// --- securityScore ---
console.log('\nsecurityScore()');

test('10 for score under 40', () => { assert.equal(securityScore(30), 10); });
test('7 for score 40-59', () => { assert.equal(securityScore(50), 7); });
test('4 for score 60-74', () => { assert.equal(securityScore(70), 4); });
test('0 for score 75+', () => { assert.equal(securityScore(80), 0); });

// --- seoScore ---
console.log('\nseoScore()');

test('5 for avg under 40', () => { assert.equal(seoScore(30), 5); });
test('3 for avg 40-59', () => { assert.equal(seoScore(50), 3); });
test('0 for avg 60+', () => { assert.equal(seoScore(70), 0); });

// --- parseId ---
console.log('\nparseId()');

test('parses valid integer', () => { assert.equal(parseId('42'), 42); });
test('parses zero', () => { assert.equal(parseId('0'), 0); });
test('returns NaN for non-numeric', () => { assert.equal(isNaN(parseId('abc')), true); });
test('returns NaN for empty string', () => { assert.equal(isNaN(parseId('')), true); });
test('returns NaN for undefined', () => { assert.equal(isNaN(parseId(undefined)), true); });
test('parses negative', () => { assert.equal(parseId('-1'), -1); });

// --- asyncRoute ---
console.log('\nasyncRoute()');

test('calls handler and resolves', async () => {
  let called = false;
  const handler = asyncRoute(async (req, res) => { called = true; });
  await handler({method: 'GET', path: '/test'}, {headersSent: false, status() { return { json() {} }; }}, () => {});
  assert.equal(called, true);
});

test('catches errors and sends 500', async () => {
  let statusCode = null;
  let errorMsg = null;
  const res = {
    headersSent: false,
    status(code) { statusCode = code; return { json(body) { errorMsg = body.error; } }; }
  };
  const handler = asyncRoute(async () => { throw new Error('boom'); });
  await handler({method: 'GET', path: '/test'}, res, () => {});
  assert.equal(statusCode, 500);
  assert.equal(errorMsg, 'boom');
});

// --- errorFingerprint ---
console.log('\nerrorFingerprint()');

test('returns 32-char hex string', () => {
  const fp = errorFingerprint('TypeError: x is not a function', 'at foo.js:10:5', 'promoforge');
  assert.equal(fp.length, 32);
  assert.match(fp, /^[0-9a-f]{32}$/);
});

test('same error produces same fingerprint', () => {
  const fp1 = errorFingerprint('TypeError: x is not a function', 'at foo.js:10:5', 'promoforge');
  const fp2 = errorFingerprint('TypeError: x is not a function', 'at foo.js:10:5', 'promoforge');
  assert.equal(fp1, fp2);
});

test('same error with different line numbers produces same fingerprint', () => {
  const fp1 = errorFingerprint('TypeError: x is not a function', '  at handler (foo.js:10:5)', 'promoforge');
  const fp2 = errorFingerprint('TypeError: x is not a function', '  at handler (foo.js:99:12)', 'promoforge');
  assert.equal(fp1, fp2);
});

test('strips UUIDs from message for grouping', () => {
  const fp1 = errorFingerprint('User a1b2c3d4-e5f6-7890-abcd-ef1234567890 not found', null, 'app');
  const fp2 = errorFingerprint('User ffffffff-ffff-ffff-ffff-ffffffffffff not found', null, 'app');
  assert.equal(fp1, fp2);
});

test('different apps produce different fingerprints', () => {
  const fp1 = errorFingerprint('Error', null, 'promoforge');
  const fp2 = errorFingerprint('Error', null, 'bannerforge');
  assert.notEqual(fp1, fp2);
});

test('handles null message and stack gracefully', () => {
  const fp = errorFingerprint(null, null, null);
  assert.equal(fp.length, 32);
});

test('extracts only top 3 stack frames', () => {
  const stack = `Error: fail
  at a (/app/a.js:1:1)
  at b (/app/b.js:2:2)
  at c (/app/c.js:3:3)
  at d (/app/d.js:4:4)
  at e (/app/e.js:5:5)`;
  const fp1 = errorFingerprint('Error: fail', stack, 'app');
  // Same top 3, different 4th+5th — should be identical
  const stack2 = `Error: fail
  at a (/app/a.js:1:1)
  at b (/app/b.js:2:2)
  at c (/app/c.js:3:3)
  at x (/app/x.js:9:9)`;
  const fp2 = errorFingerprint('Error: fail', stack2, 'app');
  assert.equal(fp1, fp2);
});

// --- errorScore ---
console.log('\nerrorScore()');

test('returns 0 when no errors', () => {
  assert.equal(errorScore(0, 0), 0);
});

test('critical errors: 5 points each, max 10', () => {
  assert.equal(errorScore(1, 0), 5);
  assert.equal(errorScore(2, 0), 10);
  assert.equal(errorScore(5, 0), 10);
});

test('regular errors: 1 point per 10, max 5', () => {
  assert.equal(errorScore(0, 10), 1);
  assert.equal(errorScore(0, 50), 5);
  assert.equal(errorScore(0, 100), 5);
});

test('total capped at 10', () => {
  assert.equal(errorScore(3, 100), 10);
});

// --- toCsv ---
console.log('\ntoCsv()');

test('converts array of objects to CSV', () => {
  const rows = [{ name: 'Alice', age: 30 }, { name: 'Bob', age: 25 }];
  assert.equal(toCsv(rows), 'name,age\nAlice,30\nBob,25');
});

test('escapes commas and quotes', () => {
  const rows = [{ text: 'hello, world', val: 'say "hi"' }];
  const csv = toCsv(rows);
  assert.ok(csv.includes('"hello, world"'));
  assert.ok(csv.includes('"say ""hi"""'));
});

test('returns empty string for empty array', () => {
  assert.equal(toCsv([]), '');
});

test('handles null/undefined values', () => {
  const rows = [{ a: null, b: undefined, c: 0 }];
  assert.equal(toCsv(rows), 'a,b,c\n,,0');
});

// --- rateLimit ---
console.log('\nrateLimit()');

test('returns a middleware function', () => {
  const mw = rateLimit(10, 60000);
  assert.equal(typeof mw, 'function');
});

test('allows requests under limit', () => {
  const mw = rateLimit(5, 60000);
  let nextCalled = false;
  const req = { ip: '127.0.0.1' };
  const res = { status() { return { json() {} }; } };
  mw(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
});

test('blocks requests over limit', () => {
  const mw = rateLimit(2, 60000);
  let blocked = false;
  const req = { ip: '10.0.0.1' };
  const res = { status(code) { if (code === 429) blocked = true; return { json() {} }; } };
  mw(req, res, () => {});
  mw(req, res, () => {});
  mw(req, res, () => {});
  assert.equal(blocked, true);
});

test('different IPs have separate limits', () => {
  const mw = rateLimit(1, 60000);
  let calls = 0;
  const res = { status() { return { json() {} }; } };
  mw({ ip: '1.1.1.1' }, res, () => { calls++; });
  mw({ ip: '2.2.2.2' }, res, () => { calls++; });
  assert.equal(calls, 2);
});

// --- Summary ---
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
