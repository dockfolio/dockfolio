import { strict as assert } from 'assert';
import { writeFileSync, unlinkSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  slugify, containerName, hashValue, todayString, percent, safeJSON,
  letterGrade, maskValue, parseEnvFile, serializeEnvVars,
  getMarketableApps, diskScore, securityScore, seoScore,
  parseId, asyncRoute
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

// --- Summary ---
console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
