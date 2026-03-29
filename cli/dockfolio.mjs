#!/usr/bin/env node

import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

// --- ANSI colors ---
const c = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m', white: '\x1b[37m',
};

const __clidir = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = join(homedir(), '.dockfolio.json');
const VERSION = JSON.parse(readFileSync(join(__clidir, 'package.json'), 'utf8')).version;
const args = process.argv.slice(2);
if (args.includes('--version') || args.includes('-V')) { console.log(`dockfolio ${VERSION}`); process.exit(0); }
const jsonMode = args.includes('--json');
const filteredArgs = args.filter(a => a !== '--json' && a !== '-y' && a !== '--yes');
const command = filteredArgs[0] || 'help';
const subArgs = filteredArgs.slice(1);

// --- Config ---
function loadConfig() {
  try { return JSON.parse(readFileSync(CONFIG_PATH, 'utf8')); } catch { return null; }
}

function saveConfig(cfg) {
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  try { chmodSync(CONFIG_PATH, 0o600); } catch {}
}

// --- API helpers ---
function authHeader(cfg) {
  const token = Buffer.from(`${cfg.username}:${cfg.password}`).toString('base64');
  return { Authorization: `Basic ${token}`, 'Content-Type': 'application/json' };
}

async function api(path, cfg, method = 'GET') {
  const url = `${cfg.url.replace(/\/$/, '')}${path}`;
  try {
    const res = await fetch(url, { method, headers: authHeader(cfg), signal: AbortSignal.timeout(15000) });
    if (res.status === 401) { error('Authentication failed. Run: dockfolio init'); process.exit(1); }
    if (!res.ok) { error(`API error: ${res.status} ${res.statusText}`); process.exit(1); }
    try { return await res.json(); } catch { error('Invalid JSON response from server'); process.exit(1); }
  } catch (e) {
    if (e.name === 'TimeoutError') { error('Request timed out (15s)'); process.exit(1); }
    error(`Connection failed: ${e.message}`);
    process.exit(1);
  }
}

// --- Output helpers ---
function out(text) { console.log(text); }
function error(msg) { console.error(`${c.red}Error:${c.reset} ${msg}`); }
function heading(title) { out(`\n${c.bold}${c.cyan}${title}${c.reset}\n`); }

function statusColor(status) {
  const s = (status || '').toLowerCase();
  if (s === 'running' || s === 'healthy' || s === 'valid' || s === 'ok') return c.green;
  if (s.includes('warn') || s.includes('partial') || s.includes('expir')) return c.yellow;
  return c.red;
}

function table(rows, widths) {
  for (const row of rows) {
    const line = row.map((cell, i) => String(cell || '').padEnd(widths[i] || 20)).join('  ');
    out(line);
  }
}

function requireConfig() {
  const cfg = loadConfig();
  if (!cfg) { error('Not configured. Run: dockfolio init'); process.exit(1); }
  return cfg;
}

function prompt(rl, question) {
  return new Promise(resolve => rl.question(question, resolve));
}

function promptSecret(question) {
  return new Promise(resolve => {
    process.stdout.write(question);
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY) stdin.setRawMode(true);
    let input = '';
    const onData = (ch) => {
      const s = ch.toString();
      if (s === '\n' || s === '\r' || s === '\u0004') {
        if (stdin.isTTY) stdin.setRawMode(wasRaw || false);
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(input);
      } else if (s === '\u007f' || s === '\b') {
        if (input.length > 0) { input = input.slice(0, -1); process.stdout.write('\b \b'); }
      } else if (s === '\u0003') {
        process.exit(130);
      } else {
        input += s;
        process.stdout.write('*');
      }
    };
    stdin.resume();
    stdin.on('data', onData);
  });
}

// --- Commands ---
async function cmdInit() {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const existing = loadConfig();
    heading('Dockfolio CLI Setup');
    const url = (await prompt(rl, `Dashboard URL [${existing?.url || 'https://admin.crelvo.dev'}]: `))
      || existing?.url || 'https://admin.crelvo.dev';
    const username = (await prompt(rl, `Username [${existing?.username || ''}]: `)) || existing?.username || '';
    rl.close();
    const password = (await promptSecret(`Password: `)) || existing?.password || '';
    if (!username || !password) { error('Username and password are required.'); process.exit(1); }
    const cfg = { url, username, password };
    // Test connection
    out(`\n${c.dim}Testing connection...${c.reset}`);
    try {
      const res = await fetch(`${url.replace(/\/$/, '')}/api/health`, { headers: authHeader(cfg), signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`${res.status}`);
      out(`${c.green}Connected successfully.${c.reset}`);
    } catch (e) {
      out(`${c.yellow}Warning: Could not verify connection (${e.message}). Config saved anyway.${c.reset}`);
    }
    saveConfig(cfg);
    out(`${c.green}Config saved to ${CONFIG_PATH}${c.reset}\n`);
  } finally {
    rl.close();
  }
}

async function cmdStatus() {
  const cfg = requireConfig();
  const data = await api('/api/apps', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('App Status');
  const apps = Array.isArray(data) ? data : data.apps || [];
  const rows = apps.map(a => {
    const containers = (a.containers || []).map(ct => {
      const s = ct.status || ct.state || 'unknown';
      return `${statusColor(s)}${ct.name || ct}(${s})${c.reset}`;
    }).join(', ') || `${c.dim}no containers${c.reset}`;
    return [` ${a.name || a.slug}`, containers];
  });
  for (const r of rows) out(`${c.bold}${r[0]}${c.reset}  ${r[1]}`);
  out('');
}

async function cmdSystem() {
  const cfg = requireConfig();
  const data = await api('/api/system', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('System Resources');
  const bar = (pct) => {
    const w = 30, filled = Math.round(w * (pct || 0) / 100);
    const color = pct > 90 ? c.red : pct > 70 ? c.yellow : c.green;
    return `${color}${'█'.repeat(filled)}${c.dim}${'░'.repeat(w - filled)}${c.reset} ${pct}%`;
  };
  const cpu = data.cpu?.usage ?? data.cpuUsage ?? 0;
  const mem = data.memory?.usedPercent ?? data.memoryUsage ?? 0;
  const disk = data.disk?.usedPercent ?? data.diskUsage ?? 0;
  out(`  CPU:    ${bar(Math.round(cpu))}`);
  out(`  Memory: ${bar(Math.round(mem))}`);
  out(`  Disk:   ${bar(Math.round(disk))}`);
  if (data.load) out(`  Load:   ${data.load.join?.(' / ') || data.load}`);
  if (data.uptime) out(`  Uptime: ${data.uptime}`);
  out('');
}

async function cmdLogs() {
  const container = subArgs[0];
  if (!container) { error('Usage: dockfolio logs <container>'); process.exit(1); }
  const cfg = requireConfig();
  const data = await api(`/api/containers/${encodeURIComponent(container)}/logs?tail=100`, cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading(`Logs: ${container}`);
  const logs = data.logs || data.output || data;
  if (typeof logs === 'string') out(logs);
  else if (Array.isArray(logs)) logs.forEach(l => out(l));
  else out(JSON.stringify(logs, null, 2));
}

async function cmdRestart() {
  const container = subArgs[0];
  if (!container) { error('Usage: dockfolio restart <container>'); process.exit(1); }
  const cfg = requireConfig();
  // Confirmation
  if (!args.includes('-y') && !args.includes('--yes')) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await prompt(rl, `${c.yellow}Restart ${container}? [y/N]:${c.reset} `);
    rl.close();
    if (answer.toLowerCase() !== 'y') { out('Cancelled.'); return; }
  }
  out(`${c.dim}Restarting ${container}...${c.reset}`);
  const data = await api(`/api/containers/${encodeURIComponent(container)}/restart`, cfg, 'POST');
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  out(`${c.green}Container ${container} restarted.${c.reset}\n`);
}

async function cmdApps() {
  const cfg = requireConfig();
  const data = await api('/api/config/apps', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('Configured Apps');
  const apps = Array.isArray(data) ? data : data.apps || [];
  const rows = [
    [`${c.bold}Name${c.reset}`, `${c.bold}Slug${c.reset}`, `${c.bold}Domain${c.reset}`, `${c.bold}Type${c.reset}`],
  ];
  for (const a of apps) rows.push([a.name || '', a.slug || '', a.domain || '', a.type || '']);
  table(rows, [25, 22, 30, 10]);
  out('');
}

async function cmdHealth() {
  const cfg = requireConfig();
  const data = await api('/api/health', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('Health Check');
  const status = data.status || data.state || 'unknown';
  const color = statusColor(status);
  out(`  Status: ${color}${c.bold}${status}${c.reset}`);
  if (data.version) out(`  Version: ${data.version}`);
  if (data.uptime) out(`  Uptime: ${data.uptime}`);
  if (data.checks) {
    for (const [k, v] of Object.entries(data.checks)) {
      const s = typeof v === 'object' ? v.status || JSON.stringify(v) : v;
      out(`  ${k}: ${statusColor(String(s))}${s}${c.reset}`);
    }
  }
  out('');
}

async function cmdSsl() {
  const cfg = requireConfig();
  const data = await api('/api/ssl', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('SSL Certificate Status');
  const certs = Array.isArray(data) ? data : data.certificates || data.ssl || [];
  if (!certs.length) { out(`${c.dim}  No SSL data available.${c.reset}`); return; }
  for (const cert of certs) {
    const s = cert.status || cert.state || 'unknown';
    const days = cert.daysRemaining ?? cert.days_remaining ?? '';
    const dayStr = days !== '' ? ` (${days}d remaining)` : '';
    out(`  ${c.bold}${cert.domain || cert.name}${c.reset}  ${statusColor(s)}${s}${c.reset}${dayStr}`);
  }
  out('');
}

async function cmdPredictions() {
  const cfg = requireConfig();
  const data = await api('/api/focus', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('Resource Predictions');
  out(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
}

async function cmdDeploys() {
  const cfg = requireConfig();
  const data = await api('/api/deploys', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('Recent Deploys');
  const deploys = Array.isArray(data) ? data : data.deploys || [];
  if (!deploys.length) { out(`${c.dim}  No deploy history available.${c.reset}`); return; }
  for (const d of deploys) {
    const s = d.status || 'unknown';
    out(`  ${statusColor(s)}${s}${c.reset}  ${d.app || d.name || ''}  ${d.timestamp || d.date || ''}  ${d.message || ''}`);
  }
  out('');
}

async function cmdSearch() {
  const query = subArgs.join(' ');
  if (!query) { error('Usage: dockfolio search <query>'); process.exit(1); }
  const cfg = requireConfig();
  const data = await api(`/api/command/search?q=${encodeURIComponent(query)}`, cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading(`Search: "${query}"`);
  const results = Array.isArray(data) ? data : data.results || [];
  if (!results.length) { out(`${c.dim}  No results found.${c.reset}`); return; }
  for (const r of results) {
    out(`  ${c.bold}${r.title || r.name || r.label || ''}${c.reset}  ${c.dim}${r.description || r.type || ''}${c.reset}`);
  }
  out('');
}

async function cmdPerf() {
  const cfg = requireConfig();
  const data = await api('/api/perf', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('API Performance');
  out(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
}

async function cmdNotifications() {
  const cfg = requireConfig();
  const data = await api('/api/notifications', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('Notifications');
  const items = Array.isArray(data) ? data : data.notifications || [];
  if (!items.length) { out(`${c.dim}  No unread notifications.${c.reset}`); return; }
  for (const n of items) {
    const icon = n.type === 'error' ? c.red + '!' : n.type === 'warning' ? c.yellow + '!' : c.blue + 'i';
    out(`  ${icon}${c.reset} ${n.message || n.title || JSON.stringify(n)}  ${c.dim}${n.timestamp || ''}${c.reset}`);
  }
  out('');
}

async function cmdCost() {
  const cfg = requireConfig();
  const data = await api('/api/portfolio/pnl', cfg);
  if (jsonMode) return out(JSON.stringify(data, null, 2));
  heading('Cost Analysis');
  out(typeof data === 'string' ? data : JSON.stringify(data, null, 2));
}

function cmdHelp() {
  heading('Dockfolio CLI');
  out(`  Usage: ${c.bold}dockfolio <command> [options]${c.reset}\n`);
  const cmds = [
    ['init',               'Configure CLI (URL, credentials)'],
    ['status',             'Show all apps with container status'],
    ['system',             'Show CPU, memory, disk, load'],
    ['logs <container>',   'Show last 100 lines of container logs'],
    ['restart <container>','Restart a container (with confirmation)'],
    ['apps',               'List all configured apps'],
    ['health',             'Dashboard health check'],
    ['ssl',                'Show SSL certificate status'],
    ['predictions',        'Show resource predictions'],
    ['deploys',            'Show recent deploy history'],
    ['search <query>',     'Search via command palette'],
    ['perf',               'Show API performance metrics'],
    ['notifications',      'Show unread notifications'],
    ['cost',               'Run cost analysis'],
    ['help',               'Show this help'],
  ];
  for (const [cmd, desc] of cmds) out(`  ${c.green}${cmd.padEnd(22)}${c.reset}${desc}`);
  out(`\n  ${c.dim}Options:${c.reset}`);
  out(`    ${c.yellow}--json${c.reset}       Output raw JSON`);
  out(`    ${c.yellow}-y, --yes${c.reset}    Skip confirmation prompts`);
  out(`    ${c.yellow}-V, --version${c.reset} Show version\n`);
  out(`  ${c.dim}Config: ${CONFIG_PATH}${c.reset}\n`);
}

// --- Router ---
const commands = {
  init: cmdInit, status: cmdStatus, system: cmdSystem, logs: cmdLogs,
  restart: cmdRestart, apps: cmdApps, health: cmdHealth, ssl: cmdSsl,
  predictions: cmdPredictions, deploys: cmdDeploys, search: cmdSearch,
  perf: cmdPerf, notifications: cmdNotifications, cost: cmdCost, help: cmdHelp,
};

const handler = commands[command];
if (!handler) {
  error(`Unknown command: ${command}`);
  out(`Run ${c.bold}dockfolio help${c.reset} for usage.\n`);
  process.exit(1);
}
try {
  await handler();
} catch (e) {
  error(e.message || 'Unexpected error');
  process.exit(1);
}
