#!/usr/bin/env node
/**
 * Seed smartsteuer affiliate banners into the Dockfolio banner system.
 *
 * Run once to create the banners:
 *   node scripts/seed-smartsteuer-banners.js
 *
 * Creates banners + placements for 4 tax-adjacent sites:
 *   - abfindungsoptimizer (highest fit)
 *   - schenkungsplaner (high fit)
 *   - lohncheck (good fit)
 *   - abschlusscheck (student audience)
 */

import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = join(__dirname, '..', 'dashboard', 'data.db');

const AWIN_ID = process.env.AWIN_ID || '2820526';
const ADVERTISER_ID = '15043'; // smartsteuer DE program ID from the email

// Awin click tracking URL format
const awinLink = (deeplink) =>
  `https://www.awin1.com/cread.php?awinmid=${ADVERTISER_ID}&awinaffid=${AWIN_ID}&ued=${encodeURIComponent(deeplink)}`;

const SMARTSTEUER_URL = 'https://www.smartsteuer.de';
const CLICK_URL = awinLink(SMARTSTEUER_URL);

// Banner variations per audience
const BANNERS = [
  {
    name: 'smartsteuer — Abfindung Steueroptimierung',
    slug: 'abfindungsoptimizer',
    headline: 'Abfindung erhalten? Steuererklärung jetzt einfach online machen',
    subline: 'Mit smartsteuer in unter 1 Stunde — 10% Neukunden-Rabatt mit Code CRELVO10',
    cta: 'Jetzt starten',
  },
  {
    name: 'smartsteuer — Schenkungssteuer',
    slug: 'schenkungsplaner',
    headline: 'Schenkung geplant? Steuererklärung nicht vergessen',
    subline: 'smartsteuer macht es einfach — 10% Rabatt für Neukunden mit Code CRELVO10',
    cta: 'Steuererklärung starten',
  },
  {
    name: 'smartsteuer — Lohnsteuer Arbeitnehmer',
    slug: 'lohncheck',
    headline: 'Zu viel Lohnsteuer gezahlt? Hol dir dein Geld zurück',
    subline: 'Durchschnittlich 1.063€ Erstattung — smartsteuer mit 10% Neukunden-Rabatt',
    cta: 'Erstattung berechnen',
  },
  {
    name: 'smartsteuer — Studenten Steuererklärung',
    slug: 'abschlusscheck',
    headline: 'Studium abgeschlossen? Erste Steuererklärung = bares Geld',
    subline: 'Semesterbeiträge, Laptop, Fachliteratur absetzen — 10% Rabatt mit CRELVO10',
    cta: 'Kostenlos testen',
  },
];

function generateBannerHTML(banner) {
  return `<div style="background:linear-gradient(135deg,#1a5276,#2e86c1);border-radius:8px;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;font-family:-apple-system,BlinkMacSystemFont,sans-serif;color:#fff;max-width:728px;box-sizing:border-box">
  <div style="flex:1;margin-right:16px">
    <div style="font-size:15px;font-weight:600;margin-bottom:4px">${banner.headline}</div>
    <div style="font-size:12px;opacity:0.85">${banner.subline}</div>
  </div>
  <div style="flex-shrink:0;background:#fff;color:#1a5276;padding:8px 18px;border-radius:6px;font-weight:600;font-size:13px;white-space:nowrap">${banner.cta}</div>
</div>`;
}

// --- Main ---
const db = new Database(DB_PATH, { verbose: null });
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

const insertBanner = db.prepare(`
  INSERT INTO banners (name, type, width, height, content, click_url, tags)
  VALUES (?, 'custom_html', 728, 90, ?, ?, 'affiliate,smartsteuer,awin')
`);

const insertPlacement = db.prepare(`
  INSERT INTO banner_placements (banner_id, app_slug, position, status, priority, weight, click_url)
  VALUES (?, ?, 'default', 'draft', 10, 100, ?)
`);

const seedAll = db.transaction(() => {
  let created = 0;

  for (const banner of BANNERS) {
    // Check if already exists
    const existing = db.prepare('SELECT id FROM banners WHERE name = ?').get(banner.name);
    if (existing) {
      console.log(`  SKIP: "${banner.name}" already exists (id=${existing.id})`);
      continue;
    }

    const html = generateBannerHTML(banner);
    const result = insertBanner.run(banner.name, html, CLICK_URL);
    const bannerId = result.lastInsertRowid;
    console.log(`  CREATED banner: "${banner.name}" (id=${bannerId})`);

    // Create placement for the target app
    insertPlacement.run(bannerId, banner.slug, CLICK_URL);
    console.log(`    -> Placement on ${banner.slug} (status=draft)`);

    created++;
  }

  return created;
});

console.log('\n=== Seeding smartsteuer affiliate banners ===\n');
const count = seedAll();
console.log(`\n=== Done! Created ${count} banners with placements ===`);
console.log('\nBanners are in DRAFT status. To activate:');
console.log('  1. Activate via API: PATCH /api/marketing/placements/:id { "status": "active" }');
console.log('  3. Or activate from the Dockfolio dashboard Marketing > Banners tab');
console.log('\nTo deploy banner injection to abfindungsoptimizer.de & schenkungsplaner.eu:');
console.log('  scp scripts/deploy-banner-injection.sh deploy@91.99.104.132:/tmp/');
console.log('  ssh deploy@91.99.104.132 "bash /tmp/deploy-banner-injection.sh"');

db.close();
