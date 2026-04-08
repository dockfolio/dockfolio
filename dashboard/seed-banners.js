/**
 * Seed cross-promotion banners for the career pipeline.
 *
 * Usage: Run via the dashboard API after deployment.
 * This file documents the banner configurations — create them via:
 *   POST /api/marketing/banners
 *   POST /api/marketing/placements
 *
 * Or run: node seed-banners.js http://localhost:3000 (with auth cookie)
 */

const BANNERS = [
  // AbschlussCheck → LohnCheck
  {
    name: 'Thesis done → Salary check',
    type: 'custom_html',
    width: 728, height: 90,
    click_url: 'https://lohnpruefung.de?ref=abschlusscheck',
    tags: 'crosspromo,career',
    content: '<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:8px;color:#fff;font-family:system-ui"><span style="font-size:24px">🎓</span><div><strong style="font-size:14px">Abschlussarbeit abgegeben?</strong><br><span style="font-size:12px;opacity:0.8">Finde heraus ob dein Einstiegsgehalt fair ist → LohnCheck</span></div></div>',
    placement: { app_slug: 'abschlusscheck', position: 'default' },
  },
  // LohnCheck → Bewerbungsfotos AI
  {
    name: 'Salary too low → New job photos',
    type: 'custom_html',
    width: 728, height: 90,
    click_url: 'https://bewerbungsfotos-ai.de?ref=lohncheck',
    tags: 'crosspromo,career',
    content: '<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:linear-gradient(135deg,#0f3460,#1a1a2e);border-radius:8px;color:#fff;font-family:system-ui"><span style="font-size:24px">📸</span><div><strong style="font-size:14px">Gehalt zu niedrig? Neuer Job?</strong><br><span style="font-size:12px;opacity:0.8">Professionelle KI-Bewerbungsfotos in 5 Minuten → Bewerbungsfotos AI</span></div></div>',
    placement: { app_slug: 'lohncheck', position: 'default' },
  },
  // Bewerbungsfotos AI → AbschlussCheck
  {
    name: 'Still studying → Thesis check',
    type: 'custom_html',
    width: 728, height: 90,
    click_url: 'https://abschlusscheck.de?ref=bewerbungsfotos-ai',
    tags: 'crosspromo,career',
    content: '<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:linear-gradient(135deg,#16213e,#1a1a2e);border-radius:8px;color:#fff;font-family:system-ui"><span style="font-size:24px">📝</span><div><strong style="font-size:14px">Noch im Studium?</strong><br><span style="font-size:12px;opacity:0.8">Lass deine Abschlussarbeit in 5 Min von KI prüfen → AbschlussCheck</span></div></div>',
    placement: { app_slug: 'bewerbungsfotos-ai', position: 'default' },
  },
  // LohnCheck → AbschlussCheck
  {
    name: 'Salary negotiation → Thesis quality',
    type: 'custom_html',
    width: 728, height: 90,
    click_url: 'https://abschlusscheck.de?ref=lohncheck',
    tags: 'crosspromo,career',
    content: '<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:linear-gradient(135deg,#1a1a2e,#0f3460);border-radius:8px;color:#fff;font-family:system-ui"><span style="font-size:24px">✅</span><div><strong style="font-size:14px">Bessere Note = besseres Gehalt</strong><br><span style="font-size:12px;opacity:0.8">KI-Feedback für deine Abschlussarbeit → AbschlussCheck</span></div></div>',
    placement: { app_slug: 'lohncheck', position: 'footer' },
  },
  // All German sites → Career Bundle
  {
    name: 'Crelvo Career Bundle',
    type: 'custom_html',
    width: 728, height: 90,
    click_url: 'https://crelvo.dev/karriere?ref=crosspromo',
    tags: 'crosspromo,bundle,career',
    content: '<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:linear-gradient(135deg,#e94560,#0f3460);border-radius:8px;color:#fff;font-family:system-ui"><span style="font-size:24px">🚀</span><div><strong style="font-size:14px">Karriere-Bundle: Thesis + Gehalt + Bewerbungsfoto</strong><br><span style="font-size:12px;opacity:0.8">3 Tools, 1 Preis — von Crelvo</span></div></div>',
    placement: null, // Deploy manually to specific apps
  },
  // Dev sites → Dockfolio
  {
    name: 'Dockfolio promo',
    type: 'custom_html',
    width: 728, height: 90,
    click_url: 'https://dockfolio.dev?ref=crosspromo',
    tags: 'crosspromo,dev',
    content: '<div style="display:flex;align-items:center;gap:12px;padding:12px 20px;background:linear-gradient(135deg,#1a1a2e,#533483);border-radius:8px;color:#fff;font-family:system-ui"><span style="font-size:24px">⚡</span><div><strong style="font-size:14px">Running Docker apps? Try Dockfolio</strong><br><span style="font-size:12px;opacity:0.8">Self-hosted dashboard for solopreneurs — infra + revenue + marketing in one</span></div></div>',
    placement: { app_slug: 'codewithrigor', position: 'default' },
  },
];

// Export for use as documentation / reference
export default BANNERS;
