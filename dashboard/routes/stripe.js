import { asyncRoute, slugify } from '../utils.js';

const STRIPE_API = 'https://api.stripe.com/v1';
const TIMEOUT_STANDARD = 10_000;

function stripeHeaders(secretKey) {
  return { 'Authorization': 'Basic ' + Buffer.from(secretKey + ':').toString('base64') };
}

export default function registerStripeRoutes({ app, config, getStripeKeys, cron, guardedCron, sendTelegram, getSetting, setSetting, cronFail }) {

  function getStripeKeyForApp(appSlug, appKeys) {
    if (!appSlug) return null;
    for (const appDef of config.apps) {
      if (slugify(appDef.name) === appSlug) {
        return appKeys.get(appDef.name);
      }
    }
    return null;
  }

  // List Stripe products and prices for an app
  app.get('/api/stripe/products', asyncRoute(async (req, res) => {
    const { keys, appKeys } = getStripeKeys();
    const appSlug = req.query.app;
    let secretKey = getStripeKeyForApp(appSlug, appKeys);
    if (!secretKey) secretKey = keys.keys().next().value;
    if (!secretKey) return res.json({ products: [], error: 'No Stripe key configured' });

    const headers = stripeHeaders(secretKey);
    const opts = { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) };

    const [productsRes, pricesRes] = await Promise.all([
      fetch(`${STRIPE_API}/products?active=true&limit=100`, opts),
      fetch(`${STRIPE_API}/prices?active=true&limit=100&expand[]=data.product`, opts),
    ]);

    const products = productsRes.ok ? (await productsRes.json()).data : [];
    const prices = pricesRes.ok ? (await pricesRes.json()).data : [];

    res.json({
      products: products.map(p => ({
        id: p.id,
        name: p.name,
        description: p.description,
        images: p.images,
        metadata: p.metadata,
      })),
      prices: prices.map(p => ({
        id: p.id,
        productId: p.product?.id || p.product,
        productName: p.product?.name || null,
        currency: p.currency,
        unitAmount: p.unit_amount,
        type: p.type,
        recurring: p.recurring ? { interval: p.recurring.interval, intervalCount: p.recurring.interval_count } : null,
      })),
      timestamp: new Date().toISOString(),
    });
  }));

  // Create a Stripe Checkout session (one-time or subscription)
  app.post('/api/stripe/checkout', asyncRoute(async (req, res) => {
    const { priceId, mode, successUrl, cancelUrl, appSlug } = req.body;
    if (!priceId) return res.status(400).json({ error: 'priceId is required' });
    if (!successUrl || !cancelUrl) {
      return res.status(400).json({ error: 'success_url and cancel_url are required' });
    }

    const { keys, appKeys } = getStripeKeys();
    let secretKey = getStripeKeyForApp(appSlug, appKeys);
    if (!secretKey) secretKey = keys.keys().next().value;
    if (!secretKey) return res.status(400).json({ error: 'No Stripe key configured' });

    const headers = stripeHeaders(secretKey);
    const body = new URLSearchParams({
      'line_items[0][price]': priceId,
      'line_items[0][quantity]': '1',
      'mode': mode || 'payment',
      'success_url': successUrl,
      'cancel_url': cancelUrl,
      'allow_promotion_codes': 'true',
      'tax_id_collection[enabled]': 'true',
    });

    // Add German payment methods for payment mode
    if ((mode || 'payment') === 'payment') {
      body.append('payment_method_types[]', 'card');
      body.append('payment_method_types[]', 'sepa_debit');
    }

    const sessionRes = await fetch(`${STRIPE_API}/checkout/sessions`, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
    });

    if (!sessionRes.ok) {
      const err = await sessionRes.json();
      return res.status(400).json({ error: err.error?.message || 'Stripe API error' });
    }

    const session = await sessionRes.json();
    res.json({
      sessionId: session.id,
      url: session.url,
      mode: session.mode,
      expiresAt: new Date(session.expires_at * 1000).toISOString(),
    });
  }));

  // List Stripe Payment Links
  app.get('/api/stripe/payment-links', asyncRoute(async (req, res) => {
    const { keys, appKeys } = getStripeKeys();
    const appSlug = req.query.app;
    let secretKey = getStripeKeyForApp(appSlug, appKeys);
    if (!secretKey) secretKey = keys.keys().next().value;
    if (!secretKey) return res.json({ links: [], error: 'No Stripe key configured' });

    const headers = stripeHeaders(secretKey);
    const linksRes = await fetch(`${STRIPE_API}/payment_links?active=true&limit=100`, {
      headers,
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
    });

    if (!linksRes.ok) {
      const err = await linksRes.json();
      return res.status(400).json({ error: err.error?.message || 'Stripe API error' });
    }

    const data = await linksRes.json();
    res.json({
      links: data.data.map(l => ({
        id: l.id,
        url: l.url,
        active: l.active,
        metadata: l.metadata,
      })),
      timestamp: new Date().toISOString(),
    });
  }));

  // Create a Stripe Payment Link (permanent, reusable)
  app.post('/api/stripe/payment-links', asyncRoute(async (req, res) => {
    const { priceId, appSlug } = req.body;
    if (!priceId) return res.status(400).json({ error: 'priceId is required' });

    const { keys, appKeys } = getStripeKeys();
    let secretKey = getStripeKeyForApp(appSlug, appKeys);
    if (!secretKey) secretKey = keys.keys().next().value;
    if (!secretKey) return res.status(400).json({ error: 'No Stripe key configured' });

    const headers = stripeHeaders(secretKey);
    const body = new URLSearchParams({
      'line_items[0][price]': priceId,
      'line_items[0][quantity]': '1',
      'allow_promotion_codes': 'true',
      'tax_id_collection[enabled]': 'true',
    });

    if (req.body.afterCompletionUrl) {
      body.append('after_completion[type]', 'redirect');
      body.append('after_completion[redirect][url]', req.body.afterCompletionUrl);
    }

    const linkRes = await fetch(`${STRIPE_API}/payment_links`, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
    });

    if (!linkRes.ok) {
      const err = await linkRes.json();
      return res.status(400).json({ error: err.error?.message || 'Stripe API error' });
    }

    const link = await linkRes.json();
    res.json({
      id: link.id,
      url: link.url,
      active: link.active,
    });
  }));

  // Stripe recent payments/charges summary
  app.get('/api/stripe/recent', asyncRoute(async (_req, res) => {
    const { keys } = getStripeKeys();
    const secretKey = keys.keys().next().value;
    if (!secretKey) return res.json({ charges: [], error: 'No Stripe key configured' });

    const headers = stripeHeaders(secretKey);
    const chargesRes = await fetch(`${STRIPE_API}/charges?limit=25`, {
      headers,
      signal: AbortSignal.timeout(TIMEOUT_STANDARD),
    });

    if (!chargesRes.ok) return res.json({ charges: [], error: 'Stripe API error' });

    const data = await chargesRes.json();
    res.json({
      charges: data.data.map(c => ({
        id: c.id,
        amount: c.amount,
        currency: c.currency,
        status: c.status,
        description: c.description,
        customerEmail: c.billing_details?.email,
        created: new Date(c.created * 1000).toISOString(),
        paid: c.paid,
        refunded: c.refunded,
      })),
      timestamp: new Date().toISOString(),
    });
  }));

  // --- New-sale watcher ------------------------------------------------------
  // Fires a clear Telegram notice the moment money actually lands. This is the
  // *confirmed* sale signal (amount); the visit-watcher's "möglicher Verkauf"
  // heads-up names *which app* (from the domain) a few seconds earlier.
  //
  // IMPORTANT: /v1/charges is account-wide, not per-app. Several app keys here
  // resolve to the SAME Stripe account, so we group keys by account id and keep
  // ONE cursor per account — otherwise one sale would fire once per key. The
  // charge itself has no per-app fields, but the Checkout Session behind it does
  // (line-item product name, app domain), so we look that up per new sale to
  // label it precisely — no app-repo changes needed (see describeSale).

  function formatMoney(amountCents, currency) {
    const amount = (amountCents / 100).toFixed(2).replace('.', ',');
    const symbols = { eur: '€', usd: '$', gbp: '£', chf: 'CHF' };
    const sym = symbols[(currency || '').toLowerCase()] || (currency || '').toUpperCase();
    return `${amount} ${sym}`.trim();
  }

  function paymentMethodLabel(c) {
    const t = c.payment_method_details?.type;
    const map = { card: 'Karte', sepa_debit: 'SEPA', paypal: 'PayPal', link: 'Link', klarna: 'Klarna', giropay: 'giropay', sofort: 'Sofort', ideal: 'iDEAL' };
    return t ? (map[t] || t) : null;
  }

  // The charge itself has no per-app info, but the Checkout Session behind it
  // does: the line-item description is a perfect label ("AbschlussCheck:
  // Bachelorarbeit"), plus a richer email and the app domain. One extra lookup
  // per new sale (rare) attributes every sale with no app-repo changes.
  async function describeSale(c, headers) {
    let label = null;
    let email = c.billing_details?.email || null;
    try {
      if (c.payment_intent) {
        const url = `${STRIPE_API}/checkout/sessions?payment_intent=${c.payment_intent}&limit=1&expand[]=data.line_items`;
        const r = await fetch(url, { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) });
        if (r.ok) {
          const s = (await r.json()).data?.[0];
          if (s) {
            const product = s.line_items?.data?.[0]?.description;
            let host = null;
            try { host = new URL(s.success_url).hostname.replace(/^www\./, ''); } catch { /* ignore */ }
            if (host === 'localhost' || /^\d/.test(host || '')) host = null; // ignore localhost / IPs
            label = product || s.metadata?.app || host || null;
            email = email || s.customer_details?.email || s.metadata?.email || null;
          }
        }
      }
    } catch { /* best-effort: fall back to no label */ }
    return { label, email };
  }

  // Resolve a secret key to its Stripe account id so keys on the same account
  // share one cursor. Cached for the process; falls back to a non-secret key
  // signature if /v1/account is unreadable (still dedupes per key).
  const accountIdCache = new Map();
  async function getAccountId(secretKey, headers) {
    if (accountIdCache.has(secretKey)) return accountIdCache.get(secretKey);
    let id = 'key_' + secretKey.slice(-8);
    try {
      const r = await fetch(`${STRIPE_API}/account`, { headers, signal: AbortSignal.timeout(TIMEOUT_STANDARD) });
      if (r.ok) { const j = await r.json(); if (j?.id) id = j.id; }
    } catch { /* keep fallback */ }
    accountIdCache.set(secretKey, id);
    return id;
  }

  async function pollStripeSales() {
    try {
      const { keys } = getStripeKeys(); // Map(secretKey -> [appNames])

      // Group distinct keys by Stripe account (dedupe shared accounts).
      const accounts = new Map(); // accountId -> { headers }
      for (const [secretKey] of keys) {
        const headers = stripeHeaders(secretKey);
        const acctId = await getAccountId(secretKey, headers);
        if (!accounts.has(acctId)) accounts.set(acctId, { headers });
      }

      for (const [acctId, info] of accounts) {
        let chargesRes;
        try {
          chargesRes = await fetch(`${STRIPE_API}/charges?limit=20`, {
            headers: info.headers,
            signal: AbortSignal.timeout(TIMEOUT_STANDARD),
          });
        } catch { continue; }
        if (!chargesRes.ok) continue;

        const data = await chargesRes.json();
        const charges = data.data || [];

        const cursorKey = `stripe_seen_charge:${acctId}`;
        const lastSeen = getSetting(cursorKey);

        // First sight of this account: record the position (or a sentinel when
        // there is no history yet) WITHOUT replaying. This also guarantees the
        // very first sale on a brand-new account still notifies next tick.
        if (lastSeen === null || lastSeen === undefined) {
          setSetting(cursorKey, charges.length ? charges[0].id : '__none__');
          continue;
        }
        if (charges.length === 0) continue;
        const newestId = charges[0].id;
        if (lastSeen === newestId) continue;

        // Collect charges newer than the cursor (newest-first list → stop at cursor).
        const fresh = [];
        for (const c of charges) {
          if (c.id === lastSeen) break;
          fresh.push(c);
        }
        // Advance the cursor regardless, so a burst is never reported twice.
        setSetting(cursorKey, newestId);

        // Notify oldest-first so the order reads naturally in the chat.
        for (const c of fresh.reverse()) {
          // Real money only: paid, settled, not refunded, and live (never test mode).
          if (!c.paid || c.status !== 'succeeded' || c.refunded || c.livemode === false) continue;
          const pm = paymentMethodLabel(c);
          const { label, email } = await describeSale(c, info.headers);
          const lines = [
            '💰💰💰 <b>NEUER VERKAUF</b>',
            label ? `🎯 ${label}` : null,
            `💶 <b>${formatMoney(c.amount, c.currency)}</b>${pm ? ` · ${pm}` : ''}`,
            email ? `📧 ${email}` : null,
          ].filter(Boolean);
          await sendTelegram(lines.join('\n'));
        }
      }
    } catch (err) {
      if (typeof cronFail === 'function') cronFail('stripe-sales', err);
      else console.error('[stripe-sales]', (err && err.message) || err);
    }
  }

  // Every 2 minutes — responsive without hammering the Stripe API.
  if (cron && guardedCron && sendTelegram && getSetting && setSetting) {
    cron.schedule('*/2 * * * *', guardedCron('stripe-sales', pollStripeSales));
  }
}
