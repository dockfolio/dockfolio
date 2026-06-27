# Session Handover

**Date:** 2026-06-27 (Session 26)
**Goal:** Make the Telegram bot notices clearer — distinguish real purchases from ordinary page visits, and tighten bot filtering so only real visitors ping. User: "make it clearer" → chose Both (success-page heads-up + Stripe confirmation) + restyle visits, then "do all" (autonomous).

## ⚠️ Authoritative document is RECHTLICHE-ANALYSE.md

For legal/compliance state of public sites, `RECHTLICHE-ANALYSE.md` (§5b) remains the single source of truth. This file is the rolling session handover.

## What got shipped this session (deployed + verified)

Three Telegram-notification improvements. The previous setup sent one identical format for every page view, so a sale and a blog reader looked the same in chat.

### 1. Dashboard Stripe sales poller — CONFIRMED sale notice
- **Code:** `dashboard/routes/stripe.js` + `dashboard/server.js`. Commits `6e51131` (initial) + `4b331a4` (account-dedup fix) on `master`, pushed to origin.
- New cron `stripe-sales` (every 2 min) → `pollStripeSales()`. Notifies only on `paid && status===succeeded && !refunded && livemode!==false`. Message: `💰💰💰 NEUER VERKAUF` + amount (`formatMoney`, €/$/£/CHF) + payment method + email.
- ⚠️ **KEY FINDING (verified live):** the per-app Stripe keys all resolve to ONE account `acct_1SWLDMRJyY7UPueJ`, and `/v1/charges` is account-wide. The first version kept a cursor per key → one sale would have fired up to 3x with wrong app labels. **Fix:** group keys by Stripe account id (`/v1/account`, cached, key-signature fallback) → ONE cursor per account (`settings` key `stripe_seen_charge:acct_…`). Bootstraps on first sight (records position, no replay; sentinel `__none__` when no history so the very first sale still notifies). Wrapped in `try/catch → cronFail` (guardedCron has no catch).
- **No app label by design:** charges on this account carry `description=null, metadata={}`, statement descriptor mostly null/"PROMOFORGE" (account default) → no reliable per-app identity. Guessing = wrong label. So the confirmed notice shows amount+method+email; the visit-watcher `💰 möglicher Verkauf` already names the app (from domain). To get a per-app label later, set Checkout `metadata.app` at session-creation in each app and read `c.metadata.app` here.
- `server.js`: wired `cron, guardedCron, sendTelegram, cronFail, getSetting, setSetting` into `registerStripeRoutes`; added `revenue` category in `parseNotificationFromTelegram`.
- **Deployed + VERIFIED:** VM `/home/deploy/appmanager/dashboard` is **build-from-source** (`docker compose up -d --build dashboard`, container `dockfolio-dashboard`) — NOT a prebuilt image, NOT git (rsync-managed). After deploy, confirmed live: exactly ONE cursor row `stripe_seen_charge:acct_1SWLDMRJyY7UPueJ` created at the cron tick (no 3x dup), no replay of 6 historical sales, no errors. Cleaned 3 orphaned old per-key cursor rows from the settings DB. Telegram delivery proven end-to-end: dashboard token tail `1WHK78` + `chat_id 975931713` == visit-watcher's chat; sent a real test message (`telegram_ok=true`, id 12561).

### 2. visit-watcher.sh — POSSIBLE sale heads-up + restyle + bot filter
- **File:** `scripts/visit-watcher.sh`. **GITIGNORED** (contains the Telegram bot token) → not in git; the repo copy IS the deploy source, kept in sync with the VM.
- `is_purchase_success()`: detects Stripe success redirect (`session_id=cs_(live|test)_`) + common success paths (`/danke`, `/success`, `/checkout/success`, `/erfolg`, etc.). Fires `💰 möglicher Verkauf`, deduped on the cs_ session id, runs AFTER bot+datacenter filters (so bots can't fake a sale). The dashboard poller is the source of truth for real amounts.
- Normal visits relabeled `👁 Besuch` with device · IP on one line (was an unlabeled blob).
- `is_bot_ua()` extended: AI crawlers (PerplexityBot, CCBot, ChatGPT-User, Applebot, Amazonbot, meta-externalagent…), SEO scrapers, feed readers, headless tooling, `Mozilla/4.0`, bare `Mozilla/5.0 (compatible)`. Deliberately did NOT block TikTok/Snapchat/Pinterest in-app browsers (those are real humans). Tested: 5 real browser UAs pass, 7 bot UAs filtered.
- **Deployed:** backup `visit-watcher.sh.bak-20260627` on VM, scp'd, validated (LF clean, `bash -n` ok), restarted with `setsid -f` (PID was 2386297). NOTE: a plain `nohup … &` over SSH did NOT survive session close — must use `setsid -f`. There is a `@reboot` cron that restarts it, but no supervisor.

## Decisions inherited / still standing

- **GitHub Actions billing** (from session 25): was disabled account-wide. Did not need it this session — the dashboard deploy was a direct VM build, bypassing CI/ghcr entirely. If still blocked, pushes to master will show a failing `docker.yml` run, but that image is unused (VM builds locally). Harmless.
- SSH: `deploy@91.99.104.132`, `-o BatchMode=yes`, ONE connect per action, **never retry failed auth (fail2ban)**.
- `config.yml` and `scripts/visit-watcher.sh` are VM-local / gitignored — edit-and-deploy, not version-controlled.

## How to verify it's working (for the user)

- A test sale in Stripe live mode → within ~2 min a `💰💰💰 NEUER VERKAUF` message. (First poll only sets the cursor; sales AFTER that notify.)
- Any real visitor now reads `👁 Besuch`; a buyer hitting the success page reads `💰 möglicher Verkauf`.

## Rollback

- Dashboard: `git revert 4b331a4 6e51131`, re-scp `routes/stripe.js`+`server.js`, `docker compose up -d --build dashboard`. (Cron is additive; reverting fully removes it.)
- visit-watcher: on VM `cp /home/deploy/scripts/visit-watcher.sh.bak-20260627 /home/deploy/scripts/visit-watcher.sh`, `pkill -f visit-watcher.sh; rm -f /home/deploy/visit-logs/.watcher.pid; setsid -f bash /home/deploy/scripts/visit-watcher.sh`.

## Open follow-ups (not blocking)

1. Confirm each monetized app's Stripe success URL carries `?session_id=…` (Stripe Checkout default). Payment Links with a custom thank-you page need their path added to `is_purchase_success()`.
2. **Per-app sale labels:** all apps share ONE Stripe account and charges have no metadata, so the confirmed notice can't name the app. To fix, set `metadata[app]` on each app's Checkout session / payment link, then add `c.metadata.app` to the label in `pollStripeSales()`.
3. Optional: a tiny systemd unit for visit-watcher instead of the `@reboot` cron, so it auto-restarts on crash (not just reboot).
