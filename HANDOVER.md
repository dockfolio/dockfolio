# Session Handover

**Date:** 2026-06-11 (Session 25)
**Goal:** Drain the last user-gated items of the legal/compliance sweep in `RECHTLICHE-ANALYSE.md`. User answered three decisions up front, then "go" (autonomous). All shippable items shipped.

## ⚠️ Authoritative document is RECHTLICHE-ANALYSE.md

The legal analysis + live fix log lives in **`RECHTLICHE-ANALYSE.md`** (§5b). Single source of truth for the compliance state of all public sites. This file is a thin pointer + session summary.

## Decisions taken this session (user-answered, then autonomous)

1. **betpilot** → take offline / fully private.
2. **MwSt** → stay §19 Kleinunternehmer, fix wording.
3. **Infra** → do both (BannerForge versioning + AbschlussCheck CI).

## What got done (each its own commit + push)

1. **PromoForge MwSt → §19** (`konradreyhe/videoCreator` `079e509e`). `de.ts` pricing, `AGBPage.tsx`, `HelpCenterPage.data.tsx`: "inkl./zzgl. 19% MwSt" → "Endpreis ohne Umsatzsteuer (§19 UStG)". ⚠️ Live deploy deferred (manual SSH `docker compose down/up` downs the DB; 🟡 priority, ~0 traffic). Source correct + CI-validated.
2. **Headshot AI MwSt → §19** (`konradreyhe/headshot-ai-pro` `65b9d67`). `messages/de.json` (2 spots). ⚠️ CI auto-deploy failed — billing block (see below); ships when billing restored.
3. **betpilot privatized** — whole `betpilot.crelvo.dev` now behind nginx Basic Auth (reuses `/home/deploy/appmanager/.htpasswd` = admin dashboard creds). A non-public Telemedium has no DDG Impressumspflicht → item 8 closed without putting the Klarname on a gambling tool. `/health` stays open for monitoring. **Live verified:** `/`,`/login`,`/dashboard` = 401; `/health` = 200. VM `config.yml` health → `/health`. Backups: `nginx-configs-backup-betpilot-private-20260611.conf`, `appmanager-config-backup-betpilot-20260611.yml`. Fix log `160d356`.
4. **BannerForge** — premise was wrong: `konradreyhe/bannerforge` already exists (private, active). VM `/home/deploy/bannerforge` is a stale April copy (live build, clean). **Real find:** canonical June redesign had reintroduced fake testimonials + "1,000+" claims → removed (`ed1a86f`). Live unaffected (already clean).
5. **AbschlussCheck CI** — no code bug. `deploy.yml` sound (last success Apr 7), VM pulls the prebuilt image (the "2-byte stub Dockerfile" is irrelevant). Root cause = billing block. Added `workflow_dispatch` (`8fe0a41`) for one-click re-deploy post-billing. Live already current (`/agb`,`/widerruf` = 200).

appManager fix-log commits: `160d356` (betpilot) + this handover/analysis-update commit.

## 🔴 CRITICAL blocker for the user — GitHub Actions billing

GitHub Actions is **disabled account-wide**: runs fail with "recent account payments have failed or your spending limit needs to be increased." Affects every repo. So pushed fixes (Headshot, and any future push) won't auto-deploy until you fix **GitHub → Settings → Billing & plans**. Then they deploy automatically / via `workflow_dispatch`.

## What's left (genuine user decisions, not code)

1. **GitHub Actions billing** — fix it, then Headshot MwSt deploys automatically; re-run AbschlussCheck deploy via workflow_dispatch.
2. **PromoForge live deploy** — manual SSH rebuild (downs DB): `ssh deploy@91.99.104.132 "cd /opt/promoforge && git pull && docker compose build && docker compose down && docker compose up -d"`. Deferred (DB downtime for a 🟡 wording fix).
3. **BannerForge divergence** — canonical June redesign (Three.js hero, now testimonial-free) vs. live April build. Decide which is canonical + whether to deploy the redesign. USD→EUR/§19 pricing still a business decision (touches Stripe).
4. **agorahoch3.org** — client's Impressum/Datenschutz duty; escalate (you are host/builder only).
5. **Insurance (Markel Pro Media)** — acute defects cleared; clarify the 3 broker questions in §4.5, then sign (start-up discount while <1 yr). orbedge + betpilot excluded (trading/gambling).

## Rollback

Each item independently revertable. betpilot: restore `nginx-configs-backup-betpilot-private-20260611.conf` + reload. MwSt/testimonials: `git revert` the noted commits per repo. appManager changes are doc-only (RECHTLICHE-ANALYSE.md + handover).

## Recurring patterns (confirmed)

- `config.yml` is **gitignored** in appManager — it's rsync/VM-local, not version-controlled. Edit the VM copy at `/home/deploy/appmanager/dashboard/config.yml` for live effect.
- Make a site private without an Impressum: whole-server `auth_basic` + `auth_basic_user_file /home/deploy/appmanager/.htpasswd`, keep `location = /health { auth_basic off; }`.
- SSH: always `deploy@91.99.104.132`, `-o BatchMode=yes`, one connect per action, never retry failed auth (fail2ban). Passwordless `sudo nginx -c /home/deploy/nginx-configs/nginx.conf -t / -s reload`.
- BannerForge/AbschlussCheck/Headshot deploy = build image → push ghcr → VM `docker compose pull` (VM does not build). PromoForge = manual SSH `docker compose build` on VM.
