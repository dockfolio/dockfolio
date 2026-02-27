# CLAUDE.md — Dockfolio

## What This Is
Dockfolio is a self-hosted Docker dashboard combining infrastructure management with business intelligence. Single Node.js monolith, 13 apps on one Hetzner VM. AGPL-3.0.

## Quick Navigation
| Need to know...           | Read this file                          |
|---------------------------|-----------------------------------------|
| Current state & next steps| handover.md                             |
| All apps, ports, domains  | dashboard/config.yml                    |
| Engineering principles    | PRINCIPLES.md                           |
| Accounts & credentials    | ACCOUNTS.md *(gitignored)*              |
| Product strategy          | plans/product-strategy.md               |
| Productization roadmap    | plans/productization-plan.md            |
| Deploy process            | deploy.sh *(read the comments)*         |
| Environment variables     | .env.example                            |
| Contributing guide        | CONTRIBUTING.md                         |
| Launch copy               | LAUNCH.md                               |

## Architecture
- **Backend:** `dashboard/server.js` — Express, ~80 routes, SQLite (better-sqlite3), Dockerode, node-cron (~3,900 lines)
- **Frontend:** `dashboard/public/index.html` — vanilla JS SPA, keyboard-driven, no build step (~3,400 lines)
- **Config:** `dashboard/config.yml` — all 13 apps with containers, domains, ports, health endpoints, env paths, marketing metadata
- **Databases:** `auth.db` (sessions/users), `data.db` (marketing/metrics/healing/banners) — both SQLite, WAL mode
- **Deploy:** `bash deploy.sh --rebuild` from project root (rsync to VM, docker compose up)
- **CI:** `.github/workflows/docker.yml` — builds to ghcr.io/crelvo/appmanager

## VM & Infrastructure
- **IP:** 91.99.104.132 | **User:** deploy | **SSH:** via ssh-agent (no password)
- **Nginx:** `/home/deploy/nginx-configs/` | Reload: `sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload`
- **Banner injection:** All 12 user-facing sites have embed.js via nginx `sub_filter`
- **Backups:** `/home/deploy/backups/` — daily 3-4 AM, 7-day retention
- **fail2ban:** Active on SSH — avoid rapid connections

## The 13 Apps
| App | Type | Domain | Port | Containers |
|-----|------|--------|------|------------|
| PromoForge | SaaS | promoforge.app | 3000 | api, worker, postgres, redis |
| BannerForge | SaaS | bannerforge.app | 3003 | bannerforge |
| Headshot AI | SaaS | bewerbungsfotos-ai.de | 3001 | headshot-web |
| AbschlussCheck | Tool | abschlusscheck.de | 3002 | abschlusscheck |
| LohnCheck | Tool | lohncheck.info | 8002 | lohncheck-web, lohncheck-db |
| SacredLens | Tool | sacredlens.app | 8001 | sacredlens |
| Plausible | Infra | plausible.crelvo.dev | 8000 | plausible, plausible-db, plausible-events-db |
| TheADHDMind | Static | theadhdmind.org | — | theadhdmind |
| Creative Programmer | Static | creativeprogrammer.de | — | creative-programmer |
| Crelvo | Static | crelvo.dev | — | crelvo-website |
| Old World Logos | Static | oldworldlogos.com | — | old-world-logos |
| Code With Rigor | Static | codewithrigor.com | — | codewithrigor |
| AgoraHoch3 | Static | agorahoch3.de | — | agorahoch3 |

Full config with env paths, compose files, repos, marketing metadata: `dashboard/config.yml`

## API Reference
Base URL: `https://admin.crelvo.dev`
Auth: Session cookie (POST /api/auth/login) or Basic Auth (credentials in ACCOUNTS.md)
Public endpoints (no auth): `/login`, `/api/auth/*`, `/health`, `/api/health`, `/api/banners/embed.js`, `/api/banners/serve`, `/api/banners/*/click`, `/api/banners/*/view`

### Auth
```
GET  /api/auth/status                          — Check if setup needed
POST /api/auth/setup                           — Create initial admin
POST /api/auth/login                           — Login (returns session cookie)
POST /api/auth/logout                          — Logout
GET  /api/auth/me                              — Current user info
```

### Docker & Infrastructure
```
GET  /api/apps                                 — All apps with live container status
GET  /api/system                               — CPU, memory, disk, load, swap
GET  /api/containers/stats                     — Per-container CPU/memory usage
GET  /api/containers/:name/logs?tail=N         — Container logs (last N lines)
POST /api/containers/:name/restart             — Restart a container
GET  /api/docker/overview                      — Docker engine info + summary
GET  /api/health                               — Dashboard health check
GET  /api/uptime                               — Uptime Kuma integration
GET  /api/ssl                                  — SSL certificate status per domain
GET  /api/events                               — Recent Docker events
GET  /api/disk                                 — Disk usage breakdown
POST /api/actions/prune                        — Docker system prune
GET  /api/discover                             — Auto-discover untracked containers
GET  /api/backups                              — Backup status per app
```

### App Configuration
```
GET    /api/config/apps                        — All app configs from config.yml
POST   /api/config/apps                        — Add new app
PUT    /api/config/apps/:slug                  — Update app config
DELETE /api/config/apps/:slug                  — Remove app
```

### Environment Management
```
GET  /api/apps/:slug/env                       — Read app's .env file
PUT  /api/apps/:slug/env                       — Write app's .env file
POST /api/apps/:slug/recreate                  — docker compose up -d --no-build
GET  /api/env/health                           — Validate all API keys
GET  /api/env/shared                           — Detect shared keys across apps
```

### Marketing & Revenue
```
GET  /api/marketing/overview                   — Portfolio summary (revenue + traffic + health)
GET  /api/marketing/revenue                    — Stripe MRR, 30d revenue, per-app breakdown
GET  /api/marketing/analytics                  — Plausible traffic per app
GET  /api/marketing/trends                     — Historical revenue/traffic trends
GET  /api/marketing/health                     — Integration health (Stripe, Plausible, etc.)
GET  /api/marketing/seo?url=DOMAIN             — SEO audit (13 checks, 0-100 score)
```

### Content & Email
```
GET   /api/marketing/content                   — AI-generated content queue
POST  /api/marketing/content/generate          — Generate content (Anthropic)
PATCH /api/marketing/content/:id               — Update content status
GET   /api/marketing/emails/sequences          — Email lifecycle sequences
GET   /api/marketing/emails/queue              — Email send queue
POST  /api/marketing/emails/send-test          — Send test email (Resend)
POST  /api/marketing/emails/pause/:id          — Pause email sequence
POST  /api/marketing/emails/resume/:id         — Resume email sequence
```

### Cohorts & Cross-Promotion
```
GET    /api/marketing/cohorts                  — Cross-app customer graph (Stripe emails)
GET    /api/marketing/cohorts/crosssell        — Cross-sell opportunities
GET    /api/marketing/crosspromo               — Cross-promo campaigns
POST   /api/marketing/crosspromo               — Create campaign
PATCH  /api/marketing/crosspromo/:id           — Update campaign
DELETE /api/marketing/crosspromo/:id           — Delete campaign
GET    /api/crosspromo/embed.js                — Legacy embeddable script
GET    /api/crosspromo/banner                  — Serve legacy cross-promo banner
POST   /api/crosspromo/:id/view                — Track legacy view
GET    /api/crosspromo/:id/click               — Track legacy click + redirect
```

### Banner System (v2)
```
GET    /api/marketing/banners                  — List all banners
POST   /api/marketing/banners                  — Create banner
PUT    /api/marketing/banners/:id              — Update banner
DELETE /api/marketing/banners/:id              — Delete banner
POST   /api/marketing/banners/:id/regenerate   — Regenerate via BannerForge
GET    /api/marketing/placements               — List placements per app
POST   /api/marketing/placements               — Create placement
PATCH  /api/marketing/placements/:id           — Update placement (activate/pause)
DELETE /api/marketing/placements/:id           — Delete placement
GET    /api/banners/embed.js                   — Embeddable script (public, injected by nginx)
GET    /api/banners/serve?app=SLUG             — Serve banner for site (public)
POST   /api/banners/:placementId/view          — Track view (public)
GET    /api/banners/:placementId/click         — Track click + redirect (public)
GET    /api/banners/injection-status           — Check nginx injection across sites
```

### Marketing Playbooks
```
GET    /api/marketing/playbooks                — List playbooks
POST   /api/marketing/playbooks                — Create playbook
PUT    /api/marketing/playbooks/:id            — Update playbook
DELETE /api/marketing/playbooks/:id            — Delete playbook
POST   /api/marketing/playbooks/:appSlug/generate — AI-generate playbook (Anthropic Haiku)
```

### Security
```
GET  /api/security/scan?category=CATEGORY      — Run security scan (full, auth, docker, network, etc.)
GET  /api/security/status                      — Latest scan results with findings
GET  /api/security/history?limit=N             — Historical scan results
GET  /api/security/app/:slug                   — Security findings for a specific app
POST /api/security/dismiss/:id                 — Dismiss a security finding
```

### AI & Automation
```
GET  /api/briefing                             — AI morning briefing (Anthropic Haiku)
GET  /api/command/search?q=QUERY               — Command palette fuzzy search
GET  /api/healing/log                          — Auto-healing event log
POST /api/healing/approve/:id                  — Approve manual healing action
POST /api/healing/dismiss/:id                  — Dismiss healing event
```

## Cron Jobs (server.js)
| Schedule | Job |
|----------|-----|
| Every 6h | Revenue + analytics refresh (Stripe, Plausible) |
| Daily 2 AM | SEO audits for all domains |
| Weekly Sun 3 AM | AI content generation |
| Daily 3:30 AM | Cross-app cohort analysis (Stripe) |
| Hourly | Email queue processing (Resend) |
| Every 2 min | Auto-healing check + Telegram alerts |

## Key Conventions
- **Two files:** All backend in `server.js`, all frontend in `index.html` — by design
- **No TypeScript, no bundler, no framework** — vanilla JS, KISS philosophy
- **Config-driven:** App changes go through `config.yml`, not hardcoded
- **SQLite everywhere:** WAL mode, busy_timeout=5000, better-sqlite3
- **Conventional commits:** Imperative mood, present tense, under 72 chars
- **No test suite yet** — manual testing, acknowledged limitation
- **Follow PRINCIPLES.md** — KISS > architecture, YAGNI > speculative features

## Common Agent Tasks
- **Check all app status:** `GET /api/apps` returns live container status for all 13 apps
- **Read container logs:** `GET /api/containers/{container-name}/logs?tail=100`
- **Restart a container:** `POST /api/containers/{container-name}/restart`
- **Get system health:** `GET /api/system` for CPU/memory/disk, `GET /api/health` for dashboard
- **Check revenue:** `GET /api/marketing/revenue` for Stripe data across all apps
- **Run SEO audit:** `GET /api/marketing/seo?url=promoforge.app`
- **Deploy changes:** `bash deploy.sh --rebuild` from project root
- **Add an API endpoint:** Add route in `server.js`, follow existing try/catch + res.json pattern
- **Add a UI panel:** Add to `index.html`, follow glassmorphic card pattern with keyboard shortcut
- **Modify app config:** Edit `dashboard/config.yml` or use `PUT /api/config/apps/:slug`
