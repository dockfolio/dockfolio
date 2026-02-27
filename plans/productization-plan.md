# App Manager — Productization Plan

**Date:** 2026-02-26
**Decision:** Productize as open-source with paid cloud offering
**Model:** Coolify-style — 100% free self-hosted, paid cloud for convenience

---

## Strategic Decision

**Why productize now:**
- No competitor combines infra management + business intelligence
- Coolify proves solo dev can reach $15K/mo MRR with open source + cloud
- The feature set is already strong — 77 endpoints, AI briefings, auto-healing, marketing manager, banners, playbooks
- "Ship fast, iterate" — Coolify v4 had zero tests when it launched

**Why NOT do a full rewrite first:**
- YAGNI — build what's needed for the next 10 users, not 10,000
- Coolify launched with messy code and iterated
- A rewrite delays launch by 6 months with zero market validation

**Revenue model:**
- Self-hosted: free forever (AGPL-3.0)
- Cloud-managed: $9/mo Solo, $19/mo Builder, $39/mo Portfolio

---

## Phase 0: Foundation (Current Sprint — 2-3 weeks)

**Goal:** Make it installable by someone else. Get 5 beta users.

### 0.1 Authentication (CRITICAL — Week 1) ✅ DONE
- [x] Add user auth with sessions (cookie-parser + SQLite session store, 30-day TTL)
- [x] Login page (username + password, bcryptjs hashed)
- [x] Protect all API routes with auth middleware (path normalization, public path whitelist)
- [x] First user = admin (setup wizard creates account via /api/auth/setup)
- [ ] API key support for programmatic access
- **NOT YET:** OAuth, RBAC, teams, SSO — those come later

### 0.2 Configuration Decoupling (Week 1) ✅ MOSTLY DONE
- [x] Move hardcoded Telegram credentials to env vars
- [x] Make config.yml user-editable via UI (add/remove apps via Settings panel)
- [x] Auto-discover running Docker containers (GET /api/discover)
- [ ] Remove all references to specific apps (PromoForge, BannerForge, etc.) — config.yml still has them
- [x] Make Stripe/Anthropic/Plausible/Resend keys configurable per-install (via .env file reading)

### 0.3 Install Script (Week 2) ✅ MOSTLY DONE
- [x] One-command install: `curl -fsSL .../install.sh | bash` (URL uses GitHub raw, not appmanager.dev)
- [x] Creates docker-compose.yml, pulls images, starts dashboard
- [x] Setup wizard: create admin account on first visit
- [ ] Works on Ubuntu 22.04+ with Docker installed — not broadly tested
- [ ] Auto-generate nginx config or run with built-in reverse proxy

### 0.4 Documentation (Week 2-3) — PARTIAL
- [x] README.md rewrite: what it does, install instructions (no screenshots yet)
- [ ] docs/getting-started.md — 5-minute quickstart (docs/ directory does not exist)
- [ ] docs/configuration.md — all config options
- [ ] docs/integrations.md — Stripe, Plausible, Anthropic, Resend setup
- [ ] CONTRIBUTING.md — how to contribute

### 0.5 Code Quality (Week 2-3) ✅ MOSTLY DONE
- [x] Remove all hardcoded secrets from code (Telegram token, Plausible key)
- [x] Add helmet.js for security headers (CSP disabled for inline scripts)
- [x] Add rate limiting on login endpoint (in-memory, 5 attempts / 15 min per IP)
- [ ] Add input validation on all POST endpoints (zod or joi) — not added, validation is manual
- [x] Basic error handling (try/catch in route handlers)
- [x] Add .env.example with all config options documented

---

## Phase 1: Launch (Weeks 4-6)

**Goal:** Public launch, first 100 GitHub stars, first 10 installs.

### 1.1 Open Source Launch
- [ ] Clean up git history (squash sensitive commits) — secrets still in history
- [x] Choose license: AGPL-3.0 (prevents SaaS forks without contributing back)
- [ ] GitHub repo: public, proper README, screenshots, demo GIF — repo still private, no screenshots
- [x] GitHub Actions: build + push to ghcr.io/crelvo/appmanager (no lint/tests yet)
- [ ] Docker Hub / ghcr.io: ghcr.io is set up, Docker Hub not used

### 1.2 Marketing Site
- [ ] Landing page at appmanager.dev (or similar domain)
- [ ] "Why App Manager" comparison page vs Coolify/Portainer/CapRover
- [ ] Demo instance (read-only, fake data)
- [ ] Blog post: "How I manage 13 apps on a $5 VPS with one dashboard"

### 1.3 Community Launch
- [ ] Show HN post
- [ ] r/selfhosted post
- [ ] Indie Hackers post
- [ ] Twitter/X thread with screenshots + demo GIF
- [ ] Product Hunt launch

### 1.4 Quick Wins from Research
- [ ] App auto-discovery (detect all Docker containers automatically)
- [ ] One-click app templates (like CapRover's marketplace)
- [ ] Real-time log streaming via WebSockets (current: polling)

---

## Phase 2: Growth (Weeks 7-12)

**Goal:** 500 stars, 50 active installs, first paying cloud customers.

### 2.1 Multi-Server Support
- [ ] SSH-based remote server management (like Coolify)
- [ ] Add server via UI: hostname, SSH key, test connection
- [ ] Run Docker commands on remote servers
- [ ] Aggregate metrics across servers

### 2.2 Cloud Offering
- [ ] Hosted version at cloud.appmanager.dev
- [ ] Stripe billing integration
- [ ] Free trial (14 days), then $9/$19/$39
- [ ] Automatic updates for cloud customers

### 2.3 Git Deployments
- [ ] Connect GitHub/GitLab repo to app
- [ ] Webhook → auto-build → deploy on push
- [ ] Build logs in dashboard
- [ ] Rollback to previous deployment

---

## Phase 3: Scale (Months 4-6)

### 3.1 Architecture Improvements (only if needed)
- [ ] Split server.js into routes/ + services/ (if maintainability becomes an issue)
- [ ] Migrate SQLite → PostgreSQL (if concurrent users cause lock contention)
- [ ] Add Redis for sessions + caching (if scaling horizontally)
- [ ] Consider React/Vue frontend (if community contributors can't work with vanilla JS)

### 3.2 Enterprise Features
- [ ] RBAC (admin, operator, viewer roles)
- [ ] Team support (invite users)
- [ ] Audit logs
- [ ] SSO/OAuth

---

## Architecture for Phase 0

Keep the monolith. Add only what's needed:

```
dashboard/
├── server.js              # Add auth middleware, env var config (keep monolith)
├── public/
│   ├── index.html          # Add login page, setup wizard
│   └── (existing)
├── config.yml              # Make user-editable, remove hardcoded apps
├── package.json            # Added: bcryptjs, cookie-parser, helmet (8 deps total)
├── Dockerfile              # No changes needed
├── .env.example            # NEW: all config options documented
└── install.sh              # NEW: one-command install

docker-compose.yml          # Simplify for generic install
docs/
├── getting-started.md
├── configuration.md
└── integrations.md
```

**What NOT to change:**
- Don't split server.js (YAGNI — working monolith ships value)
- Don't add a frontend framework (vanilla JS works, community can contribute)
- Don't migrate database (SQLite handles 50+ concurrent users fine)
- Don't add Kubernetes (Docker Compose is the target audience)

---

## Competitive Positioning

**Tagline options:**
1. "The operating system for indie SaaS portfolios"
2. "Coolify meets Baremetrics — for indie hackers"
3. "Manage your apps AND your business from one dashboard"
4. "The dashboard your side projects deserve"

**One-line pitch:**
> "App Manager is an open-source dashboard that combines Docker container management with business intelligence. Monitor your apps, track your revenue, automate your marketing — all from one keyboard-driven interface."

**Key differentiators to emphasize:**
1. Revenue tracking built into your ops dashboard (nobody else does this)
2. AI Morning Briefings — know your entire portfolio health in 30 seconds
3. Auto-Healing — your apps fix themselves at 3 AM
4. Command Palette — keyboard-first, developer-native UX
5. Free forever self-hosted — no feature paywalls

---

## Success Metrics

| Milestone | Target | Timeframe |
|-----------|--------|-----------|
| GitHub stars | 100 | Month 1 |
| Self-hosted installs | 25 | Month 2 |
| GitHub stars | 500 | Month 3 |
| First cloud customer | 1 | Month 3 |
| Cloud MRR | $500 | Month 6 |
| GitHub stars | 2,000 | Month 6 |
| Cloud MRR | $2,000 | Month 12 |

---

## Immediate Next Actions (Updated 2026-02-27)

1. Commit all uncommitted changes (banners, playbooks, toast, cross-promo, UI polish)
2. Squash git history into one clean initial commit (secrets in history)
3. Rotate Telegram bot token via @BotFather `/revoke`
4. Add CONTRIBUTING.md
5. Add screenshots to README
6. Make repo public and launch (Show HN, r/selfhosted, Indie Hackers)
