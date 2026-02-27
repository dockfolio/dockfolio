# Launch Posts

## Show HN

**Title:** Show HN: Dockfolio - Business dashboard for indie hackers running Docker apps

**Body:**

Hi HN,

I built Dockfolio because I run 6 SaaS apps and 7 static sites on a single Hetzner VPS, and I got tired of switching between Portainer (is it running?), Stripe (is it earning?), and Google Search Console (is it ranking?).

Dockfolio is a single-container dashboard that sits next to your Docker apps and gives you:

- Container management (status, restart, logs, resource usage)
- Stripe revenue tracking (MRR, per-app breakdown, shared account detection)
- SEO auditing (13 checks, A-F scoring)
- AI morning briefing via Claude Haiku (~$0.001/day)
- Auto-healing (restart unhealthy containers, disk cleanup, Telegram alerts)
- Command palette (Ctrl+K) with 15 keyboard shortcuts
- Cross-app customer cohort analysis
- Marketing automation (email sequences, content pipeline, banner management)

It's a ~140KB vanilla JS frontend + Express backend + SQLite. No frameworks, no build step, no external dependencies required. Connects to your Docker socket and reads API keys from your apps' .env files.

Install:
```
curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
```

GitHub: https://github.com/dockfolio/dockfolio
Landing page: https://dockfolio.dev
License: AGPL-3.0

The key insight: tools like Coolify and CapRover help you deploy apps. But once they're running, you need to understand them as a business. Dockfolio fills that gap.

Known limitations: single-server only (multi-server planned), no git deployments, no RBAC, no automated tests. It's a monolith by design.

Would love feedback on what's missing or what you'd want to see next.

---

## r/selfhosted

**Title:** Dockfolio - A self-hosted business dashboard for your Docker app portfolio (AGPL-3.0, single container)

**Body:**

I've been running 13 sites on a single Hetzner VPS for a while now - 3 SaaS products, 3 tools, Plausible Analytics, and 6 static sites. I built a dashboard to manage all of them from one place.

**What it does:**

- Docker container management (status, restart, logs, disk usage, prune)
- System metrics (CPU, memory, disk, swap, load)
- Stripe revenue tracking per app (MRR, charges, customer cohorts)
- SEO auditing with A-F scoring (13 checks per site)
- AI morning briefing via Claude Haiku
- Auto-healing engine (restart unhealthy containers, disk cleanup)
- Ctrl+K command palette with 15 keyboard shortcuts
- Email sequences, content pipeline, banner management
- SSL certificate monitoring
- Uptime Kuma integration

**Screenshots:** See the GitHub repo or https://dockfolio.dev

**Stack:** Node.js, Express, vanilla JS, SQLite, Dockerode. Single container, ~140KB frontend, 77 API endpoints. No frameworks.

**Install:**
```
curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
```

Then open http://your-server:9091 and create your admin account. Apps are auto-discovered from running Docker containers.

**Integrations (all optional):** Stripe, Plausible Analytics, Anthropic (Claude), Resend, Telegram, Uptime Kuma

**GitHub:** https://github.com/dockfolio/dockfolio
**License:** AGPL-3.0

This is not a PaaS. It doesn't deploy apps or manage git repos. It's the dashboard you open after your apps are already running to understand how they're doing as a portfolio.

Feedback welcome!

---

## awesome-selfhosted PR entry

Category: `Software Development - Project Management`

```
- [Dockfolio](https://dockfolio.dev) - Business dashboard for Docker app portfolios. Monitor containers, track Stripe revenue, automate marketing, and heal infrastructure from one keyboard-driven interface. ([Source Code](https://github.com/dockfolio/dockfolio)) `AGPL-3.0` `Docker`
```
