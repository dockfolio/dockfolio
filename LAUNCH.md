# Launch Posts

## Show HN

**Title:** Show HN: Dockfolio - A dashboard that treats your Docker apps as a business, not just containers

**Body:**

Hi HN,

I run 6 SaaS apps and 7 static sites on a single Hetzner VPS. I got tired of checking three different tabs every morning: Portainer (is it running?), Stripe (is it earning?), Search Console (is it ranking?).

So I built one dashboard that answers all three.

Dockfolio sits next to your Docker apps as a single container. It reads your Docker socket for infrastructure, reads your apps' .env files for Stripe/Plausible/Resend keys, and gives you one view of your entire portfolio.

What I actually use daily:

- **Worry Score**: A single 0-100 number that tells me if I need to open the dashboard. Composite of container health, API keys, disk, backups, security, and SEO. If it's under 15, I go back to sleep.
- **Morning briefing**: AI-generated summary of what happened overnight (Claude Haiku, ~$0.001/day)
- **Revenue per app**: Stripe MRR and charges broken down by app, even when they share a Stripe account
- **Auto-healing**: Restarts unhealthy containers and alerts me on Telegram before I notice
- **Security audits**: Automated scans across the whole fleet — SSL, headers, CORS, cookies, injection vectors
- **ADHD Mode** (Shift+A): Dims everything that's healthy so I only see problems. This is the feature I built for myself.
- **Ctrl+K command palette**: Keyboard-driven everything. I rarely touch the mouse.

It also does SEO audits, traffic analytics (Plausible), project management with kanban boards, config drift detection, app dependency mapping, email sequences, and cross-app customer tracking.

Stack: Express + vanilla JS + SQLite. ~140KB frontend. No build step. 106 API endpoints in a single server.js. It's a monolith by design.

```
curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
```

GitHub: https://github.com/dockfolio/dockfolio
Site: https://dockfolio.dev
License: AGPL-3.0

Limitations I'm upfront about: single-server only, no git deployments, no RBAC, no automated tests. Multi-server is planned.

Happy to answer questions about the architecture or how I'm using it.

---

## r/selfhosted

**Title:** I built a dashboard that combines Docker management with Stripe revenue tracking (Dockfolio, AGPL-3.0)

**Body:**

I run 13 sites on a single Hetzner VPS (3 SaaS products, 3 tools, Plausible, 6 static sites). Portainer tells me if containers are running. Stripe tells me if they're earning. Plausible tells me if anyone's visiting. I got tired of checking all three separately.

**Dockfolio** is a single Docker container that gives me one dashboard for all of it:

- Container management (status, restart, logs, prune, resource usage)
- **Ops Intelligence**: Worry score (0-100), config drift detection, app dependency mapping, per-app report cards (A-F)
- **Security audits**: Fleet-wide scans — SSL, headers, CORS, cookies, injection vectors
- **Project management**: Tasks, kanban roadmap, AI insights
- Stripe revenue tracking per app (MRR, charges, shared account detection)
- Plausible traffic integration
- SEO audits (13 checks, A-F scores)
- Auto-healing (restarts unhealthy containers, Telegram alerts)
- AI morning briefing via Claude Haiku
- **ADHD Mode**: Dims healthy items so you only see problems
- Ctrl+K command palette, 17 keyboard shortcuts

It's keyboard-first and deliberately simple: Express, vanilla JS, SQLite. ~140KB frontend, 106 API endpoints. It auto-discovers your running Docker containers and reads API keys from your apps' .env files.

**This is not a PaaS.** It doesn't deploy, doesn't manage git repos, doesn't build images. It's the dashboard you open after your apps are already running to understand how your portfolio is doing.

**Install:**
```
curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
```
Then open `http://your-server:9091` and create your admin account.

**Screenshots + docs:** https://dockfolio.dev
**GitHub:** https://github.com/dockfolio/dockfolio
**License:** AGPL-3.0

Would love to hear what features you'd find useful. Multi-server support is the most requested thing so far.

---

## awesome-selfhosted PR entry

Category: `Software Development - Deployment`

```
- [Dockfolio](https://dockfolio.dev) - Dashboard for Docker app portfolios combining container management, ops intelligence, security auditing, Stripe revenue tracking, and auto-healing. ([Source Code](https://github.com/dockfolio/dockfolio)) `AGPL-3.0` `Docker`
```
