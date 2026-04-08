# Show HN Draft — Ready to Post

**Best time:** Tuesday-Wednesday, 11 AM ET (5 PM CET)
**Requirement:** Must be online 6 hours to engage with every comment

---

**Title:** Show HN: I run 25+ apps on one $12/month server as a solo dev

**Body:**

Hi HN,

I run 6 SaaS apps, 7 static sites, and a bunch of tools on a single Hetzner VPS. I got tired of context-switching: Portainer to check if containers are running, Stripe to see if they're earning, Search Console to check rankings.

So I built one dashboard that does it all.

**Dockfolio** is a single Docker container that treats your portfolio as a business, not just infrastructure. It auto-discovers your running apps, reads your .env files for API keys, and gives you one keyboard-driven view of everything.

What I actually use every day:

- **Worry Score**: A single 0-100 number that tells me if I need to open the dashboard. If it's under 15, I go back to sleep.
- **Morning briefing**: AI-generated summary of what happened overnight (Claude Haiku, ~$0.001/day)
- **Revenue per app**: Stripe MRR broken down by app, even when they share an account
- **Auto-healing**: Restarts unhealthy containers and alerts me on Telegram before I notice
- **Security audits**: Automated scans across the fleet — SSL, headers, CORS, injection vectors
- **ADHD Mode** (Shift+A): Dims everything healthy so I only see problems
- **Ctrl+K command palette**: Keyboard-first everything. Rarely touch the mouse.

It also does SEO audits, traffic analytics (Plausible), project management, config drift detection, and cross-app customer tracking.

**The twist:** Unlike Portainer or Coolify, this combines infrastructure management with business intelligence. Know how your apps are performing *as a business*.

**Stack:** Express + vanilla JS + SQLite. ~370KB frontend, ~150 API endpoints in a single monolith. No external dependencies required.

**Install:**
```
curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
```

**GitHub:** https://github.com/dockfolio/dockfolio (AGPL-3.0)
**Website:** https://dockfolio.dev

Limitations I'm upfront about: single-server only, no git deployments, no RBAC. Multi-server support is planned.

Happy to answer questions about the architecture or why I chose this stack.
