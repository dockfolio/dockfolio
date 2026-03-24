# Launch Posts — Dockfolio

## Show HN

**Title:** Dockfolio -- Self-hosted Docker dashboard with Stripe revenue tracking and AI briefings

Hi HN, I built Dockfolio because I was opening 5 tabs every morning -- Portainer, Stripe, Plausible, Sentry, Search Console -- just to check if my 13 apps were alive and making money. That's 15 minutes before writing any code.

Dockfolio is a single-container Node.js dashboard that connects to your Docker socket and gives you container management + business intelligence in one place. Think Portainer, but with Stripe MRR tracking, built-in analytics, security auditing, SEO audits, error tracking, and an AI morning briefing that summarizes everything in 30 seconds.

It has a "Worry Score" -- one number from 0 to 100 that composites container health, API key validity, disk usage, backup status, security findings, and SEO scores. If it's under 15, nothing needs your attention.

Tech details:

- Single Express server (~6,700 LOC), vanilla JS SPA (~6,100 LOC, ~370KB), SQLite (WAL mode)
- No TypeScript, no framework, no bundler, no external dependencies required
- 144 REST API endpoints, 28 cron jobs, 21 keyboard shortcuts
- Auto-healing: restarts unhealthy containers, cleans disk, detects restart loops
- AI morning briefing via Anthropic Haiku (~$0.001/day)
- Ctrl+K command palette, Telegram alerts, ADHD mode (dims healthy items, kills animations)
- 94 unit tests + 34 integration tests

I use it in production to manage 13 apps on a single Hetzner VM (4 CPU, 8 GB RAM, EUR 12/mo). It replaced Portainer + separate Stripe dashboard + Sentry + manual SEO checks for me.

It does NOT do git deployments or multi-server (yet). If you need those, Coolify is better. Dockfolio is for after deployment -- understanding and growing what's already running.

AGPL-3.0 licensed. Self-hosted only. Your data stays on your server.

GitHub: https://github.com/dockfolio/dockfolio
Site: https://dockfolio.dev
Demo: https://demo.dockfolio.dev (login: demo / demo1234)

Happy to answer any questions about the architecture choices (vanilla JS, SQLite, monolith) or anything else.

---

## r/selfhosted

**Title:** I built a self-hosted Docker dashboard that also tracks my Stripe revenue, runs security audits, and gives me an AI morning briefing

I run 13 apps (mix of SaaS, tools, and static sites) on a single Hetzner VM. Every morning I was checking Portainer, Stripe, Plausible, and Sentry in separate tabs just to figure out if everything was OK. Got tired of it and built Dockfolio.

**What it does:**

- Docker container management (start/stop/restart, logs, resource usage)
- Stripe revenue tracking -- MRR, 30-day revenue, per-app breakdown
- Built-in privacy-first analytics (no cookies, no third parties)
- Error tracking (basically a self-hosted Sentry replacement)
- Security auditing -- container hardening, SSL, headers, network exposure, A-F scoring
- SEO audits for all your domains (13 checks, 0-100 score)
- Auto-healing -- restarts dead containers at 3 AM, cleans disk, sends Telegram alerts
- AI morning briefing that summarizes your entire portfolio in 30 seconds (~$0.001/day via Anthropic)
- "Worry Score" -- one number that tells you if anything needs attention
- Ctrl+K command palette, 21 keyboard shortcuts
- ADHD mode that dims healthy items and kills animations (I have ADHD, built this for myself)

**What it is NOT:**

- Not a deployment tool (no git push to deploy -- use Coolify for that)
- Not multi-server yet (planned)
- Not a Portainer replacement per se -- more like Portainer + Stripe dashboard + Sentry + SEO tool combined

**Tech stack:**

Single Docker container. Node.js/Express backend, vanilla JS frontend (~370KB), SQLite databases. No frameworks, no TypeScript, no build step. Connects to Docker socket, auto-discovers your containers. 144 API endpoints so you can script everything.

The whole thing runs alongside my 13 apps on a 4-core / 8 GB Hetzner box that costs EUR 12/mo.

**Self-hosting:**

```
curl -fsSL https://raw.githubusercontent.com/dockfolio/dockfolio/master/install.sh | bash
```

Or docker-compose:

```yaml
services:
  dockfolio:
    image: ghcr.io/dockfolio/dockfolio:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - dockfolio-data:/data
    ports:
      - "9091:3000"
volumes:
  dockfolio-data:
```

All data stays local in SQLite. No phone-home, no telemetry. AGPL-3.0.

GitHub: https://github.com/dockfolio/dockfolio
Site: https://dockfolio.dev
Demo: https://demo.dockfolio.dev (login: demo / demo1234)

Would love feedback from anyone running a similar multi-app setup. What's missing? What would make this useful for your stack?
