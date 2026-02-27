# Contributing to Dockfolio

Thank you for your interest in contributing to Dockfolio. This guide covers everything you need to get started.

## Local Development Setup

**Prerequisites:** Docker running locally, Node.js 20+, npm.

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/dockfolio.git
cd dockfolio/dashboard

# 2. Install dependencies
npm install

# 3. Create a config.yml with at least one app
cp config.yml.example config.yml  # or create manually

# 4. Start in dev mode (auto-restarts on file changes)
npm run dev
```

The dashboard runs at `http://localhost:9091` by default. Docker must be running for container management features to work. On first visit, you will be prompted to create an admin account.

**Alternatively, run via Docker:**

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## Branch Strategy

1. Fork the repository
2. Create a feature branch from `master`: `git checkout -b my-feature`
3. Make your changes
4. Open a pull request against `master`

Keep PRs focused on a single change. Large PRs are harder to review.

## Commit Messages

Use imperative mood, present tense. Keep the first line under 72 characters.

```
Add multi-server SSH connection support
Fix revenue deduplication for shared Stripe keys
Remove unused CSS from healing panel
```

Do not prefix with `feat:`, `fix:`, etc. Just describe what the commit does.

## Code Style

- **Backend:** Node.js with Express (ES modules). All server code lives in `server.js`.
- **Frontend:** Vanilla JavaScript and HTML. All UI code lives in `public/index.html`. No frameworks, no build step, no TypeScript.
- **Data:** SQLite via `better-sqlite3`. No ORMs.
- **Config:** `config.yml` parsed with `js-yaml`.
- **Containers:** `dockerode` for Docker API access.

This is a monolith by design. Do not introduce frontend frameworks, TypeScript, or build tools. Keep dependencies minimal.

## Architecture Overview

```
dashboard/
  server.js        Express API (77 endpoints), cron jobs, auth, all backend logic
  public/
    index.html     Self-contained SPA (~140KB), vanilla JS, CSS-in-HTML
  config.yml       App registry (names, domains, containers, env paths)
  package.json     8 dependencies total

Dockerfile         Multi-stage production build
docker-compose.prod.yml   Generic compose for new installs
install.sh         One-command install script
```

**Key concepts:**
- `config.yml` defines which apps Dockfolio tracks (containers, domains, health endpoints, env file paths)
- SQLite stores auth, metrics, SEO audits, cohorts, emails, content, healing logs, banners, and playbooks
- `node-cron` runs 6 scheduled jobs (revenue sync, SEO audits, content generation, cohort analysis, email queue, auto-healing)
- The frontend is a single HTML file with inline JS/CSS -- no bundler, no components

## Testing

There are no automated tests. All testing is manual.

Before submitting a PR, verify your changes work by:

1. Starting the dev server with `npm run dev`
2. Confirming Docker containers are detected and displayed
3. Testing any UI changes across the relevant panels (marketing, healing, settings, etc.)
4. Checking the browser console and server logs for errors
5. If you changed an API endpoint, test it with `curl`

If your change affects cron jobs or scheduled tasks, describe how you verified the behavior in your PR description.

## Reporting Issues

Use [GitHub Issues](https://github.com/dockfolio/dockfolio/issues). Include:

- What you expected vs. what happened
- Steps to reproduce
- Docker version, OS, and Node.js version
- Relevant logs from the browser console or container output

## Areas Where Help Is Wanted

- Multi-server support (SSH-based remote Docker management)
- Git-based deployments (webhook-triggered build and deploy)
- Frontend accessibility and mobile responsiveness
- Documentation and user guides
- Integrations with additional services (Umami, PostHog, Lemon Squeezy, etc.)

## License

By contributing, you agree that your contributions will be licensed under the [AGPL-3.0 License](LICENSE). If you distribute a modified version or offer it as a hosted service, you must open-source your changes under the same license.
