# Engineering Principles — Dockfolio

**Purpose:** Core engineering principles that guide all development in this codebase.

**Audience:** All developers, AI assistants, code reviewers

**Status:** Living document — updated as we learn

---

## Core Philosophy

> **"Optimize for clarity and adaptability, not perfection."**

This codebase prioritizes:
- **Maintainable** — Easy to understand and change
- **Evolvable** — Adaptable to new requirements
- **Minimal** — No frameworks, no build steps, no unnecessary complexity
- **NOT Perfect** — Good enough, shipped, is better than perfect in a branch

---

## Guiding Principles

### 1. KISS — Keep It Simple, Stupid

**Rule:** The simplest solution that works is the best solution.

**In Practice:**
- Two files: `server.js` (backend) + `index.html` (frontend) — by design
- No TypeScript, no bundler, no framework — vanilla JS, KISS philosophy
- Favor clarity over cleverness
- Break complex logic into small, understandable pieces
- No "clever" code that sacrifices readability

```javascript
// BAD: Clever but hard to understand
const result = data.reduce((acc, x) => ({ ...acc, [x.id]: x }), {});

// GOOD: Clear and explicit
const result = {};
for (const item of data) {
  result[item.id] = item;
}
```

**Anti-Perfection Rule:** Prefer clear, working solutions over complex "perfect" ones.

---

### 2. DRY — Don't Repeat Yourself

**Rule:** Every piece of knowledge should have a single, unambiguous representation.

**In Practice:**
- Extract common logic into reusable functions (`dashboard/utils.js`)
- Config-driven: app changes go through `config.yml`, not hardcoded
- Constants for magic numbers
- Shared CSS custom properties (design tokens in `:root`)

**Note:** DRY applies to *knowledge* and *business logic*, not necessarily code. Sometimes duplication is better than the wrong abstraction. Three similar lines is better than a premature abstraction.

---

### 3. YAGNI — You Ain't Gonna Need It

**Rule:** Only implement features you actually need right now.

**In Practice:**
- Don't add functionality "just in case"
- No speculative features or abstractions
- Remove unused code and commented-out blocks
- Don't add error handling for scenarios that can't happen
- Don't design for hypothetical future requirements

---

### 4. SRP — Single Responsibility Principle

**Rule:** Each function should have one, and only one, reason to change.

**In Practice:**
- Functions should do one thing and do it well
- `server.js` routes follow: parse input > do work > return JSON
- `index.html` functions follow: fetch data > render HTML > bind events
- Utility functions in `utils.js` are pure — no side effects, no I/O

---

### 5. Config-Driven Architecture

**Rule:** App configuration belongs in `config.yml`, not hardcoded in source.

**In Practice:**
- All 13 apps defined in `dashboard/config.yml`
- Domains, ports, containers, health endpoints, env paths — all config
- Add/edit apps via config or API, not by editing source code
- SQLite databases for runtime state (sessions, metrics, marketing)

---

## Architecture Principles

### Monolith-First

**Rule:** A single monolith is simpler than distributed services, until it isn't.

- One Express server (`server.js`) handles everything
- One HTML file (`index.html`) is the entire frontend
- SQLite (not Postgres) — zero-config, embedded, WAL mode
- Docker Compose for deployment — one command

### Frontend Architecture

**Rule:** The frontend is a vanilla JS SPA with view-based navigation.

- 5 view containers: `view-home`, `view-marketing`, `view-infra`, `view-security`, `view-settings`
- Only one view active at a time (`.view.active { display: block }`)
- Panels inside views are always visible — no toggle stacking
- KPI row is shared across all views
- Chart.js for visualizations, SVG for sparklines
- Keyboard-driven: 1-6 for views, letter keys for shortcuts
- ADHD mode: body-level CSS class, works across all views
- No build step, no bundler, no npm for frontend

### Backend Patterns

**Rule:** Follow existing patterns consistently.

- All routes: `try/catch` > `res.json(data)` or `res.status(N).json({ error })`
- Route handlers wrapped with `asyncRoute()` for error catching
- SQLite with WAL mode, `busy_timeout=5000`
- Cron jobs for periodic data refresh (revenue, analytics, healing)
- `utils.js` for pure functions — all tested

---

## Security Principles

### Defense in Depth

- **Layer 1:** nginx basic auth (`.htpasswd`) for dashboard access
- **Layer 2:** App session auth (bcryptjs passwords, HTTP-only cookies)
- **Layer 3:** CSRF tokens on state-changing requests
- **Layer 4:** CSP headers restrict script/style sources
- **Layer 5:** Docker hardening (non-root user, resource limits, no-new-privileges)

### Input Validation

- Validate at system boundaries (API routes)
- `escapeHtml()` for all user-supplied content in DOM
- Parameterized SQLite queries (no string concatenation)
- Rate limiting on auth endpoints

### No Secrets in Code

- All secrets in environment variables (`.env` files)
- `.env` files are gitignored
- Credentials documented in `ACCOUNTS.md` (gitignored)
- Logs sanitized — no passwords, tokens, or API keys

---

## Testing Principles

### Current State

- 94 unit tests in `dashboard/utils.test.js` covering all utility functions
- ~30 integration tests in `dashboard/server.test.js` (auth, endpoints, CSRF, headers)
- Integration tests run in CI via GitHub Actions
- Manual testing for UI changes

### Test Quality

- Tests are readable, independent, and deterministic
- Pure functions in `utils.js` are the primary test targets
- Test names describe behavior, not implementation

---

## Process Principles

### Commits

- Conventional commits: imperative mood, present tense, under 72 chars
- One logical change per commit
- Clean working tree before starting new work

### Deploy

- `scp` files to VM > `docker compose build` > `docker compose up -d`
- No CI/CD pipeline for dashboard (manual deploy)
- GitHub Actions builds container image to `ghcr.io`

### Documentation

- `CLAUDE.md` — AI-facing quick reference with full API docs
- `PRINCIPLES.md` — This file
- `handover.md` — Session handover state
- `config.yml` — Single source of truth for app configuration
- Keep docs minimal, focused, and up-to-date
- Consolidate rather than create new docs

---

## Summary

| Principle | Rule |
|-----------|------|
| KISS | Simple > Clever. Two files, no frameworks. |
| DRY | Don't repeat knowledge. Config-driven. |
| YAGNI | Build what you need now. Delete the rest. |
| SRP | One function, one job. |
| Config-Driven | Apps in config.yml, not hardcoded. |
| Monolith-First | One server, one HTML file, SQLite. |
| Defense in Depth | nginx > session > CSRF > CSP > Docker. |
| Fail Fast | Validate early, throw explicitly. |
| Consistency | Follow existing patterns. |
| Minimal Docs | Up-to-date > comprehensive. |

---

**Remember:** These are guidelines, not laws. Use judgment. The goal is **maintainable, shippable code** — not perfect code.

---

**Last Updated:** 2026-03-04
**Maintainer:** Konrad Reyhe
