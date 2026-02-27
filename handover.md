# Handover — 2026-02-27 (Session 11)

## 30-Second Summary

Session 11: Built and deployed the **Security Manager** — a full security audit engine for the Docker infrastructure. 4 scanners (container hardening, SSL/TLS certificates, HTTP security headers, network exposure) with weighted scoring (0-100, A-F grades). Also deployed **cross-promotion banners** across all SaaS apps (4 banners, 25 active placements). Fixed HTTP security headers on all 12 nginx sites (score: 84 → 91). Created security knowledge base document.

**Most important thing for next session:** Post the launches (LAUNCH.md still ready). The dashboard now has Security + Marketing + Healing — solid feature set for Show HN.

## Session Focus

1. Deploy cross-promotion banners between SaaS apps
2. Build Security Manager feature (full audit engine)
3. Fix HTTP security headers across all sites
4. Create security knowledge base

## Completed

- [x] Committed session 10 changes (banner injection, deploy scripts)
- [x] Created 4 cross-promo banners (PromoForge, BannerForge, HeadshotAI, AbschlussCheck)
- [x] Placed banners across all sites (25 active placements, weighted rotation)
- [x] Built Security Manager backend: 4 scanners, 5 API endpoints, 3 cron jobs
- [x] Built Security Manager frontend: 5-tab panel, scoring dashboard, finding cards
- [x] Fixed self-signed cert false positive in SSL scanner
- [x] Added security score to morning briefing context
- [x] Added Security command to command palette
- [x] Keyboard shortcut: Shift+S for Security Manager
- [x] Fixed HTTP security headers on 12 nginx sites (6 had zero headers)
- [x] Added X-XSS-Protection to 6 sites that were missing it
- [x] Created security knowledge base (plans/security-knowledge-base.md)
- [x] Re-scanned: 88/100 (B) → 93/100 (A)

## Not Done — Carry Forward

- [ ] **Post Show HN** — content in LAUNCH.md, best timing Tue-Thu 9-10AM EST
- [ ] **Post on r/selfhosted** — content in LAUNCH.md
- [ ] **Rotate Telegram bot token** — manual: @BotFather `/revoke`, update `.env`
- [ ] **Fix GitHub Actions billing** — all repos failing CI/CD
- [ ] **Archive Crelvo/appManager repo** — old private repo
- [ ] **Container name rename** — docker-compose.yml has appmanager→dockfolio NOT deployed

## Security Manager — Architecture

### Scanners (all zero external dependencies)

| Scanner | Method | Checks |
|---------|--------|--------|
| Container Security | dockerode `container.inspect()` | 14 checks: privileged, socket mount, PID/IPC namespace, root user, capabilities, mounts, resource limits, security opts |
| SSL/TLS | Node.js native `tls.connect()` | 5 checks per domain: validity, expiry, chain, TLS version, self-signed |
| HTTP Headers | `fetch()` HEAD request | 7 checks per domain: HSTS, CSP, XCTO, XFO, Referrer, Permissions, XSS |
| Network | dockerode `listContainers()` | Published ports (critical if database), default bridge detection |

### Scoring

- Per-category: 0-100 (weighted checks)
- Overall: average of 4 categories
- Grades: A+ (95+), A (90+), B (75+), C (60+), D (40+), F (<40)

### Current Score (post-fixes)

| Category | Score |
|----------|-------|
| **Overall** | **93/100 (A)** |
| Containers | 81/100 |
| Certificates | 100/100 |
| Headers | 91/100 |
| Network | 100/100 |

89 findings: 2 critical (expected: docker socket on dashboard + uptime-kuma), 11 high (mostly root user in DB containers), 25 medium (resource limits, no-new-privileges), 42 low (writable rootfs, PID limits, minor headers)

### API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/security/scan?category=full | Trigger scan (full/containers/certificates/headers/network) |
| GET | /api/security/status | Latest scan results (no re-scan) |
| GET | /api/security/history?limit=30 | Scan trend data |
| GET | /api/security/app/:slug | Per-app findings |
| POST | /api/security/dismiss/:id | Dismiss a finding |

### Cron Jobs

| Schedule | Job |
|----------|-----|
| 0 1 * * * | Full security scan |
| 0 */6 * * * | SSL certificate check + Telegram alert on critical |
| 0 5 * * 0 | Cleanup scans > 90 days old |

### Database Tables

- `security_scans` — scan metadata, scores, finding counts
- `security_findings` — individual findings with severity, remediation, dismiss status

### Frontend

- Header button: "Security" with grade badge
- 5 tabs: Dashboard (score + category cards + top findings), Containers (per-container check grid), Certificates (per-domain TLS status), Headers (per-domain header audit), Network (port exposure)
- Keyboard: Shift+S
- Command palette: "security"
- Findings have click-to-copy remediation text
- Dismiss button per finding

## Cross-Promotion Banners

| Banner | Target | Sites Showing It |
|--------|--------|-----------------|
| PromoForge (ID 4) | promoforge.app | bannerforge, headshot-ai, abschlusscheck, creative-programmer, crelvo, code-with-rigor, theadhdmind |
| BannerForge (ID 5) | bannerforge.app | promoforge, headshot-ai, abschlusscheck, theadhdmind, creative-programmer, old-world-logos |
| Headshot AI (ID 6) | bewerbungsfotos-ai.de | promoforge, bannerforge, abschlusscheck, crelvo, theadhdmind, lohncheck |
| AbschlussCheck (ID 7) | abschlusscheck.de | promoforge, bannerforge, headshot-ai, creative-programmer, theadhdmind, sacredlens |

25 active placements. Each SaaS never shows its own banner. Weighted rotation.

## HTTP Header Fixes (nginx)

Added security headers to 12 sites. 6 sites had zero security headers (bannerforge, bewerbungsfotos-ai, promoforge, plausible, logos, crelvo). Added X-XSS-Protection to 6 more sites. Backup at `/home/deploy/nginx-configs/sites-backup-20260227-191007/`.

Remaining issues (won't fix — low severity):
- Proxy apps where upstream app overrides nginx headers
- Location blocks with `add_header` that override server-level headers
- CSP not added globally (needs per-site tuning)

## Decisions Made

| Decision | Why | Alternatives |
|----------|-----|-------------|
| Zero new npm dependencies | dockerode + native TLS + fetch cover everything | Could add trivy for image CVE scanning, ssl-checker, portscanner |
| Self-signed check uses CN comparison | Let's Encrypt certs have matching issuer/subject O field, causing false positives with O comparison | Could check issuer chain depth instead |
| 14 container checks (not image CVE scanning) | Trivy would require installing a separate tool; container config checks are higher value for ops | Could run trivy as a Docker container in future |
| Don't add CSP globally | CSP is highly app-specific, wrong CSP breaks apps | Could add CSP report-only mode as future enhancement |

## Rollback Info

**Security Manager rollback:** Revert to commit `2d369fc`. Security code is isolated in server.js (after healing, before cross-promo) and index.html (security panel section).

**nginx header rollback:**
```bash
ssh deploy@91.99.104.132
cp -r /home/deploy/nginx-configs/sites-backup-20260227-191007/* /home/deploy/nginx-configs/sites/
sudo nginx -t -c /home/deploy/nginx-configs/nginx.conf
sudo nginx -s reload -c /home/deploy/nginx-configs/nginx.conf
```

## Files Modified This Session

### appManager repo
| File | What Changed |
|------|-------------|
| `dashboard/server.js` | +392 lines: security DB tables, 4 scanner functions, 5 API endpoints, 3 cron jobs, command palette entry, briefing integration |
| `dashboard/public/index.html` | +331 lines: security panel CSS, HTML (5 tabs), JS (toggle, scan, render functions), keyboard shortcut |
| `plans/security-knowledge-base.md` | NEW — Docker security reference, CIS benchmark, header guide, remediation playbook |
| `handover.md` | Updated for session 11 |

### VM Changes (not in git)
| File | What Changed |
|------|-------------|
| `/home/deploy/nginx-configs/sites/*` | 12 configs: added security headers (HSTS, XCTO, XFO, Referrer, Permissions, XSS) |
| `/home/deploy/nginx-configs/sites-backup-20260227-191007/` | Pre-header-fix backup |

## Git State

| Repo | Branch | Status | Latest Commit |
|------|--------|--------|---------------|
| appManager | master | clean (minus handover + knowledge base) | 8775ada |

## Next Steps (Priority Order)

1. **Post Show HN** — LAUNCH.md ready (Tue-Thu 9-10AM EST best)
2. **Post r/selfhosted** — LAUNCH.md ready
3. **Rotate Telegram bot token** — @BotFather `/revoke`
4. **Fix GitHub Actions billing**
5. **Add CSP headers** — Per-site CSP in report-only mode first
6. **Image vulnerability scanning** — Add trivy integration to Security Manager
7. **Container resource limits** — Add limits to docker-compose files (biggest score improvement)

## Key URLs

| Resource | URL |
|----------|-----|
| Dashboard | https://admin.crelvo.dev |
| Dockfolio landing | https://dockfolio.dev |
| GitHub (Dockfolio) | https://github.com/dockfolio/dockfolio |
| Security KB | plans/security-knowledge-base.md |
