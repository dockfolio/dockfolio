# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release on `master` | Yes |
| Older releases | No |

Dockfolio follows a rolling release model. Security fixes are applied to the latest version only. Self-hosters should always run the most recent release.

## Reporting a Vulnerability

If you discover a security vulnerability in Dockfolio, please report it responsibly.

**Email:** [security@crelvo.dev](mailto:security@crelvo.dev)

Include the following in your report:

- A clear description of the vulnerability
- Steps to reproduce the issue
- The affected component (e.g., API endpoint, authentication, Docker integration)
- Any potential impact assessment
- Suggested fix, if available

**Do not** open a public GitHub issue for security vulnerabilities.

## What Qualifies as a Vulnerability

- Authentication or session bypass
- Unauthorized access to API endpoints
- SQL injection, XSS, or CSRF in the dashboard
- Exposure of secrets, credentials, or session tokens
- Privilege escalation through the Docker socket integration
- Path traversal or arbitrary file read/write via API routes
- Denial of service through resource exhaustion in server-side logic
- Insecure default configurations shipped with the project

## What Does NOT Qualify

- Security issues arising from self-hosted misconfigurations (e.g., exposing the dashboard to the public internet without authentication, running as root, disabling firewalls)
- Vulnerabilities in third-party dependencies unless exploitable through Dockfolio specifically
- Missing security headers on a self-hosted instance (these are configured via nginx, not the application)
- Rate limiting or brute-force concerns on a local network deployment
- Theoretical attacks that require physical access to the host machine
- Docker socket access by design -- Dockfolio requires the Docker socket to function; this is documented and expected

## Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgment of report | Within 48 hours |
| Initial assessment and severity classification | Within 7 days |
| Fix development and testing | Depends on severity |
| Patch release | As soon as a fix is verified |

Critical vulnerabilities (authentication bypass, remote code execution) are prioritized and patched as quickly as possible.

## Disclosure Policy

Dockfolio follows a **90-day coordinated disclosure** policy:

1. The reporter submits the vulnerability via email.
2. The maintainers acknowledge and assess the issue.
3. A fix is developed, tested, and released.
4. The reporter is credited (unless they prefer anonymity).
5. After 90 days from the initial report -- or once a fix is released, whichever comes first -- the vulnerability may be publicly disclosed.

If a fix cannot be completed within 90 days, the maintainers will communicate a revised timeline to the reporter.

## Security Best Practices for Self-Hosters

Dockfolio is designed to run on a private server. Follow these practices to keep your deployment secure.

### Docker Socket

- Mount the Docker socket as read-only (`/var/run/docker.sock:/var/run/docker.sock:ro`) if you do not need container management features (restart, prune).
- Never expose the Docker TCP socket (port 2375/2376) to the network.
- Run the Dockfolio container as a non-root user where possible.

### Network and Access

- Place the dashboard behind a reverse proxy (nginx, Caddy, Traefik) with HTTPS.
- Do not expose Dockfolio directly to the public internet without authentication.
- Use firewall rules to restrict access to the dashboard port (default 9091) to trusted IPs only.
- Enable fail2ban or equivalent intrusion prevention on SSH and exposed services.

### Authentication

- Set a strong admin password during initial setup.
- Rotate session secrets periodically by updating the `SESSION_SECRET` environment variable.
- Use HTTP-only, secure cookies (enforced by default when behind HTTPS).

### Backups

- Enable automated backups of the SQLite databases (`auth.db`, `data.db`).
- Store backups on a separate volume or off-site location.
- Test backup restoration periodically.

### Updates

- Pull the latest Dockfolio image regularly to receive security patches.
- Monitor the [GitHub repository](https://github.com/crelvo/appmanager) for release announcements.
- Review changelogs before updating to understand what changed.

### Environment Variables

- Never commit `.env` files to version control.
- Restrict file permissions on `.env` files (`chmod 600`).
- Use unique API keys and secrets for each deployment.

## Contact

For security-related questions that are not vulnerability reports, open a GitHub Discussion or email [security@crelvo.dev](mailto:security@crelvo.dev).
