# Security Knowledge Base — Dockfolio

Reference document for Docker infrastructure security. Used by the Security Manager feature and as an ops reference.

---

## 1. Docker Container Hardening

### Critical Checks

| Check | Risk | Fix |
|-------|------|-----|
| **Privileged mode** | Full host access, kernel module loading, device access | Remove `--privileged`. Use `--cap-add` for specific capabilities only. |
| **Docker socket mount** | Equivalent to root on host. Can create privileged containers. | Only mount for management tools. Consider Docker API proxy (e.g., Tecnativa/docker-socket-proxy). |
| **Host PID namespace** | Can see/signal all host processes. Enables process injection. | Remove `--pid=host` unless needed for monitoring (e.g., cAdvisor). |
| **Host IPC namespace** | Shared memory access across host processes. | Remove `--ipc=host`. Use named IPC namespaces if apps need shared memory. |

### High Checks

| Check | Risk | Fix |
|-------|------|-----|
| **Host network** | Bypasses network isolation. Container sees all host traffic. | Use bridge networking: `-p 127.0.0.1:PORT:PORT` for local-only, `-p PORT:PORT` for public. |
| **Running as root** | Container escape exploits are much worse as root. | `USER nonroot` in Dockerfile, or `--user 1000:1000` in compose. Most images support this. |
| **Dangerous capabilities** | `SYS_ADMIN` = near-privileged. `NET_RAW` = packet sniffing. | `--cap-drop=ALL --cap-add=CHOWN --cap-add=SETGID --cap-add=SETUID` (only what's needed). |
| **Sensitive volume mounts** | Mounting `/etc`, `/root`, `/proc` exposes host secrets and configs. | Mount only specific files/dirs needed. Use read-only mounts (`:ro`) where possible. |

### Medium Checks

| Check | Risk | Fix |
|-------|------|-----|
| **No memory limit** | One container can OOM-kill the entire host. | `mem_limit: 512m` in compose, or `--memory=512m`. |
| **No CPU limit** | One container can starve others. | `cpus: '0.5'` in compose, or `--cpus=0.5`. |
| **no-new-privileges not set** | Processes can escalate privileges via setuid binaries. | `security_opt: ["no-new-privileges:true"]` in compose. |

### Low Checks

| Check | Risk | Fix |
|-------|------|-----|
| **No PID limit** | Fork bomb can crash the container host. | `pids_limit: 200` in compose. |
| **Writable root filesystem** | Malware can modify container binaries. | `read_only: true` in compose + `tmpfs: [/tmp, /run]` for writable dirs. |
| **No restart policy** | Container stays down after crash. | `restart: unless-stopped` in compose. |

### CIS Docker Benchmark Categories

The CIS Docker Benchmark (v1.6.0) covers 7 areas:
1. **Host Configuration** — kernel, audit, Docker storage
2. **Docker Daemon** — debug mode, TLS, ulimits, user namespaces
3. **Daemon Config Files** — permissions on /etc/docker, socket
4. **Container Images** — trusted base images, no secrets in layers
5. **Container Runtime** — the 14 checks in our Security Manager
6. **Security Operations** — vulnerability scanning, updates
7. **Docker Swarm** — N/A for single-host deployments

---

## 2. SSL/TLS Security

### Certificate Checks

| Check | Impact | Details |
|-------|--------|---------|
| **Valid/Trusted** | Users see browser warnings | Must be CA-signed (Let's Encrypt is free). Check `socket.authorized`. |
| **Expiry > 30 days** | Service outage if cert expires | Let's Encrypt certs last 90 days. `certbot renew` runs via cron. Alert at 30 days, critical at 7. |
| **Complete chain** | Some clients fail to connect | nginx `ssl_certificate` must include full chain (cert + intermediates). |
| **TLS 1.3** | Older protocols have known vulnerabilities | `ssl_protocols TLSv1.2 TLSv1.3;` — never allow 1.0 or 1.1. |
| **Not self-signed** | Browsers reject, users can't verify identity | Use Let's Encrypt: `certbot --nginx -d domain.com`. |

### Let's Encrypt Operations

```bash
# Renew all certificates
sudo certbot renew

# Issue new certificate
sudo certbot --nginx -d newdomain.com

# Check certificate details
openssl s_client -connect domain.com:443 -servername domain.com < /dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer

# Check days until expiry
echo | openssl s_client -connect domain.com:443 -servername domain.com 2>/dev/null | openssl x509 -noout -enddate
```

### Recommended nginx SSL Config

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

---

## 3. HTTP Security Headers

### Header Reference

| Header | Value | Purpose | nginx Directive |
|--------|-------|---------|-----------------|
| **HSTS** | `max-age=31536000; includeSubDomains` | Force HTTPS, prevent downgrade attacks | `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` |
| **CSP** | (site-specific) | Whitelist allowed resource sources, prevent XSS | `add_header Content-Security-Policy "default-src 'self'; ..." always;` |
| **X-Content-Type-Options** | `nosniff` | Prevent MIME type sniffing | `add_header X-Content-Type-Options "nosniff" always;` |
| **X-Frame-Options** | `SAMEORIGIN` or `DENY` | Prevent clickjacking | `add_header X-Frame-Options "SAMEORIGIN" always;` |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | Control referrer info leakage | `add_header Referrer-Policy "strict-origin-when-cross-origin" always;` |
| **Permissions-Policy** | `camera=(), microphone=(), geolocation=()` | Disable browser APIs not needed | `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;` |
| **X-XSS-Protection** | `1; mode=block` | Legacy XSS filter (deprecated, CSP is better) | `add_header X-XSS-Protection "1; mode=block" always;` |

### nginx `add_header` Gotcha

**nginx drops ALL parent-level `add_header` directives when a child `location` block has its own `add_header`.** This means:

```nginx
server {
    add_header X-Frame-Options "DENY" always;  # This gets dropped...

    location / {
        add_header Cache-Control "public";      # ...because this location has add_header
    }
}
```

**Fix:** Either repeat security headers in every location block, or use the `headers-more` module (`more_set_headers` is always inherited).

### CSP Starter Templates

**Static site:**
```
default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'
```

**App with Plausible analytics:**
```
default-src 'self'; script-src 'self' 'unsafe-inline' https://plausible.theadhdmind.org; style-src 'self' 'unsafe-inline'; connect-src 'self' https://plausible.theadhdmind.org; img-src 'self' data:; frame-ancestors 'none'
```

---

## 4. Network Security

### Port Exposure Rules

| Port Type | Bind To | Example |
|-----------|---------|---------|
| **Public web** | `0.0.0.0:443` | nginx |
| **Internal app** | `127.0.0.1:PORT` | Node.js apps behind nginx |
| **Database** | NEVER expose | Postgres, Redis, ClickHouse — use Docker networks only |
| **Management** | `127.0.0.1:PORT` | Dashboard, Uptime Kuma |

### Docker Network Isolation

```yaml
# Good: Custom networks for isolation
networks:
  frontend:
  backend:

services:
  web:
    networks: [frontend, backend]
  db:
    networks: [backend]   # Not accessible from frontend
```

**Default bridge network:** All containers can talk to each other. Use custom networks instead.

### Firewall (UFW)

```bash
# Allow SSH, HTTP, HTTPS only
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

---

## 5. Secret Management

### Rules

1. **Never hardcode secrets.** Use `.env` files or Docker secrets.
2. **Never log secrets.** Mask values in API responses (first 8 + last 4 chars).
3. **Rotate keys periodically.** Track last rotation date.
4. **Detect shared keys.** Same key across apps = single point of failure.
5. **Minimize scope.** Each app should have its own API keys where possible.

### Dockfolio's Implementation

- Env files read/written via Docker volume mounts at original host paths
- Values masked in API responses: `sk_live_...jliV` (8 prefix + 4 suffix)
- SHA256 hash comparison for shared key detection (never compares plaintext)
- API key validation: Stripe (GET /v1/balance), Anthropic (GET /v1/models), Resend (POST /emails → 422 = valid)

---

## 6. Security Scoring

### Dockfolio Security Manager

**Per-category scoring:** Each check has a weight. Score = (earned / total) * 100.

**Grades:**
| Score | Grade |
|-------|-------|
| 95-100 | A+ |
| 90-94 | A |
| 75-89 | B |
| 60-74 | C |
| 40-59 | D |
| 0-39 | F |

**Overall:** Weighted average of containers, certificates, headers, network.

**Severity levels:**
- **Critical** — Immediate exploitation risk, fix now
- **High** — Significant risk, fix within 24h
- **Medium** — Moderate risk, fix within 1 week
- **Low** — Minor hardening improvement, fix when convenient

### Scan Schedule

| Scan | Frequency | Alerts |
|------|-----------|--------|
| Full scan | Daily 1 AM | Telegram on critical findings |
| SSL check | Every 6 hours | Telegram if cert < 7 days |
| Cleanup | Weekly Sunday 5 AM | Removes scans > 90 days old |

---

## 7. Remediation Playbook

### Quick Wins (biggest score impact)

1. **Add resource limits to all containers:**
   ```yaml
   deploy:
     resources:
       limits:
         memory: 512M
         cpus: '0.5'
         pids: 200
   ```

2. **Add security options:**
   ```yaml
   security_opt:
     - no-new-privileges:true
   read_only: true
   tmpfs:
     - /tmp
   ```

3. **Run as non-root:**
   ```yaml
   user: "1000:1000"
   ```

4. **Add all security headers to nginx:**
   ```nginx
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-Frame-Options "SAMEORIGIN" always;
   add_header Referrer-Policy "strict-origin-when-cross-origin" always;
   add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
   add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
   ```

### Things You Cannot Fix (expected findings)

- **Dashboard needs Docker socket** — Required for container management
- **Database containers run as root** — Official Postgres/Redis images run as root by default
- **CSP disabled on dashboard** — Inline scripts in the SPA require it

---

## 8. References

- [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
- [securityheaders.com](https://securityheaders.com)
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)

---

**Last Updated:** 2026-02-27
**Maintainer:** Dockfolio Security Manager (automated scans) + manual review
