#!/bin/bash
# Deploy Dockfolio to VM (single SSH connection to avoid fail2ban)
# Usage: bash deploy.sh [--rebuild]
# Works from both Linux (rsync) and Windows/Git Bash (scp fallback)

set -euo pipefail

SERVER="deploy@91.99.104.132"
REMOTE_DIR="/home/deploy/appmanager"
REBUILD="${1:-}"

echo "==> Uploading files..."
if command -v rsync &>/dev/null; then
    rsync -avz --delete \
        --exclude 'node_modules' \
        --exclude '.git' \
        --exclude 'scripts/fix-*.js' \
        --exclude 'scripts/setup-kuma*.js' \
        --exclude 'scripts/kuma-*.js' \
        ./ "${SERVER}:${REMOTE_DIR}/"
else
    # Fallback for Windows/Git Bash without rsync
    scp -r \
        dashboard/server.js \
        dashboard/package.json \
        dashboard/Dockerfile \
        dashboard/config.yml \
        dashboard/public/ \
        "${SERVER}:${REMOTE_DIR}/dashboard/"
    scp docker-compose.yml nginx-dockfolio.conf deploy.sh .env "${SERVER}:${REMOTE_DIR}/"
    scp scripts/system-alert.sh scripts/backup-databases.sh "${SERVER}:${REMOTE_DIR}/scripts/"
fi

echo "==> Running remote setup..."
ssh "$SERVER" bash -s -- "$REBUILD" << 'REMOTE'
set -euo pipefail
cd /home/deploy/appmanager
REBUILD="$1"

# Build dashboard
if [ "$REBUILD" = "--rebuild" ]; then
    echo "[1/4] Rebuilding containers..."
    docker compose up -d --build
    docker builder prune -f 2>&1 | tail -1
else
    echo "[1/4] Starting containers (no rebuild)..."
    docker compose up -d
fi

# Nginx config
echo "[2/4] Updating nginx..."
cp nginx-dockfolio.conf /home/deploy/nginx-configs/sites/appmanager
cp nginx-dockfolio.conf /home/deploy/nginx-extra/appmanager.conf 2>/dev/null || true
sudo /usr/sbin/nginx -t -c /home/deploy/nginx-configs/nginx.conf && \
sudo /usr/sbin/nginx -s reload -c /home/deploy/nginx-configs/nginx.conf

# Cron (idempotent)
echo "[3/4] Ensuring cron jobs..."
chmod +x scripts/system-alert.sh
chmod +x scripts/backup-databases.sh 2>/dev/null || true

# Create backup directories
mkdir -p /home/deploy/backups/{promoforge,lohncheck,sacredlens,plausible-pg,plausible-clickhouse}

# Create marketing data directory
mkdir -p /home/deploy/marketing

# Clear alert state to trigger initial alerts on deploy
rm -f /tmp/dockfolio-alert-state

CRON_UPDATED=false
CURRENT_CRON=$(crontab -l 2>/dev/null || true)

# Alert cron
if ! echo "$CURRENT_CRON" | grep -q "system-alert.sh"; then
    CURRENT_CRON="${CURRENT_CRON}
*/5 * * * * /home/deploy/appmanager/scripts/system-alert.sh"
    CRON_UPDATED=true
    echo "  Alert cron added"
else
    echo "  Alert cron already exists"
fi

# Backup crons (staggered)
if ! echo "$CURRENT_CRON" | grep -q "backup-databases.sh"; then
    CURRENT_CRON="${CURRENT_CRON}
0 3 * * * /home/deploy/appmanager/scripts/backup-databases.sh promoforge
15 3 * * * /home/deploy/appmanager/scripts/backup-databases.sh lohncheck
30 3 * * * /home/deploy/appmanager/scripts/backup-databases.sh sacredlens
45 3 * * * /home/deploy/appmanager/scripts/backup-databases.sh plausible"
    CRON_UPDATED=true
    echo "  Backup crons added"
else
    echo "  Backup crons already exist"
fi

if [ "$CRON_UPDATED" = true ]; then
    echo "$CURRENT_CRON" | crontab -
fi

echo "[4/4] Status:"
docker compose ps --format "table {{.Name}}\t{{.Status}}"
echo ""
echo "Dashboard:   https://admin.crelvo.dev"
echo "Uptime Kuma: https://admin.crelvo.dev/uptime/"
echo "Status Page: https://admin.crelvo.dev/uptime/status-page/status"
REMOTE
