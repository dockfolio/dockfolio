#!/bin/bash
# Off-site backup: rsync local backups to Hetzner Storage Box (or any SSH target)
# Usage: backup-offsite.sh
# Schedule: daily at 4:30 AM (after all local backups complete)
#
# SETUP:
#   1. Order Hetzner Storage Box (BX11 = 1TB, ~€3.81/month)
#   2. Add your SSH key: ssh-copy-id -p 23 uXXXXXX@uXXXXXX.your-storagebox.de
#   3. Set env vars in /home/deploy/appmanager/.env:
#      BACKUP_REMOTE_HOST=uXXXXXX.your-storagebox.de
#      BACKUP_REMOTE_USER=uXXXXXX
#      BACKUP_REMOTE_PORT=23
#   4. Add cron: 30 4 * * * set -a && . /home/deploy/appmanager/.env && set +a && /home/deploy/appmanager/scripts/backup-offsite.sh >> /home/deploy/logs/backup-offsite.log 2>&1
#   5. Test: bash /home/deploy/appmanager/scripts/backup-offsite.sh

set -euo pipefail

BACKUP_ROOT="/home/deploy/backups"
REMOTE_HOST="${BACKUP_REMOTE_HOST:-}"
REMOTE_USER="${BACKUP_REMOTE_USER:-}"
REMOTE_PATH="${BACKUP_REMOTE_PATH:-/backups/dockfolio}"
REMOTE_PORT="${BACKUP_REMOTE_PORT:-23}"  # Hetzner Storage Box uses port 23

# Telegram notifications
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

send_telegram() {
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"text\": \"$1\", \"parse_mode\": \"HTML\"}" > /dev/null 2>&1 || true
}

if [ -z "$REMOTE_HOST" ]; then
    echo "[$(date)] ERROR: BACKUP_REMOTE_HOST not set. See setup instructions in this script."
    exit 1
fi

echo "[$(date)] Starting off-site backup to ${REMOTE_HOST}..."

# Ensure remote directory exists
ssh -p "${REMOTE_PORT}" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    "${REMOTE_USER}@${REMOTE_HOST}" "mkdir -p ${REMOTE_PATH}" 2>/dev/null || true

# Rsync with compression, preserving structure
START_TIME=$(date +%s)
if rsync -az --delete --stats \
    -e "ssh -p ${REMOTE_PORT} -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new" \
    "${BACKUP_ROOT}/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"; then

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    # Get transferred size from rsync stats
    REMOTE_SIZE=$(ssh -p "${REMOTE_PORT}" "${REMOTE_USER}@${REMOTE_HOST}" \
        "du -sh ${REMOTE_PATH} 2>/dev/null | cut -f1" 2>/dev/null || echo "unknown")

    echo "[$(date)] Off-site backup complete in ${DURATION}s (remote size: ${REMOTE_SIZE})"
    send_telegram "✅ <b>Off-site backup complete</b>
Duration: ${DURATION}s
Remote size: ${REMOTE_SIZE}
Target: ${REMOTE_HOST}"
else
    echo "[$(date)] ERROR: Off-site backup FAILED"
    send_telegram "❌ <b>Off-site backup FAILED</b>
Target: ${REMOTE_HOST}
Check: /home/deploy/logs/backup-offsite.log"
    exit 1
fi
