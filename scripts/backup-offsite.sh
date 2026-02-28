#!/bin/bash
# Off-site backup: rsync local backups to remote storage
# Usage: backup-offsite.sh
# Schedule: daily after local backups complete (e.g., 4:30 AM)
#
# Supports: Hetzner Storage Box, any SSH-accessible server, or local archive
# Configure via environment variables or edit REMOTE_* below

set -euo pipefail

BACKUP_ROOT="/home/deploy/backups"
ARCHIVE_DIR="/home/deploy/backups-archive"
TIMESTAMP=$(date +%Y%m%d)

# Remote config (set these for off-site rsync)
REMOTE_HOST="${BACKUP_REMOTE_HOST:-}"
REMOTE_USER="${BACKUP_REMOTE_USER:-}"
REMOTE_PATH="${BACKUP_REMOTE_PATH:-/backups/dockfolio}"
REMOTE_PORT="${BACKUP_REMOTE_PORT:-22}"

# Telegram notifications
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

send_notification() {
    [ -z "$TELEGRAM_BOT_TOKEN" ] && return
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"text\": \"$1\"}" > /dev/null 2>&1 || true
}

# Mode 1: rsync to remote server (if configured)
if [ -n "$REMOTE_HOST" ]; then
    echo "[$(date)] Syncing backups to ${REMOTE_HOST}:${REMOTE_PATH}..."
    if rsync -avz --delete \
        -e "ssh -p ${REMOTE_PORT} -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new" \
        "${BACKUP_ROOT}/" \
        "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"; then
        echo "[$(date)] Off-site sync complete"
        send_notification "Backup sync to ${REMOTE_HOST} complete"
    else
        echo "[$(date)] ERROR: Off-site sync failed"
        send_notification "Backup sync to ${REMOTE_HOST} FAILED"
        exit 1
    fi
else
    # Mode 2: create local archive (fallback when no remote configured)
    echo "[$(date)] No remote host configured. Creating local archive..."
    mkdir -p "$ARCHIVE_DIR"

    ARCHIVE_FILE="${ARCHIVE_DIR}/dockfolio-backup-${TIMESTAMP}.tar.gz"
    if tar czf "$ARCHIVE_FILE" -C "$BACKUP_ROOT" .; then
        SIZE=$(du -sh "$ARCHIVE_FILE" | cut -f1)
        echo "[$(date)] Archive created: ${ARCHIVE_FILE} (${SIZE})"

        # Retain last 7 archives
        find "$ARCHIVE_DIR" -name "dockfolio-backup-*.tar.gz" -mtime +7 -delete
        COUNT=$(ls -1 "$ARCHIVE_DIR"/dockfolio-backup-*.tar.gz 2>/dev/null | wc -l)
        echo "[$(date)] Archives retained: ${COUNT}"
    else
        echo "[$(date)] ERROR: Archive creation failed"
        send_notification "Backup archive FAILED"
        exit 1
    fi
fi

echo "[$(date)] Off-site backup complete"
