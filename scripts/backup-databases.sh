#!/bin/bash
# Unified database backup script for Dockfolio
# Usage: backup-databases.sh [appname|all]
# Runs daily via cron, staggered to avoid load spikes
# Stores compressed backups in /opt/backups/<appname>/
# Retains last 7 daily backups per app

set -euo pipefail

BACKUP_ROOT="/home/deploy/backups"
RETENTION_DAYS=7
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Telegram notifications (same as system-alert.sh)
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID}"

send_notification() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"text\": \"$message\"}" > /dev/null 2>&1 || true
}

backup_postgres() {
    local app_name="$1"
    local container="$2"
    local backup_dir="${BACKUP_ROOT}/${app_name}"
    local backup_file="${backup_dir}/${app_name}-${TIMESTAMP}.sql.gz"

    mkdir -p "$backup_dir"

    echo "[$(date)] Backing up ${app_name} (container: ${container})..."

    # Check container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "  ERROR: Container ${container} is not running"
        send_notification "❌ Backup FAILED: ${app_name} — container ${container} not running"
        return 1
    fi

    # Auto-detect database name and user from container env
    local db_user db_name
    db_user=$(docker exec "$container" sh -c 'echo $POSTGRES_USER' 2>/dev/null)
    db_name=$(docker exec "$container" sh -c 'echo $POSTGRES_DB' 2>/dev/null)
    [ -z "$db_user" ] && db_user="postgres"
    [ -z "$db_name" ] && db_name="postgres"
    echo "  Using user=${db_user} db=${db_name}"

    # Run pg_dump inside the container, compress on host
    if docker exec "$container" pg_dump -U "$db_user" "$db_name" 2>/dev/null | gzip > "$backup_file"; then
        local size=$(du -sh "$backup_file" | cut -f1)
        echo "  OK: ${backup_file} (${size})"

        # Cleanup old backups
        find "$backup_dir" -name "${app_name}-*.sql.gz" -mtime +${RETENTION_DAYS} -delete
        local count=$(ls -1 "$backup_dir"/${app_name}-*.sql.gz 2>/dev/null | wc -l)
        echo "  Retained: ${count} backups"
        return 0
    else
        rm -f "$backup_file"
        echo "  ERROR: pg_dump failed for ${app_name}"
        send_notification "❌ Backup FAILED: ${app_name} — pg_dump error"
        return 1
    fi
}

backup_clickhouse() {
    local container="$1"
    local backup_dir="${BACKUP_ROOT}/plausible-clickhouse"
    local backup_file="${backup_dir}/plausible-clickhouse-${TIMESTAMP}.tar.gz"

    mkdir -p "$backup_dir"

    echo "[$(date)] Backing up Plausible ClickHouse (container: ${container})..."

    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "  ERROR: Container ${container} is not running"
        send_notification "❌ Backup FAILED: Plausible ClickHouse — container ${container} not running"
        return 1
    fi

    # Get list of tables
    local tables
    tables=$(docker exec "$container" clickhouse-client \
        --query "SELECT name FROM system.tables WHERE database = 'plausible_events_db' AND engine NOT IN ('View', 'MaterializedView')" \
        --format TSV 2>/dev/null)

    if [ -z "$tables" ]; then
        echo "  ERROR: No tables found or ClickHouse not responding"
        send_notification "❌ Backup FAILED: Plausible ClickHouse — no tables found"
        return 1
    fi

    # Dump each table as CREATE TABLE + INSERT (CSVWithNames for data, restorable)
    local tmpdir="/tmp/ch-backup-${TIMESTAMP}"
    mkdir -p "$tmpdir"
    local ok=true

    for table in $tables; do
        # Schema
        docker exec "$container" clickhouse-client \
            --query "SHOW CREATE TABLE plausible_events_db.${table}" \
            --format TSVRaw > "${tmpdir}/${table}.schema.sql" 2>/dev/null || true
        # Data as CSVWithNames (human-readable, importable)
        docker exec "$container" clickhouse-client \
            --query "SELECT * FROM plausible_events_db.${table} FORMAT CSVWithNames" \
            > "${tmpdir}/${table}.csv" 2>/dev/null || true
        echo "    Table: ${table} ($(wc -l < "${tmpdir}/${table}.csv") rows)"
    done

    # Pack into tarball
    if tar czf "$backup_file" -C "$tmpdir" . 2>/dev/null; then
        local size=$(du -sh "$backup_file" | cut -f1)
        echo "  OK: ${backup_file} (${size})"
        find "$backup_dir" -name "plausible-clickhouse-*.tar.gz" -mtime +${RETENTION_DAYS} -delete
        rm -rf "$tmpdir"
        return 0
    else
        rm -rf "$tmpdir"
        echo "  ERROR: tar failed"
        send_notification "❌ Backup FAILED: Plausible ClickHouse — tar error"
        return 1
    fi
}

# --- Main ---
TARGET="${1:-all}"
ERRORS=0
SUCCESSES=0

case "$TARGET" in
    promoforge)
        backup_postgres "promoforge" "promoforge-postgres-1" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        ;;
    lohncheck)
        backup_postgres "lohncheck" "lohncheck-postgres" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        ;;
    sacredlens)
        backup_postgres "sacredlens" "sacredlens-postgres" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        ;;
    plausible)
        backup_postgres "plausible-pg" "plausible-plausible_db-1" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        backup_clickhouse "plausible-plausible_events_db-1" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        ;;
    all)
        backup_postgres "promoforge" "promoforge-postgres-1" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        backup_postgres "lohncheck" "lohncheck-postgres" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        backup_postgres "sacredlens" "sacredlens-postgres" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        backup_postgres "plausible-pg" "plausible-plausible_db-1" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        backup_clickhouse "plausible-plausible_events_db-1" && SUCCESSES=$((SUCCESSES+1)) || ERRORS=$((ERRORS+1))
        ;;
    *)
        echo "Usage: $0 [promoforge|lohncheck|sacredlens|plausible|all]"
        exit 1
        ;;
esac

echo ""
echo "[$(date)] Backup complete: ${SUCCESSES} succeeded, ${ERRORS} failed"

if [ "$ERRORS" -gt 0 ]; then
    exit 1
fi
