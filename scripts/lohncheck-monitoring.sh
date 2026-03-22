#!/bin/bash
# LohnCheck additional monitoring checks
# Run standalone via cron: */5 * * * * /home/deploy/scripts/lohncheck-monitoring.sh

source /home/deploy/appmanager/.env 2>/dev/null
HOSTNAME=$(hostname)
STATE_FILE="/tmp/lohncheck-monitor-state"

send_alert() {
    local msg="$1"
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="⚠️ ${HOSTNAME}: ${msg}" \
        -d parse_mode="HTML" > /dev/null 2>&1
}

check_state() { grep -q "^$1$" "$STATE_FILE" 2>/dev/null; }
set_state() { echo "$1" >> "$STATE_FILE"; }
clear_state() { [ -f "$STATE_FILE" ] && sed -i "/^$1$/d" "$STATE_FILE"; }

# --- Disk space check (alert ONCE at 80%, clear when recovered) ---
DISK_USAGE=$(df / | awk 'NR==2{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -ge 80 ]; then
    if ! check_state "disk_high"; then
        send_alert "Disk usage at ${DISK_USAGE}% — cleanup needed"
        set_state "disk_high"
    fi
else
    clear_state "disk_high"
fi

# --- Docker container restart count ---
RESTART_COUNT=$(docker inspect --format='{{.RestartCount}}' lohncheck-backend 2>/dev/null || echo "0")
if [ "$RESTART_COUNT" -gt 0 ]; then
    LAST_ALERT_FILE="/tmp/lohncheck-restart-alert"
    LAST_ALERTED=$(cat "$LAST_ALERT_FILE" 2>/dev/null || echo "0")
    if [ "$RESTART_COUNT" != "$LAST_ALERTED" ]; then
        send_alert "LohnCheck backend container has restarted ${RESTART_COUNT} time(s)"
        echo "$RESTART_COUNT" > "$LAST_ALERT_FILE"
    fi
fi

# --- SSL certificate expiry (alert if <7 days) ---
CERT_EXPIRY=$(echo | openssl s_client -connect lohnpruefung.de:443 -servername lohnpruefung.de 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
if [ -n "$CERT_EXPIRY" ]; then
    EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    if [ "$DAYS_LEFT" -lt 7 ]; then
        if ! check_state "ssl_expiry"; then
            send_alert "SSL certificate expires in ${DAYS_LEFT} days!"
            set_state "ssl_expiry"
        fi
    else
        clear_state "ssl_expiry"
    fi
fi

# --- 5xx error rate in last 5 minutes ---
LOGFILE="/var/log/nginx/lohnpruefung-access.log"
if [ -f "$LOGFILE" ]; then
    FIVE_MIN_AGO=$(date -d '5 minutes ago' '+%d/%b/%Y:%H:%M' 2>/dev/null)
    if [ -n "$FIVE_MIN_AGO" ]; then
        COUNT_5XX=$(awk -v since="$FIVE_MIN_AGO" '$4 >= "["since && $9 ~ /^5[0-9][0-9]$/' "$LOGFILE" 2>/dev/null | wc -l)
        if [ "$COUNT_5XX" -gt 10 ]; then
            send_alert "High 5xx error rate: ${COUNT_5XX} errors in last 5 minutes"
        fi
    fi
fi

# --- Deep health check (DB + Redis) ---
DEEP_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8002/health/deep 2>/dev/null)
if [ "$DEEP_HEALTH" != "200" ]; then
    if ! check_state "deep_health_fail"; then
        BODY=$(curl -s http://localhost:8002/health/deep 2>/dev/null)
        send_alert "Deep health check failed (HTTP ${DEEP_HEALTH}): ${BODY}"
        set_state "deep_health_fail"
    fi
else
    clear_state "deep_health_fail"
fi
