#!/bin/bash
# System resource alert script — runs via cron every 5 minutes
# Sends alerts to a Discord/Telegram webhook when thresholds are exceeded

# --- Configuration ---
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
WEBHOOK_URL="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
ALERT_TYPE="telegram"

# Thresholds
DISK_WARN=80
MEM_WARN=85
SWAP_WARN=70

# State file to prevent alert spam (only alert once per issue)
STATE_FILE="/tmp/appmanager-alert-state"

# --- Functions ---
send_alert() {
    local message="$1"
    [ -z "$WEBHOOK_URL" ] && echo "[ALERT] $message" && return

    if [ "$ALERT_TYPE" = "discord" ]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"content\": \"$message\"}" > /dev/null 2>&1
    elif [ "$ALERT_TYPE" = "telegram" ]; then
        # WEBHOOK_URL should be: https://api.telegram.org/bot<TOKEN>/sendMessage
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"text\": \"$message\"}" > /dev/null 2>&1
    fi
}

check_state() {
    local key="$1"
    grep -q "^${key}$" "$STATE_FILE" 2>/dev/null
}

set_state() {
    local key="$1"
    echo "$key" >> "$STATE_FILE"
}

clear_state() {
    local key="$1"
    [ -f "$STATE_FILE" ] && sed -i "/^${key}$/d" "$STATE_FILE"
}

# --- Checks ---
HOSTNAME=$(hostname)
ALERTS=""

# Disk usage
DISK_PCT=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_PCT" -ge "$DISK_WARN" ]; then
    if ! check_state "disk_high"; then
        ALERTS="${ALERTS}⚠️ **Disk usage at ${DISK_PCT}%** (threshold: ${DISK_WARN}%)\n"
        set_state "disk_high"
    fi
else
    clear_state "disk_high"
fi

# Memory usage
MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_AVAIL=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
MEM_PCT=$(( (MEM_TOTAL - MEM_AVAIL) * 100 / MEM_TOTAL ))
if [ "$MEM_PCT" -ge "$MEM_WARN" ]; then
    if ! check_state "mem_high"; then
        ALERTS="${ALERTS}⚠️ **Memory usage at ${MEM_PCT}%** (threshold: ${MEM_WARN}%)\n"
        set_state "mem_high"
    fi
else
    clear_state "mem_high"
fi

# Swap usage
SWAP_TOTAL=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
SWAP_FREE=$(grep SwapFree /proc/meminfo | awk '{print $2}')
if [ "$SWAP_TOTAL" -gt 0 ]; then
    SWAP_PCT=$(( (SWAP_TOTAL - SWAP_FREE) * 100 / SWAP_TOTAL ))
    if [ "$SWAP_PCT" -ge "$SWAP_WARN" ]; then
        if ! check_state "swap_high"; then
            ALERTS="${ALERTS}⚠️ **Swap usage at ${SWAP_PCT}%** (threshold: ${SWAP_WARN}%)\n"
            set_state "swap_high"
        fi
    else
        clear_state "swap_high"
    fi
fi

# Docker containers in unhealthy/restarting state
UNHEALTHY=$(docker ps --filter "health=unhealthy" --format "{{.Names}}" 2>/dev/null)
RESTARTING=$(docker ps --filter "status=restarting" --format "{{.Names}}" 2>/dev/null)

for c in $UNHEALTHY; do
    if ! check_state "unhealthy_${c}"; then
        ALERTS="${ALERTS}🔴 **Container unhealthy:** \`${c}\`\n"
        set_state "unhealthy_${c}"
    fi
done

for c in $RESTARTING; do
    if ! check_state "restarting_${c}"; then
        ALERTS="${ALERTS}🟡 **Container restarting:** \`${c}\`\n"
        set_state "restarting_${c}"
    fi
done

# Clear states for containers that recovered
if [ -f "$STATE_FILE" ]; then
    for key in $(grep "^unhealthy_" "$STATE_FILE" 2>/dev/null); do
        name="${key#unhealthy_}"
        if ! echo "$UNHEALTHY" | grep -q "^${name}$"; then
            clear_state "$key"
            ALERTS="${ALERTS}✅ **Container recovered:** \`${name}\`\n"
        fi
    done
    for key in $(grep "^restarting_" "$STATE_FILE" 2>/dev/null); do
        name="${key#restarting_}"
        if ! echo "$RESTARTING" | grep -q "^${name}$"; then
            clear_state "$key"
            ALERTS="${ALERTS}✅ **Container recovered:** \`${name}\`\n"
        fi
    done
fi

# Send combined alert if any
if [ -n "$ALERTS" ]; then
    MESSAGE="🖥️ **Dockfolio Alert** — \`${HOSTNAME}\`\n\n${ALERTS}"
    send_alert "$MESSAGE"
fi
