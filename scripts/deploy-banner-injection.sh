#!/bin/bash
# Deploy Dockfolio banner injection to all 12 user-facing sites via nginx sub_filter
# This proxies /api/banners/ through each site to avoid CSP issues (same-origin)
# Control is 100% from the dashboard — if no active placements, embed.js does nothing

set -euo pipefail

NGINX_SITES="/home/deploy/nginx-configs/sites"
BACKUP_DIR="/home/deploy/nginx-configs/sites-backup-$(date +%Y%m%d-%H%M%S)"

echo "=== Dockfolio Banner Injection Deploy ==="
echo ""

# Step 1: Backup all configs
echo "[1/4] Backing up nginx configs to $BACKUP_DIR"
cp -r "$NGINX_SITES" "$BACKUP_DIR"
echo "  Backed up $(ls "$BACKUP_DIR" | wc -l) config files"

# Step 2: Define the banner proxy location block (shared by all sites)
# This proxies /api/banners/* to the Dockfolio dashboard container
BANNER_PROXY='
    # Dockfolio banner system (proxied for same-origin, no CSP issues)
    location /api/banners/ {
        proxy_pass http://127.0.0.1:9091/api/banners/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }'

inject_site() {
    local file="$1"
    local slug="$2"
    local type="$3"  # "proxy" or "static"
    local server_name="$4"

    echo "  Processing $server_name (slug=$slug, type=$type)"

    # Check if already injected
    if grep -q 'Dockfolio banner system' "$file"; then
        echo "    SKIP: Already has banner injection"
        return
    fi

    # Add the banner proxy location block before the last closing brace of the main HTTPS server block
    # We find the main server block by looking for the server_name

    # Strategy: Add sub_filter for </body> injection
    # For sites that already have sub_filter (Plausible), just add one more sub_filter line
    # For sites without sub_filter, add the full block

    local sub_filter_line="    sub_filter '</body>' '<script src=\"/api/banners/embed.js\" data-app=\"$slug\"></script></body>';"

    if grep -q "sub_filter_once" "$file"; then
        # Site already has sub_filter — just add our line before the existing sub_filter_once
        # Find the FIRST sub_filter_once in the main HTTPS server block
        sed -i "0,/sub_filter_once/s|sub_filter_once|${sub_filter_line}\n    sub_filter_once|" "$file"
    else
        if [ "$type" = "proxy" ]; then
            # Proxy site without sub_filter — add full block at server level
            # Insert before the main 'location / {' line
            sed -i "0,/location \/ {/s|location / {|${sub_filter_line}\n    sub_filter_once on;\n    sub_filter_types text/html;\n    proxy_set_header Accept-Encoding \"\";\n\n    location / {|" "$file"
        else
            # Static site without sub_filter — add at server level
            sed -i "0,/location \/ {/s|location / {|${sub_filter_line}\n    sub_filter_once on;\n    sub_filter_types text/html;\n\n    location / {|" "$file"
        fi
    fi

    # Add the banner proxy location block
    # Insert before the last closing brace of the file (end of last server block)
    # We use tac/sed/tac to find the LAST } and insert before it
    # Actually, let's insert before the access_log or error_log line, or before the last }

    # Find a good insertion point in the main HTTPS server block
    # Most configs have access_log or 'location ~ /\.' near the end
    if grep -q "access_log" "$file"; then
        # Insert before the first access_log in the main block
        sed -i "0,/^    access_log/{s|^    access_log|${BANNER_PROXY}\n\n    access_log|}" "$file"
    elif grep -q "location ~ /\\\\." "$file"; then
        sed -i "0,/location ~ \/\\\\./{s|location ~ /\\\\.|${BANNER_PROXY}\n\n    location ~ /\\\\.|}" "$file"
    else
        # Fallback: insert before the last closing brace
        # Use a Python one-liner for reliability
        python3 -c "
import sys
lines = open('$file').readlines()
# Find last }
for i in range(len(lines)-1, -1, -1):
    if lines[i].strip() == '}':
        lines.insert(i, '''${BANNER_PROXY}\n''')
        break
open('$file', 'w').writelines(lines)
"
    fi

    echo "    OK: Injected"
}

echo ""
echo "[2/4] Injecting banner system into 12 site configs"

# === Proxied Sites (need Accept-Encoding header) ===
inject_site "$NGINX_SITES/promoforge"        "promoforge"      "proxy"  "promoforge.app"
inject_site "$NGINX_SITES/bannerforge"       "bannerforge"     "proxy"  "bannerforge.app"
inject_site "$NGINX_SITES/bewerbungsfotos-ai" "headshot-ai"    "proxy"  "bewerbungsfotos-ai.de"
inject_site "$NGINX_SITES/abschlusscheck.de" "abschlusscheck"  "proxy"  "abschlusscheck.de"
inject_site "$NGINX_SITES/lohnpruefung"      "lohncheck"       "static" "lohnpruefung.de"
inject_site "$NGINX_SITES/sacredlens"        "sacredlens"      "static" "sacredlens.de"

# === Static Sites ===
inject_site "$NGINX_SITES/theadhdmind"       "theadhdmind"         "static" "theadhdmind.org"
inject_site "$NGINX_SITES/creativeprogrammer" "creative-programmer" "static" "thecreativeprogrammer.dev"
inject_site "$NGINX_SITES/crelvo"            "crelvo"              "static" "crelvo.dev"
inject_site "$NGINX_SITES/logos"             "old-world-logos"     "static" "oldworldlogos.com"
inject_site "$NGINX_SITES/codewithrigor"     "code-with-rigor"     "static" "codewithrigor.com"
inject_site "$NGINX_SITES/agorahoch3"        "agorahoch3"          "static" "agorahoch3.org"

# Step 3: Test nginx config
echo ""
echo "[3/4] Testing nginx configuration"
if sudo nginx -t -c /home/deploy/nginx-configs/nginx.conf 2>&1; then
    echo "  Config test PASSED"
else
    echo "  CONFIG TEST FAILED! Restoring backup..."
    cp -r "$BACKUP_DIR"/* "$NGINX_SITES/"
    echo "  Restored from backup. No changes applied."
    exit 1
fi

# Step 4: Reload nginx
echo ""
echo "[4/4] Reloading nginx"
sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload
echo "  Nginx reloaded successfully"

echo ""
echo "=== Banner injection deployed to 12 sites ==="
echo "Backup at: $BACKUP_DIR"
echo ""
echo "To verify, run:"
echo "  curl -s https://promoforge.app | grep 'embed.js'"
echo ""
echo "To rollback:"
echo "  cp -r $BACKUP_DIR/* $NGINX_SITES/ && sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload"
