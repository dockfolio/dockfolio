#!/usr/bin/env python3
"""Deploy Dockfolio banner injection to all 12 user-facing nginx site configs.

Approach: For each site, adds:
1. A proxy location block: /api/banners/ -> localhost:9091 (dashboard)
2. A sub_filter to inject embed.js before </body>

This keeps everything same-origin (no CSP changes needed).
The dashboard controls which banners appear via placements.
If no active placements for a site, embed.js does nothing.
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime

NGINX_SITES = "/home/deploy/nginx-configs/sites"

# Mapping: config filename -> (slug, is_proxy)
SITES = {
    "promoforge":        ("promoforge",         True),
    "bannerforge":       ("bannerforge",        True),
    "bewerbungsfotos-ai":("headshot-ai",        True),
    "abschlusscheck.de": ("abschlusscheck",     True),
    "lohnpruefung":      ("lohncheck",          False),
    "sacredlens":        ("sacredlens",         False),
    "theadhdmind":       ("theadhdmind",        False),
    "creativeprogrammer":("creative-programmer", False),
    "crelvo":            ("crelvo",             False),
    "logos":             ("old-world-logos",     False),
    "codewithrigor":     ("code-with-rigor",    False),
    "agorahoch3":        ("agorahoch3",         False),
}

BANNER_PROXY_BLOCK = """
    # Dockfolio banner system (proxied for same-origin, no CSP issues)
    location /api/banners/ {
        proxy_pass http://127.0.0.1:9091/api/banners/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
"""

def find_main_https_server_block(lines):
    """Find the start and end line indices of the main HTTPS server block.
    The 'main' block is the one with listen 443 that is NOT a redirect."""
    blocks = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == 'server {':
            start = i
            depth = 1
            j = i + 1
            while j < len(lines) and depth > 0:
                for ch in lines[j]:
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                j += 1
            end = j - 1  # index of closing }
            block_text = ''.join(lines[start:end+1])
            has_443 = 'listen 443' in block_text or 'listen [::]:443' in block_text
            is_redirect = 'return 301' in block_text and 'proxy_pass' not in block_text and 'try_files' not in block_text and 'root ' not in block_text
            if has_443 and not is_redirect:
                blocks.append((start, end))
            i = end + 1
        else:
            i += 1

    if not blocks:
        return None
    # Return the largest block (most lines = the main one)
    return max(blocks, key=lambda b: b[1] - b[0])


def inject_banner(filepath, slug, is_proxy):
    """Inject banner system into a single nginx config file."""
    with open(filepath, 'r') as f:
        content = f.read()

    # Skip if already injected
    if 'Dockfolio banner system' in content:
        print(f"  SKIP {os.path.basename(filepath)}: already injected")
        return False

    lines = content.split('\n')
    block = find_main_https_server_block(lines)

    if block is None:
        print(f"  WARN {os.path.basename(filepath)}: no main HTTPS server block found!")
        return False

    start, end = block
    block_lines = lines[start:end+1]
    block_text = '\n'.join(block_lines)

    sub_filter_line = f"    sub_filter '</body>' '<script src=\"/api/banners/embed.js\" data-app=\"{slug}\"></script></body>';"

    # Check if block already has sub_filter
    has_sub_filter = 'sub_filter ' in block_text and 'sub_filter_once' in block_text

    # For bewerbungsfotos-ai: replace old crelvo-banner.js injection
    if 'crelvo-banner.js' in block_text:
        for i in range(start, end+1):
            if 'crelvo-banner.js' in lines[i] and 'sub_filter' in lines[i]:
                lines[i] = sub_filter_line
                print(f"  REPLACED crelvo-banner.js with embed.js in {os.path.basename(filepath)}")
                has_sub_filter = True  # already has sub_filter infrastructure
                break

    if has_sub_filter:
        # Just add our sub_filter line before the first sub_filter_once in this block
        for i in range(start, end+1):
            if 'sub_filter_once' in lines[i]:
                # Check if our line is already there (from replacement above)
                if any('embed.js' in lines[j] for j in range(start, i+1)):
                    break
                lines.insert(i, sub_filter_line)
                end += 1
                break
    else:
        # No sub_filter — add full block before 'location / {'
        insert_lines = [
            sub_filter_line,
            "    sub_filter_once on;",
            "    sub_filter_types text/html;",
        ]
        if is_proxy:
            insert_lines.append('    proxy_set_header Accept-Encoding "";')
        insert_lines.append("")

        # Find 'location / {' in the main block
        inserted = False
        for i in range(start, end+1):
            stripped = lines[i].strip()
            if stripped == 'location / {' or stripped.startswith('location / {'):
                for j, new_line in enumerate(insert_lines):
                    lines.insert(i + j, new_line)
                end += len(insert_lines)
                inserted = True
                break

        if not inserted:
            print(f"  WARN {os.path.basename(filepath)}: could not find 'location / {{' in main HTTPS block")
            return False

    # Now add the banner proxy location block before the closing } of the main block
    # Recalculate end since we may have inserted lines
    # Find the closing } of the main block again
    block = find_main_https_server_block(lines)
    if block is None:
        print(f"  WARN {os.path.basename(filepath)}: lost main block after sub_filter insert")
        return False
    start, end = block

    proxy_lines = BANNER_PROXY_BLOCK.rstrip('\n').split('\n')
    for j, pl in enumerate(proxy_lines):
        lines.insert(end + j, pl)

    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))

    print(f"  OK {os.path.basename(filepath)} -> slug={slug}")
    return True


def main():
    print("=== Dockfolio Banner Injection Deploy ===\n")

    # Step 1: Backup
    backup_dir = f"{NGINX_SITES}-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    shutil.copytree(NGINX_SITES, backup_dir)
    print(f"[1/4] Backed up to {backup_dir}\n")

    # Step 2: Inject
    print("[2/4] Injecting banner system into site configs")
    success = 0
    for filename, (slug, is_proxy) in SITES.items():
        filepath = os.path.join(NGINX_SITES, filename)
        if not os.path.exists(filepath):
            print(f"  WARN {filename}: file not found!")
            continue
        if inject_banner(filepath, slug, is_proxy):
            success += 1

    print(f"\n  Injected: {success}/{len(SITES)} sites\n")

    # Step 3: Test nginx config
    print("[3/4] Testing nginx configuration")
    result = subprocess.run(
        ["sudo", "nginx", "-t", "-c", "/home/deploy/nginx-configs/nginx.conf"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  FAILED! Error:\n{result.stderr}")
        print(f"\n  Restoring backup...")
        for filename in os.listdir(backup_dir):
            src = os.path.join(backup_dir, filename)
            dst = os.path.join(NGINX_SITES, filename)
            shutil.copy2(src, dst)
        print(f"  Restored. No changes applied.")
        sys.exit(1)
    print(f"  PASSED\n{result.stderr.strip()}\n")

    # Step 4: Reload nginx
    print("[4/4] Reloading nginx")
    result = subprocess.run(
        ["sudo", "nginx", "-c", "/home/deploy/nginx-configs/nginx.conf", "-s", "reload"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  FAILED! {result.stderr}")
        sys.exit(1)
    print("  Nginx reloaded successfully\n")

    print(f"=== Done! {success} sites now have banner injection ===")
    print(f"Backup: {backup_dir}")
    print(f"\nTo verify: curl -s https://promoforge.app | grep embed.js")
    print(f"To rollback: cp -r {backup_dir}/* {NGINX_SITES}/ && sudo nginx -c /home/deploy/nginx-configs/nginx.conf -s reload")


if __name__ == "__main__":
    main()
