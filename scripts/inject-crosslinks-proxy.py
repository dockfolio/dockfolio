#!/usr/bin/env python3
"""Add crosslinks widget via sub_filter to proxied sites."""
import os

sites_dir = "/home/deploy/nginx-configs/sites"

# For proxied sites, we need:
# 1. proxy_set_header Accept-Encoding ""; (so sub_filter can work on compressed content)
# 2. sub_filter '</body>' '<script ...></script></body>';
# 3. sub_filter_once on;
# 4. sub_filter_types text/html;

crosslinks_block = '''
    # Crosslinks widget injection
    proxy_set_header Accept-Encoding "";
    sub_filter '</body>' '<script src="https://admin.crelvo.dev/api/crosslinks/widget.js"></script></body>';
    sub_filter_once on;
    sub_filter_types text/html;'''

targets = {
    "betpilot": "betpilot",
    "orb": "orb",
}

for name, filename in targets.items():
    # Find the actual file (might have extension)
    candidates = [filename, filename + ".conf"]
    path = None
    for c in candidates:
        p = os.path.join(sites_dir, c)
        if os.path.exists(p):
            path = p
            break

    if not path:
        # Try glob
        import glob
        matches = glob.glob(os.path.join(sites_dir, f"*{filename}*"))
        if matches:
            path = matches[0]

    if not path:
        print(f"SKIP {name}: config not found")
        continue

    with open(path) as f:
        content = f.read()

    if "crosslinks" in content:
        print(f"SKIP {name}: already has crosslinks")
        continue

    if "proxy_pass" not in content:
        print(f"SKIP {name}: not a proxy config")
        continue

    # Find the main server block's first proxy_pass and insert before it
    lines = content.split("\n")
    new_lines = []
    injected = False
    for i, line in enumerate(lines):
        # Insert crosslinks block before the first proxy_pass in a location /
        if not injected and "proxy_pass" in line and "location" not in line:
            # Add the crosslinks block before this proxy_pass
            new_lines.append(crosslinks_block)
            injected = True
        new_lines.append(line)

    if injected:
        with open(path, "w") as f:
            f.write("\n".join(new_lines))
        print(f"OK {name}: crosslinks sub_filter added ({os.path.basename(path)})")
    else:
        print(f"WARN {name}: could not find injection point")
