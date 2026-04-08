#!/usr/bin/env python3
"""Inject crosslinks widget into game site nginx configs."""
import re
import sys

SITES = [
    'creatureforge.conf',
    'grimhollow',
    'huntingdragons.crelvo.dev',
    'lufthafen',
    'worldcontrol',
]

BASE = '/home/deploy/nginx-configs/sites/'

INJECTION = """
    # Crosslinks widget injection
    sub_filter '</body>' '<script src="https://admin.crelvo.dev/api/crosslinks/widget.js"></script></body>';
    sub_filter_once on;
    sub_filter_types text/html;
"""

for site in SITES:
    path = BASE + site
    try:
        with open(path) as f:
            content = f.read()
    except FileNotFoundError:
        print(f"SKIP {site} (file not found)")
        continue

    if 'crosslinks' in content:
        print(f"SKIP {site} (already has crosslinks)")
        continue

    # Find all server blocks
    blocks = list(re.finditer(r'server\s*\{', content))
    if len(blocks) < 2:
        # Only one server block - use it
        last_block_start = blocks[0].start() if blocks else None
    else:
        # Use last server block (HTTPS)
        last_block_start = blocks[-1].start()

    if last_block_start is None:
        print(f"ERROR {site}: no server block found")
        continue

    # Find first location directive in the last server block
    rest = content[last_block_start:]
    loc_match = re.search(r'\n(\s*location\s)', rest)
    if not loc_match:
        print(f"ERROR {site}: no location directive found")
        continue

    insert_pos = last_block_start + loc_match.start()
    new_content = content[:insert_pos] + INJECTION + content[insert_pos:]

    with open(path, 'w') as f:
        f.write(new_content)
    print(f"DONE {site}")
