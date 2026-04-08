#!/usr/bin/env python3
"""Inject crosslinks widget into nginx site configs that have sub_filter but no crosslinks."""
import os

sites_dir = "/home/deploy/nginx-configs/sites"
crosslinks_script = '<script src="https://admin.crelvo.dev/api/crosslinks/widget.js"></script>'

targets = [
    "abfindungsoptimizer.de",
    "best-age.de",
    "schenkungsplaner.eu",
    "logos",
    "creativeprogrammer",
    "dockfolio.dev.conf",
    "kettenreaktion.crelvo.dev",
]

updated = []
for site in targets:
    path = os.path.join(sites_dir, site)
    if not os.path.exists(path):
        print(f"SKIP {site}: file not found")
        continue

    with open(path) as f:
        content = f.read()

    if "crosslinks" in content:
        print(f"SKIP {site}: already has crosslinks")
        continue

    # Find sub_filter lines with </body>
    lines = content.split("\n")
    new_lines = []
    changed = False
    for line in lines:
        if "sub_filter" in line and "</body>" in line and "crosslinks" not in line:
            # Insert crosslinks script before </body>
            line = line.replace("</body>", crosslinks_script + "</body>")
            changed = True
        new_lines.append(line)

    if changed:
        with open(path, "w") as f:
            f.write("\n".join(new_lines))
        updated.append(site)
        print(f"OK {site}: crosslinks added")
    else:
        print(f"WARN {site}: no sub_filter with </body> found")
        for line in lines:
            if "sub_filter" in line.lower():
                print(f"  LINE: {line.strip()[:120]}")

print(f"\nUpdated {len(updated)} sites: {updated}")
