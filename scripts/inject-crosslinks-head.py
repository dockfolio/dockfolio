#!/usr/bin/env python3
"""Add crosslinks via </body> sub_filter to sites that only have </head> sub_filter."""
import os

sites_dir = "/home/deploy/nginx-configs/sites"
crosslinks_line = "    sub_filter '</body>' '<script src=\"https://admin.crelvo.dev/api/crosslinks/widget.js\"></script></body>';\n"

targets = ["best-age.de", "dockfolio.dev.conf"]

for site in targets:
    path = os.path.join(sites_dir, site)
    if not os.path.exists(path):
        print(f"SKIP {site}: not found")
        continue

    with open(path) as f:
        content = f.read()

    if "crosslinks" in content:
        print(f"SKIP {site}: already has crosslinks")
        continue

    # Add body sub_filter after the existing sub_filter_once line
    if "sub_filter_once" in content:
        content = content.replace(
            "sub_filter_once on;",
            "sub_filter_once on;\n" + crosslinks_line.rstrip() + "\n    sub_filter_types text/html;"
        )
        # Also need Accept-Encoding header for sub_filter to work on proxied content
        if "proxy_set_header Accept-Encoding" not in content:
            content = content.replace(
                "sub_filter_once on;",
                'proxy_set_header Accept-Encoding "";\n    sub_filter_once on;'
            )
        with open(path, "w") as f:
            f.write(content)
        print(f"OK {site}: added </body> crosslinks sub_filter")
    else:
        print(f"WARN {site}: no sub_filter_once found")
