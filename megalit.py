#!/usr/bin/env python3
"""Megalit cross-platform launcher."""
import os

import sys



sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import aiohttp  # noqa: F401
    import rich     # noqa: F401
except ImportError:
    print("Missing dependencies. Install them with:\n"
          "    pip install -r requirements.txt\n"
          "  (aiohttp + rich are required; aiohttp-socks for socks proxies)")
    sys.exit(1)

from megalit.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
