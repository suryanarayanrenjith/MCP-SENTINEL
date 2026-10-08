"""Backwards-compatible entry point: the stdio adapter now lives in ``sentinel.bridge``.

Prefer ``python -m sentinel.bridge`` in claude_desktop_config.json.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.bridge import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
