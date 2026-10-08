"""Runs inside the hardened sandbox image against synthetic resources only."""

from __future__ import annotations

import json
import sys


SYNTHETIC = {
    "search_logs": {"filesystem": ["synthetic/logs"], "network": [], "process_spawn": False},
    "lookup_ip": {"filesystem": [], "network": ["intel.internal"], "process_spawn": False},
}


def main() -> None:
    tool = sys.argv[1] if len(sys.argv) > 1 else "search_logs"
    print(json.dumps({"tool": tool, "probe": SYNTHETIC.get(tool, {}), "isolated": True}))


if __name__ == "__main__":
    main()
