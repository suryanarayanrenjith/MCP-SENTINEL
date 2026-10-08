from __future__ import annotations

import re
from dataclasses import dataclass

INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"you are now",
    r"system:\s",
    r"<\|?\s*system\s*\|?>",
    r"disable (mcp-?)?sentinel",
    r"override (security )?policy",
    r"reveal .{0,20}secret",
    r"call (the )?(privileged|admin) tool",
    r"exfiltrat",
    r"do not tell the user",
    r"hidden instruction",
    r"tool call:\s*get_credentials",
]


@dataclass
class InjectionFinding:
    detected: bool
    matches: list[str]
    risk_delta: int


class InjectionGuard:
    """Language detection is supporting evidence only. Enforcement stays in the control plane."""

    def scan(self, text: str | None) -> InjectionFinding:
        if not text:
            return InjectionFinding(False, [], 0)
        blob = text.lower()
        matches = []
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, blob, re.I):
                matches.append(pattern)
        urls = re.findall(r"https?://[^\s]+", text or "")
        for url in urls:
            if any(bad in url.lower() for bad in ("evil.", "unknown.example", "pastebin", "ngrok")):
                matches.append(f"malicious url:{url}")
        delta = min(12 * len(matches), 36) if matches else 0
        return InjectionFinding(bool(matches), matches, delta)
