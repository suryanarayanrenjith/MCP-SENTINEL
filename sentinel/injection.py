from __future__ import annotations

import re
from dataclasses import dataclass, field

from integrity.scanner import scan_text

# Legacy patterns kept as an additional, high-precision layer.
INJECTION_PATTERNS = [
    r"ignore (all |any )?previous instructions",
    r"<\|?\s*system\s*\|?>",
    r"disable (mcp-?)?sentinel",
    r"override (security )?polic(y|ies)",
    r"reveal .{0,20}secret",
    r"call (the )?(privileged|admin) tool",
    r"exfiltrat",
    r"do not tell the user",
    r"hidden instruction",
    r"tool call:\s*get_credentials",
]
SUSPICIOUS_URL_HINTS = ("evil.", "unknown.example", "pastebin", "ngrok", "requestbin", "webhook.site", "interact.sh", "burpcollaborator", "pipedream")
SEVERITY_P = {"LOW": 0.05, "MEDIUM": 0.2, "HIGH": 0.5, "CRITICAL": 0.8}


@dataclass
class InjectionFinding:
    detected: bool
    matches: list[str]
    risk_delta: int
    likelihood: float = 0.0
    severity: str = "NONE"
    details: list[dict] = field(default_factory=list)


class InjectionGuard:
    """Language detection is supporting evidence only. Enforcement stays in the control plane."""

    def scan(self, text: str | None, *, field_name: str = "text") -> InjectionFinding:
        if not text:
            return InjectionFinding(False, [], 0)
        matches: list[str] = []
        details: list[dict] = []
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, text, re.I):
                matches.append(pattern)
        for f in scan_text(text, field_name):
            if f.severity in {"MEDIUM", "HIGH", "CRITICAL"} and f.category not in {"embedded_url", "encoded_payload"}:
                matches.append(f"{f.category}: {f.title}")
                details.append(f.as_dict())
        for url in re.findall(r"https?://[^\s\"'<>]+", text):
            if any(bad in url.lower() for bad in SUSPICIOUS_URL_HINTS):
                matches.append(f"malicious url:{url[:120]}")
        matches = list(dict.fromkeys(matches))
        if not matches:
            return InjectionFinding(False, [], 0)
        worst = "HIGH" if any(not m.startswith(("injection_phrase", "malicious url")) for m in matches) else "MEDIUM"
        if any(d.get("severity") == "CRITICAL" for d in details):
            worst = "CRITICAL"
        remaining = 1.0
        for d in details:
            remaining *= 1.0 - SEVERITY_P.get(d.get("severity", "LOW"), 0.05)
        likelihood = max(1.0 - remaining, SEVERITY_P[worst] if worst in SEVERITY_P else 0.2)
        return InjectionFinding(
            True,
            matches,
            min(12 * len(matches), 36),
            likelihood=min(0.95, likelihood),
            severity=worst,
            details=details,
        )
