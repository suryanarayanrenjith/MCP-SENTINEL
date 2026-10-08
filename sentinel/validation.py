from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator

SSRF_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
}


@dataclass
class ValidationResult:
    ok: bool
    issues: list[str]
    risk_delta: int


class InputValidator:
    def validate(self, schema: dict[str, Any], arguments: dict[str, Any]) -> ValidationResult:
        issues: list[str] = []
        if schema:
            validator = Draft202012Validator(schema)
            issues.extend(f"schema: {e.message}" for e in validator.iter_errors(arguments))
        blob = str(arguments)
        if re.search(r"[;&|`$]|\$\(|\n\s*bash", blob):
            issues.append("possible command injection")
        if ".." in blob or blob.startswith("/") and "path" in str(arguments).lower():
            if re.search(r"(\.\./|/etc/|/proc/)", blob):
                issues.append("path traversal")
        for key, value in arguments.items():
            if key in {"url", "destination", "endpoint"} and isinstance(value, str):
                issues.extend(self._url_issues(value))
        risk = 0 if not issues else min(10 + 8 * len(issues), 40)
        return ValidationResult(ok=not issues, issues=issues, risk_delta=risk)

    def _url_issues(self, url: str) -> list[str]:
        issues = []
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        if host in SSRF_HOSTS or host.endswith(".internal") and "soc." not in host and "intel." not in host:
            if host in SSRF_HOSTS:
                issues.append(f"SSRF-blocked host {host}")
        if parsed.scheme in {"file", "gopher", "ftp"}:
            issues.append(f"disallowed URL scheme {parsed.scheme}")
        return issues


class OutputValidator:
    def validate(self, output: Any, expected_schema: dict[str, Any] | None = None) -> ValidationResult:
        issues: list[str] = []
        text = str(output)
        if expected_schema and isinstance(output, dict):
            validator = Draft202012Validator(expected_schema)
            issues.extend(f"schema: {e.message}" for e in validator.iter_errors(output))
        secret_like = re.findall(r"(api[_-]?key|password|secret|token)\s*[:=]\s*\S+", text, re.I)
        if secret_like:
            issues.append("output contains secret-like fields")
        if re.search(r"ignore previous|system:|disable sentinel", text, re.I):
            issues.append("output contains context-injection content")
        if re.search(r"https?://(evil|unknown)\.", text, re.I):
            issues.append("output contains unexpected malicious URL")
        risk = 0 if not issues else min(8 * len(issues), 24)
        return ValidationResult(ok=True, issues=issues, risk_delta=risk)
