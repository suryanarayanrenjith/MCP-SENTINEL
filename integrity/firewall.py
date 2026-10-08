from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from integrity.crypto import canonical_hash
from integrity.semantic import detect_semantic_changes
from sentinel.types import TrustStatus


@dataclass
class ChangeReport:
    crypto_changed: bool
    structural_changed: bool
    semantic_reasons: list[str] = field(default_factory=list)
    recommended_status: TrustStatus = TrustStatus.TRUSTED
    require_sandbox: bool = False

    @property
    def security_relevant(self) -> bool:
        return bool(self.semantic_reasons) or (self.crypto_changed and self.structural_changed)


class SemanticChangeFirewall:
    """Classifies tool/server changes. Harmless updates are not auto-blocked."""

    STRUCTURAL_KEYS = (
        "schema",
        "parameters",
        "return_structure",
        "annotations",
        "capabilities",
        "version",
        "dependencies",
        "resource",
        "network",
    )

    def compare(self, old: dict[str, Any], new: dict[str, Any]) -> ChangeReport:
        crypto_changed = canonical_hash(old) != canonical_hash(new)
        structural_changed = any(old.get(k) != new.get(k) for k in self.STRUCTURAL_KEYS)
        semantic_reasons = detect_semantic_changes(old, new)
        status = TrustStatus.TRUSTED
        require_sandbox = False
        if semantic_reasons:
            status = TrustStatus.RESTRICTED
            require_sandbox = True
        elif crypto_changed or structural_changed:
            status = TrustStatus.MONITORED
        return ChangeReport(
            crypto_changed=crypto_changed,
            structural_changed=structural_changed,
            semantic_reasons=semantic_reasons,
            recommended_status=status,
            require_sandbox=require_sandbox,
        )
