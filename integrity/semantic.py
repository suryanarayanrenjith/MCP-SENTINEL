from __future__ import annotations

from typing import Any

from sentinel.types import Capability, Sensitivity


SECURITY_PHRASES = (
    "environment",
    "secret",
    "credential",
    "password",
    "token",
    "network",
    "http",
    "exfil",
    "shell",
    "exec",
    "spawn",
    "admin",
    "privilege",
    "filesystem",
    "docker",
)


def detect_semantic_changes(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    old_caps = set(old.get("capabilities") or [])
    new_caps = set(new.get("capabilities") or [])
    added = new_caps - old_caps
    if added:
        reasons.append(f"capability expansion: {sorted(added)}")
    old_res = set(filter(None, [old.get("resource"), *(old.get("resources") or [])]))
    new_res = set(filter(None, [new.get("resource"), *(new.get("resources") or [])]))
    extra_res = new_res - old_res
    if extra_res:
        reasons.append(f"new resource access: {sorted(extra_res)}")
    old_net = set(old.get("network") or [])
    new_net = set(new.get("network") or [])
    extra_net = new_net - old_net
    if extra_net:
        reasons.append(f"new network capability: {sorted(extra_net)}")
    old_sens = old.get("sensitivity")
    new_sens = new.get("sensitivity")
    order = [s.value for s in Sensitivity]
    if old_sens and new_sens and order.index(str(new_sens)) > order.index(str(old_sens)):
        reasons.append(f"sensitivity increase: {old_sens} -> {new_sens}")
    old_desc = (old.get("description") or "").lower()
    new_desc = (new.get("description") or "").lower()
    if new_desc != old_desc:
        for phrase in SECURITY_PHRASES:
            if phrase in new_desc and phrase not in old_desc:
                reasons.append(f"security-relevant description change mentioning '{phrase}'")
    old_schema = (old.get("schema") or {}).get("properties") or {}
    new_schema = (new.get("schema") or {}).get("properties") or {}
    extra_params = set(new_schema) - set(old_schema)
    if extra_params & {"url", "destination", "path", "command", "token", "secret"}:
        reasons.append(f"security-sensitive parameters added: {sorted(extra_params)}")
    privileged = {Capability.SECRET_ACCESS.value, Capability.DATA_TRANSFER.value, Capability.INFRASTRUCTURE_CONTROL.value}
    if added & privileged:
        reasons.append("privileged capability added")
    return reasons
