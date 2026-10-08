from __future__ import annotations

from integrity.crypto import canonical_hash
from integrity.firewall import SemanticChangeFirewall


def test_unchanged_tool():
    payload = {"schema": {"a": 1}, "capabilities": ["READ"], "version": "1", "resource": "logs", "description": "search", "sensitivity": "LOW"}
    report = SemanticChangeFirewall().compare(payload, dict(payload))
    assert not report.crypto_changed
    assert not report.security_relevant


def test_hash_change():
    old = {"schema": {"a": 1}, "capabilities": ["READ"], "version": "1", "resource": "logs", "description": "search", "sensitivity": "LOW"}
    new = {**old, "version": "2"}
    assert canonical_hash(old) != canonical_hash(new)
    report = SemanticChangeFirewall().compare(old, new)
    assert report.crypto_changed
    assert report.structural_changed


def test_schema_change():
    old = {"schema": {"properties": {"q": {}}}, "capabilities": ["READ"], "version": "1", "resource": "logs", "description": "search", "sensitivity": "LOW"}
    new = {**old, "schema": {"properties": {"q": {}, "url": {}}}}
    report = SemanticChangeFirewall().compare(old, new)
    assert report.structural_changed
    assert any("parameters" in r for r in report.semantic_reasons)


def test_capability_expansion():
    old = {"capabilities": ["READ"], "schema": {}, "version": "1", "resource": "logs", "description": "search", "sensitivity": "LOW"}
    new = {**old, "capabilities": ["READ", "SECRET_ACCESS"], "sensitivity": "CRITICAL"}
    report = SemanticChangeFirewall().compare(old, new)
    assert report.security_relevant
    assert any("capability expansion" in r for r in report.semantic_reasons)
    assert any("privileged" in r for r in report.semantic_reasons)


def test_semantic_change_environment():
    old = {
        "capabilities": ["READ"],
        "schema": {},
        "version": "1",
        "resource": "security_logs",
        "description": "READ security_logs",
        "sensitivity": "LOW",
    }
    new = {
        **old,
        "resource": "environment configuration",
        "description": "READ security_logs and READ environment configuration",
        "capabilities": ["READ"],
    }
    report = SemanticChangeFirewall().compare(old, new)
    assert report.security_relevant
    assert report.require_sandbox
