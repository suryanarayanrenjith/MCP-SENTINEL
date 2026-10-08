from __future__ import annotations

import os
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_sentinel.db"
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["SENTINEL_AUTH_MODE"] = "demo"
os.environ["SENTINEL_REDIS_URL"] = ""
os.environ["SENTINEL_OPA_ENABLED"] = "false"
os.environ["SENTINEL_DEMO_JWT_SECRET"] = "test-secret-not-for-production"
os.environ["SENTINEL_JWT_ISSUER"] = "http://localhost:8080/realms/mcp-sentinel"
os.environ["SENTINEL_JWT_AUDIENCE"] = "mcp-sentinel"

import pytest
from fastapi.testclient import TestClient

from sentinel.config import get_settings
from sentinel.db import reset_engine


@pytest.fixture(autouse=True)
def _reset_db():
    get_settings.cache_clear()
    reset_engine()
    if TEST_DB.exists():
        TEST_DB.unlink()
    yield
    reset_engine()
    if TEST_DB.exists():
        TEST_DB.unlink()


@pytest.fixture
def client(_reset_db) -> TestClient:
    from sentinel.app import app

    with TestClient(app) as test_client:
        yield test_client
