from __future__ import annotations

import os
import tempfile
from pathlib import Path

TMP = Path(tempfile.mkdtemp(prefix="sentinel-tests-"))
TEST_DB = TMP / "test_sentinel.db"
os.environ["SENTINEL_DATABASE_URL"] = f"sqlite:///{TEST_DB.as_posix()}"
os.environ["SENTINEL_AUTH_MODE"] = "demo"
os.environ["SENTINEL_REDIS_URL"] = ""
os.environ["SENTINEL_OPA_ENABLED"] = "false"
os.environ["SENTINEL_DEMO_JWT_SECRET"] = "test-secret-not-for-production"
os.environ["SENTINEL_JWT_ISSUER"] = "http://localhost:8080/realms/mcp-sentinel"
os.environ["SENTINEL_JWT_AUDIENCE"] = "mcp-sentinel"
os.environ["SENTINEL_BACKGROUND_JOBS_ENABLED"] = "false"
os.environ["SENTINEL_APPROVAL_WAIT_SECONDS"] = "0"
os.environ["SENTINEL_SECRETS_KEY_FILE"] = str(TMP / "sentinel.key")
os.environ["SENTINEL_RECEIPT_KEY_FILE"] = str(TMP / "receipt_ed25519.pem")
# Nothing listens on the discard port: the lab SOC server is "down" unless a test starts one.
os.environ["SENTINEL_SOC_ENDPOINT"] = "http://127.0.0.1:9/mcp"
os.environ["SENTINEL_STATIC_DASHBOARD_DIR"] = str(TMP / "no-dashboard")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sentinel.config import get_settings  # noqa: E402
from sentinel.db import reset_engine  # noqa: E402


def _cleanup() -> None:
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(TEST_DB) + suffix)
        if p.exists():
            p.unlink()


@pytest.fixture(autouse=True)
def _reset_db():
    get_settings.cache_clear()
    reset_engine()
    _cleanup()
    yield
    reset_engine()
    _cleanup()


@pytest.fixture(scope="session")
def soc_endpoint() -> str:
    """The lab SOC MCP server, running for real (Streamable HTTP) on a free local port."""
    import socket
    import threading
    import time

    import uvicorn

    from mcp_servers.soc_server import app as soc_app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = uvicorn.Server(uvicorn.Config(soc_app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True


@pytest.fixture
def client(_reset_db, soc_endpoint) -> TestClient:
    from mcp_servers import soc_server
    from sentinel.app import app

    soc_server.STATE.update({"rugpull": False, "compromised": False})
    os.environ["SENTINEL_SOC_ENDPOINT"] = soc_endpoint
    with TestClient(app) as test_client:
        yield test_client
