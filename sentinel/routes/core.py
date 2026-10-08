from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from identity.tokens import mint_demo_token
from sentinel.config import REPO_ROOT, Settings, get_settings
from sentinel.deps import current_identity, get_store
from sentinel.types import IdentityContext

router = APIRouter()
LOOPBACK_CLIENTS = {"127.0.0.1", "::1", "localhost", "testclient"}


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "component": "mcp-sentinel", "version": "0.2.0", "store": get_store().backend}


@router.post("/v1/demo/token")
def demo_token(
    request: Request,
    role: str = "SOC_ANALYST",
    subject: str = "user-123",
    mfa: bool = False,
    agent_id: str = "soc-agent",
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if settings.auth_mode != "demo":
        raise HTTPException(403, "demo tokens disabled")
    client = request.client.host if request.client else ""
    if settings.demo_token_loopback_only and client not in LOOPBACK_CLIENTS:
        raise HTTPException(403, "demo tokens can only be minted from this machine (SENTINEL_DEMO_TOKEN_LOOPBACK_ONLY)")
    if role not in settings.role_list:
        raise HTTPException(422, f"unknown role {role}")
    token = mint_demo_token(
        settings,
        subject=subject[:128],
        roles=[role],
        agent_id=agent_id[:128],
        acr=settings.mfa_acr if mfa else None,
        amr=["pwd", "otp"] if mfa else ["pwd"],
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": 3600, "subject": subject, "role": role}


@router.get("/v1/auth/whoami")
def whoami(identity: IdentityContext = Depends(current_identity)) -> dict[str, Any]:
    return identity.model_dump(mode="json")


def claude_desktop_entry(settings: Settings) -> dict[str, Any]:
    env = {"SENTINEL_API_URL": settings.api_base_url}
    if settings.auth_mode == "demo":
        env.update({"SENTINEL_SUBJECT": "local-user", "SENTINEL_ROLE": "SECURITY_ADMIN"})
    else:
        env["SENTINEL_TOKEN"] = "<short-lived user access token from your IdP>"
    return {"command": sys.executable, "args": ["-m", "sentinel.bridge"], "env": env}


@router.get("/v1/integrations/claude-desktop")
def claude_desktop(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    entry = claude_desktop_entry(settings)
    home = Path.home()
    paths = {
        "macOS": str(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
        "Windows": r"%APPDATA%\Claude\claude_desktop_config.json",
        "Linux (unofficial builds)": str(home / ".config" / "Claude" / "claude_desktop_config.json"),
    }
    return {
        "config": {"mcpServers": {"mcp-sentinel": entry}},
        "config_paths": paths,
        "cli": f"{sys.executable} -m sentinel.cli install-claude",
        "import_cli": f"{sys.executable} -m sentinel.cli import-claude",
        "claude_code": f"claude mcp add --transport http mcp-sentinel {settings.api_base_url}/mcp --header \"Authorization: Bearer <token>\"",
        "streamable_http_url": f"{settings.api_base_url}/mcp",
        "repo_root": str(REPO_ROOT),
        "notes": [
            "Claude Desktop caches its tool list: after adding servers in Sentinel, toggle the mcp-sentinel connector "
            "off/on (or restart Claude) to see them as native tools; they are usable immediately via sentinel_invoke.",
            "Keep the API on 127.0.0.1; the bridge talks to it locally.",
        ],
    }


@router.get("/v1/integrations/info")
def integrations_info(settings: Settings = Depends(get_settings)) -> dict[str, Any]:
    return {
        "api_url": settings.api_base_url,
        "dashboard_url": settings.dashboard_base_url,
        "auth_mode": settings.auth_mode,
        "approval_wait_seconds": settings.approval_wait_seconds,
        "expose_meta_tools": settings.expose_meta_tools,
        "allow_stdio_servers": settings.allow_stdio_servers,
    }
