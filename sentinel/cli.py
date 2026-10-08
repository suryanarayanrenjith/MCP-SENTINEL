"""MCP-Sentinel command line.

    mcp-sentinel serve                 run the control plane (API + dashboard if built)
    mcp-sentinel bridge                run the stdio MCP bridge (what Claude Desktop launches)
    mcp-sentinel lab                   run the lab SOC MCP server on :9001
    mcp-sentinel claude-config         print the claude_desktop_config.json entry
    mcp-sentinel install-claude        add Sentinel to Claude Desktop's config (with a backup)
    mcp-sentinel import-claude         move existing Claude Desktop servers behind Sentinel
    mcp-sentinel token / seed          demo token / initialise the database
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from identity.tokens import mint_demo_token
from sentinel.config import get_settings


def claude_config_candidates() -> list[Path]:
    home = Path.home()
    paths: list[Path] = []
    if sys.platform == "darwin":
        paths.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
        local = os.environ.get("LOCALAPPDATA")
        if local:  # Microsoft Store (MSIX) installs virtualise %APPDATA%
            paths += [Path(p) for p in glob.glob(os.path.join(local, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"))]
    else:
        paths.append(home / ".config" / "Claude" / "claude_desktop_config.json")
    return paths


def find_claude_config(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    for p in claude_config_candidates():
        if p.exists():
            return p
    return claude_config_candidates()[0]


def sentinel_entry(api_url: str, subject: str, role: str, token: str | None) -> dict[str, Any]:
    env = {"SENTINEL_API_URL": api_url}
    if token:
        env["SENTINEL_TOKEN"] = token
    else:
        env.update({"SENTINEL_SUBJECT": subject, "SENTINEL_ROLE": role})
    return {"command": sys.executable, "args": ["-m", "sentinel.bridge"], "env": env}


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8").strip()
    return json.loads(text) if text else {}


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.sentinel-backup-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(path, backup)
    return backup


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _api_admin_token(api_url: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    import httpx

    resp = httpx.post(f"{api_url}/v1/demo/token", params={"role": "SECURITY_ADMIN", "subject": "local-admin"}, timeout=10, trust_env=False)
    if resp.status_code != 200:
        raise SystemExit(f"could not mint a demo admin token ({resp.status_code}); pass --token")
    return resp.json()["access_token"]


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-sentinel", description="MCP-Sentinel CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="initialize database and registries")
    token = sub.add_parser("token", help="mint a demo JWT")
    token.add_argument("--role", default="SOC_ANALYST")
    token.add_argument("--subject", default="user-123")
    token.add_argument("--mfa", action="store_true")
    serve = sub.add_parser("serve", help="run the control plane")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    sub.add_parser("bridge", help="run the stdio MCP bridge (Claude Desktop)")
    lab = sub.add_parser("lab", help="run the lab SOC MCP server")
    lab.add_argument("--port", type=int, default=9001)
    for name in ("claude-config", "install-claude", "import-claude"):
        p = sub.add_parser(name)
        p.add_argument("--api", default=None, help="Sentinel API URL")
        p.add_argument("--config", default=None, help="path to claude_desktop_config.json")
        p.add_argument("--subject", default="local-user")
        p.add_argument("--role", default="SECURITY_ADMIN")
        p.add_argument("--token", default=None, help="user/admin token (OIDC mode)")
        if name == "import-claude":
            p.add_argument("--replace", action="store_true", help="after importing, leave only Sentinel in Claude's config")
            p.add_argument("--sandbox", action="store_true", help="run the honeypot sandbox for each imported stdio server")
    args = parser.parse_args()
    settings = get_settings()

    if args.cmd == "seed":
        from sentinel.seed import seed

        seed()
        print("seeded")
        return
    if args.cmd == "token":
        value = mint_demo_token(
            settings, subject=args.subject, roles=[args.role],
            acr=settings.mfa_acr if args.mfa else None, amr=["pwd", "otp"] if args.mfa else ["pwd"],
        )
        print(json.dumps({"access_token": value}))
        return
    if args.cmd == "serve":
        import uvicorn

        uvicorn.run("sentinel.app:app", host=args.host or settings.gateway_host, port=args.port or settings.gateway_port)
        return
    if args.cmd == "bridge":
        from sentinel.bridge import main as bridge_main

        raise SystemExit(bridge_main())
    if args.cmd == "lab":
        import uvicorn

        uvicorn.run("mcp_servers.soc_server:app", host="127.0.0.1", port=args.port)
        return

    api_url = (args.api or settings.api_base_url).rstrip("/")
    entry = sentinel_entry(api_url, args.subject, args.role, args.token if settings.auth_mode == "oidc" else None)
    if args.cmd == "claude-config":
        print(json.dumps({"mcpServers": {"mcp-sentinel": entry}}, indent=2))
        return
    path = find_claude_config(args.config)
    config = _load(path)
    servers = dict(config.get("mcpServers") or {})
    if args.cmd == "import-claude":
        others = {k: v for k, v in servers.items() if k != "mcp-sentinel" and "sentinel.bridge" not in json.dumps(v)}
        if not others:
            print(f"no servers to import in {path}")
        else:
            import httpx

            admin = _api_admin_token(api_url, args.token)
            resp = httpx.post(
                f"{api_url}/v1/servers/import",
                json={"config": {"mcpServers": others}, "connect": True, "run_sandbox": bool(args.sandbox)},
                headers={"Authorization": f"Bearer {admin}"},
                timeout=600,
                trust_env=False,
            )
            if resp.status_code != 200:
                raise SystemExit(f"import failed: {resp.status_code} {resp.text[:300]}")
            for r in resp.json().get("results", []):
                status = r.get("error") or r.get("skipped") or f"{r.get('trust_status')} · {r.get('tools', 0)} tools"
                print(f"  {r['name']:28} {status}")
            if args.replace:
                servers = {}
    servers["mcp-sentinel"] = entry
    config["mcpServers"] = servers
    backup = _backup(path)
    _write(path, config)
    print(f"updated {path}" + (f" (backup: {backup.name})" if backup else ""))
    print("Restart Claude Desktop (or toggle the connector) to load MCP-Sentinel.")


if __name__ == "__main__":
    main()
