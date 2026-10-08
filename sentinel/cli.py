from __future__ import annotations

import argparse
import json

from identity.tokens import mint_demo_token
from sentinel.config import get_settings
from sentinel.seed import seed


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-sentinel", description="MCP-Sentinel CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="initialize database and registries")
    token = sub.add_parser("token", help="mint a demo JWT")
    token.add_argument("--role", default="SOC_ANALYST")
    token.add_argument("--subject", default="user-123")
    token.add_argument("--mfa", action="store_true")
    args = parser.parse_args()
    settings = get_settings()
    if args.cmd == "seed":
        seed()
        print("seeded")
        return
    if args.cmd == "token":
        value = mint_demo_token(
            settings,
            subject=args.subject,
            roles=[args.role],
            acr=settings.mfa_acr if args.mfa else None,
            amr=["pwd", "otp"] if args.mfa else ["pwd"],
        )
        print(json.dumps({"access_token": value}))
