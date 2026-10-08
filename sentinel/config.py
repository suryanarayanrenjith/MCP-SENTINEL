from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    env: str = "dev"
    log_level: str = "INFO"
    auth_mode: Literal["demo", "oidc"] = "demo"
    jwt_issuer: str = "http://localhost:8080/realms/mcp-sentinel"
    jwt_audience: str = "mcp-sentinel"
    jwt_algorithms: str = "RS256,HS256"
    demo_jwt_secret: str = "change-me-demo-only-not-for-production"
    oidc_jwks_url: str = "http://localhost:8080/realms/mcp-sentinel/protocol/openid-connect/certs"
    oidc_introspect_url: str = ""
    oidc_client_id: str = "mcp-sentinel"
    oidc_client_secret: str = ""
    database_url: str = "sqlite:///./sentinel.db"
    redis_url: str = "redis://localhost:6379/0"
    opa_url: str = "http://localhost:8181"
    opa_enabled: bool = False
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8443
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    tls_enabled: bool = False
    lease_default_seconds: int = 120
    workflow_ttl_seconds: int = 1800
    mfa_acr: str = "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
    hard_block_on_quarantine: bool = True
    max_risk_allow: int = 39
    mfa_risk_threshold: int = 60
    block_risk_threshold: int = 80
    sandbox_enabled: bool = False
    sandbox_image: str = "mcp-sentinel-sandbox:dev"
    public_registry_url: str = ""
    public_registry_override_local: bool = True
    roles: str = "USER,DEVELOPER,SOC_ANALYST,SECURITY_ADMIN,SYSTEM_ADMIN"

    # Risk weights (configurable, must not override hard policies)
    weight_identity: int = 8
    weight_authorization: int = 10
    weight_server_trust: int = 10
    weight_tool_integrity: int = 12
    weight_semantic_change: int = 10
    weight_workflow: int = 12
    weight_capability: int = 14
    weight_dataflow: int = 16
    weight_input: int = 8
    weight_output: int = 8
    weight_runtime: int = 14
    weight_sandbox: int = 8
    weight_authn_assurance: int = 6

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def jwt_algorithm_list(self) -> list[str]:
        return [a.strip() for a in self.jwt_algorithms.split(",") if a.strip()]

    @property
    def role_list(self) -> list[str]:
        return [r.strip() for r in self.roles.split(",") if r.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
