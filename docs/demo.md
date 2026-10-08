# Demonstration procedure

## Local (no Docker)

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
copy .env.example .env
$env:SENTINEL_DATABASE_URL = "sqlite:///./sentinel.db"
$env:SENTINEL_AUTH_MODE = "demo"
python -m uvicorn sentinel.app:app --port 8443
```

Second terminal:

```powershell
python -m uvicorn mcp_servers.soc_server:app --port 9001
cd dashboard; npm install; npm run dev
```

Third terminal:

```powershell
python -m sentinel.demo
pytest -q
```

## Docker Compose

```powershell
docker compose up --build
```

- Gateway: http://localhost:8443/health
- Dashboard: http://localhost:3000
- Keycloak: http://localhost:8080 (admin/admin), realm `mcp-sentinel`
- OPA: http://localhost:8181

Set `SENTINEL_AUTH_MODE=oidc` and `SENTINEL_OIDC_JWKS_URL=http://keycloak:8080/realms/mcp-sentinel/protocol/openid-connect/certs` for full OIDC.

## Scenarios

1. **Legitimate SOC** (`SOC_ANALYST`): `search_logs` → `lookup_ip` → `create_incident` → ALLOW, low risk.
2. **Dangerous sequence** (`SECURITY_ADMIN`): same prefix then `get_credentials` (MFA + short lease) then `send_data` to an external URL → BLOCK, receipt explains SECRET → DATA_TRANSFER.
3. **Compromised tool**: `search_logs` with observed env/network/process → BLOCK + quarantine; later calls BLOCK.

Open **Workflows** and **Risk** in the dashboard using the `workflow_id` from the demo output.
