# Control plane + dashboard (if dashboard/dist is built) on http://127.0.0.1:8443
$env:SENTINEL_DATABASE_URL = "sqlite:///./sentinel.db"
$env:SENTINEL_AUTH_MODE = "demo"
python -m sentinel.cli serve
