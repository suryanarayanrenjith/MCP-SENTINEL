$env:SENTINEL_DATABASE_URL = "sqlite:///./sentinel.db"
$env:SENTINEL_AUTH_MODE = "demo"
python -m uvicorn sentinel.app:app --reload --port 8443
