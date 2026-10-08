-- Logical schema for MCP-Sentinel (SQLAlchemy also creates this at startup).
CREATE TABLE IF NOT EXISTS servers (
  server_id VARCHAR(128) PRIMARY KEY,
  server_name VARCHAR(256) NOT NULL,
  publisher VARCHAR(256) NOT NULL,
  version VARCHAR(64) NOT NULL,
  endpoint VARCHAR(512) NOT NULL,
  transport VARCHAR(32) DEFAULT 'http',
  trust_status VARCHAR(32) DEFAULT 'MONITORED',
  registration_time TIMESTAMPTZ,
  approved_capabilities JSON,
  integrity_hash VARCHAR(128),
  last_verification_time TIMESTAMPTZ,
  risk_state VARCHAR(32),
  metadata_json JSON
);

CREATE TABLE IF NOT EXISTS tools (
  tool_id VARCHAR(256) PRIMARY KEY,
  server_id VARCHAR(128) NOT NULL,
  tool_name VARCHAR(256) NOT NULL,
  version VARCHAR(64) NOT NULL,
  schema_json JSON,
  capabilities JSON,
  annotations JSON,
  expected_behavior JSON,
  integrity_hash VARCHAR(128) NOT NULL,
  sensitivity VARCHAR(32) NOT NULL,
  trust_status VARCHAR(32),
  implementation_fingerprint VARCHAR(128),
  description TEXT,
  resource VARCHAR(256),
  last_seen TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS receipts (
  receipt_id VARCHAR(64) PRIMARY KEY,
  workflow_id VARCHAR(128),
  identity VARCHAR(256),
  agent VARCHAR(256),
  server VARCHAR(128),
  tool VARCHAR(256),
  decision VARCHAR(32),
  risk_score INTEGER,
  state VARCHAR(32),
  reasons JSON,
  previous_tools JSON,
  payload JSON,
  timestamp TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS leases (
  lease_id VARCHAR(64) PRIMARY KEY,
  workflow_id VARCHAR(128),
  subject VARCHAR(256),
  capability VARCHAR(64),
  tool_name VARCHAR(256),
  state VARCHAR(32),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ,
  revoked_reason VARCHAR(512)
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id VARCHAR(64) PRIMARY KEY,
  workflow_id VARCHAR(128),
  tool_name VARCHAR(256),
  subject VARCHAR(256),
  status VARCHAR(32),
  created_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  resolver VARCHAR(256),
  request_json JSON
);

CREATE TABLE IF NOT EXISTS security_events (
  event_id VARCHAR(64) PRIMARY KEY,
  event_type VARCHAR(64),
  severity VARCHAR(32),
  message TEXT,
  details JSON,
  timestamp TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS workflow_calls (
  id SERIAL PRIMARY KEY,
  workflow_id VARCHAR(128),
  tool_name VARCHAR(256),
  capability VARCHAR(64),
  resource VARCHAR(256),
  destination VARCHAR(512),
  data_class VARCHAR(32),
  allowed BOOLEAN,
  timestamp TIMESTAMPTZ
);
