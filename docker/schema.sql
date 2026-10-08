-- Logical schema for MCP-Sentinel (PostgreSQL dialect).
-- SQLAlchemy creates these tables at startup and adds new columns to older databases automatically.

CREATE TABLE approvals (
	approval_id VARCHAR(64) NOT NULL, 
	workflow_id VARCHAR(128) NOT NULL, 
	tool_name VARCHAR(256) NOT NULL, 
	subject VARCHAR(256) NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	resolved_at TIMESTAMP WITH TIME ZONE, 
	resolver VARCHAR(256) NOT NULL, 
	request_json JSON NOT NULL, 
	server_id VARCHAR(128), 
	request_hash VARCHAR(64), 
	risk_score INTEGER, 
	reasons JSON, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	consumed BOOLEAN, 
	PRIMARY KEY (approval_id)
);
CREATE INDEX ix_approvals_request_hash ON approvals (request_hash);
CREATE INDEX ix_approvals_workflow_id ON approvals (workflow_id);

CREATE TABLE leases (
	lease_id VARCHAR(64) NOT NULL, 
	workflow_id VARCHAR(128) NOT NULL, 
	subject VARCHAR(256) NOT NULL, 
	capability VARCHAR(64) NOT NULL, 
	tool_name VARCHAR(256) NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked_reason VARCHAR(512) NOT NULL, 
	server_id VARCHAR(128), 
	scope_hash VARCHAR(64), 
	PRIMARY KEY (lease_id)
);
CREATE INDEX ix_leases_workflow_id ON leases (workflow_id);

CREATE TABLE mfa_enrollments (
	subject VARCHAR(256) NOT NULL, 
	secret_encrypted TEXT NOT NULL, 
	active BOOLEAN NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_step INTEGER NOT NULL, 
	PRIMARY KEY (subject)
);

CREATE TABLE policy_rules (
	rule_id VARCHAR(64) NOT NULL, 
	name VARCHAR(256) NOT NULL, 
	enabled BOOLEAN NOT NULL, 
	priority INTEGER NOT NULL, 
	match JSON NOT NULL, 
	effect VARCHAR(32) NOT NULL, 
	reason TEXT NOT NULL, 
	created_by VARCHAR(256) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (rule_id)
);

CREATE TABLE receipts (
	receipt_id VARCHAR(64) NOT NULL, 
	workflow_id VARCHAR(128) NOT NULL, 
	identity VARCHAR(256) NOT NULL, 
	agent VARCHAR(256) NOT NULL, 
	server VARCHAR(128) NOT NULL, 
	tool VARCHAR(256) NOT NULL, 
	decision VARCHAR(32) NOT NULL, 
	risk_score INTEGER NOT NULL, 
	state VARCHAR(32) NOT NULL, 
	reasons JSON NOT NULL, 
	previous_tools JSON NOT NULL, 
	payload JSON NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL, 
	seq INTEGER, 
	prev_hash VARCHAR(64), 
	receipt_hash VARCHAR(64), 
	signature TEXT, 
	PRIMARY KEY (receipt_id)
);
CREATE INDEX ix_receipts_decision ON receipts (decision);
CREATE UNIQUE INDEX ix_receipts_seq ON receipts (seq);
CREATE INDEX ix_receipts_timestamp ON receipts (timestamp);
CREATE INDEX ix_receipts_workflow_id ON receipts (workflow_id);

CREATE TABLE runtime_flags (
	key VARCHAR(128) NOT NULL, 
	value JSON NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	updated_by VARCHAR(256) NOT NULL, 
	PRIMARY KEY (key)
);

CREATE TABLE security_events (
	event_id VARCHAR(64) NOT NULL, 
	event_type VARCHAR(64) NOT NULL, 
	severity VARCHAR(32) NOT NULL, 
	message TEXT NOT NULL, 
	details JSON NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL, 
	PRIMARY KEY (event_id)
);
CREATE INDEX ix_security_events_event_type ON security_events (event_type);
CREATE INDEX ix_security_events_timestamp ON security_events (timestamp);

CREATE TABLE servers (
	server_id VARCHAR(128) NOT NULL, 
	server_name VARCHAR(256) NOT NULL, 
	publisher VARCHAR(256) NOT NULL, 
	version VARCHAR(64) NOT NULL, 
	endpoint VARCHAR(512) NOT NULL, 
	transport VARCHAR(32) NOT NULL, 
	trust_status VARCHAR(32) NOT NULL, 
	registration_time TIMESTAMP WITH TIME ZONE NOT NULL, 
	approved_capabilities JSON NOT NULL, 
	integrity_hash VARCHAR(128) NOT NULL, 
	last_verification_time TIMESTAMP WITH TIME ZONE, 
	risk_state VARCHAR(32) NOT NULL, 
	metadata_json JSON NOT NULL, 
	slug VARCHAR(64), 
	enabled BOOLEAN, 
	managed BOOLEAN, 
	config_encrypted TEXT, 
	server_info JSON, 
	pinned_server_info JSON, 
	last_discovery_time TIMESTAMP WITH TIME ZONE, 
	discovery_status VARCHAR(32), 
	last_error TEXT, 
	findings JSON, 
	PRIMARY KEY (server_id)
);
CREATE INDEX ix_servers_slug ON servers (slug);

CREATE TABLE tool_changes (
	change_id VARCHAR(64) NOT NULL, 
	tool_id VARCHAR(256) NOT NULL, 
	server_id VARCHAR(128) NOT NULL, 
	tool_name VARCHAR(256) NOT NULL, 
	change_type VARCHAR(32) NOT NULL, 
	classification VARCHAR(32) NOT NULL, 
	score INTEGER NOT NULL, 
	findings JSON NOT NULL, 
	diff JSON NOT NULL, 
	old_definition JSON NOT NULL, 
	new_definition JSON NOT NULL, 
	status VARCHAR(32) NOT NULL, 
	detected_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	resolved_by VARCHAR(256) NOT NULL, 
	resolved_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (change_id)
);
CREATE INDEX ix_tool_changes_detected_at ON tool_changes (detected_at);
CREATE INDEX ix_tool_changes_server_id ON tool_changes (server_id);
CREATE INDEX ix_tool_changes_status ON tool_changes (status);
CREATE INDEX ix_tool_changes_tool_id ON tool_changes (tool_id);

CREATE TABLE tools (
	tool_id VARCHAR(256) NOT NULL, 
	server_id VARCHAR(128) NOT NULL, 
	tool_name VARCHAR(256) NOT NULL, 
	version VARCHAR(64) NOT NULL, 
	schema_json JSON NOT NULL, 
	capabilities JSON NOT NULL, 
	annotations JSON NOT NULL, 
	expected_behavior JSON NOT NULL, 
	integrity_hash VARCHAR(128) NOT NULL, 
	sensitivity VARCHAR(32) NOT NULL, 
	trust_status VARCHAR(32) NOT NULL, 
	implementation_fingerprint VARCHAR(128) NOT NULL, 
	description TEXT NOT NULL, 
	resource VARCHAR(256) NOT NULL, 
	last_seen TIMESTAMP WITH TIME ZONE NOT NULL, 
	title VARCHAR(256), 
	exposed_name VARCHAR(128), 
	live_definition JSON, 
	live_hash VARCHAR(128), 
	approved_definition JSON, 
	approved_hash VARCHAR(128), 
	scan_findings JSON, 
	inference JSON, 
	flow_roles JSON, 
	review_state VARCHAR(32), 
	removed BOOLEAN, 
	profile_locked BOOLEAN, 
	baseline JSON, 
	first_seen TIMESTAMP WITH TIME ZONE, 
	last_change_id VARCHAR(64), 
	PRIMARY KEY (tool_id)
);
CREATE INDEX ix_tools_exposed_name ON tools (exposed_name);
CREATE INDEX ix_tools_server_id ON tools (server_id);
CREATE INDEX ix_tools_tool_name ON tools (tool_name);

CREATE TABLE workflow_calls (
	id SERIAL NOT NULL, 
	workflow_id VARCHAR(128) NOT NULL, 
	tool_name VARCHAR(256) NOT NULL, 
	capability VARCHAR(64) NOT NULL, 
	resource VARCHAR(256) NOT NULL, 
	destination VARCHAR(512) NOT NULL, 
	data_class VARCHAR(32) NOT NULL, 
	allowed BOOLEAN NOT NULL, 
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL, 
	server_id VARCHAR(128), 
	decision VARCHAR(32), 
	risk_score INTEGER, 
	flow_roles JSON, 
	subject VARCHAR(256), 
	PRIMARY KEY (id)
);
CREATE INDEX ix_workflow_calls_workflow_id ON workflow_calls (workflow_id);
