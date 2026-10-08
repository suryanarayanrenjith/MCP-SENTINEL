package sentinel.authz

# Mirror of policy/engine.py (_local). Uses an ordered else-chain so exactly one decision is
# produced (the previous version declared several complete rules that could all match and made
# OPA return eval_conflict_error).
import rego.v1

forbidden_destinations := {
	"unknown.example",
	"evil.example",
	"169.254.169.254",
	"metadata.google.internal",
}

blocked_status := {"BLOCKED", "QUARANTINED"}

sensitive := {"SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL", "CODE_EXECUTION"}

all_caps := {"READ", "WRITE", "EXTERNAL_LOOKUP", "SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL", "CODE_EXECUTION"}

role_caps := {
	"USER": {"READ"},
	"DEVELOPER": {"READ", "WRITE", "EXTERNAL_LOOKUP", "CODE_EXECUTION"},
	"ANALYST": {"READ", "WRITE", "EXTERNAL_LOOKUP"},
	"SECURITY_ADMIN": all_caps,
	"SYSTEM_ADMIN": all_caps,
}

granted_caps contains c if {
	some role in input.roles
	some c in role_caps[role]
}

requested_caps := {c | some c in input.capabilities} if {
	input.capabilities
} else := {input.capability}

missing_caps := requested_caps - granted_caps

default is_sensitive := false

is_sensitive if {
	some c in requested_caps
	c in sensitive
}

forbidden_destination if {
	some d in forbidden_destinations
	contains(lower(input.destination), d)
}

deny(policy_id, reason) := {
	"allow": false,
	"hard_block": true,
	"policy_id": policy_id,
	"reasons": [reason],
	"require_mfa": false,
	"require_lease": false,
}

decision := deny("opa.deny.invalid_identity", "invalid token") if {
	not input.token_valid
} else := deny("opa.deny.no_roles", "no authorized roles in identity token") if {
	count(input.roles) == 0
} else := deny("opa.deny.server_trust", sprintf("server trust status is %v", [input.server_status])) if {
	input.server_status in blocked_status
} else := deny("opa.deny.tool_trust", sprintf("tool trust status is %v", [input.tool_status])) if {
	input.tool_status in blocked_status
} else := deny("opa.deny.unauthorized_capability", sprintf("roles %v do not include %v", [input.roles, missing_caps])) if {
	count(missing_caps) > 0
} else := deny("opa.deny.forbidden_destination", "forbidden destination") if {
	forbidden_destination
} else := deny("opa.deny.restricted_server", "restricted server cannot use sensitive capabilities") if {
	input.server_status == "RESTRICTED"
	is_sensitive
} else := {
	"allow": true,
	"hard_block": false,
	"policy_id": "opa.allow.default",
	"reasons": ["identity, role, server, tool, and capability checks passed"],
	"require_mfa": is_sensitive,
	"require_lease": is_sensitive,
}
