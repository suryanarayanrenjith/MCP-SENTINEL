package sentinel.authz

import future.keywords.if
import future.keywords.in

default decision := {
  "allow": false,
  "hard_block": true,
  "policy_id": "opa.deny.default",
  "reasons": ["default deny"],
  "require_mfa": false,
  "require_lease": false
}

forbidden_destinations := {
  "unknown.example",
  "evil.example",
  "169.254.169.254",
  "metadata.google.internal"
}

blocked_status := {"BLOCKED", "QUARANTINED"}
sensitive := {"SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL"}

role_caps := {
  "USER": {"READ"},
  "DEVELOPER": {"READ", "WRITE", "EXTERNAL_LOOKUP"},
  "SOC_ANALYST": {"READ", "WRITE", "EXTERNAL_LOOKUP"},
  "SECURITY_ADMIN": {"READ", "WRITE", "EXTERNAL_LOOKUP", "SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL"},
  "SYSTEM_ADMIN": {"READ", "WRITE", "EXTERNAL_LOOKUP", "SECRET_ACCESS", "DATA_TRANSFER", "INFRASTRUCTURE_CONTROL"}
}

granted_caps[c] if {
  some role in input.roles
  some c in role_caps[role]
}

decision := {
  "allow": false,
  "hard_block": true,
  "policy_id": "opa.deny.invalid_identity",
  "reasons": ["invalid token"],
  "require_mfa": false,
  "require_lease": false
} if {
  not input.token_valid
}

decision := {
  "allow": false,
  "hard_block": true,
  "policy_id": "opa.deny.server_trust",
  "reasons": [sprintf("server trust status is %v", [input.server_status])],
  "require_mfa": false,
  "require_lease": false
} if {
  input.server_status in blocked_status
}

decision := {
  "allow": false,
  "hard_block": true,
  "policy_id": "opa.deny.forbidden_destination",
  "reasons": ["forbidden destination"],
  "require_mfa": false,
  "require_lease": false
} if {
  some d in forbidden_destinations
  contains(lower(input.destination), d)
}

decision := {
  "allow": true,
  "hard_block": false,
  "policy_id": "opa.allow.default",
  "reasons": ["identity, role, server, tool, and capability checks passed"],
  "require_mfa": input.capability in sensitive,
  "require_lease": input.capability in sensitive
} if {
  input.token_valid
  not input.server_status in blocked_status
  not input.tool_status in blocked_status
  input.capability in granted_caps
}
