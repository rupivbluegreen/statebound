# rbac_test.rego — tests for statebound.policies.rbac.

package statebound.policies.rbac_test

import rego.v1

import data.statebound.policies.rbac

# capability_roles fixture mirrors domain.capabilityRoles for the
# capabilities the tests exercise. Keep this fixture in lockstep with
# internal/domain/rbac.go.
capability_roles := {
	"changeset:approve": ["approver", "admin"],
	"apply:execute": ["admin"],
	"product:read": ["viewer", "requester", "approver", "operator", "admin"],
}

test_admin_passes_apply if {
	result := rbac.decision with input as {
		"phase": "approve",
		"required_capability": "apply:execute",
		"actor": {"kind": "human", "subject": "alice"},
		"actor_roles": ["admin"],
		"capability_roles": capability_roles,
	}
	count(result) == 0
}

test_viewer_denied_for_apply if {
	result := rbac.decision with input as {
		"phase": "approve",
		"required_capability": "apply:execute",
		"actor": {"kind": "human", "subject": "eve"},
		"actor_roles": ["viewer"],
		"capability_roles": capability_roles,
	}
	count(result) == 1
	some d in result
	d.rule_id == "rbac_role_required"
	d.outcome == "deny"
	d.severity == "high"
}

test_empty_actor_roles_denied if {
	result := rbac.decision with input as {
		"phase": "approve",
		"required_capability": "changeset:approve",
		"actor": {"kind": "human", "subject": "mallory"},
		"actor_roles": [],
		"capability_roles": capability_roles,
	}
	count(result) == 1
	some d in result
	d.rule_id == "rbac_role_required"
}

test_unknown_capability_no_deny if {
	result := rbac.decision with input as {
		"phase": "approve",
		"required_capability": "invented:cap",
		"actor": {"kind": "human", "subject": "alice"},
		"actor_roles": ["viewer"],
		"capability_roles": capability_roles,
	}
	count(result) == 0
}

test_empty_required_capability_no_deny if {
	result := rbac.decision with input as {
		"phase": "approve",
		"required_capability": "",
		"actor": {"kind": "human", "subject": "alice"},
		"actor_roles": [],
		"capability_roles": capability_roles,
	}
	count(result) == 0
}

test_silent_outside_submit_approve if {
	result := rbac.decision with input as {
		"phase": "plan",
		"required_capability": "apply:execute",
		"actor": {"kind": "human", "subject": "eve"},
		"actor_roles": [],
		"capability_roles": capability_roles,
	}
	count(result) == 0
}

test_approver_passes_for_approve if {
	result := rbac.decision with input as {
		"phase": "approve",
		"required_capability": "changeset:approve",
		"actor": {"kind": "human", "subject": "bob"},
		"actor_roles": ["approver"],
		"capability_roles": capability_roles,
	}
	count(result) == 0
}
