# prod_requires_approval_test.rego — tests for
# statebound.policies.prod_requires_approval.

package statebound.policies.prod_requires_approval_test

import rego.v1

import data.statebound.policies.prod_requires_approval

test_fires_when_prod_asset_unapproved if {
	result := prod_requires_approval.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "asset",
			"resource_name": "pay-linux-01",
			"after": {"environment": "prod", "type": "linux-host"},
		}],
		"approvals": [],
	}
	count(result) == 1
	some d in result
	d.rule_id == "prod_requires_approval"
	d.outcome == "escalate_required"
}

test_fires_when_entitlement_has_prod_scope_unapproved if {
	result := prod_requires_approval.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-readonly",
			"after": {
				"authorizations": [{
					"type": "linux.ssh",
					"scope": "prod-linux",
				}],
			},
		}],
		"approvals": [],
	}
	count(result) == 1
}

test_silent_when_prod_change_has_approval if {
	result := prod_requires_approval.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "asset",
			"resource_name": "pay-linux-01",
			"after": {"environment": "prod"},
		}],
		"approvals": [{
			"decision": "approved",
			"actor": {"kind": "human", "subject": "bob"},
		}],
	}
	count(result) == 0
}

test_silent_when_no_prod_resources if {
	result := prod_requires_approval.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "asset",
			"resource_name": "dev-linux-01",
			"after": {"environment": "dev"},
		}],
		"approvals": [],
	}
	count(result) == 0
}

test_silent_during_submit_phase if {
	result := prod_requires_approval.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "asset",
			"resource_name": "pay-linux-01",
			"after": {"environment": "prod"},
		}],
		"approvals": [],
	}
	count(result) == 0
}
