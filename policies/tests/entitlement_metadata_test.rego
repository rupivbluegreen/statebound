# entitlement_metadata_test.rego — tests for
# statebound.policies.entitlement_metadata.

package statebound.policies.entitlement_metadata_test

import rego.v1

import data.statebound.policies.entitlement_metadata

test_fires_on_missing_owner if {
	result := entitlement_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-readonly",
			"after": {
				"name": "payments-prod-readonly",
				"purpose": "Read-only prod troubleshooting",
			},
		}],
	}
	count(result) == 1
	some d in result
	d.rule_id == "entitlement_metadata"
	d.outcome == "deny"
	d.metadata.missing_field == "owner"
}

test_fires_on_missing_purpose if {
	result := entitlement_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-readonly",
			"after": {
				"name": "payments-prod-readonly",
				"owner": "payments-team",
			},
		}],
	}
	count(result) == 1
	some d in result
	d.metadata.missing_field == "purpose"
}

test_fires_on_both_missing if {
	result := entitlement_metadata.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "anonymous",
			"after": {"name": "anonymous"},
		}],
	}
	count(result) == 2
}

test_silent_on_complete_metadata if {
	result := entitlement_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-readonly",
			"after": {
				"name": "payments-prod-readonly",
				"owner": "payments-team",
				"purpose": "Read-only prod troubleshooting",
			},
		}],
	}
	count(result) == 0
}

test_silent_on_non_entitlement if {
	result := entitlement_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "asset",
			"resource_name": "pay-linux-01",
			"after": {"name": "pay-linux-01"},
		}],
	}
	count(result) == 0
}
