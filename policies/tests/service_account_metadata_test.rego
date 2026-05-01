# service_account_metadata_test.rego — tests for
# statebound.policies.service_account_metadata.

package statebound.policies.service_account_metadata_test

import rego.v1

import data.statebound.policies.service_account_metadata

test_fires_on_missing_owner if {
	result := service_account_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "service_account",
			"resource_name": "payments-batch",
			"after": {
				"name": "payments-batch",
				"purpose": "Runs settlement jobs",
				"usage_pattern": "system-to-system",
			},
		}],
	}
	count(result) == 1
	some d in result
	d.rule_id == "service_account_metadata"
	d.outcome == "deny"
	d.metadata.missing_field == "owner"
}

test_fires_on_multiple_missing_fields if {
	result := service_account_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "service_account",
			"resource_name": "mystery-bot",
			"after": {"name": "mystery-bot"},
		}],
	}
	# owner, purpose, usage_pattern are all missing -> 3 decisions.
	count(result) == 3
}

test_fires_on_empty_string_field if {
	result := service_account_metadata.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "update",
			"kind": "service_account",
			"resource_name": "payments-batch",
			"after": {
				"owner": "",
				"purpose": "Runs settlement jobs",
				"usage_pattern": "system-to-system",
			},
		}],
	}
	count(result) == 1
	some d in result
	d.metadata.missing_field == "owner"
}

test_silent_on_complete_metadata if {
	result := service_account_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "service_account",
			"resource_name": "payments-batch",
			"after": {
				"name": "payments-batch",
				"owner": "payments-team",
				"purpose": "Runs settlement jobs",
				"usage_pattern": "system-to-system",
			},
		}],
	}
	count(result) == 0
}

test_silent_on_delete if {
	result := service_account_metadata.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "delete",
			"kind": "service_account",
			"resource_name": "old-bot",
			"after": null,
		}],
	}
	count(result) == 0
}
