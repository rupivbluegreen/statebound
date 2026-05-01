# root_equiv_test.rego — tests for statebound.policies.root_equiv.

package statebound.policies.root_equiv_test

import rego.v1

import data.statebound.policies.root_equiv

test_fires_on_root_user if {
	result := root_equiv.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-admin",
			"after": {
				"authorizations": [{
					"type": "linux.sudo",
					"as_user": "root",
					"commands": {"allow": ["/usr/bin/systemctl restart payments"]},
				}],
			},
		}],
	}
	count(result) == 1
	some d in result
	d.rule_id == "root_equiv"
	d.outcome == "escalate_required"
	d.severity == "high"
}

test_fires_on_service_account_root if {
	result := root_equiv.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "service_account",
			"resource_name": "deploy-bot",
			"after": {
				"authorizations": [{
					"type": "linux.sudo",
					"as_user": "root",
				}],
			},
		}],
	}
	count(result) == 1
}

test_silent_on_non_root_user if {
	result := root_equiv.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-readonly",
			"after": {
				"authorizations": [{
					"type": "linux.sudo",
					"as_user": "payments-runtime",
				}],
			},
		}],
	}
	count(result) == 0
}

test_silent_on_uppercase_root if {
	# Spec says case-sensitive: only literal "root" counts.
	result := root_equiv.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "weird",
			"after": {"authorizations": [{"type": "linux.sudo", "as_user": "ROOT"}]},
		}],
	}
	count(result) == 0
}
