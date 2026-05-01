# wildcard_sudo_test.rego — tests for statebound.policies.wildcard_sudo.

package statebound.policies.wildcard_sudo_test

import rego.v1

import data.statebound.policies.wildcard_sudo

test_fires_on_literal_star if {
	result := wildcard_sudo.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-admin",
			"after": {
				"name": "payments-prod-admin",
				"owner": "platform",
				"purpose": "admin",
				"authorizations": [{
					"type": "linux.sudo",
					"scope": "prod-linux",
					"as_user": "root",
					"commands": {"allow": ["*"]},
				}],
			},
		}],
	}
	count(result) >= 1
	some d in result
	d.rule_id == "wildcard_sudo"
	d.outcome == "escalate_required"
}

test_fires_on_all_keyword if {
	result := wildcard_sudo.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "service_account",
			"resource_name": "payments-batch",
			"after": {
				"authorizations": [{
					"type": "linux.sudo",
					"commands": {"allow": ["ALL"]},
				}],
			},
		}],
	}
	count(result) >= 1
	some d in result
	d.rule_id == "wildcard_sudo"
}

test_fires_on_partial_wildcard if {
	result := wildcard_sudo.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "ops-tools",
			"after": {
				"authorizations": [{
					"type": "linux.sudo",
					"commands": {"allow": ["/usr/bin/*"]},
				}],
			},
		}],
	}
	count(result) >= 1
}

test_silent_on_explicit_command_list if {
	result := wildcard_sudo.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "entitlement",
			"resource_name": "payments-prod-readonly",
			"after": {
				"authorizations": [{
					"type": "linux.sudo",
					"commands": {"allow": [
						"/usr/bin/systemctl status payments",
						"/usr/bin/journalctl -u payments --since today",
					]},
				}],
			},
		}],
	}
	count(result) == 0
}

test_silent_on_delete_action if {
	result := wildcard_sudo.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "delete",
			"kind": "entitlement",
			"resource_name": "old-admin",
			"after": null,
		}],
	}
	count(result) == 0
}
