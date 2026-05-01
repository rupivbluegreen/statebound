# scope_nonempty_prod_test.rego — tests for
# statebound.policies.scope_nonempty_prod.

package statebound.policies.scope_nonempty_prod_test

import rego.v1

import data.statebound.policies.scope_nonempty_prod

test_fires_on_top_level_authz_with_prod_env_and_empty_scope if {
	result := scope_nonempty_prod.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "authorization",
			"resource_name": "ssh-anywhere",
			"after": {
				"environment": "prod",
				"type": "linux.ssh",
			},
		}],
	}
	count(result) == 1
	some d in result
	d.rule_id == "scope_nonempty_prod"
	d.outcome == "deny"
}

test_fires_on_top_level_authz_with_empty_string_scope if {
	result := scope_nonempty_prod.decision with input as {
		"phase": "approve",
		"items": [{
			"action": "add",
			"kind": "authorization",
			"resource_name": "ssh-anywhere",
			"after": {
				"environment": "prod",
				"type": "linux.ssh",
				"scope": "",
			},
		}],
	}
	count(result) == 1
}

test_silent_when_scope_is_set if {
	result := scope_nonempty_prod.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "authorization",
			"resource_name": "ssh-prod",
			"after": {
				"environment": "prod",
				"type": "linux.ssh",
				"scope": "prod-linux",
			},
		}],
	}
	count(result) == 0
}

test_silent_for_non_prod_authz if {
	result := scope_nonempty_prod.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "add",
			"kind": "authorization",
			"resource_name": "ssh-dev",
			"after": {
				"environment": "dev",
				"type": "linux.ssh",
				"scope": "",
			},
		}],
	}
	count(result) == 0
}

test_silent_on_delete if {
	result := scope_nonempty_prod.decision with input as {
		"phase": "submit",
		"items": [{
			"action": "delete",
			"kind": "authorization",
			"resource_name": "old-thing",
			"after": null,
		}],
	}
	count(result) == 0
}
