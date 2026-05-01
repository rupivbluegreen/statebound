# unapproved_apply_test.rego — tests for statebound.policies.unapproved_apply.
#
# The package is a placeholder today, so the only meaningful assertion is
# that it never emits decisions on submit or approve inputs. When apply-time
# enforcement lands in a later phase, additional positive tests will be
# added here.

package statebound.policies.unapproved_apply_test

import rego.v1

import data.statebound.policies.unapproved_apply

test_silent_on_submit if {
	result := unapproved_apply.decision with input as {
		"phase": "submit",
		"items": [],
		"approvals": [],
	}
	count(result) == 0
}

test_silent_on_approve if {
	result := unapproved_apply.decision with input as {
		"phase": "approve",
		"items": [],
		"approvals": [{"decision": "approved", "actor": {"kind": "human", "subject": "bob"}}],
	}
	count(result) == 0
}
