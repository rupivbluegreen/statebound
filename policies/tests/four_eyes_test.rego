# four_eyes_test.rego — tests for statebound.policies.four_eyes.

package statebound.policies.four_eyes_test

import rego.v1

import data.statebound.policies.four_eyes

test_fires_on_self_approval if {
	result := four_eyes.decision with input as {
		"phase": "approve",
		"change_set": {"requested_by": {"kind": "human", "subject": "alice"}},
		"approver": {"kind": "human", "subject": "alice"},
	}
	count(result) == 1
	some d in result
	d.rule_id == "four_eyes_required"
	d.outcome == "deny"
	d.severity == "high"
}

test_silent_when_different_actor if {
	result := four_eyes.decision with input as {
		"phase": "approve",
		"change_set": {"requested_by": {"kind": "human", "subject": "alice"}},
		"approver": {"kind": "human", "subject": "bob"},
	}
	count(result) == 0
}

test_silent_during_submit_phase if {
	result := four_eyes.decision with input as {
		"phase": "submit",
		"change_set": {"requested_by": {"kind": "human", "subject": "alice"}},
		"approver": {"kind": "human", "subject": "alice"},
	}
	count(result) == 0
}
