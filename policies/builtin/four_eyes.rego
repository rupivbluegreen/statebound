# four_eyes.rego
#
# Rule: four_eyes_required
#
# A change set's requester cannot also be its approver. In four-eyes mode
# (the only mode shipped today) the actor on the approval phase must be a
# different identity than the actor who submitted the change set.
#
# Phase: approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.four_eyes

import rego.v1

decision contains d if {
	input.phase == "approve"
	input.change_set.requested_by.kind == input.approver.kind
	input.change_set.requested_by.subject == input.approver.subject
	d := {
		"rule_id": "four_eyes_required",
		"outcome": "deny",
		"message": "requester cannot approve their own change set",
		"severity": "high",
		"metadata": {
			"requested_by": input.change_set.requested_by.subject,
			"approver": input.approver.subject,
		},
	}
}
