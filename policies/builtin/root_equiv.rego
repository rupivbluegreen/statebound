# root_equiv.rego
#
# Rule: root_equiv
#
# Any authorization that grants action as the literal `root` user is
# root-equivalent and must be approved at an elevated tier. This applies
# to entitlements and service accounts alike — agents and humans alike.
#
# Phase: submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.root_equiv

import rego.v1

relevant_kinds := {"entitlement", "service_account"}

decision contains d if {
	input.phase in {"submit", "approve"}
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind in relevant_kinds

	some j
	authz := item.after.authorizations[j]
	authz.as_user == "root"

	d := {
		"rule_id": "root_equiv",
		"outcome": "escalate_required",
		"message": sprintf(
			"%s '%s' grants root-equivalent access via %s",
			[item.kind, item.resource_name, authz.type],
		),
		"severity": "high",
		"metadata": {
			"resource_kind": item.kind,
			"resource_name": item.resource_name,
			"authorization_type": authz.type,
		},
	}
}
