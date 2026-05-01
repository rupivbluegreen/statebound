# entitlement_metadata.rego
#
# Rule: entitlement_metadata
#
# Every entitlement must declare an owner and a purpose. These are the
# minimum metadata an auditor needs to understand why an access package
# exists. Missing either field is a deny: one decision per missing field
# per resource.
#
# Phase: submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.entitlement_metadata

import rego.v1

required_fields := {"owner", "purpose"}

is_missing(obj, field) if {
	not obj[field]
}

is_missing(obj, field) if {
	obj[field] == ""
}

decision contains d if {
	input.phase in {"submit", "approve"}
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind == "entitlement"

	some field in required_fields
	is_missing(item.after, field)

	d := {
		"rule_id": "entitlement_metadata",
		"outcome": "deny",
		"message": sprintf(
			"entitlement '%s' is missing required field: %s",
			[item.resource_name, field],
		),
		"severity": "high",
		"metadata": {
			"resource_name": item.resource_name,
			"missing_field": field,
		},
	}
}
