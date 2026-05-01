# service_account_metadata.rego
#
# Rule: service_account_metadata
#
# Every service account must declare an owner, a purpose, and a usage
# pattern. These fields are how auditors trace why a non-human identity
# exists and who is accountable for it. Missing any of these fields is a
# deny: one decision per missing field per resource.
#
# Phase: submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.service_account_metadata

import rego.v1

required_fields := {"owner", "purpose", "usage_pattern"}

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
	item.kind == "service_account"

	some field in required_fields
	is_missing(item.after, field)

	d := {
		"rule_id": "service_account_metadata",
		"outcome": "deny",
		"message": sprintf(
			"service account '%s' is missing required field: %s",
			[item.resource_name, field],
		),
		"severity": "high",
		"metadata": {
			"resource_name": item.resource_name,
			"missing_field": field,
		},
	}
}
