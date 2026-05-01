# prod_requires_approval.rego
#
# Rule: prod_requires_approval
#
# Any change set that touches a production resource must carry at least one
# `approved` approval before it can move forward. We err toward escalation:
# absent or non-approving approvals on a prod-touching change set fire this
# rule.
#
# Heuristics for "production-touching":
#   * an asset item with after.environment == "prod"
#   * an authorization item whose after.scope contains "prod"
#   * an entitlement / service-account item where any nested
#     authorization's `scope` contains "prod"
#
# Phase: approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.prod_requires_approval

import rego.v1

# Direct asset case.
touches_prod if {
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind == "asset"
	item.after.environment == "prod"
}

# Top-level authorization item with a prod-flavoured scope.
touches_prod if {
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind == "authorization"
	contains(lower(item.after.scope), "prod")
}

# Top-level authorization item whose own environment field is prod.
touches_prod if {
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind == "authorization"
	item.after.environment == "prod"
}

# Entitlement or service account whose nested authorizations reference prod.
touches_prod if {
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind in {"entitlement", "service_account"}

	some j
	authz := item.after.authorizations[j]
	contains(lower(authz.scope), "prod")
}

# True iff the change set already carries at least one approved approval.
has_approval if {
	some k
	input.approvals[k].decision == "approved"
}

decision contains d if {
	input.phase == "approve"
	touches_prod
	not has_approval
	d := {
		"rule_id": "prod_requires_approval",
		"outcome": "escalate_required",
		"message": "production change requires approved approval before apply",
		"severity": "high",
		"metadata": {"approval_count": count(input.approvals)},
	}
}
