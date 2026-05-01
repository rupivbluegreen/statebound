# scope_nonempty_prod.rego
#
# Rule: scope_nonempty_prod
#
# A production authorization must target a non-empty asset scope. An empty
# scope on a prod-flagged authorization is almost always a modeling mistake
# that would either grant nothing (best case) or leak across boundaries
# during future graph resolution (worst case). Either way: deny it.
#
# "Production" here is determined heuristically because OPA does not have
# the full graph at evaluation time. We treat an authorization as production
# if either:
#   * its `environment` field is "prod", OR
#   * the surrounding entitlement / service-account context puts it in a
#     prod-named scope (we cannot resolve scope objects in OPA, so we
#     compare against any scope-name-shaped hint we have).
#
# Two surfaces:
#   1. Top-level authorization items.
#   2. Nested authorizations inside entitlement / service-account items.
#
# Phase: submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.scope_nonempty_prod

import rego.v1

is_empty_scope(obj) if {
	not obj.scope
}

is_empty_scope(obj) if {
	obj.scope == ""
}

# Detect prod-ness on the authorization object itself. We accept either an
# explicit `environment == "prod"` flag or a `scope` value that names a
# prod-flavoured scope. The scope-name heuristic only fires when scope is
# present-but-prod-named, which is by definition non-empty — so it cannot
# combine with the empty-scope check on the same record. We still keep both
# clauses so the rule remains stable as the input schema evolves.
is_prod_authz(authz) if {
	authz.environment == "prod"
}

is_prod_authz(authz) if {
	contains(lower(authz.scope), "prod")
}

# --- Top-level authorization items ---

decision contains d if {
	input.phase in {"submit", "approve"}
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind == "authorization"
	is_prod_authz(item.after)
	is_empty_scope(item.after)
	d := build_decision(item.resource_name, item.kind)
}

# --- Nested authorizations on entitlements / service accounts ---

decision contains d if {
	input.phase in {"submit", "approve"}
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind in {"entitlement", "service_account"}

	some j
	authz := item.after.authorizations[j]
	is_prod_authz(authz)
	is_empty_scope(authz)
	d := build_decision(item.resource_name, item.kind)
}

build_decision(name, kind) := {
	"rule_id": "scope_nonempty_prod",
	"outcome": "deny",
	"message": sprintf("production authorization '%s' has empty scope", [name]),
	"severity": "high",
	"metadata": {
		"resource_name": name,
		"resource_kind": kind,
	},
}
