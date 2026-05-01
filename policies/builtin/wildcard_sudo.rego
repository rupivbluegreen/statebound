# wildcard_sudo.rego
#
# Rule: wildcard_sudo
#
# Wildcard sudo command grants are a privilege-escalation hazard: they let a
# holder run anything as the target user. Any `linux.sudo` authorization
# whose `commands.allow` list contains a wildcard token (`*`, `ALL`, `*:ALL`,
# or any string containing `*`) requires elevated approval.
#
# Phase: submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.wildcard_sudo

import rego.v1

# An allow-string is a wildcard if it matches one of the canonical tokens
# exactly, or if it contains a literal `*` after lowercasing.
is_wildcard_command(cmd) if {
	normalized := lower(trim_space(cmd))
	normalized in {"*", "all", "*:all"}
}

is_wildcard_command(cmd) if {
	contains(lower(trim_space(cmd)), "*")
}

# Walk entitlements and service accounts. Both carry an `authorizations`
# list whose entries may be `linux.sudo`.
relevant_kinds := {"entitlement", "service_account"}

decision contains d if {
	input.phase in {"submit", "approve"}
	some i
	item := input.items[i]
	item.action != "delete"
	item.kind in relevant_kinds

	some j
	authz := item.after.authorizations[j]
	authz.type == "linux.sudo"

	some k
	cmd := authz.commands.allow[k]
	is_wildcard_command(cmd)

	d := {
		"rule_id": "wildcard_sudo",
		"outcome": "escalate_required",
		"message": sprintf(
			"%s '%s' grants wildcard sudo command '%s'; elevated approval required",
			[item.kind, item.resource_name, cmd],
		),
		"severity": "high",
		"metadata": {
			"resource_kind": item.kind,
			"resource_name": item.resource_name,
			"command": cmd,
			"authorization_type": authz.type,
		},
	}
}
