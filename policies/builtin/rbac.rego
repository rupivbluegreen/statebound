# rbac.rego
#
# Rule: rbac_role_required
#
# RBAC pre-check: the actor performing this lifecycle action must hold a
# role granting the action's required capability. The Go side
# (internal/cli.requireCapability) performs the same check before the
# tx opens; this Rego rule is the OPA-side belt for the suspenders so
# the policy decision log has a stable record of the gate result for
# every submit/approve evaluation, even when the CLI pre-check passed.
#
# The rule is deliberately generic: input.capability_roles is the
# (capability -> []role) mapping the CLI sends verbatim from
# domain.CapabilityRolesMap(). input.required_capability names the
# action; input.actor_roles is the actor's currently active role set.
#
# A required_capability of "" means "RBAC not engaged for this
# evaluation" — the rule bails. A required_capability with no entry in
# capability_roles is also a no-op so an unknown cap does not produce
# a noisy false-positive (the CLI pre-check is the authoritative gate;
# the absence of a mapping is already deny-by-default there).
#
# Phase: submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules".

package statebound.policies.rbac

import rego.v1

decision contains d if {
	input.phase in {"submit", "approve"}
	cap := input.required_capability
	cap != ""
	required := input.capability_roles[cap]
	count(required) > 0

	# The actor's role set must intersect required. We express it as
	# "no required role appears in actor_roles" -> deny.
	actor_roles := actor_role_set
	not has_required_role(required, actor_roles)

	d := {
		"rule_id": "rbac_role_required",
		"outcome": "deny",
		"message": sprintf(
			"actor %s:%s lacks capability %s; required one of %v, holds %v",
			[input.actor.kind, input.actor.subject, cap, required, input.actor_roles],
		),
		"severity": "high",
		"metadata": {
			"actor_kind": input.actor.kind,
			"actor_subject": input.actor.subject,
			"capability": cap,
			"required_roles": required,
			"actor_roles": input.actor_roles,
		},
	}
}

# actor_role_set converts input.actor_roles ([]string) into a Rego set
# for membership tests. Defaults to the empty set when the field is
# absent or empty, so the rule still fires (deny) on a missing actor.
actor_role_set := {r | some r in input.actor_roles}

# has_required_role is true when actor_roles contains at least one role
# from the required list.
has_required_role(required, actor_roles) if {
	some r in required
	r in actor_roles
}
