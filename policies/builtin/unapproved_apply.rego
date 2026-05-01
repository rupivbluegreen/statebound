# unapproved_apply.rego
#
# Rule: unapproved_apply
#
# PLACEHOLDER PACKAGE.
#
# The substantive enforcement of "unapproved versions cannot be applied" lives
# at Plan/Apply time (Phase 4 connectors and beyond), where the connector
# refuses to run unless given an ApprovedVersion id. Submit/approve-time
# evaluation does not gate apply — there is nothing to apply yet.
#
# This package is laid down now so that:
#   * the package name is stable across phases;
#   * future phases can drop in real apply-time logic without renaming;
#   * the aggregator and CI test harness already cover it.
#
# When wired up later this rule will emit outcome "deny" with severity
# "critical" if an apply attempt references a non-approved version.
#
# Phase (today): no-op for both submit and approve.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules" — initial rule list.

package statebound.policies.unapproved_apply

import rego.v1

# Intentionally empty: no decisions are emitted today.
decision contains d if {
	false
	d := {
		"rule_id": "unapproved_apply",
		"outcome": "deny",
		"message": "unapproved versions cannot be applied",
		"severity": "critical",
	}
}
