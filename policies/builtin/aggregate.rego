# aggregate.rego
#
# Aggregator package for the Statebound built-in Rego rule library.
#
# This package walks every rule package under data.statebound.policies.* and
# unions every emitted decision into a single set. The Decision Plane queries
# this `decisions` set when evaluating a ChangeSet so it gets a consolidated
# view of every fired rule across the entire library.
#
# Spec reference: CLAUDE.md §15 "Policy and risk rules".

package statebound.aggregate

import rego.v1

decisions contains d if {
	some pkg
	d := data.statebound.policies[pkg].decision[_]
}
