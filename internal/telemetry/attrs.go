package telemetry

import "go.opentelemetry.io/otel/attribute"

// Common low-cardinality span attribute keys used across the CLI hot
// paths. All keys carry the "statebound." prefix so they are easy to
// filter in the upstream collector and do not collide with the
// semantic-convention keys the SDK populates automatically.
//
// IMPORTANT: keep these LOW-CARDINALITY when used as attributes on
// spans that may also feed metrics. UUIDs are fine here as span
// attributes (they are searchable in trace UIs) but must not become
// metric labels — when wave C adds Prometheus metrics, switch to
// enumerated labels for anything per-request.
const (
	// AttrConnector is the connector name (e.g. "linux-sudo",
	// "postgres"). Low cardinality.
	AttrConnector = attribute.Key("statebound.connector")

	// AttrConnectorVersion is the connector module version. Low
	// cardinality (one per release).
	AttrConnectorVersion = attribute.Key("statebound.connector_version")

	// AttrProductName is the user-visible product name (e.g.
	// "payments-api"). Low to medium cardinality.
	AttrProductName = attribute.Key("statebound.product")

	// AttrProductID is the internal product UUID. High cardinality —
	// span only, never a metric label.
	AttrProductID = attribute.Key("statebound.product_id")

	// AttrApprovedVersion is the approved-version sequence number for
	// the product. Low cardinality per product.
	AttrApprovedVersion = attribute.Key("statebound.approved_version")

	// AttrChangeSetID is the ChangeSet UUID. High cardinality — span
	// only.
	AttrChangeSetID = attribute.Key("statebound.change_set_id")

	// AttrPlanID is the Plan UUID. High cardinality — span only.
	AttrPlanID = attribute.Key("statebound.plan_id")

	// AttrApplyID is the PlanApplyRecord UUID. High cardinality.
	AttrApplyID = attribute.Key("statebound.apply_id")

	// AttrDriftScanID is the DriftScan UUID. High cardinality.
	AttrDriftScanID = attribute.Key("statebound.drift_scan_id")

	// AttrPolicyOutcome is the OPA outcome (allow / deny /
	// escalate_required). Low cardinality.
	AttrPolicyOutcome = attribute.Key("statebound.policy_outcome")

	// AttrPolicyPhase is the OPA evaluation phase (submit / approve /
	// plan / apply). Low cardinality.
	AttrPolicyPhase = attribute.Key("statebound.policy_phase")

	// AttrEvidencePackID is the EvidencePack UUID. High cardinality.
	AttrEvidencePackID = attribute.Key("statebound.evidence_pack_id")

	// AttrPlanContentHash is the SHA-256 of the canonical plan
	// content. Useful for joining trace and audit. High cardinality.
	AttrPlanContentHash = attribute.Key("statebound.plan_content_hash")

	// AttrEvidenceContentHash is the SHA-256 of the evidence pack
	// bytes. High cardinality.
	AttrEvidenceContentHash = attribute.Key("statebound.evidence_content_hash")

	// AttrApplyDryRun is true when the apply was preview-only.
	AttrApplyDryRun = attribute.Key("statebound.apply_dry_run")

	// AttrEvidenceFormat is the evidence pack format ("json" or
	// "markdown"). Low cardinality.
	AttrEvidenceFormat = attribute.Key("statebound.evidence_format")

	// AttrSourceRef is the connector source reference (e.g. a sudoers
	// fragment path). Low cardinality per environment.
	AttrSourceRef = attribute.Key("statebound.source_ref")

	// AttrFindingCount is the number of findings produced by a drift
	// scan. Low cardinality (small integer).
	AttrFindingCount = attribute.Key("statebound.finding_count")

	// AttrItemCount is the number of items in a plan or change set.
	// Low cardinality.
	AttrItemCount = attribute.Key("statebound.item_count")

	// AttrActorKind is "human" or "system". Opt-in via
	// STATEBOUND_OTEL_INCLUDE_ACTOR=true (off by default since actor
	// subjects can be PII).
	AttrActorKind = attribute.Key("statebound.actor_kind")

	// AttrActorSubject is the actor's subject identifier. Opt-in only.
	AttrActorSubject = attribute.Key("statebound.actor_subject")
)
