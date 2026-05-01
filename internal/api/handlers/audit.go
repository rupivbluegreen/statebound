package handlers

import (
	"net/http"
	"time"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListAuditEvents handles GET /v1/audit-events. Supported filters:
// kind, resource_type, resource_id, since (RFC3339), limit.
//
// The since filter is applied client-side after the storage list because
// the existing storage AuditFilter shape doesn't carry a time bound;
// the wave-B API can live with that until a follow-up wave widens the
// filter. limit caps the response after the time filter so a tight
// `since` doesn't silently cut a page short.
func ListAuditEvents(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}

		filter := storage.AuditFilter{
			ResourceType: r.URL.Query().Get("resource_type"),
			ResourceID:   r.URL.Query().Get("resource_id"),
			Limit:        0, // we'll cap manually after the since filter
		}
		if k := r.URL.Query().Get("kind"); k != "" {
			filter.Kind = domain.EventKind(k)
		}

		var since *time.Time
		if s := r.URL.Query().Get("since"); s != "" {
			t, perr := time.Parse(time.RFC3339, s)
			if perr != nil {
				deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid since (want RFC3339)")
				return
			}
			tt := t.UTC()
			since = &tt
		}

		events, err := deps.Store.ListAuditEvents(r.Context(), filter)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list audit events: "+err.Error())
			return
		}

		out := make([]WireAuditEvent, 0, len(events))
		for _, e := range events {
			if since != nil && e.OccurredAt.Before(*since) {
				continue
			}
			out = append(out, ToAuditEvent(e))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// VerifyAuditChain handles GET /v1/audit-events/verify. The wave-B
// implementation walks audit_events in occurred_at order and checks
// that each row's prev_hash matches the previous row's hash. The full
// SHA-256 recomputation lives in the CLI (which has direct pgxpool
// access for the audit_event_hash() SQL function); the API version
// reports the lighter "chain link" check so an add-on can spot tamper
// without re-implementing the SQL function client-side.
type VerifyResult struct {
	OK            bool   `json:"ok"`
	Count         int    `json:"count"`
	FirstMismatch string `json:"first_mismatch,omitempty"`
}

// VerifyAuditChain handles GET /v1/audit-events/verify.
func VerifyAuditChain(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events, err := deps.Store.ListAuditEvents(r.Context(), storage.AuditFilter{})
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list audit events: "+err.Error())
			return
		}
		// ListAuditEvents returns newest first; reverse for chain walk.
		ordered := make([]*domain.AuditEvent, len(events))
		for i, e := range events {
			ordered[len(events)-1-i] = e
		}
		prev := ""
		mismatch := ""
		for _, e := range ordered {
			if e.PrevHash != prev {
				mismatch = string(e.ID)
				break
			}
			prev = e.Hash
		}
		res := VerifyResult{
			OK:            mismatch == "",
			Count:         len(ordered),
			FirstMismatch: mismatch,
		}
		writeJSON(w, http.StatusOK, res)
	}
}
