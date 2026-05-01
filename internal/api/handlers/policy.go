package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListPolicyDecisions handles GET /v1/policy-decisions. Storage exposes
// only ListPolicyDecisionsByChangeSet, so change_set_id is required.
// Outcome filtering is applied client-side.
func ListPolicyDecisions(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csID := r.URL.Query().Get("change_set_id")
		if csID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "change_set_id query parameter is required")
			return
		}
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}
		recs, err := deps.Store.ListPolicyDecisionsByChangeSet(r.Context(), domain.ID(csID))
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list decisions: "+err.Error())
			return
		}
		outcomeFilter := r.URL.Query().Get("outcome")
		out := make([]WirePolicyDecision, 0, len(recs))
		for _, rec := range recs {
			if outcomeFilter != "" && rec.Outcome != outcomeFilter {
				continue
			}
			out = append(out, ToPolicyDecision(rec))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetPolicyDecision handles GET /v1/policy-decisions/{id}.
func GetPolicyDecision(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := domain.ID(chi.URLParam(r, "id"))
		if id == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		rec, err := deps.Store.GetPolicyDecisionByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrPolicyDecisionNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "policy decision not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get decision: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ToPolicyDecision(rec))
	}
}
