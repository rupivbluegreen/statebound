package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListPlanApplyRecords handles GET /v1/plan-apply-records. Storage
// exposes only ListPlanApplyRecordsByPlan, so plan_id is required.
//
// This endpoint is read-only by design: an apply execution must always
// be initiated from the CLI in v0.8. The reasoning add-on may inspect
// records but never trigger them.
func ListPlanApplyRecords(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		planID := r.URL.Query().Get("plan_id")
		if planID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "plan_id query parameter is required")
			return
		}
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}
		recs, err := deps.Store.ListPlanApplyRecordsByPlan(r.Context(), domain.ID(planID))
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list apply records: "+err.Error())
			return
		}
		out := make([]WirePlanApplyRecord, 0, len(recs))
		for _, rec := range recs {
			out = append(out, ToPlanApplyRecord(rec))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetPlanApplyRecord handles GET /v1/plan-apply-records/{id}.
func GetPlanApplyRecord(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := domain.ID(chi.URLParam(r, "id"))
		if id == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		rec, err := deps.Store.GetPlanApplyRecordByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrPlanApplyRecordNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "apply record not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get apply record: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ToPlanApplyRecord(rec))
	}
}
