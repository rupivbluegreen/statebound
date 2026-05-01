package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListPlans handles GET /v1/plans. Filters: product_id,
// approved_version_id, connector_name, limit.
//
// Storage exposes two list paths: ListPlansByProduct and
// ListPlansByApprovedVersion. We pick the most-specific one given the
// query parameters and then apply the remaining filters client-side.
// product_id OR approved_version_id is required so callers don't pull
// the entire plans table.
func ListPlans(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		productID := r.URL.Query().Get("product_id")
		avID := r.URL.Query().Get("approved_version_id")
		if productID == "" && avID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "product_id or approved_version_id is required")
			return
		}
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}
		var plans []*domain.Plan
		switch {
		case avID != "":
			plans, err = deps.Store.ListPlansByApprovedVersion(r.Context(), domain.ID(avID))
		case productID != "":
			plans, err = deps.Store.ListPlansByProduct(r.Context(), domain.ID(productID), limit)
		}
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list plans: "+err.Error())
			return
		}
		connFilter := r.URL.Query().Get("connector_name")
		out := make([]WirePlan, 0, len(plans))
		for _, p := range plans {
			if connFilter != "" && p.ConnectorName != connFilter {
				continue
			}
			if productID != "" && string(p.ProductID) != productID {
				continue
			}
			out = append(out, ToPlan(p))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetPlan handles GET /v1/plans/{id}. Returns the plan plus its items.
func GetPlan(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := domain.ID(chi.URLParam(r, "id"))
		if id == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		plan, items, err := deps.Store.GetPlanByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrPlanNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "plan not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get plan: "+err.Error())
			return
		}
		detail := WirePlanDetail{
			WirePlan: ToPlan(plan),
			Items:    make([]WirePlanItem, 0, len(items)),
		}
		for _, it := range items {
			detail.Items = append(detail.Items, ToPlanItem(it))
		}
		writeJSON(w, http.StatusOK, detail)
	}
}
