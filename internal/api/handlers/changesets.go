package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListChangeSets handles GET /v1/change-sets. Filters by product_id,
// state, and limit query params.
func ListChangeSets(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}
		filter := storage.ChangeSetFilter{Limit: limit}
		if pid := r.URL.Query().Get("product_id"); pid != "" {
			id := domain.ID(pid)
			filter.ProductID = &id
		}
		if s := r.URL.Query().Get("state"); s != "" {
			if !domain.IsValidChangeSetState(s) {
				deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid state filter")
				return
			}
			st := domain.ChangeSetState(s)
			filter.State = &st
		}
		sets, err := deps.Store.ListChangeSets(r.Context(), filter)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list change sets: "+err.Error())
			return
		}
		out := make([]WireChangeSet, 0, len(sets))
		for _, cs := range sets {
			out = append(out, ToChangeSet(cs))
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// ListChangeSetsForProduct handles GET /v1/products/{id}/change-sets.
// The path parameter binds the product filter.
func ListChangeSetsForProduct(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		productID := domain.ID(chi.URLParam(r, "id"))
		if productID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing product id")
			return
		}
		// Confirm product exists so the response is a 404 instead of an
		// empty list when the id is bogus — this distinguishes "no
		// change sets yet" from "no such product".
		if _, err := deps.Store.GetProductByID(r.Context(), productID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "product not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "lookup product: "+err.Error())
			return
		}
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}
		filter := storage.ChangeSetFilter{ProductID: &productID, Limit: limit}
		if s := r.URL.Query().Get("state"); s != "" {
			if !domain.IsValidChangeSetState(s) {
				deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid state filter")
				return
			}
			st := domain.ChangeSetState(s)
			filter.State = &st
		}
		sets, err := deps.Store.ListChangeSets(r.Context(), filter)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list change sets: "+err.Error())
			return
		}
		out := make([]WireChangeSet, 0, len(sets))
		for _, cs := range sets {
			out = append(out, ToChangeSet(cs))
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetChangeSet handles GET /v1/change-sets/{id}. Returns the change set
// header plus its items.
func GetChangeSet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csID := domain.ID(chi.URLParam(r, "id"))
		if csID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		cs, err := deps.Store.GetChangeSetByID(r.Context(), csID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "change set not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get change set: "+err.Error())
			return
		}
		items, err := deps.Store.ListChangeSetItems(r.Context(), csID)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list items: "+err.Error())
			return
		}
		detail := WireChangeSetDetail{
			WireChangeSet: ToChangeSet(cs),
			Items:         make([]WireChangeSetItem, 0, len(items)),
		}
		for _, it := range items {
			detail.Items = append(detail.Items, ToChangeSetItem(it))
		}
		writeJSON(w, http.StatusOK, detail)
	}
}
