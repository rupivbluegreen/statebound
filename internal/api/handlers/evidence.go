package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListEvidencePacks handles GET /v1/evidence-packs. Filters: product_id
// (required for non-admin pagination paths), format, limit.
//
// The storage interface only exposes ListEvidencePacksByProduct, so the
// product_id query parameter is required for now. A future wave can add
// a global list once the underlying index supports it.
func ListEvidencePacks(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		productID := r.URL.Query().Get("product_id")
		if productID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "product_id query parameter is required")
			return
		}
		limit, err := parseLimit(r)
		if err != nil {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid limit")
			return
		}
		packs, err := deps.Store.ListEvidencePacksByProduct(r.Context(), domain.ID(productID), limit)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list evidence: "+err.Error())
			return
		}
		formatFilter := r.URL.Query().Get("format")
		out := make([]WireEvidencePack, 0, len(packs))
		for _, p := range packs {
			if formatFilter != "" && p.Format != formatFilter {
				continue
			}
			out = append(out, ToEvidencePack(p))
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetEvidencePack handles GET /v1/evidence-packs/{id}. Includes the raw
// canonical content bytes inline.
func GetEvidencePack(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := domain.ID(chi.URLParam(r, "id"))
		if id == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		pack, err := deps.Store.GetEvidencePackByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrEvidencePackNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "evidence pack not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get evidence: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ToEvidencePackWithContent(pack))
	}
}
