package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListProducts handles GET /v1/products.
func ListProducts(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		products, err := deps.Store.ListProducts(r.Context())
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list products: "+err.Error())
			return
		}
		out := make([]WireProduct, 0, len(products))
		for _, p := range products {
			out = append(out, ToProduct(p))
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetProduct handles GET /v1/products/{id}.
func GetProduct(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := domain.ID(chi.URLParam(r, "id"))
		if id == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		product, err := deps.Store.GetProductByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "product not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get product: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ToProduct(product))
	}
}
