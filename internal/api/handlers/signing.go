package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/storage"
)

// ListSigningKeys handles GET /v1/signing-keys. The `include_disabled`
// query parameter (default false) toggles whether disabled / expired
// keys appear.
//
// IMPORTANT: only public material (public_key bytes, fingerprint,
// lifecycle metadata) is returned. The encoder drops PrivateKey and
// PrivateKeyRef so a future handler change cannot leak them.
func ListSigningKeys(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		includeDisabled := false
		if v := r.URL.Query().Get("include_disabled"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "invalid include_disabled (want bool)")
				return
			}
			includeDisabled = b
		}
		keys, err := deps.Store.ListSigningKeys(r.Context(), !includeDisabled)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list signing keys: "+err.Error())
			return
		}
		out := make([]WireSigningKey, 0, len(keys))
		for _, k := range keys {
			out = append(out, ToSigningKey(k))
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetSigningKey handles GET /v1/signing-keys/{key_id}.
func GetSigningKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keyID := chi.URLParam(r, "key_id")
		if keyID == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing key_id")
			return
		}
		k, err := deps.Store.GetSigningKey(r.Context(), keyID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrSigningKeyNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "signing key not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get signing key: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, ToSigningKey(k))
	}
}
