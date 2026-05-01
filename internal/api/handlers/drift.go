package handlers

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ListDriftScans handles GET /v1/drift-scans. product_id is required;
// approved_version_id and connector_name filter the result client-side.
func ListDriftScans(deps Deps) http.HandlerFunc {
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
		scans, err := deps.Store.ListDriftScansByProduct(r.Context(), domain.ID(productID), limit)
		if err != nil {
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "list drift scans: "+err.Error())
			return
		}
		avFilter := r.URL.Query().Get("approved_version_id")
		connFilter := r.URL.Query().Get("connector_name")
		out := make([]WireDriftScan, 0, len(scans))
		for _, s := range scans {
			if avFilter != "" && string(s.ApprovedVersionID) != avFilter {
				continue
			}
			if connFilter != "" && s.ConnectorName != connFilter {
				continue
			}
			out = append(out, ToDriftScan(s))
		}
		writeJSON(w, http.StatusOK, PageOf(out))
	}
}

// GetDriftScan handles GET /v1/drift-scans/{id}. Returns the scan plus
// its findings.
func GetDriftScan(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := domain.ID(chi.URLParam(r, "id"))
		if id == "" {
			deps.WriteError(w, r, http.StatusBadRequest, "invalid_argument", "missing id")
			return
		}
		scan, findings, err := deps.Store.GetDriftScanByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, storage.ErrDriftScanNotFound) {
				deps.WriteError(w, r, http.StatusNotFound, "not_found", "drift scan not found")
				return
			}
			deps.WriteError(w, r, http.StatusInternalServerError, "internal_error", "get drift scan: "+err.Error())
			return
		}
		detail := WireDriftScanDetail{
			WireDriftScan: ToDriftScan(scan),
			Findings:      make([]WireDriftFinding, 0, len(findings)),
		}
		for _, f := range findings {
			detail.Findings = append(detail.Findings, ToDriftFinding(f))
		}
		writeJSON(w, http.StatusOK, detail)
	}
}
