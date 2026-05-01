// Package handlers contains the per-resource HTTP handlers for the
// Statebound HTTP API (Phase 8 wave B).
//
// Each handler is a func(deps Deps) http.HandlerFunc factory. The Deps
// struct carries shared state (storage handle, logger, response helpers)
// so the handlers don't reach back into the api package's globals. This
// keeps the package import graph clean (api → handlers, never the other
// way) and makes the handlers easy to test with a fake storage stub.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"statebound.dev/statebound/internal/storage"
)

// Deps bundles every external dependency the handlers need. Construction
// happens once in api.Server; the same instance is shared across all
// handler factories.
type Deps struct {
	Store  storage.Storage
	Logger *slog.Logger
	// WriteError renders the standard {code, message, request_id}
	// envelope. The api package owns the request-id extraction so we
	// take the helper as a function value.
	WriteError func(w http.ResponseWriter, r *http.Request, status int, code, message string)
}

// writeJSON marshals v as JSON with status. Encoder uses default settings
// (no indent, no HTML escape) so wire output is compact and stable.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// parseLimit reads the "limit" query parameter, defaulting to 100 when
// absent and clamping to [0, 1000]. A negative or unparseable value
// returns an error so the caller can render a 400.
func parseLimit(r *http.Request) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return 100, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		n = 0
	}
	if n > 1000 {
		n = 1000
	}
	return n, nil
}
