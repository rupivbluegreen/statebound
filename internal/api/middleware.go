// Package api — HTTP middleware.
//
// Phase 8 wave B middleware chain (in order):
//
//	requestIDMiddleware  → stamps a request id; carried through logs + spans
//	otelMiddleware       → opens an "http.request" span per request
//	loggingMiddleware    → structured slog line on completion
//	corsMiddleware       → permissive default; locked down later
//	authMiddleware       → populates Identity from the Authenticator
//	requireCap(cap)      → per-route capability check against Identity.Roles
//
// Public routes (/healthz, /readyz, /openapi.yaml) skip auth + RBAC.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/telemetry"
)

// ctxKey is the package-private context-key type used for everything we
// stash in request context. Using a typed key keeps these out of the
// public request.Context() namespace.
type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyIdentity
)

// requestIDMiddleware stamps a request id on every request. Operators
// can pass X-Request-ID upstream; we honor it (clamped to 128 chars) so
// the value the add-on logged is the same one they see in our slog
// line and in OTel spans.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if len(id) > 128 {
			id = id[:128]
		}
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestIDFromContext returns the request id stamped by
// requestIDMiddleware, or "" if not set (e.g. middleware ordering bug).
func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID).(string)
	return v
}

// otelMiddleware opens an "http.request" span around every request and
// records the response status on it. Attributes mirror the conventions
// used elsewhere in internal/telemetry — operators tracing a CLI run
// alongside an API call see comparable shapes.
func otelMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := telemetry.StartSpan(r.Context(), "http.request",
			attribute.String("http.method", r.Method),
			attribute.String("http.route", r.URL.Path),
		)
		defer span.End()
		if rid := requestIDFromContext(ctx); rid != "" {
			span.SetAttributes(attribute.String("http.request_id", rid))
		}
		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.status_code", sw.status))
		if sw.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(sw.status))
		}
	})
}

// loggingMiddleware emits one structured slog line per request once the
// downstream handler returns. Status, duration, and request id make
// CSV-style log slicing trivial.
func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			logger.LogAttrs(r.Context(), slog.LevelInfo, "http.request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Duration("duration", time.Since(start)),
				slog.String("request_id", requestIDFromContext(r.Context())),
			)
		})
	}
}

// corsMiddleware sets a permissive set of CORS headers. v0.8 ships
// permissive defaults; a follow-up wave locks the allowlist down once
// the add-on's deployment shape is fixed.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware runs the configured Authenticator on every request
// inside its group, stashes the resulting Identity in context, and
// renders any AuthError as the standard Error envelope.
func authMiddleware(authn Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident, err := authn.Authenticate(r)
			if err != nil {
				writeAuthError(w, r, err)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyIdentity, ident)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// identityFromContext returns the Identity populated by authMiddleware,
// or false when missing (which only happens on routes mounted outside
// the auth group — by construction, the gated handlers always have an
// Identity).
func identityFromContext(ctx context.Context) (Identity, bool) {
	v, ok := ctx.Value(ctxKeyIdentity).(Identity)
	return v, ok
}

// requireCapability returns a middleware that ensures the request's
// Identity holds at least one of the roles granting cap. Bootstrap
// behaviour mirrors the CLI: an empty actor_role_bindings table would
// have failed earlier (the auth lookup runs through the same store), so
// here we fail closed — no role => 403.
func requireCapability(cap domain.Capability) func(http.Handler) http.Handler {
	required := domain.RolesForCapability(cap)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident, ok := identityFromContext(r.Context())
			if !ok {
				writeAuthError(w, r, &AuthError{
					Status:  http.StatusUnauthorized,
					Code:    CodeMissingToken,
					Message: "no identity on request",
				})
				return
			}
			if !hasAnyRole(ident.Roles, required) {
				writeAuthError(w, r, &AuthError{
					Status:  http.StatusForbidden,
					Code:    CodeForbidden,
					Message: "actor lacks capability " + string(cap),
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hasAnyRole reports whether held intersects required. Tiny n*m loop is
// fine: both slices have at most a handful of entries.
func hasAnyRole(held, required []domain.Role) bool {
	for _, h := range held {
		for _, r := range required {
			if h == r {
				return true
			}
		}
	}
	return false
}

// writeAuthError renders an AuthError (or any error) as the standard
// JSON Error envelope and writes the configured status code. Non-AuthError
// values are coerced to 500 with code "internal_error".
func writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *AuthError
	status := http.StatusInternalServerError
	code := "internal_error"
	msg := "internal error"
	if errors.As(err, &ae) {
		status = ae.Status
		code = ae.Code
		msg = ae.Message
	}
	writeError(w, r, status, code, msg)
}

// writeError marshals the standard {code, message, request_id} envelope
// and emits status. Used by handlers and middleware alike so the wire
// shape is consistent.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{
		"code":    code,
		"message": message,
	}
	if rid := requestIDFromContext(r.Context()); rid != "" {
		body["request_id"] = rid
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeJSON renders v as JSON with status. The encoder uses the default
// settings: no indent, no HTML-escape; clients (especially the add-on)
// shouldn't depend on cosmetic whitespace.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// statusRecorder is a tiny http.ResponseWriter wrapper that captures the
// status code so middleware can log/trace it without buffering the body.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// newRequestID returns a 16-byte hex request id. crypto/rand panics
// only on a broken kernel rng; we surface that as a sentinel "0..0"
// rather than crash the server.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}
