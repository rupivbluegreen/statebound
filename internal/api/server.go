// Package api — HTTP server (Phase 8 wave B).
//
// server.go constructs the chi router, wires the middleware chain, and
// mounts the handler functions from the handlers/ subpackage. The
// public surface is intentionally minimal:
//
//	srv, err := api.New(cfg, store)
//	if err != nil { ... }
//	if err := srv.Start(ctx); err != nil { ... }
//
// Start blocks until ctx is cancelled. Shutdown is bound to context
// cancellation so an upstream signal handler can do a graceful drain.
package api

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"statebound.dev/statebound/internal/api/handlers"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// openapiSpec embeds the OpenAPI 3.1 YAML so /openapi.yaml can serve it
// without depending on the operator's working directory.
//
// The canonical spec lives at <repo>/schemas/openapi.yaml. CI and the
// Makefile copy it into this directory before `go build` so the embed
// directive picks it up. Keep both copies in sync — `make sync-openapi`
// (and the equivalent step in CI) regenerate the embedded copy.
//
//go:embed openapi.yaml
var openapiSpec embed.FS

// Config bundles the server's tunables. Listen and at least one of
// (OIDCIssuer, DevToken) are required; everything else has sensible
// defaults filled in by New.
type Config struct {
	Listen       string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	OIDCIssuer   string
	OIDCAudience string
	DevToken     string
	StaticActor  string
	Logger       *slog.Logger
}

// Server is a configured, not-yet-started HTTP server.
type Server struct {
	cfg   Config
	store storage.Storage
	auth  Authenticator
	http  *http.Server
}

// New constructs a Server. It selects an Authenticator based on the
// config (OIDC if Issuer set, dev otherwise) and rejects an
// unauthenticated configuration outright.
func New(ctx context.Context, cfg Config, store storage.Storage) (*Server, error) {
	if store == nil {
		return nil, errors.New("api: storage handle is required")
	}
	if cfg.Listen == "" {
		return nil, errors.New("api: --listen address is required")
	}
	if cfg.OIDCIssuer == "" && cfg.DevToken == "" {
		return nil, errors.New("api: either --oidc-issuer or --dev-token must be set; refusing to start unauthenticated")
	}
	cfg = applyDefaults(cfg)

	var authn Authenticator
	switch {
	case cfg.OIDCIssuer != "":
		oidcAuth, err := NewOIDCAuthenticator(ctx, cfg.OIDCIssuer, cfg.OIDCAudience, store)
		if err != nil {
			return nil, err
		}
		authn = oidcAuth
	case cfg.DevToken != "":
		devAuth, err := NewDevAuthenticator(cfg.DevToken, cfg.StaticActor, store)
		if err != nil {
			return nil, err
		}
		authn = devAuth
	}

	srv := &Server{
		cfg:   cfg,
		store: store,
		auth:  authn,
	}
	srv.http = &http.Server{
		Addr:         cfg.Listen,
		Handler:      srv.buildRouter(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
	return srv, nil
}

// applyDefaults fills zero-value fields on cfg. Pure function so callers
// can pass a Config and trust the result.
func applyDefaults(cfg Config) Config {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 15 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 120 * time.Second
	}
	if cfg.StaticActor == "" {
		cfg.StaticActor = "human:dev"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return cfg
}

// Start binds the configured listen address and serves until the
// context is cancelled. Shutdown is graceful: in-flight requests
// complete (subject to the configured timeouts) before Start returns.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.cfg.Logger.LogAttrs(ctx, slog.LevelInfo, "api.serving",
			slog.String("listen", s.cfg.Listen),
		)
		err := s.http.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			errCh <- nil
			return
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown(context.Background())
	case err := <-errCh:
		return err
	}
}

// Shutdown drains in-flight requests within ctx's deadline. Callers
// should pass a context with a sensible timeout (e.g. 30s) to bound
// shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.http == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.http.Shutdown(shutdownCtx)
}

// buildRouter wires the chi router with the middleware chain and
// mounts every route.
func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()

	// Order matters: requestID before otel before logging so the
	// request id appears on every span attribute and slog line.
	r.Use(requestIDMiddleware)
	r.Use(otelMiddleware)
	r.Use(loggingMiddleware(s.cfg.Logger))
	r.Use(corsMiddleware)

	// Public routes (no auth).
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/openapi.yaml", s.handleOpenAPI)

	// Authenticated routes.
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware(s.auth))
		// Every read endpoint in v0.8 is gated by product:read so the
		// most-permissive role (viewer) is sufficient. Future write
		// surfaces will introduce per-route capability requirements.
		r.Use(requireCapability(domain.CapabilityProductRead))

		deps := handlers.Deps{
			Store:  s.store,
			Logger: s.cfg.Logger,
			WriteError: func(w http.ResponseWriter, req *http.Request, status int, code, message string) {
				writeError(w, req, status, code, message)
			},
		}

		r.Get("/v1/products", handlers.ListProducts(deps))
		r.Get("/v1/products/{id}", handlers.GetProduct(deps))
		r.Get("/v1/products/{id}/change-sets", handlers.ListChangeSetsForProduct(deps))

		r.Get("/v1/change-sets", handlers.ListChangeSets(deps))
		r.Get("/v1/change-sets/{id}", handlers.GetChangeSet(deps))

		r.Get("/v1/audit-events", handlers.ListAuditEvents(deps))
		r.Get("/v1/audit-events/verify", handlers.VerifyAuditChain(deps))

		r.Get("/v1/evidence-packs", handlers.ListEvidencePacks(deps))
		r.Get("/v1/evidence-packs/{id}", handlers.GetEvidencePack(deps))

		r.Get("/v1/plans", handlers.ListPlans(deps))
		r.Get("/v1/plans/{id}", handlers.GetPlan(deps))

		r.Get("/v1/drift-scans", handlers.ListDriftScans(deps))
		r.Get("/v1/drift-scans/{id}", handlers.GetDriftScan(deps))

		r.Get("/v1/policy-decisions", handlers.ListPolicyDecisions(deps))
		r.Get("/v1/policy-decisions/{id}", handlers.GetPolicyDecision(deps))

		r.Get("/v1/signing-keys", handlers.ListSigningKeys(deps))
		r.Get("/v1/signing-keys/{key_id}", handlers.GetSigningKey(deps))

		r.Get("/v1/plan-apply-records", handlers.ListPlanApplyRecords(deps))
		r.Get("/v1/plan-apply-records/{id}", handlers.GetPlanApplyRecord(deps))
	})

	return r
}

// handleHealthz returns 200 OK unconditionally. Liveness only — does
// not touch the database (use /readyz for that).
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "ok")
}

// handleReadyz pings the storage layer. If the ping succeeds we return
// 200; otherwise 503 with a generic body. The error is logged but not
// reflected in the response body (operators can chase logs for the
// underlying cause).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		s.cfg.Logger.LogAttrs(r.Context(), slog.LevelError, "api.readyz_ping_failed",
			slog.String("error", err.Error()),
		)
		writeError(w, r, http.StatusServiceUnavailable, "not_ready", "storage not ready")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "ready")
}

// handleOpenAPI serves the embedded OpenAPI 3.1 YAML. ETag is the
// embedded file's stat-derived hash so repeat callers can cache.
func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	data, err := fs.ReadFile(openapiSpec, "openapi.yaml")
	if err != nil {
		http.Error(w, "openapi spec not embedded", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(data)
}
