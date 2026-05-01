// Package api implements the Statebound HTTP API server (Phase 8 wave B).
//
// The API exposes the core's read surface so the optional
// `statebound-reason` add-on (and other ServiceAccount clients) can
// consume it. It is deliberately read-only in v0.8: write operations
// (approve, plan, apply) remain CLI-only — the reasoning add-on never
// mutates approved state.
//
// auth.go defines the Authenticator boundary and ships two
// implementations:
//
//   - DevAuthenticator: matches a static bearer token against a
//     configured value. Used for local development and CI smoke. The
//     mapped Actor is parsed from a `kind:subject` string supplied at
//     server construction.
//   - OIDCAuthenticator: validates JWT bearer tokens against an OIDC
//     issuer's discovered JWKS, then resolves the token's `sub` claim
//     against actor_role_bindings. Used in production.
//
// Both implementations return the same Identity shape so the rest of
// the server (rbacMiddleware in particular) does not branch on auth
// kind. AuthError carries an HTTP status + machine-readable code so
// the error response layer can render the standard Error envelope.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// Identity is the result of a successful Authenticate call. Actor is
// the resolved domain Actor (kind+subject); Roles is the active role
// set for that actor at request time. rbacMiddleware reads Roles to
// gate per-route capability checks.
type Identity struct {
	Actor domain.Actor
	Roles []domain.Role
}

// AuthError describes a structured authentication or authorization
// failure. Code is a stable, machine-readable identifier for the failure
// kind; Message is the human-friendly string the API returns to clients.
//
// Status is the HTTP status the response handler should emit (401 for
// authentication failures, 403 for authorization failures). The error
// renderer in middleware.go reads all three fields when shaping the
// response.
type AuthError struct {
	Status  int
	Code    string
	Message string
}

func (e *AuthError) Error() string { return e.Message }

// Common AuthError codes used by both authenticators and the rbac
// middleware. The set is intentionally small and stable — clients
// (notably the reasoning add-on) branch on Code, not Message.
const (
	CodeMissingToken = "missing_token"
	CodeInvalidToken = "invalid_token"
	CodeForbidden    = "forbidden"
)

// Authenticator extracts an Identity from an HTTP request. Implementations
// MUST NOT touch the response — they only inspect the request and either
// return a populated Identity or an *AuthError. The auth middleware
// renders the response.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// extractBearer pulls the bearer token from Authorization. Returns an
// AuthError when the header is missing or malformed; the caller
// (the concrete authenticator) propagates it unchanged.
func extractBearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeMissingToken,
			Message: "Authorization header is required",
		}
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeInvalidToken,
			Message: "Authorization must use the Bearer scheme",
		}
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeMissingToken,
			Message: "bearer token is empty",
		}
	}
	return tok, nil
}

// DevAuthenticator validates a static bearer token. It is intended for
// local development, CI smoke, and air-gapped demos where no OIDC
// provider is available.
//
// Identity mapping: the configured staticActor (kind:subject) is the
// actor every authenticated request runs as. Roles are looked up live
// against actor_role_bindings on every request so a `role grant` issued
// while the server is running takes effect on the next request.
type DevAuthenticator struct {
	token  string
	actor  domain.Actor
	store  storage.Storage
}

// NewDevAuthenticator constructs a DevAuthenticator. token must be
// non-empty; actorRef must parse as `kind:subject` with kind in
// {human, service_account, system}.
func NewDevAuthenticator(token, actorRef string, store storage.Storage) (*DevAuthenticator, error) {
	if token == "" {
		return nil, errors.New("api: dev token must not be empty")
	}
	if store == nil {
		return nil, errors.New("api: dev authenticator requires storage handle")
	}
	actor, err := parseActorRef(actorRef)
	if err != nil {
		return nil, fmt.Errorf("api: dev actor: %w", err)
	}
	return &DevAuthenticator{token: token, actor: actor, store: store}, nil
}

// Authenticate compares the request's bearer token against the
// configured value and resolves the active role set for the static
// actor.
func (a *DevAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	tok, err := extractBearer(r)
	if err != nil {
		return Identity{}, err
	}
	// Constant-time compare to avoid timing oracles even though the
	// dev path is not security-critical — keeps muscle memory consistent
	// with the OIDC path.
	if !secureCompare(tok, a.token) {
		return Identity{}, &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeInvalidToken,
			Message: "bearer token does not match configured dev token",
		}
	}
	roles, err := a.store.ListActiveRolesForActor(r.Context(), a.actor)
	if err != nil {
		// A storage error here is treated as an authentication failure
		// rather than a 500: we cannot establish the caller's identity
		// without the role lookup, and exposing the storage error verbatim
		// would leak detail about the database. Return a generic 401 and
		// let the operator inspect server logs for the underlying error.
		return Identity{}, &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeInvalidToken,
			Message: "failed to resolve actor roles",
		}
	}
	return Identity{Actor: a.actor, Roles: roles}, nil
}

// OIDCAuthenticator validates RS256/ES256 JWT bearer tokens against an
// OIDC issuer's discovered JWKS, then resolves the token's `sub` claim
// to a domain Actor (always Kind=human in v0.8 — service accounts get
// their own auth flow in a later wave).
type OIDCAuthenticator struct {
	verifier *oidc.IDTokenVerifier
	store    storage.Storage
}

// NewOIDCAuthenticator builds an OIDCAuthenticator. issuer is the
// canonical issuer URL; audience is the expected `aud` claim value.
// Both must be non-empty.
//
// The constructor performs OIDC discovery (one HTTP round trip to
// <issuer>/.well-known/openid-configuration) and caches the JWKS so
// subsequent requests are local. A failure here aborts server startup
// with a clear error.
func NewOIDCAuthenticator(ctx context.Context, issuer, audience string, store storage.Storage) (*OIDCAuthenticator, error) {
	if issuer == "" {
		return nil, errors.New("api: OIDC issuer must not be empty")
	}
	if audience == "" {
		return nil, errors.New("api: OIDC audience must not be empty")
	}
	if store == nil {
		return nil, errors.New("api: OIDC authenticator requires storage handle")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("api: OIDC discovery for %s: %w", issuer, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: audience})
	return &OIDCAuthenticator{verifier: verifier, store: store}, nil
}

// Authenticate validates the bearer token's signature, issuer, audience,
// and expiry, then resolves the `sub` claim to a domain.Actor with
// Kind=human. Roles are looked up live so changes propagate without a
// server restart.
func (a *OIDCAuthenticator) Authenticate(r *http.Request) (Identity, error) {
	tok, err := extractBearer(r)
	if err != nil {
		return Identity{}, err
	}
	idToken, err := a.verifier.Verify(r.Context(), tok)
	if err != nil {
		return Identity{}, &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeInvalidToken,
			Message: "token verification failed",
		}
	}
	if idToken.Subject == "" {
		return Identity{}, &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeInvalidToken,
			Message: "token has empty subject claim",
		}
	}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: idToken.Subject}
	roles, err := a.store.ListActiveRolesForActor(r.Context(), actor)
	if err != nil {
		return Identity{}, &AuthError{
			Status:  http.StatusUnauthorized,
			Code:    CodeInvalidToken,
			Message: "failed to resolve actor roles",
		}
	}
	return Identity{Actor: actor, Roles: roles}, nil
}

// parseActorRef splits a "kind:subject" string into a domain.Actor.
// The kind component must be one of {human, service_account, system};
// an unknown kind or empty subject returns an error.
func parseActorRef(s string) (domain.Actor, error) {
	if s == "" {
		// Default for dev mode.
		return domain.Actor{Kind: domain.ActorHuman, Subject: "dev"}, nil
	}
	idx := strings.IndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return domain.Actor{}, fmt.Errorf("actor %q must be kind:subject", s)
	}
	kind := domain.ActorKind(s[:idx])
	subject := s[idx+1:]
	switch kind {
	case domain.ActorHuman, domain.ActorServiceAccount, domain.ActorSystem:
	default:
		return domain.Actor{}, fmt.Errorf("invalid actor kind %q", kind)
	}
	return domain.Actor{Kind: kind, Subject: subject}, nil
}

// secureCompare returns true iff a and b are byte-equal, using a constant
// time comparison so the comparison's runtime does not leak information
// about a partial token match.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
