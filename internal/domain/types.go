// Package domain holds Statebound's pure domain types. No I/O. No SQL. No HTTP.
package domain

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
)

// nameRe matches the cross-cutting kebab-slug pattern used for Names across
// Products, Assets, AssetScopes, Entitlements, ServiceAccounts, GlobalObjects.
// Keep this regex in sync with any SQL CHECK constraints in migrations.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// validName reports whether s is a valid kebab-slug name (1..63 chars, [a-z0-9-]).
func validName(s string) bool {
	return nameRe.MatchString(s)
}

// ID is a UUID-v4 identifier rendered as a canonical string.
type ID string

// NewID returns a fresh UUID-v4 wrapped as an ID.
func NewID() ID {
	return ID(uuid.NewString())
}

// ActorKind enumerates the categories of actors that can take auditable actions.
type ActorKind string

const (
	ActorHuman          ActorKind = "human"
	ActorServiceAccount ActorKind = "service_account"
	// ActorSystem covers internal lifecycle events such as migrations and bootstrap.
	ActorSystem ActorKind = "system"
)

// Environment names a deployment environment.
type Environment string

const (
	EnvDev     Environment = "dev"
	EnvStaging Environment = "staging"
	EnvProd    Environment = "prod"
)

// Actor identifies who took an action. Subject is a free-form identifier
// (email, service account name, agent name) interpreted by the caller.
type Actor struct {
	Kind    ActorKind
	Subject string
}

// Sentinel errors for Actor validation.
var (
	ErrActorKindInvalid    = errors.New("domain: actor kind is invalid")
	ErrActorSubjectMissing = errors.New("domain: actor subject is required")
)

// Validate checks that the actor has a known kind and a non-empty subject.
func (a Actor) Validate() error {
	switch a.Kind {
	case ActorHuman, ActorServiceAccount, ActorSystem:
	default:
		return fmt.Errorf("%w: %q", ErrActorKindInvalid, string(a.Kind))
	}
	if a.Subject == "" {
		return ErrActorSubjectMissing
	}
	return nil
}
