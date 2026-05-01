package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/storage/postgres"
)

// envActor is the env var Phase 1 reads to derive a human Actor. Phase 8 will
// replace this with real OIDC subject extraction.
const envActor = "STATEBOUND_ACTOR"

// storeFromCmd opens a storage handle using the persistent --db-dsn flag and
// returns the concrete pgx-backed implementation as a storage.Storage value.
func storeFromCmd(cmd *cobra.Command) (storage.Storage, error) {
	dsn := dbDSN()
	store, err := postgres.New(cmd.Context(), dsn)
	if err != nil {
		return nil, fmt.Errorf("open storage: %w", err)
	}
	return store, nil
}

// actorFromCmd derives the Actor that owns side effects from this CLI run.
// STATEBOUND_ACTOR env var is the manual override during Phase 1 — Phase 8
// (OIDC) ships the proper identity binding.
func actorFromCmd(_ *cobra.Command) domain.Actor {
	if v := os.Getenv(envActor); v != "" {
		return domain.Actor{Kind: domain.ActorHuman, Subject: v}
	}
	return domain.Actor{Kind: domain.ActorSystem, Subject: "cli"}
}
