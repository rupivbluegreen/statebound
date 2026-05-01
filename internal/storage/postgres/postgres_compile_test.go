package postgres_test

import (
	"testing"

	"statebound.dev/statebound/internal/storage"
	"statebound.dev/statebound/internal/storage/postgres"
)

func TestStoreImplementsStorage(t *testing.T) {
	var _ storage.Storage = (*postgres.Store)(nil)
	_ = t // keep go vet happy
}
