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

// TestStoreSubInterfaces asserts each sub-interface independently so a regression
// in any single sub-interface fails with a precise compile error rather than a
// broad "does not implement Storage" message.
func TestStoreSubInterfaces(t *testing.T) {
	var (
		_ storage.ProductStore        = (*postgres.Store)(nil)
		_ storage.AuditStore          = (*postgres.Store)(nil)
		_ storage.AssetStore          = (*postgres.Store)(nil)
		_ storage.AssetScopeStore     = (*postgres.Store)(nil)
		_ storage.EntitlementStore    = (*postgres.Store)(nil)
		_ storage.ServiceAccountStore = (*postgres.Store)(nil)
		_ storage.GlobalObjectStore   = (*postgres.Store)(nil)
		_ storage.AuthorizationStore  = (*postgres.Store)(nil)
	)
	_ = t
}
