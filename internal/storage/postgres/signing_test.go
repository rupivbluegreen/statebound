package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/signing"
	"statebound.dev/statebound/internal/storage"
)

func newTestSigningKey(t *testing.T, keyID string) *domain.SigningKey {
	t.Helper()
	priv, pub, err := signing.Generate()
	if err != nil {
		t.Fatalf("signing.Generate: %v", err)
	}
	k, err := domain.NewSigningKey(
		keyID,
		domain.AlgorithmEd25519,
		pub,
		priv,
		signing.Fingerprint(pub),
		"file:/tmp/"+keyID+".pem",
		domain.Actor{Kind: domain.ActorHuman, Subject: "ops@example.com"},
		nil,
		"",
	)
	if err != nil {
		t.Fatalf("domain.NewSigningKey: %v", err)
	}
	return k
}

func TestAppendAndGetSigningKey(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyID := "release-" + uniqueSlug("k")
	k := newTestSigningKey(t, keyID)
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("AppendSigningKey: %v", err)
	}

	got, err := store.GetSigningKey(ctx, keyID)
	if err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if got.KeyID != keyID {
		t.Errorf("KeyID = %q, want %q", got.KeyID, keyID)
	}
	if got.Fingerprint != k.Fingerprint {
		t.Errorf("Fingerprint = %q, want %q", got.Fingerprint, k.Fingerprint)
	}
	if len(got.PrivateKey) != 0 {
		t.Errorf("storage returned %d bytes of private key; expected zero", len(got.PrivateKey))
	}
}

func TestAppendSigningKey_DuplicateKeyID(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyID := "dup-" + uniqueSlug("k")
	k := newTestSigningKey(t, keyID)
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("first AppendSigningKey: %v", err)
	}
	dup := newTestSigningKey(t, keyID)
	err := store.AppendSigningKey(ctx, dup)
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Errorf("error = %v, want ErrAlreadyExists", err)
	}
}

func TestGetSigningKey_NotFound(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := store.GetSigningKey(ctx, "no-such-"+uniqueSlug("k"))
	if !errors.Is(err, storage.ErrSigningKeyNotFound) {
		t.Errorf("error = %v, want ErrSigningKeyNotFound", err)
	}
}

func TestListSigningKeys_OnlyActiveExcludesDisabledAndExpired(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	active := newTestSigningKey(t, "active-"+uniqueSlug("k"))
	disabled := newTestSigningKey(t, "disabled-"+uniqueSlug("k"))
	disabled.Disabled = true
	past := time.Now().Add(-1 * time.Hour).UTC()
	expired := newTestSigningKey(t, "expired-"+uniqueSlug("k"))
	expired.ExpiresAt = &past

	for _, k := range []*domain.SigningKey{active, disabled, expired} {
		if err := store.AppendSigningKey(ctx, k); err != nil {
			t.Fatalf("AppendSigningKey %s: %v", k.KeyID, err)
		}
	}

	all, err := store.ListSigningKeys(ctx, false)
	if err != nil {
		t.Fatalf("ListSigningKeys(false): %v", err)
	}
	wantedSet := map[string]bool{active.KeyID: false, disabled.KeyID: false, expired.KeyID: false}
	for _, k := range all {
		if _, ok := wantedSet[k.KeyID]; ok {
			wantedSet[k.KeyID] = true
		}
	}
	for k, found := range wantedSet {
		if !found {
			t.Errorf("ListSigningKeys(false) missing %q", k)
		}
	}

	activeOnly, err := store.ListSigningKeys(ctx, true)
	if err != nil {
		t.Fatalf("ListSigningKeys(true): %v", err)
	}
	for _, k := range activeOnly {
		if k.KeyID == disabled.KeyID {
			t.Errorf("active list contains disabled key %q", k.KeyID)
		}
		if k.KeyID == expired.KeyID {
			t.Errorf("active list contains expired key %q", k.KeyID)
		}
	}
}

func TestDisableSigningKey(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	k := newTestSigningKey(t, "tog-"+uniqueSlug("k"))
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("AppendSigningKey: %v", err)
	}
	if err := store.DisableSigningKey(ctx, k.KeyID, true); err != nil {
		t.Fatalf("DisableSigningKey true: %v", err)
	}
	got, err := store.GetSigningKey(ctx, k.KeyID)
	if err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if !got.Disabled {
		t.Error("Disabled = false, want true")
	}
	if err := store.DisableSigningKey(ctx, k.KeyID, false); err != nil {
		t.Fatalf("DisableSigningKey false: %v", err)
	}
	got, err = store.GetSigningKey(ctx, k.KeyID)
	if err != nil {
		t.Fatalf("GetSigningKey 2: %v", err)
	}
	if got.Disabled {
		t.Error("Disabled = true, want false")
	}

	if err := store.DisableSigningKey(ctx, "nope-"+uniqueSlug("k"), true); !errors.Is(err, storage.ErrSigningKeyNotFound) {
		t.Errorf("error = %v, want ErrSigningKeyNotFound", err)
	}
}

func TestUpdateSigningKeyLastUsed(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	k := newTestSigningKey(t, "use-"+uniqueSlug("k"))
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("AppendSigningKey: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.UpdateSigningKeyLastUsed(ctx, k.KeyID, now); err != nil {
		t.Fatalf("UpdateSigningKeyLastUsed: %v", err)
	}
	got, err := store.GetSigningKey(ctx, k.KeyID)
	if err != nil {
		t.Fatalf("GetSigningKey: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt is nil")
	}
	// Postgres normalises to UTC; tolerate sub-second drift.
	if got.LastUsedAt.UTC().Sub(now).Abs() > time.Second {
		t.Errorf("LastUsedAt = %v, want ~%v", got.LastUsedAt, now)
	}
}

func TestPlanSignature_AppendAndList(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	planID := seedPlanForApply(ctx, t, store)

	k := newTestSigningKey(t, "ps-"+uniqueSlug("k"))
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("AppendSigningKey: %v", err)
	}

	// Build a fake but well-formed 64-byte signature; the storage layer
	// does not run cryptographic verification, only structural checks.
	sigBytes := make([]byte, 64)
	for i := range sigBytes {
		sigBytes[i] = byte(i)
	}
	ps, err := domain.NewPlanSignature(planID, k.KeyID, "ed25519", sigBytes, domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("NewPlanSignature: %v", err)
	}
	if err := store.AppendPlanSignature(ctx, ps); err != nil {
		t.Fatalf("AppendPlanSignature: %v", err)
	}

	list, err := store.ListPlanSignaturesByPlan(ctx, planID)
	if err != nil {
		t.Fatalf("ListPlanSignaturesByPlan: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(list) = %d, want 1", len(list))
	}
	if list[0].KeyID != k.KeyID {
		t.Errorf("KeyID = %q, want %q", list[0].KeyID, k.KeyID)
	}
}

func TestPlanSignature_DuplicateRejected(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	planID := seedPlanForApply(ctx, t, store)
	k := newTestSigningKey(t, "dup-"+uniqueSlug("k"))
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("AppendSigningKey: %v", err)
	}

	sigBytes := make([]byte, 64)
	ps1, err := domain.NewPlanSignature(planID, k.KeyID, "ed25519", sigBytes, domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("NewPlanSignature: %v", err)
	}
	if err := store.AppendPlanSignature(ctx, ps1); err != nil {
		t.Fatalf("first AppendPlanSignature: %v", err)
	}
	ps2, err := domain.NewPlanSignature(planID, k.KeyID, "ed25519", sigBytes, domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("NewPlanSignature 2: %v", err)
	}
	if err := store.AppendPlanSignature(ctx, ps2); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Errorf("error = %v, want ErrAlreadyExists", err)
	}
}

func TestPlanSignature_FKMissingPlan(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	k := newTestSigningKey(t, "fk-"+uniqueSlug("k"))
	if err := store.AppendSigningKey(ctx, k); err != nil {
		t.Fatalf("AppendSigningKey: %v", err)
	}
	missingPlan := domain.NewID()
	sigBytes := make([]byte, 64)
	ps, err := domain.NewPlanSignature(missingPlan, k.KeyID, "ed25519", sigBytes, domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"})
	if err != nil {
		t.Fatalf("NewPlanSignature: %v", err)
	}
	if err := store.AppendPlanSignature(ctx, ps); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}
