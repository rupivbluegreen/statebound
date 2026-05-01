package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// TestApproval_FourEyes_RequesterCannotApproveOwn verifies the four-eyes rule:
// the actor that requested a ChangeSet must not be allowed to approve it. The
// handler returns an error before any storage call beyond the initial reads,
// which is exactly what the fake stub records and the assertions check.
func TestApproval_FourEyes_RequesterCannotApproveOwn(t *testing.T) {
	requester := domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"}
	productID := domain.ID("00000000-0000-0000-0000-00000000aaaa")
	csID := domain.ID("00000000-0000-0000-0000-00000000cccc")

	cs := &domain.ChangeSet{
		ID:          csID,
		ProductID:   productID,
		State:       domain.ChangeSetStateSubmitted,
		Title:       "test",
		RequestedBy: requester,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	stub := &fourEyesStub{
		changeSets: map[domain.ID]*domain.ChangeSet{csID: cs},
		products: map[domain.ID]*domain.Product{
			productID: {ID: productID, Name: "test-product"},
		},
	}

	var buf bytes.Buffer
	err := runApprove(context.Background(), stub, &buf, csID, requester, "looks fine")
	if err == nil {
		t.Fatalf("runApprove returned nil; want four-eyes error")
	}
	if !strings.Contains(err.Error(), "requester cannot approve their own change set") {
		t.Errorf("error %q missing four-eyes message", err.Error())
	}
	if !strings.Contains(err.Error(), envActor) {
		t.Errorf("error %q missing %s reference", err.Error(), envActor)
	}
	if stub.txOpened {
		t.Errorf("WithTx was opened; expected the four-eyes check to short-circuit before any tx work")
	}
}

// TestApproval_FourEyes_DifferentApproverPasses asserts the same handler
// proceeds past the four-eyes check when the approver differs from the
// requester. The stub returns ErrNotFound from the first storage call inside
// the tx so we exit fast — what matters is that we got past the four-eyes
// gate.
func TestApproval_FourEyes_DifferentApproverPasses(t *testing.T) {
	requester := domain.Actor{Kind: domain.ActorHuman, Subject: "alice@example.com"}
	approver := domain.Actor{Kind: domain.ActorHuman, Subject: "bob@example.com"}
	productID := domain.ID("00000000-0000-0000-0000-00000000aaaa")
	csID := domain.ID("00000000-0000-0000-0000-00000000cccc")

	cs := &domain.ChangeSet{
		ID:          csID,
		ProductID:   productID,
		State:       domain.ChangeSetStateSubmitted,
		Title:       "test",
		RequestedBy: requester,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	stub := &fourEyesStub{
		changeSets: map[domain.ID]*domain.ChangeSet{csID: cs},
		products: map[domain.ID]*domain.Product{
			productID: {ID: productID, Name: "test-product"},
		},
	}

	var buf bytes.Buffer
	err := runApprove(context.Background(), stub, &buf, csID, approver, "approved")
	if err == nil {
		t.Fatalf("runApprove returned nil; expected the stub's deliberate inner-tx failure")
	}
	if strings.Contains(err.Error(), "requester cannot approve their own change set") {
		t.Errorf("four-eyes incorrectly fired for distinct approver: %v", err)
	}
	if !stub.txOpened {
		t.Errorf("WithTx was not opened; the four-eyes check should have passed")
	}
}

// fourEyesStub is the minimum storage.Storage implementation needed to drive
// the runApprove handler past its four-eyes check. It panics on any method
// the test does not exercise so accidental wider coverage shows up as a clear
// test failure rather than a silent zero-value response.
type fourEyesStub struct {
	storage.Storage // unimplemented methods will panic via embedded nil
	changeSets      map[domain.ID]*domain.ChangeSet
	products        map[domain.ID]*domain.Product
	txOpened        bool
}

func (s *fourEyesStub) Close(_ context.Context) error { return nil }
func (s *fourEyesStub) Ping(_ context.Context) error  { return nil }

func (s *fourEyesStub) GetChangeSetByID(_ context.Context, id domain.ID) (*domain.ChangeSet, error) {
	cs, ok := s.changeSets[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return cs, nil
}

func (s *fourEyesStub) GetProductByID(_ context.Context, id domain.ID) (*domain.Product, error) {
	p, ok := s.products[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return p, nil
}

// WithTx records that we entered the transactional path, then deliberately
// errors out so we don't have to implement the full Approved-version storage
// surface for this unit test.
func (s *fourEyesStub) WithTx(ctx context.Context, fn func(tx storage.Storage) error) error {
	s.txOpened = true
	return fn(&txStub{parent: s})
}

// txStub is the per-transaction storage handle. Same minimal surface as the
// parent; everything we don't need returns ErrNotFound or a stub error so the
// test exits early.
type txStub struct {
	storage.Storage
	parent *fourEyesStub
}

func (t *txStub) GetChangeSetByID(ctx context.Context, id domain.ID) (*domain.ChangeSet, error) {
	return t.parent.GetChangeSetByID(ctx, id)
}

func (t *txStub) GetLatestApprovedVersion(_ context.Context, _ domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error) {
	return nil, nil, storage.ErrNotFound
}

func (t *txStub) ListChangeSetItems(_ context.Context, _ domain.ID) ([]*domain.ChangeSetItem, error) {
	return nil, nil
}

func (t *txStub) NextSequenceForProduct(_ context.Context, _ domain.ID) (int64, error) {
	// Stop the run cleanly here so we don't have to mock CreateApprovedVersion etc.
	return 0, errors.New("test: stop after four-eyes")
}
