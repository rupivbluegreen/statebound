package model

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ImportMode selects how Import handles an incoming model.
type ImportMode string

const (
	// ImportModeChangeSet is the production default: produce a draft ChangeSet
	// for human review, never touch live tables.
	ImportModeChangeSet ImportMode = "changeset"
	// ImportModeAutoApprove auto-approves the import in one step. Dev-only:
	// requires the STATEBOUND_DEV_AUTO_APPROVE=true environment override.
	ImportModeAutoApprove ImportMode = "auto-approve"
)

// envAutoApprove gates ImportModeAutoApprove. Kept as a constant so tests can
// reference the name without retyping.
const envAutoApprove = "STATEBOUND_DEV_AUTO_APPROVE"

// ImportResult summarizes what an Import call produced. ChangeSetID is set on
// every successful run; ApprovedVersionID is set only in auto-approve mode.
// Diff is always populated (possibly empty).
type ImportResult struct {
	ProductID         domain.ID
	ChangeSetID       *domain.ID
	ApprovedVersionID *domain.ID
	Diff              *Diff
}

// Import validates the model, computes the diff against the latest approved
// version (if any), and either records a draft ChangeSet (default) or auto-
// approves it (dev mode). On validation failure it returns
// *ValidationFailedError without opening any transaction.
func Import(ctx context.Context, store storage.Storage, m *ProductAuthorizationModel, actor domain.Actor, mode ImportMode) (*ImportResult, error) {
	if findings := Validate(m); len(findings) > 0 {
		return nil, &ValidationFailedError{Findings: findings}
	}
	if mode == ImportModeAutoApprove && os.Getenv(envAutoApprove) != "true" {
		return nil, fmt.Errorf("auto-approve mode requires %s=true", envAutoApprove)
	}

	result := &ImportResult{Diff: &Diff{}}
	err := store.WithTx(ctx, func(tx storage.Storage) error {
		product, err := ensureProduct(ctx, tx, m, actor)
		if err != nil {
			return err
		}
		result.ProductID = product.ID

		// Resolve the parent approved version (if any) and reconstruct the
		// previous-state model from its snapshot.
		parentVersionID, before, err := loadParentVersion(ctx, tx, product.ID)
		if err != nil {
			return err
		}

		diff, err := ComputeDiff(before, m)
		if err != nil {
			return fmt.Errorf("compute diff: %w", err)
		}
		result.Diff = diff
		if diff.IsEmpty() {
			return nil
		}

		cs, err := createChangeSet(ctx, tx, product, m, parentVersionID, diff, actor)
		if err != nil {
			return err
		}
		csID := cs.ID
		result.ChangeSetID = &csID

		if mode == ImportModeChangeSet {
			return nil
		}
		// ImportModeAutoApprove: walk the change set through the full state
		// machine in this same tx, mint the approved version, and apply it.
		avID, err := autoApprove(ctx, tx, product.ID, m, cs, parentVersionID, actor)
		if err != nil {
			return err
		}
		result.ApprovedVersionID = &avID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ensureProduct fetches the product row by name, creating it (and emitting
// product.created) when absent.
func ensureProduct(ctx context.Context, tx storage.Storage, m *ProductAuthorizationModel, actor domain.Actor) (*domain.Product, error) {
	existing, err := tx.GetProductByName(ctx, m.Metadata.Product)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("lookup product: %w", err)
	}
	if existing != nil {
		return existing, nil
	}
	p, err := domain.NewProduct(m.Metadata.Product, m.Metadata.Owner, m.Metadata.Description)
	if err != nil {
		return nil, fmt.Errorf("build product: %w", err)
	}
	if err := tx.CreateProduct(ctx, p); err != nil {
		return nil, fmt.Errorf("create product: %w", err)
	}
	evt, err := domain.NewAuditEvent(domain.EventProductCreated, actor, "product", string(p.ID), map[string]any{
		"name":  p.Name,
		"owner": p.Owner,
	})
	if err != nil {
		return nil, fmt.Errorf("build product.created audit: %w", err)
	}
	if err := tx.AppendAuditEvent(ctx, evt); err != nil {
		return nil, fmt.Errorf("append product.created audit: %w", err)
	}
	return p, nil
}

// loadParentVersion returns the latest approved version's id and reconstructed
// model. Returns (nil, nil, nil) when there is no prior version.
func loadParentVersion(ctx context.Context, tx storage.Storage, productID domain.ID) (*domain.ID, *ProductAuthorizationModel, error) {
	av, snap, err := tx.GetLatestApprovedVersion(ctx, productID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("get latest approved version: %w", err)
	}
	model, err := FromSnapshot(snap.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("decode snapshot: %w", err)
	}
	id := av.ID
	return &id, model, nil
}

// createChangeSet writes a draft ChangeSet plus one ChangeSetItem per diff
// entry, then emits changeset.created. No per-item audit events; the change
// set itself is the audit unit at this layer.
func createChangeSet(ctx context.Context, tx storage.Storage, product *domain.Product, m *ProductAuthorizationModel, parentVersionID *domain.ID, diff *Diff, actor domain.Actor) (*domain.ChangeSet, error) {
	title := fmt.Sprintf("import %s %s", m.Metadata.Product, time.Now().UTC().Format(time.RFC3339))
	description := m.Metadata.Description
	if description == "" {
		description = fmt.Sprintf("Imported from YAML; %s", diff.Summary())
	}
	cs, err := domain.NewChangeSet(product.ID, parentVersionID, title, description, actor)
	if err != nil {
		return nil, fmt.Errorf("build change set: %w", err)
	}
	if err := tx.CreateChangeSet(ctx, cs); err != nil {
		return nil, fmt.Errorf("create change set: %w", err)
	}
	evt, err := domain.NewAuditEvent(domain.EventChangeSetCreated, actor, "change_set", string(cs.ID), map[string]any{
		"product":  m.Metadata.Product,
		"title":    cs.Title,
		"summary":  diff.Summary(),
		"items":    len(diff.Items),
	})
	if err != nil {
		return nil, fmt.Errorf("build changeset.created audit: %w", err)
	}
	if err := tx.AppendAuditEvent(ctx, evt); err != nil {
		return nil, fmt.Errorf("append changeset.created audit: %w", err)
	}
	for _, it := range diff.Items {
		csi, err := domain.NewChangeSetItem(cs.ID, it.Kind, it.Action, it.ResourceName, it.Before, it.After)
		if err != nil {
			return nil, fmt.Errorf("build change set item %q: %w", it.ResourceName, err)
		}
		if err := tx.AppendChangeSetItem(ctx, csi); err != nil {
			return nil, fmt.Errorf("append change set item %q: %w", it.ResourceName, err)
		}
	}
	return cs, nil
}

// autoApprove walks the freshly-created ChangeSet through Submitted -> Approved,
// records the approval, mints the ApprovedVersion + snapshot, and applies the
// snapshot to live tables. Audit events fire for each transition.
func autoApprove(ctx context.Context, tx storage.Storage, productID domain.ID, m *ProductAuthorizationModel, cs *domain.ChangeSet, parentVersionID *domain.ID, actor domain.Actor) (domain.ID, error) {
	now := time.Now().UTC()

	if err := tx.UpdateChangeSetState(ctx, cs.ID, domain.ChangeSetStateSubmitted, &now, ""); err != nil {
		return "", fmt.Errorf("transition to submitted: %w", err)
	}
	if err := emitChangeSetEvent(ctx, tx, domain.EventChangeSetSubmitted, cs.ID, actor, nil); err != nil {
		return "", err
	}

	seq, err := tx.NextSequenceForProduct(ctx, productID)
	if err != nil {
		return "", fmt.Errorf("next sequence: %w", err)
	}
	content, err := ToSnapshotContent(m)
	if err != nil {
		return "", fmt.Errorf("snapshot content: %w", err)
	}
	snap, err := domain.NewApprovedVersionSnapshot(content)
	if err != nil {
		return "", fmt.Errorf("build snapshot: %w", err)
	}
	av, err := domain.NewApprovedVersion(productID, snap.ID, seq, parentVersionID, cs.ID, actor, "auto-approved")
	if err != nil {
		return "", fmt.Errorf("build approved version: %w", err)
	}
	if err := tx.CreateApprovedVersion(ctx, av, snap); err != nil {
		return "", fmt.Errorf("create approved version: %w", err)
	}
	if err := emitApprovedVersionEvent(ctx, tx, av, actor); err != nil {
		return "", err
	}

	if err := tx.UpdateChangeSetState(ctx, cs.ID, domain.ChangeSetStateApproved, &now, "auto-approve"); err != nil {
		return "", fmt.Errorf("transition to approved: %w", err)
	}
	if err := emitChangeSetEvent(ctx, tx, domain.EventChangeSetApproved, cs.ID, actor, map[string]any{
		"approved_version_id": string(av.ID),
		"sequence":            av.Sequence,
	}); err != nil {
		return "", err
	}
	approval, err := domain.NewApproval(cs.ID, actor, domain.ApprovalDecisionApproved, "auto-approve")
	if err != nil {
		return "", fmt.Errorf("build approval: %w", err)
	}
	if err := tx.CreateApproval(ctx, approval); err != nil {
		return "", fmt.Errorf("create approval: %w", err)
	}

	if _, err := applyInTx(ctx, tx, productID, m, actor); err != nil {
		return "", fmt.Errorf("apply: %w", err)
	}
	return av.ID, nil
}

// emitChangeSetEvent appends a single changeset.* audit event with optional
// extra payload fields merged on top of the change-set id.
func emitChangeSetEvent(ctx context.Context, tx storage.Storage, kind domain.EventKind, csID domain.ID, actor domain.Actor, extra map[string]any) error {
	payload := map[string]any{"change_set_id": string(csID)}
	for k, v := range extra {
		payload[k] = v
	}
	evt, err := domain.NewAuditEvent(kind, actor, "change_set", string(csID), payload)
	if err != nil {
		return fmt.Errorf("build %s audit: %w", kind, err)
	}
	if err := tx.AppendAuditEvent(ctx, evt); err != nil {
		return fmt.Errorf("append %s audit: %w", kind, err)
	}
	return nil
}

// emitApprovedVersionEvent appends an approved_version.created audit event.
func emitApprovedVersionEvent(ctx context.Context, tx storage.Storage, av *domain.ApprovedVersion, actor domain.Actor) error {
	payload := map[string]any{
		"approved_version_id": string(av.ID),
		"product_id":          string(av.ProductID),
		"sequence":            av.Sequence,
		"snapshot_id":         string(av.SnapshotID),
		"source_change_set":   string(av.SourceChangeSetID),
	}
	evt, err := domain.NewAuditEvent(domain.EventApprovedVersionCreated, actor, "approved_version", string(av.ID), payload)
	if err != nil {
		return fmt.Errorf("build approved_version.created audit: %w", err)
	}
	if err := tx.AppendAuditEvent(ctx, evt); err != nil {
		return fmt.Errorf("append approved_version.created audit: %w", err)
	}
	return nil
}

// applyInTx invokes Apply against the in-transaction storage handle by
// delegating to a wrapper that no-ops the inner WithTx (we are already inside
// one). Apply itself opens its own tx via the storage handle it receives, but
// pgx tx handles route nested WithTx as a savepoint or pass-through depending
// on the implementation. To stay portable we call the apply logic directly.
func applyInTx(ctx context.Context, tx storage.Storage, productID domain.ID, m *ProductAuthorizationModel, actor domain.Actor) (*ApplyResult, error) {
	return Apply(ctx, txPassthrough{Storage: tx}, productID, m, actor)
}

// txPassthrough wraps a Storage already inside a transaction so a nested
// WithTx call runs fn against the same handle without opening a new tx. This
// keeps Apply's "atomic with audit events" promise intact when called from
// inside Import's outer tx.
type txPassthrough struct {
	storage.Storage
}

// WithTx ignores the request to open a new tx and runs fn against the
// underlying handle, which is already transactional.
func (t txPassthrough) WithTx(ctx context.Context, fn func(tx storage.Storage) error) error {
	return fn(t.Storage)
}
