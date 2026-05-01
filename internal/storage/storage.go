// Package storage defines the Statebound persistence boundary. Implementations live in subpackages (pgx-based postgres in internal/storage/postgres).
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"statebound.dev/statebound/internal/domain"
)

// Sentinel errors mapped from concrete drivers so callers do not depend on pgx.
var (
	ErrNotFound        = errors.New("storage: not found")
	ErrAlreadyExists   = errors.New("storage: already exists")
	ErrConflict        = errors.New("storage: conflict")
	ErrInvalidArgument = errors.New("storage: invalid argument")
	// ErrChangeSetNotFound is returned when a write references a change_set_id
	// that does not exist; e.g. AppendPolicyDecision against a stale id.
	ErrChangeSetNotFound = errors.New("storage: change set not found")
	// ErrPolicyDecisionNotFound is returned when a policy_decisions lookup misses.
	ErrPolicyDecisionNotFound = errors.New("storage: policy decision not found")
)

// AuditFilter narrows ListAuditEvents results. A zero Limit means no limit.
type AuditFilter struct {
	ResourceType string
	ResourceID   string
	Kind         domain.EventKind
	Limit        int
}

// ProductStore persists Products.
type ProductStore interface {
	CreateProduct(ctx context.Context, p *domain.Product) error
	GetProductByID(ctx context.Context, id domain.ID) (*domain.Product, error)
	GetProductByName(ctx context.Context, name string) (*domain.Product, error)
	ListProducts(ctx context.Context) ([]*domain.Product, error)
	UpdateProduct(ctx context.Context, p *domain.Product) error
	DeleteProduct(ctx context.Context, id domain.ID) error
}

// AuditStore appends and queries the audit log.
type AuditStore interface {
	AppendAuditEvent(ctx context.Context, e *domain.AuditEvent) error
	ListAuditEvents(ctx context.Context, f AuditFilter) ([]*domain.AuditEvent, error)
}

// AssetStore persists Assets owned by a Product.
type AssetStore interface {
	CreateAsset(ctx context.Context, a *domain.Asset) error
	GetAssetByID(ctx context.Context, id domain.ID) (*domain.Asset, error)
	GetAssetByName(ctx context.Context, productID domain.ID, name string) (*domain.Asset, error)
	ListAssetsByProduct(ctx context.Context, productID domain.ID) ([]*domain.Asset, error)
	UpdateAsset(ctx context.Context, a *domain.Asset) error
	DeleteAsset(ctx context.Context, id domain.ID) error
}

// AssetScopeStore persists AssetScopes owned by a Product.
type AssetScopeStore interface {
	CreateAssetScope(ctx context.Context, s *domain.AssetScope) error
	GetAssetScopeByID(ctx context.Context, id domain.ID) (*domain.AssetScope, error)
	GetAssetScopeByName(ctx context.Context, productID domain.ID, name string) (*domain.AssetScope, error)
	ListAssetScopesByProduct(ctx context.Context, productID domain.ID) ([]*domain.AssetScope, error)
	UpdateAssetScope(ctx context.Context, s *domain.AssetScope) error
	DeleteAssetScope(ctx context.Context, id domain.ID) error
}

// EntitlementStore persists Entitlements owned by a Product.
type EntitlementStore interface {
	CreateEntitlement(ctx context.Context, e *domain.Entitlement) error
	GetEntitlementByID(ctx context.Context, id domain.ID) (*domain.Entitlement, error)
	GetEntitlementByName(ctx context.Context, productID domain.ID, name string) (*domain.Entitlement, error)
	ListEntitlementsByProduct(ctx context.Context, productID domain.ID) ([]*domain.Entitlement, error)
	UpdateEntitlement(ctx context.Context, e *domain.Entitlement) error
	DeleteEntitlement(ctx context.Context, id domain.ID) error
}

// ServiceAccountStore persists ServiceAccounts owned by a Product.
type ServiceAccountStore interface {
	CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error
	GetServiceAccountByID(ctx context.Context, id domain.ID) (*domain.ServiceAccount, error)
	GetServiceAccountByName(ctx context.Context, productID domain.ID, name string) (*domain.ServiceAccount, error)
	ListServiceAccountsByProduct(ctx context.Context, productID domain.ID) ([]*domain.ServiceAccount, error)
	UpdateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error
	DeleteServiceAccount(ctx context.Context, id domain.ID) error
}

// GlobalObjectStore persists GlobalObjects, optionally scoped to a Product (nil = cross-product).
type GlobalObjectStore interface {
	CreateGlobalObject(ctx context.Context, g *domain.GlobalObject) error
	GetGlobalObjectByID(ctx context.Context, id domain.ID) (*domain.GlobalObject, error)
	// GetGlobalObjectByName looks up by (productID, name). Pass productID = nil for cross-product objects.
	GetGlobalObjectByName(ctx context.Context, productID *domain.ID, name string) (*domain.GlobalObject, error)
	// ListGlobalObjectsByProduct returns all global objects with the given product scope.
	// Pass productID = nil to list cross-product (NULL product_id) objects only.
	ListGlobalObjectsByProduct(ctx context.Context, productID *domain.ID) ([]*domain.GlobalObject, error)
	// ListAllGlobalObjects returns every global object regardless of product scope.
	ListAllGlobalObjects(ctx context.Context) ([]*domain.GlobalObject, error)
	UpdateGlobalObject(ctx context.Context, g *domain.GlobalObject) error
	DeleteGlobalObject(ctx context.Context, id domain.ID) error
}

// AuthorizationStore persists Authorizations. Authorizations have no Update method:
// callers (notably the importer) delete and recreate when re-syncing.
type AuthorizationStore interface {
	CreateAuthorization(ctx context.Context, a *domain.Authorization) error
	GetAuthorizationByID(ctx context.Context, id domain.ID) (*domain.Authorization, error)
	ListAuthorizationsByParent(ctx context.Context, parentKind domain.AuthorizationParentKind, parentID domain.ID) ([]*domain.Authorization, error)
	DeleteAuthorization(ctx context.Context, id domain.ID) error
}

// ChangeSetFilter narrows ListChangeSets results. A zero Limit means no limit.
type ChangeSetFilter struct {
	ProductID *domain.ID
	State     *domain.ChangeSetState
	Limit     int
}

// ChangeSetStore persists ChangeSets and their items.
type ChangeSetStore interface {
	CreateChangeSet(ctx context.Context, cs *domain.ChangeSet) error
	GetChangeSetByID(ctx context.Context, id domain.ID) (*domain.ChangeSet, error)
	ListChangeSets(ctx context.Context, filter ChangeSetFilter) ([]*domain.ChangeSet, error)
	UpdateChangeSetState(ctx context.Context, id domain.ID, newState domain.ChangeSetState, decidedAt *time.Time, decisionReason string) error
	AppendChangeSetItem(ctx context.Context, item *domain.ChangeSetItem) error
	ListChangeSetItems(ctx context.Context, csID domain.ID) ([]*domain.ChangeSetItem, error)
}

// ApprovalStore persists Approval records.
type ApprovalStore interface {
	CreateApproval(ctx context.Context, a *domain.Approval) error
	ListApprovalsByChangeSet(ctx context.Context, csID domain.ID) ([]*domain.Approval, error)
}

// ApprovedVersionStore persists immutable approved versions and their snapshots.
type ApprovedVersionStore interface {
	// CreateApprovedVersion atomically inserts the snapshot and the version that
	// references it. If snap.ID is already present (same content_hash), the
	// existing snapshot row is reused; otherwise a new snapshot row is created.
	CreateApprovedVersion(ctx context.Context, av *domain.ApprovedVersion, snap *domain.ApprovedVersionSnapshot) error
	GetLatestApprovedVersion(ctx context.Context, productID domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error)
	GetApprovedVersionByID(ctx context.Context, id domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error)
	ListApprovedVersions(ctx context.Context, productID domain.ID, limit int) ([]*domain.ApprovedVersion, error)
	// NextSequenceForProduct returns max(sequence)+1, or 1 if no prior version.
	// The unique constraint on (product_id, sequence) is the source of truth for
	// concurrency; callers retry on ErrAlreadyExists.
	NextSequenceForProduct(ctx context.Context, productID domain.ID) (int64, error)
}

// PolicyDecisionRecord is a single OPA evaluation against a ChangeSet,
// preserved for audit and replay. The Rules and Input fields hold the
// canonical JSON produced by internal/authz so the decision can be
// reproduced byte-for-byte given the same bundle hash.
type PolicyDecisionRecord struct {
	ID          domain.ID
	ChangeSetID domain.ID
	Phase       string
	Outcome     string
	Rules       json.RawMessage
	Input       json.RawMessage
	BundleHash  string
	EvaluatedAt time.Time
	CreatedAt   time.Time
}

// PolicyDecisionStore persists OPA decision records produced when a ChangeSet
// is evaluated. Decisions are append-only; there is no Update or Delete API.
type PolicyDecisionStore interface {
	// AppendPolicyDecision inserts a decision row. If rec.ChangeSetID does not
	// reference an existing change_sets row, returns ErrChangeSetNotFound.
	AppendPolicyDecision(ctx context.Context, rec *PolicyDecisionRecord) error
	// ListPolicyDecisionsByChangeSet returns decisions for csID newest first,
	// or an empty slice if there are none.
	ListPolicyDecisionsByChangeSet(ctx context.Context, csID domain.ID) ([]*PolicyDecisionRecord, error)
	// GetPolicyDecisionByID returns a single decision by id, or
	// ErrPolicyDecisionNotFound if absent.
	GetPolicyDecisionByID(ctx context.Context, id domain.ID) (*PolicyDecisionRecord, error)
}

// Storage is the aggregate persistence boundary used by the application layer.
type Storage interface {
	ProductStore
	AuditStore
	AssetStore
	AssetScopeStore
	EntitlementStore
	ServiceAccountStore
	GlobalObjectStore
	AuthorizationStore
	ChangeSetStore
	ApprovalStore
	ApprovedVersionStore
	PolicyDecisionStore
	Close(ctx context.Context) error
	Ping(ctx context.Context) error
	// WithTx runs fn inside a database transaction. The Storage handed to fn issues
	// every query inside the same transaction. Returning a non-nil error rolls back;
	// nil commits. Panics in fn cause rollback and re-panic.
	WithTx(ctx context.Context, fn func(tx Storage) error) error
}
