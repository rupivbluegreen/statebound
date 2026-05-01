// Package storage defines the Statebound persistence boundary. Implementations live in subpackages (pgx-based postgres in internal/storage/postgres).
package storage

import (
	"context"
	"errors"

	"statebound.dev/statebound/internal/domain"
)

// Sentinel errors mapped from concrete drivers so callers do not depend on pgx.
var (
	ErrNotFound      = errors.New("storage: not found")
	ErrAlreadyExists = errors.New("storage: already exists")
	ErrConflict      = errors.New("storage: conflict")
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

// Storage is the aggregate persistence boundary used by the application layer.
type Storage interface {
	ProductStore
	AuditStore
	Close(ctx context.Context) error
	Ping(ctx context.Context) error
}
