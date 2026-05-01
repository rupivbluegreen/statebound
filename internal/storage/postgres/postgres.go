// Package postgres is the Postgres-backed storage implementation. Schema lives in /migrations.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// pgUniqueViolation is the SQLSTATE code for unique_violation.
const pgUniqueViolation = "23505"

// Store is the Postgres-backed implementation of storage.Storage.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a pgx connection pool, pings it, and returns a ready Store.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Ping checks database reachability.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases pool resources. pgxpool.Close is synchronous and ignores ctx.
func (s *Store) Close(ctx context.Context) error {
	s.pool.Close()
	return nil
}

// isUniqueViolation reports whether err is a Postgres unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pgUniqueViolation
	}
	return false
}

// -------- Products --------

const productColumns = "id, name, owner, description, created_at, updated_at"

// CreateProduct inserts a new product row.
func (s *Store) CreateProduct(ctx context.Context, p *domain.Product) error {
	const q = `
INSERT INTO products (id, name, owner, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	_, err := s.pool.Exec(ctx, q,
		string(p.ID), p.Name, p.Owner, p.Description, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: insert product: %w", err)
	}
	return nil
}

// GetProductByID returns a product by primary key.
func (s *Store) GetProductByID(ctx context.Context, id domain.ID) (*domain.Product, error) {
	const q = `SELECT ` + productColumns + ` FROM products WHERE id = $1`
	row := s.pool.QueryRow(ctx, q, string(id))
	return scanProduct(row)
}

// GetProductByName returns a product by its unique slug name.
func (s *Store) GetProductByName(ctx context.Context, name string) (*domain.Product, error) {
	const q = `SELECT ` + productColumns + ` FROM products WHERE name = $1`
	row := s.pool.QueryRow(ctx, q, name)
	return scanProduct(row)
}

// ListProducts returns all products ordered by name for deterministic output.
func (s *Store) ListProducts(ctx context.Context) ([]*domain.Product, error) {
	const q = `SELECT ` + productColumns + ` FROM products ORDER BY name ASC`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres: list products: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Product, 0)
	for rows.Next() {
		p, err := scanProduct(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate products: %w", err)
	}
	return out, nil
}

// UpdateProduct overwrites a product row by id. Returns ErrNotFound if absent.
func (s *Store) UpdateProduct(ctx context.Context, p *domain.Product) error {
	const q = `
UPDATE products
   SET name = $2, owner = $3, description = $4, updated_at = $5
 WHERE id = $1
`
	tag, err := s.pool.Exec(ctx, q,
		string(p.ID), p.Name, p.Owner, p.Description, p.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: update product: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteProduct deletes a product by id. Returns ErrNotFound if absent.
func (s *Store) DeleteProduct(ctx context.Context, id domain.ID) error {
	const q = `DELETE FROM products WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete product: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// scannable abstracts pgx.Row and pgx.Rows for a single-row scan.
type scannable interface {
	Scan(dest ...any) error
}

func scanProduct(r scannable) (*domain.Product, error) {
	var (
		id   string
		p    domain.Product
		name string
	)
	err := r.Scan(&id, &name, &p.Owner, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan product: %w", err)
	}
	p.ID = domain.ID(id)
	p.Name = name
	return &p, nil
}

// -------- Audit events --------

const auditColumns = "id, kind, actor_kind, actor_subject, resource_type, resource_id, payload, occurred_at, prev_hash, hash"

// AppendAuditEvent inserts an audit event. Hash chain fields are written verbatim
// (empty strings in Phase 0; populated from v0.2 onward).
func (s *Store) AppendAuditEvent(ctx context.Context, e *domain.AuditEvent) error {
	payload, err := marshalPayload(e.Payload)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO audit_events (
  id, kind, actor_kind, actor_subject, resource_type, resource_id,
  payload, occurred_at, prev_hash, hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`
	_, err = s.pool.Exec(ctx, q,
		string(e.ID),
		string(e.Kind),
		string(e.Actor.Kind),
		e.Actor.Subject,
		e.ResourceType,
		e.ResourceID,
		payload,
		e.OccurredAt,
		e.PrevHash,
		e.Hash,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: insert audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns events filtered by AuditFilter, newest first.
func (s *Store) ListAuditEvents(ctx context.Context, f storage.AuditFilter) ([]*domain.AuditEvent, error) {
	q := `SELECT ` + auditColumns + ` FROM audit_events`
	args := make([]any, 0, 4)
	clauses := make([]string, 0, 3)

	if f.ResourceType != "" {
		args = append(args, f.ResourceType)
		clauses = append(clauses, fmt.Sprintf("resource_type = $%d", len(args)))
	}
	if f.ResourceID != "" {
		args = append(args, f.ResourceID)
		clauses = append(clauses, fmt.Sprintf("resource_id = $%d", len(args)))
	}
	if f.Kind != "" {
		args = append(args, string(f.Kind))
		clauses = append(clauses, fmt.Sprintf("kind = $%d", len(args)))
	}

	if len(clauses) > 0 {
		q += " WHERE " + joinAnd(clauses)
	}
	q += " ORDER BY occurred_at DESC, id ASC"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list audit events: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.AuditEvent, 0)
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate audit events: %w", err)
	}
	return out, nil
}

func scanAuditEvent(r scannable) (*domain.AuditEvent, error) {
	var (
		id           string
		kind         string
		actorKind    string
		actorSubject string
		payloadRaw   []byte
		e            domain.AuditEvent
	)
	err := r.Scan(
		&id,
		&kind,
		&actorKind,
		&actorSubject,
		&e.ResourceType,
		&e.ResourceID,
		&payloadRaw,
		&e.OccurredAt,
		&e.PrevHash,
		&e.Hash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan audit event: %w", err)
	}
	e.ID = domain.ID(id)
	e.Kind = domain.EventKind(kind)
	e.Actor = domain.Actor{Kind: domain.ActorKind(actorKind), Subject: actorSubject}
	if len(payloadRaw) > 0 {
		if err := json.Unmarshal(payloadRaw, &e.Payload); err != nil {
			return nil, fmt.Errorf("postgres: decode audit payload: %w", err)
		}
	}
	return &e, nil
}

// marshalPayload encodes a payload map as JSONB-ready bytes; nil maps become "{}".
func marshalPayload(p map[string]any) ([]byte, error) {
	if p == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode audit payload: %w", err)
	}
	return b, nil
}

// joinAnd joins SQL fragments with " AND " without pulling in strings.Join uses
// elsewhere; kept local to avoid an import for one call site.
func joinAnd(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " AND "
		}
		out += p
	}
	return out
}

// Compile-time assertion that *Store satisfies storage.Storage.
var _ storage.Storage = (*Store)(nil)
