// Package postgres is the Postgres-backed storage implementation. Schema lives in /migrations.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// SQLSTATE codes mapped to storage sentinel errors.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCheckViolation      = "23514"
)

// dbtx is the small subset of pgx connection methods used by every CRUD method.
// Both *pgxpool.Pool and pgx.Tx satisfy it, which lets the same Store value run
// queries either against the pool or inside a transaction.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store is the Postgres-backed implementation of storage.Storage.
// pool is non-nil only on the root Store; transactional sub-Stores share a tx via q.
type Store struct {
	pool *pgxpool.Pool
	q    dbtx
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
	return &Store{pool: pool, q: pool}, nil
}

// Ping checks database reachability. Only meaningful on the root Store.
func (s *Store) Ping(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("postgres: ping called on transactional sub-store")
	}
	return s.pool.Ping(ctx)
}

// Close releases pool resources. pgxpool.Close is synchronous and ignores ctx.
func (s *Store) Close(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("postgres: close called on transactional sub-store")
	}
	s.pool.Close()
	return nil
}

// WithTx runs fn inside a pgx transaction. On non-nil error from fn the tx is
// rolled back. On panic the tx is rolled back and the panic is re-raised.
func (s *Store) WithTx(ctx context.Context, fn func(tx storage.Storage) error) error {
	if s.pool == nil {
		return errors.New("postgres: nested WithTx is not supported")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback(ctx)
			panic(r)
		}
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	sub := &Store{pool: nil, q: tx}
	if err := fn(sub); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit tx: %w", err)
	}
	committed = true
	return nil
}

// classifyErr maps SQLSTATE codes to storage sentinels.
func classifyErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgUniqueViolation:
			return storage.ErrAlreadyExists
		case pgForeignKeyViolation, pgCheckViolation:
			return storage.ErrConflict
		}
	}
	return err
}

// isUniqueViolation reports whether err is a Postgres unique_violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == pgUniqueViolation
	}
	return false
}

// scannable abstracts pgx.Row and pgx.Rows for a single-row scan.
type scannable interface {
	Scan(dest ...any) error
}

// idPtrToParam converts a *domain.ID to a value pgx accepts for a nullable UUID column.
func idPtrToParam(id *domain.ID) any {
	if id == nil {
		return nil
	}
	return string(*id)
}

// nullableID converts a *string scanned from a nullable UUID column into a *domain.ID.
func nullableID(s *string) *domain.ID {
	if s == nil || *s == "" {
		return nil
	}
	id := domain.ID(*s)
	return &id
}

// marshalJSON encodes v as JSONB-ready bytes; nil maps become "{}".
func marshalJSON(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	if m, ok := v.(map[string]any); ok && m == nil {
		return []byte("{}"), nil
	}
	if m, ok := v.(map[string]string); ok && m == nil {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode json: %w", err)
	}
	return b, nil
}

// -------- Products --------

const productColumns = "id, name, owner, description, created_at, updated_at"

// CreateProduct inserts a new product row.
func (s *Store) CreateProduct(ctx context.Context, p *domain.Product) error {
	const q = `
INSERT INTO products (id, name, owner, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
`
	_, err := s.q.Exec(ctx, q,
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
	row := s.q.QueryRow(ctx, q, string(id))
	return scanProduct(row)
}

// GetProductByName returns a product by its unique slug name.
func (s *Store) GetProductByName(ctx context.Context, name string) (*domain.Product, error) {
	const q = `SELECT ` + productColumns + ` FROM products WHERE name = $1`
	row := s.q.QueryRow(ctx, q, name)
	return scanProduct(row)
}

// ListProducts returns all products ordered by name for deterministic output.
func (s *Store) ListProducts(ctx context.Context) ([]*domain.Product, error) {
	const q = `SELECT ` + productColumns + ` FROM products ORDER BY name ASC`
	rows, err := s.q.Query(ctx, q)
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
	tag, err := s.q.Exec(ctx, q,
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
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete product: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
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

// AppendAuditEvent inserts an audit event with a freshly computed hash-chain
// link. From v0.2 onward every event participates in the chain.
//
// Hash-chain definition (must match migrations/0003_changesets.sql exactly):
//
//	prev = (SELECT hash FROM audit_events ORDER BY occurred_at DESC, id DESC LIMIT 1)
//	hash = sha256_hex( concat_ws('|',
//	    prev,
//	    kind,
//	    actor_kind,
//	    actor_subject,
//	    resource_type,
//	    resource_id,
//	    payload::text,           -- Postgres jsonb -> text (sorted keys)
//	    occurred_at::text        -- Postgres timestamptz -> text
//	) )
//
// The hash is computed inside the same INSERT statement using the audit_event_hash
// SQL function, so Go and SQL agree by construction. The new prev_hash and hash
// values are read back into e via RETURNING.
func (s *Store) AppendAuditEvent(ctx context.Context, e *domain.AuditEvent) error {
	payload, err := marshalJSON(e.Payload)
	if err != nil {
		return err
	}

	// Read the chain tip. With a single concurrent writer this is consistent;
	// the unique-violation path is not used here because audit ids are UUIDs.
	var prev string
	const tipQ = `SELECT COALESCE(
        (SELECT hash FROM audit_events ORDER BY occurred_at DESC, id DESC LIMIT 1),
        ''
    )`
	if err := s.q.QueryRow(ctx, tipQ).Scan(&prev); err != nil {
		return fmt.Errorf("postgres: read audit chain tip: %w", err)
	}

	const q = `
INSERT INTO audit_events (
  id, kind, actor_kind, actor_subject, resource_type, resource_id,
  payload, occurred_at, prev_hash, hash
) VALUES (
  $1, $2, $3, $4, $5, $6,
  $7::jsonb, $8, $9,
  audit_event_hash($9, $2, $3, $4, $5, $6, $7::jsonb, $8)
)
RETURNING prev_hash, hash
`
	row := s.q.QueryRow(ctx, q,
		string(e.ID),
		string(e.Kind),
		string(e.Actor.Kind),
		e.Actor.Subject,
		e.ResourceType,
		e.ResourceID,
		payload,
		e.OccurredAt,
		prev,
	)
	if err := row.Scan(&e.PrevHash, &e.Hash); err != nil {
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

	rows, err := s.q.Query(ctx, q, args...)
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

// -------- Assets --------

const assetColumns = "id, name, type, product_id, environment, labels, description, created_at, updated_at"

// CreateAsset inserts a new asset row.
func (s *Store) CreateAsset(ctx context.Context, a *domain.Asset) error {
	if a == nil {
		return storage.ErrInvalidArgument
	}
	labels, err := marshalJSON(a.Labels)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO assets (id, name, type, product_id, environment, labels, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`
	_, err = s.q.Exec(ctx, q,
		string(a.ID), a.Name, string(a.Type), string(a.ProductID),
		string(a.Environment), labels, a.Description, a.CreatedAt, a.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert asset: %w", classifyErr(err))
	}
	return nil
}

// GetAssetByID returns an asset by primary key.
func (s *Store) GetAssetByID(ctx context.Context, id domain.ID) (*domain.Asset, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + assetColumns + ` FROM assets WHERE id = $1`
	return scanAsset(s.q.QueryRow(ctx, q, string(id)))
}

// GetAssetByName returns an asset by (productID, name).
func (s *Store) GetAssetByName(ctx context.Context, productID domain.ID, name string) (*domain.Asset, error) {
	if productID == "" || name == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + assetColumns + ` FROM assets WHERE product_id = $1 AND name = $2`
	return scanAsset(s.q.QueryRow(ctx, q, string(productID), name))
}

// ListAssetsByProduct lists every asset under productID, ordered by name.
func (s *Store) ListAssetsByProduct(ctx context.Context, productID domain.ID) ([]*domain.Asset, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + assetColumns + ` FROM assets WHERE product_id = $1 ORDER BY name ASC`
	rows, err := s.q.Query(ctx, q, string(productID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list assets: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.Asset, 0)
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate assets: %w", err)
	}
	return out, nil
}

// UpdateAsset overwrites an asset row by id.
func (s *Store) UpdateAsset(ctx context.Context, a *domain.Asset) error {
	if a == nil {
		return storage.ErrInvalidArgument
	}
	labels, err := marshalJSON(a.Labels)
	if err != nil {
		return err
	}
	const q = `
UPDATE assets
   SET name = $2, type = $3, product_id = $4, environment = $5,
       labels = $6, description = $7, updated_at = $8
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q,
		string(a.ID), a.Name, string(a.Type), string(a.ProductID),
		string(a.Environment), labels, a.Description, a.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update asset: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteAsset deletes an asset by id.
func (s *Store) DeleteAsset(ctx context.Context, id domain.ID) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	const q = `DELETE FROM assets WHERE id = $1`
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete asset: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAsset(r scannable) (*domain.Asset, error) {
	var (
		id, name, typ, productID, env string
		labelsRaw                     []byte
		a                             domain.Asset
	)
	err := r.Scan(&id, &name, &typ, &productID, &env, &labelsRaw, &a.Description, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan asset: %w", err)
	}
	a.ID = domain.ID(id)
	a.Name = name
	a.Type = domain.AssetType(typ)
	a.ProductID = domain.ID(productID)
	a.Environment = domain.Environment(env)
	if len(labelsRaw) > 0 {
		if err := json.Unmarshal(labelsRaw, &a.Labels); err != nil {
			return nil, fmt.Errorf("postgres: decode asset labels: %w", err)
		}
	}
	return &a, nil
}

// -------- Asset scopes --------

const assetScopeColumns = "id, name, product_id, selector, description, created_at, updated_at"

// CreateAssetScope inserts a new asset_scope row.
func (s *Store) CreateAssetScope(ctx context.Context, sc *domain.AssetScope) error {
	if sc == nil {
		return storage.ErrInvalidArgument
	}
	selector, err := marshalJSON(sc.Selector)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO asset_scopes (id, name, product_id, selector, description, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err = s.q.Exec(ctx, q,
		string(sc.ID), sc.Name, string(sc.ProductID),
		selector, sc.Description, sc.CreatedAt, sc.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert asset_scope: %w", classifyErr(err))
	}
	return nil
}

// GetAssetScopeByID returns an asset scope by primary key.
func (s *Store) GetAssetScopeByID(ctx context.Context, id domain.ID) (*domain.AssetScope, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + assetScopeColumns + ` FROM asset_scopes WHERE id = $1`
	return scanAssetScope(s.q.QueryRow(ctx, q, string(id)))
}

// GetAssetScopeByName returns an asset scope by (productID, name).
func (s *Store) GetAssetScopeByName(ctx context.Context, productID domain.ID, name string) (*domain.AssetScope, error) {
	if productID == "" || name == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + assetScopeColumns + ` FROM asset_scopes WHERE product_id = $1 AND name = $2`
	return scanAssetScope(s.q.QueryRow(ctx, q, string(productID), name))
}

// ListAssetScopesByProduct lists every asset scope under productID, ordered by name.
func (s *Store) ListAssetScopesByProduct(ctx context.Context, productID domain.ID) ([]*domain.AssetScope, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + assetScopeColumns + ` FROM asset_scopes WHERE product_id = $1 ORDER BY name ASC`
	rows, err := s.q.Query(ctx, q, string(productID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list asset_scopes: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.AssetScope, 0)
	for rows.Next() {
		sc, err := scanAssetScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate asset_scopes: %w", err)
	}
	return out, nil
}

// UpdateAssetScope overwrites an asset_scope row by id.
func (s *Store) UpdateAssetScope(ctx context.Context, sc *domain.AssetScope) error {
	if sc == nil {
		return storage.ErrInvalidArgument
	}
	selector, err := marshalJSON(sc.Selector)
	if err != nil {
		return err
	}
	const q = `
UPDATE asset_scopes
   SET name = $2, product_id = $3, selector = $4, description = $5, updated_at = $6
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q,
		string(sc.ID), sc.Name, string(sc.ProductID),
		selector, sc.Description, sc.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update asset_scope: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteAssetScope deletes an asset_scope by id.
func (s *Store) DeleteAssetScope(ctx context.Context, id domain.ID) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	const q = `DELETE FROM asset_scopes WHERE id = $1`
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete asset_scope: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAssetScope(r scannable) (*domain.AssetScope, error) {
	var (
		id, name, productID string
		selectorRaw         []byte
		sc                  domain.AssetScope
	)
	err := r.Scan(&id, &name, &productID, &selectorRaw, &sc.Description, &sc.CreatedAt, &sc.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan asset_scope: %w", err)
	}
	sc.ID = domain.ID(id)
	sc.Name = name
	sc.ProductID = domain.ID(productID)
	if len(selectorRaw) > 0 {
		if err := json.Unmarshal(selectorRaw, &sc.Selector); err != nil {
			return nil, fmt.Errorf("postgres: decode asset_scope selector: %w", err)
		}
	}
	return &sc, nil
}

// -------- Entitlements --------

const entitlementColumns = "id, name, product_id, owner, purpose, created_at, updated_at"

// CreateEntitlement inserts a new entitlement row.
func (s *Store) CreateEntitlement(ctx context.Context, e *domain.Entitlement) error {
	if e == nil {
		return storage.ErrInvalidArgument
	}
	const q = `
INSERT INTO entitlements (id, name, product_id, owner, purpose, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err := s.q.Exec(ctx, q,
		string(e.ID), e.Name, string(e.ProductID), e.Owner, e.Purpose, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert entitlement: %w", classifyErr(err))
	}
	return nil
}

// GetEntitlementByID returns an entitlement by primary key.
func (s *Store) GetEntitlementByID(ctx context.Context, id domain.ID) (*domain.Entitlement, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + entitlementColumns + ` FROM entitlements WHERE id = $1`
	return scanEntitlement(s.q.QueryRow(ctx, q, string(id)))
}

// GetEntitlementByName returns an entitlement by (productID, name).
func (s *Store) GetEntitlementByName(ctx context.Context, productID domain.ID, name string) (*domain.Entitlement, error) {
	if productID == "" || name == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + entitlementColumns + ` FROM entitlements WHERE product_id = $1 AND name = $2`
	return scanEntitlement(s.q.QueryRow(ctx, q, string(productID), name))
}

// ListEntitlementsByProduct lists every entitlement under productID, ordered by name.
func (s *Store) ListEntitlementsByProduct(ctx context.Context, productID domain.ID) ([]*domain.Entitlement, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + entitlementColumns + ` FROM entitlements WHERE product_id = $1 ORDER BY name ASC`
	rows, err := s.q.Query(ctx, q, string(productID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list entitlements: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.Entitlement, 0)
	for rows.Next() {
		e, err := scanEntitlement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate entitlements: %w", err)
	}
	return out, nil
}

// UpdateEntitlement overwrites an entitlement row by id.
func (s *Store) UpdateEntitlement(ctx context.Context, e *domain.Entitlement) error {
	if e == nil {
		return storage.ErrInvalidArgument
	}
	const q = `
UPDATE entitlements
   SET name = $2, product_id = $3, owner = $4, purpose = $5, updated_at = $6
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q,
		string(e.ID), e.Name, string(e.ProductID), e.Owner, e.Purpose, e.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update entitlement: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteEntitlement deletes an entitlement by id.
func (s *Store) DeleteEntitlement(ctx context.Context, id domain.ID) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	const q = `DELETE FROM entitlements WHERE id = $1`
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete entitlement: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanEntitlement(r scannable) (*domain.Entitlement, error) {
	var (
		id, name, productID string
		e                   domain.Entitlement
	)
	err := r.Scan(&id, &name, &productID, &e.Owner, &e.Purpose, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan entitlement: %w", err)
	}
	e.ID = domain.ID(id)
	e.Name = name
	e.ProductID = domain.ID(productID)
	return &e, nil
}

// -------- Service accounts --------

const serviceAccountColumns = "id, name, product_id, owner, purpose, usage_pattern, created_at, updated_at"

// CreateServiceAccount inserts a new service_account row.
func (s *Store) CreateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	if sa == nil {
		return storage.ErrInvalidArgument
	}
	const q = `
INSERT INTO service_accounts (id, name, product_id, owner, purpose, usage_pattern, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`
	_, err := s.q.Exec(ctx, q,
		string(sa.ID), sa.Name, string(sa.ProductID),
		sa.Owner, sa.Purpose, string(sa.UsagePattern),
		sa.CreatedAt, sa.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert service_account: %w", classifyErr(err))
	}
	return nil
}

// GetServiceAccountByID returns a service account by primary key.
func (s *Store) GetServiceAccountByID(ctx context.Context, id domain.ID) (*domain.ServiceAccount, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + serviceAccountColumns + ` FROM service_accounts WHERE id = $1`
	return scanServiceAccount(s.q.QueryRow(ctx, q, string(id)))
}

// GetServiceAccountByName returns a service account by (productID, name).
func (s *Store) GetServiceAccountByName(ctx context.Context, productID domain.ID, name string) (*domain.ServiceAccount, error) {
	if productID == "" || name == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + serviceAccountColumns + ` FROM service_accounts WHERE product_id = $1 AND name = $2`
	return scanServiceAccount(s.q.QueryRow(ctx, q, string(productID), name))
}

// ListServiceAccountsByProduct lists every service account under productID, ordered by name.
func (s *Store) ListServiceAccountsByProduct(ctx context.Context, productID domain.ID) ([]*domain.ServiceAccount, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + serviceAccountColumns + ` FROM service_accounts WHERE product_id = $1 ORDER BY name ASC`
	rows, err := s.q.Query(ctx, q, string(productID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list service_accounts: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.ServiceAccount, 0)
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate service_accounts: %w", err)
	}
	return out, nil
}

// UpdateServiceAccount overwrites a service_account row by id.
func (s *Store) UpdateServiceAccount(ctx context.Context, sa *domain.ServiceAccount) error {
	if sa == nil {
		return storage.ErrInvalidArgument
	}
	const q = `
UPDATE service_accounts
   SET name = $2, product_id = $3, owner = $4, purpose = $5, usage_pattern = $6, updated_at = $7
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q,
		string(sa.ID), sa.Name, string(sa.ProductID),
		sa.Owner, sa.Purpose, string(sa.UsagePattern), sa.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update service_account: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteServiceAccount deletes a service_account by id.
func (s *Store) DeleteServiceAccount(ctx context.Context, id domain.ID) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	const q = `DELETE FROM service_accounts WHERE id = $1`
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete service_account: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanServiceAccount(r scannable) (*domain.ServiceAccount, error) {
	var (
		id, name, productID, usage string
		sa                         domain.ServiceAccount
	)
	err := r.Scan(&id, &name, &productID, &sa.Owner, &sa.Purpose, &usage, &sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan service_account: %w", err)
	}
	sa.ID = domain.ID(id)
	sa.Name = name
	sa.ProductID = domain.ID(productID)
	sa.UsagePattern = domain.UsagePattern(usage)
	return &sa, nil
}

// -------- Global objects --------

const globalObjectColumns = "id, name, type, product_id, spec, created_at, updated_at"

// CreateGlobalObject inserts a new global_object row.
func (s *Store) CreateGlobalObject(ctx context.Context, g *domain.GlobalObject) error {
	if g == nil {
		return storage.ErrInvalidArgument
	}
	spec, err := marshalJSON(g.Spec)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO global_objects (id, name, type, product_id, spec, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err = s.q.Exec(ctx, q,
		string(g.ID), g.Name, string(g.Type),
		idPtrToParam(g.ProductID), spec, g.CreatedAt, g.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert global_object: %w", classifyErr(err))
	}
	return nil
}

// GetGlobalObjectByID returns a global object by primary key.
func (s *Store) GetGlobalObjectByID(ctx context.Context, id domain.ID) (*domain.GlobalObject, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + globalObjectColumns + ` FROM global_objects WHERE id = $1`
	return scanGlobalObject(s.q.QueryRow(ctx, q, string(id)))
}

// GetGlobalObjectByName returns a global object by (productID, name). Pass productID = nil
// to look up a cross-product (NULL product_id) object.
func (s *Store) GetGlobalObjectByName(ctx context.Context, productID *domain.ID, name string) (*domain.GlobalObject, error) {
	if name == "" {
		return nil, storage.ErrInvalidArgument
	}
	if productID == nil {
		const q = `SELECT ` + globalObjectColumns + ` FROM global_objects WHERE product_id IS NULL AND name = $1`
		return scanGlobalObject(s.q.QueryRow(ctx, q, name))
	}
	const q = `SELECT ` + globalObjectColumns + ` FROM global_objects WHERE product_id = $1 AND name = $2`
	return scanGlobalObject(s.q.QueryRow(ctx, q, string(*productID), name))
}

// ListGlobalObjectsByProduct lists global objects scoped to productID. Pass nil to list
// cross-product (NULL product_id) objects.
func (s *Store) ListGlobalObjectsByProduct(ctx context.Context, productID *domain.ID) ([]*domain.GlobalObject, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if productID == nil {
		const q = `SELECT ` + globalObjectColumns + ` FROM global_objects WHERE product_id IS NULL ORDER BY name ASC`
		rows, err = s.q.Query(ctx, q)
	} else {
		const q = `SELECT ` + globalObjectColumns + ` FROM global_objects WHERE product_id = $1 ORDER BY name ASC`
		rows, err = s.q.Query(ctx, q, string(*productID))
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: list global_objects: %w", err)
	}
	defer rows.Close()
	return collectGlobalObjects(rows)
}

// ListAllGlobalObjects lists every global object regardless of product scope.
func (s *Store) ListAllGlobalObjects(ctx context.Context) ([]*domain.GlobalObject, error) {
	const q = `SELECT ` + globalObjectColumns + ` FROM global_objects ORDER BY name ASC, id ASC`
	rows, err := s.q.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres: list all global_objects: %w", err)
	}
	defer rows.Close()
	return collectGlobalObjects(rows)
}

func collectGlobalObjects(rows pgx.Rows) ([]*domain.GlobalObject, error) {
	out := make([]*domain.GlobalObject, 0)
	for rows.Next() {
		g, err := scanGlobalObject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate global_objects: %w", err)
	}
	return out, nil
}

// UpdateGlobalObject overwrites a global_object row by id.
func (s *Store) UpdateGlobalObject(ctx context.Context, g *domain.GlobalObject) error {
	if g == nil {
		return storage.ErrInvalidArgument
	}
	spec, err := marshalJSON(g.Spec)
	if err != nil {
		return err
	}
	const q = `
UPDATE global_objects
   SET name = $2, type = $3, product_id = $4, spec = $5, updated_at = $6
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q,
		string(g.ID), g.Name, string(g.Type),
		idPtrToParam(g.ProductID), spec, g.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: update global_object: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// DeleteGlobalObject deletes a global_object by id.
func (s *Store) DeleteGlobalObject(ctx context.Context, id domain.ID) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	const q = `DELETE FROM global_objects WHERE id = $1`
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete global_object: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanGlobalObject(r scannable) (*domain.GlobalObject, error) {
	var (
		id, name, typ string
		productID     *string
		specRaw       []byte
		g             domain.GlobalObject
	)
	err := r.Scan(&id, &name, &typ, &productID, &specRaw, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan global_object: %w", err)
	}
	g.ID = domain.ID(id)
	g.Name = name
	g.Type = domain.GlobalObjectType(typ)
	g.ProductID = nullableID(productID)
	if len(specRaw) > 0 {
		if err := json.Unmarshal(specRaw, &g.Spec); err != nil {
			return nil, fmt.Errorf("postgres: decode global_object spec: %w", err)
		}
	}
	return &g, nil
}

// -------- Authorizations --------

const authorizationColumns = "id, parent_kind, parent_id, type, asset_scope_id, global_object_id, spec, created_at, updated_at"

// CreateAuthorization inserts a new authorization row. Authorizations have no
// Update operation: the importer deletes and recreates rows when re-syncing.
func (s *Store) CreateAuthorization(ctx context.Context, a *domain.Authorization) error {
	if a == nil {
		return storage.ErrInvalidArgument
	}
	spec, err := marshalJSON(a.Spec)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO authorizations (id, parent_kind, parent_id, type, asset_scope_id, global_object_id, spec, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`
	_, err = s.q.Exec(ctx, q,
		string(a.ID), string(a.ParentKind), string(a.ParentID), string(a.Type),
		idPtrToParam(a.AssetScopeID), idPtrToParam(a.GlobalObjectID),
		spec, a.CreatedAt, a.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("postgres: insert authorization: %w", classifyErr(err))
	}
	return nil
}

// GetAuthorizationByID returns an authorization by primary key.
func (s *Store) GetAuthorizationByID(ctx context.Context, id domain.ID) (*domain.Authorization, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + authorizationColumns + ` FROM authorizations WHERE id = $1`
	return scanAuthorization(s.q.QueryRow(ctx, q, string(id)))
}

// ListAuthorizationsByParent returns every authorization hung off (parentKind, parentID),
// ordered by created_at ASC, id ASC for deterministic output.
func (s *Store) ListAuthorizationsByParent(ctx context.Context, parentKind domain.AuthorizationParentKind, parentID domain.ID) ([]*domain.Authorization, error) {
	if parentKind == "" || parentID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `
SELECT ` + authorizationColumns + `
  FROM authorizations
 WHERE parent_kind = $1 AND parent_id = $2
 ORDER BY created_at ASC, id ASC
`
	rows, err := s.q.Query(ctx, q, string(parentKind), string(parentID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list authorizations: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.Authorization, 0)
	for rows.Next() {
		a, err := scanAuthorization(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate authorizations: %w", err)
	}
	return out, nil
}

// DeleteAuthorization deletes an authorization by id.
func (s *Store) DeleteAuthorization(ctx context.Context, id domain.ID) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	const q = `DELETE FROM authorizations WHERE id = $1`
	tag, err := s.q.Exec(ctx, q, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete authorization: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAuthorization(r scannable) (*domain.Authorization, error) {
	var (
		id, parentKind, parentID, typ string
		assetScopeID, globalObjectID  *string
		specRaw                       []byte
		a                             domain.Authorization
	)
	err := r.Scan(&id, &parentKind, &parentID, &typ, &assetScopeID, &globalObjectID, &specRaw, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan authorization: %w", err)
	}
	a.ID = domain.ID(id)
	a.ParentKind = domain.AuthorizationParentKind(parentKind)
	a.ParentID = domain.ID(parentID)
	a.Type = domain.AuthorizationType(typ)
	a.AssetScopeID = nullableID(assetScopeID)
	a.GlobalObjectID = nullableID(globalObjectID)
	if len(specRaw) > 0 {
		if err := json.Unmarshal(specRaw, &a.Spec); err != nil {
			return nil, fmt.Errorf("postgres: decode authorization spec: %w", err)
		}
	}
	return &a, nil
}

// -------- Change sets --------

const changeSetColumns = "id, product_id, state, parent_approved_version_id, title, description, " +
	"requested_by_kind, requested_by_subject, submitted_at, decided_at, decision_reason, created_at, updated_at"

// nullableJSONParam returns a value safe to bind to a JSONB column that allows
// NULL. A nil map encodes as SQL NULL; a non-nil map encodes as canonical JSON
// bytes (which Postgres accepts for jsonb).
func nullableJSONParam(m map[string]any) (any, error) {
	if m == nil {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode nullable json: %w", err)
	}
	return b, nil
}

// CreateChangeSet inserts a new change_sets row.
func (s *Store) CreateChangeSet(ctx context.Context, cs *domain.ChangeSet) error {
	if cs == nil {
		return storage.ErrInvalidArgument
	}
	const q = `
INSERT INTO change_sets (
  id, product_id, state, parent_approved_version_id, title, description,
  requested_by_kind, requested_by_subject, submitted_at, decided_at, decision_reason,
  created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
`
	_, err := s.q.Exec(ctx, q,
		string(cs.ID),
		string(cs.ProductID),
		string(cs.State),
		idPtrToParam(cs.ParentApprovedVersionID),
		cs.Title,
		cs.Description,
		string(cs.RequestedBy.Kind),
		cs.RequestedBy.Subject,
		cs.SubmittedAt,
		cs.DecidedAt,
		cs.DecisionReason,
		cs.CreatedAt,
		cs.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: insert change_set: %w", classifyErr(err))
	}
	return nil
}

// GetChangeSetByID returns a change set by primary key.
func (s *Store) GetChangeSetByID(ctx context.Context, id domain.ID) (*domain.ChangeSet, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + changeSetColumns + ` FROM change_sets WHERE id = $1`
	return scanChangeSet(s.q.QueryRow(ctx, q, string(id)))
}

// ListChangeSets returns change sets matching filter, newest first.
func (s *Store) ListChangeSets(ctx context.Context, f storage.ChangeSetFilter) ([]*domain.ChangeSet, error) {
	q := `SELECT ` + changeSetColumns + ` FROM change_sets`
	args := make([]any, 0, 3)
	clauses := make([]string, 0, 2)

	if f.ProductID != nil {
		args = append(args, string(*f.ProductID))
		clauses = append(clauses, fmt.Sprintf("product_id = $%d", len(args)))
	}
	if f.State != nil {
		args = append(args, string(*f.State))
		clauses = append(clauses, fmt.Sprintf("state = $%d", len(args)))
	}
	if len(clauses) > 0 {
		q += " WHERE " + joinAnd(clauses)
	}
	q += " ORDER BY created_at DESC, id ASC"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := s.q.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list change_sets: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.ChangeSet, 0)
	for rows.Next() {
		cs, err := scanChangeSet(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate change_sets: %w", err)
	}
	return out, nil
}

// UpdateChangeSetState transitions a change set's lifecycle state. Callers
// pre-validate the transition via domain.ChangeSetState.CanTransitionTo;
// this method enforces no SQL-level state-machine. It updates submitted_at
// implicitly when newState == 'submitted' and decided_at when newState is a
// terminal state. Returns ErrNotFound if no row matches id.
func (s *Store) UpdateChangeSetState(ctx context.Context, id domain.ID, newState domain.ChangeSetState, decidedAt *time.Time, decisionReason string) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	now := time.Now().UTC()

	// Decide which timestamp column to populate. Submitted -> submitted_at.
	// Approved/rejected/conflicted -> decided_at. Draft -> neither.
	var (
		setSubmittedAt *time.Time
		setDecidedAt   *time.Time
	)
	switch newState {
	case domain.ChangeSetStateSubmitted:
		t := now
		if decidedAt != nil {
			t = decidedAt.UTC()
		}
		setSubmittedAt = &t
	case domain.ChangeSetStateApproved,
		domain.ChangeSetStateRejected,
		domain.ChangeSetStateConflicted:
		t := now
		if decidedAt != nil {
			t = decidedAt.UTC()
		}
		setDecidedAt = &t
	}

	const q = `
UPDATE change_sets
   SET state           = $2,
       submitted_at    = COALESCE($3, submitted_at),
       decided_at      = COALESCE($4, decided_at),
       decision_reason = CASE WHEN $5 <> '' THEN $5 ELSE decision_reason END,
       updated_at      = $6
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q,
		string(id),
		string(newState),
		setSubmittedAt,
		setDecidedAt,
		decisionReason,
		now,
	)
	if err != nil {
		return fmt.Errorf("postgres: update change_set state: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// AppendChangeSetItem inserts an item under an existing change set.
func (s *Store) AppendChangeSetItem(ctx context.Context, item *domain.ChangeSetItem) error {
	if item == nil {
		return storage.ErrInvalidArgument
	}
	beforeParam, err := nullableJSONParam(item.Before)
	if err != nil {
		return err
	}
	afterParam, err := nullableJSONParam(item.After)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO change_set_items (
  id, change_set_id, kind, action, resource_name, before, after, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`
	_, err = s.q.Exec(ctx, q,
		string(item.ID),
		string(item.ChangeSetID),
		string(item.Kind),
		string(item.Action),
		item.ResourceName,
		beforeParam,
		afterParam,
		item.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: insert change_set_item: %w", classifyErr(err))
	}
	return nil
}

// ListChangeSetItems returns every item under csID, ordered by created_at ASC.
func (s *Store) ListChangeSetItems(ctx context.Context, csID domain.ID) ([]*domain.ChangeSetItem, error) {
	if csID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `
SELECT id, change_set_id, kind, action, resource_name, before, after, created_at
  FROM change_set_items
 WHERE change_set_id = $1
 ORDER BY created_at ASC, id ASC
`
	rows, err := s.q.Query(ctx, q, string(csID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list change_set_items: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.ChangeSetItem, 0)
	for rows.Next() {
		it, err := scanChangeSetItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate change_set_items: %w", err)
	}
	return out, nil
}

func scanChangeSet(r scannable) (*domain.ChangeSet, error) {
	var (
		id, productID, state              string
		parentApprovedVersionID           *string
		title, description                string
		requestedByKind, requestedBySubj  string
		submittedAt, decidedAt            *time.Time
		decisionReason                    string
		createdAt, updatedAt              time.Time
	)
	err := r.Scan(
		&id, &productID, &state,
		&parentApprovedVersionID,
		&title, &description,
		&requestedByKind, &requestedBySubj,
		&submittedAt, &decidedAt,
		&decisionReason,
		&createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan change_set: %w", err)
	}
	return &domain.ChangeSet{
		ID:                      domain.ID(id),
		ProductID:               domain.ID(productID),
		State:                   domain.ChangeSetState(state),
		ParentApprovedVersionID: nullableID(parentApprovedVersionID),
		Title:                   title,
		Description:             description,
		RequestedBy: domain.Actor{
			Kind:    domain.ActorKind(requestedByKind),
			Subject: requestedBySubj,
		},
		SubmittedAt:    submittedAt,
		DecidedAt:      decidedAt,
		DecisionReason: decisionReason,
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
	}, nil
}

func scanChangeSetItem(r scannable) (*domain.ChangeSetItem, error) {
	var (
		id, csID, kind, action string
		resourceName           string
		beforeRaw, afterRaw    []byte
		createdAt              time.Time
	)
	err := r.Scan(&id, &csID, &kind, &action, &resourceName, &beforeRaw, &afterRaw, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan change_set_item: %w", err)
	}
	it := &domain.ChangeSetItem{
		ID:           domain.ID(id),
		ChangeSetID:  domain.ID(csID),
		Kind:         domain.ChangeSetItemKind(kind),
		Action:       domain.ChangeSetAction(action),
		ResourceName: resourceName,
		CreatedAt:    createdAt,
	}
	if len(beforeRaw) > 0 {
		if err := json.Unmarshal(beforeRaw, &it.Before); err != nil {
			return nil, fmt.Errorf("postgres: decode change_set_item before: %w", err)
		}
	}
	if len(afterRaw) > 0 {
		if err := json.Unmarshal(afterRaw, &it.After); err != nil {
			return nil, fmt.Errorf("postgres: decode change_set_item after: %w", err)
		}
	}
	return it, nil
}

// -------- Approvals --------

const approvalColumns = "id, change_set_id, approver_kind, approver_subject, decision, reason, decided_at"

// CreateApproval inserts a new approvals row.
func (s *Store) CreateApproval(ctx context.Context, a *domain.Approval) error {
	if a == nil {
		return storage.ErrInvalidArgument
	}
	const q = `
INSERT INTO approvals (id, change_set_id, approver_kind, approver_subject, decision, reason, decided_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
`
	_, err := s.q.Exec(ctx, q,
		string(a.ID),
		string(a.ChangeSetID),
		string(a.Approver.Kind),
		a.Approver.Subject,
		string(a.Decision),
		a.Reason,
		a.DecidedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: insert approval: %w", classifyErr(err))
	}
	return nil
}

// ListApprovalsByChangeSet returns approvals for csID, newest first.
func (s *Store) ListApprovalsByChangeSet(ctx context.Context, csID domain.ID) ([]*domain.Approval, error) {
	if csID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `
SELECT ` + approvalColumns + `
  FROM approvals
 WHERE change_set_id = $1
 ORDER BY decided_at DESC, id ASC
`
	rows, err := s.q.Query(ctx, q, string(csID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list approvals: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.Approval, 0)
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate approvals: %w", err)
	}
	return out, nil
}

func scanApproval(r scannable) (*domain.Approval, error) {
	var (
		id, csID, approverKind, approverSubj, decision, reason string
		decidedAt                                              time.Time
	)
	err := r.Scan(&id, &csID, &approverKind, &approverSubj, &decision, &reason, &decidedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan approval: %w", err)
	}
	return &domain.Approval{
		ID:          domain.ID(id),
		ChangeSetID: domain.ID(csID),
		Approver: domain.Actor{
			Kind:    domain.ActorKind(approverKind),
			Subject: approverSubj,
		},
		Decision:  domain.ApprovalDecision(decision),
		Reason:    reason,
		DecidedAt: decidedAt,
	}, nil
}

// -------- Approved versions --------

const approvedVersionColumns = "id, product_id, sequence, parent_version_id, source_change_set_id, " +
	"snapshot_id, approved_by_kind, approved_by_subject, description, created_at"

const approvedVersionSnapshotColumns = "id, content, content_hash, created_at"

// CreateApprovedVersion atomically inserts the snapshot and the version that
// references it. If a snapshot with the same content_hash already exists its
// row is reused (snap.ID is rewritten to the existing id). Both writes happen
// inside a tx; if s.q is already a tx the existing tx is used, otherwise a
// short-lived local tx wraps both inserts.
func (s *Store) CreateApprovedVersion(ctx context.Context, av *domain.ApprovedVersion, snap *domain.ApprovedVersionSnapshot) error {
	if av == nil || snap == nil {
		return storage.ErrInvalidArgument
	}
	if s.pool == nil {
		// already inside a tx
		return s.createApprovedVersion(ctx, av, snap)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres: begin approved version tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	sub := &Store{pool: nil, q: tx}
	if err := sub.createApprovedVersion(ctx, av, snap); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit approved version tx: %w", err)
	}
	committed = true
	return nil
}

func (s *Store) createApprovedVersion(ctx context.Context, av *domain.ApprovedVersion, snap *domain.ApprovedVersionSnapshot) error {
	contentBytes, err := json.Marshal(snap.Content)
	if err != nil {
		return fmt.Errorf("postgres: encode snapshot content: %w", err)
	}

	// Insert-or-reuse on content_hash. ON CONFLICT does nothing; a follow-up
	// SELECT picks up the canonical id and timestamp regardless of which path
	// we took.
	const upsertSnap = `
INSERT INTO approved_version_snapshots (id, content, content_hash, created_at)
VALUES ($1, $2::jsonb, $3, $4)
ON CONFLICT (content_hash) DO NOTHING
`
	if _, err := s.q.Exec(ctx, upsertSnap,
		string(snap.ID), contentBytes, snap.ContentHash, snap.CreatedAt,
	); err != nil {
		return fmt.Errorf("postgres: upsert approved_version_snapshot: %w", classifyErr(err))
	}

	const fetchSnap = `SELECT id, created_at FROM approved_version_snapshots WHERE content_hash = $1`
	var (
		canonicalID string
		canonicalAt time.Time
	)
	if err := s.q.QueryRow(ctx, fetchSnap, snap.ContentHash).Scan(&canonicalID, &canonicalAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storage.ErrNotFound
		}
		return fmt.Errorf("postgres: fetch approved_version_snapshot: %w", err)
	}
	snap.ID = domain.ID(canonicalID)
	snap.CreatedAt = canonicalAt
	av.SnapshotID = snap.ID

	const insertVersion = `
INSERT INTO approved_versions (
  id, product_id, sequence, parent_version_id, source_change_set_id, snapshot_id,
  approved_by_kind, approved_by_subject, description, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`
	if _, err := s.q.Exec(ctx, insertVersion,
		string(av.ID),
		string(av.ProductID),
		av.Sequence,
		idPtrToParam(av.ParentVersionID),
		string(av.SourceChangeSetID),
		string(av.SnapshotID),
		string(av.ApprovedBy.Kind),
		av.ApprovedBy.Subject,
		av.Description,
		av.CreatedAt,
	); err != nil {
		if isUniqueViolation(err) {
			return storage.ErrAlreadyExists
		}
		return fmt.Errorf("postgres: insert approved_version: %w", classifyErr(err))
	}
	return nil
}

// GetLatestApprovedVersion returns the highest-sequence approved version for
// productID and its snapshot. ErrNotFound if the product has none.
func (s *Store) GetLatestApprovedVersion(ctx context.Context, productID domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error) {
	if productID == "" {
		return nil, nil, storage.ErrInvalidArgument
	}
	const q = `
SELECT ` + approvedVersionColumns + `
  FROM approved_versions
 WHERE product_id = $1
 ORDER BY sequence DESC
 LIMIT 1
`
	av, err := scanApprovedVersion(s.q.QueryRow(ctx, q, string(productID)))
	if err != nil {
		return nil, nil, err
	}
	snap, err := s.getSnapshotByID(ctx, av.SnapshotID)
	if err != nil {
		return nil, nil, err
	}
	return av, snap, nil
}

// GetApprovedVersionByID returns one approved version and its snapshot.
func (s *Store) GetApprovedVersionByID(ctx context.Context, id domain.ID) (*domain.ApprovedVersion, *domain.ApprovedVersionSnapshot, error) {
	if id == "" {
		return nil, nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + approvedVersionColumns + ` FROM approved_versions WHERE id = $1`
	av, err := scanApprovedVersion(s.q.QueryRow(ctx, q, string(id)))
	if err != nil {
		return nil, nil, err
	}
	snap, err := s.getSnapshotByID(ctx, av.SnapshotID)
	if err != nil {
		return nil, nil, err
	}
	return av, snap, nil
}

// ListApprovedVersions returns approved versions for productID, newest first.
// limit <= 0 means no limit.
func (s *Store) ListApprovedVersions(ctx context.Context, productID domain.ID, limit int) ([]*domain.ApprovedVersion, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	q := `
SELECT ` + approvedVersionColumns + `
  FROM approved_versions
 WHERE product_id = $1
 ORDER BY sequence DESC
`
	args := []any{string(productID)}
	if limit > 0 {
		args = append(args, limit)
		q += " LIMIT $2"
	}
	rows, err := s.q.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list approved_versions: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.ApprovedVersion, 0)
	for rows.Next() {
		av, err := scanApprovedVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, av)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate approved_versions: %w", err)
	}
	return out, nil
}

// NextSequenceForProduct returns max(sequence)+1, or 1 if there is no prior
// version. Concurrency is resolved by the unique (product_id, sequence)
// constraint at insert time; callers retry on storage.ErrAlreadyExists.
func (s *Store) NextSequenceForProduct(ctx context.Context, productID domain.ID) (int64, error) {
	if productID == "" {
		return 0, storage.ErrInvalidArgument
	}
	const q = `SELECT COALESCE(MAX(sequence), 0) + 1 FROM approved_versions WHERE product_id = $1`
	var next int64
	if err := s.q.QueryRow(ctx, q, string(productID)).Scan(&next); err != nil {
		return 0, fmt.Errorf("postgres: next sequence: %w", err)
	}
	return next, nil
}

func (s *Store) getSnapshotByID(ctx context.Context, id domain.ID) (*domain.ApprovedVersionSnapshot, error) {
	const q = `SELECT ` + approvedVersionSnapshotColumns + ` FROM approved_version_snapshots WHERE id = $1`
	return scanApprovedVersionSnapshot(s.q.QueryRow(ctx, q, string(id)))
}

func scanApprovedVersion(r scannable) (*domain.ApprovedVersion, error) {
	var (
		id, productID, sourceCS, snapshotID string
		parentVersionID                     *string
		sequence                            int64
		approvedByKind, approvedBySubj      string
		description                         string
		createdAt                           time.Time
	)
	err := r.Scan(
		&id, &productID, &sequence, &parentVersionID, &sourceCS, &snapshotID,
		&approvedByKind, &approvedBySubj, &description, &createdAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan approved_version: %w", err)
	}
	return &domain.ApprovedVersion{
		ID:                domain.ID(id),
		ProductID:         domain.ID(productID),
		Sequence:          sequence,
		ParentVersionID:   nullableID(parentVersionID),
		SourceChangeSetID: domain.ID(sourceCS),
		SnapshotID:        domain.ID(snapshotID),
		ApprovedBy: domain.Actor{
			Kind:    domain.ActorKind(approvedByKind),
			Subject: approvedBySubj,
		},
		Description: description,
		CreatedAt:   createdAt,
	}, nil
}

func scanApprovedVersionSnapshot(r scannable) (*domain.ApprovedVersionSnapshot, error) {
	var (
		id, contentHash string
		contentRaw      []byte
		createdAt       time.Time
	)
	err := r.Scan(&id, &contentRaw, &contentHash, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan approved_version_snapshot: %w", err)
	}
	snap := &domain.ApprovedVersionSnapshot{
		ID:          domain.ID(id),
		ContentHash: contentHash,
		CreatedAt:   createdAt,
	}
	if len(contentRaw) > 0 {
		if err := json.Unmarshal(contentRaw, &snap.Content); err != nil {
			return nil, fmt.Errorf("postgres: decode approved_version_snapshot content: %w", err)
		}
	}
	return snap, nil
}

// -------- Policy decisions --------

const policyDecisionColumns = "id, change_set_id, phase, outcome, rules, input, bundle_hash, evaluated_at, created_at"

// validPolicyPhases / validPolicyOutcomes mirror the CHECK constraints in
// migrations/0004_policy_decisions.sql. Validating in Go gives callers a clean
// ErrInvalidArgument up front instead of a Postgres CHECK violation.
var (
	validPolicyPhases   = map[string]struct{}{"submit": {}, "approve": {}}
	validPolicyOutcomes = map[string]struct{}{"allow": {}, "deny": {}, "escalate_required": {}}
)

// AppendPolicyDecision inserts a single OPA decision row. The Rules and Input
// fields are bound as JSONB. A change_set_id that does not reference an
// existing change_sets row produces ErrChangeSetNotFound. The CreatedAt field
// is populated by the database default and read back via RETURNING.
func (s *Store) AppendPolicyDecision(ctx context.Context, rec *storage.PolicyDecisionRecord) error {
	if rec == nil {
		return storage.ErrInvalidArgument
	}
	if rec.ID == "" || rec.ChangeSetID == "" {
		return storage.ErrInvalidArgument
	}
	idStr, err := canonicalUUID(string(rec.ID))
	if err != nil {
		return fmt.Errorf("%w: policy decision id: %v", storage.ErrInvalidArgument, err)
	}
	csIDStr, err := canonicalUUID(string(rec.ChangeSetID))
	if err != nil {
		return fmt.Errorf("%w: change set id: %v", storage.ErrInvalidArgument, err)
	}
	if _, ok := validPolicyPhases[rec.Phase]; !ok {
		return fmt.Errorf("%w: policy decision phase %q", storage.ErrInvalidArgument, rec.Phase)
	}
	if _, ok := validPolicyOutcomes[rec.Outcome]; !ok {
		return fmt.Errorf("%w: policy decision outcome %q", storage.ErrInvalidArgument, rec.Outcome)
	}
	if rec.BundleHash == "" {
		return fmt.Errorf("%w: policy decision bundle hash", storage.ErrInvalidArgument)
	}

	rules := jsonOrNullObject(rec.Rules)
	input := jsonOrNullObject(rec.Input)

	if rec.EvaluatedAt.IsZero() {
		rec.EvaluatedAt = time.Now().UTC()
	}

	const q = `
INSERT INTO policy_decisions (
  id, change_set_id, phase, outcome, rules, input, bundle_hash, evaluated_at
) VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
RETURNING created_at
`
	row := s.q.QueryRow(ctx, q,
		idStr,
		csIDStr,
		rec.Phase,
		rec.Outcome,
		rules,
		input,
		rec.BundleHash,
		rec.EvaluatedAt,
	)
	if err := row.Scan(&rec.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgForeignKeyViolation:
				return fmt.Errorf("%w: %s", storage.ErrChangeSetNotFound, pgErr.ConstraintName)
			case pgUniqueViolation:
				return storage.ErrAlreadyExists
			}
		}
		return fmt.Errorf("postgres: insert policy_decision: %w", err)
	}
	// Echo the canonical ids back so the caller's record matches what is on disk.
	rec.ID = domain.ID(idStr)
	rec.ChangeSetID = domain.ID(csIDStr)
	return nil
}

// ListPolicyDecisionsByChangeSet returns every decision for csID, newest first.
// An empty slice is returned (not an error) when there are no rows.
func (s *Store) ListPolicyDecisionsByChangeSet(ctx context.Context, csID domain.ID) ([]*storage.PolicyDecisionRecord, error) {
	if csID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `
SELECT ` + policyDecisionColumns + `
  FROM policy_decisions
 WHERE change_set_id = $1
 ORDER BY evaluated_at DESC, id DESC
`
	rows, err := s.q.Query(ctx, q, string(csID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list policy_decisions: %w", err)
	}
	defer rows.Close()

	out := make([]*storage.PolicyDecisionRecord, 0)
	for rows.Next() {
		rec, err := scanPolicyDecision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate policy_decisions: %w", err)
	}
	return out, nil
}

// GetPolicyDecisionByID returns the decision identified by id, or
// ErrPolicyDecisionNotFound if no row matches.
func (s *Store) GetPolicyDecisionByID(ctx context.Context, id domain.ID) (*storage.PolicyDecisionRecord, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + policyDecisionColumns + ` FROM policy_decisions WHERE id = $1`
	rec, err := scanPolicyDecision(s.q.QueryRow(ctx, q, string(id)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrPolicyDecisionNotFound
		}
		return nil, err
	}
	return rec, nil
}

func scanPolicyDecision(r scannable) (*storage.PolicyDecisionRecord, error) {
	var (
		id, csID, phase, outcome, bundleHash string
		rulesRaw, inputRaw                   []byte
		evaluatedAt, createdAt               time.Time
	)
	err := r.Scan(&id, &csID, &phase, &outcome, &rulesRaw, &inputRaw, &bundleHash, &evaluatedAt, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan policy_decision: %w", err)
	}
	rec := &storage.PolicyDecisionRecord{
		ID:          domain.ID(id),
		ChangeSetID: domain.ID(csID),
		Phase:       phase,
		Outcome:     outcome,
		BundleHash:  bundleHash,
		EvaluatedAt: evaluatedAt,
		CreatedAt:   createdAt,
	}
	if len(rulesRaw) > 0 {
		rec.Rules = json.RawMessage(append([]byte(nil), rulesRaw...))
	}
	if len(inputRaw) > 0 {
		rec.Input = json.RawMessage(append([]byte(nil), inputRaw...))
	}
	return rec, nil
}

// -------- Evidence packs --------

const evidencePackColumns = "id, product_id, approved_version_id, sequence, format, " +
	"content_hash, content, generated_at, generated_by_kind, generated_by_subject"

// validEvidencePackFormats mirrors the CHECK constraint in
// migrations/0005_evidence_packs.sql. Validating in Go gives callers a clean
// ErrInvalidArgument up front instead of a Postgres CHECK violation.
var validEvidencePackFormats = map[string]struct{}{
	"json":     {},
	"markdown": {},
}

// AppendEvidencePack inserts a single evidence pack row. The Content field is
// bound as JSONB. INSERT ... ON CONFLICT (approved_version_id, format,
// content_hash) DO NOTHING makes deterministic re-exports a no-op: callers
// that want to detect re-use can follow up with a Get.
//
// FK violations on product_id / approved_version_id surface as ErrNotFound so
// callers can distinguish a stale reference from a transient failure.
func (s *Store) AppendEvidencePack(ctx context.Context, pack *domain.EvidencePack) error {
	if pack == nil {
		return storage.ErrInvalidArgument
	}
	if pack.ID == "" {
		return fmt.Errorf("%w: evidence pack id", storage.ErrInvalidArgument)
	}
	if pack.ProductID == "" {
		return fmt.Errorf("%w: evidence pack product id", storage.ErrInvalidArgument)
	}
	if pack.ApprovedVersionID == "" {
		return fmt.Errorf("%w: evidence pack approved version id", storage.ErrInvalidArgument)
	}
	if pack.Sequence < 1 {
		return fmt.Errorf("%w: evidence pack sequence", storage.ErrInvalidArgument)
	}
	if _, ok := validEvidencePackFormats[pack.Format]; !ok {
		return fmt.Errorf("%w: evidence pack format %q", storage.ErrInvalidArgument, pack.Format)
	}
	if pack.ContentHash == "" {
		return fmt.Errorf("%w: evidence pack content hash", storage.ErrInvalidArgument)
	}
	if len(pack.Content) == 0 {
		return fmt.Errorf("%w: evidence pack content", storage.ErrInvalidArgument)
	}
	if err := pack.GeneratedBy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", storage.ErrInvalidArgument, err)
	}
	if pack.GeneratedAt.IsZero() {
		pack.GeneratedAt = time.Now().UTC()
	}

	const q = `
INSERT INTO evidence_packs (
  id, product_id, approved_version_id, sequence, format,
  content_hash, content, generated_at, generated_by_kind, generated_by_subject
) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
ON CONFLICT (approved_version_id, format, content_hash) DO NOTHING
`
	_, err := s.q.Exec(ctx, q,
		string(pack.ID),
		string(pack.ProductID),
		string(pack.ApprovedVersionID),
		pack.Sequence,
		pack.Format,
		pack.ContentHash,
		[]byte(pack.Content),
		pack.GeneratedAt,
		string(pack.GeneratedBy.Kind),
		pack.GeneratedBy.Subject,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgForeignKeyViolation:
				return fmt.Errorf("%w: %s", storage.ErrNotFound, pgErr.ConstraintName)
			case pgCheckViolation:
				return fmt.Errorf("%w: %s", storage.ErrInvalidArgument, pgErr.ConstraintName)
			}
		}
		return fmt.Errorf("postgres: insert evidence_pack: %w", err)
	}
	return nil
}

// GetEvidencePackByID returns the pack identified by id, or
// ErrEvidencePackNotFound if absent.
func (s *Store) GetEvidencePackByID(ctx context.Context, id domain.ID) (*domain.EvidencePack, error) {
	if id == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `SELECT ` + evidencePackColumns + ` FROM evidence_packs WHERE id = $1`
	pack, err := scanEvidencePack(s.q.QueryRow(ctx, q, string(id)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrEvidencePackNotFound
		}
		return nil, err
	}
	return pack, nil
}

// ListEvidencePacksByProduct returns packs for productID newest first.
// limit <= 0 means no limit. An empty slice (not an error) is returned when
// the product has no packs.
func (s *Store) ListEvidencePacksByProduct(ctx context.Context, productID domain.ID, limit int) ([]*domain.EvidencePack, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	q := `
SELECT ` + evidencePackColumns + `
  FROM evidence_packs
 WHERE product_id = $1
 ORDER BY generated_at DESC, id DESC
`
	args := []any{string(productID)}
	if limit > 0 {
		args = append(args, limit)
		q += " LIMIT $2"
	}
	rows, err := s.q.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list evidence_packs: %w", err)
	}
	defer rows.Close()

	out := make([]*domain.EvidencePack, 0)
	for rows.Next() {
		pack, err := scanEvidencePack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pack)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate evidence_packs: %w", err)
	}
	return out, nil
}

// GetEvidencePackByVersionFormat returns the most recently generated pack for
// (approved_version_id, format), or ErrEvidencePackNotFound if no row matches.
// Several rows can share the same (av, format) when the engine produces
// distinct content hashes over time; we return the newest by generated_at.
func (s *Store) GetEvidencePackByVersionFormat(ctx context.Context, approvedVersionID domain.ID, format string) (*domain.EvidencePack, error) {
	if approvedVersionID == "" {
		return nil, storage.ErrInvalidArgument
	}
	if _, ok := validEvidencePackFormats[format]; !ok {
		return nil, fmt.Errorf("%w: evidence pack format %q", storage.ErrInvalidArgument, format)
	}
	const q = `
SELECT ` + evidencePackColumns + `
  FROM evidence_packs
 WHERE approved_version_id = $1 AND format = $2
 ORDER BY generated_at DESC
 LIMIT 1
`
	pack, err := scanEvidencePack(s.q.QueryRow(ctx, q, string(approvedVersionID), format))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, storage.ErrEvidencePackNotFound
		}
		return nil, err
	}
	return pack, nil
}

func scanEvidencePack(r scannable) (*domain.EvidencePack, error) {
	var (
		id, productID, approvedVersionID         string
		sequence                                 int64
		format, contentHash                      string
		contentRaw                               []byte
		generatedAt                              time.Time
		generatedByKind, generatedBySubject      string
	)
	err := r.Scan(
		&id, &productID, &approvedVersionID, &sequence, &format,
		&contentHash, &contentRaw, &generatedAt, &generatedByKind, &generatedBySubject,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan evidence_pack: %w", err)
	}
	pack := &domain.EvidencePack{
		ID:                domain.ID(id),
		ProductID:         domain.ID(productID),
		ApprovedVersionID: domain.ID(approvedVersionID),
		Sequence:          sequence,
		Format:            format,
		ContentHash:       contentHash,
		GeneratedAt:       generatedAt,
		GeneratedBy: domain.Actor{
			Kind:    domain.ActorKind(generatedByKind),
			Subject: generatedBySubject,
		},
	}
	if len(contentRaw) > 0 {
		pack.Content = json.RawMessage(append([]byte(nil), contentRaw...))
	}
	return pack, nil
}

// canonicalUUID parses s as a UUID and re-formats it in the canonical 36-char
// hyphenated lowercase form expected by Postgres uuid columns. Returns an
// error if s is not a valid UUID.
func canonicalUUID(s string) (string, error) {
	parsed, err := uuid.Parse(s)
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

// jsonOrNullObject returns raw if it carries any bytes; otherwise it returns
// the canonical empty JSON object so the JSONB NOT NULL columns always have a
// valid payload even when callers forget to populate them.
func jsonOrNullObject(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return raw
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

// -------- Plans --------

const planColumns = "id, product_id, approved_version_id, sequence, connector_name, " +
	"connector_version, state, summary, content_hash, content, refused_reason, " +
	"generated_at, generated_by_kind, generated_by_subject"

const planItemColumns = "id, plan_id, sequence, action, resource_kind, " +
	"resource_ref, body, risk, note"

// validPlanStates mirrors the CHECK constraint in
// migrations/0006_plans.sql. Validating in Go gives callers a clean
// ErrInvalidArgument up front instead of a Postgres CHECK violation.
var validPlanStates = map[string]struct{}{
	"draft":    {},
	"ready":    {},
	"refused":  {},
	"applied":  {},
	"failed":   {},
}

var validPlanActions = map[string]struct{}{
	"create": {},
	"update": {},
	"delete": {},
}

var validPlanRisks = map[string]struct{}{
	"low":      {},
	"medium":   {},
	"high":     {},
	"critical": {},
}

// AppendPlan inserts a plan + its items in one transaction. INSERT ...
// ON CONFLICT (approved_version_id, connector_name, content_hash) DO
// NOTHING makes deterministic re-plans a no-op: when the unique
// constraint trips, this method returns nil and does not insert items
// either. FK violations on product_id / approved_version_id surface as
// ErrNotFound so callers can distinguish a stale reference from a
// transient failure.
func (s *Store) AppendPlan(ctx context.Context, plan *domain.Plan, items []*domain.PlanItem) error {
	if plan == nil {
		return storage.ErrInvalidArgument
	}
	if plan.ID == "" {
		return fmt.Errorf("%w: plan id", storage.ErrInvalidArgument)
	}
	if plan.ProductID == "" {
		return fmt.Errorf("%w: plan product id", storage.ErrInvalidArgument)
	}
	if plan.ApprovedVersionID == "" {
		return fmt.Errorf("%w: plan approved version id", storage.ErrInvalidArgument)
	}
	if plan.Sequence < 1 {
		return fmt.Errorf("%w: plan sequence", storage.ErrInvalidArgument)
	}
	if plan.ConnectorName == "" {
		return fmt.Errorf("%w: plan connector name", storage.ErrInvalidArgument)
	}
	if plan.ConnectorVersion == "" {
		return fmt.Errorf("%w: plan connector version", storage.ErrInvalidArgument)
	}
	if _, ok := validPlanStates[string(plan.State)]; !ok {
		return fmt.Errorf("%w: plan state %q", storage.ErrInvalidArgument, plan.State)
	}
	if plan.ContentHash == "" {
		return fmt.Errorf("%w: plan content hash", storage.ErrInvalidArgument)
	}
	if len(plan.Content) == 0 {
		return fmt.Errorf("%w: plan content", storage.ErrInvalidArgument)
	}
	if err := plan.GeneratedBy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", storage.ErrInvalidArgument, err)
	}
	if plan.GeneratedAt.IsZero() {
		plan.GeneratedAt = time.Now().UTC()
	}
	for i, it := range items {
		if it == nil {
			return fmt.Errorf("%w: plan_items[%d] is nil", storage.ErrInvalidArgument, i)
		}
		if it.ID == "" {
			return fmt.Errorf("%w: plan_items[%d].id", storage.ErrInvalidArgument, i)
		}
		if it.Sequence < 1 {
			return fmt.Errorf("%w: plan_items[%d].sequence", storage.ErrInvalidArgument, i)
		}
		if _, ok := validPlanActions[it.Action]; !ok {
			return fmt.Errorf("%w: plan_items[%d].action %q", storage.ErrInvalidArgument, i, it.Action)
		}
		if it.ResourceKind == "" {
			return fmt.Errorf("%w: plan_items[%d].resource_kind", storage.ErrInvalidArgument, i)
		}
		if it.ResourceRef == "" {
			return fmt.Errorf("%w: plan_items[%d].resource_ref", storage.ErrInvalidArgument, i)
		}
		if _, ok := validPlanRisks[it.Risk]; !ok {
			return fmt.Errorf("%w: plan_items[%d].risk %q", storage.ErrInvalidArgument, i, it.Risk)
		}
	}

	// AppendPlan must run in a transaction so the plan + items insert
	// atomically. If we are already inside a tx (s.q is a pgx.Tx via
	// WithTx) reuse it; otherwise open one for the duration.
	if _, ok := s.q.(pgx.Tx); ok {
		return s.appendPlanTx(ctx, plan, items)
	}
	if s.pool == nil {
		// Defensive: Store with no pool and no tx is a programmer error.
		return errors.New("postgres: AppendPlan called on Store with no pool and no tx")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("postgres: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	sub := &Store{pool: nil, q: tx}
	if err := sub.appendPlanTx(ctx, plan, items); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit tx: %w", err)
	}
	committed = true
	return nil
}

// appendPlanTx is the inner half of AppendPlan; assumes s.q is a tx.
// It performs the plan insert and, only if a row was actually inserted
// (i.e. ON CONFLICT did not skip), the items insert.
func (s *Store) appendPlanTx(ctx context.Context, plan *domain.Plan, items []*domain.PlanItem) error {
	const planQ = `
INSERT INTO plans (
  id, product_id, approved_version_id, sequence, connector_name,
  connector_version, state, summary, content_hash, content,
  refused_reason, generated_at, generated_by_kind, generated_by_subject
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14)
ON CONFLICT (approved_version_id, connector_name, content_hash) DO NOTHING
RETURNING id
`
	var insertedID string
	row := s.q.QueryRow(ctx, planQ,
		string(plan.ID),
		string(plan.ProductID),
		string(plan.ApprovedVersionID),
		plan.Sequence,
		plan.ConnectorName,
		plan.ConnectorVersion,
		string(plan.State),
		plan.Summary,
		plan.ContentHash,
		[]byte(plan.Content),
		plan.RefusedReason,
		plan.GeneratedAt,
		string(plan.GeneratedBy.Kind),
		plan.GeneratedBy.Subject,
	)
	if err := row.Scan(&insertedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ON CONFLICT DO NOTHING fired: deterministic re-plan, the
			// existing row stands, items are not re-inserted.
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgForeignKeyViolation:
				return fmt.Errorf("%w: %s", storage.ErrNotFound, pgErr.ConstraintName)
			case pgCheckViolation:
				return fmt.Errorf("%w: %s", storage.ErrInvalidArgument, pgErr.ConstraintName)
			}
		}
		return fmt.Errorf("postgres: insert plan: %w", err)
	}

	// We inserted a fresh plan row. Now persist its items in sequence
	// order. plan_items.plan_id FK + UNIQUE(plan_id, sequence) protect
	// us against duplication; everything else is application invariant.
	const itemQ = `
INSERT INTO plan_items (
  id, plan_id, sequence, action, resource_kind, resource_ref, body, risk, note
) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
`
	for _, it := range items {
		body := jsonOrNullObject(it.Body)
		_, err := s.q.Exec(ctx, itemQ,
			string(it.ID),
			string(plan.ID),
			it.Sequence,
			it.Action,
			it.ResourceKind,
			it.ResourceRef,
			body,
			it.Risk,
			it.Note,
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				switch pgErr.Code {
				case pgUniqueViolation:
					return fmt.Errorf("%w: plan_items %s", storage.ErrAlreadyExists, pgErr.ConstraintName)
				case pgForeignKeyViolation:
					return fmt.Errorf("%w: %s", storage.ErrNotFound, pgErr.ConstraintName)
				case pgCheckViolation:
					return fmt.Errorf("%w: %s", storage.ErrInvalidArgument, pgErr.ConstraintName)
				}
			}
			return fmt.Errorf("postgres: insert plan_item: %w", err)
		}
	}
	return nil
}

// GetPlanByID returns the plan + ordered items, or ErrPlanNotFound if
// no row matches id. Items are returned in sequence-ascending order so
// the caller can render them deterministically.
func (s *Store) GetPlanByID(ctx context.Context, id domain.ID) (*domain.Plan, []*domain.PlanItem, error) {
	if id == "" {
		return nil, nil, storage.ErrInvalidArgument
	}
	const planQ = `SELECT ` + planColumns + ` FROM plans WHERE id = $1`
	plan, err := scanPlan(s.q.QueryRow(ctx, planQ, string(id)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil, storage.ErrPlanNotFound
		}
		return nil, nil, err
	}

	const itemsQ = `
SELECT ` + planItemColumns + `
  FROM plan_items
 WHERE plan_id = $1
 ORDER BY sequence ASC
`
	rows, err := s.q.Query(ctx, itemsQ, string(id))
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: list plan_items: %w", err)
	}
	defer rows.Close()
	items := make([]*domain.PlanItem, 0)
	for rows.Next() {
		it, err := scanPlanItem(rows)
		if err != nil {
			return nil, nil, err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("postgres: iterate plan_items: %w", err)
	}
	return plan, items, nil
}

// ListPlansByProduct returns plans for productID newest first. limit
// <= 0 means no limit. An empty slice (not an error) is returned when
// the product has no plans.
func (s *Store) ListPlansByProduct(ctx context.Context, productID domain.ID, limit int) ([]*domain.Plan, error) {
	if productID == "" {
		return nil, storage.ErrInvalidArgument
	}
	q := `
SELECT ` + planColumns + `
  FROM plans
 WHERE product_id = $1
 ORDER BY generated_at DESC, id DESC
`
	args := []any{string(productID)}
	if limit > 0 {
		args = append(args, limit)
		q += " LIMIT $2"
	}
	rows, err := s.q.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list plans: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.Plan, 0)
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate plans: %w", err)
	}
	return out, nil
}

// ListPlansByApprovedVersion returns every plan against the given
// approved_version_id, newest first. An empty slice is returned (not
// an error) when there are no rows.
func (s *Store) ListPlansByApprovedVersion(ctx context.Context, approvedVersionID domain.ID) ([]*domain.Plan, error) {
	if approvedVersionID == "" {
		return nil, storage.ErrInvalidArgument
	}
	const q = `
SELECT ` + planColumns + `
  FROM plans
 WHERE approved_version_id = $1
 ORDER BY generated_at DESC, id DESC
`
	rows, err := s.q.Query(ctx, q, string(approvedVersionID))
	if err != nil {
		return nil, fmt.Errorf("postgres: list plans by version: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.Plan, 0)
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate plans: %w", err)
	}
	return out, nil
}

// UpdatePlanState transitions a plan's state. Callers pre-validate the
// transition via domain.Plan.CanTransitionTo; this method only updates
// columns. A non-empty reason populates refused_reason; otherwise the
// existing value is preserved (so a re-Refused with empty reason does
// not blank prior context). Returns ErrPlanNotFound if no row matches
// id.
func (s *Store) UpdatePlanState(ctx context.Context, id domain.ID, state domain.PlanState, reason string) error {
	if id == "" {
		return storage.ErrInvalidArgument
	}
	if _, ok := validPlanStates[string(state)]; !ok {
		return fmt.Errorf("%w: plan state %q", storage.ErrInvalidArgument, state)
	}
	const q = `
UPDATE plans
   SET state          = $2,
       refused_reason = CASE WHEN $3 <> '' THEN $3 ELSE refused_reason END
 WHERE id = $1
`
	tag, err := s.q.Exec(ctx, q, string(id), string(state), reason)
	if err != nil {
		return fmt.Errorf("postgres: update plan state: %w", classifyErr(err))
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrPlanNotFound
	}
	return nil
}

func scanPlan(r scannable) (*domain.Plan, error) {
	var (
		id, productID, approvedVersionID    string
		sequence                            int64
		connectorName, connectorVersion     string
		state, summary, contentHash         string
		contentRaw                          []byte
		refusedReason                       string
		generatedAt                         time.Time
		generatedByKind, generatedBySubject string
	)
	err := r.Scan(
		&id, &productID, &approvedVersionID, &sequence, &connectorName,
		&connectorVersion, &state, &summary, &contentHash, &contentRaw,
		&refusedReason, &generatedAt, &generatedByKind, &generatedBySubject,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan plan: %w", err)
	}
	plan := &domain.Plan{
		ID:                domain.ID(id),
		ProductID:         domain.ID(productID),
		ApprovedVersionID: domain.ID(approvedVersionID),
		Sequence:          sequence,
		ConnectorName:     connectorName,
		ConnectorVersion:  connectorVersion,
		State:             domain.PlanState(state),
		Summary:           summary,
		ContentHash:       contentHash,
		RefusedReason:     refusedReason,
		GeneratedAt:       generatedAt,
		GeneratedBy: domain.Actor{
			Kind:    domain.ActorKind(generatedByKind),
			Subject: generatedBySubject,
		},
	}
	if len(contentRaw) > 0 {
		plan.Content = json.RawMessage(append([]byte(nil), contentRaw...))
	}
	return plan, nil
}

func scanPlanItem(r scannable) (*domain.PlanItem, error) {
	var (
		id, planID, action, resourceKind, resourceRef, risk, note string
		sequence                                                  int
		bodyRaw                                                   []byte
	)
	err := r.Scan(&id, &planID, &sequence, &action, &resourceKind, &resourceRef, &bodyRaw, &risk, &note)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: scan plan_item: %w", err)
	}
	item := &domain.PlanItem{
		ID:           domain.ID(id),
		PlanID:       domain.ID(planID),
		Sequence:     sequence,
		Action:       action,
		ResourceKind: resourceKind,
		ResourceRef:  resourceRef,
		Risk:         risk,
		Note:         note,
	}
	if len(bodyRaw) > 0 {
		item.Body = json.RawMessage(append([]byte(nil), bodyRaw...))
	}
	return item, nil
}

// Compile-time assertion that *Store satisfies storage.Storage.
var _ storage.Storage = (*Store)(nil)
