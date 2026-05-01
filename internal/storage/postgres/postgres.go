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

// AppendAuditEvent inserts an audit event. Hash chain fields are written verbatim
// (empty strings in Phase 0; populated from v0.2 onward).
func (s *Store) AppendAuditEvent(ctx context.Context, e *domain.AuditEvent) error {
	payload, err := marshalJSON(e.Payload)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO audit_events (
  id, kind, actor_kind, actor_subject, resource_type, resource_id,
  payload, occurred_at, prev_hash, hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`
	_, err = s.q.Exec(ctx, q,
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
