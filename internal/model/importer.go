package model

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// ImportResult summarizes what an Import call did. Counts make Phase-1 import
// idempotent checks easy: a no-op import has zeros across the *Added /
// *Updated / *Deleted fields.
type ImportResult struct {
	Product            string
	ProductCreated     bool
	ProductUpdated     bool
	AssetsAdded        int
	AssetsUpdated      int
	AssetsDeleted      int
	AssetScopesAdded   int
	AssetScopesUpdated int
	AssetScopesDeleted int
	EntitlementsAdded   int
	EntitlementsUpdated int
	EntitlementsDeleted int
	ServiceAccountsAdded   int
	ServiceAccountsUpdated int
	ServiceAccountsDeleted int
	GlobalObjectsAdded   int
	GlobalObjectsUpdated int
	GlobalObjectsDeleted int
	AuthorizationsTotal int
}

// Import applies a desired-state model to storage with sync semantics: rows
// not present in the YAML are deleted, rows that have changed are updated,
// and missing rows are created. It runs entirely in a single transaction.
//
// Validation runs first; on any findings, Import returns a *ValidationFailedError
// without touching the database.
func Import(ctx context.Context, store storage.Storage, m *ProductAuthorizationModel, actor domain.Actor) (*ImportResult, error) {
	if findings := Validate(m); len(findings) > 0 {
		return nil, &ValidationFailedError{Findings: findings}
	}

	result := &ImportResult{Product: m.Metadata.Product}
	err := store.WithTx(ctx, func(tx storage.Storage) error {
		product, err := upsertProduct(ctx, tx, m, result)
		if err != nil {
			return err
		}
		assetIDs, err := syncAssets(ctx, tx, product.ID, m.Spec.Assets, result)
		if err != nil {
			return err
		}
		scopeIDs, err := syncAssetScopes(ctx, tx, product.ID, m.Spec.AssetScopes, assetIDs, result)
		if err != nil {
			return err
		}
		globalIDs, err := syncGlobalObjects(ctx, tx, &product.ID, m.Spec.GlobalObjects, result)
		if err != nil {
			return err
		}
		entitlementIDs, err := syncEntitlements(ctx, tx, product.ID, m.Spec.Entitlements, result)
		if err != nil {
			return err
		}
		serviceAccountIDs, err := syncServiceAccounts(ctx, tx, product.ID, m.Spec.ServiceAccounts, result)
		if err != nil {
			return err
		}

		// Authorizations: delete-and-recreate everything attached to each
		// entitlement, service account, and global object owned by this
		// product. Spec is the desired state; previous rows are gone.
		authCount := 0
		for _, e := range m.Spec.Entitlements {
			parentID := entitlementIDs[e.Name]
			n, err := replaceAuthorizations(ctx, tx, domain.AuthParentEntitlement, parentID, e.Authorizations, scopeIDs, globalIDs)
			if err != nil {
				return err
			}
			authCount += n
		}
		for _, a := range m.Spec.ServiceAccounts {
			parentID := serviceAccountIDs[a.Name]
			n, err := replaceAuthorizations(ctx, tx, domain.AuthParentServiceAccount, parentID, a.Authorizations, scopeIDs, globalIDs)
			if err != nil {
				return err
			}
			authCount += n
		}
		result.AuthorizationsTotal = authCount

		// One audit event per import; row-level events arrive in Phase 2
		// alongside the ChangeSet diff machinery.
		payload := map[string]any{
			"product": m.Metadata.Product,
			"counts": map[string]any{
				"assets":           len(m.Spec.Assets),
				"asset_scopes":     len(m.Spec.AssetScopes),
				"entitlements":     len(m.Spec.Entitlements),
				"service_accounts": len(m.Spec.ServiceAccounts),
				"global_objects":   len(m.Spec.GlobalObjects),
				"authorizations":   authCount,
			},
		}
		evt, err := domain.NewAuditEvent(domain.EventModelImported, actor, "product", string(product.ID), payload)
		if err != nil {
			return fmt.Errorf("build audit event: %w", err)
		}
		if err := tx.AppendAuditEvent(ctx, evt); err != nil {
			return fmt.Errorf("append audit event: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// upsertProduct creates the product if absent or updates owner/description if
// the row already exists. The created/updated flags drive ImportResult.
func upsertProduct(ctx context.Context, tx storage.Storage, m *ProductAuthorizationModel, r *ImportResult) (*domain.Product, error) {
	existing, err := tx.GetProductByName(ctx, m.Metadata.Product)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("lookup product: %w", err)
	}
	if existing == nil {
		p, err := domain.NewProduct(m.Metadata.Product, m.Metadata.Owner, m.Metadata.Description)
		if err != nil {
			return nil, fmt.Errorf("build product: %w", err)
		}
		if err := tx.CreateProduct(ctx, p); err != nil {
			return nil, fmt.Errorf("create product: %w", err)
		}
		r.ProductCreated = true
		return p, nil
	}
	if existing.Owner != m.Metadata.Owner || existing.Description != m.Metadata.Description {
		existing.Owner = m.Metadata.Owner
		existing.Description = m.Metadata.Description
		existing.UpdatedAt = nowUTC()
		if err := tx.UpdateProduct(ctx, existing); err != nil {
			return nil, fmt.Errorf("update product: %w", err)
		}
		r.ProductUpdated = true
	}
	return existing, nil
}

func syncAssets(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLAsset, r *ImportResult) (map[string]domain.ID, error) {
	existing, err := tx.ListAssetsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	byName := indexByName(existing, func(a *domain.Asset) string { return a.Name })
	desiredNames := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))

	for _, y := range want {
		desiredNames[y.Name] = struct{}{}
		if cur, ok := byName[y.Name]; ok {
			labels := copyLabels(y.Labels)
			if cur.Type == domain.AssetType(y.Type) &&
				cur.Environment == domain.Environment(y.Environment) &&
				cur.Description == y.Description &&
				labelsEqual(cur.Labels, labels) {
				out[y.Name] = cur.ID
				continue
			}
			cur.Type = domain.AssetType(y.Type)
			cur.Environment = domain.Environment(y.Environment)
			cur.Description = y.Description
			cur.Labels = labels
			cur.UpdatedAt = nowUTC()
			if err := tx.UpdateAsset(ctx, cur); err != nil {
				return nil, fmt.Errorf("update asset %q: %w", y.Name, err)
			}
			r.AssetsUpdated++
			out[y.Name] = cur.ID
			continue
		}
		a, err := domain.NewAsset(productID, y.Name, domain.AssetType(y.Type), domain.Environment(y.Environment), copyLabels(y.Labels), y.Description)
		if err != nil {
			return nil, fmt.Errorf("build asset %q: %w", y.Name, err)
		}
		if err := tx.CreateAsset(ctx, a); err != nil {
			return nil, fmt.Errorf("create asset %q: %w", y.Name, err)
		}
		r.AssetsAdded++
		out[y.Name] = a.ID
	}

	for _, cur := range existing {
		if _, keep := desiredNames[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteAsset(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete asset %q: %w", cur.Name, err)
		}
		r.AssetsDeleted++
	}
	return out, nil
}

func syncAssetScopes(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLAssetScope, _ map[string]domain.ID, r *ImportResult) (map[string]domain.ID, error) {
	existing, err := tx.ListAssetScopesByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list asset scopes: %w", err)
	}
	byName := indexByName(existing, func(s *domain.AssetScope) string { return s.Name })
	desiredNames := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))

	for _, y := range want {
		desiredNames[y.Name] = struct{}{}
		sel := domain.AssetSelector{
			Type:        domain.AssetType(y.Selector.Type),
			Environment: domain.Environment(y.Selector.Environment),
			Labels:      copyLabels(y.Selector.Labels),
			AssetNames:  append([]string(nil), y.AssetNames...),
		}
		if cur, ok := byName[y.Name]; ok {
			if cur.Description == y.Description && selectorsEqual(cur.Selector, sel) {
				out[y.Name] = cur.ID
				continue
			}
			cur.Description = y.Description
			cur.Selector = sel
			cur.UpdatedAt = nowUTC()
			if err := tx.UpdateAssetScope(ctx, cur); err != nil {
				return nil, fmt.Errorf("update asset scope %q: %w", y.Name, err)
			}
			r.AssetScopesUpdated++
			out[y.Name] = cur.ID
			continue
		}
		s, err := domain.NewAssetScope(productID, y.Name, sel, y.Description)
		if err != nil {
			return nil, fmt.Errorf("build asset scope %q: %w", y.Name, err)
		}
		if err := tx.CreateAssetScope(ctx, s); err != nil {
			return nil, fmt.Errorf("create asset scope %q: %w", y.Name, err)
		}
		r.AssetScopesAdded++
		out[y.Name] = s.ID
	}

	for _, cur := range existing {
		if _, keep := desiredNames[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteAssetScope(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete asset scope %q: %w", cur.Name, err)
		}
		r.AssetScopesDeleted++
	}
	return out, nil
}

func syncGlobalObjects(ctx context.Context, tx storage.Storage, productID *domain.ID, want []YAMLGlobalObject, r *ImportResult) (map[string]domain.ID, error) {
	existing, err := tx.ListGlobalObjectsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list global objects: %w", err)
	}
	byName := indexByName(existing, func(g *domain.GlobalObject) string { return g.Name })
	desiredNames := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))

	for _, y := range want {
		desiredNames[y.Name] = struct{}{}
		if cur, ok := byName[y.Name]; ok {
			if string(cur.Type) == y.Type && reflect.DeepEqual(cur.Spec, y.Spec) {
				out[y.Name] = cur.ID
				continue
			}
			cur.Type = domain.GlobalObjectType(y.Type)
			cur.Spec = y.Spec
			cur.UpdatedAt = nowUTC()
			if err := tx.UpdateGlobalObject(ctx, cur); err != nil {
				return nil, fmt.Errorf("update global object %q: %w", y.Name, err)
			}
			r.GlobalObjectsUpdated++
			out[y.Name] = cur.ID
			continue
		}
		g, err := domain.NewGlobalObject(y.Name, domain.GlobalObjectType(y.Type), productID, y.Spec)
		if err != nil {
			return nil, fmt.Errorf("build global object %q: %w", y.Name, err)
		}
		if err := tx.CreateGlobalObject(ctx, g); err != nil {
			return nil, fmt.Errorf("create global object %q: %w", y.Name, err)
		}
		r.GlobalObjectsAdded++
		out[y.Name] = g.ID
	}

	for _, cur := range existing {
		if _, keep := desiredNames[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteGlobalObject(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete global object %q: %w", cur.Name, err)
		}
		r.GlobalObjectsDeleted++
	}
	return out, nil
}

func syncEntitlements(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLEntitlement, r *ImportResult) (map[string]domain.ID, error) {
	existing, err := tx.ListEntitlementsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list entitlements: %w", err)
	}
	byName := indexByName(existing, func(e *domain.Entitlement) string { return e.Name })
	desiredNames := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))

	for _, y := range want {
		desiredNames[y.Name] = struct{}{}
		if cur, ok := byName[y.Name]; ok {
			if cur.Owner == y.Owner && cur.Purpose == y.Purpose {
				out[y.Name] = cur.ID
				continue
			}
			cur.Owner = y.Owner
			cur.Purpose = y.Purpose
			cur.UpdatedAt = nowUTC()
			if err := tx.UpdateEntitlement(ctx, cur); err != nil {
				return nil, fmt.Errorf("update entitlement %q: %w", y.Name, err)
			}
			r.EntitlementsUpdated++
			out[y.Name] = cur.ID
			continue
		}
		e, err := domain.NewEntitlement(productID, y.Name, y.Owner, y.Purpose)
		if err != nil {
			return nil, fmt.Errorf("build entitlement %q: %w", y.Name, err)
		}
		if err := tx.CreateEntitlement(ctx, e); err != nil {
			return nil, fmt.Errorf("create entitlement %q: %w", y.Name, err)
		}
		r.EntitlementsAdded++
		out[y.Name] = e.ID
	}

	for _, cur := range existing {
		if _, keep := desiredNames[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteEntitlement(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete entitlement %q: %w", cur.Name, err)
		}
		r.EntitlementsDeleted++
	}
	return out, nil
}

func syncServiceAccounts(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLServiceAccount, r *ImportResult) (map[string]domain.ID, error) {
	existing, err := tx.ListServiceAccountsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	byName := indexByName(existing, func(s *domain.ServiceAccount) string { return s.Name })
	desiredNames := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))

	for _, y := range want {
		desiredNames[y.Name] = struct{}{}
		if cur, ok := byName[y.Name]; ok {
			if cur.Owner == y.Owner && cur.Purpose == y.Purpose && string(cur.UsagePattern) == y.UsagePattern {
				out[y.Name] = cur.ID
				continue
			}
			cur.Owner = y.Owner
			cur.Purpose = y.Purpose
			cur.UsagePattern = domain.UsagePattern(y.UsagePattern)
			cur.UpdatedAt = nowUTC()
			if err := tx.UpdateServiceAccount(ctx, cur); err != nil {
				return nil, fmt.Errorf("update service account %q: %w", y.Name, err)
			}
			r.ServiceAccountsUpdated++
			out[y.Name] = cur.ID
			continue
		}
		s, err := domain.NewServiceAccount(productID, y.Name, y.Owner, y.Purpose, domain.UsagePattern(y.UsagePattern))
		if err != nil {
			return nil, fmt.Errorf("build service account %q: %w", y.Name, err)
		}
		if err := tx.CreateServiceAccount(ctx, s); err != nil {
			return nil, fmt.Errorf("create service account %q: %w", y.Name, err)
		}
		r.ServiceAccountsAdded++
		out[y.Name] = s.ID
	}

	for _, cur := range existing {
		if _, keep := desiredNames[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteServiceAccount(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete service account %q: %w", cur.Name, err)
		}
		r.ServiceAccountsDeleted++
	}
	return out, nil
}

// replaceAuthorizations deletes every authorization currently attached to the
// parent and inserts the ones declared in YAML. Returns the number of new
// rows inserted (which equals the post-import row count).
func replaceAuthorizations(ctx context.Context, tx storage.Storage, parentKind domain.AuthorizationParentKind, parentID domain.ID, want []YAMLAuthorization, scopeIDs, globalIDs map[string]domain.ID) (int, error) {
	existing, err := tx.ListAuthorizationsByParent(ctx, parentKind, parentID)
	if err != nil {
		return 0, fmt.Errorf("list authorizations: %w", err)
	}
	for _, a := range existing {
		if err := tx.DeleteAuthorization(ctx, a.ID); err != nil {
			return 0, fmt.Errorf("delete authorization: %w", err)
		}
	}
	for i, y := range want {
		var scopeID, globalID *domain.ID
		if y.Scope != "" {
			id, ok := scopeIDs[y.Scope]
			if !ok {
				return 0, fmt.Errorf("authorization %d: scope %q not found", i, y.Scope)
			}
			scopeID = &id
		}
		if y.GlobalObject != "" {
			id, ok := globalIDs[y.GlobalObject]
			if !ok {
				return 0, fmt.Errorf("authorization %d: global object %q not found", i, y.GlobalObject)
			}
			globalID = &id
		}
		auth, err := domain.NewAuthorization(parentKind, parentID, domain.AuthorizationType(y.Type), scopeID, globalID, y.Spec)
		if err != nil {
			return 0, fmt.Errorf("build authorization %d: %w", i, err)
		}
		if err := tx.CreateAuthorization(ctx, auth); err != nil {
			return 0, fmt.Errorf("create authorization %d: %w", i, err)
		}
	}
	return len(want), nil
}

// indexByName builds a name->row map. Names already validated to be unique.
func indexByName[T any](rows []T, name func(T) string) map[string]T {
	out := make(map[string]T, len(rows))
	for _, r := range rows {
		out[name(r)] = r
	}
	return out
}

// labelsEqual is true when both maps have the same key/value pairs. nil and
// empty are equivalent.
func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// selectorsEqual compares two AssetSelectors structurally (asset name order
// matters, but we sort below to ignore reorderings produced by the database).
func selectorsEqual(a, b domain.AssetSelector) bool {
	if a.Type != b.Type || a.Environment != b.Environment {
		return false
	}
	if !labelsEqual(a.Labels, b.Labels) {
		return false
	}
	an := append([]string(nil), a.AssetNames...)
	bn := append([]string(nil), b.AssetNames...)
	sort.Strings(an)
	sort.Strings(bn)
	if len(an) != len(bn) {
		return false
	}
	for i := range an {
		if an[i] != bn[i] {
			return false
		}
	}
	return true
}

// copyLabels returns a defensive copy; nil maps stay nil so reflect-deep-equal
// stays well-behaved for empty selectors.
func copyLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
