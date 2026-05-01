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

// ApplyCounts counts diff-sync row operations for a single entity kind.
type ApplyCounts struct {
	Added   int
	Updated int
	Deleted int
}

// ApplyResult breaks down an Apply call by entity kind. Authorization counts
// are reported as the post-apply row count under Added (authorizations are
// rebuilt wholesale per parent, so Updated/Deleted aren't meaningful here).
type ApplyResult struct {
	Counts map[domain.ChangeSetItemKind]ApplyCounts
}

// Apply pushes a model into the live tables for an existing product, using
// diff-sync semantics: rows present only in storage are deleted, rows present
// only in the model are created, rows on both sides whose payload changed are
// updated. Runs inside store.WithTx. Emits no audit events: the caller (e.g.
// approval.approve) is responsible for the higher-level event chain.
//
// productID must reference an existing product row; ErrNotFound otherwise.
func Apply(ctx context.Context, store storage.Storage, productID domain.ID, model *ProductAuthorizationModel, actor domain.Actor) (*ApplyResult, error) {
	_ = actor // reserved for future per-row events; not used in Apply itself
	if model == nil {
		return nil, errors.New("model: Apply: nil model")
	}

	result := &ApplyResult{Counts: map[domain.ChangeSetItemKind]ApplyCounts{}}
	err := store.WithTx(ctx, func(tx storage.Storage) error {
		// Verify the product exists and refresh owner/description from the model.
		product, err := tx.GetProductByID(ctx, productID)
		if err != nil {
			return fmt.Errorf("lookup product %s: %w", productID, err)
		}
		if err := applyProductHeader(ctx, tx, product, model, result); err != nil {
			return err
		}

		assetIDs, err := applyAssets(ctx, tx, product.ID, model.Spec.Assets, result)
		if err != nil {
			return err
		}
		scopeIDs, err := applyAssetScopes(ctx, tx, product.ID, model.Spec.AssetScopes, assetIDs, result)
		if err != nil {
			return err
		}
		globalIDs, err := applyGlobalObjects(ctx, tx, &product.ID, model.Spec.GlobalObjects, result)
		if err != nil {
			return err
		}
		entitlementIDs, err := applyEntitlements(ctx, tx, product.ID, model.Spec.Entitlements, result)
		if err != nil {
			return err
		}
		serviceAccountIDs, err := applyServiceAccounts(ctx, tx, product.ID, model.Spec.ServiceAccounts, result)
		if err != nil {
			return err
		}

		authCount := 0
		for _, e := range model.Spec.Entitlements {
			parentID := entitlementIDs[e.Name]
			n, err := applyAuthorizations(ctx, tx, domain.AuthParentEntitlement, parentID, e.Authorizations, scopeIDs, globalIDs)
			if err != nil {
				return err
			}
			authCount += n
		}
		for _, a := range model.Spec.ServiceAccounts {
			parentID := serviceAccountIDs[a.Name]
			n, err := applyAuthorizations(ctx, tx, domain.AuthParentServiceAccount, parentID, a.Authorizations, scopeIDs, globalIDs)
			if err != nil {
				return err
			}
			authCount += n
		}
		// Surface the post-apply authorization row count under Added; we delete
		// and recreate every authorization so per-row counts aren't useful.
		c := result.Counts[domain.ChangeSetItemKindAuthorization]
		c.Added = authCount
		result.Counts[domain.ChangeSetItemKindAuthorization] = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// applyProductHeader updates owner/description on the product row when the
// model differs.
func applyProductHeader(ctx context.Context, tx storage.Storage, product *domain.Product, m *ProductAuthorizationModel, r *ApplyResult) error {
	if product.Owner == m.Metadata.Owner && product.Description == m.Metadata.Description {
		return nil
	}
	product.Owner = m.Metadata.Owner
	product.Description = m.Metadata.Description
	product.UpdatedAt = nowUTC()
	if err := tx.UpdateProduct(ctx, product); err != nil {
		return fmt.Errorf("update product: %w", err)
	}
	c := r.Counts[domain.ChangeSetItemKindProduct]
	c.Updated++
	r.Counts[domain.ChangeSetItemKindProduct] = c
	return nil
}

func applyAssets(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLAsset, r *ApplyResult) (map[string]domain.ID, error) {
	existing, err := tx.ListAssetsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	byName := indexByName(existing, func(a *domain.Asset) string { return a.Name })
	desired := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))
	c := r.Counts[domain.ChangeSetItemKindAsset]

	for _, y := range want {
		desired[y.Name] = struct{}{}
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
			c.Updated++
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
		c.Added++
		out[y.Name] = a.ID
	}

	for _, cur := range existing {
		if _, keep := desired[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteAsset(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete asset %q: %w", cur.Name, err)
		}
		c.Deleted++
	}
	r.Counts[domain.ChangeSetItemKindAsset] = c
	return out, nil
}

func applyAssetScopes(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLAssetScope, _ map[string]domain.ID, r *ApplyResult) (map[string]domain.ID, error) {
	existing, err := tx.ListAssetScopesByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list asset scopes: %w", err)
	}
	byName := indexByName(existing, func(s *domain.AssetScope) string { return s.Name })
	desired := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))
	c := r.Counts[domain.ChangeSetItemKindAssetScope]

	for _, y := range want {
		desired[y.Name] = struct{}{}
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
			c.Updated++
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
		c.Added++
		out[y.Name] = s.ID
	}

	for _, cur := range existing {
		if _, keep := desired[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteAssetScope(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete asset scope %q: %w", cur.Name, err)
		}
		c.Deleted++
	}
	r.Counts[domain.ChangeSetItemKindAssetScope] = c
	return out, nil
}

func applyGlobalObjects(ctx context.Context, tx storage.Storage, productID *domain.ID, want []YAMLGlobalObject, r *ApplyResult) (map[string]domain.ID, error) {
	existing, err := tx.ListGlobalObjectsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list global objects: %w", err)
	}
	byName := indexByName(existing, func(g *domain.GlobalObject) string { return g.Name })
	desired := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))
	c := r.Counts[domain.ChangeSetItemKindGlobalObject]

	for _, y := range want {
		desired[y.Name] = struct{}{}
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
			c.Updated++
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
		c.Added++
		out[y.Name] = g.ID
	}

	for _, cur := range existing {
		if _, keep := desired[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteGlobalObject(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete global object %q: %w", cur.Name, err)
		}
		c.Deleted++
	}
	r.Counts[domain.ChangeSetItemKindGlobalObject] = c
	return out, nil
}

func applyEntitlements(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLEntitlement, r *ApplyResult) (map[string]domain.ID, error) {
	existing, err := tx.ListEntitlementsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list entitlements: %w", err)
	}
	byName := indexByName(existing, func(e *domain.Entitlement) string { return e.Name })
	desired := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))
	c := r.Counts[domain.ChangeSetItemKindEntitlement]

	for _, y := range want {
		desired[y.Name] = struct{}{}
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
			c.Updated++
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
		c.Added++
		out[y.Name] = e.ID
	}

	for _, cur := range existing {
		if _, keep := desired[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteEntitlement(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete entitlement %q: %w", cur.Name, err)
		}
		c.Deleted++
	}
	r.Counts[domain.ChangeSetItemKindEntitlement] = c
	return out, nil
}

func applyServiceAccounts(ctx context.Context, tx storage.Storage, productID domain.ID, want []YAMLServiceAccount, r *ApplyResult) (map[string]domain.ID, error) {
	existing, err := tx.ListServiceAccountsByProduct(ctx, productID)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	byName := indexByName(existing, func(s *domain.ServiceAccount) string { return s.Name })
	desired := make(map[string]struct{}, len(want))
	out := make(map[string]domain.ID, len(want))
	c := r.Counts[domain.ChangeSetItemKindServiceAccount]

	for _, y := range want {
		desired[y.Name] = struct{}{}
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
			c.Updated++
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
		c.Added++
		out[y.Name] = s.ID
	}

	for _, cur := range existing {
		if _, keep := desired[cur.Name]; keep {
			continue
		}
		if err := tx.DeleteServiceAccount(ctx, cur.ID); err != nil {
			return nil, fmt.Errorf("delete service account %q: %w", cur.Name, err)
		}
		c.Deleted++
	}
	r.Counts[domain.ChangeSetItemKindServiceAccount] = c
	return out, nil
}

// applyAuthorizations replaces the entire authorization set for a parent.
// Returns the post-apply row count.
func applyAuthorizations(ctx context.Context, tx storage.Storage, parentKind domain.AuthorizationParentKind, parentID domain.ID, want []YAMLAuthorization, scopeIDs, globalIDs map[string]domain.ID) (int, error) {
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

// indexByName builds a name->row map. Names are validator-enforced unique.
func indexByName[T any](rows []T, name func(T) string) map[string]T {
	out := make(map[string]T, len(rows))
	for _, r := range rows {
		out[name(r)] = r
	}
	return out
}

// labelsEqual reports identical key/value pairs. nil and empty are equivalent.
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

// selectorsEqual compares two AssetSelectors structurally; asset name order is
// normalized for stable comparison.
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

// copyLabels returns a defensive copy; nil maps stay nil so reflect.DeepEqual
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
