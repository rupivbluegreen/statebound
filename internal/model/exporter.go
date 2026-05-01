package model

import (
	"context"
	"fmt"
	"sort"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// Export reconstructs a ProductAuthorizationModel from storage. Output is
// fully deterministic: every collection is sorted by name (or by a stable
// composite key for authorizations) so two exports of the same database state
// produce byte-identical YAML.
func Export(ctx context.Context, store storage.Storage, productName string) (*ProductAuthorizationModel, error) {
	product, err := store.GetProductByName(ctx, productName)
	if err != nil {
		return nil, fmt.Errorf("lookup product %q: %w", productName, err)
	}

	assets, err := store.ListAssetsByProduct(ctx, product.ID)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	scopes, err := store.ListAssetScopesByProduct(ctx, product.ID)
	if err != nil {
		return nil, fmt.Errorf("list asset scopes: %w", err)
	}
	entitlements, err := store.ListEntitlementsByProduct(ctx, product.ID)
	if err != nil {
		return nil, fmt.Errorf("list entitlements: %w", err)
	}
	serviceAccounts, err := store.ListServiceAccountsByProduct(ctx, product.ID)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	globals, err := store.ListGlobalObjectsByProduct(ctx, &product.ID)
	if err != nil {
		return nil, fmt.Errorf("list global objects: %w", err)
	}

	scopeNameByID := make(map[domain.ID]string, len(scopes))
	for _, s := range scopes {
		scopeNameByID[s.ID] = s.Name
	}
	globalNameByID := make(map[domain.ID]string, len(globals))
	for _, g := range globals {
		globalNameByID[g.ID] = g.Name
	}

	model := &ProductAuthorizationModel{
		APIVersion: APIVersion,
		Kind:       Kind,
		Metadata: ProductMetadata{
			Product:     product.Name,
			Owner:       product.Owner,
			Description: product.Description,
		},
	}

	model.Spec.Assets = exportAssets(assets)
	model.Spec.AssetScopes = exportScopes(scopes)
	model.Spec.GlobalObjects = exportGlobals(globals)

	model.Spec.Entitlements = make([]YAMLEntitlement, 0, len(entitlements))
	sort.Slice(entitlements, func(i, j int) bool { return entitlements[i].Name < entitlements[j].Name })
	for _, e := range entitlements {
		auths, err := store.ListAuthorizationsByParent(ctx, domain.AuthParentEntitlement, e.ID)
		if err != nil {
			return nil, fmt.Errorf("list authorizations for entitlement %q: %w", e.Name, err)
		}
		model.Spec.Entitlements = append(model.Spec.Entitlements, YAMLEntitlement{
			Name:           e.Name,
			Owner:          e.Owner,
			Purpose:        e.Purpose,
			Authorizations: exportAuthorizations(auths, scopeNameByID, globalNameByID),
		})
	}

	model.Spec.ServiceAccounts = make([]YAMLServiceAccount, 0, len(serviceAccounts))
	sort.Slice(serviceAccounts, func(i, j int) bool { return serviceAccounts[i].Name < serviceAccounts[j].Name })
	for _, a := range serviceAccounts {
		auths, err := store.ListAuthorizationsByParent(ctx, domain.AuthParentServiceAccount, a.ID)
		if err != nil {
			return nil, fmt.Errorf("list authorizations for service account %q: %w", a.Name, err)
		}
		model.Spec.ServiceAccounts = append(model.Spec.ServiceAccounts, YAMLServiceAccount{
			Name:           a.Name,
			Owner:          a.Owner,
			UsagePattern:   string(a.UsagePattern),
			Purpose:        a.Purpose,
			Authorizations: exportAuthorizations(auths, scopeNameByID, globalNameByID),
		})
	}

	return model, nil
}

func exportAssets(assets []*domain.Asset) []YAMLAsset {
	sort.Slice(assets, func(i, j int) bool { return assets[i].Name < assets[j].Name })
	out := make([]YAMLAsset, 0, len(assets))
	for _, a := range assets {
		out = append(out, YAMLAsset{
			Name:        a.Name,
			Type:        string(a.Type),
			Environment: string(a.Environment),
			Labels:      copyLabels(a.Labels),
			Description: a.Description,
		})
	}
	return out
}

func exportScopes(scopes []*domain.AssetScope) []YAMLAssetScope {
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })
	out := make([]YAMLAssetScope, 0, len(scopes))
	for _, s := range scopes {
		assetNames := append([]string(nil), s.Selector.AssetNames...)
		sort.Strings(assetNames)
		out = append(out, YAMLAssetScope{
			Name:        s.Name,
			Description: s.Description,
			Selector: YAMLAssetSelector{
				Type:        string(s.Selector.Type),
				Environment: string(s.Selector.Environment),
				Labels:      copyLabels(s.Selector.Labels),
			},
			AssetNames: assetNames,
		})
	}
	return out
}

func exportGlobals(globals []*domain.GlobalObject) []YAMLGlobalObject {
	sort.Slice(globals, func(i, j int) bool { return globals[i].Name < globals[j].Name })
	out := make([]YAMLGlobalObject, 0, len(globals))
	for _, g := range globals {
		out = append(out, YAMLGlobalObject{
			Name: g.Name,
			Type: string(g.Type),
			Spec: g.Spec,
		})
	}
	return out
}

// exportAuthorizations sorts and projects raw authorizations into YAML entries.
// Sort key: type, then resolved scope/global name, then created_at.
func exportAuthorizations(auths []*domain.Authorization, scopeNames, globalNames map[domain.ID]string) []YAMLAuthorization {
	sort.SliceStable(auths, func(i, j int) bool {
		ai, aj := auths[i], auths[j]
		if ai.Type != aj.Type {
			return ai.Type < aj.Type
		}
		ki := authSortKey(ai, scopeNames, globalNames)
		kj := authSortKey(aj, scopeNames, globalNames)
		if ki != kj {
			return ki < kj
		}
		return ai.CreatedAt.Before(aj.CreatedAt)
	})
	out := make([]YAMLAuthorization, 0, len(auths))
	for _, a := range auths {
		entry := YAMLAuthorization{
			Type: string(a.Type),
			Spec: a.Spec,
		}
		if a.AssetScopeID != nil {
			entry.Scope = scopeNames[*a.AssetScopeID]
		}
		if a.GlobalObjectID != nil {
			entry.GlobalObject = globalNames[*a.GlobalObjectID]
		}
		out = append(out, entry)
	}
	return out
}

func authSortKey(a *domain.Authorization, scopeNames, globalNames map[domain.ID]string) string {
	if a.AssetScopeID != nil {
		return "scope:" + scopeNames[*a.AssetScopeID]
	}
	if a.GlobalObjectID != nil {
		return "global:" + globalNames[*a.GlobalObjectID]
	}
	return ""
}
