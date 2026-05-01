package model

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"statebound.dev/statebound/internal/domain"
)

// Diff is the ordered set of differences between two ProductAuthorizationModels.
// Items follow a canonical order: product first, then assets, asset_scopes,
// global_objects, entitlements (with their authorizations), service_accounts
// (with their authorizations) — each named-entity collection sorted by name.
type Diff struct {
	Items []*DiffItem
}

// DiffItem is one entry produced by ComputeDiff. It mirrors the persistent
// shape of a domain.ChangeSetItem without the storage-managed fields
// (ID/ChangeSetID/CreatedAt) — the importer fills those in via
// domain.NewChangeSetItem.
type DiffItem struct {
	Kind         domain.ChangeSetItemKind
	Action       domain.ChangeSetAction
	ResourceName string
	Before       map[string]any
	After        map[string]any
}

// IsEmpty reports whether the diff has no items.
func (d *Diff) IsEmpty() bool { return d == nil || len(d.Items) == 0 }

// Summary returns a one-line "X adds, Y updates, Z deletes" string.
func (d *Diff) Summary() string {
	var adds, updates, deletes int
	if d != nil {
		for _, it := range d.Items {
			switch it.Action {
			case domain.ChangeSetActionAdd:
				adds++
			case domain.ChangeSetActionUpdate:
				updates++
			case domain.ChangeSetActionDelete:
				deletes++
			}
		}
	}
	return fmt.Sprintf("%d adds, %d updates, %d deletes", adds, updates, deletes)
}

// ComputeDiff walks two models in canonical order and emits Add/Update/Delete
// entries for every named-entity collection. Either side may be nil. Equality
// is decided by canonical-JSON of the YAML round-trip payload.
func ComputeDiff(before, after *ProductAuthorizationModel) (*Diff, error) {
	d := &Diff{}
	if before == nil && after == nil {
		return d, nil
	}

	// Product header.
	if err := diffProduct(d, before, after); err != nil {
		return nil, err
	}

	// Assets — sorted by name on both sides.
	if err := diffAssets(d, assetsOrEmpty(before), assetsOrEmpty(after)); err != nil {
		return nil, err
	}
	// Asset scopes.
	if err := diffAssetScopes(d, scopesOrEmpty(before), scopesOrEmpty(after)); err != nil {
		return nil, err
	}
	// Global objects.
	if err := diffGlobalObjects(d, globalsOrEmpty(before), globalsOrEmpty(after)); err != nil {
		return nil, err
	}
	// Entitlements (and their inline authorizations).
	if err := diffEntitlements(d, entitlementsOrEmpty(before), entitlementsOrEmpty(after)); err != nil {
		return nil, err
	}
	// Service accounts (and their inline authorizations).
	if err := diffServiceAccounts(d, serviceAccountsOrEmpty(before), serviceAccountsOrEmpty(after)); err != nil {
		return nil, err
	}

	return d, nil
}

// ----- product -----

func diffProduct(d *Diff, before, after *ProductAuthorizationModel) error {
	bMap, err := productPayload(before)
	if err != nil {
		return err
	}
	aMap, err := productPayload(after)
	if err != nil {
		return err
	}
	name := ""
	switch {
	case after != nil:
		name = after.Metadata.Product
	case before != nil:
		name = before.Metadata.Product
	}
	res := "product:" + name
	switch {
	case bMap == nil && aMap != nil:
		d.Items = append(d.Items, &DiffItem{Kind: domain.ChangeSetItemKindProduct, Action: domain.ChangeSetActionAdd, ResourceName: res, After: aMap})
	case bMap != nil && aMap == nil:
		d.Items = append(d.Items, &DiffItem{Kind: domain.ChangeSetItemKindProduct, Action: domain.ChangeSetActionDelete, ResourceName: res, Before: bMap})
	case bMap != nil && aMap != nil:
		if !canonicalEqual(bMap, aMap) {
			d.Items = append(d.Items, &DiffItem{Kind: domain.ChangeSetItemKindProduct, Action: domain.ChangeSetActionUpdate, ResourceName: res, Before: bMap, After: aMap})
		}
	}
	return nil
}

// productPayload captures the metadata fields that distinguish a product row.
func productPayload(m *ProductAuthorizationModel) (map[string]any, error) {
	if m == nil {
		return nil, nil
	}
	type productRow struct {
		Product     string `yaml:"product"`
		Owner       string `yaml:"owner"`
		Description string `yaml:"description,omitempty"`
	}
	return yamlToMap(productRow{
		Product:     m.Metadata.Product,
		Owner:       m.Metadata.Owner,
		Description: m.Metadata.Description,
	})
}

// ----- assets -----

func diffAssets(d *Diff, before, after []YAMLAsset) error {
	bm := indexAssetsByName(before)
	am := indexAssetsByName(after)
	for _, name := range mergedSortedKeys(bm, am) {
		bRow, bOK := bm[name]
		aRow, aOK := am[name]
		var bMap, aMap map[string]any
		var err error
		if bOK {
			if bMap, err = yamlToMap(bRow); err != nil {
				return fmt.Errorf("asset %q before: %w", name, err)
			}
		}
		if aOK {
			if aMap, err = yamlToMap(aRow); err != nil {
				return fmt.Errorf("asset %q after: %w", name, err)
			}
		}
		emit(d, domain.ChangeSetItemKindAsset, "asset:"+name, bMap, aMap)
	}
	return nil
}

func indexAssetsByName(in []YAMLAsset) map[string]YAMLAsset {
	out := make(map[string]YAMLAsset, len(in))
	for _, a := range in {
		out[a.Name] = a
	}
	return out
}

// ----- asset scopes -----

func diffAssetScopes(d *Diff, before, after []YAMLAssetScope) error {
	bm := indexScopesByName(before)
	am := indexScopesByName(after)
	for _, name := range mergedSortedKeys(bm, am) {
		bRow, bOK := bm[name]
		aRow, aOK := am[name]
		var bMap, aMap map[string]any
		var err error
		if bOK {
			if bMap, err = yamlToMap(bRow); err != nil {
				return fmt.Errorf("asset_scope %q before: %w", name, err)
			}
		}
		if aOK {
			if aMap, err = yamlToMap(aRow); err != nil {
				return fmt.Errorf("asset_scope %q after: %w", name, err)
			}
		}
		emit(d, domain.ChangeSetItemKindAssetScope, "asset_scope:"+name, bMap, aMap)
	}
	return nil
}

func indexScopesByName(in []YAMLAssetScope) map[string]YAMLAssetScope {
	out := make(map[string]YAMLAssetScope, len(in))
	for _, s := range in {
		out[s.Name] = s
	}
	return out
}

// ----- global objects -----

func diffGlobalObjects(d *Diff, before, after []YAMLGlobalObject) error {
	bm := indexGlobalsByName(before)
	am := indexGlobalsByName(after)
	for _, name := range mergedSortedKeys(bm, am) {
		bRow, bOK := bm[name]
		aRow, aOK := am[name]
		var bMap, aMap map[string]any
		var err error
		if bOK {
			if bMap, err = yamlToMap(bRow); err != nil {
				return fmt.Errorf("global_object %q before: %w", name, err)
			}
		}
		if aOK {
			if aMap, err = yamlToMap(aRow); err != nil {
				return fmt.Errorf("global_object %q after: %w", name, err)
			}
		}
		emit(d, domain.ChangeSetItemKindGlobalObject, "global_object:"+name, bMap, aMap)
	}
	return nil
}

func indexGlobalsByName(in []YAMLGlobalObject) map[string]YAMLGlobalObject {
	out := make(map[string]YAMLGlobalObject, len(in))
	for _, g := range in {
		out[g.Name] = g
	}
	return out
}

// ----- entitlements + their authorizations -----

func diffEntitlements(d *Diff, before, after []YAMLEntitlement) error {
	bm := indexEntitlementsByName(before)
	am := indexEntitlementsByName(after)
	for _, name := range mergedSortedKeys(bm, am) {
		bRow, bOK := bm[name]
		aRow, aOK := am[name]
		bHeader, aHeader, err := entitlementHeaders(bRow, bOK, aRow, aOK)
		if err != nil {
			return err
		}
		emit(d, domain.ChangeSetItemKindEntitlement, "entitlement:"+name, bHeader, aHeader)

		var bAuths, aAuths []YAMLAuthorization
		if bOK {
			bAuths = bRow.Authorizations
		}
		if aOK {
			aAuths = aRow.Authorizations
		}
		if err := diffAuthorizations(d, "entitlement", name, bAuths, aAuths); err != nil {
			return err
		}
	}
	return nil
}

func indexEntitlementsByName(in []YAMLEntitlement) map[string]YAMLEntitlement {
	out := make(map[string]YAMLEntitlement, len(in))
	for _, e := range in {
		out[e.Name] = e
	}
	return out
}

// entitlementHeaders projects the header-only fields (no authorizations) so
// authorizations diff independently.
func entitlementHeaders(b YAMLEntitlement, bOK bool, a YAMLEntitlement, aOK bool) (map[string]any, map[string]any, error) {
	type header struct {
		Name    string `yaml:"name"`
		Owner   string `yaml:"owner"`
		Purpose string `yaml:"purpose"`
	}
	var bMap, aMap map[string]any
	var err error
	if bOK {
		if bMap, err = yamlToMap(header{Name: b.Name, Owner: b.Owner, Purpose: b.Purpose}); err != nil {
			return nil, nil, err
		}
	}
	if aOK {
		if aMap, err = yamlToMap(header{Name: a.Name, Owner: a.Owner, Purpose: a.Purpose}); err != nil {
			return nil, nil, err
		}
	}
	return bMap, aMap, nil
}

// ----- service accounts + their authorizations -----

func diffServiceAccounts(d *Diff, before, after []YAMLServiceAccount) error {
	bm := indexServiceAccountsByName(before)
	am := indexServiceAccountsByName(after)
	for _, name := range mergedSortedKeys(bm, am) {
		bRow, bOK := bm[name]
		aRow, aOK := am[name]
		bHeader, aHeader, err := serviceAccountHeaders(bRow, bOK, aRow, aOK)
		if err != nil {
			return err
		}
		emit(d, domain.ChangeSetItemKindServiceAccount, "service_account:"+name, bHeader, aHeader)

		var bAuths, aAuths []YAMLAuthorization
		if bOK {
			bAuths = bRow.Authorizations
		}
		if aOK {
			aAuths = aRow.Authorizations
		}
		if err := diffAuthorizations(d, "service_account", name, bAuths, aAuths); err != nil {
			return err
		}
	}
	return nil
}

func indexServiceAccountsByName(in []YAMLServiceAccount) map[string]YAMLServiceAccount {
	out := make(map[string]YAMLServiceAccount, len(in))
	for _, s := range in {
		out[s.Name] = s
	}
	return out
}

func serviceAccountHeaders(b YAMLServiceAccount, bOK bool, a YAMLServiceAccount, aOK bool) (map[string]any, map[string]any, error) {
	type header struct {
		Name         string `yaml:"name"`
		Owner        string `yaml:"owner"`
		UsagePattern string `yaml:"usagePattern"`
		Purpose      string `yaml:"purpose"`
	}
	var bMap, aMap map[string]any
	var err error
	if bOK {
		if bMap, err = yamlToMap(header{Name: b.Name, Owner: b.Owner, UsagePattern: b.UsagePattern, Purpose: b.Purpose}); err != nil {
			return nil, nil, err
		}
	}
	if aOK {
		if aMap, err = yamlToMap(header{Name: a.Name, Owner: a.Owner, UsagePattern: a.UsagePattern, Purpose: a.Purpose}); err != nil {
			return nil, nil, err
		}
	}
	return bMap, aMap, nil
}

// ----- authorizations (list-positional under a parent) -----

// diffAuthorizations compares two parallel authorization lists by index. List
// position is the identity here since authorizations have no name.
func diffAuthorizations(d *Diff, parentKind, parentName string, before, after []YAMLAuthorization) error {
	maxLen := len(before)
	if len(after) > maxLen {
		maxLen = len(after)
	}
	for i := 0; i < maxLen; i++ {
		var bMap, aMap map[string]any
		var err error
		if i < len(before) {
			if bMap, err = yamlToMap(before[i]); err != nil {
				return fmt.Errorf("authorization %s:%s[%d] before: %w", parentKind, parentName, i, err)
			}
		}
		if i < len(after) {
			if aMap, err = yamlToMap(after[i]); err != nil {
				return fmt.Errorf("authorization %s:%s[%d] after: %w", parentKind, parentName, i, err)
			}
		}
		res := fmt.Sprintf("authorization:%s:%s:%d", parentKind, parentName, i)
		emit(d, domain.ChangeSetItemKindAuthorization, res, bMap, aMap)
	}
	return nil
}

// ----- helpers -----

// emit appends an Add/Update/Delete or skips when nil/equal.
func emit(d *Diff, kind domain.ChangeSetItemKind, resource string, before, after map[string]any) {
	switch {
	case before == nil && after != nil:
		d.Items = append(d.Items, &DiffItem{Kind: kind, Action: domain.ChangeSetActionAdd, ResourceName: resource, After: after})
	case before != nil && after == nil:
		d.Items = append(d.Items, &DiffItem{Kind: kind, Action: domain.ChangeSetActionDelete, ResourceName: resource, Before: before})
	case before != nil && after != nil:
		if !canonicalEqual(before, after) {
			d.Items = append(d.Items, &DiffItem{Kind: kind, Action: domain.ChangeSetActionUpdate, ResourceName: resource, Before: before, After: after})
		}
	}
}

// canonicalEqual compares two map[string]any payloads via canonical-JSON form
// (sorted keys at every level). Equal bytes = equal.
func canonicalEqual(a, b map[string]any) bool {
	ab, err := canonicalJSONBytes(a)
	if err != nil {
		return false
	}
	bb, err := canonicalJSONBytes(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// yamlToMap round-trips an arbitrary value through yaml.Marshal+yaml.Unmarshal
// so nested structures collapse to plain map[string]any / []any. The resulting
// map serializes deterministically under canonicalJSONBytes.
func yamlToMap(v any) (map[string]any, error) {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal yaml: %w", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	if out == nil {
		out = map[string]any{}
	}
	return normalizeMapKeys(out).(map[string]any), nil
}

// normalizeMapKeys converts any map[any]any (yaml's default for non-string
// keys) into map[string]any so canonical JSON encoding works recursively.
func normalizeMapKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeMapKeys(val)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = normalizeMapKeys(val)
		}
		return out
	case []any:
		for i, item := range t {
			t[i] = normalizeMapKeys(item)
		}
		return t
	}
	return v
}

// mergedSortedKeys returns the lexicographically-sorted union of two maps' keys.
func mergedSortedKeys[V any](a, b map[string]V) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assetsOrEmpty / scopesOrEmpty / ... shorthands so the diff* functions stay
// uncluttered when one side of the diff is nil.
func assetsOrEmpty(m *ProductAuthorizationModel) []YAMLAsset {
	if m == nil {
		return nil
	}
	return m.Spec.Assets
}
func scopesOrEmpty(m *ProductAuthorizationModel) []YAMLAssetScope {
	if m == nil {
		return nil
	}
	return m.Spec.AssetScopes
}
func globalsOrEmpty(m *ProductAuthorizationModel) []YAMLGlobalObject {
	if m == nil {
		return nil
	}
	return m.Spec.GlobalObjects
}
func entitlementsOrEmpty(m *ProductAuthorizationModel) []YAMLEntitlement {
	if m == nil {
		return nil
	}
	return m.Spec.Entitlements
}
func serviceAccountsOrEmpty(m *ProductAuthorizationModel) []YAMLServiceAccount {
	if m == nil {
		return nil
	}
	return m.Spec.ServiceAccounts
}
