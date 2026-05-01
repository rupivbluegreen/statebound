package domain

import (
	"errors"
	"fmt"
	"time"
)

// ChangeSetAction enumerates the kinds of mutations a ChangeSetItem represents.
type ChangeSetAction string

const (
	ChangeSetActionAdd    ChangeSetAction = "add"
	ChangeSetActionUpdate ChangeSetAction = "update"
	ChangeSetActionDelete ChangeSetAction = "delete"
)

// ChangeSetItemKind names the kind of domain object an item touches.
type ChangeSetItemKind string

const (
	ChangeSetItemKindProduct        ChangeSetItemKind = "product"
	ChangeSetItemKindAsset          ChangeSetItemKind = "asset"
	ChangeSetItemKindAssetScope     ChangeSetItemKind = "asset_scope"
	ChangeSetItemKindEntitlement    ChangeSetItemKind = "entitlement"
	ChangeSetItemKindServiceAccount ChangeSetItemKind = "service_account"
	ChangeSetItemKindGlobalObject   ChangeSetItemKind = "global_object"
	ChangeSetItemKindAuthorization  ChangeSetItemKind = "authorization"
)

// Sentinel errors for ChangeSetItem validation.
var (
	ErrChangeSetItemChangeSetIDRequired  = errors.New("domain: change set item change set id is required")
	ErrChangeSetItemKindInvalid          = errors.New("domain: change set item kind is invalid")
	ErrChangeSetItemActionInvalid        = errors.New("domain: change set item action is invalid")
	ErrChangeSetItemResourceNameRequired = errors.New("domain: change set item resource name is required")
	ErrChangeSetItemBeforeAfterMismatch  = errors.New("domain: change set item before/after does not match action")
)

// ChangeSetItem is a single mutation within a ChangeSet. ResourceName is a
// human-friendly identifier; for authorizations callers should use the form
// "<parent_kind>:<parent_name>:<auth_type>:<scope_or_global_name>".
type ChangeSetItem struct {
	ID           ID
	ChangeSetID  ID
	Kind         ChangeSetItemKind
	Action       ChangeSetAction
	ResourceName string
	Before       map[string]any
	After        map[string]any
	CreatedAt    time.Time
}

// IsValidChangeSetAction reports whether s is one of the ChangeSetAction constants.
func IsValidChangeSetAction(s string) bool {
	switch ChangeSetAction(s) {
	case ChangeSetActionAdd, ChangeSetActionUpdate, ChangeSetActionDelete:
		return true
	}
	return false
}

// IsValidChangeSetItemKind reports whether s is one of the ChangeSetItemKind constants.
func IsValidChangeSetItemKind(s string) bool {
	switch ChangeSetItemKind(s) {
	case ChangeSetItemKindProduct,
		ChangeSetItemKindAsset,
		ChangeSetItemKindAssetScope,
		ChangeSetItemKindEntitlement,
		ChangeSetItemKindServiceAccount,
		ChangeSetItemKindGlobalObject,
		ChangeSetItemKindAuthorization:
		return true
	}
	return false
}

// NewChangeSetItem constructs and validates a ChangeSetItem.
func NewChangeSetItem(csID ID, kind ChangeSetItemKind, action ChangeSetAction, resourceName string, before, after map[string]any) (*ChangeSetItem, error) {
	item := &ChangeSetItem{
		ID:           NewID(),
		ChangeSetID:  csID,
		Kind:         kind,
		Action:       action,
		ResourceName: resourceName,
		Before:       before,
		After:        after,
		CreatedAt:    time.Now().UTC(),
	}
	if err := item.Validate(); err != nil {
		return nil, err
	}
	return item, nil
}

// Validate enforces ChangeSetItem invariants.
func (i *ChangeSetItem) Validate() error {
	if i.ChangeSetID == "" {
		return ErrChangeSetItemChangeSetIDRequired
	}
	if !IsValidChangeSetItemKind(string(i.Kind)) {
		return fmt.Errorf("%w: %q", ErrChangeSetItemKindInvalid, string(i.Kind))
	}
	if !IsValidChangeSetAction(string(i.Action)) {
		return fmt.Errorf("%w: %q", ErrChangeSetItemActionInvalid, string(i.Action))
	}
	if i.ResourceName == "" {
		return ErrChangeSetItemResourceNameRequired
	}
	switch i.Action {
	case ChangeSetActionAdd:
		if i.Before != nil || i.After == nil {
			return fmt.Errorf("%w: add requires before==nil and after!=nil", ErrChangeSetItemBeforeAfterMismatch)
		}
	case ChangeSetActionDelete:
		if i.Before == nil || i.After != nil {
			return fmt.Errorf("%w: delete requires before!=nil and after==nil", ErrChangeSetItemBeforeAfterMismatch)
		}
	case ChangeSetActionUpdate:
		if i.Before == nil || i.After == nil {
			return fmt.Errorf("%w: update requires both before and after", ErrChangeSetItemBeforeAfterMismatch)
		}
	}
	return nil
}
