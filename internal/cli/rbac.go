// Package cli — RBAC pre-check helper.
//
// Phase 8 wave A: every gated CLI command (approve, reject, plan, drift
// scan, apply --dry-run, apply --apply, role grant/revoke) calls
// requireCapability before opening any tx. The helper looks up the
// actor's currently active roles, intersects them with the roles that
// grant the requested capability, and either lets the call proceed or
// returns an audit-emitting denial.
//
// Bootstrap path: when the actor_role_bindings table is empty we let
// every operation through with a stderr warning. The first
// `role grant --bootstrap --role admin` plants a row, after which the
// escape hatch is gone (any non-empty table flips RBAC enforcement on).
// docs/security-model.md documents this.
package cli

import (
	"context"
	"fmt"
	"io"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// requireCapability checks that actor holds at least one role granting
// the requested capability. On allow it returns nil. On deny it emits
// an EventRBACDenied audit event and returns a clear, actionable
// error describing what role is missing.
//
// Bootstrap path: an empty actor_role_bindings table opens the gate
// (with a stderr warning) so the first admin can be granted before
// RBAC starts enforcing. As soon as any binding exists the gate
// closes for real.
//
// stderr is optional; nil is fine. It is used only for the bootstrap
// warning so the operator sees the open gate at every invocation.
func requireCapability(
	ctx context.Context,
	store storage.Storage,
	stderr io.Writer,
	actor domain.Actor,
	cap domain.Capability,
) error {
	// Bootstrap: any binding present? If not, allow + warn and return.
	bindings, err := store.ListActorRoleBindings(ctx, storage.ActorRoleBindingFilter{Limit: 1})
	if err != nil {
		return fmt.Errorf("rbac: list bindings: %w", err)
	}
	if len(bindings) == 0 {
		if stderr != nil {
			_, _ = fmt.Fprintln(stderr,
				"WARNING: actor_role_bindings is empty; RBAC is open. "+
					"Run `statebound role grant --bootstrap --actor <kind>:<subject> --role admin` to seed the first admin.")
		}
		return nil
	}

	roles, err := store.ListActiveRolesForActor(ctx, actor)
	if err != nil {
		return fmt.Errorf("rbac: list active roles: %w", err)
	}
	required := domain.RolesForCapability(cap)

	if hasAnyRole(roles, required) {
		return nil
	}

	// Emit audit + return error. We deliberately log the denial inside
	// any surrounding tx the caller has opened by passing the same
	// store handle the caller is using; if the caller's tx rolls back,
	// the denial is rolled back too — that is the caller's choice.
	denial := fmt.Errorf("rbac: actor %s:%s lacks capability %s (requires one of %s)",
		actor.Kind, actor.Subject, cap, formatRoles(required))

	evt, evtErr := domain.NewAuditEvent(
		domain.EventRBACDenied,
		actor,
		"rbac",
		string(cap),
		map[string]any{
			"actor_kind":     string(actor.Kind),
			"actor_subject":  actor.Subject,
			"capability":     string(cap),
			"required_roles": rolesAsStrings(required),
			"actor_roles":    rolesAsStrings(roles),
		},
	)
	if evtErr != nil {
		// Building the event should never fail given the inputs above;
		// surface the original denial alongside the build error so the
		// operator sees both.
		return fmt.Errorf("%w (audit build: %v)", denial, evtErr)
	}
	if appendErr := store.AppendAuditEvent(ctx, evt); appendErr != nil {
		return fmt.Errorf("%w (audit append: %v)", denial, appendErr)
	}
	return denial
}

// hasAnyRole reports whether held contains at least one of required.
// Works in O(len(held)*len(required)) which is fine for the tiny
// fixed-size role set.
func hasAnyRole(held, required []domain.Role) bool {
	for _, h := range held {
		for _, r := range required {
			if h == r {
				return true
			}
		}
	}
	return false
}

// rolesAsStrings converts a []domain.Role into the []string the audit
// payload expects. Stable order via the input slice.
func rolesAsStrings(rs []domain.Role) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// formatRoles renders a []domain.Role for human error output. Empty
// slice renders as "<none — capability not registered>" so the
// operator gets a hint that the cap is default-deny rather than a
// known cap with no role assignments.
func formatRoles(rs []domain.Role) string {
	if len(rs) == 0 {
		return "<none — capability not registered>"
	}
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += ", "
		}
		out += string(r)
	}
	return out
}

// rbacEnforcedAt reports whether RBAC is currently enforcing at the
// given store handle. The bootstrap path open-gates everything until
// the first binding exists; this helper is used by the role grant
// CLI to decide whether --bootstrap is allowed.
func rbacEnforcedAt(ctx context.Context, store storage.Storage) (bool, error) {
	bindings, err := store.ListActorRoleBindings(ctx, storage.ActorRoleBindingFilter{Limit: 1})
	if err != nil {
		return false, fmt.Errorf("rbac: list bindings: %w", err)
	}
	return len(bindings) > 0, nil
}

// hasAdminBinding reports whether at least one active admin binding
// exists. The role grant --bootstrap path errors when this returns
// true — the bootstrap escape hatch is single-use.
func hasAdminBinding(ctx context.Context, store storage.Storage) (bool, error) {
	bindings, err := store.ListActorRoleBindings(ctx, storage.ActorRoleBindingFilter{
		Role:       domain.RoleAdmin,
		OnlyActive: true,
		Limit:      1,
	})
	if err != nil {
		return false, fmt.Errorf("rbac: list admin bindings: %w", err)
	}
	return len(bindings) > 0, nil
}
