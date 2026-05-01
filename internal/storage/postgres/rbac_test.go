package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// TestAppendActorRoleBinding_HappyPath inserts a binding and reads it
// back through the active-roles fast path.
func TestAppendActorRoleBinding_HappyPath(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subject := uniqueSlug("rbac-alice")
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: subject}
	grantor := domain.Actor{Kind: domain.ActorSystem, Subject: "test-bootstrap"}
	b, err := domain.NewActorRoleBinding(actor, domain.RoleAdmin, grantor, nil, "happy path test")
	if err != nil {
		t.Fatalf("NewActorRoleBinding: %v", err)
	}
	if err := store.AppendActorRoleBinding(ctx, b); err != nil {
		t.Fatalf("AppendActorRoleBinding: %v", err)
	}

	roles, err := store.ListActiveRolesForActor(ctx, actor)
	if err != nil {
		t.Fatalf("ListActiveRolesForActor: %v", err)
	}
	if len(roles) != 1 || roles[0] != domain.RoleAdmin {
		t.Errorf("active roles = %v; want [admin]", roles)
	}
}

// TestAppendActorRoleBinding_DuplicateReturnsErr asserts the unique
// constraint surfaces as ErrRoleBindingDuplicate.
func TestAppendActorRoleBinding_DuplicateReturnsErr(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subject := uniqueSlug("rbac-dup")
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: subject}
	grantor := domain.Actor{Kind: domain.ActorSystem, Subject: "test"}

	b1, _ := domain.NewActorRoleBinding(actor, domain.RoleViewer, grantor, nil, "")
	if err := store.AppendActorRoleBinding(ctx, b1); err != nil {
		t.Fatalf("first append: %v", err)
	}
	b2, _ := domain.NewActorRoleBinding(actor, domain.RoleViewer, grantor, nil, "")
	err := store.AppendActorRoleBinding(ctx, b2)
	if !errors.Is(err, storage.ErrRoleBindingDuplicate) {
		t.Errorf("second append err = %v; want ErrRoleBindingDuplicate", err)
	}
}

// TestDeleteActorRoleBinding asserts the delete path and ErrRoleBindingNotFound
// when the id is unknown.
func TestDeleteActorRoleBinding(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subject := uniqueSlug("rbac-del")
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: subject}
	grantor := domain.Actor{Kind: domain.ActorSystem, Subject: "test"}
	b, _ := domain.NewActorRoleBinding(actor, domain.RoleApprover, grantor, nil, "")
	if err := store.AppendActorRoleBinding(ctx, b); err != nil {
		t.Fatalf("append: %v", err)
	}

	if err := store.DeleteActorRoleBinding(ctx, b.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	roles, err := store.ListActiveRolesForActor(ctx, actor)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("expected no roles after delete; got %v", roles)
	}

	// Second delete should report not found.
	err = store.DeleteActorRoleBinding(ctx, b.ID)
	if !errors.Is(err, storage.ErrRoleBindingNotFound) {
		t.Errorf("second delete err = %v; want ErrRoleBindingNotFound", err)
	}
}

// TestListActorRoleBindings_FilterByActor exercises the actor filter
// path used by `role list --actor`.
func TestListActorRoleBindings_FilterByActor(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a1 := domain.Actor{Kind: domain.ActorHuman, Subject: uniqueSlug("a1")}
	a2 := domain.Actor{Kind: domain.ActorHuman, Subject: uniqueSlug("a2")}
	grantor := domain.Actor{Kind: domain.ActorSystem, Subject: "test"}
	b1, _ := domain.NewActorRoleBinding(a1, domain.RoleViewer, grantor, nil, "")
	b2, _ := domain.NewActorRoleBinding(a2, domain.RoleAdmin, grantor, nil, "")
	if err := store.AppendActorRoleBinding(ctx, b1); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendActorRoleBinding(ctx, b2); err != nil {
		t.Fatal(err)
	}

	got, err := store.ListActorRoleBindings(ctx, storage.ActorRoleBindingFilter{
		ActorKind:    string(a1.Kind),
		ActorSubject: a1.Subject,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 binding for a1; got %d", len(got))
	}
	if got[0].Actor.Subject != a1.Subject {
		t.Errorf("listed binding for wrong actor: %v", got[0].Actor)
	}
}

// TestListActiveRolesForActor_ExcludesExpired asserts the partial
// index excludes expired bindings.
func TestListActiveRolesForActor_ExcludesExpired(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subject := uniqueSlug("rbac-expired")
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: subject}
	grantor := domain.Actor{Kind: domain.ActorSystem, Subject: "test"}

	past := time.Now().UTC().Add(-time.Hour)
	expired, _ := domain.NewActorRoleBinding(actor, domain.RoleViewer, grantor, &past, "expired")
	if err := store.AppendActorRoleBinding(ctx, expired); err != nil {
		t.Fatal(err)
	}

	active, _ := domain.NewActorRoleBinding(actor, domain.RoleApprover, grantor, nil, "active")
	if err := store.AppendActorRoleBinding(ctx, active); err != nil {
		t.Fatal(err)
	}

	roles, err := store.ListActiveRolesForActor(ctx, actor)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(roles) != 1 || roles[0] != domain.RoleApprover {
		t.Errorf("active roles = %v; want [approver]", roles)
	}
}

// TestListActorRoleBindings_OnlyActive verifies the OnlyActive filter
// drops expired rows.
func TestListActorRoleBindings_OnlyActive(t *testing.T) {
	store := requireDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subject := uniqueSlug("rbac-onlyactive")
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: subject}
	grantor := domain.Actor{Kind: domain.ActorSystem, Subject: "test"}

	past := time.Now().UTC().Add(-time.Hour)
	b1, _ := domain.NewActorRoleBinding(actor, domain.RoleViewer, grantor, &past, "")
	b2, _ := domain.NewActorRoleBinding(actor, domain.RoleAdmin, grantor, nil, "")
	_ = store.AppendActorRoleBinding(ctx, b1)
	_ = store.AppendActorRoleBinding(ctx, b2)

	all, err := store.ListActorRoleBindings(ctx, storage.ActorRoleBindingFilter{
		ActorKind:    string(actor.Kind),
		ActorSubject: actor.Subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 total bindings; got %d", len(all))
	}

	active, err := store.ListActorRoleBindings(ctx, storage.ActorRoleBindingFilter{
		ActorKind:    string(actor.Kind),
		ActorSubject: actor.Subject,
		OnlyActive:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Errorf("expected 1 active binding; got %d", len(active))
	}
	if len(active) == 1 && active[0].Role != domain.RoleAdmin {
		t.Errorf("active binding role = %s; want admin", active[0].Role)
	}
}
