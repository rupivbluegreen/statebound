package domain

import (
	"errors"
	"testing"
	"time"
)

func TestIsValidRole(t *testing.T) {
	cases := []struct {
		in   Role
		want bool
	}{
		{RoleViewer, true},
		{RoleRequester, true},
		{RoleApprover, true},
		{RoleOperator, true},
		{RoleAdmin, true},
		{Role(""), false},
		{Role("superuser"), false},
		{Role("ADMIN"), false},
	}
	for _, c := range cases {
		if got := IsValidRole(c.in); got != c.want {
			t.Errorf("IsValidRole(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRolesForCapability_Mapping(t *testing.T) {
	cases := []struct {
		cap  Capability
		want []Role
	}{
		{CapabilityProductRead, []Role{RoleViewer, RoleRequester, RoleApprover, RoleOperator, RoleAdmin}},
		{CapabilityChangeSetCreate, []Role{RoleRequester, RoleAdmin}},
		{CapabilityApprove, []Role{RoleApprover, RoleAdmin}},
		{CapabilityApply, []Role{RoleAdmin}},
		{CapabilityRoleManage, []Role{RoleAdmin}},
		// Defense-in-depth: admin must NOT auto-imply approver. Approve
		// requires either approver or admin specifically.
		{CapabilityReject, []Role{RoleApprover, RoleAdmin}},
		{CapabilityPlanGenerate, []Role{RoleOperator, RoleAdmin}},
		{CapabilityDriftScan, []Role{RoleOperator, RoleAdmin}},
		{CapabilityApplyDryRun, []Role{RoleOperator, RoleAdmin}},
	}
	for _, c := range cases {
		got := RolesForCapability(c.cap)
		if len(got) != len(c.want) {
			t.Errorf("RolesForCapability(%q) len = %d, want %d (got=%v want=%v)", c.cap, len(got), len(c.want), got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("RolesForCapability(%q)[%d] = %q, want %q", c.cap, i, got[i], c.want[i])
			}
		}
	}
}

func TestRolesForCapability_UnknownIsEmpty(t *testing.T) {
	got := RolesForCapability(Capability("invented:cap"))
	if got == nil {
		t.Fatalf("RolesForCapability of unknown cap returned nil; want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("RolesForCapability(unknown) = %v, want []", got)
	}
}

func TestRolesForCapability_ReturnsCopy(t *testing.T) {
	a := RolesForCapability(CapabilityApply)
	if len(a) != 1 || a[0] != RoleAdmin {
		t.Fatalf("expected single-admin slice, got %v", a)
	}
	a[0] = RoleViewer
	b := RolesForCapability(CapabilityApply)
	if b[0] != RoleAdmin {
		t.Errorf("internal mapping was mutated; got %v after caller mutation", b)
	}
}

func TestNewActorRoleBinding_HappyPath(t *testing.T) {
	actor := Actor{Kind: ActorHuman, Subject: "alice@example.com"}
	grantor := Actor{Kind: ActorHuman, Subject: "bootstrap"}
	b, err := NewActorRoleBinding(actor, RoleAdmin, grantor, nil, "first admin")
	if err != nil {
		t.Fatalf("NewActorRoleBinding: %v", err)
	}
	if b.ID == "" {
		t.Errorf("expected fresh ID")
	}
	if b.Actor != actor {
		t.Errorf("actor = %+v, want %+v", b.Actor, actor)
	}
	if b.Role != RoleAdmin {
		t.Errorf("role = %q, want admin", b.Role)
	}
	if b.GrantedBy != grantor {
		t.Errorf("granted_by = %+v, want %+v", b.GrantedBy, grantor)
	}
	if b.ExpiresAt != nil {
		t.Errorf("expected no expiry; got %v", *b.ExpiresAt)
	}
	if b.GrantedAt.IsZero() {
		t.Errorf("granted_at not stamped")
	}
}

func TestNewActorRoleBinding_RejectsInvalidRole(t *testing.T) {
	actor := Actor{Kind: ActorHuman, Subject: "alice"}
	grantor := Actor{Kind: ActorHuman, Subject: "bob"}
	_, err := NewActorRoleBinding(actor, Role("godmode"), grantor, nil, "")
	if err == nil {
		t.Fatalf("expected ErrRoleInvalid; got nil")
	}
	if !errors.Is(err, ErrRoleInvalid) {
		t.Errorf("error %v not ErrRoleInvalid", err)
	}
}

func TestNewActorRoleBinding_RejectsInvalidActor(t *testing.T) {
	grantor := Actor{Kind: ActorHuman, Subject: "alice"}
	_, err := NewActorRoleBinding(Actor{}, RoleViewer, grantor, nil, "")
	if err == nil {
		t.Fatalf("expected actor validation error; got nil")
	}
}

func TestNewActorRoleBinding_RejectsLongNote(t *testing.T) {
	actor := Actor{Kind: ActorHuman, Subject: "alice"}
	grantor := Actor{Kind: ActorHuman, Subject: "bob"}
	long := make([]byte, noteMaxLen+1)
	for i := range long {
		long[i] = 'x'
	}
	_, err := NewActorRoleBinding(actor, RoleViewer, grantor, nil, string(long))
	if err == nil {
		t.Fatalf("expected note-length error; got nil")
	}
}

func TestActorRoleBinding_IsActive(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	b := &ActorRoleBinding{ExpiresAt: nil}
	if !b.IsActive(now) {
		t.Errorf("nil-expiry binding should always be active")
	}

	b = &ActorRoleBinding{ExpiresAt: &future}
	if !b.IsActive(now) {
		t.Errorf("future-expiry binding should be active")
	}

	b = &ActorRoleBinding{ExpiresAt: &past}
	if b.IsActive(now) {
		t.Errorf("past-expiry binding should not be active")
	}
}

func TestAllRoles(t *testing.T) {
	got := AllRoles()
	want := []Role{RoleViewer, RoleRequester, RoleApprover, RoleOperator, RoleAdmin}
	if len(got) != len(want) {
		t.Fatalf("AllRoles length = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("AllRoles[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCapabilityRolesMap_IsCopy(t *testing.T) {
	m := CapabilityRolesMap()
	if _, ok := m[CapabilityApply]; !ok {
		t.Fatalf("CapabilityRolesMap missing apply:execute")
	}
	// Mutate the returned map. The package-level mapping must not change.
	m[CapabilityApply] = []Role{RoleViewer}
	got := RolesForCapability(CapabilityApply)
	if len(got) != 1 || got[0] != RoleAdmin {
		t.Errorf("internal map mutated after caller modified copy; got %v", got)
	}
}
