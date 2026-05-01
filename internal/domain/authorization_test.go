package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func scopeIDPtr() *ID { id := NewID(); return &id }
func globalIDPtr() *ID { id := NewID(); return &id }

func validSudoSpec() map[string]any {
	return map[string]any{
		"asUser": "root",
		"commands": map[string]any{
			"allow": []any{"/usr/bin/systemctl status payments"},
			"deny":  []any{},
		},
	}
}

func TestNewAuthorization_Valid(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()

	cases := []struct {
		name string
		t    AuthorizationType
		spec map[string]any
	}{
		{"linux.ssh", AuthTypeLinuxSSH, map[string]any{"methods": []any{"ssh"}}},
		{"linux.sudo", AuthTypeLinuxSudo, validSudoSpec()},
		{"linux.local-group", AuthTypeLinuxLocalGroup, map[string]any{"group": "payments-runtime"}},
		{"postgres.grant", AuthTypePostgresGrant, map[string]any{"privileges": []any{"SELECT"}, "objects": []any{"public.payments"}}},
		{"kubernetes.role-binding", AuthTypeKubernetesRoleBinding, map[string]any{"role": "view", "subjects": []any{map[string]any{"kind": "Group", "name": "ops"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewAuthorization(AuthParentEntitlement, parentID, tc.t, scope, nil, tc.spec)
			if err != nil {
				t.Fatalf("NewAuthorization error: %v", err)
			}
			if a.ID == "" {
				t.Error("ID empty")
			}
			if a.CreatedAt.Location() != time.UTC {
				t.Errorf("CreatedAt not UTC")
			}
		})
	}
}

func TestNewAuthorization_TargetExclusivity(t *testing.T) {
	parentID := NewID()
	spec := map[string]any{"methods": []any{"ssh"}}
	scope := scopeIDPtr()
	gobj := globalIDPtr()

	cases := []struct {
		name  string
		scope *ID
		gobj  *ID
	}{
		{"both nil", nil, nil},
		{"both set", scope, gobj},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxSSH, tc.scope, tc.gobj, spec)
			if !errors.Is(err, ErrAuthorizationTargetExclusivity) {
				t.Errorf("err = %v, want %v", err, ErrAuthorizationTargetExclusivity)
			}
		})
	}
}

func TestNewAuthorization_Invalid_Common(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()
	spec := map[string]any{"methods": []any{"ssh"}}

	cases := []struct {
		name  string
		pkind AuthorizationParentKind
		pid   ID
		t     AuthorizationType
		want  error
	}{
		{"empty parent kind", "", parentID, AuthTypeLinuxSSH, ErrAuthorizationParentKindInvalid},
		{"bad parent kind", "weird", parentID, AuthTypeLinuxSSH, ErrAuthorizationParentKindInvalid},
		{"empty parent id", AuthParentEntitlement, "", AuthTypeLinuxSSH, ErrAuthorizationParentIDRequired},
		{"empty type", AuthParentEntitlement, parentID, "", ErrAuthorizationTypeInvalid},
		{"bad type", AuthParentEntitlement, parentID, "weird", ErrAuthorizationTypeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAuthorization(tc.pkind, tc.pid, tc.t, scope, nil, spec)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestAuthorization_LinuxSSH_Spec(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()

	t.Run("valid", func(t *testing.T) {
		_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxSSH, scope, nil, map[string]any{"methods": []any{"ssh"}})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	bad := []struct {
		name string
		spec map[string]any
	}{
		{"missing methods", map[string]any{}},
		{"methods not a list", map[string]any{"methods": "ssh"}},
		{"empty methods", map[string]any{"methods": []any{}}},
		{"unsupported method", map[string]any{"methods": []any{"telnet"}}},
		{"non-string entry", map[string]any{"methods": []any{42}}},
	}
	for _, tc := range bad {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxSSH, scope, nil, tc.spec)
			if !errors.Is(err, ErrAuthorizationSpecInvalid) {
				t.Errorf("err = %v, want errors.Is == %v", err, ErrAuthorizationSpecInvalid)
			}
		})
	}
}

func TestAuthorization_LinuxSudo_Spec(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()

	t.Run("valid with empty allow/deny", func(t *testing.T) {
		spec := map[string]any{
			"asUser":   "root",
			"commands": map[string]any{"allow": []any{}, "deny": []any{}},
		}
		_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxSudo, scope, nil, spec)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("valid with allow entries", func(t *testing.T) {
		_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxSudo, scope, nil, validSudoSpec())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	longCmd := "/" + strings.Repeat("a", linuxSudoCommandMaxLen)
	bad := []struct {
		name string
		spec map[string]any
	}{
		{"missing asUser", map[string]any{"commands": map[string]any{"allow": []any{}, "deny": []any{}}}},
		{"empty asUser", map[string]any{"asUser": "", "commands": map[string]any{"allow": []any{}, "deny": []any{}}}},
		{"asUser not string", map[string]any{"asUser": 1, "commands": map[string]any{"allow": []any{}, "deny": []any{}}}},
		{"missing commands", map[string]any{"asUser": "root"}},
		{"commands not object", map[string]any{"asUser": "root", "commands": "list"}},
		{"missing allow", map[string]any{"asUser": "root", "commands": map[string]any{"deny": []any{}}}},
		{"missing deny", map[string]any{"asUser": "root", "commands": map[string]any{"allow": []any{}}}},
		{"allow not list", map[string]any{"asUser": "root", "commands": map[string]any{"allow": "x", "deny": []any{}}}},
		{"non-absolute path", map[string]any{"asUser": "root", "commands": map[string]any{"allow": []any{"systemctl status"}, "deny": []any{}}}},
		{"empty path", map[string]any{"asUser": "root", "commands": map[string]any{"allow": []any{""}, "deny": []any{}}}},
		{"path too long", map[string]any{"asUser": "root", "commands": map[string]any{"allow": []any{longCmd}, "deny": []any{}}}},
		{"non-string in allow", map[string]any{"asUser": "root", "commands": map[string]any{"allow": []any{1}, "deny": []any{}}}},
	}
	for _, tc := range bad {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxSudo, scope, nil, tc.spec)
			if !errors.Is(err, ErrAuthorizationSpecInvalid) {
				t.Errorf("err = %v, want errors.Is == %v", err, ErrAuthorizationSpecInvalid)
			}
		})
	}
}

func TestAuthorization_LinuxLocalGroup_Spec(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()

	good := []string{"payments-runtime", "_svc", "g1", "ops_team-1"}
	for _, g := range good {
		t.Run("valid/"+g, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxLocalGroup, scope, nil, map[string]any{"group": g})
			if err != nil {
				t.Errorf("unexpected error for %q: %v", g, err)
			}
		})
	}

	bad := []struct {
		name string
		spec map[string]any
	}{
		{"missing group", map[string]any{}},
		{"empty group", map[string]any{"group": ""}},
		{"group too long", map[string]any{"group": strings.Repeat("a", linuxGroupNameMaxLen+1)}},
		{"uppercase", map[string]any{"group": "BAD"}},
		{"starts with digit", map[string]any{"group": "1foo"}},
		{"starts with hyphen", map[string]any{"group": "-foo"}},
		{"group not string", map[string]any{"group": 1}},
	}
	for _, tc := range bad {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeLinuxLocalGroup, scope, nil, tc.spec)
			if !errors.Is(err, ErrAuthorizationSpecInvalid) {
				t.Errorf("err = %v, want errors.Is == %v", err, ErrAuthorizationSpecInvalid)
			}
		})
	}
}

func TestAuthorization_PostgresGrant_Spec(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()

	t.Run("valid", func(t *testing.T) {
		spec := map[string]any{"privileges": []any{"SELECT", "INSERT"}, "objects": []any{"public.payments"}}
		_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypePostgresGrant, scope, nil, spec)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	bad := []struct {
		name string
		spec map[string]any
	}{
		{"missing privileges", map[string]any{"objects": []any{"x"}}},
		{"empty privileges", map[string]any{"privileges": []any{}, "objects": []any{"x"}}},
		{"privileges wrong type", map[string]any{"privileges": "SELECT", "objects": []any{"x"}}},
		{"missing objects", map[string]any{"privileges": []any{"SELECT"}}},
		{"empty objects", map[string]any{"privileges": []any{"SELECT"}, "objects": []any{}}},
		{"objects non-string", map[string]any{"privileges": []any{"SELECT"}, "objects": []any{42}}},
	}
	for _, tc := range bad {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypePostgresGrant, scope, nil, tc.spec)
			if !errors.Is(err, ErrAuthorizationSpecInvalid) {
				t.Errorf("err = %v, want errors.Is == %v", err, ErrAuthorizationSpecInvalid)
			}
		})
	}
}

func TestAuthorization_KubernetesRoleBinding_Spec(t *testing.T) {
	parentID := NewID()
	scope := scopeIDPtr()

	t.Run("valid", func(t *testing.T) {
		spec := map[string]any{"role": "view", "subjects": []any{map[string]any{"kind": "Group", "name": "ops"}}}
		_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeKubernetesRoleBinding, scope, nil, spec)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	bad := []struct {
		name string
		spec map[string]any
	}{
		{"missing role", map[string]any{"subjects": []any{"x"}}},
		{"empty role", map[string]any{"role": "", "subjects": []any{"x"}}},
		{"role wrong type", map[string]any{"role": 1, "subjects": []any{"x"}}},
		{"missing subjects", map[string]any{"role": "view"}},
		{"empty subjects", map[string]any{"role": "view", "subjects": []any{}}},
		{"subjects wrong type", map[string]any{"role": "view", "subjects": "ops"}},
	}
	for _, tc := range bad {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			_, err := NewAuthorization(AuthParentEntitlement, parentID, AuthTypeKubernetesRoleBinding, scope, nil, tc.spec)
			if !errors.Is(err, ErrAuthorizationSpecInvalid) {
				t.Errorf("err = %v, want errors.Is == %v", err, ErrAuthorizationSpecInvalid)
			}
		})
	}
}

func TestAuthorization_Validate(t *testing.T) {
	now := time.Now().UTC()
	scope := scopeIDPtr()
	parent := NewID()
	cases := []struct {
		name string
		a    Authorization
		want error
	}{
		{
			name: "valid linux ssh",
			a: Authorization{
				ID:           NewID(),
				ParentKind:   AuthParentEntitlement,
				ParentID:     parent,
				Type:         AuthTypeLinuxSSH,
				AssetScopeID: scope,
				Spec:         map[string]any{"methods": []any{"ssh"}},
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			want: nil,
		},
		{
			name: "neither target",
			a: Authorization{
				ID:         NewID(),
				ParentKind: AuthParentEntitlement,
				ParentID:   parent,
				Type:       AuthTypeLinuxSSH,
				Spec:       map[string]any{"methods": []any{"ssh"}},
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			want: ErrAuthorizationTargetExclusivity,
		},
		{
			name: "missing parent id",
			a: Authorization{
				ID:           NewID(),
				ParentKind:   AuthParentEntitlement,
				Type:         AuthTypeLinuxSSH,
				AssetScopeID: scope,
				Spec:         map[string]any{"methods": []any{"ssh"}},
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			want: ErrAuthorizationParentIDRequired,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.a.Validate()
			if tc.want == nil {
				if err != nil {
					t.Errorf("Validate returned %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Validate err = %v, want errors.Is == %v", err, tc.want)
			}
		})
	}
}

func TestIsValidAuthorizationParentKind(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"entitlement", true},
		{"service-account", true},
		{"global-object", true},
		{"", false},
		{"weird", false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			if got := IsValidAuthorizationParentKind(tc.s); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsValidAuthorizationType(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"linux.ssh", true},
		{"linux.sudo", true},
		{"linux.local-group", true},
		{"postgres.grant", true},
		{"kubernetes.role-binding", true},
		{"", false},
		{"weird", false},
		{"LINUX.SSH", false},
	}
	for _, tc := range cases {
		t.Run(tc.s, func(t *testing.T) {
			if got := IsValidAuthorizationType(tc.s); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
