package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// TestRoleCmd_HelpText asserts the role subcommand surfaces the three
// expected verbs (list, grant, revoke). A help-text regression here
// would silently break operator muscle memory.
func TestRoleCmd_HelpText(t *testing.T) {
	cmd := newRoleListCmd()
	if cmd.Name() != "list" {
		t.Errorf("expected `list`; got %q", cmd.Name())
	}
	cmd = newRoleGrantCmd()
	if cmd.Name() != "grant" {
		t.Errorf("expected `grant`; got %q", cmd.Name())
	}
	if !cmd.Flags().Lookup("bootstrap").Hidden && cmd.Flags().Lookup("bootstrap") == nil {
		t.Errorf("--bootstrap flag missing")
	}
	cmd = newRoleRevokeCmd()
	if cmd.Name() != "revoke" {
		t.Errorf("expected `revoke`; got %q", cmd.Name())
	}
	if cmd.Flags().Lookup("binding") == nil {
		t.Errorf("--binding flag missing on revoke")
	}
}

// TestParseActorRef covers the kind:subject parser used by `role grant`
// and `role list --actor`.
func TestParseActorRef(t *testing.T) {
	cases := []struct {
		in       string
		wantKind string
		wantSub  string
		wantErr  bool
	}{
		{"human:alice@example.com", "human", "alice@example.com", false},
		{"service_account:agent-modeler", "service_account", "agent-modeler", false},
		{"system:bootstrap", "system", "bootstrap", false},
		{"alice", "", "", true},
		{":alice", "", "", true},
		{"human:", "", "", true},
		{"unknown:foo", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		k, s, err := parseActorRef(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseActorRef(%q) = (%q, %q); want error", c.in, k, s)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseActorRef(%q): unexpected error %v", c.in, err)
			continue
		}
		if k != c.wantKind || s != c.wantSub {
			t.Errorf("parseActorRef(%q) = (%q, %q); want (%q, %q)",
				c.in, k, s, c.wantKind, c.wantSub)
		}
	}
}

// TestRequireCapability_BootstrapOpenGate asserts the bootstrap path:
// when actor_role_bindings is empty, requireCapability passes for any
// actor + any capability so the first admin can be granted.
func TestRequireCapability_BootstrapOpenGate(t *testing.T) {
	stub := &rbacStub{} // no bindings, no roles
	var stderr bytes.Buffer
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "anyone"}
	if err := requireCapability(context.Background(), stub, &stderr, actor, domain.CapabilityApply); err != nil {
		t.Fatalf("bootstrap path returned error: %v", err)
	}
	if !strings.Contains(stderr.String(), "actor_role_bindings is empty") {
		t.Errorf("expected bootstrap warning on stderr; got %q", stderr.String())
	}
}

// TestRequireCapability_DeniesWithoutRole asserts that once at least
// one binding exists, an actor without the required role is denied
// and an audit event is emitted.
func TestRequireCapability_DeniesWithoutRole(t *testing.T) {
	stub := &rbacStub{
		bindings: []*domain.ActorRoleBinding{
			{
				ID:        domain.NewID(),
				Actor:     domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
				Role:      domain.RoleAdmin,
				GrantedBy: domain.Actor{Kind: domain.ActorSystem, Subject: "bootstrap"},
				GrantedAt: time.Now().UTC(),
			},
		},
		rolesByActor: map[string][]domain.Role{}, // eve has no roles
	}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "eve"}
	err := requireCapability(context.Background(), stub, nil, actor, domain.CapabilityApprove)
	if err == nil {
		t.Fatalf("expected denial; got nil")
	}
	if !strings.Contains(err.Error(), "lacks capability") {
		t.Errorf("error %q missing 'lacks capability'", err.Error())
	}
	if len(stub.appendedEvents) != 1 {
		t.Fatalf("expected one audit event; got %d", len(stub.appendedEvents))
	}
	evt := stub.appendedEvents[0]
	if evt.Kind != domain.EventRBACDenied {
		t.Errorf("audit kind = %q; want rbac.denied", evt.Kind)
	}
	if got := evt.Payload["capability"]; got != string(domain.CapabilityApprove) {
		t.Errorf("payload.capability = %v; want %q", got, domain.CapabilityApprove)
	}
}

// TestRequireCapability_AllowsWithRole asserts the happy path: an
// actor with at least one of the required roles passes and no audit
// event is emitted.
func TestRequireCapability_AllowsWithRole(t *testing.T) {
	stub := &rbacStub{
		bindings: []*domain.ActorRoleBinding{
			{
				ID:        domain.NewID(),
				Actor:     domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
				Role:      domain.RoleAdmin,
				GrantedBy: domain.Actor{Kind: domain.ActorSystem, Subject: "bootstrap"},
				GrantedAt: time.Now().UTC(),
			},
		},
		rolesByActor: map[string][]domain.Role{
			"human:alice": {domain.RoleAdmin},
		},
	}
	actor := domain.Actor{Kind: domain.ActorHuman, Subject: "alice"}
	if err := requireCapability(context.Background(), stub, nil, actor, domain.CapabilityApply); err != nil {
		t.Fatalf("alice (admin) denied for apply: %v", err)
	}
	if len(stub.appendedEvents) != 0 {
		t.Errorf("audit event emitted on allow; got %d events", len(stub.appendedEvents))
	}
}

// TestRunApprove_RBACDeniesNonApprover asserts the integration: an
// actor without the approver role is rejected by runApprove BEFORE
// the four-eyes check fires.
func TestRunApprove_RBACDeniesNonApprover(t *testing.T) {
	stubPolicyGate(t)
	requester := domain.Actor{Kind: domain.ActorHuman, Subject: "alice"}
	approver := domain.Actor{Kind: domain.ActorHuman, Subject: "bob"}
	productID := domain.ID("00000000-0000-0000-0000-000000000aaa")
	csID := domain.ID("00000000-0000-0000-0000-000000000ccc")

	cs := &domain.ChangeSet{
		ID:          csID,
		ProductID:   productID,
		State:       domain.ChangeSetStateSubmitted,
		Title:       "test",
		RequestedBy: requester,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	stub := &rbacApprovalStub{
		fourEyesStub: fourEyesStub{
			changeSets: map[domain.ID]*domain.ChangeSet{csID: cs},
			products: map[domain.ID]*domain.Product{
				productID: {ID: productID, Name: "test-product"},
			},
		},
		bindings: []*domain.ActorRoleBinding{
			{
				ID:    domain.NewID(),
				Actor: domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
				Role:  domain.RoleAdmin,
			},
		},
		rolesByActor: map[string][]domain.Role{
			"human:bob": {domain.RoleViewer}, // no approver/admin
		},
	}

	var buf bytes.Buffer
	err := runApprove(context.Background(), stub, &buf, csID, approver, "looks good")
	if err == nil {
		t.Fatalf("runApprove returned nil; want RBAC denial")
	}
	if !strings.Contains(err.Error(), "lacks capability") {
		t.Errorf("error %q is not the RBAC denial", err.Error())
	}
}

// rbacStub is a storage stub focused on the RBAC surface. It records
// audit events the helper writes so tests can inspect them.
type rbacStub struct {
	storage.Storage
	bindings       []*domain.ActorRoleBinding
	rolesByActor   map[string][]domain.Role
	appendedEvents []*domain.AuditEvent
}

func (s *rbacStub) Close(_ context.Context) error { return nil }
func (s *rbacStub) Ping(_ context.Context) error  { return nil }

func (s *rbacStub) ListActorRoleBindings(_ context.Context, f storage.ActorRoleBindingFilter) ([]*domain.ActorRoleBinding, error) {
	if f.Limit > 0 && len(s.bindings) > f.Limit {
		return s.bindings[:f.Limit], nil
	}
	return s.bindings, nil
}

func (s *rbacStub) ListActiveRolesForActor(_ context.Context, actor domain.Actor) ([]domain.Role, error) {
	key := string(actor.Kind) + ":" + actor.Subject
	return s.rolesByActor[key], nil
}

func (s *rbacStub) AppendAuditEvent(_ context.Context, e *domain.AuditEvent) error {
	if e == nil {
		return errors.New("nil audit event")
	}
	s.appendedEvents = append(s.appendedEvents, e)
	return nil
}

// rbacApprovalStub composes fourEyesStub with the RBAC surface so the
// integration test exercises the full runApprove path.
type rbacApprovalStub struct {
	fourEyesStub
	bindings       []*domain.ActorRoleBinding
	rolesByActor   map[string][]domain.Role
	appendedEvents []*domain.AuditEvent
}

func (s *rbacApprovalStub) ListActorRoleBindings(_ context.Context, f storage.ActorRoleBindingFilter) ([]*domain.ActorRoleBinding, error) {
	if f.Limit > 0 && len(s.bindings) > f.Limit {
		return s.bindings[:f.Limit], nil
	}
	return s.bindings, nil
}

func (s *rbacApprovalStub) ListActiveRolesForActor(_ context.Context, actor domain.Actor) ([]domain.Role, error) {
	key := string(actor.Kind) + ":" + actor.Subject
	return s.rolesByActor[key], nil
}

func (s *rbacApprovalStub) AppendAuditEvent(_ context.Context, e *domain.AuditEvent) error {
	if e == nil {
		return errors.New("nil audit event")
	}
	s.appendedEvents = append(s.appendedEvents, e)
	return nil
}
