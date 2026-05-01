package connectors

import (
	"context"
	"testing"
)

// fakeConnector is a tiny stand-in for the registry tests. The real
// Linux connectors live in their own subpackages; this file deliberately
// avoids importing them so the registry test stays focused on registry
// semantics.
type fakeConnector struct {
	name    string
	version string
	caps    []Capability
}

func (f *fakeConnector) Name() string                   { return f.name }
func (f *fakeConnector) Version() string                { return f.version }
func (f *fakeConnector) Capabilities() []Capability     { return f.caps }
func (f *fakeConnector) ValidateDesiredState(_ context.Context, _ ApprovedState) ([]ValidationFinding, error) {
	return nil, nil
}
func (f *fakeConnector) Plan(_ context.Context, _ ApprovedState) (*PlanResult, error) {
	return &PlanResult{
		ConnectorName:    f.name,
		ConnectorVersion: f.version,
	}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()

	a := &fakeConnector{name: "linux-sudo", version: "0.4.0", caps: []Capability{CapabilityPlan}}
	b := &fakeConnector{name: "linux-ssh", version: "0.4.0", caps: []Capability{CapabilityPlan}}
	r.Register(a)
	r.Register(b)

	got, ok := r.Get("linux-sudo")
	if !ok {
		t.Fatalf("Get(linux-sudo): not found")
	}
	if got != a {
		t.Errorf("Get(linux-sudo) returned %v, want %v", got, a)
	}

	got, ok = r.Get("linux-ssh")
	if !ok {
		t.Fatalf("Get(linux-ssh): not found")
	}
	if got != b {
		t.Errorf("Get(linux-ssh) returned %v, want %v", got, b)
	}

	_, ok = r.Get("missing")
	if ok {
		t.Errorf("Get(missing) returned ok=true; want false")
	}
}

func TestRegistry_List_DeterministicOrder(t *testing.T) {
	r := NewRegistry()
	// Register out of order so we can assert the list is sorted.
	r.Register(&fakeConnector{name: "postgres", version: "0.6.0", caps: []Capability{CapabilityPlan}})
	r.Register(&fakeConnector{name: "linux-ssh", version: "0.4.0", caps: []Capability{CapabilityPlan}})
	r.Register(&fakeConnector{name: "linux-sudo", version: "0.4.0", caps: []Capability{CapabilityPlan}})

	got := r.List()
	want := []string{"linux-ssh", "linux-sudo", "postgres"}
	if len(got) != len(want) {
		t.Fatalf("len(List()) = %d, want %d", len(got), len(want))
	}
	for i, c := range got {
		if c.Name() != want[i] {
			t.Errorf("List()[%d].Name() = %q, want %q", i, c.Name(), want[i])
		}
	}
}

func TestRegistry_List_Empty(t *testing.T) {
	r := NewRegistry()
	got := r.List()
	if got == nil {
		t.Errorf("List() = nil, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len(List()) = %d, want 0", len(got))
	}
}

func TestRegistry_DuplicateRegistrationPanics(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeConnector{name: "linux-sudo", version: "0.4.0", caps: []Capability{CapabilityPlan}})

	defer func() {
		if recover() == nil {
			t.Errorf("expected panic on duplicate Register; got none")
		}
	}()
	r.Register(&fakeConnector{name: "linux-sudo", version: "0.4.1", caps: []Capability{CapabilityPlan}})
}

func TestRegistry_NilRegistrationPanics(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Errorf("expected panic on Register(nil); got none")
		}
	}()
	r.Register(nil)
}
