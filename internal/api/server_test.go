package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"statebound.dev/statebound/internal/api/handlers"
	"statebound.dev/statebound/internal/domain"
	"statebound.dev/statebound/internal/storage"
)

// fakeStore is a minimal in-memory storage stub that implements the
// subset of storage.Storage exercised by the API. Methods we don't
// need return ErrNotFound or empty slices so the test surface stays
// narrow.
type fakeStore struct {
	storage.Storage // embed for default-deny on unused methods (returns nil-method panics)

	products      []*domain.Product
	changeSets    []*domain.ChangeSet
	csItems       map[domain.ID][]*domain.ChangeSetItem
	auditEvents   []*domain.AuditEvent
	roleBindings  []*domain.ActorRoleBinding
	roles         map[string][]domain.Role // keyed by "kind:subject"
	pingErr       error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		csItems: map[domain.ID][]*domain.ChangeSetItem{},
		roles:   map[string][]domain.Role{},
	}
}

func (f *fakeStore) Close(_ context.Context) error { return nil }
func (f *fakeStore) Ping(_ context.Context) error  { return f.pingErr }
func (f *fakeStore) WithTx(ctx context.Context, fn func(tx storage.Storage) error) error {
	return fn(f)
}

func (f *fakeStore) ListProducts(_ context.Context) ([]*domain.Product, error) {
	return f.products, nil
}
func (f *fakeStore) GetProductByID(_ context.Context, id domain.ID) (*domain.Product, error) {
	for _, p := range f.products {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (f *fakeStore) ListChangeSets(_ context.Context, filter storage.ChangeSetFilter) ([]*domain.ChangeSet, error) {
	out := []*domain.ChangeSet{}
	for _, cs := range f.changeSets {
		if filter.ProductID != nil && cs.ProductID != *filter.ProductID {
			continue
		}
		if filter.State != nil && cs.State != *filter.State {
			continue
		}
		out = append(out, cs)
	}
	return out, nil
}
func (f *fakeStore) GetChangeSetByID(_ context.Context, id domain.ID) (*domain.ChangeSet, error) {
	for _, cs := range f.changeSets {
		if cs.ID == id {
			return cs, nil
		}
	}
	return nil, storage.ErrNotFound
}
func (f *fakeStore) ListChangeSetItems(_ context.Context, csID domain.ID) ([]*domain.ChangeSetItem, error) {
	return f.csItems[csID], nil
}

func (f *fakeStore) ListAuditEvents(_ context.Context, _ storage.AuditFilter) ([]*domain.AuditEvent, error) {
	// Return newest-first to match the real storage layer.
	out := make([]*domain.AuditEvent, len(f.auditEvents))
	for i, e := range f.auditEvents {
		out[len(f.auditEvents)-1-i] = e
	}
	return out, nil
}

func (f *fakeStore) ListEvidencePacksByProduct(_ context.Context, productID domain.ID, _ int) ([]*domain.EvidencePack, error) {
	return nil, nil
}
func (f *fakeStore) GetEvidencePackByID(_ context.Context, _ domain.ID) (*domain.EvidencePack, error) {
	return nil, storage.ErrEvidencePackNotFound
}

func (f *fakeStore) ListPlansByProduct(_ context.Context, _ domain.ID, _ int) ([]*domain.Plan, error) {
	return nil, nil
}
func (f *fakeStore) ListPlansByApprovedVersion(_ context.Context, _ domain.ID) ([]*domain.Plan, error) {
	return nil, nil
}
func (f *fakeStore) GetPlanByID(_ context.Context, _ domain.ID) (*domain.Plan, []*domain.PlanItem, error) {
	return nil, nil, storage.ErrPlanNotFound
}

func (f *fakeStore) ListDriftScansByProduct(_ context.Context, _ domain.ID, _ int) ([]*domain.DriftScan, error) {
	return nil, nil
}
func (f *fakeStore) GetDriftScanByID(_ context.Context, _ domain.ID) (*domain.DriftScan, []*domain.DriftFinding, error) {
	return nil, nil, storage.ErrDriftScanNotFound
}

func (f *fakeStore) ListPolicyDecisionsByChangeSet(_ context.Context, _ domain.ID) ([]*storage.PolicyDecisionRecord, error) {
	return nil, nil
}
func (f *fakeStore) GetPolicyDecisionByID(_ context.Context, _ domain.ID) (*storage.PolicyDecisionRecord, error) {
	return nil, storage.ErrPolicyDecisionNotFound
}

func (f *fakeStore) ListSigningKeys(_ context.Context, _ bool) ([]*domain.SigningKey, error) {
	return nil, nil
}
func (f *fakeStore) GetSigningKey(_ context.Context, _ string) (*domain.SigningKey, error) {
	return nil, storage.ErrSigningKeyNotFound
}

func (f *fakeStore) ListPlanApplyRecordsByPlan(_ context.Context, _ domain.ID) ([]*domain.PlanApplyRecord, error) {
	return nil, nil
}
func (f *fakeStore) GetPlanApplyRecordByID(_ context.Context, _ domain.ID) (*domain.PlanApplyRecord, error) {
	return nil, storage.ErrPlanApplyRecordNotFound
}

func (f *fakeStore) ListActorRoleBindings(_ context.Context, _ storage.ActorRoleBindingFilter) ([]*domain.ActorRoleBinding, error) {
	return f.roleBindings, nil
}
func (f *fakeStore) ListActiveRolesForActor(_ context.Context, actor domain.Actor) ([]domain.Role, error) {
	return f.roles[string(actor.Kind)+":"+actor.Subject], nil
}

// Ensure fakeStore implements the methods we use; if a future API change
// adds a new storage call, the missing-method panic from the embedded
// interface will surface immediately during a test run.
var _ storage.Storage = (*fakeStore)(nil)

// newTestServer constructs a Server bound to httptest, returning the
// server URL plus a shutdown closure. The dev token "test-token" maps
// to actor "human:tester".
func newTestServer(t *testing.T, store *fakeStore) (string, func()) {
	t.Helper()
	cfg := Config{
		Listen:      "127.0.0.1:0",
		DevToken:    "test-token",
		StaticActor: "human:tester",
	}
	cfg = applyDefaults(cfg)
	authn, err := NewDevAuthenticator(cfg.DevToken, cfg.StaticActor, store)
	if err != nil {
		t.Fatalf("NewDevAuthenticator: %v", err)
	}
	srv := &Server{cfg: cfg, store: store, auth: authn}
	ts := httptest.NewServer(srv.buildRouter())
	return ts.URL, ts.Close
}

func TestHealthz(t *testing.T) {
	store := newFakeStore()
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/healthz", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ok") {
		t.Fatalf("body %q lacks ok", body)
	}
}

func TestReadyz_OK(t *testing.T) {
	store := newFakeStore()
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/readyz", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestReadyz_StorageDown(t *testing.T) {
	store := newFakeStore()
	store.pingErr = errors.New("db down")
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/readyz", "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestOpenAPI_Served(t *testing.T) {
	store := newFakeStore()
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/openapi.yaml", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "openapi: 3.1.0") {
		t.Fatalf("body lacks 'openapi: 3.1.0'")
	}
}

func TestProducts_RequiresAuth(t *testing.T) {
	store := newFakeStore()
	url, stop := newTestServer(t, store)
	defer stop()

	// No token → 401
	resp := mustGet(t, url+"/v1/products", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	// Wrong token → 401
	resp = mustGet(t, url+"/v1/products", "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestProducts_ForbiddenWithoutRole(t *testing.T) {
	store := newFakeStore()
	// Bindings exist but tester has no role.
	store.roleBindings = []*domain.ActorRoleBinding{seedBinding("human:other", domain.RoleAdmin)}
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/v1/products", "test-token")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProducts_AllowedAsViewer(t *testing.T) {
	store := newFakeStore()
	store.roleBindings = []*domain.ActorRoleBinding{seedBinding("human:tester", domain.RoleViewer)}
	store.roles["human:tester"] = []domain.Role{domain.RoleViewer}
	prod, _ := domain.NewProduct("test-product", "team", "")
	store.products = []*domain.Product{prod}
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/v1/products", "test-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		Items []map[string]any `json:"items"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v (%s)", err, body)
	}
	if got.Count != 1 || got.Items[0]["name"] != "test-product" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestGetProduct_NotFound(t *testing.T) {
	store := newFakeStore()
	store.roleBindings = []*domain.ActorRoleBinding{seedBinding("human:tester", domain.RoleViewer)}
	store.roles["human:tester"] = []domain.Role{domain.RoleViewer}
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/v1/products/missing", "test-token")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestChangeSets_FilterByProduct(t *testing.T) {
	store := newFakeStore()
	store.roleBindings = []*domain.ActorRoleBinding{seedBinding("human:tester", domain.RoleViewer)}
	store.roles["human:tester"] = []domain.Role{domain.RoleViewer}
	prod, _ := domain.NewProduct("p1", "team", "")
	store.products = []*domain.Product{prod}
	cs, _ := domain.NewChangeSet(prod.ID, nil, "title", "desc", domain.Actor{Kind: domain.ActorHuman, Subject: "alice"})
	store.changeSets = []*domain.ChangeSet{cs}

	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/v1/change-sets?product_id="+string(prod.ID), "test-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAuditVerify_Empty(t *testing.T) {
	store := newFakeStore()
	store.roleBindings = []*domain.ActorRoleBinding{seedBinding("human:tester", domain.RoleViewer)}
	store.roles["human:tester"] = []domain.Role{domain.RoleViewer}
	url, stop := newTestServer(t, store)
	defer stop()

	resp := mustGet(t, url+"/v1/audit-events/verify", "test-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got struct {
		OK    bool `json:"ok"`
		Count int  `json:"count"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.OK {
		t.Fatalf("expected ok=true, got %v (body=%s)", got.OK, body)
	}
}

func TestSigningKeys_NoPrivateMaterial(t *testing.T) {
	// Verify the encoder shape itself can never include private bytes —
	// even when a SigningKey carries them in memory at the source.
	now := time.Now()
	pub := make([]byte, 32)
	priv := make([]byte, 64)
	for i := range priv {
		priv[i] = byte(i)
	}
	k := &domain.SigningKey{
		KeyID:         "secret-key",
		Algorithm:     domain.AlgorithmEd25519,
		PublicKey:     pub,
		PrivateKey:    priv,
		Fingerprint:   "sha256:abc",
		PrivateKeyRef: "file:/secret/path",
		CreatedBy:     domain.Actor{Kind: domain.ActorHuman, Subject: "alice"},
		CreatedAt:     now,
	}
	wired := handlers.ToSigningKey(k)
	b, err := json.Marshal(wired)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(b)
	if strings.Contains(body, "/secret/path") {
		t.Fatalf("private_key_ref leaked: %s", body)
	}
	if strings.Contains(body, "private_key_ref") {
		t.Fatalf("private_key_ref field leaked: %s", body)
	}
	if strings.Contains(body, "private_key") {
		t.Fatalf("private_key field leaked: %s", body)
	}
}

func TestNew_RefusesUnauthenticated(t *testing.T) {
	store := newFakeStore()
	_, err := New(context.Background(), Config{Listen: ":0"}, store)
	if err == nil {
		t.Fatalf("expected error for unauthenticated config")
	}
}

// ----- helpers -----

func mustGet(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

func seedBinding(actorRef string, role domain.Role) *domain.ActorRoleBinding {
	parts := strings.SplitN(actorRef, ":", 2)
	actor := domain.Actor{Kind: domain.ActorKind(parts[0]), Subject: parts[1]}
	b, _ := domain.NewActorRoleBinding(actor, role,
		domain.Actor{Kind: domain.ActorSystem, Subject: "test"}, nil, "")
	return b
}
