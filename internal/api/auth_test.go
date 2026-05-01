package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"statebound.dev/statebound/internal/domain"
)

func TestExtractBearer_MissingHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := extractBearer(r)
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected AuthError, got %v", err)
	}
	if ae.Status != http.StatusUnauthorized || ae.Code != CodeMissingToken {
		t.Fatalf("unexpected AuthError: %+v", ae)
	}
}

func TestExtractBearer_WrongScheme(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic foo")
	_, err := extractBearer(r)
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected AuthError, got %v", err)
	}
	if ae.Code != CodeInvalidToken {
		t.Fatalf("expected invalid_token, got %s", ae.Code)
	}
}

func TestExtractBearer_EmptyToken(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer ")
	_, err := extractBearer(r)
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected AuthError, got %v", err)
	}
	if ae.Code != CodeMissingToken {
		t.Fatalf("expected missing_token, got %s", ae.Code)
	}
}

func TestExtractBearer_OK(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abcdef")
	tok, err := extractBearer(r)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if tok != "abcdef" {
		t.Fatalf("got %q", tok)
	}
}

func TestDevAuthenticator_Match(t *testing.T) {
	store := newFakeStore()
	store.roles["human:alice"] = []domain.Role{domain.RoleAdmin}
	a, err := NewDevAuthenticator("right-token", "human:alice", store)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer right-token")
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.Actor.Subject != "alice" || len(id.Roles) != 1 {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestDevAuthenticator_Mismatch(t *testing.T) {
	store := newFakeStore()
	a, err := NewDevAuthenticator("right-token", "human:alice", store)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer wrong")
	_, err = a.Authenticate(r)
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected AuthError, got %v", err)
	}
	if ae.Code != CodeInvalidToken {
		t.Fatalf("expected invalid_token, got %s", ae.Code)
	}
}

func TestDevAuthenticator_RejectsEmptyToken(t *testing.T) {
	store := newFakeStore()
	if _, err := NewDevAuthenticator("", "human:alice", store); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestParseActorRef(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"human:alice@example.com", true},
		{"service_account:agent-modeler", true},
		{"system:bootstrap", true},
		{"", true}, // empty defaults to human:dev
		{"badkind:foo", false},
		{"human", false},
		{"human:", false},
	}
	for _, c := range cases {
		_, err := parseActorRef(c.in)
		if (err == nil) != c.valid {
			t.Errorf("parseActorRef(%q) err=%v, want valid=%v", c.in, err, c.valid)
		}
	}
}
