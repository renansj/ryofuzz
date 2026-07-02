package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A server that returns the same full data regardless of identity models a
// broken-access-control endpoint: anon and a low-priv user see what only an
// admin should. TestEndpoint must flag it.
func TestBrokenAccessControlDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(strings.Repeat("sensitive-record;", 20))) // >100 bytes
	}))
	defer srv.Close()

	ids := []Identity{
		{Name: "anon", Headers: nil},
		{Name: "admin", Headers: map[string]string{"Authorization": "Bearer admin"}},
	}
	findings := TestEndpoint(context.Background(), srv.Client(), "GET", srv.URL+"/api/users/1", "", ids)
	if len(findings) == 0 {
		t.Fatal("expected a broken-access-control finding when anon sees admin data")
	}
	if findings[0].Type != "broken-auth" {
		t.Errorf("expected broken-auth, got %q", findings[0].Type)
	}
}

// A properly protected endpoint: anon is denied (403, no data), admin gets data.
// No finding should be produced.
func TestProtectedEndpointNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(strings.Repeat("sensitive-record;", 20)))
	}))
	defer srv.Close()

	ids := []Identity{
		{Name: "anon", Headers: nil},
		{Name: "admin", Headers: map[string]string{"Authorization": "Bearer admin"}},
	}
	findings := TestEndpoint(context.Background(), srv.Client(), "GET", srv.URL+"/api/users/1", "", ids)
	if len(findings) != 0 {
		t.Errorf("expected no finding on a protected endpoint, got %d: %+v", len(findings), findings)
	}
}

func TestContextCancelStopsAuthz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	ids := []Identity{{Name: "anon"}, {Name: "admin"}}
	// Should return without panic and produce no findings.
	if f := TestEndpoint(ctx, srv.Client(), "GET", srv.URL, "", ids); len(f) != 0 {
		t.Errorf("expected no findings on cancelled context, got %d", len(f))
	}
}
