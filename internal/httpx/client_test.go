package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAppliesGranularTimeouts(t *testing.T) {
	tr := NewTransport(Options{TimeoutSec: 5})
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout not set")
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("ResponseHeaderTimeout not set")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("IdleConnTimeout not set")
	}
	if tr.DialContext == nil {
		t.Error("DialContext not set")
	}
}

func TestTLSVerifyConfigurable(t *testing.T) {
	insecure := NewTransport(Options{InsecureSkipVerify: true})
	if !insecure.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify true")
	}
	secure := NewTransport(Options{InsecureSkipVerify: false})
	if secure.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify false (F3: verify-tls)")
	}
}

func TestProxyWiring(t *testing.T) {
	tr := NewTransport(Options{Proxy: "http://127.0.0.1:8080"})
	if tr.Proxy == nil {
		t.Error("expected proxy function to be set")
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Host != "127.0.0.1:8080" {
		t.Errorf("proxy not wired correctly: u=%v err=%v", u, err)
	}
}

func TestFollowRedirectsFalse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/dest", http.StatusFound)
			return
		}
		w.WriteHeader(200)
	}))
	defer backend.Close()

	client := New(Options{FollowRedirects: false})
	resp, err := client.Get(backend.URL + "/redir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 (redirect not followed), got %d", resp.StatusCode)
	}
}

func TestHeaderInjection(t *testing.T) {
	var gotAuth, gotCookie string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(200)
	}))
	defer backend.Close()

	client := New(Options{
		Headers: []string{"Authorization: Bearer xyz"},
		Cookies: "sid=abc",
	})
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer xyz" {
		t.Errorf("expected injected Authorization, got %q", gotAuth)
	}
	if gotCookie != "sid=abc" {
		t.Errorf("expected injected Cookie, got %q", gotCookie)
	}
}
