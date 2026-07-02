package httpx

import "testing"

func TestScopeAllowlist(t *testing.T) {
	s := NewScope([]string{"example.com"}, true)
	cases := map[string]bool{
		"http://example.com/x":     true,
		"http://api.example.com/y": true, // subdomain
		"http://evil.com/z":        false,
		"http://notexample.com/":   false,
	}
	for u, want := range cases {
		got, _ := s.Allowed(u)
		if got != want {
			t.Errorf("Allowed(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestScopeBlocksInternalByDefault(t *testing.T) {
	s := NewScope(nil, false) // no allowlist, internal denied
	blocked := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:8080/",
		"http://10.0.0.5/",
		"http://192.168.1.1/",
		"http://metadata.google.internal/",
	}
	for _, u := range blocked {
		if ok, _ := s.Allowed(u); ok {
			t.Errorf("Allowed(%q) = true, want false (internal must be blocked)", u)
		}
	}
	// A public host with no allowlist is fine.
	if ok, _ := s.Allowed("http://example.com/"); !ok {
		t.Error("public host should be allowed with empty allowlist")
	}
}

func TestScopeAllowInternal(t *testing.T) {
	s := NewScope(nil, true) // labs: internal permitted
	if ok, _ := s.Allowed("http://127.0.0.1:18100/"); !ok {
		t.Error("internal host should be allowed when allowInternal=true")
	}
}
