package vulns

import (
	"strings"
	"testing"

	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestClickjackModule_Detect(t *testing.T) {
	m := &ClickjackModule{}
	cases := []struct {
		name        string
		headers     map[string][]string
		wantFinding bool
	}{
		{"no protection html", map[string][]string{"Content-Type": {"text/html"}}, true},
		{"has x-frame-options", map[string][]string{"Content-Type": {"text/html"}, "X-Frame-Options": {"DENY"}}, false},
		{"has csp frame-ancestors", map[string][]string{"Content-Type": {"text/html"}, "Content-Security-Policy": {"frame-ancestors 'self'"}}, false},
		{"non-html not flagged", map[string][]string{"Content-Type": {"application/json"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Variant: "frame-check", Module: "clickjack"}
			got := m.Detect(p, "", 200, 0, "<html></html>", 200, 0, c.headers)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
		})
	}
}

func TestReDoSModule_Detect(t *testing.T) {
	m := &ReDoSModule{}
	t.Run("catastrophic delay", func(t *testing.T) {
		p := mutator.Payload{Value: strings.Repeat("a", 100), Module: "redos", Variant: "catastrophic-0"}
		got := m.Detect(p, "", 200, 100, "ok", 200, 5000, nil)
		if got == nil {
			t.Fatal("expected finding for large delay")
		}
	})
	t.Run("no delay", func(t *testing.T) {
		p := mutator.Payload{Value: "a", Module: "redos", Variant: "catastrophic-0"}
		got := m.Detect(p, "", 200, 100, "ok", 200, 150, nil)
		if got != nil {
			t.Fatal("did not expect finding without delay")
		}
	})
}

func TestXSLTModule_Detect(t *testing.T) {
	m := &XSLTModule{}
	cases := []struct {
		name        string
		respBody    string
		wantFinding bool
		wantSev     string
	}{
		{"file read", "result: root:x:0:0:root:/root:/bin/bash", true, "critical"},
		{"libxslt leak", "Error in libxslt processing", true, "high"},
		{"clean", "<html>normal page</html>", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Value: "x", Module: "xslt", Variant: "file-read"}
			got := m.Detect(p, "baseline", 200, 0, c.respBody, 200, 0, nil)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
			if got != nil && c.wantSev != "" && got.Severity != c.wantSev {
				t.Errorf("sev want %q got %q", c.wantSev, got.Severity)
			}
		})
	}
}

func TestSessionModule_Detect(t *testing.T) {
	m := &SessionModule{}
	cases := []struct {
		name        string
		cookie      string
		wantFinding bool
	}{
		{"missing httponly and secure", "sessionid=abcdefghijklmnopqrstuvwxyz; Path=/", true},
		{"short token", "sid=abc; HttpOnly; Secure", true},
		{"secure session ok", "sessionid=abcdefghijklmnopqrstuvwxyz123456; HttpOnly; Secure; SameSite=Strict", false},
		{"non-session cookie", "theme=dark; Path=/", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Variant: "session-check", Module: "session"}
			hdrs := map[string][]string{"Set-Cookie": {c.cookie}}
			got := m.Detect(p, "", 200, 0, "", 200, 0, hdrs)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
		})
	}
}

func TestUserEnumModule_Detect(t *testing.T) {
	m := &UserEnumModule{}
	cases := []struct {
		name        string
		respBody    string
		wantFinding bool
	}{
		{"user not found message", "Error: user not found", true},
		{"email not found", "No account with that email", true},
		{"generic error", "Invalid credentials", false},
		{"success", "Welcome back", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Value: "x", Module: "userenum", Variant: "invalid-user"}
			got := m.Detect(p, "", 200, 0, c.respBody, 200, 0, nil)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
		})
	}
}
