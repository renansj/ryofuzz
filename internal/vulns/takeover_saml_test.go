package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestTakeoverModule_Detect(t *testing.T) {
	m := &TakeoverModule{}
	cases := []struct {
		name        string
		respBody    string
		wantFinding bool
	}{
		{"aws s3 orphan", "<Error><Code>NoSuchBucket</Code></Error>", true},
		{"github pages orphan", "There isn't a GitHub Pages site here.", true},
		{"heroku orphan", "<title>No such app</title>", true},
		{"fastly orphan", "Fastly error: unknown domain example.com", true},
		{"shopify orphan", "Sorry, this shop is currently unavailable.", true},
		// FP guards
		{"normal page", "<html><body>Welcome to our site</body></html>", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Variant: "takeover-check", Module: "takeover"}
			got := m.Detect(p, "", 200, 0, c.respBody, 200, 0, nil)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
		})
	}
}

func TestSAMLModule_Detect(t *testing.T) {
	m := &SAMLModule{}
	cases := []struct {
		name        string
		variant     string
		baseStatus  int
		respStatus  int
		respBody    string
		setCookie   []string
		wantFinding bool
	}{
		{
			name: "session issued for forged assertion", variant: "xsw-forged-assertion",
			baseStatus: 401, respStatus: 302, respBody: "redirecting",
			setCookie: []string{"sessionid=abc; HttpOnly"}, wantFinding: true,
		},
		{
			name: "unsigned assertion accepted (401 to 200)", variant: "unsigned-assertion",
			baseStatus: 401, respStatus: 200, respBody: "<html>Dashboard</html>", wantFinding: true,
		},
		// FP guards
		{
			name: "rejected with signature error", variant: "unsigned-assertion",
			baseStatus: 401, respStatus: 200, respBody: "invalid signature on assertion", wantFinding: false,
		},
		{
			name: "both unauthorized", variant: "xsw-forged-assertion",
			baseStatus: 401, respStatus: 401, respBody: "denied", wantFinding: false,
		},
		{
			name: "baseline already authorized", variant: "unsigned-assertion",
			baseStatus: 200, respStatus: 200, respBody: "<html>Dashboard</html>", wantFinding: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Variant: c.variant, Module: "saml"}
			hdrs := map[string][]string{}
			if len(c.setCookie) > 0 {
				hdrs["Set-Cookie"] = c.setCookie
			}
			got := m.Detect(p, "", c.baseStatus, 0, c.respBody, c.respStatus, 0, hdrs)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
		})
	}
}
