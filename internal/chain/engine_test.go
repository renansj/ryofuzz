package chain

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/vulns"
)

func TestChainDetect(t *testing.T) {
	pt := input.InjectionPoint{Name: "url", Location: input.LocQueryParam}

	tests := []struct {
		name      string
		findings  []*vulns.Finding
		wantChain string
		wantNil   bool
	}{
		{
			"SSRF triggers cloud cred chain",
			[]*vulns.Finding{{Module: "ssrf", Severity: "critical", Title: "SSRF", Point: pt}},
			"[CHAIN] SSRF to Cloud Credentials",
			false,
		},
		{
			"redirect + oauth triggers ATO chain",
			[]*vulns.Finding{
				{Module: "redirect", Severity: "medium", Title: "Open Redirect", Point: pt},
				{Module: "oauth", Severity: "high", Title: "OAuth", Point: pt},
			},
			"[CHAIN] Open Redirect + OAuth = Account Takeover",
			false,
		},
		{
			"xss + cors triggers cross-origin chain",
			[]*vulns.Finding{
				{Module: "xss", Severity: "high", Title: "XSS", Point: pt},
				{Module: "cors", Severity: "medium", Title: "CORS", Point: pt},
			},
			"[CHAIN] XSS + CORS Misconfiguration = Cross-Origin Data Theft",
			false,
		},
		{
			"jwt triggers auth bypass chain",
			[]*vulns.Finding{{Module: "jwt", Severity: "critical", Title: "JWT", Point: pt}},
			"[CHAIN] JWT Algorithm Confusion = Auth Bypass",
			false,
		},
		{
			"no matching findings emits no chain",
			[]*vulns.Finding{{Module: "crlf", Severity: "medium", Title: "CRLF", Point: pt}},
			"",
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chains := Detect(tc.findings)
			if tc.wantNil {
				if len(chains) != 0 {
					t.Fatalf("expected no chains, got %d: %s", len(chains), chains[0].Title)
				}
				return
			}
			found := false
			for _, c := range chains {
				if c.Title == tc.wantChain {
					found = true
					if c.Module != "chain" {
						t.Fatalf("expected module 'chain', got %s", c.Module)
					}
					break
				}
			}
			if !found {
				titles := ""
				for _, c := range chains {
					titles += c.Title + "; "
				}
				t.Fatalf("expected chain %q not found in: %s", tc.wantChain, titles)
			}
		})
	}
}
