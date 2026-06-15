package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestCSRFModule_Detect(t *testing.T) {
	m := &CSRFModule{}

	cases := []struct {
		name         string
		respBody     string
		setCookie    []string
		wantFinding  bool
		wantSeverity string
	}{
		{
			name:        "post form without token",
			respBody:    `<form method="post" action="/transfer"><input name="amount"></form>`,
			wantFinding: true, wantSeverity: "medium",
		},
		{
			name:        "post form without token + session cookie no samesite",
			respBody:    `<form method="post" action="/transfer"><input name="amount"></form>`,
			setCookie:   []string{"sessionid=abc; HttpOnly; Secure"},
			wantFinding: true, wantSeverity: "high",
		},
		{
			name:        "session cookie missing samesite only",
			respBody:    `<html><p>no forms here</p></html>`,
			setCookie:   []string{"PHPSESSID=xyz; Path=/"},
			wantFinding: true, wantSeverity: "medium",
		},
		// False positive guards
		{
			name:        "post form WITH csrf token",
			respBody:    `<form method="post"><input name="_token" value="abc"><input name="amount"></form>`,
			wantFinding: false,
		},
		{
			name:        "post form with authenticity_token",
			respBody:    `<form method="POST"><input type="hidden" name="authenticity_token" value="z"></form>`,
			wantFinding: false,
		},
		{
			name:        "GET form only",
			respBody:    `<form method="get" action="/search"><input name="q"></form>`,
			wantFinding: false,
		},
		{
			name:        "no form, cookie with samesite",
			respBody:    `<html>nothing</html>`,
			setCookie:   []string{"sessionid=abc; SameSite=Strict; HttpOnly"},
			wantFinding: false,
		},
		{
			name:        "no form, non-session cookie",
			respBody:    `<html>nothing</html>`,
			setCookie:   []string{"theme=dark; Path=/"},
			wantFinding: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Variant: "csrf-check", Module: "csrf"}
			hdrs := map[string][]string{}
			if len(c.setCookie) > 0 {
				hdrs["Set-Cookie"] = c.setCookie
			}
			got := m.Detect(p, "", 200, 0, c.respBody, 200, 0, hdrs)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
			if got != nil && c.wantSeverity != "" && got.Severity != c.wantSeverity {
				t.Errorf("severity: want %q got %q", c.wantSeverity, got.Severity)
			}
		})
	}
}
