package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestInfoLeakModule_Detect(t *testing.T) {
	m := &InfoLeakModule{}
	base := "<html>404 not found</html>"

	cases := []struct {
		name         string
		variant      string
		value        string
		respBody     string
		respStatus   int
		baseStatus   int
		wantFinding  bool
		wantSeverity string
	}{
		{
			name: "git config exposed", variant: "git-config", value: "/.git/config",
			respBody: "[core]\n\trepositoryformatversion = 0", respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "high",
		},
		{
			name: "dotenv exposed", variant: "dotenv", value: "/.env",
			respBody: "APP_KEY=base64:xxx\nDB_PASSWORD=secret123", respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "critical",
		},
		{
			name: "actuator env", variant: "actuator-env", value: "/actuator/env",
			respBody: `{"activeProfiles":[],"propertySources":[]}`, respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "critical",
		},
		{
			name: "phpinfo", variant: "phpinfo", value: "/phpinfo.php",
			respBody: "<title>phpinfo()</title>PHP Version 8.1", respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "high",
		},
		{
			name: "sourcemap", variant: "sourcemap", value: "/app.js.map",
			respBody: `{"version":3,"sources":["a.ts"],"mappings":"AAAA"}`, respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "medium",
		},
		{
			name: "aws credentials", variant: "aws-credentials", value: "/.aws/credentials",
			respBody: "[default]\naws_access_key_id = AKIA...", respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "critical",
		},
		{
			name: "generic backup 200 vs 404 baseline", variant: "backup-zip", value: "/backup.zip",
			respBody: "PK\x03\x04 binary content here", respStatus: 200, baseStatus: 404,
			wantFinding: true, wantSeverity: "high",
		},
		// False positive guards
		{
			name: "404 not flagged", variant: "git-config", value: "/.git/config",
			respBody: base, respStatus: 404, baseStatus: 404,
			wantFinding: false,
		},
		{
			name: "200 but no signature", variant: "dotenv", value: "/.env",
			respBody: "<html>welcome page</html>", respStatus: 200, baseStatus: 404,
			wantFinding: false,
		},
		{
			name: "backup but baseline also 200 (catch-all)", variant: "backup-zip", value: "/backup.zip",
			respBody: "some content", respStatus: 200, baseStatus: 200,
			wantFinding: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Value: c.value, Variant: c.variant, Module: "infoleak",
				Metadata: map[string]string{"rawpath": c.value}}
			got := m.Detect(p, base, c.baseStatus, 0, c.respBody, c.respStatus, 0, nil)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
			if got != nil && c.wantSeverity != "" && got.Severity != c.wantSeverity {
				t.Errorf("severity: want %q got %q", c.wantSeverity, got.Severity)
			}
		})
	}
}
