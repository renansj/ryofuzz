package vulns

import (
	"strings"
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestNoSQLiDetect(t *testing.T) {
	m := &NoSQLiModule{}
	point := input.InjectionPoint{Name: "user", Location: input.LocQueryParam}

	tests := []struct {
		name         string
		payload      mutator.Payload
		respBody     string
		respStatus   int
		respTime     int64
		baseBody     string
		baseStatus   int
		baseTime     int64
		respHeaders  map[string][]string
		wantFinding  bool
		wantSeverity string
	}{
		// === TRUE POSITIVES: Time-based ===
		{
			name:         "time-based mongo $where sleep",
			payload:      mutator.Payload{Value: `{"$where":"sleep(5000)"}`, Point: point, Module: "nosqli", Variant: "mongo-time"},
			respBody:     "normal",
			respStatus:   200,
			respTime:     5500,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "critical",
		},
		// === TRUE POSITIVES: Auth bypass ===
		{
			name:         "auth bypass with $ne",
			payload:      mutator.Payload{Value: `{"$ne":""}`, Point: point, Module: "nosqli", Variant: "mongo-ne"},
			respBody:     `{"user":"admin","email":"admin@example.com","role":"superuser"}` + strings.Repeat("x", 100),
			respStatus:   200,
			respTime:     110,
			baseBody:     "short",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "auth bypass with $gt",
			payload:      mutator.Payload{Value: `{"$gt":""}`, Point: point, Module: "nosqli", Variant: "mongo-gt"},
			respBody:     `{"authenticated":true,"user":"admin","token":"abc123"}` + strings.Repeat("y", 100),
			respStatus:   200,
			respTime:     110,
			baseBody:     "unauthorized",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "auth bypass with url-ne",
			payload:      mutator.Payload{Value: "[$ne]=1", Point: point, Module: "nosqli", Variant: "url-ne"},
			respBody:     `{"user":"admin","data":"secret stuff here with a lot of content to exceed the threshold"}` + strings.Repeat("z", 50),
			respStatus:   200,
			respTime:     110,
			baseBody:     "denied",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "auth bypass with mongo-auth-bypass variant",
			payload:      mutator.Payload{Value: `{"username":{"$gt":""},"password":{"$gt":""}}`, Point: point, Module: "nosqli", Variant: "mongo-auth-bypass"},
			respBody:     `{"success":true,"token":"eyJhbGciOiJIUzI1NiJ9"}` + strings.Repeat("w", 100),
			respStatus:   200,
			respTime:     110,
			baseBody:     "nope",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name:         "FP: dynamic body diff but not bypass/ne/gt variant",
			payload:      mutator.Payload{Value: `{"$where":"this.a==this.b"}`, Point: point, Module: "nosqli", Variant: "mongo-where"},
			respBody:     strings.Repeat("x", 200),
			respStatus:   200,
			respTime:     110,
			baseBody:     "short",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: time variant but no delay",
			payload:      mutator.Payload{Value: `{"$where":"sleep(5000)"}`, Point: point, Module: "nosqli", Variant: "mongo-time"},
			respBody:     "normal response",
			respStatus:   200,
			respTime:     200,
			baseBody:     "normal response",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: body diff < 100",
			payload:      mutator.Payload{Value: `{"$ne":""}`, Point: point, Module: "nosqli", Variant: "mongo-ne"},
			respBody:     "a bit longer response here with some extra content",
			respStatus:   200,
			respTime:     110,
			baseBody:     "short baseline",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: status not 200",
			payload:      mutator.Payload{Value: `{"$gt":""}`, Point: point, Module: "nosqli", Variant: "mongo-gt"},
			respBody:     strings.Repeat("x", 300),
			respStatus:   500,
			respTime:     110,
			baseBody:     "short",
			baseStatus:   200,
			baseTime:     100,
			wantFinding:  false,
			wantSeverity: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := m.Detect(tt.payload, tt.baseBody, tt.baseStatus, tt.baseTime, tt.respBody, tt.respStatus, tt.respTime, tt.respHeaders)
			if tt.wantFinding && f == nil {
				t.Fatal("expected finding, got nil")
			}
			if !tt.wantFinding && f != nil {
				t.Fatalf("expected nil, got finding: %s", f.Title)
			}
			if tt.wantFinding && f.Severity != tt.wantSeverity {
				t.Fatalf("expected severity %s, got %s", tt.wantSeverity, f.Severity)
			}
		})
	}
}
