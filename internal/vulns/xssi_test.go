package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestXSSIDetect(t *testing.T) {
	m := &XSSIModule{}
	point := input.InjectionPoint{Name: "callback", Location: input.LocQueryParam}

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
		// === TRUE POSITIVES: JSONP with sensitive data ===
		{
			name: "JSONP callback with sensitive user data",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `ryofuzz_xssi({"user":"admin","email":"admin@example.com"})`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/javascript"}},
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name: "JSONP with comment prefix",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `/**/ryofuzz_xssi({"id":123,"token":"secret"})`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/javascript"}},
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name: "JSONP without sensitive data (medium)",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `ryofuzz_xssi({"status":"ok","timestamp":1234567890})`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/javascript"}},
			wantFinding:  true,
			wantSeverity: "medium",
		},
		{
			name: "JSONP with space before paren",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `ryofuzz_xssi ({"name":"John","account":"12345"})`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/javascript"}},
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name: "FP: JSON with anti-XSSI prefix )]}'",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `)]}'` + "\n" + `{"user":"admin"}`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"application/json"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: application/json content-type with nosniff",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `ryofuzz_xssi({"user":"admin"})`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"application/json"}, "X-Content-Type-Options": {"nosniff"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: response is not JSONP format",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `{"user":"admin","email":"admin@example.com"}`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/javascript"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: non-200 status",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `ryofuzz_xssi({"error":"not found"})`,
			respStatus:   404,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/javascript"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name: "FP: application/json content-type (protection)",
			payload: mutator.Payload{Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
				Metadata: map[string]string{"callback": "ryofuzz_xssi"}},
			respBody:     `ryofuzz_xssi({"user":"admin","email":"test@test.com"})`,
			respStatus:   200,
			respTime:     110,
			baseBody:     "",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"application/json"}},
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
