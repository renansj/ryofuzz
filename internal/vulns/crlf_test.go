package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestCRLFDetect(t *testing.T) {
	m := &CRLFModule{}
	point := input.InjectionPoint{Name: "url", Location: input.LocQueryParam}

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
		// === TRUE POSITIVES: Injected header ===
		{
			name:         "injected header present in response",
			payload:      mutator.Payload{Value: "test%0d%0aInjected-Header:true", Point: point, Module: "crlf", Variant: "basic"},
			respBody:     "normal page",
			respStatus:   302,
			respTime:     110,
			baseBody:     "normal page",
			baseStatus:   302,
			baseTime:     100,
			respHeaders:  map[string][]string{"Injected-Header": {"true"}, "Location": {"http://example.com"}},
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === TRUE POSITIVES: Response splitting (XSS) ===
		{
			name:         "response splitting with script injection",
			payload:      mutator.Payload{Value: "test%0d%0a%0d%0a<script>alert(1)</script>", Point: point, Module: "crlf", Variant: "basic"},
			respBody:     "HTTP/1.1 200\r\n\r\n<script>alert(1)</script>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal page content",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/html"}},
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name:         "FP: no injected header, no script in body",
			payload:      mutator.Payload{Value: "test%0d%0aInjected-Header:true", Point: point, Module: "crlf", Variant: "basic"},
			respBody:     "normal page content without injection",
			respStatus:   200,
			respTime:     110,
			baseBody:     "normal page content without injection",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/html"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: script already in baseline",
			payload:      mutator.Payload{Value: "test%0d%0a%0d%0a<script>alert(1)</script>", Point: point, Module: "crlf", Variant: "basic"},
			respBody:     "page with <script>alert(1)</script> existing",
			respStatus:   200,
			respTime:     110,
			baseBody:     "page with <script>alert(1)</script> existing",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/html"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: payload echoed in body only (no header injection)",
			payload:      mutator.Payload{Value: "test%0d%0aInjected-Header:true", Point: point, Module: "crlf", Variant: "basic"},
			respBody:     "Error: invalid URL test%0d%0aInjected-Header:true",
			respStatus:   400,
			respTime:     110,
			baseBody:     "normal",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  map[string][]string{"Content-Type": {"text/html"}},
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: clean redirect no injection",
			payload:      mutator.Payload{Value: "test\r\nInjected-Header:true", Point: point, Module: "crlf", Variant: "basic"},
			respBody:     "",
			respStatus:   302,
			respTime:     110,
			baseBody:     "",
			baseStatus:   302,
			baseTime:     100,
			respHeaders:  map[string][]string{"Location": {"http://example.com/test"}},
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
