package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestXSSDetect(t *testing.T) {
	m := &XSSModule{}
	point := input.InjectionPoint{Name: "q", Location: input.LocQueryParam}
	htmlHeaders := map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}
	jsonHeaders := map[string][]string{"Content-Type": {"application/json"}}

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
		// === TRUE POSITIVES: HTML body with tags ===
		{
			name:         "reflected script tag in html_body",
			payload:      mutator.Payload{Value: "<script>alert(1)</script>", Point: point, Module: "xss", Variant: "basic"},
			respBody:     "<html><body>Search: <script>alert(1)</script></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body>Search: </body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "reflected img onerror in html_body",
			payload:      mutator.Payload{Value: "<img src=x onerror=alert(1)>", Point: point, Module: "xss", Variant: "event-handler"},
			respBody:     "<html><body>Result: <img src=x onerror=alert(1)></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body>Result: </body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "reflected svg onload",
			payload:      mutator.Payload{Value: "<svg onload=alert(1)>", Point: point, Module: "xss", Variant: "svg"},
			respBody:     "<html><body>Here: <svg onload=alert(1)></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body>Here: </body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === TRUE POSITIVES: Attribute context (with break tag) ===
		{
			name:         "attribute breakout with script tag",
			payload:      mutator.Payload{Value: `"><script>alert(1)</script>`, Point: point, Module: "xss", Variant: "attr-break"},
			respBody:     `<html><body><input value=""><script>alert(1)</script>" /></body></html>`,
			respStatus:   200,
			respTime:     110,
			baseBody:     `<html><body><input value="" /></body></html>`,
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === TRUE POSITIVES: Script context (with closing/opening tags) ===
		{
			name:         "script break with closing and opening tags",
			payload:      mutator.Payload{Value: "</script><script>alert(1)</script>", Point: point, Module: "xss", Variant: "script-break"},
			respBody:     "<html><body><script>var x='</script><script>alert(1)</script>';</script></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body><script>var x='';</script></body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === TRUE POSITIVES: Empty Content-Type (treated as HTML) ===
		{
			name:         "reflected with empty content-type",
			payload:      mutator.Payload{Value: "<script>alert(1)</script>", Point: point, Module: "xss", Variant: "basic"},
			respBody:     "<html><body><script>alert(1)</script></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body></body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  nil,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === PAYLOAD DIVERSITY ===
		{
			name:         "case-varied ScRiPt tag",
			payload:      mutator.Payload{Value: "<ScRiPt>alert(1)</ScRiPt>", Point: point, Module: "xss", Variant: "waf-case"},
			respBody:     "<html><body><ScRiPt>alert(1)</ScRiPt></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body></body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		{
			name:         "encoded payload with angle brackets",
			payload:      mutator.Payload{Value: "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", Point: point, Module: "xss", Variant: "waf-decimal"},
			respBody:     "<html><body><img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body></body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  true,
			wantSeverity: "high",
		},
		// === FALSE POSITIVE GUARDS ===
		{
			name:         "FP: application/json content-type returns info",
			payload:      mutator.Payload{Value: "<script>alert(1)</script>", Point: point, Module: "xss", Variant: "basic"},
			respBody:     `{"error": "<script>alert(1)</script>"}`,
			respStatus:   200,
			respTime:     110,
			baseBody:     `{"error": ""}`,
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  jsonHeaders,
			wantFinding:  true,
			wantSeverity: "info",
		},
		{
			name:         "FP: HTML-encoded (safe)",
			payload:      mutator.Payload{Value: "<script>alert(1)</script>", Point: point, Module: "xss", Variant: "basic"},
			respBody:     "<html><body>Search: <script>alert(1)</script> &lt;script&gt;alert(1)&lt;/script&gt;</body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body>Search: </body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: payload present in baseline",
			payload:      mutator.Payload{Value: "<script>alert(1)</script>", Point: point, Module: "xss", Variant: "basic"},
			respBody:     "<html><body><script>alert(1)</script></body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body><script>alert(1)</script></body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
			wantFinding:  false,
			wantSeverity: "",
		},
		{
			name:         "FP: payload not reflected at all",
			payload:      mutator.Payload{Value: "<script>alert(1)</script>", Point: point, Module: "xss", Variant: "basic"},
			respBody:     "<html><body>Welcome to the site</body></html>",
			respStatus:   200,
			respTime:     110,
			baseBody:     "<html><body>Welcome to the site</body></html>",
			baseStatus:   200,
			baseTime:     100,
			respHeaders:  htmlHeaders,
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
