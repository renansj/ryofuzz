package analyzer

import (
	"net/http"
	"testing"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/vulns"
)

func TestFilterFalsePositives(t *testing.T) {
	pt := input.InjectionPoint{Name: "q", Location: input.LocQueryParam}
	baseline := &engine.Response{StatusCode: 200, Body: "normal"}

	tests := []struct {
		name     string
		finding  *vulns.Finding
		result   engine.FuzzResult
		filtered bool
	}{
		{
			"XSS in JSON response is FP",
			&vulns.Finding{Module: "xss", Title: "XSS", Payload: "<script>alert(1)</script>", Point: pt},
			engine.FuzzResult{
				Payload:  mutator.Payload{Value: "<script>alert(1)</script>", Point: pt, Module: "xss"},
				Response: engine.Response{StatusCode: 200, Body: `{"url":"<script>alert(1)</script>"}`, Headers: http.Header{"Content-Type": {"application/json"}}},
			},
			true,
		},
		{
			"Prototype pollution echoed in JSON error is FP",
			&vulns.Finding{Module: "prototype", Confidence: "high", Title: "Prototype Pollution", Payload: `{"__proto__":{"polluted":"yes"}}`, Point: pt},
			engine.FuzzResult{
				Payload:  mutator.Payload{Value: `{"__proto__":{"polluted":"yes"}}`, Point: pt, Module: "prototype"},
				Response: engine.Response{StatusCode: 200, Body: `{"error":"invalid","url":"{\"__proto__\":{\"polluted\":\"yes\"}}"}`, Headers: http.Header{"Content-Type": {"application/json"}}},
			},
			true,
		},
		{
			"Real XSS in HTML is kept",
			&vulns.Finding{Module: "xss", Title: "XSS", Payload: "<script>alert(1)</script>", Point: pt},
			engine.FuzzResult{
				Payload:  mutator.Payload{Value: "<script>alert(1)</script>", Point: pt, Module: "xss"},
				Response: engine.Response{StatusCode: 200, Body: `<html><script>alert(1)</script></html>`, Headers: http.Header{"Content-Type": {"text/html"}}},
			},
			false,
		},
		{
			"CRLF finding in JSON with no actual header injection is FP",
			&vulns.Finding{Module: "crlf", Title: "CRLF Injection", Evidence: "HTML injected via response splitting", Payload: "test%0d%0a", Point: pt},
			engine.FuzzResult{
				Payload:  mutator.Payload{Value: "test%0d%0a", Point: pt, Module: "crlf"},
				Response: engine.Response{StatusCode: 200, Body: `{"error":"test"}`, Headers: http.Header{"Content-Type": {"application/json"}}},
			},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := []engine.FuzzResult{tc.result}
			out := FilterFalsePositives(baseline, []*vulns.Finding{tc.finding}, results)
			if tc.filtered && len(out) > 0 {
				t.Fatalf("expected finding to be filtered out, but it was kept")
			}
			if !tc.filtered && len(out) == 0 {
				t.Fatalf("expected finding to be kept, but it was filtered out")
			}
		})
	}
}
