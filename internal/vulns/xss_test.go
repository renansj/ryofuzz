package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestXSSDetect_ReflectedHTML(t *testing.T) {
	m := &XSSModule{}
	p := mutator.Payload{
		Value:   "<script>alert(1)</script>",
		Point:   input.InjectionPoint{Name: "q", Location: input.LocQueryParam},
		Module:  "xss",
		Variant: "basic",
	}
	headers := map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}
	respBody := "<html><body>Search: <script>alert(1)</script></body></html>"
	f := m.Detect(p, "<html><body>Search: </body></html>", 200, 100, respBody, 200, 110, headers)
	if f == nil {
		t.Fatal("expected finding for reflected XSS in HTML, got nil")
	}
	if f.Module != "xss" {
		t.Fatalf("expected module xss, got %s", f.Module)
	}
}

func TestXSSDetect_HTMLEncoded(t *testing.T) {
	m := &XSSModule{}
	p := mutator.Payload{
		Value:   "<script>alert(1)</script>",
		Point:   input.InjectionPoint{Name: "q", Location: input.LocQueryParam},
		Module:  "xss",
		Variant: "basic",
	}
	headers := map[string][]string{"Content-Type": {"text/html; charset=utf-8"}}
	// Body contains both the raw payload AND the encoded version
	respBody := "<html><body>Search: <script>alert(1)</script> and &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
	f := m.Detect(p, "<html><body>Search: </body></html>", 200, 100, respBody, 200, 110, headers)
	// The encoded check: if respBody contains the html-encoded form, returns nil
	if f != nil {
		t.Fatalf("expected nil for HTML-encoded reflection, got finding: %s", f.Title)
	}
}

func TestXSSDetect_NonHTMLContentType(t *testing.T) {
	m := &XSSModule{}
	p := mutator.Payload{
		Value:   "<script>alert(1)</script>",
		Point:   input.InjectionPoint{Name: "q", Location: input.LocQueryParam},
		Module:  "xss",
		Variant: "basic",
	}
	headers := map[string][]string{"Content-Type": {"application/json"}}
	respBody := `{"result": "<script>alert(1)</script>"}`
	f := m.Detect(p, `{"result": ""}`, 200, 100, respBody, 200, 110, headers)
	// Non-HTML returns an info-level finding (not nil), but severity is info
	if f == nil {
		t.Fatal("expected info finding for non-HTML, got nil")
	}
	if f.Severity != "info" {
		t.Fatalf("expected severity info for non-HTML, got %s", f.Severity)
	}
}
