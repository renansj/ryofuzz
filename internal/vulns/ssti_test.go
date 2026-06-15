package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestSSTIDetect_MathMarker(t *testing.T) {
	m := &SSTIModule{}
	p := mutator.Payload{
		Value:    "{{7*7}}",
		Point:    input.InjectionPoint{Name: "name", Location: input.LocQueryParam},
		Module:   "ssti",
		Variant:  "jinja2/twig",
		Metadata: map[string]string{"expected": "49"},
	}
	f := m.Detect(p, "Hello user", 200, 100, "Hello 49 user", 200, 110, nil)
	if f == nil {
		t.Fatal("expected finding for SSTI 49 marker, got nil")
	}
	if f.Module != "ssti" {
		t.Fatalf("expected module ssti, got %s", f.Module)
	}
	if f.Severity != "critical" {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
}

func TestSSTIDetect_Clean(t *testing.T) {
	m := &SSTIModule{}
	p := mutator.Payload{
		Value:    "{{7*7}}",
		Point:    input.InjectionPoint{Name: "name", Location: input.LocQueryParam},
		Module:   "ssti",
		Variant:  "jinja2/twig",
		Metadata: map[string]string{"expected": "49"},
	}
	f := m.Detect(p, "Hello user", 200, 100, "Hello user", 200, 110, nil)
	if f != nil {
		t.Fatalf("expected nil for clean response, got finding: %s", f.Title)
	}
}
