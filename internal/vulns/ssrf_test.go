package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestSSRFDetect_AWSMetadata(t *testing.T) {
	m := &SSRFModule{}
	p := mutator.Payload{Value: "http://169.254.169.254/latest/meta-data/", Point: input.InjectionPoint{Name: "url", Location: input.LocQueryParam}, Module: "ssrf", Variant: "metadata"}
	f := m.Detect(p, "normal page", 200, 100, "ami-id: ami-12345\nsecurity-credentials: role", 200, 120, nil)
	if f == nil {
		t.Fatal("expected finding for AWS metadata, got nil")
	}
	if f.Severity != "critical" {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
	if f.Module != "ssrf" {
		t.Fatalf("expected module ssrf, got %s", f.Module)
	}
}

func TestSSRFDetect_InternalWithGuard(t *testing.T) {
	m := &SSRFModule{}
	// Payload targeting internal resource (variant contains "internal")
	p := mutator.Payload{Value: "http://127.0.0.1:8080/", Point: input.InjectionPoint{Name: "url", Location: input.LocQueryParam}, Module: "ssrf", Variant: "internal-8080"}
	f := m.Detect(p, "normal", 200, 100, "root:x:0:0:root:/root:/bin/bash", 200, 120, nil)
	if f == nil {
		t.Fatal("expected finding for internal resource with internal variant, got nil")
	}

	// Payload NOT targeting internal (variant without internal/bypass/localhost, value without 127./localhost/0.0.0.0)
	p2 := mutator.Payload{Value: "http://example.com/", Point: input.InjectionPoint{Name: "url", Location: input.LocQueryParam}, Module: "ssrf", Variant: "external"}
	f2 := m.Detect(p2, "normal", 200, 100, "root:x:0:0:root:/root:/bin/bash", 200, 120, nil)
	if f2 != nil {
		t.Fatalf("expected nil for non-internal payload, got finding: %s", f2.Title)
	}
}

func TestSSRFDetect_Clean(t *testing.T) {
	m := &SSRFModule{}
	p := mutator.Payload{Value: "http://169.254.169.254/latest/meta-data/", Point: input.InjectionPoint{Name: "url", Location: input.LocQueryParam}, Module: "ssrf", Variant: "metadata"}
	f := m.Detect(p, "normal page", 200, 100, "Nothing interesting here", 200, 110, nil)
	if f != nil {
		t.Fatalf("expected nil for clean response, got finding: %s", f.Title)
	}
}
