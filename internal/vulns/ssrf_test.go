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

func TestSSRFDetect_Extended(t *testing.T) {
	m := &SSRFModule{}
	pt := input.InjectionPoint{Name: "url", Location: input.LocQueryParam}

	tests := []struct {
		name    string
		payload mutator.Payload
		base    string
		resp    string
		wantNil bool
	}{
		{
			name:    "TP GCP metadata indicator",
			payload: mutator.Payload{Value: "http://metadata.google.internal/computeMetadata/v1/", Point: pt, Module: "ssrf", Variant: "gcp-metadata"},
			base:    "normal page",
			resp:    "project-id: my-project\nmeta-data items",
			wantNil: false,
		},
		{
			name:    "TP AccessKeyId in response",
			payload: mutator.Payload{Value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Point: pt, Module: "ssrf", Variant: "metadata-iam"},
			base:    "no secrets",
			resp:    `{"AccessKeyId":"AKIA...","SecretAccessKey":"xxx","Token":"yyy"}`,
			wantNil: false,
		},
		{
			name:    "TP root file via localhost payload",
			payload: mutator.Payload{Value: "http://127.0.0.1/etc/passwd", Point: pt, Module: "ssrf", Variant: "internal-localhost"},
			base:    "normal",
			resp:    "root:x:0:0:root:/root:/bin/bash",
			wantNil: false,
		},
		{
			name:    "TP bypass variant with private keyword",
			payload: mutator.Payload{Value: "http://0x7f000001/", Point: pt, Module: "ssrf", Variant: "bypass-hex-localhost"},
			base:    "normal",
			resp:    "private network data exposed",
			wantNil: false,
		},
		{
			name:    "FP indicator in baseline already",
			payload: mutator.Payload{Value: "http://169.254.169.254/latest/meta-data/", Point: pt, Module: "ssrf", Variant: "metadata"},
			base:    "Your ami-id is displayed here",
			resp:    "Your ami-id is displayed here",
			wantNil: true,
		},
		{
			name:    "FP localhost in baseline (no new indicator)",
			payload: mutator.Payload{Value: "http://127.0.0.1/", Point: pt, Module: "ssrf", Variant: "internal-localhost"},
			base:    "running on localhost:3000",
			resp:    "running on localhost:3000",
			wantNil: true,
		},
		{
			name:    "FP payload not targeting internal, no guard pass",
			payload: mutator.Payload{Value: "http://attacker.com/", Point: pt, Module: "ssrf", Variant: "dns-rebind"},
			base:    "normal",
			resp:    "connection refused from intranet",
			wantNil: true,
		},
		{
			name:    "TP status differential with metadata variant",
			payload: mutator.Payload{Value: "http://169.254.169.254/latest/meta-data/", Point: pt, Module: "ssrf", Variant: "metadata"},
			base:    "normal",
			resp:    "not found",
			wantNil: true, // respBody has no indicator, status change alone does not trigger here (baseStatus==respStatus==200 won't trigger diff)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := m.Detect(tc.payload, tc.base, 200, 100, tc.resp, 200, 120, nil)
			if tc.wantNil && f != nil {
				t.Fatalf("expected nil, got finding: %s", f.Title)
			}
			if !tc.wantNil && f == nil {
				t.Fatal("expected finding, got nil")
			}
		})
	}
}

func TestSSRFDetect_StatusDifferential(t *testing.T) {
	m := &SSRFModule{}
	pt := input.InjectionPoint{Name: "url", Location: input.LocQueryParam}

	// TP: status changes from 404 to 200 with metadata variant
	p := mutator.Payload{Value: "http://169.254.169.254/latest/meta-data/", Point: pt, Module: "ssrf", Variant: "metadata"}
	f := m.Detect(p, "not found", 404, 100, "ok", 200, 120, nil)
	if f == nil {
		t.Fatal("expected finding for status differential with metadata variant, got nil")
	}

	// FP: status changes but variant is not metadata/internal
	p2 := mutator.Payload{Value: "http://example.com/", Point: pt, Module: "ssrf", Variant: "dns-rebind"}
	f2 := m.Detect(p2, "not found", 404, 100, "ok", 200, 120, nil)
	if f2 != nil {
		t.Fatalf("expected nil for non-metadata variant status change, got: %s", f2.Title)
	}
}
