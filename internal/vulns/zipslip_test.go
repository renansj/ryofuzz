package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestZipSlipModule_Detect(t *testing.T) {
	m := &ZipSlipModule{}
	cases := []struct {
		name        string
		respBody    string
		respStatus  int
		wantFinding bool
	}{
		{"extraction reported", "Files extracted successfully", 200, true},
		{"marker filename echoed", "saved ryofuzz_zipslip.txt", 200, true},
		{"clean response", "upload received", 200, false},
		{"error status", "Files extracted", 500, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := mutator.Payload{Module: "zipslip", Variant: "unix-traversal", Value: "ryofuzz_slip.zip"}
			got := m.Detect(p, "", 200, 0, c.respBody, c.respStatus, 0, nil)
			if (got != nil) != c.wantFinding {
				t.Fatalf("wantFinding=%v got=%v", c.wantFinding, got)
			}
		})
	}
}

func TestZipSlipModule_GeneratesValidZip(t *testing.T) {
	m := &ZipSlipModule{}
	z := buildZipSlip("../../evil.txt", "marker")
	if len(z) == 0 {
		t.Fatal("expected non-empty zip bytes")
	}
	// ZIP local file header magic
	if z[0] != 'P' || z[1] != 'K' {
		t.Errorf("expected PK zip magic, got %q", z[:2])
	}
	_ = m
}
