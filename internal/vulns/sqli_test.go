package vulns

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestSQLiDetect_TruePositive(t *testing.T) {
	m := &SQLiModule{}
	p := mutator.Payload{Value: "' OR 1=1--", Point: input.InjectionPoint{Name: "id", Location: input.LocQueryParam}, Module: "sqli", Variant: "error"}
	f := m.Detect(p, "normal page", 200, 100, "You have an error in your SQL syntax near something", 500, 120, nil)
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if f.Module != "sqli" {
		t.Fatalf("expected module sqli, got %s", f.Module)
	}
	if f.Severity != "critical" {
		t.Fatalf("expected severity critical, got %s", f.Severity)
	}
}

func TestSQLiDetect_TrueNegative(t *testing.T) {
	m := &SQLiModule{}
	p := mutator.Payload{Value: "' OR 1=1--", Point: input.InjectionPoint{Name: "id", Location: input.LocQueryParam}, Module: "sqli", Variant: "error"}
	f := m.Detect(p, "normal page", 200, 100, "Welcome to the site", 200, 110, nil)
	if f != nil {
		t.Fatalf("expected nil, got finding: %s", f.Title)
	}
}

func TestSQLiDetect_TimeBased(t *testing.T) {
	m := &SQLiModule{}
	p := mutator.Payload{Value: "' OR SLEEP(5)--", Point: input.InjectionPoint{Name: "id", Location: input.LocQueryParam}, Module: "sqli", Variant: "time"}
	f := m.Detect(p, "normal", 200, 100, "normal", 200, 5000, nil)
	if f == nil {
		t.Fatal("expected finding for time-based, got nil")
	}
	if f.Title != "SQL Injection - Time-based Blind (unconfirmed)" {
		t.Fatalf("unexpected title: %s", f.Title)
	}
}

func TestSQLiDetect_Boolean(t *testing.T) {
	m := &SQLiModule{}
	p := mutator.Payload{Value: "' AND '1'='1", Point: input.InjectionPoint{Name: "id", Location: input.LocQueryParam}, Module: "sqli", Variant: "boolean"}
	baseBody := "short"
	respBody := "this is a much longer response body that differs significantly from the base response body padding"
	f := m.Detect(p, baseBody, 200, 100, respBody, 200, 110, nil)
	if f == nil {
		t.Fatal("expected finding for boolean-based, got nil")
	}
	if f.Confidence != "low" {
		t.Fatalf("expected confidence low, got %s", f.Confidence)
	}
}
