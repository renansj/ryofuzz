package vulns

import (
	"strings"
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
)

// destructiveMarkers are substrings that must never appear in generated
// payloads unless --allow-destructive is set.
var destructiveMarkers = []string{
	"DROP TABLE",
	"xp_cmdshell",
	"LOAD_FILE",
	"UTL_HTTP",
	"pg_sleep(5);--", // stacked write variant
}

func containsDestructive(value string) bool {
	for _, mk := range destructiveMarkers {
		if strings.Contains(value, mk) {
			return true
		}
	}
	return false
}

func TestSQLiDestructiveGate(t *testing.T) {
	m := &SQLiModule{}
	point := input.InjectionPoint{Name: "id", Location: input.LocQueryParam}

	// Ensure a clean default regardless of test ordering.
	SetAllowDestructive(false)
	t.Cleanup(func() { SetAllowDestructive(false) })

	// Default: no destructive payloads.
	safe := m.GeneratePayloads([]input.InjectionPoint{point}, "payloads", 0)
	if len(safe) == 0 {
		t.Fatal("expected safe payloads to be generated")
	}
	for _, p := range safe {
		if containsDestructive(p.Value) {
			t.Errorf("destructive payload leaked with gate OFF: %q (variant %s)", p.Value, p.Variant)
		}
	}

	// Opt-in: destructive payloads present.
	SetAllowDestructive(true)
	all := m.GeneratePayloads([]input.InjectionPoint{point}, "payloads", 0)
	if len(all) <= len(safe) {
		t.Fatalf("expected more payloads with gate ON: got %d, safe was %d", len(all), len(safe))
	}
	foundDestructive := false
	for _, p := range all {
		if containsDestructive(p.Value) {
			foundDestructive = true
			break
		}
	}
	if !foundDestructive {
		t.Error("expected at least one destructive payload with gate ON")
	}
}

func TestAllowDestructiveToggle(t *testing.T) {
	t.Cleanup(func() { SetAllowDestructive(false) })

	SetAllowDestructive(false)
	if AllowDestructive() {
		t.Error("expected AllowDestructive() == false after SetAllowDestructive(false)")
	}
	SetAllowDestructive(true)
	if !AllowDestructive() {
		t.Error("expected AllowDestructive() == true after SetAllowDestructive(true)")
	}
}
