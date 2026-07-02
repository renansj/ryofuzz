package plugins

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

const validPlugin = `
name: test-check
description: test
severity: high
module: test-mod
detection:
  method: regex
  patterns:
    - "err[0-9]+"
`

const invalidMethodPlugin = `
name: bad-method
module: bad-mod
detection:
  method: bogus
`

const invalidRegexPlugin = `
name: bad-regex
module: bad-regex-mod
detection:
  method: regex
  patterns:
    - "("
`

const invalidSeverityPlugin = `
name: bad-sev
module: bad-sev-mod
severity: catastrophic
detection:
  method: contains
  patterns: ["x"]
`

func writePlugin(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
}

func TestLoadPluginValid(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "ok.yaml", validPlugin)

	mods, err := LoadPlugins([]string{dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 module, got %d", len(mods))
	}
	if mods[0].Name() != "test-mod" {
		t.Errorf("expected module name test-mod, got %q", mods[0].Name())
	}
}

// J2: an unknown detection method must be rejected at load, not silently
// never match.
func TestLoadPluginInvalidMethod(t *testing.T) {
	_, err := loadFromString(t, invalidMethodPlugin)
	if err == nil {
		t.Fatal("expected error for invalid detection method")
	}
}

// J2: an invalid severity must be rejected.
func TestLoadPluginInvalidSeverity(t *testing.T) {
	_, err := loadFromString(t, invalidSeverityPlugin)
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

// F2/C2: an invalid regex must fail at load (fail early) rather than being
// compiled repeatedly at detection time and silently never matching.
func TestLoadPluginInvalidRegexFailsEarly(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "bad.yaml", invalidRegexPlugin)
	mods, err := LoadPlugins([]string{dir})
	if err == nil {
		t.Fatal("expected aggregated error for invalid regex")
	}
	if len(mods) != 0 {
		t.Fatalf("expected 0 modules for invalid regex, got %d", len(mods))
	}
}

// J1: one broken plugin must not prevent the others from loading.
func TestLoadPluginsPartialLoad(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "good.yaml", validPlugin)
	writePlugin(t, dir, "bad.yaml", invalidMethodPlugin)

	mods, err := LoadPlugins([]string{dir})
	if err == nil {
		t.Error("expected aggregated error reporting the skipped plugin")
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 valid module despite 1 broken plugin, got %d", len(mods))
	}
	if mods[0].Name() != "test-mod" {
		t.Errorf("expected the valid module to load, got %q", mods[0].Name())
	}
}

// J2: header lookup must be case-insensitive (canonicalized) regardless of how
// the response header map is keyed.
func TestPluginHeaderDetectionCanonicalized(t *testing.T) {
	p := &Plugin{
		Name:   "hdr",
		Module: "hdr-mod",
		Detection: PluginDetection{
			Method:     "header",
			HeaderName: "x-powered-by",
			HeaderVal:  "PHP",
		},
	}
	mod, err := p.ToModule()
	if err != nil {
		t.Fatalf("ToModule: %v", err)
	}
	payload := mutator.Payload{Value: "x", Point: input.InjectionPoint{Name: "q"}}
	// Header map keyed with canonical casing (as net/http stores it).
	headers := map[string][]string{"X-Powered-By": {"PHP/8.1"}}
	f := mod.Detect(payload, "", 200, 0, "", 200, 0, headers)
	if f == nil {
		t.Fatal("expected finding from case-insensitive header match")
	}
}

// F2: regex detection over a body works after pre-compilation.
func TestPluginRegexDetection(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "ok.yaml", validPlugin)
	mods, err := LoadPlugins([]string{dir})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	payload := mutator.Payload{Value: "x", Point: input.InjectionPoint{Name: "q"}}
	if f := mods[0].Detect(payload, "", 200, 0, "boom err404 boom", 200, 0, nil); f == nil {
		t.Error("expected regex match on err404")
	}
	if f := mods[0].Detect(payload, "", 200, 0, "nothing here", 200, 0, nil); f != nil {
		t.Error("did not expect match on clean body")
	}
}

func loadFromString(t *testing.T, content string) (*Plugin, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return LoadPlugin(path)
}
