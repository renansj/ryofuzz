package nuclei

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseRate measures how much of the official nuclei-templates corpus this
// engine can parse and how much it can fully evaluate (supported) vs must skip
// (G9). It is a REPORTING test: it never fails on coverage, only on panics.
// Set RYOFUZZ_TEMPLATES to point at a nuclei-templates checkout to run it.
func TestParseRate(t *testing.T) {
	dir := os.Getenv("RYOFUZZ_TEMPLATES")
	if dir == "" {
		// default common location
		if home, err := os.UserHomeDir(); err == nil {
			cand := filepath.Join(home, "nuclei-templates")
			if st, err := os.Stat(cand); err == nil && st.IsDir() {
				dir = cand
			}
		}
	}
	if dir == "" {
		t.Skip("set RYOFUZZ_TEMPLATES to a nuclei-templates dir to run the parse-rate harness")
	}

	var total, parsed, httpTemplates, supported int
	skipReasons := map[string]int{}

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		total++
		// Guard against panics per template.
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("PANIC parsing %s: %v", path, r)
				}
			}()
			tmpl, lerr := LoadTemplate(path)
			if lerr != nil {
				return
			}
			parsed++
			if len(tmpl.AllRequests()) > 0 {
				httpTemplates++
			}
			if reason, ok := tmpl.CheckCapability(); ok {
				supported++
			} else {
				// bucket the reason (first few words)
				key := reason
				if idx := strings.Index(reason, ":"); idx > 0 {
					key = reason[:idx]
				}
				skipReasons[key]++
			}
		}()
		return nil
	})

	t.Logf("nuclei-templates corpus: %s", dir)
	t.Logf("total files:        %d", total)
	t.Logf("parsed OK:          %d (%.1f%%)", parsed, pct(parsed, total))
	t.Logf("http templates:     %d", httpTemplates)
	t.Logf("fully supported:    %d (%.1f%% of parsed)", supported, pct(supported, parsed))
	t.Logf("skipped by reason (G9):")
	for reason, n := range skipReasons {
		t.Logf("    %-55s %d", reason, n)
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
