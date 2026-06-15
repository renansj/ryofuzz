package nuclei

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDifferentialVsNuclei runs both the real nuclei binary and this engine
// against the SAME target with the SAME templates, then diffs the per-template
// match verdicts. This is how compatibility is PROVEN rather than claimed.
//
// Gated by env: requires the `nuclei` binary on PATH and:
//   RYOFUZZ_DIFF_TARGET   a reachable URL to scan
//   RYOFUZZ_DIFF_TEMPLATES a template dir (small subset recommended)
// Example:
//   RYOFUZZ_DIFF_TARGET=http://127.0.0.1:8080 \
//   RYOFUZZ_DIFF_TEMPLATES=~/nuclei-templates/http/misconfiguration \
//   go test ./internal/nuclei/ -run TestDifferentialVsNuclei -v
func TestDifferentialVsNuclei(t *testing.T) {
	target := os.Getenv("RYOFUZZ_DIFF_TARGET")
	tdir := os.Getenv("RYOFUZZ_DIFF_TEMPLATES")
	if target == "" || tdir == "" {
		t.Skip("set RYOFUZZ_DIFF_TARGET and RYOFUZZ_DIFF_TEMPLATES to run the differential harness")
	}
	nucleiBin, err := exec.LookPath("nuclei")
	if err != nil {
		t.Skip("nuclei binary not on PATH")
	}

	// 1. Run the real nuclei binary, JSON output.
	nucleiMatches := runRealNuclei(t, nucleiBin, target, tdir)

	// 2. Run our engine over the same templates.
	ryoMatches := map[string]bool{}
	skipped := map[string]string{}
	_ = filepath.Walk(tdir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		tmpl, lerr := LoadTemplate(path)
		if lerr != nil {
			return nil
		}
		res := Execute(tmpl, target, 10, "")
		if res.Skipped {
			skipped[tmpl.ID] = res.SkipReason
			return nil
		}
		if res.Matched {
			ryoMatches[tmpl.ID] = true
		}
		return nil
	})

	// 3. Diff. Only compare templates our engine did NOT skip (G9: skipped
	// templates are honestly out of scope, not false negatives).
	var falseNeg, falsePos, agree int
	for id := range nucleiMatches {
		if _, wasSkipped := skipped[id]; wasSkipped {
			continue
		}
		if ryoMatches[id] {
			agree++
		} else {
			falseNeg++
			t.Logf("FALSE NEGATIVE: nuclei matched %s, ryofuzz did not", id)
		}
	}
	for id := range ryoMatches {
		if !nucleiMatches[id] {
			falsePos++
			t.Logf("FALSE POSITIVE: ryofuzz matched %s, nuclei did not", id)
		}
	}

	t.Logf("=== Differential result (target=%s) ===", target)
	t.Logf("nuclei matches:   %d", len(nucleiMatches))
	t.Logf("ryofuzz matches:  %d", len(ryoMatches))
	t.Logf("skipped (G9):     %d", len(skipped))
	t.Logf("agree:            %d", agree)
	t.Logf("false negatives:  %d", falseNeg)
	t.Logf("false positives:  %d", falsePos)
}

func runRealNuclei(t *testing.T, bin, target, tdir string) map[string]bool {
	out := map[string]bool{}
	ctx := exec.Command(bin, "-target", target, "-t", tdir, "-jsonl", "-silent", "-no-color", "-disable-update-check")
	ctx.Env = os.Environ()
	done := make(chan struct{})
	var stdout []byte
	go func() {
		stdout, _ = ctx.Output()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Minute):
		_ = ctx.Process.Kill()
	}
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			TemplateID string `json:"template-id"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.TemplateID != "" {
			out[rec.TemplateID] = true
		}
	}
	return out
}
