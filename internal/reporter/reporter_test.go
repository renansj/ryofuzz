package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/renansj/ryofuzz/internal/vulns"
)

func sampleFindings() []*vulns.Finding {
	return []*vulns.Finding{
		{Module: "sqli", Severity: "critical", Confidence: "high", Title: "SQLi", CWE: "CWE-89"},
		{Module: "xss", Severity: "high", Confidence: "confirmed", Title: "XSS", CWE: "CWE-79"},
		{Module: "csrf", Severity: "medium", Confidence: "low", Title: "CSRF"},
	}
}

func TestReportJSONIsValid(t *testing.T) {
	out := reportJSON(sampleFindings())
	var decoded []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("reportJSON produced invalid JSON: %v", err)
	}
	if len(decoded) != 3 {
		t.Errorf("expected 3 findings in JSON, got %d", len(decoded))
	}
}

func TestReportMarkdownStructure(t *testing.T) {
	out := reportMarkdown(sampleFindings())
	if !strings.Contains(out, "SQLi") || !strings.Contains(out, "XSS") {
		t.Errorf("markdown missing finding titles: %s", out)
	}
}

func TestCountBySeverity(t *testing.T) {
	counts := countBySeverity(sampleFindings())
	if counts["critical"] != 1 || counts["high"] != 1 || counts["medium"] != 1 {
		t.Errorf("unexpected severity counts: %v", counts)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 3); len(got) > 6 {
		t.Errorf("truncate did not shorten: %q", got)
	}
	if got := truncate("ab", 10); got != "ab" {
		t.Errorf("truncate altered short string: %q", got)
	}
}

func TestReportWritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	Report(sampleFindings(), "json", path, false)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("report file not written: %v", err)
	}
	var decoded []map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("written file is not valid JSON: %v", err)
	}
}
