package vulns

import "testing"

func TestSeverityRankOrder(t *testing.T) {
	order := []string{"critical", "high", "medium", "low", "info"}
	for i := 1; i < len(order); i++ {
		if SeverityRank(order[i-1]) >= SeverityRank(order[i]) {
			t.Errorf("severity %q should rank before %q", order[i-1], order[i])
		}
	}
	// Unknown sorts last.
	if SeverityRank("bogus") <= SeverityRank("info") {
		t.Error("unknown severity should rank after info")
	}
	// Case/space insensitive.
	if SeverityRank("  CRITICAL ") != SeverityRank("critical") {
		t.Error("severity rank should be case/space insensitive")
	}
}

func TestValidSeverityAndConfidence(t *testing.T) {
	if !ValidSeverity("high") || ValidSeverity("spicy") {
		t.Error("ValidSeverity misclassified")
	}
	if !ValidConfidence("confirmed") || ValidConfidence("certain") {
		t.Error("ValidConfidence misclassified")
	}
}

func TestNormalizeFinding(t *testing.T) {
	f := &Finding{Severity: "  HIGH ", Confidence: "CONFIRMED"}
	NormalizeFinding(f)
	if f.Severity != "high" || f.Confidence != "confirmed" {
		t.Errorf("normalize failed: sev=%q conf=%q", f.Severity, f.Confidence)
	}
	// Invalid values get safe defaults.
	bad := &Finding{Severity: "???", Confidence: "???"}
	NormalizeFinding(bad)
	if bad.Severity != SeverityInfo || bad.Confidence != ConfidenceLow {
		t.Errorf("expected safe defaults, got sev=%q conf=%q", bad.Severity, bad.Confidence)
	}
	NormalizeFinding(nil) // must not panic
}
