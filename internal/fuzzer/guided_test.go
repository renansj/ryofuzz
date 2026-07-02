package fuzzer

import (
	"math/bits"
	"testing"
)

func TestNormalizeBodyStripsDynamicTokens(t *testing.T) {
	body := `user 550e8400-e29b-41d4-a716-446655440000 at 2024-01-02T03:04:05 ` +
		`ts 1700000000 hash deadbeefdeadbeefdeadbeefdeadbeef ` +
		`<input name="_token" value="abc123">`
	got := normalizeBody(body)

	// All volatile tokens should be gone so two structurally-identical pages
	// with different tokens fingerprint the same.
	for _, leak := range []string{
		"550e8400-e29b-41d4", "2024-01-02T03:04:05", "1700000000",
		"deadbeefdeadbeef", `value="abc123"`,
	} {
		if contains(got, leak) {
			t.Errorf("normalizeBody left dynamic token %q in %q", leak, got)
		}
	}
	// Static text survives.
	if !contains(got, "user") || !contains(got, "at") {
		t.Errorf("normalizeBody stripped static text: %q", got)
	}
}

func TestSimhashSimilarity(t *testing.T) {
	base := "the quick brown fox jumps over the lazy dog and runs away quickly"
	similar := "the quick brown fox jumps over the lazy dog and walks away quickly"
	different := "completely unrelated content about databases and networking protocols"

	h1 := simhash(base)
	h2 := simhash(similar)
	h3 := simhash(different)

	distSimilar := bits.OnesCount64(h1 ^ h2)
	distDifferent := bits.OnesCount64(h1 ^ h3)

	if distSimilar >= distDifferent {
		t.Errorf("expected similar bodies closer than different: similar=%d different=%d",
			distSimilar, distDifferent)
	}
}

func TestSimhashStable(t *testing.T) {
	s := "some response body content"
	if simhash(s) != simhash(s) {
		t.Error("simhash must be deterministic")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
