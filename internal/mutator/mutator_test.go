package mutator

import (
	"strings"
	"testing"
)

func TestMutateCount(t *testing.T) {
	out := Mutate("test", 20)
	if len(out) != 20 {
		t.Errorf("expected 20 mutations, got %d", len(out))
	}
	// default when n <= 0
	if len(Mutate("test", 0)) != 50 {
		t.Errorf("expected 50 default mutations, got %d", len(Mutate("test", 0)))
	}
}

func TestMutateDoesNotPanicOnShortInput(t *testing.T) {
	for _, in := range []string{"", "a", "ab"} {
		_ = Mutate(in, 30) // must not panic on tiny inputs
	}
}

func TestEncodeVariants(t *testing.T) {
	variants := EncodeVariants("<script>")
	if len(variants) == 0 {
		t.Fatal("expected at least one encoding variant")
	}
	// URL-encoding should appear somewhere in the set
	joined := strings.Join(variants, "\n")
	if !strings.Contains(joined, "%3C") && !strings.Contains(joined, "%3c") {
		t.Errorf("expected a URL-encoded variant of '<', got: %v", variants)
	}
}

func TestEncodeVariantsDeterministicNonEmpty(t *testing.T) {
	// Every variant must be non-empty.
	for _, v := range EncodeVariants("' OR 1=1") {
		if v == "" {
			t.Error("encoding produced an empty variant")
		}
	}
}
