package util

import (
	"strings"
	"testing"
)

func TestAbs(t *testing.T) {
	if got := Abs(-5); got != 5 {
		t.Errorf("Abs(-5) = %d, want 5", got)
	}
	if got := Abs(5); got != 5 {
		t.Errorf("Abs(5) = %d, want 5", got)
	}
	if got := Abs(0); got != 0 {
		t.Errorf("Abs(0) = %d, want 0", got)
	}
	if got := Abs(int64(-9)); got != 9 {
		t.Errorf("Abs(int64(-9)) = %d, want 9", got)
	}
}

func TestReadBodyLimitedTruncates(t *testing.T) {
	src := strings.NewReader(strings.Repeat("A", 1000))
	got, err := ReadBodyLimited(src, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 100 {
		t.Errorf("expected 100 bytes (bounded), got %d", len(got))
	}
}

func TestReadBodyLimitedDefault(t *testing.T) {
	src := strings.NewReader("short body")
	got, err := ReadBodyLimited(src, 0) // 0 -> default bound
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "short body" {
		t.Errorf("expected full short body, got %q", string(got))
	}
}
