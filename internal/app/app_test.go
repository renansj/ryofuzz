package app

import (
	"testing"

	"github.com/renansj/ryofuzz/internal/mutator"
)

func TestParseTests(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"all", []string{"all"}},
		{"", []string{"all"}},
		{"sqli", []string{"sqli"}},
		{"sqli,xss,lfi", []string{"sqli", "xss", "lfi"}},
		{" sqli , xss ", []string{"sqli", "xss"}}, // trims whitespace
		{"sqli,,", []string{"sqli"}},              // drops empties
	}
	for _, c := range cases {
		got := ParseTests(c.in)
		if len(got) != len(c.want) {
			t.Errorf("ParseTests(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseTests(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestInterleaveByModuleUnderLimit(t *testing.T) {
	in := []mutator.Payload{{Module: "a"}, {Module: "b"}}
	out := InterleaveByModule(in, 10)
	if len(out) != 2 {
		t.Errorf("under-limit should be unchanged, got %d", len(out))
	}
}

func TestInterleaveByModuleFairness(t *testing.T) {
	// 10 of module a, 10 of module b; budget 6 should be ~3 each, not 6 a's.
	var in []mutator.Payload
	for i := 0; i < 10; i++ {
		in = append(in, mutator.Payload{Module: "a", Value: "a"})
	}
	for i := 0; i < 10; i++ {
		in = append(in, mutator.Payload{Module: "b", Value: "b"})
	}
	out := InterleaveByModule(in, 6)
	if len(out) != 6 {
		t.Fatalf("expected 6 payloads, got %d", len(out))
	}
	var countA, countB int
	for _, p := range out {
		switch p.Module {
		case "a":
			countA++
		case "b":
			countB++
		}
	}
	if countA == 0 || countB == 0 {
		t.Errorf("interleave starved a module: a=%d b=%d", countA, countB)
	}
	if countA != 3 || countB != 3 {
		t.Errorf("expected fair 3/3 split, got a=%d b=%d", countA, countB)
	}
}
