// Package app holds orchestration logic extracted from the CLI layer so it can
// be unit-tested independently of cobra and package-level flag state. This is
// the first step of breaking up the monolithic run() (review A1): pure helpers
// move here first, the stateful scan pipeline follows behind a Scanner type.
package app

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/mutator"
)

// ParseTests splits the -t/--tests selector into individual module selectors.
// "all" (or empty) is returned as a single-element slice so downstream
// selection treats it as "everything".
func ParseTests(t string) []string {
	t = strings.TrimSpace(t)
	if t == "" || t == "all" {
		return []string{"all"}
	}
	parts := strings.Split(t, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"all"}
	}
	return out
}

// InterleaveByModule caps the total payload count to limit while keeping module
// coverage fair: it round-robins across modules instead of letting the first
// module consume the whole budget. Preserves first-seen module order.
func InterleaveByModule(payloads []mutator.Payload, limit int) []mutator.Payload {
	if limit <= 0 || len(payloads) <= limit {
		return payloads
	}
	groups := map[string][]mutator.Payload{}
	var order []string
	for _, p := range payloads {
		if _, ok := groups[p.Module]; !ok {
			order = append(order, p.Module)
		}
		groups[p.Module] = append(groups[p.Module], p)
	}
	var out []mutator.Payload
	idx := map[string]int{}
	for len(out) < limit {
		progressed := false
		for _, m := range order {
			if idx[m] < len(groups[m]) {
				out = append(out, groups[m][idx[m]])
				idx[m]++
				progressed = true
				if len(out) >= limit {
					break
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}
