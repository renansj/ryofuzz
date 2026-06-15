package taint

import (
	"strings"
	"testing"
)

func TestTracker_Generate(t *testing.T) {
	tr := NewTracker()
	c1 := tr.Generate("/api/user", "name", "query")
	c2 := tr.Generate("/api/user", "email", "query")

	if !strings.HasPrefix(c1, "ryofz") {
		t.Fatalf("expected canary prefix ryofz, got %s", c1)
	}
	if !strings.HasPrefix(c2, "ryofz") {
		t.Fatalf("expected canary prefix ryofz, got %s", c2)
	}
	if c1 == c2 {
		t.Fatal("expected unique canaries, got duplicates")
	}
}

func TestTracker_Scan_Found(t *testing.T) {
	tr := NewTracker()
	canary := tr.Generate("/api/user", "name", "query")

	body := "Hello " + canary + " world"
	matches := tr.Scan(body, "/api/profile")

	if len(matches) == 0 {
		t.Fatal("expected canary match, got none")
	}
	if matches[0].Source.Param != "name" {
		t.Fatalf("expected source param name, got %s", matches[0].Source.Param)
	}
	if matches[0].Source.Endpoint != "/api/user" {
		t.Fatalf("expected source endpoint /api/user, got %s", matches[0].Source.Endpoint)
	}
	if matches[0].FoundAt != "/api/profile" {
		t.Fatalf("expected foundAt /api/profile, got %s", matches[0].FoundAt)
	}
}

func TestTracker_Scan_NotFound(t *testing.T) {
	tr := NewTracker()
	tr.Generate("/api/user", "name", "query")

	body := "This body has no canaries at all"
	matches := tr.Scan(body, "/api/profile")

	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}
