package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const specJSON = `{
  "servers": [{"url": "https://api.example.com"}],
  "paths": {
    "/users/{id}": {
      "get": {
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}},
          {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}
        ]
      }
    },
    "/login": {
      "post": {
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {"type": "object", "properties": {
                "user": {"type": "string"},
                "pass": {"type": "string"}
              }}
            }
          }
        }
      }
    }
  }
}`

func TestLoadAndExtractTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(path, []byte(specJSON), 0o600); err != nil {
		t.Fatalf("write spec: %v", err)
	}

	spec, err := LoadFromURL(path)
	if err != nil {
		t.Fatalf("LoadFromURL: %v", err)
	}
	if len(spec.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(spec.Paths))
	}

	targets := ExtractTargets(spec, "")
	if len(targets) == 0 {
		t.Fatal("expected extracted targets")
	}

	var sawGet, sawPost bool
	for _, tg := range targets {
		if tg.Method == "GET" && strings.Contains(tg.URL, "/users/") {
			sawGet = true
		}
		if tg.Method == "POST" && strings.Contains(tg.URL, "/login") {
			sawPost = true
			if tg.Body == "" {
				t.Error("expected POST /login to carry an example body")
			}
		}
	}
	if !sawGet {
		t.Error("expected a GET target for /users/{id}")
	}
	if !sawPost {
		t.Error("expected a POST target for /login")
	}
}

func TestLoadInvalidSpec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := LoadFromURL(path); err == nil {
		t.Error("expected error for invalid spec")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := LoadFromURL("/no/such/spec.json"); err == nil {
		t.Error("expected error for missing file")
	}
}
