package schema

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/renansj/ryofuzz/internal/util"
)

type OpenAPISpec struct {
	Paths   map[string]map[string]Operation `json:"paths"`
	Servers []Server                        `json:"servers"`
}

type Server struct {
	URL string `json:"url"`
}

type Operation struct {
	Parameters  []Parameter  `json:"parameters"`
	RequestBody *RequestBody `json:"requestBody"`
}

type Parameter struct {
	Name     string     `json:"name"`
	In       string     `json:"in"`
	Required bool       `json:"required"`
	Schema   *SchemaObj `json:"schema"`
}

type RequestBody struct {
	Content map[string]MediaType `json:"content"`
}

type MediaType struct {
	Schema *SchemaObj `json:"schema"`
}

type SchemaObj struct {
	Type       string                `json:"type"`
	Properties map[string]*SchemaObj `json:"properties"`
	Items      *SchemaObj            `json:"items"`
	Example    interface{}           `json:"example"`
}

// Target represents a fuzzable endpoint extracted from spec
type Target struct {
	Method  string
	Path    string
	URL     string
	Body    string
	Headers []string
	Params  map[string]string
}

// LoadFromURL fetches and parses an OpenAPI spec
func LoadFromURL(specURL string) (*OpenAPISpec, error) {
	var data []byte

	// Support local file paths (e.g. recon spec from proxy mode) and file:// URLs
	if !strings.HasPrefix(specURL, "http://") && !strings.HasPrefix(specURL, "https://") {
		path := strings.TrimPrefix(specURL, "file://")
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read spec file: %w", err)
		}
		data = b
	} else {
		resp, err := http.Get(specURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, _ = util.ReadBodyLimited(resp.Body, 0)
	}

	var spec OpenAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}
	return &spec, nil
}

// ExtractTargets generates fuzzable targets from the spec
func ExtractTargets(spec *OpenAPISpec, baseURL string) []Target {
	var targets []Target
	if baseURL == "" && len(spec.Servers) > 0 {
		baseURL = spec.Servers[0].URL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	for path, methods := range spec.Paths {
		for method, op := range methods {
			t := Target{
				Method: strings.ToUpper(method),
				Path:   path,
				URL:    baseURL + path,
				Params: make(map[string]string),
			}

			var queryParts []string
			for _, p := range op.Parameters {
				val := exampleValue(p.Schema, p.Name)
				t.Params[p.Name] = val
				if p.In == "query" {
					queryParts = append(queryParts, p.Name+"="+val)
				} else if p.In == "header" {
					t.Headers = append(t.Headers, p.Name+": "+val)
				} else if p.In == "path" {
					t.URL = strings.Replace(t.URL, "{"+p.Name+"}", val, 1)
				}
			}
			if len(queryParts) > 0 {
				t.URL += "?" + strings.Join(queryParts, "&")
			}

			if op.RequestBody != nil {
				for _, media := range op.RequestBody.Content {
					if media.Schema != nil {
						t.Body = buildExampleJSON(media.Schema)
					}
					break
				}
			}

			targets = append(targets, t)
		}
	}
	return targets
}

func exampleValue(s *SchemaObj, name string) string {
	if s == nil {
		return "test"
	}
	if s.Example != nil {
		return fmt.Sprintf("%v", s.Example)
	}
	switch s.Type {
	case "integer":
		return "1"
	case "number":
		return "1.0"
	case "boolean":
		return "true"
	case "array":
		return "[]"
	default:
		return "test"
	}
}

func buildExampleJSON(s *SchemaObj) string {
	if s == nil || s.Properties == nil {
		return "{}"
	}
	parts := []string{}
	for name, prop := range s.Properties {
		val := exampleValue(prop, name)
		if prop != nil && prop.Type == "string" {
			parts = append(parts, fmt.Sprintf("%q:%q", name, val))
		} else {
			parts = append(parts, fmt.Sprintf("%q:%s", name, val))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}
