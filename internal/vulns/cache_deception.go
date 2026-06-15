package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type CacheDeceptionModule struct{}

func (m *CacheDeceptionModule) Name() string        { return "cache-deception" }
func (m *CacheDeceptionModule) Description() string { return "Web Cache Deception" }

func (m *CacheDeceptionModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	suffixes := []string{
		".css", ".js", ".png", ".svg", ".gif", ".ico",
		"/x.css", "/x.js", "/x.png",
		";.css", ";.js",
		"%0a.css", "%0a.js",
		"/.css", "/..%2f.css",
		"%3b.css", "%23.css",
	}
	for _, point := range points {
		if point.Location == input.LocPath || point.Location == input.LocQueryParam {
			for _, sfx := range suffixes {
				payloads = append(payloads, mutator.Payload{
					Value:    point.OriginalValue + sfx,
					Point:    point,
					Module:   "cache-deception",
					Variant:  "path-suffix",
					Metadata: map[string]string{"suffix": sfx},
				})
			}
		}
	}
	return payloads
}

func (m *CacheDeceptionModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if respStatus != 200 {
		return nil
	}

	// Check for cache headers indicating the response was cached
	cached := false
	for _, v := range respHeaders["X-Cache"] {
		if strings.Contains(strings.ToUpper(v), "HIT") {
			cached = true
		}
	}
	for _, v := range respHeaders["Cf-Cache-Status"] {
		if strings.Contains(strings.ToUpper(v), "HIT") {
			cached = true
		}
	}
	for _, v := range respHeaders["Age"] {
		if v != "" && v != "0" {
			cached = true
		}
	}

	if !cached {
		return nil
	}

	// Check if sensitive data from baseline is present in the cached response
	sensitiveMarkers := []string{"session", "token", "api_key", "apikey", "email", "password", "secret", "csrf", "user"}
	found := false
	evidence := ""
	for _, marker := range sensitiveMarkers {
		if strings.Contains(strings.ToLower(baseBody), marker) && strings.Contains(strings.ToLower(respBody), marker) {
			found = true
			evidence = "Sensitive keyword '" + marker + "' present in cached response"
			break
		}
	}

	if !found {
		return nil
	}

	return &Finding{
		Module:      "cache-deception",
		Severity:    "critical",
		Confidence:  "high",
		Title:       "Web Cache Deception - Sensitive data cached",
		Description: "The server caches a response containing sensitive data when a static file extension is appended to the path",
		Payload:     payload.Value,
		Point:       payload.Point,
		Evidence:    evidence,
		OWASP:       "A01:2021",
		CWE:         "CWE-525",
	}
}
