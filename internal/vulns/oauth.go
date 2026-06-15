package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type OAuthModule struct{}

func (m *OAuthModule) Name() string        { return "oauth" }
func (m *OAuthModule) Description() string { return "OAuth/OIDC Misconfiguration" }

func (m *OAuthModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	redirectPayloads := []struct {
		value   string
		variant string
	}{
		{"https://evil.com", "redirect-domain-swap"},
		{"https://legit.com@evil.com", "redirect-at-bypass"},
		{"https://legit.com/..%2f..%2fevil.com", "redirect-path-traversal"},
		{"https://legit.com#@evil.com", "redirect-fragment"},
		{"https://evil.com%23.legit.com", "redirect-encoded-fragment"},
		{"https://legit.com/.evil.com", "redirect-dot-bypass"},
		{"https://legit.com%00.evil.com", "redirect-nullbyte"},
		{"//evil.com", "redirect-protocol-relative"},
		{"https://evil.com?legit.com", "redirect-query-bypass"},
		{"https://legit.com\\@evil.com", "redirect-backslash"},
	}

	statePayloads := []struct {
		value   string
		variant string
	}{
		{"", "state-removed"},
		{"x", "state-short"},
	}

	challengePayloads := []struct {
		value   string
		variant string
	}{
		{"plain", "pkce-downgrade-plain"},
		{"", "pkce-removed"},
	}

	for _, point := range points {
		name := strings.ToLower(point.Name)
		if strings.Contains(name, "redirect") || strings.Contains(name, "uri") || strings.Contains(name, "callback") {
			for _, p := range redirectPayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "oauth", Variant: p.variant,
				})
			}
		}
		if strings.Contains(name, "state") {
			for _, p := range statePayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "oauth", Variant: p.variant,
				})
			}
		}
		if strings.Contains(name, "code_challenge") || strings.Contains(name, "challenge") {
			for _, p := range challengePayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "oauth", Variant: p.variant,
				})
			}
		}
		// If no specific match, test redirect payloads on all query params
		if point.Location == input.LocQueryParam {
			for _, p := range redirectPayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "oauth", Variant: p.variant,
				})
			}
		}
	}
	return payloads
}

func (m *OAuthModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Check for redirect to evil domain
	if strings.Contains(payload.Variant, "redirect") {
		// Check Location header for redirect
		for _, loc := range respHeaders["Location"] {
			if strings.Contains(loc, "evil.com") {
				return &Finding{
					Module:      "oauth",
					Severity:    "critical",
					Confidence:  "confirmed",
					Title:       "OAuth Open Redirect - Attacker domain in redirect",
					Description: "The authorization server redirects to an attacker-controlled domain",
					Payload:     payload.Value,
					Point:       payload.Point,
					Evidence:    "Location: " + loc,
					OWASP:       "A07:2021",
					CWE:         "CWE-601",
				}
			}
		}
		// Check body for redirect URL
		if strings.Contains(respBody, "evil.com") && (respStatus == 302 || respStatus == 301 || respStatus == 303) {
			return &Finding{
				Module:      "oauth",
				Severity:    "high",
				Confidence:  "high",
				Title:       "OAuth Open Redirect - Attacker domain reflected",
				Description: "The attacker domain appears in redirect response",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "evil.com found in response body with redirect status",
				OWASP:       "A07:2021",
				CWE:         "CWE-601",
			}
		}
	}

	// Check for missing state validation
	if strings.Contains(payload.Variant, "state") {
		if respStatus == 200 || respStatus == 302 {
			if !strings.Contains(respBody, "invalid") && !strings.Contains(respBody, "error") &&
				!strings.Contains(respBody, "missing") {
				return &Finding{
					Module:      "oauth",
					Severity:    "high",
					Confidence:  "medium",
					Title:       "OAuth CSRF - State parameter not validated",
					Description: "The server accepts OAuth flow without a valid state parameter",
					Payload:     payload.Value,
					Point:       payload.Point,
					Evidence:    "Request accepted without valid state param",
					OWASP:       "A07:2021",
					CWE:         "CWE-352",
				}
			}
		}
	}

	return nil
}
