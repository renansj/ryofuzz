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

	// Check for missing state validation.
	// Only flag when there is a POSITIVE signal that the OAuth flow proceeded
	// without state: an authorization code or token was actually issued, or a
	// redirect back to a redirect_uri occurred. Absence of error words alone is
	// not sufficient (too false-positive prone).
	if strings.Contains(payload.Variant, "state") {
		issued := false
		evidence := ""

		// Authorization code or token issued in a redirect Location
		for _, loc := range respHeaders["Location"] {
			low := strings.ToLower(loc)
			if strings.Contains(low, "code=") || strings.Contains(low, "access_token=") ||
				strings.Contains(low, "id_token=") {
				issued = true
				evidence = "Location issued credential without state: " + loc
				break
			}
		}
		// Token issued directly in the body
		if !issued && (respStatus == 200) {
			low := strings.ToLower(respBody)
			if strings.Contains(low, "\"access_token\"") || strings.Contains(low, "\"id_token\"") ||
				strings.Contains(low, "\"authorization_code\"") {
				issued = true
				evidence = "Token issued in response body without state parameter"
			}
		}

		if issued {
			return &Finding{
				Module:      "oauth",
				Severity:    "high",
				Confidence:  "high",
				Title:       "OAuth CSRF - State parameter not validated",
				Description: "The authorization server issued credentials without a valid state parameter, enabling CSRF / login fixation.",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    evidence,
				OWASP:       "A07:2021",
				CWE:         "CWE-352",
			}
		}
	}

	return nil
}
