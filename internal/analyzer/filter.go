package analyzer

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/vulns"
)

// FilterFalsePositives removes findings that are just the server echoing back input
// in error messages, JSON responses, or non-executable contexts.
func FilterFalsePositives(baseline *engine.Response, findings []*vulns.Finding, results []engine.FuzzResult) []*vulns.Finding {
	var filtered []*vulns.Finding

	for _, f := range findings {
		if isFalsePositive(baseline, f, results) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func isFalsePositive(baseline *engine.Response, f *vulns.Finding, results []engine.FuzzResult) bool {
	// Find the response for this finding
	var resp *engine.Response
	for _, r := range results {
		if r.Payload.Value == f.Payload && r.Payload.Point.Name == f.Point.Name && r.Error == nil {
			resp = &r.Response
			break
		}
	}
	if resp == nil {
		return false
	}

	// Rule 1: Non-HTML Content-Type - XSS/CRLF/Prompt findings in JSON/text are FP
	ct := ""
	if resp.Headers != nil {
		if vals, ok := resp.Headers["Content-Type"]; ok && len(vals) > 0 {
			ct = strings.ToLower(vals[0])
		}
	}
	isJSON := strings.Contains(ct, "json")
	isText := strings.Contains(ct, "text/plain")
	notHTML := isJSON || isText

	if notHTML {
		switch f.Module {
		case "xss", "crlf", "prompt":
			return true
		}
	}

	// Rule 2: Payload echoed in error message - not a real finding
	// If the response contains "error" field with our payload, it's just echo
	if isJSON && resp.Body != "" {
		bodyLower := strings.ToLower(resp.Body)
		if strings.Contains(bodyLower, "error") || strings.Contains(bodyLower, "message") {
			// The server returned an error that contains our payload text
			if f.Module == "prototype" && strings.Contains(resp.Body, f.Payload) {
				return true
			}
			if f.Module == "prompt" && containsPayloadInError(resp.Body, f.Payload) {
				return true
			}
			if f.Module == "graphql" && containsPayloadInError(resp.Body, f.Payload) {
				return true
			}
		}
	}

	// Rule 3: Server returned error status (4xx/5xx) with payload echoed back
	// This is just the server saying "I couldn't process your input"
	if resp.StatusCode >= 400 && resp.StatusCode < 600 {
		if f.Module == "prototype" && f.Confidence == "high" {
			// "polluted" in a 4xx JSON error is just the URL being echoed
			if isJSON && strings.Contains(resp.Body, `"url"`) {
				return true
			}
		}
	}

	// Rule 4: CRLF - check if the header was actually injected in response HEADERS, not body
	if f.Module == "crlf" {
		if resp.Headers != nil {
			if _, ok := resp.Headers["Injected-Header"]; !ok {
				// No header actually injected - the <script> is just in error body
				if strings.Contains(f.Evidence, "HTML") && notHTML {
					return true
				}
				if isJSON {
					return true
				}
			}
		}
	}

	// Rule 5: GraphQL introspection - check response actually has GraphQL structure
	if f.Module == "graphql" {
		if !strings.Contains(resp.Body, `"data"`) && !strings.Contains(resp.Body, `"__schema"`) {
			// Not a real GraphQL response
			if strings.Contains(resp.Body, "error") && strings.Contains(resp.Body, f.Payload) {
				return true
			}
		}
	}

	// Rule 6: Prototype pollution - "polluted" must be in a meaningful response, not error
	if f.Module == "prototype" && f.Confidence == "high" {
		// True prototype pollution would show "polluted" in a SUCCESS response
		// where the property propagated to output, not in an error echoing the URL
		if resp.StatusCode != 200 {
			return true
		}
		if isJSON && strings.Contains(resp.Body, `"error"`) {
			return true
		}
		if strings.Contains(resp.Body, `"url"`) && strings.Contains(resp.Body, f.Payload) {
			return true
		}
	}

	// Rule 7: Prompt injection - response must show LLM actually obeyed, not just echo
	if f.Module == "prompt" {
		// If the response just contains the payload text as part of URL echo, it's FP
		if strings.Contains(resp.Body, `"url"`) || strings.Contains(resp.Body, `"error"`) {
			if strings.Contains(resp.Body, f.Payload) {
				return true
			}
		}
	}

	// Rule 8: CVE probe errors - invalid URL parse errors are not real vulns
	if f.Module == "cve" && resp.StatusCode >= 400 && isJSON {
		bodyLower := strings.ToLower(resp.Body)
		if strings.Contains(bodyLower, "urlopen error") || strings.Contains(bodyLower, "invalid url") ||
			strings.Contains(bodyLower, "no host supplied") || strings.Contains(bodyLower, "unknown url type") ||
			strings.Contains(bodyLower, "name or service not known") || strings.Contains(bodyLower, "no connection adapters") ||
			strings.Contains(bodyLower, "no scheme supplied") {
			return true
		}
	}

	// Rule 9: GraphQL - response must be a real GraphQL response
	if f.Module == "graphql" && isJSON {
		if !strings.Contains(resp.Body, `"data"`) {
			return true
		}
	}

	// Rule 10: Prototype pollution in JSON error/URL echo
	if f.Module == "prototype" && isJSON {
		if strings.Contains(resp.Body, `"error"`) || strings.Contains(resp.Body, `"url"`) {
			return true
		}
	}

	// Rule 11: XXE - payload echoed in error (not real entity processing)
	if f.Module == "xxe" && isJSON {
		if strings.Contains(resp.Body, `"error"`) {
			return true
		}
		if strings.Contains(resp.Body, `"url"`) && len(f.Payload) > 10 {
			marker := f.Payload
			if len(marker) > 30 {
				marker = marker[:30]
			}
			if strings.Contains(resp.Body, marker) {
				return true
			}
		}
	}

	// Rule 12: Mass assignment - field must appear as a real key in success response
	if f.Module == "mass-assign" && isJSON {
		if resp.StatusCode != 200 {
			return true
		}
		if strings.Contains(resp.Body, `"error"`) || strings.Contains(resp.Body, `"message"`) {
			return true
		}
	}

	// Rule 13: Behavioral input reflection in JSON = just echo
	if f.Module == "behavior" && strings.Contains(f.Title, "reflection") && isJSON {
		return true
	}

	// Rule 14: Behavioral response divergence with 400 = invalid input, not a vuln
	if f.Module == "behavior" && strings.Contains(f.Title, "divergence") && resp.StatusCode == 400 {
		return true
	}

	// Rule 15: 414 URI Too Long is not a timing anomaly
	if f.Module == "behavior" && resp.StatusCode == 414 {
		return true
	}

	return false
}

func containsPayloadInError(body, payload string) bool {
	// Check if the payload (or significant part of it) appears near an "error"/"url" key
	if len(payload) < 5 {
		return false
	}
	// Use first 20 chars as marker
	marker := payload
	if len(marker) > 20 {
		marker = marker[:20]
	}
	return strings.Contains(body, marker)
}

