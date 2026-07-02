package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type XSSIModule struct{}

func (m *XSSIModule) Name() string        { return "xssi" }
func (m *XSSIModule) Description() string { return "Cross-Site Script Inclusion (JSONP/XSSI)" }

func (m *XSSIModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	callbackParams := []string{"callback", "jsonp", "cb", "jsonpcallback", "func", "call"}

	for _, point := range points {
		name := strings.ToLower(point.Name)
		// If this point IS a callback param, inject our function name
		for _, cp := range callbackParams {
			if name == cp {
				payloads = append(payloads, mutator.Payload{
					Value: "ryofuzz_xssi", Point: point, Module: "xssi", Variant: "callback-inject",
					Metadata: map[string]string{"callback": "ryofuzz_xssi"},
				})
				payloads = append(payloads, mutator.Payload{
					Value: "alert", Point: point, Module: "xssi", Variant: "callback-alert",
					Metadata: map[string]string{"callback": "alert"},
				})
				break
			}
		}
		// Try adding callback parameter
		if point.Location == input.LocQueryParam {
			for _, cp := range callbackParams {
				payloads = append(payloads, mutator.Payload{
					Value: point.OriginalValue + "&" + cp + "=ryofuzz_xssi", Point: point, Module: "xssi", Variant: "append-" + cp,
					Metadata: map[string]string{"callback": "ryofuzz_xssi"},
				})
			}
		}
	}
	return payloads
}

func (m *XSSIModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if respStatus != 200 {
		return nil
	}

	callbackName := "ryofuzz_xssi"
	if payload.Metadata != nil && payload.Metadata["callback"] != "" {
		callbackName = payload.Metadata["callback"]
	}

	// Check if response wraps data in callback function
	trimmed := strings.TrimSpace(respBody)
	isJSONP := strings.HasPrefix(trimmed, callbackName+"(") ||
		strings.HasPrefix(trimmed, "/**/"+callbackName+"(") ||
		strings.HasPrefix(trimmed, callbackName+" (")

	if !isJSONP {
		return nil
	}

	// Check Content-Type - vulnerable if not application/json
	hasProtection := false
	for _, ct := range respHeaders["Content-Type"] {
		if strings.Contains(strings.ToLower(ct), "application/json") {
			hasProtection = true
		}
	}
	for _, v := range respHeaders["X-Content-Type-Options"] {
		if strings.ToLower(v) == "nosniff" {
			hasProtection = true
		}
	}

	if hasProtection {
		return nil
	}

	// Check for sensitive data indicators
	sensitiveKeys := []string{"email", "user", "token", "session", "name", "id", "account", "secret"}
	hasSensitive := false
	bodyLower := strings.ToLower(respBody)
	for _, key := range sensitiveKeys {
		if strings.Contains(bodyLower, "\""+key+"\"") {
			hasSensitive = true
			break
		}
	}

	severity := "medium"
	if hasSensitive {
		severity = "high"
	}

	return &Finding{
		Module:      "xssi",
		Severity:    severity,
		Confidence:  "high",
		Title:       "XSSI/JSONP - Sensitive data exposed via callback",
		Description: "JSONP endpoint returns data wrapped in a callback function without proper Content-Type or nosniff protection",
		Payload:     payload.Value,
		Point:       payload.Point,
		Evidence:    "Response starts with: " + trimmed[:min(len(trimmed), 80)],
		OWASP:       "A01:2021",
		CWE:         "CWE-352",
	}
}
