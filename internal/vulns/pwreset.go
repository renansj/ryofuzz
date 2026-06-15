package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type PwResetModule struct{}

func (m *PwResetModule) Name() string        { return "pwreset" }
func (m *PwResetModule) Description() string { return "Password Reset Poisoning" }

func (m *PwResetModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	evilHost := "evil.com"
	hostPayloads := []struct {
		value   string
		variant string
	}{
		{evilHost, "host-header"},
		{evilHost, "x-forwarded-host"},
		{evilHost, "x-original-url"},
		{"http://" + evilHost, "x-forwarded-host-url"},
		{evilHost + ":443", "host-with-port"},
		{evilHost + "\r\nX-Injected: true", "host-crlf"},
	}

	for _, point := range points {
		// Only inject into host-related headers. Injecting into arbitrary query
		// params (e.g. a url= param) and then matching the host in an echoed
		// response is a false positive, not password reset poisoning.
		if point.Location != input.LocHeader {
			continue
		}
		name := strings.ToLower(point.Name)
		if name == "host" || strings.Contains(name, "forward") || strings.Contains(name, "original") ||
			strings.Contains(name, "referer") || strings.Contains(name, "true-client") {
			for _, p := range hostPayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "pwreset", Variant: p.variant,
					Metadata: map[string]string{"evil_host": evilHost},
				})
			}
		}
	}
	return payloads
}

func (m *PwResetModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	evilHost := "evil.com"
	if payload.Metadata != nil && payload.Metadata["evil_host"] != "" {
		evilHost = payload.Metadata["evil_host"]
	}

	// Check if evil host appears in response body in a URL context
	bodyLower := strings.ToLower(respBody)
	if strings.Contains(bodyLower, "http://"+evilHost) || strings.Contains(bodyLower, "https://"+evilHost) ||
		strings.Contains(bodyLower, "//"+evilHost) {
		return &Finding{
			Module:      "pwreset",
			Severity:    "critical",
			Confidence:  "confirmed",
			Title:       "Password Reset Poisoning - Host header injection",
			Description: "The injected host value appears in a URL in the response, likely a password reset link",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Injected host '" + evilHost + "' found in response URL",
			OWASP:       "A07:2021",
			CWE:         "CWE-640",
		}
	}

	// Check response headers for the evil host
	for _, vals := range respHeaders {
		for _, v := range vals {
			if strings.Contains(strings.ToLower(v), evilHost) {
				return &Finding{
					Module:      "pwreset",
					Severity:    "high",
					Confidence:  "high",
					Title:       "Password Reset Poisoning - Host reflected in headers",
					Description: "The injected host value is reflected in response headers",
					Payload:     payload.Value,
					Point:       payload.Point,
					Evidence:    "Host reflected in response header: " + v,
					OWASP:       "A07:2021",
					CWE:         "CWE-640",
				}
			}
		}
	}

	return nil
}
