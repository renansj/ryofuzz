package vulns

import (
	"fmt"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type HPPModule struct{}

func (m *HPPModule) Name() string        { return "hpp" }
func (m *HPPModule) Description() string { return "HTTP Parameter Pollution" }

func (m *HPPModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	for _, point := range points {
		if point.Location != input.LocQueryParam && point.Location != input.LocFormBody {
			continue
		}
		orig := point.OriginalValue
		name := point.Name

		hppPayloads := []struct {
			value   string
			variant string
		}{
			{orig + "&" + name + "=hpp_test", "duplicate-param"},
			{"hpp_first&" + name + "=hpp_second", "duplicate-diff"},
			{orig + "&" + name + "=<script>", "duplicate-xss"},
			{name + "[]=1&" + name + "[]=2", "array-syntax"},
			{orig + "&" + name + "[]=" + orig, "array-append"},
			{"%26" + name + "%3dhpp_encoded", "encoded-ampersand"},
			{orig + "," + orig + "2", "comma-separated"},
			{orig + "\n" + name + "=injected", "newline-param"},
		}

		for _, p := range hppPayloads {
			payloads = append(payloads, mutator.Payload{
				Value: p.value, Point: point, Module: "hpp", Variant: p.variant,
				Metadata: map[string]string{"original": orig, "param_name": name},
			})
		}
	}
	return payloads
}

func (m *HPPModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Status code change
	if baseStatus != respStatus && respStatus != 0 {
		return &Finding{
			Module:      "hpp",
			Severity:    "medium",
			Confidence:  "medium",
			Title:       "HTTP Parameter Pollution - Status code change",
			Description: "Duplicate parameters caused a different server response status",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    fmt.Sprintf("Baseline status=%d, response status=%d", baseStatus, respStatus),
			OWASP:       "A03:2021",
			CWE:         "CWE-235",
		}
	}

	// Body length difference > 100 bytes
	lenDiff := len(respBody) - len(baseBody)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	if lenDiff > 100 {
		return &Finding{
			Module:      "hpp",
			Severity:    "medium",
			Confidence:  "medium",
			Title:       "HTTP Parameter Pollution - Response size divergence",
			Description: "Duplicate parameters caused a significantly different response body size",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    fmt.Sprintf("Body length diff: %d bytes", lenDiff),
			OWASP:       "A03:2021",
			CWE:         "CWE-235",
		}
	}

	// Check if second param value is reflected (server uses last occurrence)
	if strings.Contains(payload.Variant, "duplicate") {
		if strings.Contains(respBody, "hpp_second") || strings.Contains(respBody, "hpp_test") {
			return &Finding{
				Module:      "hpp",
				Severity:    "medium",
				Confidence:  "high",
				Title:       "HTTP Parameter Pollution - Second param value used",
				Description: "Server uses the second occurrence of a duplicated parameter, enabling pollution attacks",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Injected duplicate value reflected in response",
				OWASP:       "A03:2021",
				CWE:         "CWE-235",
			}
		}
	}

	return nil
}
