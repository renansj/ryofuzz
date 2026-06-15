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

	// A jump to a 5xx server error usually means the malformed value broke the
	// request (e.g. invalid host), not a genuine parameter-pollution behavior.
	// Only consider non-error status changes.
	if baseStatus != respStatus && respStatus != 0 && respStatus < 500 && baseStatus < 500 {
		return &Finding{
			Module:      "hpp",
			Severity:    "low",
			Confidence:  "low",
			Title:       "HTTP Parameter Pollution - Status code change (tentative)",
			Description: "Duplicate parameters changed the response status. Confirm the server selects a different parameter occurrence.",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    fmt.Sprintf("Baseline status=%d, response status=%d", baseStatus, respStatus),
			OWASP:       "A03:2021",
			CWE:         "CWE-235",
		}
	}

	// Second occurrence used by the server (true second-param-wins) is the
	// reliable signal. Require a non-error response and the injected marker
	// present while NOT being attributable to a full echo of both values.
	if strings.Contains(payload.Variant, "duplicate") && respStatus < 500 {
		usesSecond := strings.Contains(respBody, "hpp_second")
		usesTest := strings.Contains(respBody, "hpp_test") && !strings.Contains(respBody, "hpp_first")
		if usesSecond || usesTest {
			return &Finding{
				Module:      "hpp",
				Severity:    "medium",
				Confidence:  "high",
				Title:       "HTTP Parameter Pollution - Second param value used",
				Description: "Server uses the second occurrence of a duplicated parameter, enabling pollution attacks",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Injected duplicate value reflected as the effective value",
				OWASP:       "A03:2021",
				CWE:         "CWE-235",
			}
		}
	}

	return nil
}
