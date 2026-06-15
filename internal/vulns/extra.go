package vulns

import (
	"strconv"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// ===== Clickjacking =====

type ClickjackModule struct{}

func (m *ClickjackModule) Name() string        { return "clickjack" }
func (m *ClickjackModule) Description() string { return "Clickjacking (missing frame protection)" }

func (m *ClickjackModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var anchor input.InjectionPoint
	if len(points) > 0 {
		anchor = points[0]
	}
	return []mutator.Payload{{Value: "", Point: anchor, Module: "clickjack", Variant: "frame-check"}}
}

func (m *ClickjackModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if payload.Variant != "frame-check" {
		return nil
	}
	// Only meaningful for HTML pages
	ct := strings.ToLower(headerVal(respHeaders, "Content-Type"))
	if ct != "" && !strings.Contains(ct, "html") {
		return nil
	}
	xfo := headerVal(respHeaders, "X-Frame-Options")
	csp := strings.ToLower(headerVal(respHeaders, "Content-Security-Policy"))
	hasFrameAncestors := strings.Contains(csp, "frame-ancestors")
	if xfo == "" && !hasFrameAncestors {
		return &Finding{
			Module:      "clickjack",
			Severity:    "medium",
			Confidence:  "high",
			Title:       "Clickjacking - No frame protection",
			Description: "The page can be framed by any origin (no X-Frame-Options and no CSP frame-ancestors), enabling clickjacking.",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Missing X-Frame-Options and CSP frame-ancestors",
			OWASP:       "A05:2021 Security Misconfiguration",
			CWE:         "CWE-1021",
		}
	}
	return nil
}

// ===== ReDoS (Regular Expression Denial of Service) =====

type ReDoSModule struct{}

func (m *ReDoSModule) Name() string        { return "redos" }
func (m *ReDoSModule) Description() string { return "Regular Expression Denial of Service" }

func (m *ReDoSModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	// Catastrophic backtracking triggers
	evil := []string{
		strings.Repeat("a", 50000) + "!",
		strings.Repeat("a", 30000) + "X",
		strings.Repeat("0", 40000) + "!",
		"(" + strings.Repeat("a", 1000) + ")*!",
		strings.Repeat("ab", 20000) + "!",
	}
	for _, point := range points {
		for i, e := range evil {
			payloads = append(payloads, mutator.Payload{
				Value: e, Point: point, Module: "redos", Variant: "catastrophic-" + strconv.Itoa(i),
			})
		}
	}
	return payloads
}

func (m *ReDoSModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if payload.Module != "redos" {
		return nil
	}
	// A large differential delay indicates catastrophic backtracking.
	if respTime-baseTime > 4000 {
		return &Finding{
			Module:      "redos",
			Severity:    "high",
			Confidence:  "medium",
			Title:       "ReDoS - Catastrophic backtracking (unconfirmed)",
			Description: "A crafted input caused a large processing delay, indicating a vulnerable regular expression. Confirm with varied input lengths.",
			Payload:     truncatePayload(payload.Value),
			Point:       payload.Point,
			Evidence:    "Response delay " + strconv.FormatInt(respTime-baseTime, 10) + "ms over baseline",
			OWASP:       "A06:2021 Vulnerable and Outdated Components",
			CWE:         "CWE-1333",
		}
	}
	return nil
}

// ===== XSLT Injection =====

type XSLTModule struct{}

func (m *XSLTModule) Name() string        { return "xslt" }
func (m *XSLTModule) Description() string { return "XSLT Injection" }

func (m *XSLTModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	tests := []struct{ value, variant string }{
		{`<xsl:value-of select="system-property('xsl:version')"/>`, "version-probe"},
		{`<xsl:value-of select="unparsed-text('/etc/passwd')"/>`, "file-read"},
		{`<xsl:value-of select="document('/etc/passwd')"/>`, "document-read"},
		{`<xsl:value-of select="php:function('system','id')"/>`, "php-function"},
	}
	for _, point := range points {
		for _, tt := range tests {
			payloads = append(payloads, mutator.Payload{
				Value: tt.value, Point: point, Module: "xslt", Variant: tt.variant,
			})
		}
	}
	return payloads
}

func (m *XSLTModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if payload.Module != "xslt" {
		return nil
	}
	// version-probe: XSLT processor version leaks (e.g. "1.0", "2.0") plus engine names
	indicators := map[string]string{
		"root:x:0:0":            "file read via XSLT",
		"libxslt":               "libxslt processor exposed",
		"Saxonica":              "Saxon processor exposed",
		"XSLT":                  "XSLT processing error",
		"xsl:version":           "XSLT version property evaluated",
		"Transformation failed": "XSLT transformation error",
	}
	low := respBody
	for ind, desc := range indicators {
		if indicatorConfirmed(low, baseBody, payload.Value, ind) {
			sev := "high"
			if ind == "root:x:0:0" {
				sev = "critical"
			}
			return &Finding{
				Module:      "xslt",
				Severity:    sev,
				Confidence:  "high",
				Title:       "XSLT Injection - " + desc,
				Description: "User input is processed as XSLT, enabling file read or code execution.",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Indicator '" + ind + "' in response",
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-91",
			}
		}
	}
	return nil
}

// ===== Session Management =====

type SessionModule struct{}

func (m *SessionModule) Name() string        { return "session" }
func (m *SessionModule) Description() string { return "Session management weaknesses" }

func (m *SessionModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var anchor input.InjectionPoint
	if len(points) > 0 {
		anchor = points[0]
	}
	return []mutator.Payload{{Value: "", Point: anchor, Module: "session", Variant: "session-check"}}
}

func (m *SessionModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if payload.Variant != "session-check" {
		return nil
	}
	for _, c := range respHeaders["Set-Cookie"] {
		lower := strings.ToLower(c)
		isSession := strings.Contains(lower, "session") || strings.Contains(lower, "sid") ||
			strings.Contains(lower, "jsessionid") || strings.Contains(lower, "phpsessid") ||
			strings.Contains(lower, "auth")
		if !isSession {
			continue
		}
		var issues []string
		if !strings.Contains(lower, "httponly") {
			issues = append(issues, "missing HttpOnly")
		}
		if !strings.Contains(lower, "secure") {
			issues = append(issues, "missing Secure")
		}
		// Extract token value to estimate entropy
		if val := cookieValue(c); len(val) > 0 && len(val) < 16 {
			issues = append(issues, "short/low-entropy token")
		}
		if len(issues) > 0 {
			return &Finding{
				Module:      "session",
				Severity:    "medium",
				Confidence:  "high",
				Title:       "Session Cookie Weakness",
				Description: "Session cookie has insecure attributes: " + strings.Join(issues, ", "),
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    c,
				OWASP:       "A07:2021 Identification and Authentication Failures",
				CWE:         "CWE-614",
			}
		}
	}
	return nil
}

// ===== Username/Account Enumeration =====

type UserEnumModule struct{}

func (m *UserEnumModule) Name() string        { return "userenum" }
func (m *UserEnumModule) Description() string { return "Account / username enumeration" }

func (m *UserEnumModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	for _, point := range points {
		name := strings.ToLower(point.Name)
		if strings.Contains(name, "user") || strings.Contains(name, "email") ||
			strings.Contains(name, "login") || strings.Contains(name, "account") {
			payloads = append(payloads,
				mutator.Payload{Value: "nonexistent_user_zzz999", Point: point, Module: "userenum", Variant: "invalid-user"},
			)
		}
	}
	return payloads
}

func (m *UserEnumModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if payload.Module != "userenum" {
		return nil
	}
	// Verbose messages that distinguish valid from invalid accounts
	low := strings.ToLower(respBody)
	enumMessages := []string{
		"user not found", "no such user", "account does not exist",
		"unknown user", "email not found", "no account with that email",
		"username does not exist", "invalid username",
	}
	for _, msg := range enumMessages {
		if strings.Contains(low, msg) {
			return &Finding{
				Module:      "userenum",
				Severity:    "low",
				Confidence:  "medium",
				Title:       "Username Enumeration - Verbose response",
				Description: "The response distinguishes existing from non-existing accounts, enabling enumeration.",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Distinguishing message: '" + msg + "'",
				OWASP:       "A07:2021 Identification and Authentication Failures",
				CWE:         "CWE-203",
			}
		}
	}
	return nil
}

// ===== helpers =====

func headerVal(h map[string][]string, key string) string {
	if h == nil {
		return ""
	}
	if v, ok := h[key]; ok && len(v) > 0 {
		return v[0]
	}
	// case-insensitive fallback
	for k, v := range h {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func cookieValue(setCookie string) string {
	parts := strings.SplitN(setCookie, ";", 2)
	if len(parts) == 0 {
		return ""
	}
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) != 2 {
		return ""
	}
	return strings.TrimSpace(kv[1])
}

func truncatePayload(s string) string {
	if len(s) > 60 {
		return s[:60] + "...[" + strconv.Itoa(len(s)) + " bytes]"
	}
	return s
}
