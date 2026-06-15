package vulns

import (
	"regexp"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// CSRFModule detects Cross-Site Request Forgery weaknesses by analyzing the
// baseline page: state-changing forms lacking an anti-CSRF token, and
// session cookies missing the SameSite attribute.
type CSRFModule struct{}

func (m *CSRFModule) Name() string        { return "csrf" }
func (m *CSRFModule) Description() string { return "Cross-Site Request Forgery" }

func (m *CSRFModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	// One benign probe so Detect runs once against the real page response.
	var anchor input.InjectionPoint
	if len(points) > 0 {
		anchor = points[0]
	}
	return []mutator.Payload{
		{Value: "", Point: anchor, Module: "csrf", Variant: "csrf-check"},
	}
}

var (
	rePostForm  = regexp.MustCompile(`(?is)<form[^>]*\bmethod\s*=\s*["']?post["']?[^>]*>(.*?)</form>`)
	reCSRFField = regexp.MustCompile(`(?i)name\s*=\s*["']?[^"'>]*(csrf|token|_token|authenticity_token|__requestverificationtoken|nonce)`)
)

func (m *CSRFModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if payload.Variant != "csrf-check" {
		return nil
	}

	// Find POST forms and check whether any lack an anti-CSRF token.
	forms := rePostForm.FindAllStringSubmatch(respBody, -1)
	formWithoutToken := false
	for _, f := range forms {
		if len(f) < 2 {
			continue
		}
		if !reCSRFField.MatchString(f[1]) {
			formWithoutToken = true
			break
		}
	}

	// Check session cookies for a missing SameSite attribute.
	sessionCookieNoSameSite := false
	for _, c := range respHeaders["Set-Cookie"] {
		lower := strings.ToLower(c)
		isSession := strings.Contains(lower, "session") || strings.Contains(lower, "sid") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "phpsessid") ||
			strings.Contains(lower, "jsessionid")
		if isSession && !strings.Contains(lower, "samesite") {
			sessionCookieNoSameSite = true
			break
		}
	}

	if !formWithoutToken && !sessionCookieNoSameSite {
		return nil
	}

	severity := "medium"
	var evidence []string
	if formWithoutToken {
		evidence = append(evidence, "POST form without anti-CSRF token")
	}
	if sessionCookieNoSameSite {
		evidence = append(evidence, "session cookie missing SameSite attribute")
	}
	if formWithoutToken && sessionCookieNoSameSite {
		severity = "high"
	}

	confidence := "medium"
	if formWithoutToken {
		confidence = "high"
	}

	return &Finding{
		Module:      "csrf",
		Severity:    severity,
		Confidence:  confidence,
		Title:       "Cross-Site Request Forgery - Missing protection",
		Description: "State-changing request lacks CSRF protection.",
		Payload:     payload.Value,
		Point:       payload.Point,
		Evidence:    strings.Join(evidence, "; "),
		OWASP:       "A01:2021 Broken Access Control",
		CWE:         "CWE-352",
	}
}
