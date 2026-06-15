package chain

import "github.com/renansj/ryofuzz/internal/vulns"

// ChainRule defines a vulnerability chain rule
type ChainRule struct {
	Requires []string
	Title    string
	Severity string
	Impact   string
}

// Rules maps combinations of findings to elevated-severity chains
var Rules = []ChainRule{
	{Requires: []string{"ssrf"}, Title: "SSRF to Cloud Credentials", Severity: "critical", Impact: "If SSRF can reach 169.254.169.254, attacker gets IAM credentials for lateral movement"},
	{Requires: []string{"redirect", "oauth"}, Title: "Open Redirect + OAuth = Account Takeover", Severity: "critical", Impact: "Redirect in OAuth flow leaks authorization code to attacker domain"},
	{Requires: []string{"xss", "cors"}, Title: "XSS + CORS Misconfiguration = Cross-Origin Data Theft", Severity: "critical", Impact: "Stored XSS in domain with permissive CORS allows cross-origin credentialed requests"},
	{Requires: []string{"sqli", "idor"}, Title: "SQLi + IDOR = Mass Data Exfiltration", Severity: "critical", Impact: "SQL injection combined with object enumeration enables full database dump"},
	{Requires: []string{"ssrf", "xxe"}, Title: "XXE + SSRF = Internal Network Scanning", Severity: "critical", Impact: "XXE provides SSRF primitive for scanning internal services"},
	{Requires: []string{"xss"}, Title: "Stored XSS = Session Hijacking", Severity: "high", Impact: "If cookies lack HttpOnly, stored XSS enables mass session theft"},
	{Requires: []string{"upload", "cmdi"}, Title: "Upload + Command Injection = RCE", Severity: "critical", Impact: "File upload combined with execution achieves remote code execution"},
	{Requires: []string{"cache-deception"}, Title: "Cache Deception = Account Data Leak", Severity: "critical", Impact: "Cached authenticated responses expose user data to anonymous attackers"},
	{Requires: []string{"prototype"}, Title: "Prototype Pollution to RCE", Severity: "critical", Impact: "Server-side prototype pollution may chain to RCE via gadgets in EJS/Pug/Handlebars"},
	{Requires: []string{"jwt"}, Title: "JWT Algorithm Confusion = Auth Bypass", Severity: "critical", Impact: "Forged JWT grants arbitrary privilege escalation"},
}

// Detect evaluates chain rules against current findings
func Detect(findings []*vulns.Finding) []*vulns.Finding {
	foundModules := make(map[string]bool)
	for _, f := range findings {
		foundModules[f.Module] = true
	}

	var chains []*vulns.Finding
	for _, rule := range Rules {
		allPresent := true
		for _, req := range rule.Requires {
			if !foundModules[req] {
				allPresent = false
				break
			}
		}
		if allPresent {
			chains = append(chains, &vulns.Finding{
				Module:      "chain",
				Severity:    rule.Severity,
				Confidence:  "medium",
				Title:       "[CHAIN] " + rule.Title,
				Description: rule.Impact,
				OWASP:       "A04:2021 Insecure Design",
				CWE:         "CWE-269",
			})
		}
	}
	return chains
}
