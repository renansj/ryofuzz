package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// TakeoverModule detects subdomain takeover by matching the response body
// against fingerprints of orphaned third-party services (dangling CNAME).
type TakeoverModule struct{}

func (m *TakeoverModule) Name() string        { return "takeover" }
func (m *TakeoverModule) Description() string { return "Subdomain Takeover (dangling CNAME)" }

func (m *TakeoverModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	// Passive: one probe so Detect runs against the target's own response.
	var anchor input.InjectionPoint
	if len(points) > 0 {
		anchor = points[0]
	}
	return []mutator.Payload{
		{Value: "", Point: anchor, Module: "takeover", Variant: "takeover-check"},
	}
}

// takeoverSig pairs a service name with a fingerprint string that an orphaned
// instance of that service returns.
type takeoverSig struct {
	service     string
	fingerprint string
}

func takeoverSignatures() []takeoverSig {
	return []takeoverSig{
		{"AWS S3", "NoSuchBucket"},
		{"AWS S3", "The specified bucket does not exist"},
		{"GitHub Pages", "There isn't a GitHub Pages site here"},
		{"GitHub Pages", "For root URLs (like http://example.com/) you must provide an index.html file"},
		{"Heroku", "No such app"},
		{"Heroku", "herokucdn.com/error-pages/no-such-app.html"},
		{"Shopify", "Sorry, this shop is currently unavailable"},
		{"Fastly", "Fastly error: unknown domain"},
		{"Bitbucket", "Repository not found"},
		{"Ghost", "The thing you were looking for is no longer here"},
		{"Tumblr", "There's nothing here."},
		{"Tumblr", "Whatever you were looking for doesn't currently exist at this address"},
		{"WordPress", "Do you want to register"},
		{"Surge.sh", "project not found"},
		{"Azure", "404 Web Site not found"},
		{"Pantheon", "The gods are wise, but do not know of the site which you seek"},
		{"Cargo", "If you're moving your domain away from Cargo"},
		{"Zendesk", "Help Center Closed"},
		{"Readme.io", "Project doesnt exist... yet!"},
		{"Netlify", "Not Found - Request ID"},
	}
}

func (m *TakeoverModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if payload.Variant != "takeover-check" {
		return nil
	}

	for _, s := range takeoverSignatures() {
		if strings.Contains(respBody, s.fingerprint) {
			return &Finding{
				Module:      "takeover",
				Severity:    "high",
				Confidence:  "high",
				Title:       "Subdomain Takeover - " + s.service,
				Description: "The host points to an orphaned " + s.service + " instance. An attacker may claim it and serve content from this domain.",
				Payload:     s.service,
				Point:       payload.Point,
				Evidence:    "Service fingerprint matched: " + s.fingerprint,
				OWASP:       "A05:2021 Security Misconfiguration",
				CWE:         "CWE-350",
			}
		}
	}
	return nil
}
