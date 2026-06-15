package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// InfoLeakModule probes for exposed sensitive files and information disclosure.
// It checks for common misconfigurations: exposed VCS metadata, env files,
// backups, debug endpoints, and source maps.
type InfoLeakModule struct{}

func (m *InfoLeakModule) Name() string        { return "infoleak" }
func (m *InfoLeakModule) Description() string { return "Sensitive file / information disclosure" }

type leakPath struct {
	path    string
	variant string
}

func infoLeakPaths() []leakPath {
	return []leakPath{
		{"/.git/config", "git-config"},
		{"/.git/HEAD", "git-head"},
		{"/.env", "dotenv"},
		{"/.svn/entries", "svn-entries"},
		{"/.DS_Store", "ds-store"},
		{"/config.php.bak", "php-backup"},
		{"/index.php.old", "php-old"},
		{"/.htaccess", "htaccess"},
		{"/web.config", "web-config"},
		{"/actuator", "actuator"},
		{"/actuator/env", "actuator-env"},
		{"/actuator/heapdump", "actuator-heapdump"},
		{"/server-status", "server-status"},
		{"/phpinfo.php", "phpinfo"},
		{"/.aws/credentials", "aws-credentials"},
		{"/backup.zip", "backup-zip"},
		{"/app.js.map", "sourcemap"},
		{"/wp-config.php.bak", "wpconfig-backup"},
		{"/.travis.yml", "ci-config"},
	}
}

func (m *InfoLeakModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	// Host-level probing: one payload per sensitive path, independent of params.
	var anchor input.InjectionPoint
	if len(points) > 0 {
		anchor = points[0]
	}
	var payloads []mutator.Payload
	for _, lp := range infoLeakPaths() {
		payloads = append(payloads, mutator.Payload{
			Value:   lp.path,
			Point:   anchor,
			Module:  "infoleak",
			Variant: lp.variant,
			Metadata: map[string]string{
				"rawpath": lp.path,
			},
		})
	}
	return payloads
}

func (m *InfoLeakModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if respStatus != 200 {
		return nil
	}

	// Signature-based confirmation per file type.
	type sig struct {
		variants []string
		needles  []string
		severity string
	}
	signatures := []sig{
		{[]string{"git-config", "git-head"}, []string{"[core]", "ref: refs/"}, "high"},
		{[]string{"dotenv"}, []string{"DB_PASSWORD", "APP_KEY", "SECRET", "DB_HOST"}, "critical"},
		{[]string{"actuator-env"}, []string{"\"propertySources\"", "\"activeProfiles\""}, "critical"},
		{[]string{"actuator-heapdump"}, []string{"JAVA PROFILE", "HPROF"}, "critical"},
		{[]string{"actuator"}, []string{"\"_links\"", "\"health\""}, "medium"},
		{[]string{"server-status"}, []string{"Apache Server Status"}, "medium"},
		{[]string{"phpinfo"}, []string{"PHP Version", "phpinfo()"}, "high"},
		{[]string{"sourcemap"}, []string{"\"sources\":", "\"mappings\":"}, "medium"},
		{[]string{"aws-credentials"}, []string{"aws_access_key_id", "aws_secret_access_key"}, "critical"},
		{[]string{"svn-entries"}, []string{"dir\n", "svn:"}, "high"},
		{[]string{"web-config"}, []string{"<configuration>", "<connectionStrings>"}, "high"},
		{[]string{"ds-store"}, []string{"Bud1", "\x00\x00\x00\x01Bud1"}, "low"},
	}

	for _, s := range signatures {
		if !variantIn(payload.Variant, s.variants) {
			continue
		}
		for _, needle := range s.needles {
			if strings.Contains(respBody, needle) && !strings.Contains(baseBody, needle) {
				return &Finding{
					Module:      "infoleak",
					Severity:    s.severity,
					Confidence:  "confirmed",
					Title:       "Sensitive File Exposed - " + payload.Variant,
					Description: "A sensitive file or debug endpoint is publicly accessible: " + payload.Value,
					Payload:     payload.Value,
					Point:       payload.Point,
					Evidence:    "Signature '" + needle + "' found at " + payload.Value,
					OWASP:       "A05:2021 Security Misconfiguration",
					CWE:         "CWE-200",
				}
			}
		}
	}

	// Generic backup/archive exposure: 200 for a path that 404s in baseline.
	backupVariants := []string{"php-backup", "php-old", "backup-zip", "wpconfig-backup"}
	if variantIn(payload.Variant, backupVariants) && baseStatus != 200 && respStatus == 200 && len(respBody) > 0 {
		return &Finding{
			Module:      "infoleak",
			Severity:    "high",
			Confidence:  "high",
			Title:       "Backup File Exposed - " + payload.Variant,
			Description: "A backup or old file is publicly accessible: " + payload.Value,
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Path returned 200 (baseline " + statusStr(baseStatus) + "): " + payload.Value,
			OWASP:       "A05:2021 Security Misconfiguration",
			CWE:         "CWE-200",
		}
	}

	return nil
}

func variantIn(v string, list []string) bool {
	for _, x := range list {
		if v == x {
			return true
		}
	}
	return false
}

func statusStr(s int) string {
	switch s {
	case 404:
		return "404"
	case 403:
		return "403"
	case 0:
		return "none"
	default:
		return "non-200"
	}
}
