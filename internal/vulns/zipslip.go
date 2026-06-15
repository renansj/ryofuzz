package vulns

import (
	"archive/zip"
	"bytes"
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// ZipSlipModule tests for archive extraction path traversal (Zip Slip): an
// uploaded archive containing entries with ../ sequences that, when extracted,
// write outside the intended directory.
type ZipSlipModule struct{}

func (m *ZipSlipModule) Name() string        { return "zipslip" }
func (m *ZipSlipModule) Description() string { return "Archive extraction path traversal (Zip Slip)" }

// buildZipSlip creates an in-memory zip whose single entry uses a traversal path.
func buildZipSlip(entryName, content string) string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Use a writer that does not sanitize the name (raw header)
	hdr := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
	w, err := zw.CreateHeader(hdr)
	if err == nil {
		w.Write([]byte(content))
	}
	zw.Close()
	return buf.String()
}

func (m *ZipSlipModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	slipEntries := []struct {
		name    string
		variant string
	}{
		{"../../../../../../tmp/ryofuzz_zipslip.txt", "unix-traversal"},
		{"..\\..\\..\\..\\..\\windows\\temp\\ryofuzz.txt", "windows-traversal"},
		{"../../../var/www/html/ryofuzz_shell.php", "webroot-php"},
		{"./../../.ssh/authorized_keys", "ssh-keys"},
	}

	for _, point := range points {
		name := strings.ToLower(point.Name)
		isFileField := strings.Contains(name, "file") || strings.Contains(name, "upload") ||
			strings.Contains(name, "archive") || strings.Contains(name, "zip") ||
			strings.Contains(name, "attachment")
		if !isFileField {
			continue
		}
		for _, se := range slipEntries {
			zipBytes := buildZipSlip(se.name, "ryofuzz-zipslip-marker")
			payloads = append(payloads, mutator.Payload{
				Value:   "ryofuzz_slip.zip",
				Point:   point,
				Module:  "zipslip",
				Variant: se.variant,
				Metadata: map[string]string{
					"upload":          "1",
					"upload_field":    point.Name,
					"upload_filename": "ryofuzz_slip.zip",
					"upload_content":  zipBytes,
					"upload_ctype":    "application/zip",
				},
			})
		}
	}
	return payloads
}

func (m *ZipSlipModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {
	if payload.Module != "zipslip" {
		return nil
	}
	if respStatus != 200 && respStatus != 201 {
		return nil
	}
	low := strings.ToLower(respBody)
	// Signals that the archive was extracted (and possibly the traversal honored)
	extractionSignals := []string{
		"extracted", "unzipped", "extraction complete", "files extracted",
		"ryofuzz_zipslip", "ryofuzz_shell", "ryofuzz.txt",
	}
	for _, sig := range extractionSignals {
		if strings.Contains(low, sig) {
			return &Finding{
				Module:      "zipslip",
				Severity:    "high",
				Confidence:  "medium",
				Title:       "Zip Slip - Archive extraction path traversal (" + payload.Variant + ")",
				Description: "An uploaded archive with a traversal entry was accepted/extracted. Verify the file was written outside the target directory.",
				Payload:     payload.Variant,
				Point:       payload.Point,
				Evidence:    "Extraction signal '" + sig + "' in response",
				OWASP:       "A01:2021 Broken Access Control",
				CWE:         "CWE-22",
			}
		}
	}
	return nil
}
