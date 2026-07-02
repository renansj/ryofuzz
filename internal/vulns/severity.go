package vulns

import "strings"

// Severity and Confidence are stored on Finding as strings for backward
// compatibility with the 48 existing modules, but their allowed values and
// ordering are defined here so reporting, sorting and validation stop relying
// on scattered string literals and magic maps (review E4).

// Severity levels, ordered most to least severe.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Confidence levels.
const (
	ConfidenceConfirmed = "confirmed"
	ConfidenceHigh      = "high"
	ConfidenceMedium    = "medium"
	ConfidenceLow       = "low"
)

// severityRank maps a severity to a sort rank (lower = more severe).
var severityRank = map[string]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// SeverityRank returns the sort rank of a severity. Unknown values sort last.
func SeverityRank(sev string) int {
	if r, ok := severityRank[strings.ToLower(strings.TrimSpace(sev))]; ok {
		return r
	}
	return 99
}

// ValidSeverity reports whether s is a known severity value.
func ValidSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// validConfidence is the set of accepted confidence values.
var validConfidence = map[string]bool{
	ConfidenceConfirmed: true,
	ConfidenceHigh:      true,
	ConfidenceMedium:    true,
	ConfidenceLow:       true,
}

// ValidConfidence reports whether c is a known confidence value.
func ValidConfidence(c string) bool {
	return validConfidence[strings.ToLower(strings.TrimSpace(c))]
}

// NormalizeFinding lowercases and defaults the severity/confidence of a finding
// so downstream sorting and reporting are consistent even if a module emitted
// an odd case or left a field blank.
func NormalizeFinding(f *Finding) {
	if f == nil {
		return
	}
	f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
	if !ValidSeverity(f.Severity) {
		f.Severity = SeverityInfo
	}
	f.Confidence = strings.ToLower(strings.TrimSpace(f.Confidence))
	if !ValidConfidence(f.Confidence) {
		f.Confidence = ConfidenceLow
	}
}
