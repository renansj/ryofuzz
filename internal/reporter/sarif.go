package reporter

import (
	"encoding/json"
	"os"

	"github.com/renansj/ryofuzz/internal/vulns"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	Properties       sarifProperties `json:"properties,omitempty"`
}

type sarifProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID  string         `json:"ruleId"`
	Level   string         `json:"level"`
	Message sarifMessage   `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func severityToLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// ReportSARIF writes findings in SARIF 2.1.0 format
func ReportSARIF(findings []*vulns.Finding, outputFile string) error {
	ruleMap := make(map[string]bool)
	var rules []sarifRule
	for _, f := range findings {
		if !ruleMap[f.Module] {
			ruleMap[f.Module] = true
			rules = append(rules, sarifRule{
				ID:               f.Module,
				ShortDescription: sarifMessage{Text: f.Module + " vulnerability detection"},
				Properties:       sarifProperties{Tags: []string{f.OWASP, f.CWE}},
			})
		}
	}

	var results []sarifResult
	for _, f := range findings {
		msg := f.Title
		if f.Evidence != "" {
			msg += " | " + f.Evidence
		}
		r := sarifResult{
			RuleID:  f.Module,
			Level:   severityToLevel(f.Severity),
			Message: sarifMessage{Text: msg},
		}
		if f.Point.Name != "" {
			r.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Point.Name},
				},
			}}
		}
		results = append(results, r)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "ryofuzz",
					Version: "1.0.0",
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputFile, data, 0644)
}
