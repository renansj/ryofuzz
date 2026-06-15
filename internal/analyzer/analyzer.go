package analyzer

import (
	"sort"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/vulns"
)

// Analyze compares fuzz results against baseline and runs per-module detection
func Analyze(baseline *engine.Response, results []engine.FuzzResult, modules []vulns.VulnModule) []*vulns.Finding {
	var findings []*vulns.Finding
	seen := make(map[string]bool) // dedup por module+point+title

	for _, result := range results {
		if result.Error != nil {
			continue
		}

		// Encontrar o módulo correspondente ao payload
		for _, mod := range modules {
			if mod.Name() != result.Payload.Module {
				continue
			}

			// Converter headers para map[string][]string
			headers := make(map[string][]string)
			for k, v := range result.Response.Headers {
				headers[k] = v
			}

			finding := mod.Detect(
				result.Payload,
				baseline.Body,
				baseline.StatusCode,
				baseline.TimeMs,
				result.Response.Body,
				result.Response.StatusCode,
				result.Response.TimeMs,
				headers,
			)

			if finding != nil {
				key := finding.Module + "|" + finding.Point.Name + "|" + finding.Title
				if !seen[key] {
					seen[key] = true
					finding.Request = formatRequest(result)
					finding.Response = formatResponse(result.Response)
					findings = append(findings, finding)
				}
			}
			break
		}
	}

	// Ordenar por severidade
	sortFindings(findings)
	return findings
}

func formatRequest(result engine.FuzzResult) string {
	return result.Payload.Point.Method + " → " + result.Payload.Point.Name + "=" + result.Payload.Value
}

func formatResponse(resp engine.Response) string {
	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "...[truncated]"
	}
	return resp.Status + " | " + body
}

func sortFindings(findings []*vulns.Finding) {
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(findings, func(i, j int) bool {
		return sevOrder[findings[i].Severity] < sevOrder[findings[j].Severity]
	})
}
