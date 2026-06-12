package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/renansj/ryofuzz/internal/vulns"
)

// Report gera output no formato solicitado
func Report(findings []*vulns.Finding, format, outputFile string, verbose bool) {
	var output string

	switch format {
	case "json":
		output = reportJSON(findings)
	case "markdown":
		output = reportMarkdown(findings)
	default:
		output = reportText(findings, verbose)
	}

	if outputFile != "" {
		os.WriteFile(outputFile, []byte(output), 0644)
		fmt.Printf("[*] Report saved to: %s\n", outputFile)
	} else {
		fmt.Println(output)
	}
}

func reportText(findings []*vulns.Finding, verbose bool) string {
	if len(findings) == 0 {
		return "\n[*] No vulnerabilities detected.\n"
	}

	var sb strings.Builder
	sb.WriteString("\n╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                    RESULTS - ryofuzz                        ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sevColors := map[string]string{
		"critical": "\033[91m[CRITICAL]\033[0m",
		"high":     "\033[31m[HIGH]\033[0m",
		"medium":   "\033[33m[MEDIUM]\033[0m",
		"low":      "\033[34m[LOW]\033[0m",
		"info":     "\033[36m[INFO]\033[0m",
	}

	for i, f := range findings {
		sev := sevColors[f.Severity]
		if sev == "" {
			sev = "[" + strings.ToUpper(f.Severity) + "]"
		}

		sb.WriteString(fmt.Sprintf("─── Finding #%d ───────────────────────────────────────────\n", i+1))
		sb.WriteString(fmt.Sprintf("  %s %s\n", sev, f.Title))
		sb.WriteString(fmt.Sprintf("  Confidence: %s\n", f.Confidence))
		sb.WriteString(fmt.Sprintf("  Module: %s\n", f.Module))
		sb.WriteString(fmt.Sprintf("  Point: %s [%s]\n", f.Point.Name, f.Point.Location))
		sb.WriteString(fmt.Sprintf("  OWASP: %s\n", f.OWASP))
		sb.WriteString(fmt.Sprintf("  CWE: %s\n", f.CWE))
		sb.WriteString(fmt.Sprintf("  Payload: %s\n", truncate(f.Payload, 100)))
		sb.WriteString(fmt.Sprintf("  Evidence: %s\n", f.Evidence))

		if verbose && f.Request != "" {
			sb.WriteString(fmt.Sprintf("  Request: %s\n", f.Request))
		}
		if verbose && f.Response != "" {
			sb.WriteString(fmt.Sprintf("  Response: %s\n", truncate(f.Response, 200)))
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString(fmt.Sprintf("  Total: %d findings\n", len(findings)))
	counts := countBySeverity(findings)
	sb.WriteString(fmt.Sprintf("  Critical: %d | High: %d | Medium: %d | Low: %d\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"]))
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}

func reportJSON(findings []*vulns.Finding) string {
	data, _ := json.MarshalIndent(findings, "", "  ")
	return string(data)
}

func reportMarkdown(findings []*vulns.Finding) string {
	var sb strings.Builder
	sb.WriteString("# ryofuzz - Vulnerability Report\n\n")
	sb.WriteString(fmt.Sprintf("## Summary\n\nTotal: **%d** findings\n\n", len(findings)))

	counts := countBySeverity(findings)
	sb.WriteString(fmt.Sprintf("| Severity | Count |\n|---|---|\n"))
	sb.WriteString(fmt.Sprintf("| Critical | %d |\n", counts["critical"]))
	sb.WriteString(fmt.Sprintf("| High | %d |\n", counts["high"]))
	sb.WriteString(fmt.Sprintf("| Medium | %d |\n", counts["medium"]))
	sb.WriteString(fmt.Sprintf("| Low | %d |\n\n", counts["low"]))

	sb.WriteString("## Findings\n\n")
	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, strings.ToUpper(f.Severity), f.Title))
		sb.WriteString(fmt.Sprintf("- **Module**: %s\n", f.Module))
		sb.WriteString(fmt.Sprintf("- **Confidence**: %s\n", f.Confidence))
		sb.WriteString(fmt.Sprintf("- **Point de injeção**: %s [%s]\n", f.Point.Name, f.Point.Location))
		sb.WriteString(fmt.Sprintf("- **OWASP**: %s\n", f.OWASP))
		sb.WriteString(fmt.Sprintf("- **CWE**: %s\n", f.CWE))
		sb.WriteString(fmt.Sprintf("- **Payload**: `%s`\n", f.Payload))
		sb.WriteString(fmt.Sprintf("- **Evidence**: %s\n\n", f.Evidence))
	}

	return sb.String()
}

func countBySeverity(findings []*vulns.Finding) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
