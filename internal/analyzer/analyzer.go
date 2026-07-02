package analyzer

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/mutator"
	"github.com/renansj/ryofuzz/internal/vulns"
)

// Analyze compares fuzz results against baseline and runs per-module detection
func Analyze(baseline *engine.Response, results []engine.FuzzResult, modules []vulns.VulnModule, cfg ...engine.Config) []*vulns.Finding {
	var findings []*vulns.Finding
	seen := make(map[string]bool) // dedup por module+point+title

	for _, result := range results {
		if result.Error != nil {
			continue
		}

		// Encontrar o modulo correspondente ao payload
		for _, mod := range modules {
			if mod.Name() != result.Payload.Module {
				continue
			}

			// Converter headers para map[string][]string
			headers := make(map[string][]string)
			for k, v := range result.Response.Headers {
				headers[k] = v
			}

			finding := safeDetect(
				mod,
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

					// Confirmation loops if engine config provided
					if len(cfg) > 0 {
						finding = confirmFinding(finding, result, cfg[0])
					}

					if finding != nil {
						findings = append(findings, finding)
					}
				}
			}
			break
		}
	}

	// Ordenar por severidade
	sortFindings(findings)
	return findings
}

// safeDetect runs a module's Detect under a recover so a panic in one module
// (bad slice index, plugin regex, etc.) cannot crash the scan. A panicking
// module simply yields no finding.
func safeDetect(mod vulns.VulnModule, payload mutator.Payload, baseBody string, baseStatus int, baseTime int64,
	respBody string, respStatus int, respTime int64, respHeaders map[string][]string) (f *vulns.Finding) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[!] recovered panic in module %q Detect (payload %q): %v\n",
				mod.Name(), payload.Value, r)
			f = nil
		}
	}()
	return mod.Detect(payload, baseBody, baseStatus, baseTime, respBody, respStatus, respTime, respHeaders)
}

// confirmFinding applies confirmation checks for time-based and boolean findings
func confirmFinding(finding *vulns.Finding, result engine.FuzzResult, cfg engine.Config) *vulns.Finding {
	if strings.Contains(finding.Title, "Time-based") {
		return confirmTimeBased(finding, result, cfg)
	}
	if strings.Contains(finding.Title, "Boolean") || strings.Contains(finding.Title, "boolean") {
		return confirmBoolean(finding, result, cfg)
	}
	return finding
}

// confirmTimeBased re-sends the payload and sends a no-sleep variant
func confirmTimeBased(finding *vulns.Finding, result engine.FuzzResult, cfg engine.Config) *vulns.Finding {
	// Re-send the same payload to check reproducibility
	r1 := engine.Fuzz(cfg, nil, []mutator.Payload{result.Payload}, 1, 0, 0, false)
	if len(r1) == 0 || r1[0].Error != nil {
		return finding
	}
	// Check if delay reproduced (at least 3 seconds)
	if r1[0].Response.TimeMs < 3000 {
		// Delay did not reproduce, likely network latency
		return nil
	}

	// Send no-sleep variant: replace sleep values with 0
	noSleep := buildNoSleepPayload(result.Payload)
	r2 := engine.Fuzz(cfg, nil, []mutator.Payload{noSleep}, 1, 0, 0, false)
	if len(r2) == 0 || r2[0].Error != nil {
		return finding
	}
	// If the no-sleep variant is also slow, it is network latency
	if r2[0].Response.TimeMs > 3000 {
		return nil
	}

	// Both checks passed - upgrade confidence
	finding.Confidence = "confirmed"
	finding.Evidence = finding.Evidence + " | Confirmed: delay reproduced, no-sleep variant was fast"
	return finding
}

// confirmBoolean sends the complementary payload and checks for response diff
func confirmBoolean(finding *vulns.Finding, result engine.FuzzResult, cfg engine.Config) *vulns.Finding {
	comp := buildComplementPayload(result.Payload)
	r1 := engine.Fuzz(cfg, nil, []mutator.Payload{comp}, 1, 0, 0, false)
	if len(r1) == 0 || r1[0].Error != nil {
		return finding
	}
	// Responses should differ for a true boolean injection
	if r1[0].Response.Body == result.Response.Body && r1[0].Response.StatusCode == result.Response.StatusCode {
		// No difference, likely false positive
		return nil
	}
	finding.Confidence = "confirmed"
	finding.Evidence = finding.Evidence + " | Confirmed: complementary payload produced different response"
	return finding
}

func buildNoSleepPayload(p mutator.Payload) mutator.Payload {
	v := p.Value
	v = strings.Replace(v, "SLEEP(5)", "SLEEP(0)", 1)
	v = strings.Replace(v, "sleep(5)", "sleep(0)", 1)
	v = strings.Replace(v, "SLEEP(10)", "SLEEP(0)", 1)
	v = strings.Replace(v, "sleep(10)", "sleep(0)", 1)
	v = strings.Replace(v, "pg_sleep(5)", "pg_sleep(0)", 1)
	v = strings.Replace(v, "pg_sleep(10)", "pg_sleep(0)", 1)
	v = strings.Replace(v, "WAITFOR DELAY '0:0:5'", "WAITFOR DELAY '0:0:0'", 1)
	v = strings.Replace(v, "WAITFOR DELAY '0:0:10'", "WAITFOR DELAY '0:0:0'", 1)
	return mutator.Payload{
		Value:    v,
		Point:    p.Point,
		Module:   p.Module,
		Variant:  p.Variant + "+nosleep",
		Metadata: p.Metadata,
	}
}

func buildComplementPayload(p mutator.Payload) mutator.Payload {
	v := p.Value
	// Flip true condition to false
	v = strings.Replace(v, "OR 1=1", "OR 1=2", 1)
	v = strings.Replace(v, "or 1=1", "or 1=2", 1)
	v = strings.Replace(v, "OR '1'='1'", "OR '1'='2'", 1)
	v = strings.Replace(v, "or '1'='1'", "or '1'='2'", 1)
	v = strings.Replace(v, "AND 1=1", "AND 1=2", 1)
	v = strings.Replace(v, "and 1=1", "and 1=2", 1)
	// If nothing changed, try the reverse
	if v == p.Value {
		v = strings.Replace(v, "OR 1=2", "OR 1=1", 1)
		v = strings.Replace(v, "or 1=2", "or 1=1", 1)
		v = strings.Replace(v, "AND 1=2", "AND 1=1", 1)
		v = strings.Replace(v, "and 1=2", "and 1=1", 1)
	}
	return mutator.Payload{
		Value:    v,
		Point:    p.Point,
		Module:   p.Module,
		Variant:  p.Variant + "+complement",
		Metadata: p.Metadata,
	}
}

func formatRequest(result engine.FuzzResult) string {
	method := result.Payload.Point.Method
	if method == "" {
		method = "GET"
	}
	return fmt.Sprintf("%s %s=%s [%s in %s]",
		method, result.Payload.Point.Name, result.Payload.Value,
		result.Payload.Module, result.Payload.Point.Location)
}

func formatResponse(resp engine.Response) string {
	body := resp.Body
	if len(body) > 1000 {
		body = body[:1000] + "...[truncated]"
	}
	return fmt.Sprintf("%d %s | %d bytes | %dms\n%s",
		resp.StatusCode, resp.Status, resp.BodyLength, resp.TimeMs, body)
}

func sortFindings(findings []*vulns.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return vulns.SeverityRank(findings[i].Severity) < vulns.SeverityRank(findings[j].Severity)
	})
}
