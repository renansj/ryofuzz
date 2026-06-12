package analyzer

import (
	"crypto/md5"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/renansj/ryofuzz/internal/engine"
	"github.com/renansj/ryofuzz/internal/vulns"
)

// BehaviorCluster groups similar responses together.
// The outliers (small clusters) are the interesting findings.
type BehaviorCluster struct {
	Fingerprint string
	StatusCode  int
	BodyHash    string
	BodyLength  int
	TimeMs      int64
	Count       int
	Samples     []engine.FuzzResult
}

// BehaviorAnalysis performs anomaly detection on fuzz results.
// Instead of just pattern matching (nuclei-style), we look for
// responses that DIFFER from the majority - those are the bugs.
func BehaviorAnalysis(baseline *engine.Response, results []engine.FuzzResult) []*vulns.Finding {
	var findings []*vulns.Finding
	if len(results) == 0 {
		return findings
	}

	clusters := clusterResponses(results)
	baseFingerprint := fingerprint(baseline.StatusCode, baseline.Body, baseline.BodyLength)

	// Sort clusters by size (smallest first = most anomalous)
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].Count < clusters[j].Count
	})

	// Count how many results are 500 - if too many, it's just bad error handling
	total500 := 0
	totalResults := len(results)
	for _, c := range clusters {
		if c.StatusCode == 500 {
			total500 += c.Count
		}
	}
	suppress500 := float64(total500) > float64(totalResults)*0.2

	maxFindings := 5 // cap behavioral findings to reduce noise
	for _, cluster := range clusters {
		if len(findings) >= maxFindings {
			break
		}
		// Skip the baseline cluster (normal behavior)
		if cluster.Fingerprint == baseFingerprint {
			continue
		}
		// Skip large clusters (common behavior, not interesting)
		if float64(cluster.Count) > float64(totalResults)*0.02 {
			continue
		}

		// Anomaly detected - small cluster with different behavior
		severity := "info"
		confidence := "low"
		title := "Behavioral anomaly"

		// Score the anomaly
		statusDiff := cluster.StatusCode != baseline.StatusCode
		sizeDiff := math.Abs(float64(cluster.BodyLength-baseline.BodyLength)) > float64(baseline.BodyLength)*0.3
		timeDiff := cluster.TimeMs > baseline.TimeMs*3

		anomalyScore := 0
		if statusDiff {
			anomalyScore += 2
		}
		if sizeDiff {
			anomalyScore += 1
		}
		if timeDiff {
			anomalyScore += 3
		}

		if cluster.StatusCode == 500 {
			if suppress500 {
				continue // Too many 500s - just bad error handling, not interesting
			}
			severity = "high"
			confidence = "high"
			title = "Server crash / unhandled exception"
			anomalyScore += 3
		} else if cluster.StatusCode == 200 && baseline.StatusCode != 200 {
			severity = "high"
			confidence = "medium"
			title = "Access control bypass (200 on normally restricted endpoint)"
		} else if timeDiff {
			severity = "high"
			confidence = "medium"
			title = "Timing anomaly (possible injection / DoS)"
		} else if sizeDiff && statusDiff {
			severity = "medium"
			confidence = "medium"
			title = "Response divergence (status + body size change)"
		} else if sizeDiff {
			severity = "low"
			confidence = "low"
			title = "Body size anomaly"
		}

		if anomalyScore < 2 {
			continue
		}

		// Pick the most interesting sample from the cluster
		sample := cluster.Samples[0]

		evidence := fmt.Sprintf("Cluster: %d/%d responses | status=%d (baseline=%d) | size=%d (baseline=%d) | time=%dms (baseline=%dms)",
			cluster.Count, totalResults, cluster.StatusCode, baseline.StatusCode,
			cluster.BodyLength, baseline.BodyLength, cluster.TimeMs, baseline.TimeMs)

		findings = append(findings, &vulns.Finding{
			Module:      "behavior",
			Severity:    severity,
			Confidence:  confidence,
			Title:       title,
			Description: "Behavioral differential analysis detected anomalous server response",
			Payload:     sample.Payload.Value,
			Point:       sample.Payload.Point,
			Evidence:    evidence,
			OWASP:       classifyOWASP(cluster, baseline),
			CWE:         classifyCWE(cluster, baseline),
		})
	}

	return findings
}

// DifferentialPairs sends true/false payload pairs to detect boolean oracles.
func DifferentialPairs(results []engine.FuzzResult) []*vulns.Finding {
	var findings []*vulns.Finding

	// Group results by injection point
	byPoint := make(map[string][]engine.FuzzResult)
	for _, r := range results {
		key := r.Payload.Point.Name + "|" + string(r.Payload.Point.Location)
		byPoint[key] = append(byPoint[key], r)
	}

	// For each point, look for response pairs that differ significantly
	for _, pointResults := range byPoint {
		if len(pointResults) < 10 {
			continue
		}

		// Group by response body length
		byLength := make(map[int][]engine.FuzzResult)
		for _, r := range pointResults {
			if r.Error == nil {
				byLength[r.Response.BodyLength] = append(byLength[r.Response.BodyLength], r)
			}
		}

		// If we have exactly 2-3 distinct response sizes, it might be a boolean oracle
		if len(byLength) >= 2 && len(byLength) <= 4 {
			var sizes []int
			for size := range byLength {
				sizes = append(sizes, size)
			}
			sort.Ints(sizes)

			// Check if sizes differ meaningfully
			if len(sizes) >= 2 {
				diff := sizes[len(sizes)-1] - sizes[0]
				if diff > 50 {
					sample := byLength[sizes[0]][0]
					findings = append(findings, &vulns.Finding{
						Module:      "behavior",
						Severity:    "medium",
						Confidence:  "medium",
						Title:       "Boolean oracle detected",
						Description: fmt.Sprintf("Responses cluster into %d distinct sizes (%v), suggesting boolean-based injection", len(sizes), sizes),
						Payload:     sample.Payload.Value,
						Point:       sample.Payload.Point,
						Evidence:    fmt.Sprintf("Distinct response sizes: %v (diff=%d bytes)", sizes, diff),
						OWASP:       "A03:2021 Injection",
						CWE:         "CWE-89",
					})
				}
			}
		}
	}

	return findings
}

// TimingAnalysis detects timing-based vulnerabilities across all results.
func TimingAnalysis(baseline *engine.Response, results []engine.FuzzResult) []*vulns.Finding {
	var findings []*vulns.Finding
	seen := make(map[string]bool)

	// Calculate baseline timing statistics
	var times []int64
	for _, r := range results {
		if r.Error == nil {
			times = append(times, r.Response.TimeMs)
		}
	}
	if len(times) == 0 {
		return findings
	}

	mean, stddev := stats(times)
	threshold := mean + 3*stddev // 3 sigma = significant outlier
	if threshold < float64(baseline.TimeMs)+4000 {
		threshold = float64(baseline.TimeMs) + 4000 // minimum 4s above baseline
	}

	for _, r := range results {
		if r.Error != nil {
			continue
		}
		if float64(r.Response.TimeMs) > threshold {
			key := r.Payload.Point.Name + "|" + r.Payload.Module
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, &vulns.Finding{
				Module:      "behavior",
				Severity:    "high",
				Confidence:  "high",
				Title:       "Timing anomaly - possible blind injection",
				Description: "Response time significantly exceeds statistical baseline",
				Payload:     r.Payload.Value,
				Point:       r.Payload.Point,
				Evidence:    fmt.Sprintf("time=%dms, mean=%.0fms, stddev=%.0fms, threshold=%.0fms", r.Response.TimeMs, mean, stddev, threshold),
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-89",
			})
		}
	}

	return findings
}

func clusterResponses(results []engine.FuzzResult) []BehaviorCluster {
	clusterMap := make(map[string]*BehaviorCluster)

	for _, r := range results {
		if r.Error != nil {
			continue
		}
		fp := fingerprint(r.Response.StatusCode, r.Response.Body, r.Response.BodyLength)
		if c, ok := clusterMap[fp]; ok {
			c.Count++
			if len(c.Samples) < 3 {
				c.Samples = append(c.Samples, r)
			}
		} else {
			clusterMap[fp] = &BehaviorCluster{
				Fingerprint: fp,
				StatusCode:  r.Response.StatusCode,
				BodyHash:    fmt.Sprintf("%x", md5.Sum([]byte(r.Response.Body))),
				BodyLength:  r.Response.BodyLength,
				TimeMs:      r.Response.TimeMs,
				Count:       1,
				Samples:     []engine.FuzzResult{r},
			}
		}
	}

	var clusters []BehaviorCluster
	for _, c := range clusterMap {
		clusters = append(clusters, *c)
	}
	return clusters
}

func fingerprint(status int, body string, length int) string {
	// Fingerprint = status + body length bucket + first 64 bytes hash
	bucket := length / 100 * 100 // bucket by 100 bytes
	sample := body
	if len(sample) > 64 {
		sample = sample[:64]
	}
	return fmt.Sprintf("%d|%d|%x", status, bucket, md5.Sum([]byte(sample)))
}

func stats(values []int64) (mean, stddev float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := int64(0)
	for _, v := range values {
		sum += v
	}
	mean = float64(sum) / float64(len(values))
	variance := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	stddev = math.Sqrt(variance)
	return
}

func classifyOWASP(cluster BehaviorCluster, baseline *engine.Response) string {
	if cluster.StatusCode == 500 {
		return "A05:2021 Security Misconfiguration"
	}
	if cluster.StatusCode == 200 && baseline.StatusCode >= 400 {
		return "A01:2021 Broken Access Control"
	}
	return "A03:2021 Injection"
}

func classifyCWE(cluster BehaviorCluster, baseline *engine.Response) string {
	if cluster.StatusCode == 500 {
		return "CWE-755"
	}
	if cluster.StatusCode == 200 && baseline.StatusCode >= 400 {
		return "CWE-284"
	}
	return "CWE-20"
}

// ReflectionScan checks if any part of any payload appears in any response (not just exact match)
func ReflectionScan(results []engine.FuzzResult, baseBody string) []*vulns.Finding {
	var findings []*vulns.Finding
	seen := make(map[string]bool)

	for _, r := range results {
		if r.Error != nil || r.Payload.Value == "" {
			continue
		}
		// Check if significant portion of payload is reflected
		payload := r.Payload.Value
		if len(payload) > 5 && strings.Contains(r.Response.Body, payload) && !strings.Contains(baseBody, payload) {
			key := r.Payload.Point.Name + "|reflection"
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, &vulns.Finding{
				Module:      "behavior",
				Severity:    "medium",
				Confidence:  "high",
				Title:       "Input reflection detected",
				Description: "User input is reflected in response without transformation",
				Payload:     payload,
				Point:       r.Payload.Point,
				Evidence:    fmt.Sprintf("Payload of length %d reflected verbatim in response", len(payload)),
				OWASP:       "A03:2021 Injection",
				CWE:         "CWE-79",
			})
		}
	}
	return findings
}
