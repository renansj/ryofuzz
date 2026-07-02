package vulns

import (
	"strings"

	"github.com/renansj/ryofuzz/internal/input"
	"github.com/renansj/ryofuzz/internal/mutator"
)

// VulnModule interface para cada classe de vulnerabilidade
type VulnModule interface {
	Name() string
	Description() string
	GeneratePayloads(points []input.InjectionPoint, mode string, mutations int) []mutator.Payload
	Detect(payload mutator.Payload, baselineBody string, baselineStatus int, baselineTime int64, respBody string, respStatus int, respTime int64, respHeaders map[string][]string) *Finding
}

// Finding resultado de detecção
type Finding struct {
	Module      string
	Severity    string // critical, high, medium, low, info
	Confidence  string // confirmed, high, medium, low
	Title       string
	Description string
	Payload     string
	Point       input.InjectionPoint
	Evidence    string
	OWASP       string // ex: "A03:2021 Injection"
	CWE         string // ex: "CWE-89"
	Request     string
	Response    string
}

// Select returns the modules matching the given selectors. Selectors may be:
//   - "all": every registered module
//   - a module name: "sqli", "xss", ...
//   - a tag selector: "tag:injection", "tag:safe", ...
//
// Backed by the module registry (review A4) so adding a module means one
// register() call, not editing this function.
func Select(tests []string) []VulnModule {
	if len(tests) == 1 && tests[0] == "all" {
		return AllModules()
	}

	testMap := make(map[string]bool)
	var tagFilters []Tag
	for _, t := range tests {
		if suffix, ok := strings.CutPrefix(t, "tag:"); ok {
			tagFilters = append(tagFilters, Tag(suffix))
			continue
		}
		testMap[t] = true
	}

	var selected []VulnModule
	seen := make(map[string]bool)
	for _, r := range registry {
		match := testMap[r.name]
		if !match {
			for _, tf := range tagFilters {
				if r.hasTag(tf) {
					match = true
					break
				}
			}
		}
		if match && !seen[r.name] {
			seen[r.name] = true
			selected = append(selected, r.factory())
		}
	}
	return selected
}
